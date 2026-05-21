"""
scripts/Network/Nokia_G42_Upgrade.py — Software upgrade flow for Nokia G42.

The companion HTTP server (Software Upgrades GUI tab) stages the .manifest
+ payload files at http://169.254.0.101:8000/. This script SSHes to
169.254.0.1 (the G42 service interface) and drives the upgrade through
its phases:

  Phase 1 — Pre-upgrade prep
    change-ztp-mode disabled            (interactive confirm)
    clear recover-mode                  (interactive confirm)

  Phase 2 — Download
    set system security security-policies secure-mode false
    download swimage source=<server-url>     (long-running, watches HTTP server)

  Phase 3 — Validate
    set system security security-policies secure-mode true
    prepare-upgrade validate <manifest>
    show software-load
    NB: it is common for validation to stick on slot 1/3 with an XMM4 card
    seated. If that happens the operator has to physically unseat the
    card and re-run the validate. This script logs the stuck state but
    will not perform that physical step.

  Phase 4 — Apply
    prepare-upgrade -i apply <manifest>       (long-running)
    show software-load

  Phase 5 — Activate
    activate swimage                          (device reboots → SSH drops)

A dropped SSH session after `activate` is the success signal, identical
in spirit to the Ciena RLS warm-reset.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Callable, List, Optional, Tuple

import paramiko

from utils.helpers import ensure_host_key_known, get_known_hosts_path, safe_load_host_keys

logger = logging.getLogger(__name__)

# Per-phase command timeouts (seconds). These are intentionally generous —
# the slow steps on a G42 are bound by disk + flash speed, not network.
_PROMPT_TIMEOUT_S = 30
_DOWNLOAD_TIMEOUT_S = 45 * 60   # full image pull from the local HTTP server
_VALIDATE_TIMEOUT_S = 20 * 60
_APPLY_TIMEOUT_S = 60 * 60
_ACTIVATE_DROP_TIMEOUT_S = 5 * 60

# Treat post-activate session drop as success only after at least this
# many seconds, so a connectivity blip doesn't get misread as completion.
_MIN_ELAPSED_FOR_RESET_S = 30.0

_PROMPT_RE = re.compile(r"([A-Za-z0-9._\-]+[#>])\s*$")
# Matches the most common Nokia confirmation prompts: "(y/n)", "[y/n]",
# and "Press y to continue" variants.
_CONFIRM_RE = re.compile(
    r"\(y/n\)|\[y/n\]|press\s+['\"]?y['\"]?|y/n\s*:?\s*$",
    re.IGNORECASE,
)


class NokiaG42UpgradeScript:
    """Drive a Nokia G42 software upgrade end to end over SSH."""

    def __init__(
        self,
        *,
        ip_address: str,
        username: str,
        password: str,
        server_url: str,
        manifest_name: str,
        output_callback: Optional[Callable[[str], None]] = None,
        stop_callback: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.server_url = server_url
        self.manifest_name = manifest_name
        self.output_callback = output_callback or (lambda _msg: None)
        self.stop_callback = stop_callback or (lambda: False)
        self._prompt: str = ""

    # ── Public entry ────────────────────────────────────────────────────────

    def run(self) -> bool:
        self._log(f"Connecting to G42 at {self.ip_address} as {self.username}…")
        if not ensure_host_key_known(self.ip_address, port=22):
            self._log(f"Host key verification failed for {self.ip_address}.")
            return False

        client = paramiko.SSHClient()
        safe_load_host_keys(client, str(get_known_hosts_path()))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        try:
            client.connect(
                self.ip_address,
                port=22,
                username=self.username,
                password=self.password,
                timeout=15,
                banner_timeout=15,
                auth_timeout=15,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException:
            self._log("SSH authentication failed — check credentials.")
            return False
        except Exception as exc:
            self._log(f"SSH connect error: {exc}")
            return False

        session = None
        try:
            session = client.invoke_shell(width=200, height=10000)
            session.settimeout(30)

            if not self._detect_prompt(session):
                self._log("Could not detect G42 shell prompt.")
                return False
            self._log(f"Logged in; prompt detected ({self._prompt}).")

            phases: List[Tuple[str, Callable[[paramiko.Channel], bool]]] = [
                ("pre-upgrade prep", self._phase_pre_upgrade),
                ("download swimage", self._phase_download),
                ("validate manifest", self._phase_validate),
                ("apply manifest", self._phase_apply),
                ("activate swimage", self._phase_activate),
            ]
            for name, fn in phases:
                if self.stop_callback():
                    self._log(f"Stop requested before phase '{name}'.")
                    return False
                self._log(f"── Phase: {name} ──")
                if not fn(session):
                    self._log(f"Phase '{name}' did not complete cleanly.")
                    # _phase_activate signals success via session drop, so
                    # treat its "failure" as success when the drop is the
                    # cause. That branch handles its own return value.
                    if name != "activate swimage":
                        return False
                    return False
            return True
        finally:
            try:
                if session:
                    session.close()
            except Exception:
                pass
            try:
                client.close()
            except Exception:
                pass

    # ── Phase implementations ───────────────────────────────────────────────

    def _phase_pre_upgrade(self, session) -> bool:
        ok = self._send_confirm(session, "change-ztp-mode disabled")
        if not ok:
            return False
        return self._send_confirm(session, "clear recover-mode")

    def _phase_download(self, session) -> bool:
        if not self._send_simple(
            session,
            "set system security security-policies secure-mode false",
            timeout=_PROMPT_TIMEOUT_S,
        ):
            return False
        cmd = f"download swimage source={self.server_url}"
        self._log(f">> {cmd}  (this may take many minutes)")
        out = self._send_raw(session, cmd, timeout=_DOWNLOAD_TIMEOUT_S)
        if out is None:
            self._log("Download did not return to prompt in time.")
            return False
        self._echo_relevant(out, cmd)
        return True

    def _phase_validate(self, session) -> bool:
        if not self._send_simple(
            session,
            "set system security security-policies secure-mode true",
            timeout=_PROMPT_TIMEOUT_S,
        ):
            return False
        cmd = f"prepare-upgrade validate {self.manifest_name}"
        self._log(f">> {cmd}")
        out = self._send_raw(session, cmd, timeout=_VALIDATE_TIMEOUT_S)
        if out is None:
            self._log("Validate did not return to prompt in time.")
            return False
        self._echo_relevant(out, cmd)

        load_out = self._send_raw(
            session, "show software-load", timeout=_PROMPT_TIMEOUT_S
        )
        if load_out:
            self._echo_relevant(load_out, "show software-load")
            self._warn_if_slot_stuck(load_out)
        return True

    def _phase_apply(self, session) -> bool:
        cmd = f"prepare-upgrade -i apply {self.manifest_name}"
        self._log(f">> {cmd}  (this may take a while)")
        out = self._send_raw(session, cmd, timeout=_APPLY_TIMEOUT_S)
        if out is None:
            self._log("Apply did not return to prompt in time.")
            return False
        self._echo_relevant(out, cmd)

        load_out = self._send_raw(
            session, "show software-load", timeout=_PROMPT_TIMEOUT_S
        )
        if load_out:
            self._echo_relevant(load_out, "show software-load")
        return True

    def _phase_activate(self, session) -> bool:
        """Send 'activate swimage' and treat the resulting SSH drop as
        the success signal (the device reboots into the new load)."""
        cmd = "activate swimage"
        self._log(f">> {cmd}  (device will reboot — SSH will drop)")
        start = time.monotonic()
        try:
            session.send(cmd + "\n")
        except Exception as exc:
            self._log(f"send error on activate: {exc}")
            return False

        # Wait for the channel to close. recv_ready stops returning data,
        # then session.closed flips. Anything earlier than the minimum
        # threshold is treated as a connectivity issue, not completion.
        deadline = time.time() + _ACTIVATE_DROP_TIMEOUT_S
        while time.time() < deadline:
            if self.stop_callback():
                self._log("Stop requested during activate.")
                return False
            try:
                if session.recv_ready():
                    chunk = session.recv(65535)
                    if chunk:
                        # echo any pre-reboot output (commit messages, etc.)
                        for line in chunk.decode("utf-8", errors="replace").splitlines():
                            if line.strip():
                                self._log(f"  {line.rstrip()}")
                elif session.closed or session.exit_status_ready():
                    elapsed = time.monotonic() - start
                    if elapsed >= _MIN_ELAPSED_FOR_RESET_S:
                        self._log(
                            f"SSH session closed after {elapsed:.0f}s — "
                            "device is rebooting into the new load. "
                            "Treating upgrade as complete."
                        )
                        return True
                    self._log(
                        f"SSH closed only {elapsed:.0f}s in — too early to "
                        "credit as a reboot. Failing."
                    )
                    return False
                else:
                    time.sleep(0.5)
            except Exception as exc:
                # paramiko raises on closed channel — same success signal
                elapsed = time.monotonic() - start
                if elapsed >= _MIN_ELAPSED_FOR_RESET_S:
                    self._log(
                        f"SSH channel error after {elapsed:.0f}s ({exc}); "
                        "treating as expected reboot."
                    )
                    return True
                self._log(f"SSH channel error too early: {exc}")
                return False

        self._log("Activate did not result in a session drop within timeout.")
        return False

    # ── Send helpers ────────────────────────────────────────────────────────

    def _send_simple(self, session, cmd: str, timeout: float) -> bool:
        """Send a command, wait for prompt, echo output."""
        self._log(f">> {cmd}")
        out = self._send_raw(session, cmd, timeout=timeout)
        if out is None:
            return False
        self._echo_relevant(out, cmd)
        return True

    def _send_confirm(self, session, cmd: str) -> bool:
        """Send a command that prompts for y/n confirmation, send 'y'."""
        self._log(f">> {cmd}  (will answer 'y' to confirmation)")
        try:
            session.send(cmd + "\n")
        except Exception as exc:
            self._log(f"send error: {exc}")
            return False

        # Read until we see either a confirmation prompt or the regular prompt.
        deadline = time.time() + _PROMPT_TIMEOUT_S
        buf = bytearray()
        confirmed = False
        prompt_b = self._prompt.encode("utf-8")
        while time.time() < deadline:
            if self.stop_callback():
                return False
            try:
                if session.recv_ready():
                    chunk = session.recv(65535)
                    if not chunk:
                        return False
                    buf.extend(chunk)
                    decoded = bytes(buf).decode("utf-8", errors="replace")
                    if not confirmed and _CONFIRM_RE.search(decoded[-200:]):
                        session.send("y\n")
                        confirmed = True
                        # Reset buf so the post-confirm prompt detection
                        # doesn't re-trigger on the same y/n line.
                        buf = bytearray()
                        deadline = time.time() + _PROMPT_TIMEOUT_S
                        continue
                else:
                    stripped = bytes(buf).replace(b"\r", b"").rstrip()
                    if stripped.endswith(prompt_b) and b"\n" in stripped:
                        time.sleep(0.3)
                        if not session.recv_ready():
                            self._echo_relevant(
                                bytes(buf).decode("utf-8", errors="replace"),
                                cmd,
                            )
                            return True
                    time.sleep(0.1)
            except Exception as exc:
                self._log(f"recv error: {exc}")
                return False
        self._log(f"Timed out waiting for confirmation/prompt after '{cmd}'")
        return False

    def _send_raw(
        self, session, cmd: str, timeout: float
    ) -> Optional[str]:
        try:
            session.send(cmd + "\n")
        except Exception as exc:
            logger.debug("send failed: %s", exc)
            return None
        return self._read_until_prompt(session, timeout=timeout)

    # ── Prompt detection / output reading ───────────────────────────────────

    def _detect_prompt(self, session) -> bool:
        time.sleep(2.0)
        buf = self._drain(session, idle_seconds=1.5, max_wait=8.0)
        m = _PROMPT_RE.search(buf)
        for _ in range(5):
            if m:
                break
            if self.stop_callback():
                return False
            try:
                session.send("\n")
            except Exception:
                return False
            time.sleep(1.0)
            buf += self._drain(session, idle_seconds=1.0, max_wait=4.0)
            m = _PROMPT_RE.search(buf)
        if not m:
            return False
        self._prompt = m.group(1)
        return True

    @staticmethod
    def _drain(session, idle_seconds: float = 1.0, max_wait: float = 5.0) -> str:
        deadline = time.time() + max_wait
        last_read = time.time()
        buf = bytearray()
        while time.time() < deadline:
            if session.recv_ready():
                chunk = session.recv(65535)
                if chunk:
                    buf.extend(chunk)
                    last_read = time.time()
            else:
                if time.time() - last_read >= idle_seconds and buf:
                    break
                time.sleep(0.1)
        return buf.decode("utf-8", errors="replace")

    def _read_until_prompt(self, session, timeout: float) -> Optional[str]:
        deadline = time.time() + timeout
        buf = bytearray()
        prompt_b = self._prompt.encode("utf-8")
        last_progress_log = time.time()
        while time.time() < deadline:
            if self.stop_callback():
                return None
            try:
                if session.recv_ready():
                    chunk = session.recv(65535)
                    if not chunk:
                        return None
                    buf.extend(chunk)
                    # Long-running commands print intermediate output —
                    # surface it to the log every couple of seconds so the
                    # operator can see progress without spamming.
                    if time.time() - last_progress_log >= 2.0:
                        tail = bytes(buf[-512:]).decode("utf-8", errors="replace")
                        for line in tail.splitlines()[-3:]:
                            line = line.rstrip()
                            if line and not line.endswith(self._prompt):
                                self._log(f"  {line}")
                        last_progress_log = time.time()
                else:
                    stripped = bytes(buf).replace(b"\r", b"").rstrip()
                    if stripped.endswith(prompt_b) and b"\n" in stripped:
                        time.sleep(0.4)
                        if not session.recv_ready():
                            return buf.decode("utf-8", errors="replace")
                        continue
                    if session.closed or session.exit_status_ready():
                        return None
                    time.sleep(0.2)
            except Exception as exc:
                logger.debug("recv error: %s", exc)
                return None
        return None

    # ── Output post-processing ──────────────────────────────────────────────

    def _echo_relevant(self, out: str, cmd: str) -> None:
        """Strip the command echo + trailing prompt, log what's left."""
        lines = out.splitlines()
        if lines and cmd in lines[0]:
            lines = lines[1:]
        if lines and re.match(r"^[A-Za-z0-9._\-]+[#>]\s*$", lines[-1].strip()):
            lines = lines[:-1]
        for line in lines:
            line = line.rstrip()
            if line:
                self._log(f"  {line}")

    @staticmethod
    def _warn_if_slot_stuck(load_out: str) -> None:
        """If `show software-load` shows slot 1/3 in a non-completed state
        while others have moved on, log the known-issue hint. The exact
        column shape varies by firmware revision so we keep the match
        loose."""
        lower = load_out.lower()
        if "1/3" in lower and ("stuck" in lower or "failed" in lower):
            logger.warning(
                "G42 validate appears stuck on slot 1/3 — physical unseat "
                "of XMM4 may be required."
            )

    def _log(self, msg: str) -> None:
        try:
            self.output_callback(msg)
        except Exception:
            pass
        logger.info("[G42-Upgrade %s] %s", self.ip_address, msg)
