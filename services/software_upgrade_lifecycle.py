"""Windows network and HTTP-transfer lifecycle for software upgrades.

This module deliberately contains no GUI-toolkit imports so both the PySide6
workflow and the legacy Tk fallback can use the same operational primitives.
"""
from __future__ import annotations

import ctypes
import logging
import os
import socket
import subprocess
import tempfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional, Tuple

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

_HTTP_PORT = 8000
_CHUNK_SIZE = 64 * 1024
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

def _is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0  # type: ignore[attr-defined]
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_netsh(args: list[str], timeout: float = 30.0) -> Tuple[bool, str]:
    """Run `netsh <args>`. If ATLAS isn't elevated, prompt UAC via
    ShellExecuteEx and wait for the elevated child to exit.
    """
    if os.name != "nt":
        return False, "netsh is only available on Windows."

    logging.info(
        "[NETSH] running: netsh %s",
        subprocess.list2cmdline(args),
    )

    if _is_admin():
        try:
            proc = subprocess.run(
                ["netsh"] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=_CREATE_NO_WINDOW,
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            return proc.returncode == 0, output.strip() or "OK"
        except subprocess.TimeoutExpired:
            return False, "netsh timed out."
        except Exception as exc:
            return False, f"netsh failed: {exc}"

    # Optional pywin32 path for UAC elevation when not already admin
    try:
        import win32event
        import win32process
        import win32con
        from win32com.shell.shell import ShellExecuteEx  # type: ignore[import-not-found]
        from win32com.shell import shellcon  # type: ignore[import-not-found]
    except ImportError:
        return False, (
            "Setting a static IP requires administrator privileges. "
            "Re-launch ATLAS as administrator, or install pywin32 to enable "
            "auto-elevation."
        )

    # Import only when needed (avoids Pylance errors)
    tmp_log_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", prefix="atlas_netsh_",
            delete=False, encoding="utf-8",
        ) as _tmp:
            tmp_log_path = _tmp.name
    except Exception as exc:
        logging.warning(f"[NETSH] could not create capture tempfile: {exc}")

    try:
        if tmp_log_path:
            cmd_line = (
                f'/c netsh {subprocess.list2cmdline(args)} > '
                f'"{tmp_log_path}" 2>&1'
            )
            se = ShellExecuteEx(
                nShow=win32con.SW_HIDE,
                fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                lpVerb="runas",
                lpFile="cmd.exe",
                lpParameters=cmd_line,
            )
        else:
            se = ShellExecuteEx(
                nShow=win32con.SW_HIDE,
                fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                lpVerb="runas",
                lpFile="netsh.exe",
                lpParameters=subprocess.list2cmdline(args),
            )
        handle = se["hProcess"]
        wait_rc = win32event.WaitForSingleObject(handle, int(timeout * 1000))
        if wait_rc != 0:  # WAIT_OBJECT_0
            return False, "Elevated netsh timed out or was interrupted."
        rc = win32process.GetExitCodeProcess(handle)

        captured = ""
        if tmp_log_path:
            try:
                with open(tmp_log_path, "r", encoding="utf-8", errors="replace") as f:
                    captured = f.read().strip()
            except Exception as exc:
                captured = f"(could not read netsh output: {exc})"
            finally:
                try:
                    os.unlink(tmp_log_path)
                except Exception:
                    pass

        if rc == 0:
            return True, captured or "OK"
        msg = captured or f"netsh exit code {rc}"
        return False, msg
    except Exception as exc:
        if tmp_log_path:
            try:
                os.unlink(tmp_log_path)
            except Exception:
                pass
        return False, f"Elevation cancelled or failed: {exc}"


def _set_static_ipv4(nic: str, ip: str, mask: str) -> Tuple[bool, str]:
    """Set *nic* to a static IPv4 address, robust against stale
    bindings from a previous run.

    Why this exists: plain ``netsh interface ipv4 set address NAME
    static IP MASK`` fails with ``The object already exists.`` when
    *any* previous run already bound the same IP on this NIC, even
    after a successful ``set address … source=dhcp`` to restore
    DHCP. Windows persists the static binding in the registry and
    DHCP-restore doesn't always clear it before the next ``set``
    runs. The reliable pattern is:

      1. Best-effort ``delete address NAME addr=IP`` to drop the
         stale binding if it's there. Failure (e.g. "the specified
         entry was not found") is fine -- it just means there was
         nothing to delete.
      2. ``set address NAME static IP MASK``.

    Returns ``(success, message)`` matching :func:`_run_netsh`.
    """
    # Step 1: idempotent cleanup of any prior binding of this exact
    # address. Ignore the result -- the only failure mode that
    # matters is the subsequent ``set``.
    del_ok, del_msg = _run_netsh(
        ["interface", "ipv4", "delete", "address",
         f"name={nic}", f"addr={ip}"],
        timeout=15.0,
    )
    if not del_ok:
        # Log at debug-ish level; this is expected when the address
        # wasn't bound.
        logging.info(
            f"[NETSH] pre-clean delete of {ip} on {nic} returned: {del_msg}"
        )

    # Step 2: set the new static address as the primary binding.
    return _run_netsh(
        ["interface", "ipv4", "set", "address",
         f"name={nic}", "static", ip, mask],
    )


# NIC names the operator never wants in the dropdown for a wired
# upgrade session. Pattern-matched case-insensitively against the
# adapter friendly name from psutil:
#   * Wi-Fi / wireless adapters
#   * The MS virtual "Local Area Connection* N" hotspot adapters
#   * Bluetooth Network Connection
#   * Hyper-V / WSL vEthernet, VMware, VirtualBox virtual switches
#   * Loopback
# Substring match (lowercased).
_NIC_EXCLUDE_PATTERNS = (
    "wi-fi",
    "wifi",
    "wireless",
    "local area connection*",
    "bluetooth",
    "vethernet",
    "vmware",
    "virtualbox",
    "loopback",
)


def _list_nics() -> list[str]:
    """Return the names of usable wired Ethernet NICs for the upgrade
    dropdown.

    Filters (all must pass):
      1. Name doesn't substring-match anything in
         :data:`_NIC_EXCLUDE_PATTERNS` (wireless / Bluetooth /
         virtual switches / loopback).
      2. Interface is currently UP -- ``psutil.net_if_stats().isup``
         is the equivalent of ``ipconfig`` reporting an actual
         binding instead of ``Media disconnected``. This naturally
         hides the laptop's onboard Ethernet ports when no cable is
         plugged in (and lets ``Ethernet 4``+ remain visible the
         instant the operator plugs into them, without us having to
         maintain a manual allow/exclude list of numbered ports).
      3. Adapter has at least one IPv4 address (covers APIPA /
         static / DHCP). Pure-IPv6 doesn't work for our setup.
    """
    if not _HAS_PSUTIL:
        return []

    try:
        stats = psutil.net_if_stats()
    except Exception:
        stats = {}

    names: list[str] = []
    for name, addrs in psutil.net_if_addrs().items():
        low = name.lower()
        if any(pat in low for pat in _NIC_EXCLUDE_PATTERNS):
            continue
        st = stats.get(name)
        if st is not None and not st.isup:
            continue
        if any(a.family == socket.AF_INET for a in addrs):
            names.append(name)
    # Alphabetical -- every remaining entry is a wired Ethernet the
    # operator knows by number.
    names.sort(key=lambda n: n.lower())
    return names


# ── In-process HTTP server with progress reporting ──────────────────────────

class _ProgressHTTPHandler(SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler that streams files in 64 KiB chunks and
    invokes ``self.server.on_progress(filename, sent, total)`` after each
    chunk so the GUI can drive its progress bar.
    """

    # Quieter default log_message — route through `self.server.on_log` if set
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        try:
            msg = f"{self.address_string()} - {fmt % args}"
        except Exception:
            msg = fmt
        on_log = getattr(self.server, "on_log", None)
        if callable(on_log):
            try:
                on_log(msg)
            except Exception:
                pass
        else:
            logging.getLogger("software_upgrade.http").info(msg)

    def copyfile(self, source, outputfile):  # type: ignore[override]
        """Chunked copy with progress callback. Mirrors the behaviour of
        ``shutil.copyfileobj`` but reports each chunk."""
        on_progress = getattr(self.server, "on_progress", None)
        # ``source`` is the open file; size lives on the response headers we
        # already sent. Re-derive from path for safety.
        try:
            total = os.fstat(source.fileno()).st_size
        except Exception:
            total = 0
        sent = 0
        fname = os.path.basename(self.path.split("?", 1)[0])

        if callable(on_progress):
            try:
                on_progress(fname, 0, total)
            except Exception:
                pass

        while True:
            buf = source.read(_CHUNK_SIZE)
            if not buf:
                break
            outputfile.write(buf)
            sent += len(buf)
            if callable(on_progress):
                try:
                    on_progress(fname, sent, total)
                except Exception:
                    pass

        if callable(on_progress):
            try:
                on_progress(fname, sent, total, done=True)
            except Exception:
                pass


class _UpgradeHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that pins serving to a specific root directory
    (via ``directory=`` on the handler) and exposes ``on_progress`` /
    ``on_log`` callbacks for the GUI to subscribe to.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: Tuple[str, int],
        directory: str,
        on_progress: Optional[Callable[..., None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._directory = directory
        self.on_progress = on_progress
        self.on_log = on_log

        def _factory(*args, **kwargs):
            # SimpleHTTPRequestHandler honours `directory=` to chroot the
            # listing/serving to that path.
            return _ProgressHTTPHandler(*args, directory=directory, **kwargs)

        super().__init__(server_address, _factory)

