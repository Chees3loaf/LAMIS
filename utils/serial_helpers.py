"""Serial-console helpers for Nokia SAR/IXR (and similar) devices.

These exist because the per-script `capture_full_output_serial` loops
were polling `in_waiting` and breaking on the first momentary gap,
which truncated multi-screen `show` output, and because no script was
authenticating against the serial console — commands were blasted at a
`Login:` prompt and silently ignored.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Callable, List, Optional, Tuple

# Match the common operational prompts at end-of-buffer:
#   Nokia SROS:    "A:hostname#"   "*A:hostname#"  "B:hostname>"
#   Generic:       "hostname#"     "hostname>"     "hostname$"
#   Waveserver-5:  "Waveserver-5*#" / "WS5_1*#" — the trailing ``*`` flags
#                  pending-but-unsaved config changes; we tolerate it so
#                  the prompt detector doesn't stall mid-provisioning.
# Also matches Login:/Password: prompts so callers can drive the login.
_PROMPT_RE = re.compile(
    rb"(?:[\*]?[ABab]:[A-Za-z0-9_\-.]+[#>]\s*$)"
    rb"|(?:[A-Za-z0-9_\-.]+\*?\s*[#>$]\s*$)"
    rb"|(?:[Ll]ogin:\s*$)"
    rb"|(?:[Uu]sername:\s*$)"
    rb"|(?:[Pp]assword:\s*$)"
)

_LOGIN_RE = re.compile(rb"(?:[Ll]ogin|[Uu]sername):\s*$")
_PASSWORD_RE = re.compile(rb"[Pp]assword:\s*$")
_SHELL_RE = re.compile(rb"(?:[\*]?[ABab]:[A-Za-z0-9_\-.]+[#>]|[A-Za-z0-9_\-.]+\*?[#>$])\s*$")
_FAIL_RE = re.compile(rb"(?:[Ll]ogin\s+(?:incorrect|failed)|[Aa]uthentication\s+fail)")


def _drain_quiet(ser, quiet_ms: int = 400, max_wait: float = 2.0) -> None:
    """Read and discard bytes until the line has been quiet for *quiet_ms*.

    The device's banner can arrive in chunks over several hundred ms after a
    wake-up CR; if we send the first credential before the banner finishes,
    `reset_input_buffer` won't help — the bytes still in flight will land in
    the next read and trick us into thinking the device already responded.
    Sit and absorb those bytes before sending anything new.
    """
    deadline = time.time() + max_wait
    last_byte_time = time.time()
    while time.time() < deadline:
        n = ser.in_waiting
        if n:
            ser.read(n)
            last_byte_time = time.time()
        else:
            if (time.time() - last_byte_time) * 1000 >= quiet_ms:
                return
            time.sleep(0.05)


def _read_until(
    ser,
    pattern: re.Pattern,
    timeout: float,
    should_stop: Optional[Callable[[], bool]] = None,
) -> Tuple[bytes, bool]:
    """Read bytes from *ser* until *pattern* matches the tail or *timeout*.

    Returns (buffer, matched). Buffer is the raw bytes read so far.
    """
    deadline = time.time() + timeout
    buf = bytearray()
    while time.time() < deadline:
        if should_stop and should_stop():
            return bytes(buf), False
        n = ser.in_waiting
        if n:
            buf.extend(ser.read(n))
            tail = bytes(buf[-512:])
            if pattern.search(tail):
                return bytes(buf), True
            # Page-pause handling. Different vendors emit different
            # paging banners — handle the common ones inline so callers
            # don't have to re-implement the same loop per device.
            #   * Nokia SROS:        "Press any key to continue"
            #   * Ciena Waveserver:  "--more--"  (also "--More--")
            # A single space advances all of them by one screen.
            if b"Press any key to continue" in tail:
                ser.write(b" ")
            elif b"--more--" in tail or b"--More--" in tail:
                ser.write(b" ")
        else:
            time.sleep(0.05)
    return bytes(buf), False


def open_serial_with_baud_probe(
    port: str,
    baud_rates: List[int],
    *,
    timeout: float = 2.0,
    should_stop: Optional[Callable[[], bool]] = None,
):
    """Open *port* trying each baud in *baud_rates*, returning the first
    that produces a recognisable login/shell/password prompt within
    *timeout* seconds.

    Returns the opened ``serial.Serial`` instance on success, or ``None``
    when every candidate baud rate is silent or garbled. The caller is
    responsible for closing the returned object.

    The probe sends a single CR to wake the console, reads briefly, and
    looks for any of: Login:/Username:/Password:/<host>#/<host>>. A
    wrong baud rate typically returns high-bit garbage or nothing at
    all — neither matches the prompt patterns so we move on. Used by
    devices where the operator may not know the console speed in
    advance (RLS lab gear ships at 9600 OR 115200 depending on the
    flash image).
    """
    import serial  # local import keeps the module importable on systems
                   # without pyserial when only the regexes are needed
    for baud in baud_rates:
        if should_stop and should_stop():
            return None
        logging.info(f"[SERIAL] Probing {port} at {baud} baud...")
        try:
            ser = serial.Serial(port, baud, timeout=timeout)
        except Exception as exc:
            logging.warning(f"[SERIAL] Could not open {port}@{baud}: {exc}")
            continue
        try:
            ser.reset_input_buffer()
        except Exception:
            pass
        try:
            ser.write(b"\r")
        except Exception:
            try:
                ser.close()
            except Exception:
                pass
            continue
        buf, matched = _read_until(
            ser, _PROMPT_RE, timeout=timeout, should_stop=should_stop
        )
        if matched:
            logging.info(f"[SERIAL] {port} locked onto {baud} baud")
            return ser
        # Empty buffer = no response (cable issue or really wrong speed);
        # non-empty = bytes arrived but didn't match a prompt (likely the
        # wrong baud emitting garbage). Either way, close and try next.
        logging.info(
            f"[SERIAL] {port}@{baud} did not yield a prompt "
            f"(got {len(buf)} bytes); trying next baud"
        )
        try:
            ser.close()
        except Exception:
            pass
    logging.warning(
        f"[SERIAL] No baud rate in {baud_rates} produced a prompt on {port}"
    )
    return None


def serial_login(
    ser,
    defaults: List[Tuple[str, str]],
    timeout: float = 10.0,
    should_stop: Optional[Callable[[], bool]] = None,
) -> Tuple[bool, Optional[Tuple[str, str]]]:
    """Drive the device to a shell prompt, rotating through *defaults*.

    Sends a CR to wake the prompt, then:
      - if a shell prompt appears, succeed with no auth needed
      - if Login:/Username: appears, walk *defaults* trying each pair
        until a shell prompt appears or all pairs fail
    """
    try:
        ser.reset_input_buffer()
    except Exception:
        pass
    ser.write(b"\r")
    buf, matched = _read_until(ser, _PROMPT_RE, timeout=timeout, should_stop=should_stop)
    tail = buf[-512:]

    if _SHELL_RE.search(tail):
        logging.info("[SERIAL] Already at shell prompt; no auth needed.")
        return True, None

    if not (_LOGIN_RE.search(tail) or _PASSWORD_RE.search(tail)):
        logging.warning(
            f"[SERIAL] No prompt seen within {timeout}s. Last bytes: {tail[-200:]!r}"
        )
        return False, None

    for user, pw in defaults:
        logging.info(f"[SERIAL] Trying credentials user={user!r}")
        # Wait for the line to go quiet so the device's banner finishes
        # before we send the username. Without this the first iteration
        # consumes residual banner bytes and never actually waits for the
        # device's Password: prompt.
        _drain_quiet(ser, quiet_ms=400, max_wait=2.0)
        try:
            ser.reset_input_buffer()
        except Exception:
            pass
        ser.write((user + "\r").encode("utf-8", errors="replace"))
        buf, matched = _read_until(ser, _PROMPT_RE, timeout=timeout, should_stop=should_stop)
        tail = buf[-512:]
        if _PASSWORD_RE.search(tail):
            ser.write((pw + "\r").encode("utf-8", errors="replace"))
            buf, matched = _read_until(ser, _PROMPT_RE, timeout=timeout, should_stop=should_stop)
            tail = buf[-512:]
        if _SHELL_RE.search(tail):
            logging.info(f"[SERIAL] Login OK as {user!r}.")
            return True, (user, pw)
        # Some devices (Nokia SROS variants) don't print "Login incorrect" on
        # bad creds — they silently replay the banner and re-prompt with
        # Login:. Treat any post-credential return-to-Login: as auth failure.
        if _FAIL_RE.search(buf) or _LOGIN_RE.search(tail):
            logging.info(f"[SERIAL] Auth failed for {user!r}; trying next default.")
            continue
        # Whatever happened, we don't have a shell. Try next.
        logging.info(
            f"[SERIAL] No shell after {user!r}; trying next default. "
            f"Last bytes: {tail[-200:]!r}"
        )

    logging.warning("[SERIAL] All default credentials exhausted on serial console.")
    return False, None


def capture_until_prompt(
    ser,
    command: str,
    timeout: float = 20.0,
    should_stop: Optional[Callable[[], bool]] = None,
) -> Optional[str]:
    """Send *command* and read until the shell prompt re-appears.

    Returns the decoded output (excluding the prompt line) or None on
    timeout / abort.
    """
    try:
        ser.reset_input_buffer()
    except Exception:
        pass
    ser.write((command + "\r").encode("utf-8", errors="replace"))
    buf, matched = _read_until(ser, _SHELL_RE, timeout=timeout, should_stop=should_stop)
    if should_stop and should_stop():
        return None
    if not matched:
        logging.warning(
            f"[SERIAL] No prompt within {timeout}s for command {command!r}; "
            f"returning {len(buf)} bytes captured so far."
        )
    return buf.decode("utf-8", errors="replace")
