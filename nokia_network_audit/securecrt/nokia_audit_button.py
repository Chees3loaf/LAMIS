# $language = "python3"
# $interface = "1.0"

"""SecureCRT toolbar button: audit whatever device this session is logged into.

Press the button while a SecureCRT session is connected. The script drives the
*existing* terminal session, so it inherits whatever path already got you to the
device -- jump host, telnet, serial console, saved credentials, MFA -- and never
asks for or stores a password of its own.

What it does, in order:

1. Learns the session prompt.
2. Identifies the platform (SR OS classic CLI vs. 1830 PSS), or asks.
3. Disables pagination for this CLI session only.
4. Sends the read-only ``show`` baseline for that platform.
5. Saves the raw transcript.
6. Runs the offline audit over the transcript, if the package is reachable.

Every command sent is drawn from ``nokia_network_audit.profiles`` and is
re-checked against the read-only allowlist here, in this process, immediately
before it is sent. Nothing is sent that does not begin with ``show`` except the
platform's documented pagination setting, which is session-scoped display state
rather than configuration.

SecureCRT 9.x runs this under the system Python 3.10-3.13 interpreter (via its
PythonNNN-shim.dll), so the audit package imports directly -- no subprocess and
no third-party dependency is required.
"""

import os
import re
import sys
import time
from datetime import datetime, timezone

# SecureCRT injects ``crt`` into the script's globals.
try:
    crt  # type: ignore[used-before-def]  # noqa: B018
except NameError:  # pragma: no cover - only hit when run outside SecureCRT
    raise SystemExit("This script must be run from within SecureCRT.")


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

# Where transcripts and reports are written. Override with the
# NOKIA_AUDIT_OUTPUT environment variable.
DEFAULT_OUTPUT_DIR = os.path.join(
    os.path.expanduser("~"), "Documents", "NokiaNetworkAudit"
)

# Set NOKIA_AUDIT_REPO to the repository root if this script is copied out of
# the repo into SecureCRT's script directory.
REPO_ENV_VAR = "NOKIA_AUDIT_REPO"

# Credentials used when hopping to a neighbouring SR OS router. These are the
# lab's convention; override without editing this file by setting
# NOKIA_AUDIT_USER / NOKIA_AUDIT_PASSWORD in the environment. They are held in
# memory for the run only -- never written to a transcript, a report, or disk.
# If a device rejects them the hop is abandoned rather than retried, so a wrong
# value here cannot lock an account out through repeated attempts.
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"


def hop_credentials():
    return (
        os.environ.get("NOKIA_AUDIT_USER") or DEFAULT_USERNAME,
        os.environ.get("NOKIA_AUDIT_PASSWORD") or DEFAULT_PASSWORD,
    )

COMMAND_TIMEOUT = 120  # seconds to wait for one command's output
PROMPT_TIMEOUT = 10
ECHO_TIMEOUT = 15  # seconds to wait for the device to echo a sent command
HOP_TIMEOUT = 60  # seconds to get a usable prompt on a neighbour, or back

PAGER_MATCHES = ("--More--", "Press any key to continue", "Press <space> to continue")

# Fallback used only when the audit package cannot be located. Keep in sync
# with nokia_network_audit/profiles.py.
_SROS_FALLBACK_COMMANDS = (
    "show system information",
    "show chassis detail",
    "show card state",
    "show card detail",
    "show mda",
    "show mda detail",
    "show port",
    "show port detail",
    "show lag",
    "show lag detail",
    "show router interface",
    "show router interface detail",
    "show router ospf neighbor",
    "show router isis adjacency",
    "show router isis adjacency detail",
    "show router isis capabilities",
    "show router bgp neighbor",
    "show router ldp session",
    "show service service-using",
    "show aps",
    "show system lldp neighbor",
    "show external-alarms input",
    "show system sync-if-timing",
    "show redundancy synchronization",
    "show system cpu",
)

_FALLBACK_PROFILES = {
    "7705-sar-8": {
        "description": "7705 SAR-8 classic SR OS baseline",
        "paging_command": "environment no more",
        "identity_command": "show system information",
        # The event log is 7705-only here, mirroring SAR_8_BASELINE in
        # profiles.py. The 7250 entries below therefore cannot alias this
        # dict any more -- they share the base tuple instead.
        "commands": _SROS_FALLBACK_COMMANDS + ("show log log-id 99",),
    },
}
_FALLBACK_PROFILES["7250-ixr-r6"] = {
    "description": "7250 IXR-R6 classic SR OS baseline",
    "paging_command": "environment no more",
    "identity_command": "show system information",
    "commands": _SROS_FALLBACK_COMMANDS,
}
_FALLBACK_PROFILES["7250-ixr-r6d"] = _FALLBACK_PROFILES["7250-ixr-r6"]
_FALLBACK_PROFILES["7250-ixr-r6dl"] = _FALLBACK_PROFILES["7250-ixr-r6"]
_FALLBACK_PROFILES["1830-pss-8"] = {
    "description": "1830 PSS-8 equipment and optical baseline",
    "paging_command": "paging status disabled",
    "identity_command": "show general system-identification",
    "commands": (
        "show general name",
        "show general system-identification",
        "show software dynamic",
        "show shelf inventory *",
        "show slot *",
        "show card inventory *",
        "show card sfdc8b *",
        "show interface sfdc8b *",
        "show interface inventory *",
        "show interface topology *",
        "show condition",
        "show alarmleds",
    ),
}

_ALLOWED_PAGING = frozenset({"environment no more", "paging status disabled"})

# Why the audit package could not be loaded, if it could not. Surfaced to the
# operator: falling back silently produced captures with a stale command set and
# no audit, which looked like a successful run.
PACKAGE_ERROR = None


# --------------------------------------------------------------------------
# Repository / package discovery
# --------------------------------------------------------------------------


def _candidate_repo_roots():
    override = os.environ.get(REPO_ENV_VAR)
    if override:
        yield override
    try:
        # <repo>/nokia_network_audit/securecrt/nokia_audit_button.py
        here = os.path.dirname(os.path.abspath(crt.ScriptFullName))
        yield os.path.dirname(os.path.dirname(here))
    except Exception:
        pass


def _purge_cached_package():
    """Drop any previously imported copy of the audit package.

    SecureCRT keeps its Python interpreter alive between button presses, so
    ``sys.modules`` holds whatever version was imported the first time. Editing
    the package then has no effect until SecureCRT itself is restarted -- and
    worse, a *partial* mismatch (a new name imported from a stale module) raises
    ImportError, which used to be swallowed into a silent fallback. Reloading
    each press keeps the button honest about what is on disk.
    """
    for name in [n for n in sys.modules if n.split(".")[0] == "nokia_network_audit"]:
        del sys.modules[name]


def load_audit_package():
    """Import the audit package, returning ``(module_dict, repo_root)``.

    Returns ``(None, None)`` when the package is not reachable; the caller then
    captures the transcript only. ``PACKAGE_ERROR`` records why, because a
    silent downgrade to the built-in fallback produced captures with a stale
    command set and no audit at all.
    """
    global PACKAGE_ERROR
    PACKAGE_ERROR = None
    _purge_cached_package()
    tried = []
    for root in _candidate_repo_roots():
        if not root or not os.path.isdir(os.path.join(root, "nokia_network_audit")):
            tried.append("%s (no nokia_network_audit directory)" % root)
            continue
        if root not in sys.path:
            sys.path.insert(0, root)
        try:
            from nokia_network_audit.audit import AuditEngine
            from nokia_network_audit.chain import (
                SEED_ENV_VAR,
                ChainPlan,
                WalkState,
                hop_targets,
                max_walk_devices,
                management_subnet,
                seed_targets,
                seeds_from_environment,
                seeds_outside_subnet,
                spans_needing_shelves,
                unaccounted_lags,
            )
            from nokia_network_audit.cli import _load
            from nokia_network_audit.graph import correlate_optical_channels
            from nokia_network_audit.models import AuditSnapshot
            from nokia_network_audit.profiles import (
                PROFILES,
                is_paging_command,
                is_read_only_command,
                session_commands,
            )
            from nokia_network_audit.report import write_json, write_markdown
        except Exception as exc:
            tried.append("%s (%s: %s)" % (root, type(exc).__name__, exc))
            _purge_cached_package()
            continue
        return (
            {
                "AuditEngine": AuditEngine,
                "AuditSnapshot": AuditSnapshot,
                "PROFILES": PROFILES,
                "_load": _load,
                "chain": {
                    "ChainPlan": ChainPlan,
                    "SEED_ENV_VAR": SEED_ENV_VAR,
                    "max_walk_devices": max_walk_devices,
                    "WalkState": WalkState,
                    "hop_targets": hop_targets,
                    "management_subnet": management_subnet,
                    "seed_targets": seed_targets,
                    "seeds_outside_subnet": seeds_outside_subnet,
                    "seeds_from_environment": seeds_from_environment,
                    "spans_needing_shelves": spans_needing_shelves,
                    "unaccounted_lags": unaccounted_lags,
                },
                "correlate_optical_channels": correlate_optical_channels,
                "is_paging_command": is_paging_command,
                "is_read_only_command": is_read_only_command,
                "session_commands": session_commands,
                "write_json": write_json,
                "write_markdown": write_markdown,
            },
            root,
        )
    PACKAGE_ERROR = "; ".join(tried) if tried else "no candidate repository root"
    return None, None


def profile_commands(pkg, profile_name):
    """Ordered command list for ``profile_name``, paging setup first."""
    if pkg:
        return list(pkg["session_commands"](pkg["PROFILES"][profile_name]))
    spec = _FALLBACK_PROFILES[profile_name]
    return [spec["paging_command"]] + list(spec["commands"])


def profile_names(pkg):
    return sorted(pkg["PROFILES"] if pkg else _FALLBACK_PROFILES)


def assert_read_only(pkg, commands):
    """Re-check every command here, in-process, right before it is sent."""
    if pkg:
        ok_show = pkg["is_read_only_command"]
        ok_page = pkg["is_paging_command"]
    else:

        def ok_show(command):
            return " ".join(command.strip().lower().split()).startswith("show ")

        def ok_page(command):
            return " ".join(command.strip().lower().split()) in _ALLOWED_PAGING

    unsafe = [c for c in commands if not (ok_show(c) or ok_page(c))]
    if unsafe:
        raise RuntimeError(
            "Refusing to run; these are not read-only commands:\n  "
            + "\n  ".join(unsafe)
        )


# --------------------------------------------------------------------------
# Terminal interaction
# --------------------------------------------------------------------------


def detect_prompt():
    """Return the session's current prompt string.

    Reads the prompt off the *screen* rather than the read stream, because the
    stream has no notion of "the current line".
    """
    crt.Screen.Send("\r")
    time.sleep(0.5)
    row = crt.Screen.CurrentRow
    col = crt.Screen.CurrentColumn - 1
    if col < 1:
        return ""
    return crt.Screen.Get(row, 1, row, col).rstrip()


def drain(prompt, attempts=4):
    """Consume anything already waiting in the read stream.

    Learning the prompt costs a bare carriage return, and the prompt the device
    emits in reply lands in the read stream where nothing consumes it. Left
    there, it satisfies the *next* command's read immediately -- so that command
    returns the previous exchange's tail, and every command after it drifts one
    character further. Clearing the stream first keeps reads aligned with sends.
    """
    for _ in range(attempts):
        crt.Screen.ReadString(prompt, 1)
        if crt.Screen.MatchIndex == 0:
            return


def send_command(prompt, command, timeout=COMMAND_TIMEOUT):
    """Send one command and return its output, or ``None`` on timeout."""
    crt.Screen.Send(command + "\r")
    # Re-synchronise on the device's echo of this exact command before reading
    # its output. This is what makes the read immune to a stale prompt sitting
    # in the stream: WaitForString skips forward to our echo instead of letting
    # the leftover prompt terminate the read early.
    crt.Screen.WaitForString(command, ECHO_TIMEOUT)
    collected = []
    deadline = time.monotonic() + timeout
    while True:
        remaining = max(1, int(deadline - time.monotonic()))
        chunk = crt.Screen.ReadString([prompt] + list(PAGER_MATCHES), remaining)
        index = crt.Screen.MatchIndex
        if index == 0:  # timeout
            collected.append(chunk or "")
            return None
        collected.append(chunk or "")
        if index == 1:  # the prompt: command finished
            break
        crt.Screen.Send(" ")  # a pager slipped through; page past it
        if time.monotonic() >= deadline:
            return None
    text = "".join(collected).replace("\r\n", "\n").replace("\r", "\n")
    # Drop the device's echo of the command itself.
    lines = text.split("\n")
    if lines and lines[0].strip() == command.strip():
        lines = lines[1:]
    return "\n".join(lines).strip("\n")


def looks_like_error(output):
    """True when the device rejected the command, rather than answering it.

    Matched per line and anchored, never as a substring of the whole output.
    A 7705 SAR-8 answers ``show system information`` with a field reading
    ``Microwave S/W Package  : invalid`` -- a legitimate value. Treating a bare
    "invalid" anywhere as failure made every 7705 look unidentifiable, so the
    walk silently skipped all twenty of them while capturing every 7250.
    """
    if not output or not output.strip():
        return True
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(("Error:", "MINOR:", "MAJOR:", "CRITICAL:")):
            return True
        # SR OS points at a syntax error with a caret on its own line.
        if stripped == "^":
            return True
    return False


def looks_like_sros_prompt(prompt):
    """SR OS prompts carry a CPM letter, e.g. "*A:HOST#"; the 1830's is bare."""
    return bool(re.match(r"^\*?[A-Za-z]:[^:]", prompt or ""))


def detect_platform(prompt):
    """Best-effort platform detection. Returns a profile name or ``None``.

    The prompt shape decides which probe to try first, so the common case costs
    one command instead of two and does not leave an error on the device: asking
    a router for ``show general system-identification`` prints
    "Error: Invalid parameter." into its session and the transcript.
    """
    if not looks_like_sros_prompt(prompt):
        identity = send_command(prompt, "show general system-identification", 30)
        if identity and not looks_like_error(identity):
            return "1830-pss-8", identity

    system = send_command(prompt, "show system information", 30)
    if system and not looks_like_error(system):
        lowered = system.lower()
        if "7705" in lowered:
            return "7705-sar-8", system
        if "ixr-r6dl" in lowered:
            return "7250-ixr-r6dl", system
        if "ixr-r6d" in lowered:
            return "7250-ixr-r6d", system
        if "7250" in lowered or "ixr" in lowered:
            return "7250-ixr-r6", system
        return None, system

    if looks_like_sros_prompt(prompt):
        # The prompt suggested SR OS but the probe failed; fall back rather than
        # give up on a device whose prompt is simply unusual.
        identity = send_command(prompt, "show general system-identification", 30)
        if identity and not looks_like_error(identity):
            return "1830-pss-8", identity
    return None, ""


def choose_profile(pkg, detected, ask=True):
    """Pick the profile, asking only when there is a real choice to make.

    Detection reads the platform out of the device's own ``show system
    information``. When that succeeds there is nothing for a human to add, and
    in a chained run the dialog appears once per device -- so it only asks when
    detection came back empty.
    """
    names = profile_names(pkg)
    if detected in names and not ask:
        return detected
    listing = "\n".join("  %d. %s" % (i + 1, n) for i, n in enumerate(names))
    default = str(names.index(detected) + 1) if detected in names else ""
    heading = (
        "Detected platform: %s\n\nPress OK to accept, or enter a different number."
        % detected
        if detected
        else "Could not identify the platform automatically.\n\nEnter a number."
    )
    answer = crt.Dialog.Prompt(
        "%s\n\n%s" % (heading, listing), "Nokia Network Audit", default, False
    )
    if not answer:
        return None
    answer = answer.strip()
    if answer.isdigit() and 1 <= int(answer) <= len(names):
        return names[int(answer) - 1]
    if answer in names:
        return answer
    crt.Dialog.MessageBox("Not a valid selection: %s" % answer, "Nokia Network Audit", 16)
    return None


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def safe_name(value):
    keep = []
    for ch in (value or "").strip():
        keep.append(ch if (ch.isalnum() or ch in "._-") else "_")
    return ("".join(keep).strip("._") or "device")[:60]


def hostname_from_prompt(prompt):
    """The device's own name, taken from its prompt.

    Available before any command is sent, and it is what the device calls
    itself -- so a run directory is named MOPN002_7705 rather than whichever
    address happened to reach it. A chained hop reaches a router by its system
    address while a direct session uses its management address; naming by
    address made the same device look like two.
    """
    text = (prompt or "").strip()
    match = re.match(r"^\*?[A-Za-z]:([^#>\s]+)", text)  # SR OS: "*A:HOST>ctx#"
    if match:
        return match.group(1)
    match = re.match(r"^([\w.\-]+)\s*#", text)  # 1830: "HOST#"
    if match:
        return match.group(1)
    return ""


def session_label(prompt):
    name = hostname_from_prompt(prompt)
    if name:
        return name
    for attr in ("RemoteAddress", "Label", "Path"):
        try:
            value = getattr(crt.Session, attr)
        except Exception:
            continue
        if value:
            return str(value).replace("\\", "_").split("_")[-1] or str(value)
    return prompt.strip(" >#$") or "device"


def build_transcript(host, profile_name, prompt, results):
    stamp = datetime.now(timezone.utc)
    parts = [
        "\n".join(
            [
                "# Nokia Network Audit raw baseline transcript",
                "# Host: %s" % host,
                "# Profile: %s" % profile_name,
                "# Captured UTC: %s" % stamp.isoformat(),
                "# Source: SecureCRT session (read-only operational queries)",
                "",
            ]
        )
    ]
    # The prompt is captured rstripped so screen padding cannot break matching;
    # put the separator back when rebuilding the echo line.
    echo_prompt = prompt if prompt.endswith((" ", "\t")) else prompt + " "
    for command, output in results:
        parts.append("\n# COMMAND: %s\n" % command)
        # Reproduce the prompt+echo line so the transcript parser can split on
        # command boundaries exactly as it does for a plain terminal log.
        parts.append("%s%s" % (echo_prompt, command))
        parts.append(output if output is not None else "# ERROR: command timed out")
    return "\n".join(parts) + "\n"


def run_offline_audit(pkg, transcript_path, output_dir):
    """Parse the transcript and write audit.json / audit.md next to it."""
    snapshot = pkg["AuditSnapshot"](
        metadata={"created_at": datetime.now(timezone.utc).isoformat()}
    )
    device = pkg["_load"](_as_path(transcript_path), "auto")
    snapshot.devices[device.device_id] = device
    pkg["correlate_optical_channels"](snapshot)
    findings = pkg["AuditEngine"]().run(snapshot)
    pkg["write_json"](snapshot, _as_path(os.path.join(output_dir, "audit.json")))
    pkg["write_markdown"](snapshot, _as_path(os.path.join(output_dir, "audit.md")))
    return device, findings


def _as_path(value):
    from pathlib import Path

    return Path(value)


# --------------------------------------------------------------------------
# Chained capture
# --------------------------------------------------------------------------

# What a router says between "ssh 10.0.0.9" and a usable prompt.
#
# These must match only the *question being asked*, never the surrounding
# chatter. An earlier version listed "key fingerprint", which matches the purely
# informational "ECDSA key fingerprint is SHA256:..." line printed before the
# question -- so a reply was sent while the device was still talking. Anything
# sent when nothing is being asked lands on the CLI as a command, and with a
# password of "admin" that silently entered SR OS's admin context and left the
# origin prompt permanently changed.
_PASSWORD_CUES = ("'s password:", "Password:", "password:")
_USERNAME_CUES = ("Username:", "username:")
# A getty asks "login:" before any CLI exists. On the 1830 the account taken
# here ("cli") has no password and is not the identity the device ends up
# logged in as -- the CLI behind it asks separately. A router never shows this.
_GETTY_CUES = ("login:",)
_HOSTKEY_CUES = ("continue connecting", "Please type 'yes'")
_FAILURE_CUES = (
    "Connection refused",
    "Connection closed",
    "closed by foreign host",
    "Connection timed out",
    "No route to host",
    "Network is unreachable",
    "Permission denied",
    "Authentication failed",
    "Too many authentication failures",
)


class HopAborted(RuntimeError):
    """A hop could not be completed, or the session is not where expected."""


def expect(options, timeout):
    """Read until one of ``options`` appears.

    Returns ``(index, text)`` where index is 1-based into ``options`` (0 on
    timeout) and text is everything read before the match -- the device's own
    output, which is where a key fingerprint has to be picked up from.
    """
    text = crt.Screen.ReadString(list(options), timeout)
    return crt.Screen.MatchIndex, (text or "")


_FINGERPRINT_RE = re.compile(
    r"key fingerprint is\s+(?P<value>[A-Za-z0-9]+:[A-Za-z0-9+/=:]+)", re.IGNORECASE
)


def fingerprints(text):
    """Every key fingerprint the ssh client printed, in order."""
    return [m.group("value") for m in _FINGERPRINT_RE.finditer(text or "")]


class HostKeyPolicy:
    """How to answer "the authenticity of host ... can't be established".

    SR OS offers no way to suppress the question -- its ssh client takes only
    ``-l``, ``router``, ``re-exchange-*`` and ``-p`` -- so it must be answered
    once per unknown host. Asking the operator each time meant 36 dialogs in a
    40-device walk and would mean ~180 on the full network, which is not a
    decision anyone makes carefully the hundredth time.

    So the choice is made once, up front, and every key actually accepted is
    recorded with its fingerprint so the run leaves a trail.
    """

    ASK = "ask"
    ACCEPT = "accept"

    def __init__(self, mode=ASK):
        self.mode = mode
        self.accepted = []  # (address, fingerprint)
        self.refused = []

    def decide(self, target, seen_text):
        found = fingerprints(seen_text)
        fingerprint = found[0] if found else "unknown"
        if self.mode == self.ACCEPT:
            self.accepted.append((target.address, fingerprint))
            return True
        answer = crt.Dialog.MessageBox(
            "%s presented an unrecognised host key.\n\n%s\n\n"
            "Accept it and continue connecting?"
            % (target.display, "\n".join(found) or "(no fingerprint seen)"),
            "Nokia Network Audit",
            4 | 48,  # Yes/No + warning
        )
        if answer == 6:  # IDYES
            self.accepted.append((target.address, fingerprint))
            return True
        self.refused.append(target.address)
        return False

    def summary(self):
        lines = []
        if self.accepted:
            lines.append(
                "Host keys accepted (%s):"
                % ("no prompt, chosen once for this walk"
                   if self.mode == self.ACCEPT else "confirmed individually")
            )
            for address, fingerprint in self.accepted:
                lines.append("  %s  %s" % (address, fingerprint))
        for address in self.refused:
            lines.append("  %s: host key refused" % address)
        return lines


def ensure_at_origin(origin_prompt, attempts=4):
    """Get the session back to the origin's root context, or report failure.

    Called before every hop as well as after a failed one. A hop that fails
    part-way can leave the session somewhere unexpected -- logged into the far
    device, or on the origin but inside a CLI sub-context -- and typing the next
    hop command from there is how a run goes badly wrong.
    """
    for _ in range(attempts):
        prompt = detect_prompt()
        if prompt == origin_prompt:
            drain(origin_prompt)
            return True
        here = hostname_from_prompt(prompt)
        if not here:
            # Not a device prompt at all -- most likely still inside the ssh
            # client, at its password prompt. Words typed here are login
            # attempts, so abort with an interrupt, which cannot be read as one.
            crt.Screen.Send(chr(3))
        elif here == hostname_from_prompt(origin_prompt):
            # Right device, wrong context (e.g. "A:HOST>admin#"). Back out.
            crt.Screen.Send("exit all\r")
        else:
            # Logged into something else.
            crt.Screen.Send("logout\r")
        crt.Screen.ReadString([origin_prompt], 10)
    return detect_prompt() == origin_prompt


def hop_to(target, origin_prompt, username, password, hostkey=None):
    """Open a session on ``target``, trying each login it offers in turn.

    Optical shelves do not agree on how to log in. Some take the getty account
    with no password and then ask the CLI for its own identity; others refuse
    that account and take the CLI user straight over ssh. Both exist on the same
    network at the same release, so the shape is discovered rather than assumed:
    the first login is tried, and only a credential refusal moves on to the next.

    Each account is attempted in its own ssh session, so the "one password per
    account" rule is not weakened -- a refusal ends that attempt rather than
    licensing more guesses at the same login.
    """
    logins = target.login_sequence()
    for index, login in enumerate(logins):
        attempt = target.with_login(login) if login != target.login_user else target
        try:
            return _hop_once(attempt, origin_prompt, username, password, hostkey)
        except HopAborted as exc:
            last = index == len(logins) - 1
            if last or not _login_was_refused(exc):
                raise
    raise HopAborted("no login succeeded for %s" % target.display)


def _login_was_refused(exc):
    """Whether a failed hop is worth retrying as a different account.

    A shelf that rejects the account drops the session rather than saying so:
    live output is three password prompts followed by "Connection closed by
    foreign host", which arrives as a refusal rather than as rejected
    credentials depending on which cue is seen first. Both mean the same thing
    here. Anything else -- no route, a declined host key, an unreachable host --
    would fail identically as any other account, so it is raised immediately
    rather than doubling the time spent failing.
    """
    text = str(exc).lower()
    return "credentials rejected" in text or "connection closed" in text


def _hop_once(target, origin_prompt, username, password, hostkey=None):
    """One ssh attempt as one account.

    Returns the far device's prompt. The command is rebuilt and re-validated by
    ``HopTarget.command()`` immediately before being typed, so the only string
    that can reach the router is a bare ssh/telnet to the approved address.

    Nothing is ever sent speculatively. Each reply goes out only in response to
    the matching question, because anything typed when the device is not asking
    is executed as a CLI command instead.
    """
    if not ensure_at_origin(origin_prompt):
        raise HopAborted(
            "Not at %s before hopping; refusing to type a hop command from an "
            "unknown context." % origin_prompt
        )

    command = target.command()
    crt.Screen.Send(command + "\r")

    hostkey = hostkey or HostKeyPolicy()
    cues = list(
        _PASSWORD_CUES + _USERNAME_CUES + _GETTY_CUES + _HOSTKEY_CUES + _FAILURE_CUES
    )
    deadline = time.monotonic() + HOP_TIMEOUT
    password_prompts = 0
    getty_seen = False
    getty_password_replies = 0
    cli_user_sent = False
    failure = None
    seen = ""
    # A seeded shelf carries its own identities; a discovered router uses the
    # walk's.
    hop_username = getattr(target, "username", None) or username
    hop_password = getattr(target, "password", None) or password
    getty_user = getattr(target, "login_user", None) or hop_username
    while time.monotonic() < deadline:
        index, text = expect(cues, 5)
        seen += text
        if index == 0:
            break  # nothing recognised; fall through to prompt detection
        cue = cues[index - 1]
        if cue in _PASSWORD_CUES:
            # Two logins, two identities. Anything asked before the CLI has
            # requested its own username belongs to the account ssh is
            # authenticating -- the getty ("cli"), which carries no password.
            # Answering it with the CLI password spends the single permitted
            # attempt on the wrong account: one shelf asks
            # "cli@10.9.102.99's password:" where its siblings go straight to
            # "Username:", and sending "admin" there got the connection closed
            # with the real login never reached.
            #
            # Both shapes are covered without needing to know which to expect:
            # no prompt at all before "Username:" is the common case, and a
            # prompt at that point is answered empty. Bounded to one reply --
            # a device that keeps asking is refusing, and looping would burn
            # the whole hop deadline sending blank lines. If it asks a second
            # time the configured password is tried once, in case that account
            # does carry one, and a third ask ends the hop: two attempts, never
            # a loop.
            getty_stage = not cli_user_sent and (
                getty_seen or (getty_user and getty_user != hop_username)
            )
            if getty_stage and getty_password_replies < 1:
                getty_password_replies += 1
                crt.Screen.Send("\r")
                continue
            password_prompts += 1
            if password_prompts > 1:
                # The device asked again, so the credentials were rejected.
                # Sending them a second time achieves nothing and walks toward
                # an account lockout.
                failure = "credentials rejected by %s" % target.display
                break
            crt.Screen.Send(hop_password + "\r")
        elif cue in _GETTY_CUES:
            getty_seen = True
            crt.Screen.Send((getty_user or "") + "\r")
        elif cue in _USERNAME_CUES:
            cli_user_sent = True
            crt.Screen.Send((hop_username or "") + "\r")
        elif cue in _HOSTKEY_CUES:
            # Accepting an unknown key is a security decision. It stays the
            # operator's, but is taken once per walk rather than once per host.
            if not hostkey.decide(target, seen):
                crt.Screen.Send("no\r")
                failure = "host key for %s was not accepted" % target.display
                break
            crt.Screen.Send("yes\r")
        else:
            failure = "%s refused the session (%s)" % (target.display, cue)
            break

    if failure is None:
        prompt = detect_prompt()
        if prompt and prompt != origin_prompt:
            drain(prompt)
            return prompt
        failure = "did not reach %s" % target.display

    # However it went wrong, leave the session where the caller expects it. The
    # ssh client may still be waiting at its own password prompt, so interrupt
    # it first rather than typing anything it could read as a login attempt.
    crt.Screen.Send(chr(3))
    if not ensure_at_origin(origin_prompt):
        raise HopAborted(
            "%s, and the session did not come back to %s. Check it before "
            "running anything else." % (failure, origin_prompt)
        )
    raise HopAborted(failure)


def hop_back(current_prompt, origin_prompt):
    """Return to the origin device and prove we got there.

    Guarded on the prompt having actually changed: sending ``logout`` while still
    on the origin would drop the operator's own session.
    """
    if not current_prompt or current_prompt == origin_prompt:
        raise HopAborted(
            "Refusing to log out: the session already looks like the origin."
        )
    crt.Screen.Send("logout\r")
    # Wait for the origin prompt to arrive on its own rather than polling with
    # carriage returns: each poll emits another prompt into the read stream, and
    # an unconsumed prompt is exactly what desynchronises later reads. A live run
    # spent 43 needless keystrokes here before this.
    crt.Screen.ReadString([origin_prompt], HOP_TIMEOUT)
    if crt.Screen.MatchIndex != 1:
        raise HopAborted(
            "Could not get back to %s after capturing. The session is left where "
            "it is; check it before running anything else." % origin_prompt
        )
    drain(origin_prompt)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main():
    if not crt.Session.Connected:
        crt.Dialog.MessageBox(
            "Connect a session first, then press the audit button.",
            "Nokia Network Audit",
            16,
        )
        return

    crt.Screen.Synchronous = True
    crt.Screen.IgnoreEscape = True
    try:
        _run()
    finally:
        crt.Screen.Synchronous = False


def capture_here(pkg, prompt, host, confirm=True, interactive=True):
    """Capture and audit the device the session is currently on.

    Returns ``(summary_lines, device)``; ``device`` is None when the audit step
    did not run.

    ``interactive=False`` is used mid-walk: an unrecognised platform is recorded
    and skipped rather than raising a dialog. A walk across a large network will
    meet models this tool has no profile for, and stopping on each one to ask a
    human defeats the point of walking.
    """
    detected, _identity = detect_platform(prompt)
    known = detected in profile_names(pkg)
    if not known and not interactive:
        return ["  %s: platform not recognised, skipped" % host], None
    # Only interrupt when detection could not decide; otherwise the device has
    # already told us what it is.
    profile_name = choose_profile(pkg, detected, ask=not known)
    if not profile_name:
        return None, None

    commands = profile_commands(pkg, profile_name)
    assert_read_only(pkg, commands)

    if confirm:
        answer = crt.Dialog.MessageBox(
            "Run the %s baseline against %s?\n\n"
            "%d commands will be sent. All are read-only.\n\n%s"
            % (profile_name, host, len(commands), "\n".join(commands)),
            "Nokia Network Audit",
            1 | 32,  # OK/Cancel + question icon
        )
        if answer != 1:  # IDOK
            return None, None

    results = []
    failed = []
    for index, command in enumerate(commands, start=1):
        try:
            crt.Session.SetStatusText(
                "Nokia audit: %d/%d  %s" % (index, len(commands), command)
            )
        except Exception:
            pass
        output = send_command(prompt, command)
        if output is None:
            failed.append(command)
        results.append((command, output))
    try:
        crt.Session.SetStatusText("")
    except Exception:
        pass

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base_dir = os.environ.get("NOKIA_AUDIT_OUTPUT") or DEFAULT_OUTPUT_DIR
    output_dir = os.path.join(base_dir, "%s_%s_%s" % (host, safe_name(profile_name), stamp))
    os.makedirs(output_dir, exist_ok=True)
    transcript_path = os.path.join(output_dir, "transcript.txt")
    with open(transcript_path, "w", encoding="utf-8") as handle:
        handle.write(build_transcript(host, profile_name, prompt, results))

    summary = ["%s -> %s" % (host, transcript_path)]
    if failed:
        summary.append("  timed out: %s" % ", ".join(failed))

    device = None
    if pkg:
        try:
            device, findings = run_offline_audit(pkg, transcript_path, output_dir)
            counts = {}
            for finding in findings:
                counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
            summary.append(
                "  %s  platform=%s  ports=%d  lags=%d  channels=%d"
                % (
                    device.device_id,
                    device.platform.value,
                    len(device.ports),
                    len(device.lags),
                    len(device.optical_channels),
                )
            )
            summary.append(
                "  findings: "
                + (", ".join("%s=%d" % kv for kv in sorted(counts.items())) or "none")
            )
        except Exception as exc:  # keep the transcript even if parsing fails
            summary.append("  audit step failed: %s: %s" % (type(exc).__name__, exc))
    else:
        summary.append(
            "  !! TRANSCRIPT ONLY - the audit package did not load, so this run "
            "used the script's built-in fallback command list, wrote no audit, "
            "and cannot walk."
        )
        summary.append("     %s" % (PACKAGE_ERROR or "reason unknown"))
        summary.append("     Set %s to the repository root." % REPO_ENV_VAR)
    return summary, device


def ask_for_seeds(chain, missing, preset, summary, origin_device=None):
    """Ask for the addresses of shelves the walk has proven it cannot reach.

    Asked at the end rather than the start, and only when there is something to
    ask about: by then the walk knows exactly which sites hold an optical shelf
    (a coherent pluggable is talking to a line system) and which channels it
    carries, so the question names them instead of asking blind on every run.

    Pre-filled from %s when that is set. A rejected entry is refused rather than
    dropped, because a mistyped seed looks exactly like a device that was never
    found -- and a seed exists precisely because nothing else will find it.
    """ % chain["SEED_ENV_VAR"]
    described = ", ".join(
        "%s (ch %s)" % (site, "/".join(channels)) if channels else site
        for site, channels in missing
    )
    default = " ".join(
        target.address if not target.label else "%s=%s" % (target.address, target.label)
        for target in preset
    )
    subnet = chain["management_subnet"](origin_device) if origin_device else None
    reach = ""
    if subnet:
        reach = (
            "\n\nThese are reached in the management routing instance from %s, "
            "whose management interface is %s -- so expect addresses in %s/%d."
            % (origin_device.device_id, origin_device.management_ip, subnet[0], subnet[1])
        )
    try:
        answer = crt.Dialog.Prompt(
            "The walk found %d site(s) whose links run over a DWDM line "
            "system, but no optical shelf there was captured:\n\n  %s\n\n"
            "No router names these -- a transparent wavelength shows the "
            "far-end router, never the shelf -- so they can only be reached by "
            "address. Seed one per span and the walk follows to its partner.%s\n\n"
            "Addresses separated by spaces, or blank to finish."
            % (len(missing), described, reach),
            "Nokia Network Audit - optical shelves not captured",
            default,
            False,
        )
    except Exception:
        return []
    if answer is None:
        return []
    answer = answer.strip()
    if not answer:
        return []
    try:
        seeds = chain["seed_targets"](answer)
        outside = chain["seeds_outside_subnet"](seeds, subnet)
        if outside:
            # Not refused: the management instance may hold routes beyond its own
            # subnet. But every seed of a live run was off by two octets and the
            # only symptom was "No route to destination" once the walk had already
            # finished, so say it plainly and up front.
            summary.append(
                "  WARNING: %s outside %s/%d and probably unreachable from %s"
                % (
                    ", ".join(t.address for t in outside),
                    subnet[0],
                    subnet[1],
                    origin_device.device_id if origin_device else "the origin",
                )
            )
            crt.Dialog.MessageBox(
                "These addresses are outside %s/%d, the management network of "
                "%s:\n\n  %s\n\nThey will be tried anyway, but unless the "
                "management instance has a route beyond its own subnet each will "
                "fail with \"No route to destination\"."
                % (
                    subnet[0],
                    subnet[1],
                    origin_device.device_id if origin_device else "the origin",
                    ", ".join(t.address for t in outside),
                ),
                "Nokia Network Audit - seeds outside the management subnet",
                48,  # warning icon
            )
        return seeds
    except Exception as exc:
        crt.Dialog.MessageBox(
            "%s\n\nNo extra devices were added; the rest of the walk is "
            "unaffected." % exc,
            "Nokia Network Audit - seed list",
            16,  # error icon
        )
        summary.append("  seed list rejected: %s" % exc)
        return []


def chain_from(pkg, origin_device, origin_prompt, summary):
    """Offer to hop to the origin's routed neighbours and capture each.

    Depth is one on purpose for now: each hop returns to the origin before the
    next, so the session is only ever one level deep and the way back is a single
    verified step. Recursing would multiply the number of places the session can
    be stranded.
    """
    if pkg is None or origin_device is None:
        return
    chain = pkg["chain"]
    visited = set(origin_device.identities())
    targets = chain["hop_targets"](origin_device, visited=visited)
    if not targets:
        return

    plan = chain["ChainPlan"](origin=origin_device.device_id, targets=targets)
    try:
        plan.validate()
    except Exception as exc:
        summary.append("Chained capture unavailable: %s" % exc)
        return

    username, _password = hop_credentials()
    for target in targets:
        target.username = username
    answer = crt.Dialog.MessageBox(
        "Network walk from %s.\n\n"
        "%d neighbour(s) are known now, and the walk follows the topology "
        "outward from there, so it will reach devices not on this list -- up to "
        "%d in total.\n\n"
        "Every hop is made from %s as %s and logged out of before the next, so "
        "the session never goes deeper than one level.\n\n%s\n\n"
        "Only bare ssh/telnet commands are used to open a session; each device "
        "then gets the same read-only baseline."
        % (origin_device.device_id, len(targets), chain["max_walk_devices"](),
           origin_device.device_id, username, plan.summary()),
        "Nokia Network Audit - network walk",
        4 | 32,  # Yes/No + question
    )
    if answer != 6:  # IDYES
        return

    username, password = hop_credentials()

    # One decision about host keys, not one per device. SR OS cannot suppress
    # the question, so on a large walk this is otherwise a dialog per hop.
    answer = crt.Dialog.MessageBox(
        "Each device not already known to %s will present an unrecognised host "
        "key, and SR OS has no option to skip that question.\n\n"
        "Accept them automatically for this walk?\n\n"
        "Yes  - accept every key, and list each one with its fingerprint in the "
        "summary.\n"
        "No   - ask about each device individually (one dialog per hop)."
        % origin_device.device_id,
        "Nokia Network Audit - host keys",
        4 | 48,  # Yes/No + warning
    )
    hostkey = HostKeyPolicy(
        HostKeyPolicy.ACCEPT if answer == 6 else HostKeyPolicy.ASK
    )

    state = chain["WalkState"](origin=origin_device.device_id, visited=set(visited))
    state.enqueue(targets)
    state.captured.append(origin_device.device_id)
    devices = [origin_device]

    summary.append("")
    summary.append("Network walk:")
    stranded = False
    asked_for_seeds = False
    while True:
        target = state.next_target()
        if target is None:
            # The routed topology is exhausted. Anything left is equipment no
            # router can name, and only now is it known which sites those are
            # -- so the question is asked once, here, naming them.
            if asked_for_seeds or state.budget_left <= 0:
                break
            asked_for_seeds = True
            missing = chain["spans_needing_shelves"](devices)
            if not missing:
                break
            preset = []
            try:
                preset = chain["seeds_from_environment"](username=username)
            except Exception as exc:
                summary.append("  seed list from environment ignored: %s" % exc)
            seeds = ask_for_seeds(chain, missing, preset, summary, origin_device)
            for seed in seeds:
                seed.username = seed.username or username
            added = state.enqueue(seeds)
            if not added:
                break
            summary.append(
                "  seeded %s" % ", ".join(t.display for t in added)
            )
            continue
        if state.budget_left <= 0:
            summary.append(
                "  stopped at the %d-device limit; %d still queued"
                % (state.max_devices, len(state.queue) + 1)
            )
            break

        far_prompt = None
        try:
            crt.Session.SetStatusText(
                "Nokia walk: %d done, %d queued - %s"
                % (len(state.captured), len(state.queue), target.display)
            )
        except Exception:
            pass
        try:
            far_prompt = hop_to(
                target, origin_prompt, username, password, hostkey=hostkey
            )
            far_host = safe_name(session_label(far_prompt) or target.address)
            lines, far_device = capture_here(
                pkg, far_prompt, far_host, confirm=False, interactive=False
            )
            summary.extend(lines or ["  %s: capture skipped" % target.display])
            if far_device is not None:
                state.mark_visited(far_device.identities())
                state.captured.append(far_device.device_id)
                devices.append(far_device)
                # Every hop is made from the origin, so a newly discovered
                # neighbour is reachable without going through this device.
                found = state.enqueue(
                    chain["hop_targets"](
                        far_device, visited=state.visited, username=username
                    )
                )
                if found:
                    summary.append(
                        "    discovered %s"
                        % ", ".join(t.display for t in found)
                    )
            else:
                state.mark_visited({target.address})
        except HopAborted as exc:
            state.failed[target.address] = str(exc)
            state.mark_visited({target.address})
            summary.append("  %s: %s" % (target.display, exc))
        except Exception as exc:
            state.failed[target.address] = "%s: %s" % (type(exc).__name__, exc)
            state.mark_visited({target.address})
            summary.append("  %s: %s: %s" % (target.display, type(exc).__name__, exc))
        # Always attempt the return, whatever happened above -- but do not
        # return out of a finally block, which would discard an in-flight
        # exception and hide why the walk stopped.
        if far_prompt:
            try:
                hop_back(far_prompt, origin_prompt)
            except HopAborted as exc:
                summary.append("  STOPPED: %s" % exc)
                stranded = True
                break
    try:
        crt.Session.SetStatusText("")
    except Exception:
        pass
    if stranded:
        return

    key_lines = hostkey.summary()
    if key_lines:
        summary.append("")
        summary.extend(key_lines)

    summary.append("")
    unaccounted = chain["unaccounted_lags"](devices)
    if unaccounted:
        summary.append("LAGs whose far end was not reached:")
        for device_id, lag_id, partner in unaccounted:
            summary.append("  %s lag-%s (partner %s)" % (device_id, lag_id, partner))
    else:
        summary.append("Every LAG seen has both ends captured.")


def _run():
    pkg, repo_root = load_audit_package()

    prompt = detect_prompt()
    if not prompt:
        crt.Dialog.MessageBox(
            "Could not read the session prompt. Make sure the session is at an "
            "idle CLI prompt and try again.",
            "Nokia Network Audit",
            16,
        )
        return
    drain(prompt)

    host = safe_name(session_label(prompt))
    try:
        summary, device = capture_here(pkg, prompt, host)
    except RuntimeError as exc:
        crt.Dialog.MessageBox(str(exc), "Nokia Network Audit", 16)
        return
    if summary is None:
        return

    chain_from(pkg, device, prompt, summary)
    crt.Dialog.MessageBox("\n".join(summary), "Nokia Network Audit", 64)


main()
