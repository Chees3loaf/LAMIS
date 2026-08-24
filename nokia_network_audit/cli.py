from __future__ import annotations

import argparse
import glob
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from .audit import AuditEngine
from .graph import correlate_optical_channels, correlate_reported_adjacencies
from .models import AuditSnapshot
from .parsers import parse_pss_transcript, parse_sros_transcript
from .report import write_json, write_markdown


TRANSCRIPT_SUFFIXES = (".txt", ".log")

# Platform detection has to be structural. Testing for the substring "1830"
# matched a 7250 transcript because the digits appear inside the packet counter
# 6183078 -- across a 200 KB capture full of counters that is close to certain.
# Each marker below is anchored to a label, an echoed command, or a prompt.
_PSS_MARKERS = (
    r"^[ \t]*Shelf type[ \t]*:",
    r"^[ \t]*Product[ \t]*:[ \t]*1830\b",
    r"\b1830PSS[\w.-]*-",
    r"^[ \t]*show general\b",
    r"^[ \t]*show shelf inventory\b",
    r"\bSFDC8[A-E]\b",
    r"^[ \t]*paging status\b",
)

_SROS_MARKERS = (
    r"\bTiMOS\b",
    r"^[ \t]*System Type[ \t]*:.*\b(?:7705|7250|7750|7450|7950)\b",
    r"^[ \t]*environment no more\b",
    r"^\*?[A-Za-z]:[\w.\-]+(?:>[\w.\-]*)*#",
    r"^[ \t]*show card state\b",
    r"^[ \t]*show lag\b",
)


def _score(text: str, markers: tuple[str, ...]) -> int:
    return sum(
        1
        for marker in markers
        if re.search(marker, text, re.IGNORECASE | re.MULTILINE)
    )


def detect_transcript_type(text: str) -> str:
    """Return ``"pss"`` or ``"sros"`` from structural markers in the text."""
    return "pss" if _score(text, _PSS_MARKERS) > _score(text, _SROS_MARKERS) else "sros"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nokia-network-audit",
        description="Standalone transcript-first Nokia topology and health audit.",
        epilog=(
            "Arguments may be files, directories, or wildcards. PowerShell does "
            "not expand wildcards for this command, so they are expanded here."
        ),
    )
    parser.add_argument("transcripts", nargs="+")
    parser.add_argument(
        "--type",
        choices=("auto", "sros", "pss"),
        default="auto",
        help="Transcript platform; auto detects 1830/PSS text.",
    )
    parser.add_argument("--output", type=Path, default=Path("audit-output"))
    return parser


def _transcripts_in(directory: Path):
    """The transcript files directly inside ``directory``."""
    for child in directory.iterdir():
        if child.is_file() and child.suffix.lower() in TRANSCRIPT_SUFFIXES:
            yield child


def resolve_inputs(patterns: list[str]) -> tuple[list[Path], list[str]]:
    """Expand arguments into transcript files.

    Wildcards are expanded here rather than left to the shell: PowerShell passes
    ``*.txt`` through verbatim to a native command, so a glob that works in bash
    would otherwise arrive as a literal filename. Directories expand to the
    ``.txt``/``.log`` files they contain, and -- because the capture button writes
    one ``<device>_<platform>_<timestamp>/transcript.txt`` directory per shelf --
    to those held one level down as well. Pointing at the capture root is the
    obvious thing to do with a walk's worth of output, and it used to report that
    the directory held no transcripts at all.

    Returns the files found and the arguments that matched nothing.
    """
    found: list[Path] = []
    missing: list[str] = []
    for pattern in patterns:
        path = Path(pattern)
        if path.is_dir():
            matches = sorted(_transcripts_in(path))
            if not matches:
                matches = sorted(
                    transcript
                    for child in path.iterdir()
                    if child.is_dir()
                    for transcript in _transcripts_in(child)
                )
        elif any(char in pattern for char in "*?["):
            matches = sorted(Path(p) for p in glob.glob(pattern) if Path(p).is_file())
        elif path.is_file():
            matches = [path]
        else:
            matches = []
        if matches:
            found.extend(matches)
        else:
            missing.append(pattern)
    # Preserve order while dropping repeats (a file named twice, or matched by
    # both a directory and a wildcard).
    unique: list[Path] = []
    seen = set()
    for path in found:
        key = path.resolve()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique, missing


def _explain_missing(missing: list[str]) -> str:
    lines = ["Could not find these transcripts:"]
    lines += [f"  {name}" for name in missing]
    hints = []
    for name in missing:
        path = Path(name)
        if path.is_dir():
            suffixes = "/".join(TRANSCRIPT_SUFFIXES)
            hints.append(
                f"  {path} exists but holds no {suffixes} files, in it or in "
                "any directory directly inside it."
            )
            continue
        parent = path.parent
        if parent != Path("") and not parent.exists():
            hints.append(f"  {parent}\\ does not exist.")
            continue
        if parent.exists():
            siblings = sorted(
                child.name
                for child in parent.iterdir()
                if child.is_file() and child.suffix.lower() in TRANSCRIPT_SUFFIXES
            )
            if siblings:
                shown = ", ".join(siblings[:8])
                more = "" if len(siblings) <= 8 else f", ... (+{len(siblings) - 8})"
                hints.append(f"  {parent} contains: {shown}{more}")
            else:
                hints.append(f"  {parent} has no .txt or .log files in it.")
    if hints:
        lines.append("")
        lines.extend(dict.fromkeys(hints))
    lines.append("")
    lines.append(
        "Save a terminal log of the device session (SecureCRT: File > Log "
        "Session), or press the audit button to capture one, then point at it. "
        "Sample captures ship in tests_network_audit/fixtures."
    )
    return "\n".join(lines)


def looks_like_command_list(text: str) -> bool:
    """True when the file is a list of commands to run, not device output.

    ``baseline_commands/*.txt`` holds the commands to type at a device; a
    capture is what the device printed back. The two are easy to mix up, and
    feeding the former in yields a device with no ports and no LAGs -- a report
    that looks successful but describes nothing.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return False
    payload = [line for line in lines if not line.startswith("#")]
    if not payload:
        return False
    commands = sum(
        1
        for line in payload
        if line.lower().startswith(("show ", "environment ", "paging "))
    )
    # Device output always carries far more than the echoed commands.
    return commands == len(payload)


def _label(path: Path) -> str:
    """Enough of a path to tell two captures apart.

    Every run writes a file called ``transcript.txt``; the run directory is what
    carries the host and timestamp, so naming the file alone identifies nothing.
    """
    parent = path.parent.name
    return f"{parent}/{path.name}" if parent else path.name


def capture_time(path: Path, text: str) -> float:
    """When a transcript was taken, for choosing between two of the same device.

    The header the capture tooling writes is authoritative; a plain terminal log
    has none, so fall back to the file's own timestamp.
    """
    match = re.search(r"^#[ \t]*Captured UTC[ \t]*:[ \t]*(\S+)", text, re.MULTILINE)
    if match:
        from datetime import datetime

        try:
            return datetime.fromisoformat(match.group(1)).timestamp()
        except ValueError:
            pass
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _load(path: Path, requested_type: str):
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        raise ValueError(f"{path} is empty")
    if looks_like_command_list(text):
        raise ValueError(
            f"{path} looks like a command list rather than device output "
            "(every line is a command). Run these commands on the device and "
            "save what it prints back"
        )
    transcript_type = requested_type
    if transcript_type == "auto":
        transcript_type = detect_transcript_type(text)
    parser = parse_pss_transcript if transcript_type == "pss" else parse_sros_transcript
    return parser(text, source=str(path))


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    transcripts, missing = resolve_inputs(args.transcripts)
    if missing:
        print(_explain_missing(missing), file=sys.stderr)
        return 2
    if not transcripts:
        print("No transcripts to audit.", file=sys.stderr)
        return 2

    snapshot = AuditSnapshot(
        metadata={"created_at": datetime.now(timezone.utc).isoformat()}
    )
    loaded: dict[str, tuple[Path, float]] = {}
    superseded: list[str] = []
    for transcript in transcripts:
        try:
            text = transcript.read_text(encoding="utf-8", errors="replace")
            device = _load(transcript, args.type)
        except (OSError, ValueError) as exc:
            print(f"Could not read {transcript}: {exc}", file=sys.stderr)
            return 2
        taken = capture_time(transcript, text)
        previous = loaded.get(device.device_id)
        if previous is not None:
            # Re-capturing a device is normal -- a chained run revisits one, and
            # you re-run after a change. Audit the newer transcript rather than
            # refusing the whole batch, but say which one was set aside.
            keep_new = taken >= previous[1]
            older = previous[0] if keep_new else transcript
            newer = transcript if keep_new else previous[0]
            superseded.append(
                f"  {device.device_id}: using {_label(newer)}, "
                f"skipping older {_label(older)}"
            )
            if not keep_new:
                continue
        # A capture that yields a name but nothing else is the signature of a log
        # holding only the commands -- a desynchronised read, or a file saved
        # before the output came back. Every kind of parsed content counts, so a
        # deliberately narrow capture (system health, or LLDP alone) is not
        # reported as suspect: warning about a good file teaches you to ignore
        # the warning.
        if not any(
            (
                device.ports,
                device.lags,
                device.optical_channels,
                device.alarms,
                device.adjacencies,
                device.router_interfaces,
                # These three are records, not containers, so they are truthy
                # even when every field is unset -- ``reported`` is the emptiness
                # test the audit rules use.
                device.chassis.reported,
                device.timing.reported,
                device.redundancy.reported,
                device.cpu,
            )
        ):
            print(
                f"Warning: {transcript} parsed as {device.device_id!r} but yielded "
                "no ports, LAGs, channels, alarms, adjacencies, or system state. "
                "Check that it contains the device's output and not just the "
                "commands.",
                file=sys.stderr,
            )
        snapshot.devices[device.device_id] = device
        loaded[device.device_id] = (transcript, taken)

    # Device-reported far ends first, so frequency correlation only has to
    # reason about channels nothing has already claimed.
    correlate_reported_adjacencies(snapshot)
    correlate_optical_channels(snapshot)
    AuditEngine().run(snapshot)
    args.output.mkdir(parents=True, exist_ok=True)
    write_json(snapshot, args.output / "audit.json")
    write_markdown(snapshot, args.output / "audit.md")
    for device_id, (transcript, _taken) in sorted(loaded.items()):
        device = snapshot.devices[device_id]
        print(f"  {device_id:<18} {device.platform.value:<14} {transcript}")
    if superseded:
        print("Superseded by a newer capture:")
        for line in superseded:
            print(line)
    print(
        f"Audited {len(snapshot.devices)} devices, found {len(snapshot.links)} "
        f"candidate links and {len(snapshot.findings)} findings."
    )
    print(f"Reports: {args.output.resolve()}")
    return 0
