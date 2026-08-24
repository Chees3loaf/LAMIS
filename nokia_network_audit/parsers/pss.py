from __future__ import annotations

import re

from ..models import (
    Adjacency,
    Alarm,
    Device,
    DeviceKind,
    Evidence,
    OpticalChannel,
    Platform,
)
from ..wavelengths import sfdc8b_channels
from .common import (
    capture_host,
    field,
    is_absent,
    split_command_sections,
    strip_ansi,
)


# ``show slot *`` / ``show card inventory *`` rows: ``  1/10 SFDC8B  SFDC8B``.
SFDC8B_SLOT_RE = re.compile(r"^[ \t]*(\d+/\d+)[ \t]+SFDC8B\b", re.IGNORECASE | re.MULTILINE)

# ``show interface sfdc8b *`` channel rows. The AID's last field is the ITU
# channel number in units of 10 GHz above 100 THz (``9330`` -> 193.30 THz):
#
#   1/10/9330 Channel      ITU#33                    Bi  Down  Down
CHANNEL_ROW_RE = re.compile(
    r"^[ \t]*(?P<aid>\d+/\d+/(?P<chan>\d{4}))[ \t]+Channel[ \t]+"
    r"(?P<desc>\S+)[ \t]+(?P<dir>\S+)[ \t]+(?P<admin>Up|Down)[ \t]+(?P<oper>Up|Down)",
    re.IGNORECASE | re.MULTILINE,
)

# ``show condition`` rows, e.g.
#   NR NSA   00/01/28 06:45:26 OCH      OPR-OUT   1/2/LINEOUT Out 9310.000
#   CR SA    00/01/27 07:18:41 EQPT     PWR       1/7
# followed by an indented human-readable description line.
# Leading whitespace is required, not optional: the 1830 wraps critical rows in
# an SGR colour sequence, so stripping the escape leaves the row indented by the
# space that sat between "\x1b[1;31m" and "CR".
CONDITION_RE = re.compile(
    r"^[ \t]*(?P<sev>CR|MJ|MN|NR|WR)[ \t]+(?P<sa>SA|NSA)[ \t]+"
    r"(?P<stamp>\S+[ \t]+\S+)[ \t]+(?P<type>\S+)[ \t]+"
    r"(?P<cond>\S+)[ \t]*(?P<subject>.*?)[ \t]*$",
    re.MULTILINE,
)

# ``show interface topology *`` rows:
#   1/10/9310  Ext  10.9.102.132              Ext  10.9.102.132
#   1/2/LINEIN   -                            Ext  10.9.102.132 1/3/4
TOPOLOGY_RE = re.compile(
    r"^[ \t]*(?P<local>\d+/\d+(?:/\S+)?)[ \t]+"
    r"(?P<to_type>Int|Ext|-)[ \t]+(?P<to>\S+(?:[ \t]+\S+)?)[ \t]*$"
    r"|^[ \t]*(?P<local2>\d+/\d+(?:/\S+)?)[ \t]+"
    r"(?P<to_type2>Int|Ext|-)[ \t]+(?P<to2>.*?)[ \t]{2,}"
    r"(?P<from_type>Int|Ext|-)[ \t]+(?P<from>.*?)[ \t]*$",
    re.MULTILINE,
)


def channel_frequency_thz(channel_number: str) -> float:
    """``9330`` -> 193.30 THz (100 THz plus the AID's 10 GHz units)."""
    return round(100.0 + int(channel_number) / 100.0, 2)


def _hostname(text: str) -> str:
    for pattern in (
        r"^[ \t]*System Name[ \t]*:[ \t]*(\S+)",
        r"^[ \t]*(?:TID|NE Name)[ \t]*:[ \t]*(\S+)",
        r"(?:^|\n)([A-Za-z][\w.-]*)#[ \t]*show\b",
    ):
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1)
    return "unknown-pss"


def _platform(text: str) -> Platform:
    shelf = field(text, "Shelf type") or ""
    if "pss-8" in shelf.lower() or re.search(r"\bPSS-8\b", text):
        return Platform.PSS_8
    return Platform.UNKNOWN


def _parse_channels(text: str) -> dict[str, OpticalChannel]:
    """Build channels from what the card actually reports, not a static plan."""
    channels: dict[str, OpticalChannel] = {}
    for match in CHANNEL_ROW_RE.finditer(text):
        aid = match.group("aid")
        channel = OpticalChannel(
            channel_id=aid,
            frequency_thz=channel_frequency_thz(match.group("chan")),
            admin_state=match.group("admin").lower(),
            oper_state=match.group("oper").lower(),
        )
        channel.finalize()
        channels[aid] = channel
    return channels


def _parse_alarms(body: str) -> list[Alarm]:
    alarms: list[Alarm] = []
    lines = body.split("\n")
    for index, line in enumerate(lines):
        match = CONDITION_RE.match(line)
        if not match:
            continue
        subject = match.group("subject").strip() or None
        # The following indented line carries the plain-language description.
        description = None
        if index + 1 < len(lines):
            following = lines[index + 1]
            if following.startswith((" ", "\t")) and following.strip():
                description = re.split(r"[ \t]{3,}", following.strip())[0] or None
        alarms.append(
            Alarm(
                severity=match.group("sev"),
                condition=match.group("cond"),
                subject=subject,
                description=description,
                service_affecting=match.group("sa") == "SA",
                raised_at=match.group("stamp").strip(),
            )
        )
    return alarms


def _parse_topology(body: str) -> list[Adjacency]:
    """Read ``show interface topology *``.

    Each row is ``<local> <to-type> <connected-to> <from-type> <connected-from>``
    and either direction may be ``-``. Both are recorded: a port whose
    "Connected To" is ``-`` can still name a real far end under
    "Connected From", which is how the OSC line-in ports report their peer.
    """
    adjacencies: list[Adjacency] = []
    for line in body.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith(("Interface", "---")):
            continue
        match = re.match(r"^[ \t]*(\d+/\d+(?:/\w+)?)[ \t]+(.*)$", line)
        if not match:
            continue
        local, rest = match.group(1), match.group(2)
        # Pair each direction marker with the text that follows it.
        for scope, target in re.findall(
            r"\b(Int|Ext)\b[ \t]+((?:(?!\b(?:Int|Ext)\b)[^\s])"
            r"(?:[ \t]?(?!\b(?:Int|Ext)\b)\S)*)",
            rest,
        ):
            parts = target.split()
            if not parts or parts[0] == "-":
                continue
            adjacencies.append(
                Adjacency(
                    local_port=local,
                    remote=parts[0],
                    remote_port=parts[1] if len(parts) > 1 else None,
                    scope=scope,
                )
            )
    # A bidirectional channel names the same far end under both "Connected To"
    # and "Connected From", so the row yields the identical adjacency twice.
    unique: list[Adjacency] = []
    seen = set()
    for adjacency in adjacencies:
        key = (
            adjacency.local_port,
            adjacency.remote,
            adjacency.remote_port,
            adjacency.scope,
        )
        if key not in seen:
            seen.add(key)
            unique.append(adjacency)
    return unique


def parse_pss_transcript(text: str, source: str = "transcript") -> Device:
    text = strip_ansi(text)
    hostname = _hostname(text)
    device = Device(
        device_id=hostname,
        hostname=hostname,
        kind=DeviceKind.OPTICAL,
        platform=_platform(text),
        evidence=[Evidence(source=source, detail="Parsed 1830 PSS transcript")],
    )
    device.management_ip = capture_host(text)
    release = field(text, "Release")
    if release and not is_absent(release):
        device.software_release = release
    serial = field(text, "Serial number")
    if serial and not is_absent(serial):
        device.serial_number = serial

    sections = split_command_sections(text)

    def body_for(*prefixes: str) -> str:
        matched = [
            body
            for command, body in sections.items()
            if any(command.lower().startswith(p) for p in prefixes)
        ]
        return "\n".join(matched) if matched else text

    # Prefer the channels the card reports. Fall back to the documented SFDC8B
    # plan only when the interface listing was not captured, so a partial
    # transcript still yields the eight channels for a populated slot.
    device.optical_channels.update(_parse_channels(body_for("show interface sfdc8b")))
    if not device.optical_channels:
        for slot in sorted(set(SFDC8B_SLOT_RE.findall(text))):
            device.optical_channels.update(sfdc8b_channels(slot))

    device.alarms = _parse_alarms(body_for("show condition"))
    device.adjacencies = _parse_topology(body_for("show interface topology"))

    # An OPR-OUT condition names the offending channel frequency (``9310.000``);
    # tie it back to the channel so the finding points at a real object.
    for alarm in device.alarms:
        match = re.search(r"\b(\d{4})\.\d+\b", alarm.subject or "")
        if not match:
            continue
        frequency = channel_frequency_thz(match.group(1))
        for channel in device.optical_channels.values():
            if channel.frequency_thz == frequency:
                channel.circuit_id = channel.circuit_id or alarm.condition

    device.finalize()
    return device
