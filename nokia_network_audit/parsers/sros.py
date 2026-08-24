from __future__ import annotations

import re

from ..models import (
    Adjacency,
    ChassisHealth,
    ExternalAlarmInput,
    SystemTiming,
    TimingReference,
    Redundancy,
    CpuUsage,
    Device,
    DeviceKind,
    Evidence,
    Lag,
    LagMember,
    Optic,
    Platform,
    Port,
    PowerThresholds,
    RouterInterface,
)
from .common import (
    banner_blocks,
    capture_host,
    field as field_value,
    first_field,
    is_absent,
    normalize_state,
    split_command_sections,
    strip_ansi,
)


# Real port IDs are not all ``slot/mda/port``. A 7250 IXR-R6 reports connector
# and breakout ports (``1/1/c7``, ``1/1/c7/1``) and CPM/GNSS ports carry a
# letter slot (``A/1``, ``B/gnss``).
PORT_ID_RE = r"[0-9A-Za-z]+(?:/[0-9A-Za-z]+)+"

INTERFACE_LINE_RE = re.compile(
    rf"^[ \t]*Interface[ \t]*:[ \t]*({PORT_ID_RE})[ \t]*(?:[ \t][A-Za-z].*)?$",
    re.MULTILINE,
)

# ``show lag detail`` heads each LAG either as ``Lag-id : 2 Lag-name : lag-2``
# (7250 IXR) or as ``LAG 2`` (7705 SAR). Both appear between ``---`` rules.
LAG_SECTION_RE = re.compile(
    r"^[ \t]*(?:Lag-id[ \t]*:[ \t]*(\d+)[ \t]+Lag-name|LAG[ \t]+(\d+))[ \t]*.*$",
    re.MULTILINE,
)

# Member row: ``1/1/1  up  active  up  yes  1  -  1``. The trailing LACP table
# repeats the port with ``actor``/``partner`` in column two, so anchoring on
# up/down in that position keeps the two tables apart.
LAG_MEMBER_RE = re.compile(
    rf"^[ \t]*({PORT_ID_RE})[ \t]+(up|down)[ \t]+(active|standby)[ \t]+(up|down)\b",
    re.IGNORECASE | re.MULTILINE,
)

# ``show lag`` summary: ``2  up  up  No  0  2  N/A``.
LAG_SUMMARY_RE = re.compile(
    r"^[ \t]*(\d+)[ \t]+(up|down)[ \t]+(up|down)[ \t]+\S+", re.IGNORECASE | re.MULTILINE
)

# DDM / coherent power rows put the live reading in the first numeric column:
#
#   Tx Output Power (dBm)         -2.25      2.50       0.50      -8.20     -10.20
#   Rx Total Power (dBm)           5.88      2.87     -99.00       5.88
#
# Anchoring at line start is what keeps the per-lane *threshold* rows
# ("Lane Tx Output Power (dBm)"), which have no value column, out of the match.
DDM_ROW_RE = re.compile(
    r"^[ \t]*(Tx Output Power|Rx Optical Power|Tx Total Power|Rx Total Power)"
    r"[^:\n]*?\(.*?dBm\)[ \t]+(-?\d+\.\d+)",
    re.IGNORECASE | re.MULTILINE,
)

# Value + High Alarm / High Warn / Low Warn / Low Alarm, as printed for a
# directly-modulated pluggable:
#   Rx Optical Power (avg dBm)    -1.58      2.50       0.50     -14.40     -16.40
DDM_LIMITS_RE = re.compile(
    r"^[ \t]*(Tx Output Power|Rx Optical Power)[^:\n]*?\(.*?dBm\)"
    r"[ \t]+(-?\d+\.\d+)[ \t]+(-?\d+\.\d+)[ \t]+(-?\d+\.\d+)"
    r"[ \t]+(-?\d+\.\d+)[ \t]+(-?\d+\.\d+)",
    re.IGNORECASE | re.MULTILINE,
)

# A coherent module prints thresholds per lane, with no value column:
#   Lane Rx Optical Pwr (avg dBm)          2.00        1.00      -21.02      -23.01
LANE_LIMITS_RE = re.compile(
    r"^[ \t]*Lane[ \t]+(Tx Output Power|Rx Optical Pwr)[^:\n]*?\(.*?dBm\)"
    r"[ \t]+(-?\d+\.\d+)[ \t]+(-?\d+\.\d+)[ \t]+(-?\d+\.\d+)[ \t]+(-?\d+\.\d+)",
    re.IGNORECASE | re.MULTILINE,
)

# Note: a DDM section's title and its data rows are separated by a banner, so
# they land in different blocks. Power is therefore applied from any non-port
# block that follows a port; DDM_ROW_RE is specific enough that statistics
# sections cannot contribute a false reading.


# ``show router interface`` prints each interface across two lines:
#
#   to_MOPN001_7705                  Up        Up/Down     Network lag-2
#      172.18.6.106/31                                             n/a
ROUTER_IF_RE = re.compile(
    r"^(?P<name>[A-Za-z_][\w.\-]*)[ \t]+(?P<adm>Up|Down)[ \t]+"
    r"(?P<opr>\S+)[ \t]+(?P<mode>\S+)[ \t]+(?P<port>\S+)[ \t]*$"
    r"\n[ \t]+(?P<addr>\d+\.\d+\.\d+\.\d+/\d+)",
    re.IGNORECASE | re.MULTILINE,
)

# ``show router ospf neighbor``: the Rtr Id is the peer's system address.
OSPF_NEIGHBOUR_RE = re.compile(
    r"^(?P<name>[A-Za-z_][\w.\-]*)[ \t]+(?P<rtrid>\d+\.\d+\.\d+\.\d+)[ \t]+"
    r"(?P<state>\w+)[ \t]+\d+",
    re.MULTILINE,
)

# ``show router ldp session``: "172.16.245.193:0  Link  Established  ..."
LDP_SESSION_RE = re.compile(
    r"^(?P<peer>\d+\.\d+\.\d+\.\d+):\d+[ \t]+\S+[ \t]+(?P<state>\w+)", re.MULTILINE
)

# ``show system lldp neighbor``, from live 7705 SAR-8 v2 output:
#
#   Lcl Port      Scope Remote Chassis ID  Index  Remote Port     Remote Sys Name
#   1/2/6         NB    24:F6:8D:3C:90:00  1      1/2/2, 1-Gig/1* MOPN001_7250
#
# The Remote Port column is fixed width and truncated with "*", carrying the port
# and its description ("1/2/2, 1-Gig/1*"), so only the part before the comma is
# the port. The remote system name is the final token, which is what lets the
# truncated middle column be captured loosely without swallowing it.
#
# An earlier attempt at this pattern, written with no sample to work from,
# matched ``show port`` summary rows instead ("1/3/1 Down No Down" read as
# port/peer/peer-port) and invented 54 adjacencies on a device that had none.
# Hence: anchored columns, and parsed only from this command's own section.
LLDP_ROW_RE = re.compile(
    r"^(?P<local>\S+)[ \t]+(?P<scope>NB|NTPMR|NC)[ \t]+"
    r"(?P<chassis>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})[ \t]+"
    r"(?P<index>\d+)[ \t]+(?P<rest>.*?)[ \t]*$",
    re.MULTILINE,
)

# The column where "Remote Sys Name" starts, measured from the real header rather
# than assumed, so a release that pads differently still reads correctly.
LLDP_HEADER_RE = re.compile(
    r"^(?P<lead>.*?Remote[ \t]+Port[ \t]+)Remote[ \t]+Sys[ \t]+Name[ \t]*$",
    re.MULTILINE,
)


def _lldp_row_fields(line: str, rest_offset: int, name_column: int | None):
    """Split a row's trailing text into remote port and remote system name.

    A system name can contain spaces -- a microwave radio reports ``MSS SiteA``
    -- so taking the last whitespace-delimited word silently truncated it to
    ``SiteA``, and that truncated name then became a device on the capture
    worklist. The table is column-aligned (SR OS marks an over-long value with
    ``*`` precisely to preserve the columns), so the split comes from the header.
    """
    if (
        name_column is not None
        and rest_offset <= name_column < len(line)
        and line[name_column - 1] in " \t"
    ):
        name = line[name_column:].strip()
        if name:
            return line[rest_offset:name_column].strip(), name
    # No header, or a row that does not line up with it: fall back to treating
    # the last word as the name, which is right whenever it holds no space.
    parts = line[rest_offset:].rsplit(None, 1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1]
    return "", line[rest_offset:].strip()


def _lldp_adjacencies(text: str) -> list[Adjacency]:
    """Port-level neighbours, independent of any routing protocol.

    LLDP is the only source that pairs *member* ports: OSPF sees a LAG as one
    interface, so it can never say which member reaches which far-end port. The
    Remote Chassis ID is the peer's base MAC -- the same value it presents as its
    LACP System Id -- giving a third join key alongside OSPF Router Id and the
    /31 pairing.
    """
    header = LLDP_HEADER_RE.search(text)
    name_column = len(header.group("lead")) if header else None
    found = []
    for match in LLDP_ROW_RE.finditer(text):
        line = match.group(0)
        port_text, sysname = _lldp_row_fields(
            line, match.start("rest") - match.start(), name_column
        )
        if not sysname:
            continue
        remote_port = port_text.split(",")[0].strip() or None
        found.append(
            Adjacency(
                local_port=match.group("local"),
                remote=sysname,
                remote_port=remote_port,
                remote_label=sysname,
                scope="Ext",
                protocol="lldp",
                remote_ip=None,
                remote_chassis_id=match.group("chassis").lower(),
            )
        )
    return found

# Port descriptions look like adjacency data -- "MOPN001_7250 1/1/1 to
# MOPN001_7705 1/1/5" -- but they are hand-written and this network shows why
# they cannot carry a link: the 7250 gives *both* 1/1/1 and 1/2/1 the same text,
# because it was copied between LAG members. Believing it produced a confident
# link from 1/2/1 to a port that 1/2/1 does not touch. Peer *names* now come
# from the interface name instead (see peer_label), which sits on the same
# object as the protocol adjacency that proves the link.


# "Tel/Tel6/SSH/FTP Admin : Disabled/Disabled/Enabled/Disabled"
REMOTE_ACCESS_RE = re.compile(
    r"^[ \t]*Tel/Tel6/SSH/FTP[ \t]+Admin[ \t]*:[ \t]*"
    r"(?P<telnet>\w+)/(?P<telnet6>\w+)/(?P<ssh>\w+)/(?P<ftp>\w+)",
    re.IGNORECASE | re.MULTILINE,
)


# "          IN-1   1    Critical      : ok"
EXTERNAL_ALARM_RE = re.compile(
    r"^[ \t]*(?P<id>IN-\d+)[ \t]+\d+[ \t]+(?P<sev>\w+)[ \t]*:[ \t]*(?P<state>\S+)",
    re.MULTILINE,
)

# "show external-alarms input" rows:
#   alarm.d-1                  Digital-In Up     Open   Ok
#   port-1/5/1   CABINET-DOOR  Oper-State Up     Down   Alarm-Detected
EXTERNAL_ALARM_ROW_RE = re.compile(
    r"^[ \t]*(?P<id>(?:alarm|relay)[\w.\-]*|port-\d+/\d+/\S+)[ \t]+"
    r"(?:(?P<name>\S+)[ \t]+)??"
    r"(?P<type>Digital-In|Analog-In|Oper-State)[ \t]+"
    r"(?P<admin>\S+)[ \t]+(?P<value>\S+)[ \t]+(?P<state>\S+)[ \t]*$",
    re.MULTILINE,
)

# Per-component "Current alarm state : alarm cleared". The component is whatever
# block the line sits in, so the preceding banner/heading is what names it.
COMPONENT_ALARM_RE = re.compile(
    r"^[ \t]*Current alarm state[ \t]*:[ \t]*(?P<state>.+?)[ \t]*$", re.MULTILINE
)


def _chassis_health(text: str) -> ChassisHealth:
    """Read the alarm state a classic chassis reports about itself.

    All of this already arrives in ``show chassis detail`` -- it simply was not
    being looked at, so routers reported no alarm state at all while the 1830s
    got proper findings from ``show condition``.
    """
    health = ChassisHealth(
        critical_led=field_value(text, "Critical LED state"),
        major_led=field_value(text, "Major LED state"),
        minor_led=field_value(text, "Minor LED state"),
        over_temperature=field_value(text, "Over Temperature state"),
    )

    for match in EXTERNAL_ALARM_RE.finditer(text):
        health.external_inputs.append(
            ExternalAlarmInput(
                input_id=match.group("id"),
                severity=match.group("sev"),
                state=match.group("state"),
            )
        )
    for match in EXTERNAL_ALARM_ROW_RE.finditer(text):
        health.external_inputs.append(
            ExternalAlarmInput(
                input_id=match.group("id"),
                name=match.group("name"),
                state=match.group("state"),
            )
        )

    # A component whose alarm state is anything but cleared is worth naming. The
    # nearest preceding non-indented heading identifies it.
    lines = text.split("\n")
    heading = None
    for line in lines:
        stripped = line.strip()
        if stripped and not line.startswith((" ", "\t")) and not set(stripped) <= set("=-"):
            heading = stripped
        match = COMPONENT_ALARM_RE.match(line)
        if not match:
            continue
        state = match.group("state").strip()
        if state.lower() not in {"alarm cleared", "cleared", "ok", "no alarm"}:
            health.components_in_alarm.append(
                "%s: %s" % (heading or "chassis", state)
            )
    return health


# "System Status CPM A                : Master Locked"
#
# The documentation says "CSM A"; a live 7705 SAR-8 v2 says **CPM A**. Hardcoding
# either one loses the status entirely -- and with it the only signal that says
# whether the node is locked -- so the card label is read rather than assumed.
TIMING_STATUS_RE = re.compile(
    r"^[ \t]*System Status[ \t]+(?P<card>[A-Z]{2,4}[ \t]+[A-Z])[ \t]*:"
    r"[ \t]*(?P<state>.+?)[ \t]*$",
    re.MULTILINE,
)

# Each reference is introduced by a bare heading, then indented fields:
#
#   Reference Input 1
#       Admin Status                   : up
#   External Reference Input
#       Admin Status                   : down
#
# Real headings include "Reference Input 1..3", "External Reference Input" and
# "External Reference Output"; the docs also show "Reference BITS 1/2". Rather
# than enumerate them, a heading is any line mentioning a reference that carries
# no colon -- which is what separates it from "Reference Order : ref1 ref2".
TIMING_REF_RE = re.compile(
    r"^[ \t]*(?P<name>(?:External[ \t]+)?Reference(?:[ \t]+[\w\-]+)*)[ \t]*$",
    re.MULTILINE,
)


def _system_timing(text: str) -> SystemTiming:
    """Parse ``show system sync-if-timing``.

    Grounded in the output example in the 7705 SAR Basic System Configuration
    Guide 25.10.R1 (show>system sync-if-timing). That example is for a
    **SAR-18**, which has BITS references the SAR-8 and 7250 IXR do not, so this
    reads whatever reference blocks are present rather than expecting a fixed
    set. Fields are matched by label, never by position.
    """
    timing = SystemTiming(
        reference_mode=field_value(text, "Reference Input Mode"),
        quality_level_selection=field_value(text, "Quality Level Selection"),
        reference_order=field_value(text, "Reference Order"),
        selected_reference=field_value(text, "Reference Selected"),
        system_quality_level=field_value(text, "System Quality Level"),
    )
    for match in TIMING_STATUS_RE.finditer(text):
        card = " ".join(match.group("card").split())
        timing.status[card] = match.group("state").strip()

    starts = list(TIMING_REF_RE.finditer(text))
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        block = text[match.end() : end]
        timing.references.append(
            TimingReference(
                name=" ".join(match.group("name").split()),
                admin_state=field_value(block, "Admin Status"),
                qualified=field_value(block, "Qualified For Use"),
                selected=field_value(block, "Selected For Use"),
                not_qualified_reason=field_value(block, "Not Qualified Due To"),
                not_selected_reason=field_value(block, "Not Selected Due To"),
                rx_quality=field_value(block, "Rx Quality Level"),
                source_port=None
                if is_absent(field_value(block, "Source Port"))
                else field_value(block, "Source Port"),
            )
        )
    return timing


def _redundancy(text: str) -> Redundancy:
    """Parse ``show redundancy synchronization``.

    Grounded in live 7705 SAR-8 v2 output; the classic documentation carries no
    example for this command, only prose that it exists.
    """
    return Redundancy(
        standby_status=field_value(text, "Standby Status"),
        last_failure=field_value(text, "Last Standby Failure"),
        failover_time=field_value(text, "Failover Time"),
        failover_reason=field_value(text, "Failover Reason"),
        config_sync_mode=field_value(text, "Boot/Config Sync Mode"),
        config_sync_status=field_value(text, "Boot/Config Sync Status"),
        last_config_sync=field_value(text, "Last Config File Sync Time"),
    )


# "IOM                                     388,488           6.51%          15.76%"
# Usage columns can read "~0.00%" for "non-zero but below resolution".
CPU_ROW_RE = re.compile(
    r"^(?P<name>\S.*?)[ \t]{2,}(?P<time>[\d,]+)[ \t]+(?P<usage>~?[\d.]+%)"
    r"[ \t]+(?P<capacity>~?[\d.]+%)[ \t]*$",
    re.MULTILINE,
)


def _cpu(text: str) -> list[CpuUsage]:
    """Parse ``show system cpu`` rows. Reported, never audited.

    A threshold for "too busy" depends on the network's own baseline, so this is
    collected for the report rather than turned into a finding.
    """
    rows = []
    for match in CPU_ROW_RE.finditer(text):
        rows.append(
            CpuUsage(
                name=" ".join(match.group("name").split()),
                cpu_usage=match.group("usage"),
                capacity_usage=match.group("capacity"),
            )
        )
    return rows


def _remote_access(text: str) -> dict[str, bool]:
    match = REMOTE_ACCESS_RE.search(text)
    if not match:
        return {}
    return {
        name: match.group(name).strip().lower() == "enabled"
        for name in ("telnet", "telnet6", "ssh", "ftp")
    }


def _platform(text: str) -> Platform:
    # Anchor on the reported System Type / chassis Type so unrelated mentions of
    # a model number elsewhere in the transcript cannot vote.
    match = re.search(r"^[ \t]*(?:System )?Type[ \t]*:[ \t]*(.+)$", text, re.MULTILINE)
    candidate = (match.group(1) if match else text).lower()
    for probe in (candidate, text.lower()):
        if "7705" in probe and "sar-8" in probe:
            return Platform.SAR_7705_8
        if "ixr-r6dl" in probe:
            return Platform.IXR_R6DL
        if "ixr-r6d" in probe:
            return Platform.IXR_R6D
        if "7250" in probe and "ixr-r6" in probe:
            return Platform.IXR_R6
    return Platform.UNKNOWN


def _hostname(text: str) -> str | None:
    for pattern in (
        r"^[ \t]*System Name[ \t]*:[ \t]*(\S+)",
        r"^[ \t]*Name[ \t]*:[ \t]*(\S+)",
        r"(?:^|\n)\*?[AB]:([^#\s>]+)#",
    ):
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1)
    return None


def _release(text: str) -> str | None:
    # ``System Version : B-25.10.R2`` is the cleanest source; the boot header
    # (``TiMOS-B-25.10.R2 both/hops64``) is the fallback.
    version = field_value(text, "System Version")
    if version and not is_absent(version):
        return version
    match = re.search(r"TiMOS-([A-Za-z0-9.\-]+)", text)
    return match.group(1) if match else None


def _optic(block: str) -> Optic | None:
    status = field_value(block, "Transceiver Status")
    if status is None or status.lower() == "not-equipped":
        return None
    optic = Optic(
        port_id="",
        part_number=field_value(block, "Part Number"),
        serial_number=field_value(block, "Serial Number"),
        model=field_value(block, "Model Number"),
    )
    # Coherent/tunable pluggables report frequency in MHz.
    freq = first_field(block, "Oper Freq (MHz)", "Config Freq (MHz)")
    if freq and freq.replace(".", "").isdigit():
        optic.frequency_thz = round(float(freq) / 1_000_000, 6)
    # "DCO : Enabled" marks a digital-coherent module. Both a grey QSFP28 and a
    # coherent ZR print a wavelength, so the frequency alone is not the test --
    # the grey optic simply has no Oper Freq, and DCO states it outright.
    optic.coherent = (field_value(block, "DCO") or "").lower() == "enabled"
    optic.tunability = field_value(block, "Laser Tunability")
    _apply_power(optic, block)
    return optic


# "Rx S1 Byte         : 0x0a (st3)" -- the raw byte and the quality it encodes.
S1_BYTE_RE = re.compile(
    r"^[ \t]*(?P<direction>Rx|Tx)[ \t]+S1[ \t]+Byte[ \t]*:[ \t]*"
    r"(?P<byte>0x[0-9A-Fa-f]+)(?:[ \t]*\((?P<quality>[\w\-]+)\))?",
    re.MULTILINE,
)

# "Rx K1/K2 Byte      : 0x00/0x00" -- APS signalling, meaningful only when a
# protection group exists, which on this network it never does.
K1_K2_RE = re.compile(
    # Printed in the right-hand column, sharing a line with the Rx S1 byte, so
    # this cannot be anchored to line start the way the S1 fields are.
    r"(?:^|[ \t]{2,})Rx[ \t]+K1/K2[ \t]+Byte[ \t]*:[ \t]*"
    r"(?P<k1>0x[0-9A-Fa-f]+)[ \t]*/[ \t]*(?P<k2>0x[0-9A-Fa-f]+)",
    re.MULTILINE,
)


def _apply_sonet(port: Port, block: str) -> None:
    """Read the SONET-only fields a port block carries.

    The S1 byte is the reason a node can report "Master Locked" and still be at
    ``st3``: it is the synchronisation quality the far end is advertising, and it
    is carried nowhere else. Three live 7705s take their reference from an OC3
    port whose ``Rx S1`` reads ``0x0a (st3)``, which is exactly the quality they
    then report as their own -- unreadable from the Ethernet-shaped fields.
    """
    state = port.sonet
    for match in S1_BYTE_RE.finditer(block):
        quality = (match.group("quality") or "").lower() or None
        if match.group("direction") == "Rx":
            state.rx_s1 = match.group("byte")
            state.rx_s1_quality = quality
        else:
            state.tx_s1 = match.group("byte")
            state.tx_s1_quality = quality
    keys = K1_K2_RE.search(block)
    if keys is not None:
        state.rx_k1, state.rx_k2 = keys.group("k1"), keys.group("k2")
    state.clock_source = state.clock_source or field_value(block, "Clock Source")
    state.ber_sd_threshold = state.ber_sd_threshold or field_value(
        block, "BER SD Threshold"
    )
    state.ber_sf_threshold = state.ber_sf_threshold or field_value(
        block, "BER SF Threshold"
    )


def _apply_power(optic: Optic, block: str) -> None:
    for match in DDM_ROW_RE.finditer(block):
        value = float(match.group(2))
        if match.group(1).lower().startswith("tx"):
            optic.tx_dbm = value
        else:
            optic.rx_dbm = value
    for regex, has_value in ((DDM_LIMITS_RE, True), (LANE_LIMITS_RE, False)):
        for match in regex.finditer(block):
            numbers = [float(g) for g in match.groups()[1:]]
            if has_value:
                numbers = numbers[1:]  # drop the live reading
            limits = PowerThresholds(*numbers)
            if match.group(1).lower().startswith("tx"):
                optic.tx_limits = limits
            else:
                optic.rx_limits = limits


def _parse_ports(body: str) -> dict[str, Port]:
    """Parse ``show port detail`` blocks.

    Blocks are cut on the ``===`` banners rather than on the ``Interface :``
    line, because SR OS prints ``Description`` *above* it -- slicing at the
    interface line attributes every description to the previous port.
    """
    ports: dict[str, Port] = {}
    current: Port | None = None
    for block in banner_blocks(body):
        match = INTERFACE_LINE_RE.search(block)
        if not match:
            # DDM and coherent-module readings are printed in their own banner
            # sections after the port they belong to.
            if current is not None and current.optic is not None:
                _apply_power(current.optic, block)
            continue
        port_id = match.group(1)
        # A SONET port labels its rate plainly "Speed"; Ethernet uses "Oper
        # Speed"/"Config Speed". Missing the SONET spelling left rate None on
        # every OC3 port in the network, and because the SONET rules gate on the
        # rate being a known OC-n they silently graded nothing at all -- 60 ports
        # with no findings of any kind. "Speed" is searched last and cannot be
        # confused with the Ethernet labels: the two-space column test needs
        # whitespace immediately before the label, and "Oper Speed" has none.
        rate = first_field(block, "Oper Speed", "Config Speed", "Speed")
        if is_absent(rate):
            rate = field_value(block, "Config Speed")
            if is_absent(rate):
                rate = None
        port = ports.get(port_id) or Port(port_id=port_id)
        port.description = port.description or field_value(block, "Description")
        port.rate = port.rate or rate
        port.admin_state = port.admin_state or normalize_state(
            first_field(block, "Admin State", "Admin Status")
        )
        port.oper_state = port.oper_state or normalize_state(
            first_field(block, "Oper State", "Oper Status")
        )
        port.mode = port.mode or first_field(block, "Configured Mode", "Mode")
        port.framing = port.framing or field_value(block, "Framing")
        port.aps_group = port.aps_group or field_value(block, "APS Group")
        port.aps_role = port.aps_role or field_value(block, "APS Role")
        if port.phys_state_changes is None:
            changes = field_value(block, "Phys State Chng Cnt")
            if changes and changes.strip().isdigit():
                port.phys_state_changes = int(changes.strip())
        if port.optic is None:
            optic = _optic(block)
            if optic is not None:
                optic.port_id = port_id
                port.optic = optic
        alarm_text = first_field(block, "Alarm Status", "Reported Alarms")
        if alarm_text and not is_absent(alarm_text):
            port.alarms = alarm_text.split()
        configured = field_value(block, "Cfg Alarm")
        if configured and not is_absent(configured):
            port.configured_alarms = configured.split()
        _apply_sonet(port, block)
        ports[port_id] = port
        current = port
    return ports


def _parse_lag_detail(body: str) -> dict[str, Lag]:
    lags: dict[str, Lag] = {}
    sections = list(LAG_SECTION_RE.finditer(body))
    for index, match in enumerate(sections):
        lag_id = match.group(1) or match.group(2)
        end = sections[index + 1].start() if index + 1 < len(sections) else len(body)
        block = body[match.start() : end]
        lag = Lag(
            lag_id=lag_id,
            description=field_value(block, "Description"),
            admin_state=normalize_state(first_field(block, "Adm", "Admin State")),
            oper_state=normalize_state(first_field(block, "Opr", "Oper State")),
            lacp_mode=field_value(block, "LACP"),
            system_id=field_value(block, "System Id"),
            partner_system_id=field_value(block, "Prtr System Id"),
        )
        for member in LAG_MEMBER_RE.finditer(block):
            lag.members.append(
                LagMember(
                    port_id=member.group(1),
                    admin_state=member.group(2).lower(),
                    activity=member.group(3).lower(),
                    oper_state=member.group(4).lower(),
                )
            )
        lags[lag_id] = lag
    return lags


def _parse_lag_summary(body: str) -> dict[str, Lag]:
    lags: dict[str, Lag] = {}
    for match in LAG_SUMMARY_RE.finditer(body):
        lags[match.group(1)] = Lag(
            lag_id=match.group(1),
            admin_state=match.group(2).lower(),
            oper_state=match.group(3).lower(),
        )
    return lags


def _parse_router_interfaces(text: str) -> dict[str, RouterInterface]:
    interfaces: dict[str, RouterInterface] = {}
    for match in ROUTER_IF_RE.finditer(text):
        name = match.group("name")
        interfaces[name] = RouterInterface(
            name=name,
            port_id=match.group("port"),
            address=match.group("addr"),
            admin_state=match.group("adm").lower(),
            oper_state=match.group("opr").split("/")[0].lower(),
        )
    return interfaces


def _parse_adjacencies(text: str, interfaces: dict[str, RouterInterface]):
    """Derive adjacencies from every source the baseline captures.

    OSPF is the strongest: the neighbour's Router ID is that device's ``system``
    address, so it joins two independent captures directly. Where the interface
    is a /31 the far-end *interface* address follows arithmetically, which pins
    the adjacency to a port on the peer rather than just to the peer.
    """
    adjacencies: list[Adjacency] = []

    for match in OSPF_NEIGHBOUR_RE.finditer(text):
        name = match.group("name")
        interface = interfaces.get(name)
        if interface is None:
            continue
        adjacencies.append(
            Adjacency(
                local_port=interface.port_id or name,
                remote=match.group("rtrid"),
                remote_label=peer_label(name),
                scope="Ext",
                protocol="ospf",
                interface_name=name,
                local_ip=interface.ip,
                remote_ip=interface.point_to_point_peer,
            )
        )

    return adjacencies


def peer_label(interface_name: str | None) -> str | None:
    """The peer's hostname as encoded in an interface name, e.g. ``to_SITE-B``.

    Used only to *label* a peer that has not been audited, never to assert a
    link: it is a naming convention, not device-reported state.
    """
    if not interface_name:
        return None
    match = re.match(r"^to[_-](?P<peer>[\w.\-]+)$", interface_name, re.IGNORECASE)
    return match.group("peer") if match else None


def parse_sros_transcript(text: str, source: str = "transcript") -> Device:
    text = strip_ansi(text)
    hostname = _hostname(text)
    device = Device(
        device_id=hostname or "unknown-sros",
        hostname=hostname,
        kind=DeviceKind.ROUTER,
        platform=_platform(text),
        software_release=_release(text),
        evidence=[Evidence(source=source, detail="Parsed SR OS transcript")],
    )
    device.management_ip = first_field(
        text, "Management IPv4 Addr", "Management IP Addr"
    ) or capture_host(text)
    device.serial_number = field_value(text, "Serial number")
    device.remote_access = _remote_access(text)
    device.base_mac = field_value(text, "Base MAC address")
    device.chassis = _chassis_health(text)
    # Scope timing to its own command section: the labels are generic enough
    # ("Admin Status", "Rx Quality Level") to collide with port output.
    sections = split_command_sections(text)
    device.timing = _system_timing(
        sections.get("show system sync-if-timing", "")
    )
    device.redundancy = _redundancy(
        sections.get("show redundancy synchronization", "")
    )
    device.cpu = _cpu(sections.get("show system cpu", ""))

    # Scan the whole transcript rather than only the section whose command name
    # matches. Transcripts arrive from session logs, copy-paste, and terminal
    # scrollback, so the command echo is not a dependable index of where the
    # output for that command actually sits -- and when it is wrong, keying on it
    # silently yields zero ports rather than an error. The block and row
    # patterns are specific enough to locate the data on their own.
    device.ports.update(_parse_ports(text))
    detail = _parse_lag_detail(text)
    if detail:
        device.lags.update(detail)
    else:
        for lag_id, lag in _parse_lag_summary(text).items():
            device.lags.setdefault(lag_id, lag)

    device.router_interfaces.update(_parse_router_interfaces(text))
    system = device.router_interfaces.get("system")
    if system is not None:
        device.system_address = system.ip
    device.adjacencies = _parse_adjacencies(text, device.router_interfaces)
    # LLDP only from its own section: an unscoped pattern once matched
    # "show port" rows and invented adjacencies wholesale.
    device.adjacencies.extend(
        _lldp_adjacencies(sections.get("show system lldp neighbor", ""))
    )
    device.finalize()
    return device
