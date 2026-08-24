from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class DeviceKind(str, Enum):
    ROUTER = "router"
    OPTICAL = "optical"
    UNKNOWN = "unknown"


class Platform(str, Enum):
    SAR_7705_8 = "7705-sar-8"
    IXR_R6 = "7250-ixr-r6"
    IXR_R6D = "7250-ixr-r6d"
    IXR_R6DL = "7250-ixr-r6dl"
    PSS_8 = "1830-pss-8"
    UNKNOWN = "unknown"


class LinkLayer(str, Enum):
    ETHERNET = "ethernet"
    SONET_SDH = "sonet-sdh"
    OPTICAL = "optical"
    LOGICAL = "logical"


class FindingSeverity(str, Enum):
    PASS = "PASS"
    # A condition the equipment reports without alarming on it -- worth showing
    # an operator, but not worth crying wolf over.
    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


# Report order: what needs action first, what passed last.
SEVERITY_ORDER = (
    FindingSeverity.FAIL,
    FindingSeverity.WARN,
    FindingSeverity.UNKNOWN,
    FindingSeverity.INFO,
    FindingSeverity.PASS,
)


ETHERNET_RATES_BPS = {
    "10m": 10_000_000,
    "100m": 100_000_000,
    "1g": 1_000_000_000,
    "10g": 10_000_000_000,
    "25g": 25_000_000_000,
    "40g": 40_000_000_000,
    "100g": 100_000_000_000,
    "400g": 400_000_000_000,
}

SONET_RATES_BPS = {
    "oc3": 155_520_000,
    "oc12": 622_080_000,
    "oc48": 2_488_320_000,
    "oc192": 9_953_280_000,
}

# SR OS ``show port detail`` reports speed as ``10 Gbps`` / ``100 Mbps`` (and
# lowercases it as ``100 mbps`` on the 7705 CSM ports), not as ``10GE``.
_RATE_ALIASES = {
    "10mbps": "10m",
    "100mbps": "100m",
    "1000mbps": "1g",
    "1gbps": "1g",
    "10gbps": "10g",
    "25gbps": "25g",
    "40gbps": "40g",
    "100gbps": "100g",
    "400gbps": "400g",
    "1ge": "1g",
    "1000m": "1g",
    "10ge": "10g",
    "25ge": "25g",
    "40ge": "40g",
    "100ge": "100g",
    "400ge": "400g",
    "stm1": "oc3",
    "stm4": "oc12",
    "stm16": "oc48",
    "stm64": "oc192",
}

_ABSENT_RATES = {"", "na", "n/a", "unrestricted", "default", "unknown", "notapplicable"}


def normalize_rate(value: str | None) -> tuple[str | None, int | None]:
    if not value:
        return None, None
    token = value.lower().replace("-", "").replace("_", "").replace(" ", "")
    token = token.rstrip(".")
    if token in _ABSENT_RATES:
        return None, None
    token = _RATE_ALIASES.get(token, token)
    return token, ETHERNET_RATES_BPS.get(token) or SONET_RATES_BPS.get(token)


def frequency_to_wavelength_nm(frequency_thz: float) -> float:
    if frequency_thz <= 0:
        raise ValueError("frequency_thz must be positive")
    return round(299_792.458 / frequency_thz, 2)


@dataclass(slots=True)
class Evidence:
    source: str
    command: str | None = None
    detail: str | None = None
    confidence: float = 1.0


@dataclass(slots=True)
class PowerThresholds:
    """DDM alarm/warning limits as the pluggable reports them, in dBm."""

    high_alarm: float | None = None
    high_warn: float | None = None
    low_warn: float | None = None
    low_alarm: float | None = None

    def classify(self, value: float | None) -> str | None:
        """``"alarm"``, ``"warn"``, or ``None`` when within limits."""
        if value is None:
            return None
        if self.high_alarm is not None and value > self.high_alarm:
            return "alarm"
        if self.low_alarm is not None and value < self.low_alarm:
            return "alarm"
        if self.high_warn is not None and value > self.high_warn:
            return "warn"
        if self.low_warn is not None and value < self.low_warn:
            return "warn"
        return None


@dataclass(slots=True)
class Optic:
    port_id: str
    part_number: str | None = None
    serial_number: str | None = None
    model: str | None = None
    frequency_thz: float | None = None
    wavelength_nm: float | None = None
    tx_dbm: float | None = None
    rx_dbm: float | None = None
    tx_limits: PowerThresholds = field(default_factory=PowerThresholds)
    rx_limits: PowerThresholds = field(default_factory=PowerThresholds)
    # A digital-coherent, frequency-tuned pluggable is riding a DWDM line
    # system; a grey optic is a direct fibre. That distinction is the only thing
    # in a router capture that reveals an optical shelf sits in the span, since
    # a transparent wavelength puts the far-end *router* in LLDP and OSPF.
    coherent: bool = False
    tunability: str | None = None

    @property
    def itu_channel(self) -> str | None:
        """The ITU channel number the 1830 uses as an AID, e.g. 193.10 THz -> 9310."""
        if not self.frequency_thz:
            return None
        return str(round((self.frequency_thz - 100) * 100))

    def finalize(self) -> None:
        if self.frequency_thz and self.wavelength_nm is None:
            self.wavelength_nm = frequency_to_wavelength_nm(self.frequency_thz)


# SONET/SDH synchronisation-status values carried in the S1 byte, best first.
# Only the top four are traceable to a real primary reference; st3 and below mean
# the far end is running on a holdover-grade clock, and dus is an explicit
# "don't use me for sync". A port can be operationally perfect and still be
# handing over unusable timing, which is invisible in its up/down state.
SONET_S1_QUALITY = ("prs", "stu", "st2", "tnc", "st3e", "st3", "smc", "st4", "dus")
SONET_S1_TRACEABLE = frozenset({"prs", "st2", "tnc", "st3e"})


@dataclass(slots=True)
class SonetState:
    """Per-port SONET/SDH state that has no Ethernet equivalent."""

    rx_s1: str | None = None
    rx_s1_quality: str | None = None
    tx_s1: str | None = None
    tx_s1_quality: str | None = None
    rx_k1: str | None = None
    rx_k2: str | None = None
    clock_source: str | None = None
    ber_sd_threshold: str | None = None
    ber_sf_threshold: str | None = None

    @property
    def reported(self) -> bool:
        return any(
            (
                self.rx_s1,
                self.tx_s1,
                self.clock_source,
                self.ber_sd_threshold,
            )
        )

    @property
    def rx_traceable(self) -> bool | None:
        """True/False when the received S1 is known, None when it is not."""
        if not self.rx_s1_quality:
            return None
        return self.rx_s1_quality.lower() in SONET_S1_TRACEABLE


@dataclass(slots=True)
class Port:
    port_id: str
    description: str | None = None
    rate: str | None = None
    rate_bps: int | None = None
    admin_state: str | None = None
    oper_state: str | None = None
    mode: str | None = None
    framing: str | None = None
    lag_id: str | None = None
    bundle_id: str | None = None
    aps_group: str | None = None
    aps_role: str | None = None
    # ``Phys State Chng Cnt`` -- how many times the physical link has come up or
    # gone down. Zero on a down port means the link has never once been lit, which
    # separates "provisioned but never fibered" from "was carrying traffic and
    # broke". Validated against field-confirmed examples of both: every real
    # break read 2, every not-yet-fibered span read 0.
    phys_state_changes: int | None = None
    alarms: list[str] = field(default_factory=list)
    # "Cfg Alarm" -- which alarms this port is set to raise, as opposed to the
    # ones it is raising now (Port.alarms). Not SONET-specific: an Ethernet port
    # reports "remote local" here. An alarm missing from this set is one the port
    # will never report, however bad things get.
    configured_alarms: list[str] = field(default_factory=list)
    optic: Optic | None = None
    sonet: SonetState = field(default_factory=SonetState)

    def finalize(self) -> None:
        self.rate, self.rate_bps = normalize_rate(self.rate)
        if self.optic:
            self.optic.finalize()


@dataclass(slots=True)
class LagMember:
    port_id: str
    admin_state: str | None = None
    oper_state: str | None = None
    activity: str | None = None
    rate: str | None = None
    rate_bps: int | None = None

    def finalize(self) -> None:
        self.rate, self.rate_bps = normalize_rate(self.rate)


@dataclass(slots=True)
class Lag:
    lag_id: str
    description: str | None = None
    admin_state: str | None = None
    oper_state: str | None = None
    lacp_mode: str | None = None
    # The local LACP System Id, and the one the far end presents. Together they
    # pair a LAG with its counterpart on another captured device without relying
    # on the two ends having been given the same LAG number.
    system_id: str | None = None
    partner_system_id: str | None = None
    members: list[LagMember] = field(default_factory=list)

    @property
    def configured_capacity_bps(self) -> int:
        return sum(member.rate_bps or 0 for member in self.members)

    @property
    def operational_capacity_bps(self) -> int:
        return sum(
            member.rate_bps or 0
            for member in self.members
            if (member.oper_state or "").lower() == "up"
            and (member.activity or "active").lower() != "standby"
        )


@dataclass(slots=True)
class OpticalChannel:
    channel_id: str
    port_number: int | None = None
    frequency_thz: float | None = None
    wavelength_nm: float | None = None
    admin_state: str | None = None
    oper_state: str | None = None
    tx_dbm: float | None = None
    rx_dbm: float | None = None
    circuit_id: str | None = None

    def finalize(self) -> None:
        if self.frequency_thz and self.wavelength_nm is None:
            self.wavelength_nm = frequency_to_wavelength_nm(self.frequency_thz)


@dataclass(slots=True)
class Alarm:
    """One row of an equipment alarm/condition list."""

    severity: str
    condition: str
    subject: str | None = None
    description: str | None = None
    service_affecting: bool = False
    raised_at: str | None = None

    @property
    def is_critical(self) -> bool:
        return self.severity.upper() in {"CR", "CRITICAL"}

    @property
    def is_major(self) -> bool:
        return self.severity.upper() in {"MJ", "MAJOR"}


@dataclass(slots=True)
class TimingReference:
    """One synchronous-timing reference and whether it is usable."""

    name: str
    admin_state: str | None = None
    qualified: str | None = None
    selected: str | None = None
    not_qualified_reason: str | None = None
    not_selected_reason: str | None = None
    rx_quality: str | None = None
    # Which physical port feeds this reference -- ties a timing fault to a link.
    source_port: str | None = None

    @staticmethod
    def _yes(value: str | None) -> bool | None:
        if value is None:
            return None
        return value.strip().lower() in {"yes", "true"}

    @property
    def is_admin_up(self) -> bool:
        return (self.admin_state or "").strip().lower() == "up"

    @property
    def is_qualified(self) -> bool | None:
        return self._yes(self.qualified)

    @property
    def is_selected(self) -> bool | None:
        return self._yes(self.selected)


@dataclass(slots=True)
class SystemTiming:
    """Synchronous interface timing, from ``show system sync-if-timing``.

    On a network carrying Sync-E this is the state that decides whether the node
    is actually locked to a reference or quietly running on its own oscillator --
    a condition that shows no alarm LED and no interface change.
    """

    status: dict[str, str] = field(default_factory=dict)  # "CSM A" -> "Master Locked"
    reference_mode: str | None = None
    quality_level_selection: str | None = None
    reference_order: str | None = None
    # The device names its own choice ("Reference Selected : ref1") and the
    # quality level it is distributing; neither appears in the documented output.
    selected_reference: str | None = None
    system_quality_level: str | None = None
    references: list[TimingReference] = field(default_factory=list)

    @property
    def reported(self) -> bool:
        return bool(self.status or self.references)

    @property
    def locked(self) -> bool | None:
        """True when every reported CSM is locked to a reference."""
        if not self.status:
            return None
        return all("locked" in value.lower() for value in self.status.values())

    @property
    def unlocked(self) -> list[str]:
        return [
            f"{name}={value}"
            for name, value in sorted(self.status.items())
            if "locked" not in value.lower()
        ]

    @property
    def selected_references(self) -> list[str]:
        return [r.name for r in self.references if r.is_selected]


@dataclass(slots=True)
class Redundancy:
    """CSM/CPM redundancy, from ``show redundancy synchronization``.

    A standby that is not ready means the node has no control-plane protection,
    which nothing else in a capture reveals: every interface, LAG and protocol
    stays up right until the active card fails.
    """

    standby_status: str | None = None
    last_failure: str | None = None
    failover_time: str | None = None
    failover_reason: str | None = None
    config_sync_mode: str | None = None
    config_sync_status: str | None = None
    last_config_sync: str | None = None

    @property
    def reported(self) -> bool:
        return bool(self.standby_status or self.config_sync_status)

    @property
    def standby_ready(self) -> bool | None:
        if not self.standby_status:
            return None
        return "ready" in self.standby_status.strip().lower()

    @property
    def had_failure(self) -> bool:
        value = (self.last_failure or "").strip().lower()
        return bool(value) and value not in {"n/a", "na", "none", "never", "-"}


@dataclass(slots=True)
class CpuUsage:
    """One row of ``show system cpu``."""

    name: str
    cpu_usage: str | None = None
    capacity_usage: str | None = None

    @staticmethod
    def _percent(value: str | None) -> float | None:
        if not value:
            return None
        cleaned = value.strip().lstrip("~").rstrip("%")
        try:
            return float(cleaned)
        except ValueError:
            return None

    @property
    def capacity_percent(self) -> float | None:
        return self._percent(self.capacity_usage)


@dataclass(slots=True)
class ExternalAlarmInput:
    """One contact-closure alarm input and whether it is currently asserted."""

    input_id: str
    severity: str | None = None  # the Event column: Critical / Major / Minor
    state: str | None = None
    name: str | None = None

    @property
    def asserted(self) -> bool:
        value = (self.state or "").strip().lower()
        return bool(value) and value not in {"ok", "up", "clear", "cleared", "-"}


@dataclass(slots=True)
class ChassisHealth:
    """Alarm state a classic SR OS chassis reports about itself.

    Classic 7705 SAR / 7250 IXR have no "list active alarms" command -- facility
    alarms and ``show system alarms`` are 7705 SAR Gen 2 only. What they do
    expose is here, in ``show chassis detail``: the front-panel LEDs, the
    over-temperature state, a per-component alarm state, and the external alarm
    inputs.
    """

    critical_led: str | None = None
    major_led: str | None = None
    minor_led: str | None = None
    over_temperature: str | None = None
    components_in_alarm: list[str] = field(default_factory=list)
    external_inputs: list[ExternalAlarmInput] = field(default_factory=list)

    @staticmethod
    def _led_on(value: str | None) -> bool:
        return (value or "").strip().lower() not in {"", "off", "n/a", "unknown"}

    @property
    def leds_lit(self) -> list[str]:
        lit = []
        for name, value in (
            ("Critical", self.critical_led),
            ("Major", self.major_led),
            ("Minor", self.minor_led),
        ):
            if self._led_on(value):
                lit.append("%s=%s" % (name, value))
        return lit

    @property
    def over_temperature_ok(self) -> bool | None:
        if not self.over_temperature:
            return None
        return self.over_temperature.strip().lower() in {"ok", "within range", "normal"}

    @property
    def reported(self) -> bool:
        """True when the capture actually carried chassis health data."""
        return any(
            (
                self.critical_led,
                self.major_led,
                self.minor_led,
                self.over_temperature,
                self.components_in_alarm,
                self.external_inputs,
            )
        )


@dataclass(slots=True)
class Adjacency:
    """A far-end binding the device itself reports for one of its ports."""

    local_port: str
    remote: str
    remote_port: str | None = None
    scope: str | None = None  # "Int" (intra-shelf) or "Ext" (another NE)
    # How the device knew: "topology" (1830 fibre map), "ospf", "lldp", "ldp",
    # or "description". Recorded so a link can say what it rests on.
    protocol: str | None = None
    interface_name: str | None = None
    # A human-readable name for the peer, taken from a naming convention rather
    # than from device state. Good enough to label an unaudited peer, never
    # enough to assert a link.
    remote_label: str | None = None
    local_ip: str | None = None
    # LLDP reports the peer's chassis MAC, which is the same value it presents as
    # its LACP System Id -- a join key independent of any routing protocol.
    remote_chassis_id: str | None = None
    # For a /31 or /30 point-to-point interface the far-end address is
    # arithmetic, which is what lets two independent captures be joined at the
    # interface rather than merely at the device.
    remote_ip: str | None = None


@dataclass(slots=True)
class RouterInterface:
    """An L3 interface from ``show router interface``."""

    name: str
    port_id: str | None = None
    address: str | None = None  # "172.18.6.106/31"
    admin_state: str | None = None
    oper_state: str | None = None

    @property
    def prefix_length(self) -> int | None:
        if not self.address or "/" not in self.address:
            return None
        try:
            return int(self.address.split("/", 1)[1])
        except ValueError:
            return None

    @property
    def ip(self) -> str | None:
        return self.address.split("/", 1)[0] if self.address else None

    @property
    def point_to_point_peer(self) -> str | None:
        """The other address in a /31 or /30, or None if not point-to-point."""
        if self.prefix_length not in (30, 31) or not self.ip:
            return None
        try:
            octets = [int(part) for part in self.ip.split(".")]
        except ValueError:
            return None
        if len(octets) != 4:
            return None
        value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        if self.prefix_length == 31:
            peer = value ^ 1
        else:
            # /30: the two usable hosts are .1 and .2 above the network address.
            network = value & ~0b11
            first, second = network + 1, network + 2
            peer = second if value == first else first
        return ".".join(str((peer >> shift) & 0xFF) for shift in (24, 16, 8, 0))


@dataclass(slots=True)
class Device:
    device_id: str
    hostname: str | None = None
    management_ip: str | None = None
    kind: DeviceKind = DeviceKind.UNKNOWN
    platform: Platform = Platform.UNKNOWN
    software_release: str | None = None
    serial_number: str | None = None
    # The router's own loopback identity, which is what a peer reports as its
    # OSPF Router ID / LDP peer ID -- the join key between two captures.
    system_address: str | None = None
    # Chassis base MAC. A peer's LLDP reports this as its Remote Chassis ID, and
    # it is also the LACP System Id, so it resolves a neighbour by hardware.
    base_mac: str | None = None
    # Which management servers this device has enabled, e.g. {"telnet": False,
    # "ssh": True}. Read from the device rather than assumed: these routers ship
    # with telnet disabled and SSH enabled, so suggesting telnet would fail.
    remote_access: dict[str, bool] = field(default_factory=dict)
    ports: dict[str, Port] = field(default_factory=dict)
    lags: dict[str, Lag] = field(default_factory=dict)
    optical_channels: dict[str, OpticalChannel] = field(default_factory=dict)
    router_interfaces: dict[str, RouterInterface] = field(default_factory=dict)
    chassis: ChassisHealth = field(default_factory=ChassisHealth)
    timing: SystemTiming = field(default_factory=SystemTiming)
    redundancy: Redundancy = field(default_factory=Redundancy)
    # Parsed for reporting, deliberately not audited: what counts as "high CPU"
    # is a judgement about a particular network, not a fact about the platform.
    cpu: list[CpuUsage] = field(default_factory=list)
    alarms: list[Alarm] = field(default_factory=list)
    adjacencies: list[Adjacency] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def identities(self) -> set[str]:
        """Every string another device might use to name this one.

        Lower-cased throughout: LLDP prints a chassis MAC in upper case while
        ``show chassis detail`` prints it in lower, and a case-sensitive compare
        would miss the match.
        """
        values = {self.device_id, self.hostname, self.system_address, self.base_mac}
        if self.management_ip:
            values.add(self.management_ip.split("/")[0])
        for interface in self.router_interfaces.values():
            if interface.ip:
                values.add(interface.ip)
        for lag in self.lags.values():
            if lag.system_id:
                values.add(lag.system_id)
        return {value.lower() for value in values if value}

    def finalize(self) -> None:
        for port in self.ports.values():
            port.finalize()
        for lag in self.lags.values():
            for member in lag.members:
                member.finalize()
                port = self.ports.get(member.port_id)
                if port:
                    member.rate = member.rate or port.rate
                    member.rate_bps = member.rate_bps or port.rate_bps
        for channel in self.optical_channels.values():
            channel.finalize()


@dataclass(slots=True)
class LinkEndpoint:
    device_id: str
    interface_id: str | None = None


@dataclass(slots=True)
class Link:
    link_id: str
    a: LinkEndpoint
    z: LinkEndpoint
    layer: LinkLayer
    rate: str | None = None
    frequency_thz: float | None = None
    confidence: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class Finding:
    rule_id: str
    severity: FindingSeverity
    subject: str
    message: str
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AuditSnapshot:
    devices: dict[str, Device] = field(default_factory=dict)
    links: dict[str, Link] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> None:
        for device in self.devices.values():
            device.finalize()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
