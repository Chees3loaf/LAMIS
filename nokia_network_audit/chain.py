"""Planning for chained capture: hopping from one router to its neighbours.

This module holds the decisions -- which neighbours are candidates, which
transport to use, what the hop command is, and what counts as a safe command to
send. It deliberately contains no terminal I/O so it can be tested without
hardware; the SecureCRT side drives it.

Chained capture is the riskiest thing this tool does, for two reasons that shape
every choice here:

1. It opens sessions on equipment the operator did not individually pick, so
   every target must be explicitly confirmed and every hop command must be
   verifiable as *only* a hop.
2. A nested session changes the prompt underneath the reader. That is exactly
   what made an early capture unusable -- a stale prompt desynchronised all 19
   commands. So each hop re-detects the prompt, and the return path is verified
   before anything else is sent.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace

from .models import Device, DeviceKind


# A hop command and nothing else: a bare ssh/telnet to a literal IPv4 address,
# with only the options SR OS documents. Anything with a shell metacharacter, a
# second command, or a hostname is rejected -- this is the last gate before a
# string is typed at a live router.
HOP_COMMAND_RE = re.compile(
    r"^(?:"
    r"ssh[ \t]+(?P<ssh_host>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:[ \t]+-l[ \t]+[\w.\-]+)?"
    r"(?:[ \t]+router[ \t]+[\w.\-]+)?"
    r"(?:[ \t]+-p[ \t]+\d{1,5})?"
    r"|"
    r"telnet[ \t]+(?P<telnet_host>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:[ \t]+\d{1,5})?"
    r"(?:[ \t]+router[ \t]+[\w.\-]+)?"
    r")$"
)

MAX_DEPTH = 3


class ChainError(RuntimeError):
    """A chained capture cannot proceed safely."""


@dataclass(slots=True)
class HopTarget:
    """One neighbour worth capturing, and how to get to it."""

    address: str
    label: str | None = None
    via_port: str | None = None
    transport: str = "ssh"
    username: str | None = None
    router_instance: str | None = None
    # The 1830 authenticates twice: ssh lands on a getty that takes an account
    # with no password ("cli"), and the CLI behind it then asks for its own
    # username and password. So the name given to ssh is not the name the device
    # ends up logged in as, and a router -- one ssh login, one password -- cannot
    # be described with the same two fields.
    login_user: str | None = None
    password: str | None = None
    # Optical shelves do not all present the same login. Some accept the getty
    # account with no password and then ask the CLI for its own identity;
    # others refuse that account outright and take the CLI user directly over
    # ssh, landing straight on the prompt. Both shapes exist on the same
    # network, at the same release, so which one a shelf uses cannot be known
    # before connecting -- it is discovered by trying.
    alternate_logins: tuple[str, ...] = ()

    def with_login(self, user: str) -> "HopTarget":
        return replace(self, login_user=user)

    def login_sequence(self) -> list[str]:
        """Login accounts to try, in order, without repeats."""
        ordered = [self.login_user] + list(self.alternate_logins)
        seen: list[str] = []
        for user in ordered:
            if user and user not in seen:
                seen.append(user)
        return seen or [None]

    @property
    def display(self) -> str:
        return f"{self.address} ({self.label})" if self.label else self.address

    def command(self) -> str:
        """The exact CLI string to type. Validated before it is returned."""
        if self.transport == "ssh":
            parts = ["ssh", self.address]
            # The getty account, where there is one -- not the CLI identity.
            if self.login_user or self.username:
                parts += ["-l", self.login_user or self.username]
            if self.router_instance:
                parts += ["router", self.router_instance]
        elif self.transport == "telnet":
            parts = ["telnet", self.address]
            if self.router_instance:
                parts += ["router", self.router_instance]
        else:
            raise ChainError(f"Unsupported transport: {self.transport!r}")
        command = " ".join(parts)
        assert_hop_command(command, self.address)
        return command


def assert_hop_command(command: str, expected_address: str) -> None:
    """Refuse anything that is not exactly a hop to ``expected_address``."""
    normalized = " ".join(command.strip().split())
    match = HOP_COMMAND_RE.match(normalized)
    if not match:
        raise ChainError(f"Refusing to send a non-hop command: {command!r}")
    host = match.group("ssh_host") or match.group("telnet_host")
    if host != expected_address:
        raise ChainError(
            f"Hop command targets {host}, not the approved {expected_address}"
        )


def preferred_transport(device: Device) -> str | None:
    """Which client to use, based on what the device reports it has enabled.

    The device tells us its own *server* state, which is the site convention
    rather than proof about the target. It is still far better than assuming:
    these routers ship telnet disabled and SSH enabled, so a telnet hop would
    simply fail.
    """
    access = device.remote_access or {}
    if access.get("ssh"):
        return "ssh"
    if access.get("telnet"):
        return "telnet"
    if not access:
        return "ssh"  # nothing reported; SSH is the safer default to try
    return None


def hop_targets(
    device: Device,
    *,
    visited: set[str] | None = None,
    username: str | None = None,
) -> list[HopTarget]:
    """Neighbours of ``device`` that have not been captured yet.

    A target has to be a routable address, so neighbours learned from a naming
    convention are not offered -- LLDP reports a system name, which is not
    something to connect to.

    Optical shelves count. This used to refuse them on the grounds that the
    1830's fibre map "names peers that have no CLI to hop to", which confused
    two different things: the 1830 has no ssh client, so it cannot be hopped
    *from*, but it answers ssh perfectly well and so can be hopped *to*. Since
    every hop in a walk is made from the origin router and returns there, the
    missing client never comes into it. Without this, the 1830 layer is
    undiscoverable -- routers cannot see it, because a transparent DWDM span
    puts the far-end *router* in LLDP and OSPF, not the shelf carrying the
    wavelength -- and each 1830 is the only thing that knows its span partner.

    Protocol adjacencies are still required from a router. The 1830 reports its
    span from ``show interface topology *`` with no protocol attached, and
    allowing that generally would later let in a weaker source: port
    descriptions were dropped as adjacency evidence precisely because this
    network copies them between LAG members.
    """
    transport = preferred_transport(device)
    if transport is None:
        return []

    seen = {value.lower() for value in (visited or set())}
    targets: dict[str, HopTarget] = {}
    for adjacency in device.adjacencies:
        if adjacency.scope == "Int":
            continue  # intra-shelf fibre, not another device
        routed = adjacency.protocol in {"ospf", "isis", "ldp"}
        topology = adjacency.protocol is None and device.kind is not DeviceKind.ROUTER
        if not (routed or topology):
            continue
        address = adjacency.remote
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", address or ""):
            continue
        if address.lower() in seen or address in targets:
            continue
        if address == device.system_address:
            continue
        targets[address] = HopTarget(
            address=address,
            label=adjacency.remote_label,
            via_port=adjacency.local_port,
            transport=transport,
            username=username,
        )
    return [targets[address] for address in sorted(targets)]


# A bound on one run, not a statement about network size. Raise it with
# NOKIA_AUDIT_MAX_DEVICES when walking something larger; the default is set so an
# unattended run on an unexpectedly big network stops and says so rather than
# spending hours discovering that for itself.
#
# 40 and then 65 were each reached exactly, truncating the walk with neighbours
# still unvisited -- a cap set near the frontier just moves where the walk stops.
# This network is about 180 devices, and 121 were known after the 65-device run,
# so the bound is set above the whole estimate: the walk should now run out of
# topology rather than out of budget, which is the only way to know it finished.
# At the measured 25 seconds per device a full 200 is a little over 80 minutes.
DEFAULT_MAX_WALK_DEVICES = 200


def max_walk_devices() -> int:
    raw = os.environ.get("NOKIA_AUDIT_MAX_DEVICES", "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return DEFAULT_MAX_WALK_DEVICES


MAX_WALK_DEVICES = DEFAULT_MAX_WALK_DEVICES


SEED_ENV_VAR = "NOKIA_AUDIT_SEED_DEVICES"

# A seed exists to reach the optical layer, so it defaults to the 1830 login:
# ssh onto the getty as an account with no password, then authenticate to the
# CLI behind it. Overridable for a site that uses different accounts, and for
# the case where a seed is something other than a shelf.
DEFAULT_SEED_LOGIN = "cli"
DEFAULT_SEED_USERNAME = "admin"
DEFAULT_SEED_PASSWORD = "admin"

# Optical shelves are reached over the management network, which SR OS keeps in
# its own routing instance. A hop issued from the default instance cannot see it
# at all -- a live run answered every seed with "MINOR: CLI No route to
# destination 10.9.102.176." while that address was pingable from the same
# shelf's management port. Instance name per the 7705 SAR Gen 2 guides,
# ``router "management"``; ``ssh ... router <instance>`` defaults to Base.
DEFAULT_SEED_ROUTER_INSTANCE = "management"


def seed_credentials() -> tuple[str, str, str]:
    """``(getty account, CLI username, CLI password)`` for seeded devices."""
    return (
        os.environ.get("NOKIA_AUDIT_SEED_LOGIN") or DEFAULT_SEED_LOGIN,
        os.environ.get("NOKIA_AUDIT_SEED_USER") or DEFAULT_SEED_USERNAME,
        os.environ.get("NOKIA_AUDIT_SEED_PASSWORD") or DEFAULT_SEED_PASSWORD,
    )


def seed_router_instance() -> str | None:
    """Routing instance a seeded hop is issued in. Empty string means the default."""
    raw = os.environ.get("NOKIA_AUDIT_SEED_ROUTER")
    if raw is None:
        return DEFAULT_SEED_ROUTER_INSTANCE
    return raw.strip() or None


def seed_targets(
    raw: str | None, *, transport: str = "ssh", username: str | None = None
) -> list[HopTarget]:
    """Extra starting points for a walk, given as addresses.

    Some equipment is unreachable by discovery no matter how the walk is run.
    An 1830 sits behind a transparent DWDM span, so no router ever names it --
    LLDP and OSPF see the far-end *router* across the wavelength -- and the
    shelves are on a management subnet with no routed relationship to the
    topology. A coherent pluggable proves a shelf is there (``OPTICAL-011``) but
    cannot say what address it answers on. Seeding one shelf per span is enough:
    each names its own span partner, which the walk then follows on its own.

    Accepts whitespace-, comma- or semicolon-separated entries, each an IPv4
    address with an optional ``=label`` for the summary. Anything that is not a
    literal IPv4 address is rejected rather than skipped: a typo that silently
    dropped a seed would look exactly like a device that simply was not found,
    and the whole point of a seed is that nothing else will discover it.
    """
    entries = [item for item in re.split(r"[\s,;]+", (raw or "").strip()) if item]
    login_user, seed_user, seed_password = seed_credentials()
    instance = seed_router_instance()
    targets: dict[str, HopTarget] = {}
    for entry in entries:
        address, _, label = entry.partition("=")
        address = address.strip()
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", address):
            raise ChainError(f"Seed {entry!r} is not an IPv4 address")
        if any(int(octet) > 255 for octet in address.split(".")):
            raise ChainError(f"Seed {entry!r} is not a valid IPv4 address")
        targets.setdefault(
            address,
            HopTarget(
                address=address,
                label=label.strip() or None,
                via_port="seed",
                transport=transport,
                login_user=login_user,
                username=username or seed_user,
                password=seed_password,
                router_instance=instance,
                # If the getty account is refused, the shelf is one of the ones
                # that takes the CLI user directly over ssh.
                alternate_logins=(seed_user,),
            ),
        )
    return list(targets.values())


def seeds_from_environment(*, username: str | None = None) -> list[HopTarget]:
    """Seeds configured out of band, so a routine walk need not retype them."""
    return seed_targets(os.environ.get(SEED_ENV_VAR), username=username)


def _ipv4_to_int(address: str) -> int | None:
    octets = address.split(".")
    if len(octets) != 4:
        return None
    value = 0
    for octet in octets:
        if not octet.isdigit() or int(octet) > 255:
            return None
        value = value * 256 + int(octet)
    return value


def management_subnet(device) -> tuple[str, int] | None:
    """The management network the origin can reach, as ``(network, prefix)``.

    Seeds are hopped to in the management routing instance, so the origin's own
    management interface defines what is reachable. Worth surfacing: a live run
    was seeded with ``172.21.102.176`` when the shelf answers on
    ``10.9.102.176`` -- the right host, the wrong prefix -- and every seed came
    back "No route to destination". Showing the range while the addresses are
    being typed makes that mistake visible before it costs a run.
    """
    raw = getattr(device, "management_ip", None)
    if not raw or "/" not in raw:
        return None
    address, _, bits = raw.partition("/")
    if not bits.isdigit():
        return None
    prefix = int(bits)
    if not 0 < prefix <= 32:
        return None
    value = _ipv4_to_int(address.strip())
    if value is None:
        return None
    network = value & ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF)
    return (
        ".".join(str((network >> shift) & 255) for shift in (24, 16, 8, 0)),
        prefix,
    )


def seeds_outside_subnet(targets, subnet) -> list:
    """Seeds that cannot be reached from a management interface on ``subnet``."""
    if not subnet:
        return []
    network, prefix = subnet
    base = _ipv4_to_int(network)
    if base is None:
        return []
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    outside = []
    for target in targets:
        value = _ipv4_to_int(target.address)
        if value is not None and (value & mask) != base:
            outside.append(target)
    return outside


def _site_of(device_id: str) -> str:
    """The site a device belongs to, with the shelf number removed.

    One optical shelf serves a whole site: GRIZ001_1830 carries the wavelengths
    used by both GRIZ001_7250 and GRIZ002_7250.
    """
    return re.sub(r"\d+$", "", (device_id or "").split("_")[0])


def spans_needing_shelves(devices) -> list[tuple[str, list[str]]]:
    """Sites proven to hold an optical shelf that the walk did not capture.

    A coherent, frequency-tuned pluggable is talking to a DWDM line system --
    a grey optic on 1310 nm is a direct fibre. That is the only evidence a
    router carries that a shelf exists at all, because a transparent wavelength
    puts the far-end *router* into LLDP and OSPF and never the shelf.

    Returns ``(site, channels)`` so the walk can say exactly which shelves are
    missing and which channels they carry, instead of asking for addresses
    before it knows whether any are needed.
    """
    captured = {
        _site_of(device.device_id)
        for device in devices
        if getattr(device, "kind", None) is DeviceKind.OPTICAL
    }
    needed: dict[str, set[str]] = {}
    for device in devices:
        if getattr(device, "kind", None) is not DeviceKind.ROUTER:
            continue
        site = _site_of(device.device_id)
        if site in captured:
            continue
        for port in device.ports.values():
            optic = port.optic
            if optic is None or not optic.coherent or not optic.frequency_thz:
                continue
            channel = optic.itu_channel
            if channel:
                needed.setdefault(site, set()).add(channel)
            else:
                needed.setdefault(site, set())
    return [(site, sorted(needed[site])) for site in sorted(needed)]


@dataclass(slots=True)
class WalkState:
    """Bookkeeping for a network walk.

    The walk expands breadth-first over discovered adjacency, but **every hop is
    made from the origin**, never from the device just captured. Within one
    routing domain each system address is an advertised /32, so the origin can
    reach the whole network directly -- and that keeps the session exactly one
    level deep at all times. A depth-first walk would need an unwinding stack of
    logouts, and losing count of it is how an operator's session gets stranded
    somewhere they did not ask to be.
    """

    origin: str
    visited: set[str] = field(default_factory=set)
    queue: list[HopTarget] = field(default_factory=list)
    captured: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    max_devices: int = field(default_factory=max_walk_devices)

    def seen(self, address: str) -> bool:
        return (address or "").lower() in {v.lower() for v in self.visited}

    def mark_visited(self, identities) -> None:
        self.visited |= {value for value in identities if value}

    def enqueue(self, targets) -> list[HopTarget]:
        """Add newly discovered targets, skipping anything already known."""
        added = []
        queued = {target.address.lower() for target in self.queue}
        for target in targets:
            key = target.address.lower()
            if key in queued or self.seen(target.address):
                continue
            if target.address in self.failed:
                continue
            self.queue.append(target)
            queued.add(key)
            added.append(target)
        return added

    def next_target(self) -> HopTarget | None:
        while self.queue:
            target = self.queue.pop(0)
            if not self.seen(target.address):
                return target
        return None

    @property
    def budget_left(self) -> int:
        return max(0, self.max_devices - len(self.captured))

    def summary(self) -> str:
        lines = [
            "Walked %d device(s) from %s." % (len(self.captured), self.origin)
        ]
        for name in self.captured:
            lines.append("  captured %s" % name)
        for address, reason in sorted(self.failed.items()):
            lines.append("  skipped %s: %s" % (address, reason))
        if self.queue:
            lines.append(
                "  %d device(s) still queued when the walk stopped" % len(self.queue)
            )
        return "\n".join(lines)


def unaccounted_lags(devices) -> list[tuple[str, str, str]]:
    """LAGs whose far end has not been captured.

    Returns ``(device_id, lag_id, partner_system_id)``. This is the walk's
    completion test: a LAG is only fully checked once the device on the other
    side has been captured too, because one end always reports itself healthy.
    """
    known = {
        (lag.system_id or "").lower()
        for device in devices
        for lag in device.lags.values()
        if lag.system_id
    }
    missing = []
    for device in devices:
        for lag in device.lags.values():
            partner = (lag.partner_system_id or "").lower()
            if partner and partner not in known:
                missing.append((device.device_id, lag.lag_id, lag.partner_system_id))
    return sorted(missing)


@dataclass(slots=True)
class ChainPlan:
    """The full set of hops approved for one run."""

    origin: str
    targets: list[HopTarget] = field(default_factory=list)
    depth: int = 1

    def validate(self) -> None:
        if self.depth < 1 or self.depth > MAX_DEPTH:
            raise ChainError(
                f"Chain depth {self.depth} outside the supported range 1..{MAX_DEPTH}"
            )
        addresses = [target.address for target in self.targets]
        if len(addresses) != len(set(addresses)):
            raise ChainError("Duplicate hop targets in plan")
        for target in self.targets:
            # Raises if the command is not a bare hop to its own address.
            target.command()

    def summary(self) -> str:
        lines = [f"Origin: {self.origin}", ""]
        for target in self.targets:
            via = f" (via {target.via_port})" if target.via_port else ""
            lines.append(f"  {target.display}{via}")
            lines.append(f"      {target.command()}")
        return "\n".join(lines)
