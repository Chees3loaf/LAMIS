from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from itertools import combinations

from .chain import preferred_transport
from .models import (
    AuditSnapshot,
    DeviceKind,
    Evidence,
    Link,
    LinkEndpoint,
    LinkLayer,
)


def _device_for_address(snapshot: AuditSnapshot, address: str):
    """Resolve a far-end identifier to a device already in the snapshot.

    A peer is named differently depending on who is reporting it: OSPF gives the
    neighbour's system address, the 1830's fibre map gives a management address,
    and a description gives a hostname. ``Device.identities()`` collects every
    form a device answers to so any of them resolves.
    """
    for device in snapshot.devices.values():
        if (address or "").lower() in device.identities():
            return device
    return None


def _interface_for_ip(device, address: str):
    for interface in device.router_interfaces.values():
        if interface.ip == address:
            return interface
    return None


def _channel_number(port: str | None) -> str | None:
    """The ITU channel number from an optical AID, e.g. ``1/10/9310`` -> 9310."""
    match = re.search(r"/(\d{4})$", port or "")
    return match.group(1) if match else None


def _back_adjacency(snapshot: AuditSnapshot, device, adjacency, peer):
    """The peer's own adjacency describing *this* link, if it reported one.

    Mutual peering is not corroboration. Two devices can each name the other on
    several ports, so "the peer mentions me somewhere" would mark every one of
    those links confirmed on one-sided evidence. A specific pairing has to be
    identifiable:

    * routers — the /31 far-end address is one of the peer's interface addresses;
    * optical channels — a channel link joins the same wavelength on both ends;
    * anything else — the far-end port we were given is a port the peer itself
      reports back to us under that name.
    """
    for back in peer.adjacencies:
        if _device_for_address(snapshot, back.remote) is not device:
            continue
        if adjacency.remote_ip and back.local_ip == adjacency.remote_ip:
            return back
        near_channel = _channel_number(adjacency.local_port)
        if near_channel and _channel_number(back.local_port) == near_channel:
            return back
        if adjacency.remote_port and back.local_port == adjacency.remote_port:
            return back
    return None


def correlate_reported_adjacencies(snapshot: AuditSnapshot) -> list[Link]:
    """Build links from far ends the equipment reports for itself.

    The 1830's ``show interface topology *`` names the peer NE by management
    address for every external port. That is the device's own view of its
    cabling, so it carries far more weight than inferring a link from a shared
    wavelength -- and unlike frequency matching it cannot produce a
    combinatorial spray of candidates.
    """
    created: list[Link] = []
    for device in snapshot.devices.values():
        for adjacency in device.adjacencies:
            if adjacency.scope == "Int":
                continue  # intra-shelf fibre, not a network link
            peer = _device_for_address(snapshot, adjacency.remote)
            resolved = peer is not None
            remote_port = adjacency.remote_port
            confirmed = False
            if peer is not None:
                # A /31 makes the far-end interface address arithmetic, so the
                # peer's own capture can be searched for the interface holding
                # it. That pins the link to a port on both ends.
                if adjacency.remote_ip:
                    far = _interface_for_ip(peer, adjacency.remote_ip)
                    if far is not None:
                        remote_port = far.port_id or far.name
                        confirmed = True
                if not confirmed:
                    back = _back_adjacency(snapshot, device, adjacency, peer)
                    if back is not None:
                        # Naming the peer's own port for the far end is what lets
                        # both reports collapse onto one link.
                        remote_port = back.local_port
                        confirmed = True

            if confirmed:
                confidence = 1.0
                note = "confirmed from both ends"
            elif resolved:
                confidence = 0.95
                note = "peer audited"
            else:
                confidence = 0.75
                note = "peer not audited"

            near = LinkEndpoint(device.device_id, adjacency.local_port)
            far = LinkEndpoint(
                peer.device_id if peer else adjacency.remote, remote_port
            )
            # One physical link, reported by each end, must not become two rows.
            # Order the endpoints so both reports land on the same identity;
            # audited devices sort first so a row reads from the known side.
            def _order(endpoint):
                return (
                    endpoint.device_id not in snapshot.devices,
                    endpoint.device_id,
                    endpoint.interface_id or "",
                )

            a, z = sorted((near, far), key=_order)
            link_id = (
                f"reported:{a.device_id}:{a.interface_id or '?'}"
                f":{z.device_id}:{z.interface_id or '?'}"
            )
            evidence = Evidence(
                source="device",
                command=adjacency.protocol,
                detail=(
                    f"{device.device_id} reports {adjacency.local_port} "
                    f"connected to {adjacency.remote}"
                    f" via {adjacency.protocol or 'topology'} ({note})"
                ),
                confidence=confidence,
            )

            existing = snapshot.links.get(link_id)
            if existing is not None:
                # The second end corroborates the first.
                existing.evidence.append(evidence)
                if confidence > existing.confidence:
                    existing.confidence = confidence
                continue

            layer = (
                LinkLayer.OPTICAL
                if device.kind.value == "optical"
                else LinkLayer.LOGICAL
            )
            link = Link(
                link_id=link_id,
                a=a,
                z=z,
                layer=layer,
                confidence=confidence,
                evidence=[evidence],
            )
            snapshot.links[link_id] = link
            created.append(link)
    return created


def _reach_hint(device, address: str) -> str:
    """How a human would get a CLI session on ``address``.

    SR OS carries ``telnet`` and ``ssh`` clients at the root of the CLI (7705 SAR
    Basic System Configuration Guide 25.10.R1, basic command reference:
    ``telnet [ip-address | dns-name] [port] [router router-instance]``), and an
    OSPF neighbour's system address is reachable in the instance the adjacency
    lives in -- so a router can be used as a stepping stone.

    The 1830 PSS has no such client; its general CLI is config/echo/help/history/
    logout/paging/prompt/session/show. Remote NEs are reached by direct IP
    instead, the gateway NE routing DCN traffic over the OSC.

    This is a suggestion printed for a person. Neither command is read-only, so
    neither belongs in a capture profile, and the toolbar button must never run
    one: a nested session changes the prompt underneath the reader.
    """
    if device.kind is DeviceKind.ROUTER:
        transport = preferred_transport(device)
        if transport is None:
            return (
                f"{device.device_id} has no remote-access server enabled; "
                f"connect directly to {address}"
            )
        return f"from {device.device_id}: {transport} {address}"
    return f"connect directly to {address}"


@dataclass(slots=True)
class MissingPeer:
    """A reported-but-not-captured device, and how to go and capture it."""

    address: str
    label: str | None = None
    reporters: list[str] = field(default_factory=list)
    reach: list[str] = field(default_factory=list)

    @property
    def display(self) -> str:
        return f"{self.address} ({self.label})" if self.label else self.address


def unaudited_peers(snapshot: AuditSnapshot) -> dict[str, list[str]]:
    """Peers reported by audited devices but not themselves captured.

    Keys are the address to connect to, annotated with the peer's conventional
    name where the interface naming supplies one -- so a single missing device
    appears once, rather than once per way of referring to it.
    """
    return {peer.display: peer.reporters for peer in missing_peers(snapshot)}


def missing_peers(snapshot: AuditSnapshot) -> list[MissingPeer]:
    """The capture worklist: what the network says exists but was not captured."""
    found: dict[str, MissingPeer] = {}
    for device in snapshot.devices.values():
        for adjacency in device.adjacencies:
            if adjacency.scope == "Int":
                continue
            if _device_for_address(snapshot, adjacency.remote) is not None:
                continue
            peer = found.setdefault(
                adjacency.remote, MissingPeer(address=adjacency.remote)
            )
            peer.label = peer.label or adjacency.remote_label
            entry = f"{device.device_id}:{adjacency.local_port}"
            if entry not in peer.reporters:
                peer.reporters.append(entry)
            hint = _reach_hint(device, adjacency.remote)
            if hint not in peer.reach:
                peer.reach.append(hint)

    # One uncaptured shelf arrives under two keys: OSPF names a peer by system
    # address and LLDP by system name, so the worklist doubled the moment LLDP
    # was parsed. Fold the name-keyed entry into the address-keyed one -- the
    # address is the form you can actually connect to, and the label on that
    # entry is what identifies them as the same device.
    by_label = {
        peer.label.casefold(): peer
        for peer in found.values()
        if peer.label and peer.label.casefold() != peer.address.casefold()
    }
    merged: dict[str, MissingPeer] = {}
    for address, peer in found.items():
        target = by_label.get(address.casefold())
        if target is None or target is peer:
            merged[address] = peer
            continue
        for reporter in peer.reporters:
            if reporter not in target.reporters:
                target.reporters.append(reporter)
        for hint in peer.reach:
            if hint not in target.reach:
                target.reach.append(hint)
    return [merged[address] for address in sorted(merged)]


def hop_counts(snapshot: AuditSnapshot) -> dict[tuple[str, str], int]:
    """Shortest hop count between each pair of *audited* devices.

    Breadth-first over the discovered links. Only edges between two audited
    devices count -- a link to an unaudited peer is a dead end, because nothing
    is known about what lies beyond it.
    """
    known = set(snapshot.devices)
    neighbours: dict[str, set[str]] = {name: set() for name in known}
    for link in snapshot.links.values():
        a, z = link.a.device_id, link.z.device_id
        if a in known and z in known and a != z:
            neighbours[a].add(z)
            neighbours[z].add(a)

    distances: dict[tuple[str, str], int] = {}
    for start in sorted(known):
        seen = {start: 0}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for adjacent in sorted(neighbours[current]):
                if adjacent not in seen:
                    seen[adjacent] = seen[current] + 1
                    queue.append(adjacent)
        for target, distance in seen.items():
            # The graph is undirected, so report each pair once.
            if target > start:
                distances[(start, target)] = distance
    return distances


def correlate_optical_channels(
    snapshot: AuditSnapshot, tolerance_thz: float = 0.001
) -> list[Link]:
    """Create candidate optical links from matching frequency plus circuit ID.

    Only channels with no device-reported far end are considered, and a bare
    frequency match is not enough on its own. Wavelengths are reused all over a
    network, so pairing every same-frequency channel across devices yields
    O(n^2) candidates that are almost all wrong -- on a filter card with eight
    channels per shelf that is pure noise. A matching circuit ID is what makes
    a pair worth reporting.
    """
    linked_ports = {
        (link.a.device_id, link.a.interface_id) for link in snapshot.links.values()
    } | {(link.z.device_id, link.z.interface_id) for link in snapshot.links.values()}

    candidates = []
    for device in snapshot.devices.values():
        for channel in device.optical_channels.values():
            if channel.frequency_thz is None:
                continue
            if (device.device_id, channel.channel_id) in linked_ports:
                continue
            candidates.append((device, channel))

    created: list[Link] = []
    for (a_dev, a_ch), (z_dev, z_ch) in combinations(candidates, 2):
        if a_dev.device_id == z_dev.device_id:
            continue
        if abs(a_ch.frequency_thz - z_ch.frequency_thz) > tolerance_thz:
            continue
        circuit_match = bool(
            a_ch.circuit_id
            and z_ch.circuit_id
            and a_ch.circuit_id.casefold() == z_ch.circuit_id.casefold()
        )
        if not circuit_match:
            continue
        link_id = (
            f"optical:{a_dev.device_id}:{a_ch.channel_id}"
            f":{z_dev.device_id}:{z_ch.channel_id}"
        )
        link = Link(
            link_id=link_id,
            a=LinkEndpoint(a_dev.device_id, a_ch.channel_id),
            z=LinkEndpoint(z_dev.device_id, z_ch.channel_id),
            layer=LinkLayer.OPTICAL,
            frequency_thz=a_ch.frequency_thz,
            confidence=0.85,
            evidence=[
                Evidence(
                    source="correlation",
                    detail="Matching frequency and circuit ID",
                    confidence=0.85,
                )
            ],
        )
        snapshot.links[link_id] = link
        created.append(link)
    return created
