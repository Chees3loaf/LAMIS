import unittest
from pathlib import Path

from nokia_network_audit.graph import (
    correlate_optical_channels,
    correlate_reported_adjacencies,
    hop_counts,
    missing_peers,
    unaudited_peers,
)
from nokia_network_audit.models import (
    Adjacency,
    AuditSnapshot,
    Device,
    DeviceKind,
    OpticalChannel,
)
from nokia_network_audit.parsers import parse_pss_transcript, parse_sros_transcript

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _device(name, circuit):
    channel = OpticalChannel(
        channel_id="1/4/9330", frequency_thz=193.30, circuit_id=circuit
    )
    return Device(device_id=name, optical_channels={channel.channel_id: channel})


class ReportedAdjacencyTests(unittest.TestCase):
    def test_far_end_is_resolved_to_an_audited_device(self):
        near = Device(
            device_id="PSS-A",
            adjacencies=[Adjacency("1/10/9310", "10.0.0.2", scope="Ext")],
        )
        far = Device(device_id="PSS-B", management_ip="10.0.0.2/24")
        snapshot = AuditSnapshot(devices={"PSS-A": near, "PSS-B": far})
        links = correlate_reported_adjacencies(snapshot)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].z.device_id, "PSS-B")
        self.assertEqual(links[0].confidence, 0.95)

    def test_unresolved_far_end_is_still_recorded_with_less_weight(self):
        near = Device(
            device_id="PSS-A",
            adjacencies=[Adjacency("1/10/9310", "10.9.102.132", scope="Ext")],
        )
        snapshot = AuditSnapshot(devices={"PSS-A": near})
        links = correlate_reported_adjacencies(snapshot)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].z.device_id, "10.9.102.132")
        self.assertEqual(links[0].confidence, 0.75)

    def test_intra_shelf_fibre_is_not_a_network_link(self):
        near = Device(
            device_id="PSS-A",
            adjacencies=[Adjacency("1/10/OMD", "1/3/LINEIN", scope="Int")],
        )
        snapshot = AuditSnapshot(devices={"PSS-A": near})
        self.assertEqual(correlate_reported_adjacencies(snapshot), [])

    def test_real_capture_yields_links_only_for_external_ports(self):
        device = parse_pss_transcript(
            (FIXTURES / "pss_8.txt").read_text(encoding="utf-8")
        )
        snapshot = AuditSnapshot(devices={device.device_id: device})
        links = correlate_reported_adjacencies(snapshot)
        self.assertTrue(links)
        self.assertTrue(all(link.confidence == 0.75 for link in links))
        local_ports = {link.a.interface_id for link in links}
        self.assertIn("1/10/9310", local_ports)
        self.assertNotIn("1/10/OMD", local_ports)


class RouterAdjacencyTests(unittest.TestCase):
    """Router adjacency from the two join keys the captures actually provide."""

    @classmethod
    def setUpClass(cls):
        cls.ixr = parse_sros_transcript(
            (FIXTURES / "ixr_r6.txt").read_text(encoding="utf-8")
        )
        cls.sar = parse_sros_transcript(
            (FIXTURES / "sar_8.txt").read_text(encoding="utf-8")
        )

    def test_system_address_is_the_join_key(self):
        # A peer reports this value as its OSPF Router ID.
        self.assertEqual(self.ixr.system_address, "172.16.245.191")
        self.assertEqual(self.sar.system_address, "172.16.245.193")

    def test_point_to_point_peer_is_arithmetic(self):
        interface = self.ixr.router_interfaces["to_MOPN001_7705"]
        self.assertEqual(interface.address, "172.18.6.106/31")
        self.assertEqual(interface.point_to_point_peer, "172.18.6.107")
        # A /32 loopback has no peer.
        self.assertIsNone(self.ixr.router_interfaces["system"].point_to_point_peer)

    def test_ospf_adjacency_carries_port_and_far_side_address(self):
        by_port = {a.local_port: a for a in self.ixr.adjacencies}
        adjacency = by_port["lag-2"]
        self.assertEqual(adjacency.protocol, "ospf")
        self.assertEqual(adjacency.remote, "172.16.245.193")
        self.assertEqual(adjacency.remote_ip, "172.18.6.107")
        self.assertEqual(adjacency.remote_label, "MOPN001_7705")

    def test_two_captures_confirm_one_link_from_both_ends(self):
        snapshot = AuditSnapshot(
            devices={self.ixr.device_id: self.ixr, self.sar.device_id: self.sar}
        )
        correlate_reported_adjacencies(snapshot)
        between = [
            link
            for link in snapshot.links.values()
            if {link.a.device_id, link.z.device_id}
            == {"MOPN001_7250", "MOPN001_7705"}
        ]
        # One physical link, one row -- not one row per reporting end.
        self.assertEqual(len(between), 1)
        link = between[0]
        self.assertEqual(link.confidence, 1.0)
        self.assertEqual(len(link.evidence), 2)
        # The /31 pins it to a port on each end.
        self.assertEqual({link.a.interface_id, link.z.interface_id}, {"lag-2"})

    def test_descriptions_never_create_a_link(self):
        # The 7250 gives 1/1/1 and 1/2/1 the same description, so believing it
        # produced a confident link from a port that does not carry it.
        self.assertTrue(
            any("1/1/1 to MOPN001_7705" in (p.description or "")
                for p in self.ixr.ports.values())
        )
        self.assertFalse(
            any(a.protocol == "description" for a in self.ixr.adjacencies)
        )

    def test_hops_between_audited_devices(self):
        snapshot = AuditSnapshot(
            devices={self.ixr.device_id: self.ixr, self.sar.device_id: self.sar}
        )
        correlate_reported_adjacencies(snapshot)
        hops = hop_counts(snapshot)
        self.assertEqual(hops, {("MOPN001_7250", "MOPN001_7705"): 1})

    def test_unaudited_peers_are_listed_once_and_named(self):
        snapshot = AuditSnapshot(devices={self.ixr.device_id: self.ixr})
        missing = unaudited_peers(snapshot)
        # Address to connect to, annotated with the conventional name.
        self.assertIn("172.16.245.201 (BKLY001_7250)", missing)
        self.assertEqual(
            missing["172.16.245.201 (BKLY001_7250)"], ["MOPN001_7250:1/1/c7/1"]
        )
        # An audited peer is not on the worklist.
        snapshot.devices[self.sar.device_id] = self.sar
        self.assertNotIn(
            "172.16.245.193", " ".join(unaudited_peers(snapshot))
        )

    def test_a_dead_end_peer_contributes_no_hops(self):
        # Nothing is known beyond an unaudited peer, so it cannot be a transit.
        snapshot = AuditSnapshot(devices={self.ixr.device_id: self.ixr})
        correlate_reported_adjacencies(snapshot)
        self.assertEqual(hop_counts(snapshot), {})


class ReachHintTests(unittest.TestCase):
    """How to get a session on a peer differs by platform.

    SR OS carries telnet/ssh clients at the root of the CLI, so a router can be
    used as a stepping stone. The 1830 PSS has no such client -- its general CLI
    is config/echo/help/history/logout/paging/prompt/session/show -- so a remote
    NE is reached by direct IP, the gateway NE routing DCN traffic over the OSC.
    """

    def test_router_peer_is_reached_through_the_reporting_router(self):
        # These routers ship telnet disabled and SSH enabled, so the transport
        # comes from what the device says it has, not from a guess.
        router = Device(
            device_id="R1",
            kind=DeviceKind.ROUTER,
            system_address="10.0.0.1",
            remote_access={"telnet": False, "ssh": True},
            adjacencies=[Adjacency("lag-1", "10.0.0.9", scope="Ext", protocol="ospf")],
        )
        snapshot = AuditSnapshot(devices={"R1": router})
        peers = missing_peers(snapshot)
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0].reach, ["from R1: ssh 10.0.0.9"])

    def test_telnet_is_only_suggested_when_ssh_is_off(self):
        router = Device(
            device_id="R1",
            kind=DeviceKind.ROUTER,
            remote_access={"telnet": True, "ssh": False},
            adjacencies=[Adjacency("lag-1", "10.0.0.9", scope="Ext", protocol="ospf")],
        )
        snapshot = AuditSnapshot(devices={"R1": router})
        self.assertEqual(
            missing_peers(snapshot)[0].reach, ["from R1: telnet 10.0.0.9"]
        )

    def test_no_server_enabled_says_so_rather_than_suggesting_a_hop(self):
        router = Device(
            device_id="R1",
            kind=DeviceKind.ROUTER,
            remote_access={"telnet": False, "ssh": False},
            adjacencies=[Adjacency("lag-1", "10.0.0.9", scope="Ext", protocol="ospf")],
        )
        snapshot = AuditSnapshot(devices={"R1": router})
        hint = missing_peers(snapshot)[0].reach[0]
        self.assertIn("no remote-access server enabled", hint)

    def test_transport_is_read_from_a_real_capture(self):
        device = parse_sros_transcript(
            (FIXTURES / "ixr_r6.txt").read_text(encoding="utf-8")
        )
        self.assertEqual(
            device.remote_access,
            {"telnet": False, "telnet6": False, "ssh": True, "ftp": False},
        )

    def test_optical_peer_is_reached_directly(self):
        pss = Device(
            device_id="PSS-A",
            kind=DeviceKind.OPTICAL,
            adjacencies=[Adjacency("1/10/9310", "10.9.102.132", scope="Ext")],
        )
        snapshot = AuditSnapshot(devices={"PSS-A": pss})
        peers = missing_peers(snapshot)
        self.assertEqual(peers[0].reach, ["connect directly to 10.9.102.132"])
        # An 1830 must never be told to telnet from itself.
        self.assertNotIn("telnet", peers[0].reach[0])

    def test_a_peer_reported_by_several_devices_lists_each_route(self):
        r1 = Device(
            device_id="R1",
            kind=DeviceKind.ROUTER,
            adjacencies=[Adjacency("lag-1", "10.0.0.9", scope="Ext")],
        )
        r2 = Device(
            device_id="R2",
            kind=DeviceKind.ROUTER,
            adjacencies=[Adjacency("lag-2", "10.0.0.9", scope="Ext")],
        )
        snapshot = AuditSnapshot(devices={"R1": r1, "R2": r2})
        peer = missing_peers(snapshot)[0]
        self.assertEqual(
            peer.reach, ["from R1: ssh 10.0.0.9", "from R2: ssh 10.0.0.9"]
        )

    def test_reach_hints_are_never_added_to_a_capture_profile(self):
        # telnet/ssh are not read-only, so they must stay suggestions only.
        from nokia_network_audit.profiles import PROFILES, session_commands

        for profile in PROFILES.values():
            for command in session_commands(profile):
                self.assertNotIn("telnet", command.lower())
                self.assertNotIn("ssh", command.lower())


class CorroborationTests(unittest.TestCase):
    """Mutual peering is not corroboration of a specific link."""

    def _pss(self, name, ip, adjacencies):
        return Device(
            device_id=name,
            management_ip=ip,
            kind=DeviceKind.OPTICAL,
            adjacencies=adjacencies,
        )

    def test_same_channel_on_both_ends_collapses_to_one_confirmed_link(self):
        # Neither end names the far-end port, but a channel link joins the same
        # wavelength -- which both identifies the far port and dedupes the row.
        a = self._pss("PSS-A", "10.0.0.1", [Adjacency("1/10/9310", "10.0.0.2", scope="Ext")])
        b = self._pss("PSS-B", "10.0.0.2", [Adjacency("1/10/9310", "10.0.0.1", scope="Ext")])
        snapshot = AuditSnapshot(devices={"PSS-A": a, "PSS-B": b})
        links = correlate_reported_adjacencies(snapshot)
        self.assertEqual(len(snapshot.links), 1)
        link = links[0]
        self.assertEqual(link.confidence, 1.0)
        self.assertEqual(len(link.evidence), 2)
        self.assertEqual(
            {link.a.interface_id, link.z.interface_id}, {"1/10/9310"}
        )

    def test_different_channels_are_not_treated_as_one_link(self):
        a = self._pss("PSS-A", "10.0.0.1", [Adjacency("1/10/9310", "10.0.0.2", scope="Ext")])
        b = self._pss("PSS-B", "10.0.0.2", [Adjacency("1/10/9320", "10.0.0.1", scope="Ext")])
        snapshot = AuditSnapshot(devices={"PSS-A": a, "PSS-B": b})
        correlate_reported_adjacencies(snapshot)
        self.assertEqual(len(snapshot.links), 2)
        self.assertTrue(all(l.confidence == 0.95 for l in snapshot.links.values()))

    def test_peer_naming_us_elsewhere_is_not_confirmation(self):
        # PSS-B reports a link to PSS-A, but on an unrelated port. Treating that
        # as corroboration marked every such link 1.00 on one-sided evidence.
        a = self._pss(
            "PSS-A", "10.0.0.1", [Adjacency("1/3/LINEOUT", "10.0.0.2", "1/2/1", scope="Ext")]
        )
        b = self._pss(
            "PSS-B", "10.0.0.2", [Adjacency("1/3/LINEOUT", "10.0.0.1", "1/2/1", scope="Ext")]
        )
        snapshot = AuditSnapshot(devices={"PSS-A": a, "PSS-B": b})
        correlate_reported_adjacencies(snapshot)
        # The far end is called "1/2/1" but the peer calls that port
        # "1/3/LINEOUT", so no pairing is provable from device output.
        for link in snapshot.links.values():
            self.assertEqual(link.confidence, 0.95)
            self.assertEqual(len(link.evidence), 1)

    def test_explicitly_named_far_port_confirms_when_the_peer_agrees(self):
        a = self._pss(
            "PSS-A", "10.0.0.1", [Adjacency("1/3/LINEOUT", "10.0.0.2", "1/2/LINEIN", scope="Ext")]
        )
        b = self._pss(
            "PSS-B", "10.0.0.2", [Adjacency("1/2/LINEIN", "10.0.0.1", "1/3/LINEOUT", scope="Ext")]
        )
        snapshot = AuditSnapshot(devices={"PSS-A": a, "PSS-B": b})
        correlate_reported_adjacencies(snapshot)
        self.assertEqual(len(snapshot.links), 1)
        link = next(iter(snapshot.links.values()))
        self.assertEqual(link.confidence, 1.0)


class FrequencyCorrelationTests(unittest.TestCase):
    def test_frequency_and_circuit_id_produce_a_candidate(self):
        snapshot = AuditSnapshot(
            devices={"A": _device("A", "WEST"), "B": _device("B", "WEST")}
        )
        links = correlate_optical_channels(snapshot)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].confidence, 0.85)

    def test_frequency_alone_produces_nothing(self):
        # Wavelengths are reused throughout a network, so pairing every
        # same-frequency channel yields O(n^2) candidates that are nearly all
        # wrong -- and each one used to become an UNKNOWN topology finding.
        snapshot = AuditSnapshot(
            devices={"A": _device("A", None), "B": _device("B", None)}
        )
        self.assertEqual(correlate_optical_channels(snapshot), [])

    def test_channels_with_a_reported_far_end_are_skipped(self):
        near = _device("A", "WEST")
        near.adjacencies = [Adjacency("1/4/9330", "B", scope="Ext")]
        far = _device("B", "WEST")
        snapshot = AuditSnapshot(devices={"A": near, "B": far})
        correlate_reported_adjacencies(snapshot)
        # The reported link already covers this channel; do not also guess.
        self.assertEqual(correlate_optical_channels(snapshot), [])


class MissingPeerFoldingTests(unittest.TestCase):
    """One uncaptured shelf must appear on the worklist once, not per naming."""

    def test_ospf_address_and_lldp_name_fold_into_one_entry(self):
        # Verbatim shape of the live case: the 7250 reports its 7705 by system
        # address on the LAG (OSPF) and by system name on each member (LLDP).
        device = Device(
            device_id="BKLY001_7250",
            adjacencies=[
                Adjacency(
                    local_port="lag-2",
                    remote="172.16.245.203",
                    remote_label="BKLY001_7705",
                    scope="Ext",
                    protocol="ospf",
                ),
                Adjacency(
                    local_port="1/1/1",
                    remote="BKLY001_7705",
                    remote_port="1/1/5",
                    remote_label="BKLY001_7705",
                    scope="Ext",
                    protocol="lldp",
                ),
            ],
        )
        snapshot = AuditSnapshot(devices={"BKLY001_7250": device})
        peers = missing_peers(snapshot)
        self.assertEqual(len(peers), 1)
        peer = peers[0]
        # The address survives as the key, because that is what you can ssh to.
        self.assertEqual(peer.address, "172.16.245.203")
        self.assertEqual(peer.label, "BKLY001_7705")
        # Both sightings are credited, so the port evidence is not lost.
        self.assertEqual(
            sorted(peer.reporters),
            ["BKLY001_7250:1/1/1", "BKLY001_7250:lag-2"],
        )

    def test_a_name_only_peer_is_still_listed(self):
        # No OSPF adjacency to fold into: LLDP is the only sighting, and dropping
        # it would hide the device entirely.
        device = Device(
            device_id="A",
            adjacencies=[
                Adjacency(
                    local_port="1/1/1",
                    remote="LONE_7705",
                    remote_label="LONE_7705",
                    scope="Ext",
                    protocol="lldp",
                )
            ],
        )
        peers = missing_peers(AuditSnapshot(devices={"A": device}))
        self.assertEqual([p.address for p in peers], ["LONE_7705"])

    def test_unrelated_peers_are_not_merged(self):
        device = Device(
            device_id="A",
            adjacencies=[
                Adjacency("lag-2", "10.0.0.1", remote_label="X_7705", scope="Ext"),
                Adjacency("lag-3", "10.0.0.2", remote_label="Y_7705", scope="Ext"),
            ],
        )
        peers = missing_peers(AuditSnapshot(devices={"A": device}))
        self.assertEqual([p.address for p in peers], ["10.0.0.1", "10.0.0.2"])


class LldpMemberLinkTests(unittest.TestCase):
    """LLDP resolves a link down to the LAG member port, and both ends agree.

    OSPF pins a link to an interface, and a LAG is one interface however many
    fibres it carries. Two shelves joined by a 2-member LAG therefore produce a
    single OSPF-derived link with no way to tell which member is which. LLDP
    reports per port, so the same span becomes one link per member -- and because
    each end names the other's port, the pairing is confirmed rather than assumed.
    """

    def _snapshot(self):
        near = parse_sros_transcript(
            (FIXTURES / "sar_8_system.txt").read_text(encoding="utf-8")
        )
        # The far end as its own capture would report it: the exact reciprocal of
        # the two rows the 7705 shows for it.
        far = Device(
            device_id="MOPN002_7250",
            base_mac="24:f6:8d:32:10:00",
            adjacencies=[
                Adjacency(
                    local_port="1/1/1",
                    remote="MOPN002_7705",
                    remote_port="1/1/5",
                    scope="Ext",
                    protocol="lldp",
                    remote_chassis_id="24:f6:8d:8d:2c:00",
                ),
                Adjacency(
                    local_port="1/2/1",
                    remote="MOPN002_7705",
                    remote_port="1/2/5",
                    scope="Ext",
                    protocol="lldp",
                    remote_chassis_id="24:f6:8d:8d:2c:00",
                ),
            ],
        )
        snapshot = AuditSnapshot(
            devices={near.device_id: near, far.device_id: far}
        )
        correlate_reported_adjacencies(snapshot)
        return snapshot

    def test_each_lag_member_becomes_its_own_confirmed_link(self):
        snapshot = self._snapshot()
        pairs = {
            (link.a.interface_id, link.z.interface_id): link.confidence
            for link in snapshot.links.values()
            if {link.a.device_id, link.z.device_id}
            == {"MOPN002_7705", "MOPN002_7250"}
        }
        self.assertEqual(pairs, {("1/1/1", "1/1/5"): 1.0, ("1/2/1", "1/2/5"): 1.0})

    def test_reciprocal_reports_collapse_onto_one_link_each(self):
        snapshot = self._snapshot()
        # Two members, reported from both ends -- four adjacencies, two links.
        between = [
            link
            for link in snapshot.links.values()
            if {link.a.device_id, link.z.device_id}
            == {"MOPN002_7705", "MOPN002_7250"}
        ]
        self.assertEqual(len(between), 2)
        for link in between:
            self.assertEqual(len(link.evidence), 2)

    def test_naming_the_peer_on_the_wrong_port_is_not_confirmation(self):
        # Guards the failure mode the /31 and channel keys were written for: a
        # peer that mentions this device somewhere must not confirm a pairing it
        # never reported. Here the far end thinks 1/1/1 faces 1/1/9, not 1/1/5.
        near = Device(
            device_id="A",
            adjacencies=[
                Adjacency("1/1/5", "B", remote_port="1/1/1", scope="Ext", protocol="lldp")
            ],
        )
        far = Device(
            device_id="B",
            adjacencies=[
                Adjacency("1/1/9", "A", remote_port="1/1/5", scope="Ext", protocol="lldp")
            ],
        )
        snapshot = AuditSnapshot(devices={"A": near, "B": far})
        correlate_reported_adjacencies(snapshot)
        # A's report cannot be matched to a B row naming 1/1/1 as B's own port,
        # so it stays at "peer audited" rather than becoming confirmed.
        a_side = snapshot.links["reported:A:1/1/5:B:1/1/1"]
        self.assertEqual(a_side.confidence, 0.95)


if __name__ == "__main__":
    unittest.main()
