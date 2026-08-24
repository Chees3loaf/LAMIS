"""Chained-capture planning.

Chained capture opens sessions on equipment the operator did not individually
pick, so the guard on what may be typed at a router is the most important thing
in this module. These tests exist mainly to keep that guard honest.
"""

import unittest
from pathlib import Path

from nokia_network_audit.chain import (
    MAX_DEPTH,
    ChainError,
    ChainPlan,
    HopTarget,
    WalkState,
    assert_hop_command,
    hop_targets,
    preferred_transport,
    unaccounted_lags,
)
from nokia_network_audit.models import Adjacency, Device, DeviceKind, Lag
from nokia_network_audit.parsers import parse_pss_transcript, parse_sros_transcript

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class HopCommandGuardTests(unittest.TestCase):
    def test_plain_hops_are_accepted(self):
        for command in (
            "ssh 10.0.0.9",
            "ssh 10.0.0.9 -l admin",
            "ssh 10.0.0.9 -l admin router Base",
            "ssh 10.0.0.9 -p 2222",
            "telnet 10.0.0.9",
            "telnet 10.0.0.9 23",
            "telnet 10.0.0.9 router Base",
        ):
            with self.subTest(command):
                assert_hop_command(command, "10.0.0.9")

    def test_anything_beyond_a_hop_is_refused(self):
        for command in (
            "ssh 10.0.0.9; configure system name X",
            "ssh 10.0.0.9 && admin save",
            "ssh 10.0.0.9 | more",
            "ssh 10.0.0.9\nadmin reboot",
            "configure system",
            "admin reboot",
            "ssh $(whoami)@10.0.0.9",
            "ssh router-b",  # a hostname could resolve anywhere
            "ssh 10.0.0.9 -l admin extra",
        ):
            with self.subTest(command):
                with self.assertRaises(ChainError):
                    assert_hop_command(command, "10.0.0.9")

    def test_a_hop_to_the_wrong_address_is_refused(self):
        # The approved target and the typed target must be the same.
        with self.assertRaises(ChainError):
            assert_hop_command("ssh 10.0.0.250", "10.0.0.9")

    def test_target_builds_and_self_validates_its_command(self):
        target = HopTarget("10.0.0.9", username="admin", router_instance="Base")
        self.assertEqual(target.command(), "ssh 10.0.0.9 -l admin router Base")
        self.assertEqual(HopTarget("10.0.0.9").command(), "ssh 10.0.0.9")

    def test_unknown_transport_is_refused(self):
        with self.assertRaises(ChainError):
            HopTarget("10.0.0.9", transport="rlogin").command()


class TransportSelectionTests(unittest.TestCase):
    def test_real_capture_selects_ssh_because_telnet_is_disabled(self):
        device = parse_sros_transcript(
            (FIXTURES / "ixr_r6.txt").read_text(encoding="utf-8")
        )
        self.assertFalse(device.remote_access["telnet"])
        self.assertTrue(device.remote_access["ssh"])
        self.assertEqual(preferred_transport(device), "ssh")

    def test_nothing_enabled_means_no_hop(self):
        device = Device(
            device_id="R1",
            kind=DeviceKind.ROUTER,
            remote_access={"telnet": False, "ssh": False},
        )
        self.assertIsNone(preferred_transport(device))

    def test_unreported_access_defaults_to_ssh(self):
        self.assertEqual(
            preferred_transport(Device(device_id="R1", kind=DeviceKind.ROUTER)), "ssh"
        )


class HopTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.device = parse_sros_transcript(
            (FIXTURES / "ixr_r6.txt").read_text(encoding="utf-8")
        )

    def test_targets_come_from_protocol_adjacencies(self):
        # This fixture is trimmed to two OSPF neighbours; the full capture it
        # came from has four.
        targets = hop_targets(self.device, username="admin")
        addresses = [t.address for t in targets]
        self.assertEqual(addresses, ["172.16.245.193", "172.16.245.201"])
        self.assertTrue(all(t.transport == "ssh" for t in targets))
        by_address = {t.address: t for t in targets}
        self.assertEqual(by_address["172.16.245.201"].label, "BKLY001_7250")
        self.assertEqual(by_address["172.16.245.201"].via_port, "1/1/c7/1")

    def test_already_captured_devices_are_skipped(self):
        targets = hop_targets(self.device, visited={"172.16.245.193"})
        self.assertNotIn("172.16.245.193", [t.address for t in targets])

    def test_an_optical_shelf_offers_its_span_partner(self):
        """The only way the 1830 layer is discoverable at all.

        A transparent DWDM span puts the far-end *router* into LLDP and OSPF,
        not the shelf carrying the wavelength, so no router ever reports an
        1830. Each shelf's own fibre map is the sole record of its span partner.

        This was previously refused because the 1830 has no ssh client -- true,
        but it is about hopping *from* one. Every hop in a walk is made from the
        origin router, so what matters is that the 1830 answers ssh, which it
        does.
        """
        pss = parse_pss_transcript(
            (FIXTURES / "pss_8.txt").read_text(encoding="utf-8")
        )
        targets = hop_targets(pss)
        self.assertEqual([t.address for t in targets], ["10.9.102.132"])
        self.assertEqual(targets[0].transport, "ssh")

    def test_intra_shelf_fibre_is_not_a_hop_target(self):
        # The same fixture names 1/10/OMD and the line ports as internal peers.
        # Those are fibres inside one shelf, not devices to open a session on.
        pss = parse_pss_transcript(
            (FIXTURES / "pss_8.txt").read_text(encoding="utf-8")
        )
        internal = [a.remote for a in pss.adjacencies if a.scope == "Int"]
        self.assertTrue(internal)  # the fixture really does contain them
        self.assertFalse(set(internal) & {t.address for t in hop_targets(pss)})

    def test_the_span_partner_is_offered_once_however_often_it_is_named(self):
        # The shelf names the same peer on LINEIN, LINEOUT and each channel.
        pss = parse_pss_transcript(
            (FIXTURES / "pss_8.txt").read_text(encoding="utf-8")
        )
        named = [
            a.remote for a in pss.adjacencies
            if a.scope == "Ext" and a.remote == "10.9.102.132"
        ]
        self.assertGreater(len(named), 1)
        self.assertEqual(len(hop_targets(pss)), 1)

    def test_a_router_still_requires_a_protocol_adjacency(self):
        # Relaxing the filter for optical shelves must not let a router follow
        # an adjacency with no protocol behind it: port descriptions were
        # dropped as evidence because this network copies them between LAG
        # members, and they must not come back in through this door.
        device = Device(
            device_id="R1",
            kind=DeviceKind.ROUTER,
            adjacencies=[
                Adjacency("1/1/1", "10.0.0.8", scope="Ext", protocol=None),
                Adjacency("1/1/2", "10.0.0.9", scope="Ext", protocol="ospf"),
            ],
        )
        self.assertEqual([t.address for t in hop_targets(device)], ["10.0.0.9"])

    def test_non_routable_peer_names_are_not_targets(self):
        device = Device(
            device_id="R1",
            kind=DeviceKind.ROUTER,
            adjacencies=[
                Adjacency("1/1/1", "BKLY001_7250", scope="Ext", protocol="description"),
                Adjacency("1/1/2", "10.0.0.9", scope="Ext", protocol="ospf"),
            ],
        )
        self.assertEqual([t.address for t in hop_targets(device)], ["10.0.0.9"])


class SeedTargetTests(unittest.TestCase):
    """Starting points that discovery cannot produce on its own.

    An 1830 behind a transparent DWDM span is named by no router, so without a
    seed the optical layer is never walked however long the walk runs.
    """

    def test_addresses_become_targets_with_an_optional_label(self):
        from nokia_network_audit.chain import seed_targets

        targets = seed_targets("10.9.102.175=KEEL001_1830 10.9.102.99", username="admin")
        self.assertEqual(
            [(t.address, t.label) for t in targets],
            [("10.9.102.175", "KEEL001_1830"), ("10.9.102.99", None)],
        )
        self.assertTrue(all(t.username == "admin" for t in targets))
        self.assertTrue(all(t.via_port == "seed" for t in targets))

    def test_any_reasonable_separator_works(self):
        from nokia_network_audit.chain import seed_targets

        targets = seed_targets("10.0.0.1, 10.0.0.2;10.0.0.3\n10.0.0.4")
        self.assertEqual(len(targets), 4)

    def test_a_repeated_address_is_listed_once(self):
        from nokia_network_audit.chain import seed_targets

        self.assertEqual(len(seed_targets("10.0.0.1 10.0.0.1")), 1)

    def test_nothing_configured_is_not_an_error(self):
        from nokia_network_audit.chain import seed_targets

        self.assertEqual(seed_targets(None), [])
        self.assertEqual(seed_targets("   "), [])

    def test_a_bad_entry_is_refused_rather_than_dropped(self):
        # Skipping it quietly would look exactly like a device that was never
        # found -- and a seed exists precisely because nothing else finds it.
        from nokia_network_audit.chain import seed_targets

        for bad in ("KEEL001_1830", "10.9.102", "10.9.102.999", "10.9.102.1/24"):
            with self.subTest(bad):
                with self.assertRaises(ChainError):
                    seed_targets(bad)

    def test_a_seed_is_issued_in_the_management_routing_instance(self):
        """The failure a live run hit on every seed.

        Optical shelves answer on the management network, which SR OS keeps in
        its own routing instance. Hopping from the default instance produced
        ``MINOR: CLI No route to destination 10.9.102.176.`` for all three
        seeds, while the same address was reachable from the shelf's own
        management port.
        """
        from nokia_network_audit.chain import seed_targets

        self.assertEqual(
            seed_targets("10.9.102.176")[0].command(),
            "ssh 10.9.102.176 -l cli router management",
        )

    def test_the_routing_instance_can_be_changed_or_turned_off(self):
        import os

        from nokia_network_audit.chain import seed_targets

        previous = os.environ.get("NOKIA_AUDIT_SEED_ROUTER")
        try:
            os.environ["NOKIA_AUDIT_SEED_ROUTER"] = "mgmt-vprn"
            self.assertIn("router mgmt-vprn", seed_targets("10.0.0.1")[0].command())
            os.environ["NOKIA_AUDIT_SEED_ROUTER"] = ""
            self.assertEqual(
                seed_targets("10.0.0.1")[0].command(), "ssh 10.0.0.1 -l cli"
            )
        finally:
            if previous is None:
                os.environ.pop("NOKIA_AUDIT_SEED_ROUTER", None)
            else:
                os.environ["NOKIA_AUDIT_SEED_ROUTER"] = previous

    def test_a_discovered_router_is_unaffected_by_the_seed_defaults(self):
        # Routed neighbours live in the default instance and take one ssh login.
        device = Device(
            device_id="R1",
            kind=DeviceKind.ROUTER,
            adjacencies=[Adjacency("1/1/1", "10.0.0.9", scope="Ext", protocol="ospf")],
        )
        target = hop_targets(device, username="admin")[0]
        self.assertEqual(target.command(), "ssh 10.0.0.9 -l admin")
        self.assertIsNone(target.router_instance)
        self.assertIsNone(target.login_user)

    def test_the_management_subnet_is_derived_from_the_origin(self):
        from nokia_network_audit.chain import management_subnet

        device = Device(device_id="ALVY002_7250")
        device.management_ip = "10.9.102.83/22"
        self.assertEqual(management_subnet(device), ("10.9.100.0", 22))

    def test_a_missing_or_malformed_management_address_is_not_guessed_at(self):
        from nokia_network_audit.chain import management_subnet

        for value in (None, "10.9.102.83", "10.9.102.83/abc", "nonsense/22"):
            with self.subTest(value):
                device = Device(device_id="R1")
                device.management_ip = value
                self.assertIsNone(management_subnet(device))

    def test_seeds_off_the_management_subnet_are_identified(self):
        """The mistake that cost a live run.

        Every seed was entered as ``172.21.102.x`` where the shelves answer on
        ``10.9.102.x`` -- right host, wrong prefix -- and the only symptom was
        "MINOR: CLI No route to destination" after the walk had already finished.
        """
        from nokia_network_audit.chain import (
            management_subnet,
            seed_targets,
            seeds_outside_subnet,
        )

        device = Device(device_id="ALVY002_7250")
        device.management_ip = "10.9.102.83/22"
        subnet = management_subnet(device)
        seeds = seed_targets("172.21.102.132 172.21.102.99 10.9.102.176 10.9.103.5")
        self.assertEqual(
            [t.address for t in seeds_outside_subnet(seeds, subnet)],
            ["172.21.102.132", "172.21.102.99"],
        )

    def test_nothing_is_flagged_when_the_subnet_is_unknown(self):
        # Without a management address there is no basis to call a seed wrong,
        # and guessing would block a legitimate one.
        from nokia_network_audit.chain import seed_targets, seeds_outside_subnet

        self.assertEqual(seeds_outside_subnet(seed_targets("172.21.102.1"), None), [])

    def test_a_seed_still_satisfies_the_hop_command_guard(self):
        # Seeds reach the same place as discovered targets, so they must clear
        # the same check on what may be typed at a router.
        from nokia_network_audit.chain import seed_targets

        target = seed_targets("10.9.102.175")[0]
        assert_hop_command("ssh %s" % target.address, target.address)
        with self.assertRaises(ChainError):
            assert_hop_command("ssh 10.9.102.176", target.address)

    def test_the_environment_supplies_a_default_list(self):
        import os

        from nokia_network_audit.chain import SEED_ENV_VAR, seeds_from_environment

        previous = os.environ.get(SEED_ENV_VAR)
        try:
            os.environ[SEED_ENV_VAR] = "10.9.102.99 10.9.102.175"
            self.assertEqual(
                [t.address for t in seeds_from_environment()],
                ["10.9.102.99", "10.9.102.175"],
            )
            os.environ.pop(SEED_ENV_VAR)
            self.assertEqual(seeds_from_environment(), [])
        finally:
            if previous is None:
                os.environ.pop(SEED_ENV_VAR, None)
            else:
                os.environ[SEED_ENV_VAR] = previous

    def test_a_seeded_walk_queues_them_alongside_discovery(self):
        from nokia_network_audit.chain import seed_targets

        state = WalkState(origin="KEEL001_7250")
        state.enqueue(seed_targets("10.9.102.175 10.9.102.99"))
        self.assertEqual(len(state.queue), 2)
        # A seed already captured earlier in the walk is not visited twice.
        state.mark_visited({"10.9.102.175"})
        state.queue.clear()
        self.assertEqual(len(state.enqueue(seed_targets("10.9.102.175"))), 0)


class WalkStateTests(unittest.TestCase):
    def test_a_known_device_is_not_queued_again(self):
        state = WalkState(origin="A", visited={"A", "10.0.0.1"})
        added = state.enqueue(
            [HopTarget("10.0.0.1"), HopTarget("10.0.0.2"), HopTarget("10.0.0.2")]
        )
        self.assertEqual([t.address for t in added], ["10.0.0.2"])
        self.assertEqual(len(state.queue), 1)

    def test_a_device_that_failed_is_not_retried(self):
        state = WalkState(origin="A", failed={"10.0.0.9": "no route"})
        self.assertEqual(state.enqueue([HopTarget("10.0.0.9")]), [])

    def test_targets_visited_mid_queue_are_skipped(self):
        # A device can be discovered twice before it is reached.
        state = WalkState(origin="A")
        state.enqueue([HopTarget("10.0.0.2"), HopTarget("10.0.0.3")])
        state.mark_visited({"10.0.0.2"})
        self.assertEqual(state.next_target().address, "10.0.0.3")
        self.assertIsNone(state.next_target())

    def test_budget_limits_the_walk(self):
        state = WalkState(origin="A", max_devices=2)
        state.captured.extend(["A", "B"])
        self.assertEqual(state.budget_left, 0)

    def test_the_cap_can_be_raised_for_a_large_network(self):
        # The default is a bound on one run, not a claim about network size.
        import os

        from nokia_network_audit.chain import DEFAULT_MAX_WALK_DEVICES, max_walk_devices

        previous = os.environ.get("NOKIA_AUDIT_MAX_DEVICES")
        try:
            self.assertEqual(max_walk_devices(), DEFAULT_MAX_WALK_DEVICES)
            os.environ["NOKIA_AUDIT_MAX_DEVICES"] = "250"
            self.assertEqual(max_walk_devices(), 250)
            self.assertEqual(WalkState(origin="A").max_devices, 250)
            for bad in ("0", "-5", "lots", ""):
                os.environ["NOKIA_AUDIT_MAX_DEVICES"] = bad
                self.assertEqual(max_walk_devices(), DEFAULT_MAX_WALK_DEVICES)
        finally:
            if previous is None:
                os.environ.pop("NOKIA_AUDIT_MAX_DEVICES", None)
            else:
                os.environ["NOKIA_AUDIT_MAX_DEVICES"] = previous


class LagAccountingTests(unittest.TestCase):
    """The walk's completion test: has every LAG's far end been captured?"""

    def _device(self, name, system_id, partner_ids):
        lags = {
            str(i): Lag(str(i), system_id=system_id, partner_system_id=partner)
            for i, partner in enumerate(partner_ids, start=2)
        }
        return Device(device_id=name, kind=DeviceKind.ROUTER, lags=lags)

    def test_a_fully_walked_network_has_nothing_outstanding(self):
        a = self._device("A", "aa", ["bb"])
        b = self._device("B", "bb", ["aa"])
        self.assertEqual(unaccounted_lags([a, b]), [])

    def test_an_uncaptured_far_end_is_reported(self):
        a = self._device("A", "aa", ["bb", "cc"])
        b = self._device("B", "bb", ["aa"])
        self.assertEqual(unaccounted_lags([a, b]), [("A", "3", "cc")])

    def test_matching_is_case_insensitive(self):
        a = self._device("A", "AA:BB", ["cc:dd"])
        b = self._device("B", "cc:dd", ["aa:bb"])
        self.assertEqual(unaccounted_lags([a, b]), [])

    def test_real_captures_account_for_both_ends(self):
        ixr = parse_sros_transcript(
            (FIXTURES / "ixr_r6.txt").read_text(encoding="utf-8")
        )
        sar = parse_sros_transcript(
            (FIXTURES / "sar_8.txt").read_text(encoding="utf-8")
        )
        # On its own the 7250 has two LAGs whose partners are unknown.
        self.assertEqual(len(unaccounted_lags([ixr])), 2)
        # Adding the 7705 accounts for one of them.
        remaining = unaccounted_lags([ixr, sar])
        self.assertEqual(len(remaining), 2)  # 7250 lag-3 and 7705 lag-3
        self.assertNotIn(("MOPN001_7250", "2", "24:f6:8d:8d:ec:00"), remaining)


class ChainPlanTests(unittest.TestCase):
    def test_a_sound_plan_validates(self):
        plan = ChainPlan(
            origin="R1",
            targets=[HopTarget("10.0.0.9", username="admin"), HopTarget("10.0.0.11")],
        )
        plan.validate()
        self.assertIn("ssh 10.0.0.9 -l admin", plan.summary())

    def test_duplicate_targets_are_refused(self):
        plan = ChainPlan(
            origin="R1", targets=[HopTarget("10.0.0.9"), HopTarget("10.0.0.9")]
        )
        with self.assertRaises(ChainError):
            plan.validate()

    def test_depth_is_bounded(self):
        for depth in (0, MAX_DEPTH + 1):
            with self.subTest(depth=depth):
                plan = ChainPlan(origin="R1", targets=[HopTarget("10.0.0.9")], depth=depth)
                with self.assertRaises(ChainError):
                    plan.validate()


if __name__ == "__main__":
    unittest.main()
