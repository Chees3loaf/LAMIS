"""Parser and audit tests driven by captures taken from live equipment.

The fixtures in ``fixtures/`` are trimmed from real SecureCRT sessions against a
7250 IXR-R6, a 7705 SAR-8 v2, and an 1830 PSS-8. Column alignment and section
banners are preserved verbatim, because that layout is exactly what the parsers
have to cope with -- SR OS prints two label/value columns per line, and the
1830 wraps critical alarm rows in ANSI colour.
"""

import unittest
from pathlib import Path

from nokia_network_audit.audit import AuditEngine
from nokia_network_audit.models import (
    AuditSnapshot,
    Device,
    FindingSeverity,
    Lag,
    LagMember,
    Platform,
    Port,
)
from nokia_network_audit.parsers import parse_pss_transcript, parse_sros_transcript

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class IxrR6Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.device = parse_sros_transcript(load("ixr_r6.txt"))

    def test_identity(self):
        self.assertEqual(self.device.device_id, "MOPN001_7250")
        self.assertEqual(self.device.platform, Platform.IXR_R6)
        self.assertEqual(self.device.software_release, "B-25.10.R2")
        self.assertEqual(self.device.management_ip, "10.9.102.140/22")

    def test_non_numeric_and_breakout_port_ids_are_found(self):
        # CPM ports use a letter slot and QSFP28 connectors add a breakout
        # level, so a slot/mda/port pattern alone misses them.
        for port_id in ("A/1", "A/gnss", "1/1/1", "1/2/c7", "1/2/c7/1"):
            self.assertIn(port_id, self.device.ports)

    def test_two_column_layout_does_not_bleed_into_values(self):
        port = self.device.ports["1/1/1"]
        # "Oper State : up - Active in LAG 2" reduces to the bare keyword.
        self.assertEqual(port.oper_state, "up")
        self.assertEqual(port.admin_state, "up")
        # "Admin State : down    Oper Duplex : full" must not capture the pair.
        self.assertEqual(self.device.ports["1/1/3"].oper_state, "down")

    def test_description_belongs_to_its_own_port(self):
        # Description is printed *above* the Interface line, so slicing blocks
        # at the interface line attributes it to the previous port.
        self.assertEqual(
            self.device.ports["1/1/1"].description,
            "MOPN001_7250 1/1/1 to MOPN001_7705 1/1/5",
        )
        self.assertEqual(
            self.device.ports["1/1/3"].description, "1-Gig/10-Gig Ethernet"
        )

    def test_speed_is_read_from_the_right_hand_column(self):
        self.assertEqual(self.device.ports["1/1/1"].rate, "10g")
        self.assertEqual(self.device.ports["1/1/1"].rate_bps, 10_000_000_000)
        self.assertEqual(self.device.ports["1/2/c7/1"].rate, "100g")
        self.assertEqual(self.device.ports["A/1"].rate, "100m")

    def test_optic_power_comes_from_the_following_ddm_section(self):
        optic = self.device.ports["1/1/1"].optic
        self.assertIsNotNone(optic)
        self.assertEqual(optic.part_number, "RTXM228-401-C85")
        self.assertEqual(optic.tx_dbm, -2.25)
        self.assertEqual(optic.rx_dbm, -1.58)

    def test_coherent_module_frequency_and_power(self):
        optic = self.device.ports["1/2/c7"].optic
        self.assertEqual(optic.frequency_thz, 193.1)
        self.assertEqual(optic.tx_dbm, -6.85)
        self.assertEqual(optic.rx_dbm, 5.88)
        # Thresholds are printed per lane, with no value column.
        self.assertEqual(optic.rx_limits.high_alarm, 2.00)
        self.assertEqual(optic.tx_limits.low_alarm, -14.00)

    def test_each_lag_is_separate(self):
        # "show lag detail" must not be read as a LAG named "detail" holding
        # every member of every LAG.
        self.assertEqual(sorted(self.device.lags), ["2", "3"])
        lag = self.device.lags["2"]
        self.assertEqual(lag.description, "to_MOPN001_7705")
        self.assertEqual(lag.oper_state, "up")
        self.assertEqual([m.port_id for m in lag.members], ["1/1/1", "1/2/1"])
        self.assertEqual(self.device.lags["3"].partner_system_id, "24:f6:8d:8d:2c:00")

    def test_receive_power_above_alarm_threshold_is_reported(self):
        # The device itself flags this reading as "5.89/H-WA".
        snapshot = AuditSnapshot(devices={self.device.device_id: self.device})
        findings = AuditEngine().run(snapshot)
        optic_fails = [
            f
            for f in findings
            if f.rule_id == "OPTIC-001" and f.subject.endswith("1/2/c7")
        ]
        self.assertEqual(len(optic_fails), 1)
        self.assertEqual(optic_fails[0].severity, FindingSeverity.FAIL)
        self.assertIn("Rx power 5.88", optic_fails[0].message)


class Sar8Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.device = parse_sros_transcript(load("sar_8.txt"))

    def test_identity(self):
        self.assertEqual(self.device.device_id, "MOPN001_7705")
        # "7705 SAR-8 v2" must still resolve to the SAR-8 platform.
        self.assertEqual(self.device.platform, Platform.SAR_7705_8)
        self.assertEqual(self.device.software_release, "B-25.10.R1")

    def test_two_column_state_with_trailing_pair(self):
        # "Oper State : up - Active in LAG 2       Config Duplex : N/A"
        self.assertEqual(self.device.ports["1/1/5"].oper_state, "up")
        self.assertEqual(self.device.ports["1/1/1"].oper_state, "down")

    def test_voice_and_tdm_ports_use_status_labels(self):
        # These blocks say "Admin Status"/"Oper Status", not "... State".
        for port_id in ("1/3/1", "1/4/1", "1/5/1"):
            self.assertEqual(self.device.ports[port_id].oper_state, "down")

    def test_lag_detail_uses_the_bare_lag_heading(self):
        # The 7705 heads each section "LAG 2"; the 7250 uses "Lag-id : 2".
        self.assertEqual(sorted(self.device.lags), ["2", "3"])
        self.assertEqual(
            [m.port_id for m in self.device.lags["2"].members], ["1/1/5", "1/2/5"]
        )

    def test_empty_aps_table_raises_no_sonet_finding(self):
        snapshot = AuditSnapshot(devices={self.device.device_id: self.device})
        findings = AuditEngine().run(snapshot)
        self.assertFalse([f for f in findings if f.rule_id.startswith("SONET")])


class Pss8Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.device = parse_pss_transcript(load("pss_8.txt"))

    def test_identity(self):
        self.assertEqual(self.device.device_id, "MOPN001_1830")
        self.assertEqual(self.device.platform, Platform.PSS_8)
        self.assertEqual(self.device.software_release, "1830PSSECX-25.12-3")
        self.assertEqual(self.device.serial_number, "RT254507385")

    def test_channels_come_from_the_card_listing(self):
        self.assertEqual(len(self.device.optical_channels), 8)
        channel = self.device.optical_channels["1/10/9330"]
        self.assertEqual(channel.frequency_thz, 193.30)
        self.assertEqual(channel.wavelength_nm, 1550.92)
        self.assertEqual(channel.oper_state, "down")
        # The OMD and EXP rows share the AID shape but are not channels.
        self.assertNotIn("1/10/OMD", self.device.optical_channels)

    def test_ansi_coloured_critical_alarm_is_not_lost(self):
        # The PSS wraps critical rows in "\x1b[1;31m", which leaves the row
        # indented once the escape is stripped.
        critical = [a for a in self.device.alarms if a.is_critical]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0].condition, "PWR")
        self.assertEqual(critical[0].subject, "1/7")
        self.assertTrue(critical[0].service_affecting)
        self.assertEqual(critical[0].description, "Battery off or power filter off")

    def test_all_conditions_are_captured(self):
        self.assertEqual(len(self.device.alarms), 9)
        self.assertEqual(
            len([a for a in self.device.alarms if a.condition == "OPR-OUT"]), 3
        )

    def test_reported_topology_names_the_far_end(self):
        external = {
            (a.local_port, a.remote)
            for a in self.device.adjacencies
            if a.scope == "Ext"
        }
        self.assertIn(("1/10/9310", "10.9.102.132"), external)
        # A port whose "Connected To" is "-" still names a peer under
        # "Connected From".
        self.assertIn(("1/2/LINEIN", "10.9.102.132"), external)

    def test_equipment_alarms_become_findings(self):
        snapshot = AuditSnapshot(devices={self.device.device_id: self.device})
        findings = AuditEngine().run(snapshot)
        alarm_findings = [f for f in findings if f.rule_id == "ALARM-001"]
        self.assertTrue(
            any(
                f.severity == FindingSeverity.FAIL and "1/7" in f.subject
                for f in alarm_findings
            )
        )

    def test_unalarmed_conditions_are_reported_not_discarded(self):
        # "NR" conditions are not alarms, but OPR-OUT ("outgoing channel optical
        # power out of range") and PWRADJFAIL are real optical problems, and here
        # they sit on the only channels carrying traffic. Dropping them hid them
        # entirely; inflating them to WARN would cry wolf.
        snapshot = AuditSnapshot(devices={self.device.device_id: self.device})
        findings = AuditEngine().run(snapshot)
        info = [f for f in findings if f.severity == FindingSeverity.INFO]
        conditions = [f.message for f in info]
        self.assertEqual(len([m for m in conditions if "OPR-OUT" in m]), 3)
        self.assertTrue(any("PWRADJFAIL" in m for m in conditions))
        # None of them may be promoted above the device's own weight.
        self.assertFalse(
            any(
                "OPR-OUT" in f.message
                and f.severity in (FindingSeverity.WARN, FindingSeverity.FAIL)
                for f in findings
            )
        )

    def test_bidirectional_rows_do_not_duplicate_an_adjacency(self):
        # A channel names the same far end under both "Connected To" and
        # "Connected From", so the row yields the identical adjacency twice.
        keys = [
            (a.local_port, a.remote, a.remote_port, a.scope)
            for a in self.device.adjacencies
        ]
        self.assertEqual(len(keys), len(set(keys)))

    def test_a_raw_session_log_has_no_capture_host(self):
        # This fixture is a plain terminal log, which carries no header. The
        # button writes one; both shapes are valid input.
        self.assertIsNone(self.device.management_ip)

    def test_management_address_falls_back_to_the_capture_host(self):
        # No baseline command makes an 1830 print its own address, so without
        # this a peer 1830 could never be matched by address when building links.
        text = (
            "# Nokia Network Audit raw baseline transcript\n"
            "# Host: 10.9.102.139\n"
            "# Profile: 1830-pss-8\n"
            "\n"
            "MOPN001_1830# show general system-identification\n"
            "Shelf type               : PSS-8\n"
        )
        device = parse_pss_transcript(text)
        self.assertEqual(device.management_ip, "10.9.102.139")


class SonetRuleTests(unittest.TestCase):
    """SONET/SDH rule logic, exercised from model objects rather than CLI text.

    Written when no OC-n capture existed. Real 7705s with a channelised OC3
    adapter have since been captured, and ``SonetPortTests`` covers the parsing
    path against their verbatim output -- these stay as the narrow check on rule
    behaviour alone.

    Every port here declares ``admin_state="up"``, which is not decoration: a
    port that is administratively down is skipped by all of these rules, because
    an out-of-service channel legitimately reports loss of signal and grading it
    produced thirty-four confident failures about equipment doing as it was told.
    """

    def _device(self, **port_kwargs):
        port_kwargs.setdefault("admin_state", "up")
        port = Port(port_id="1/2/1", rate="oc3", **port_kwargs)
        port.finalize()
        return Device(device_id="SITE-A", ports={port.port_id: port})

    def test_down_sonet_port_fails(self):
        device = self._device(admin_state="up", oper_state="down")
        findings = AuditEngine().run(AuditSnapshot(devices={"SITE-A": device}))
        self.assertTrue(any(f.rule_id == "SONET-001" for f in findings))

    def test_an_out_of_service_channel_is_not_graded(self):
        device = self._device(admin_state="down", oper_state="down", alarms=["LOS"])
        rules = {
            f.rule_id
            for f in AuditEngine().run(AuditSnapshot(devices={"SITE-A": device}))
        }
        self.assertFalse({r for r in rules if r.startswith("SONET")})

    def test_sonet_alarms_fail(self):
        device = self._device(oper_state="up", alarms=["LOS", "LOF"])
        findings = AuditEngine().run(AuditSnapshot(devices={"SITE-A": device}))
        self.assertTrue(any(f.rule_id == "SONET-002" for f in findings))

    def test_aps_group_without_role_warns(self):
        device = self._device(oper_state="up", aps_group="1")
        findings = AuditEngine().run(AuditSnapshot(devices={"SITE-A": device}))
        self.assertTrue(
            any(
                f.rule_id == "SONET-003" and f.severity == FindingSeverity.WARN
                for f in findings
            )
        )


class ChassisHealthTests(unittest.TestCase):
    """Alarm state a classic SR OS chassis reports about itself.

    Classic 7705 SAR / 7250 IXR have no "list active alarms" command --
    ``show system alarms`` is 7705 SAR Gen 2 only. Everything here already
    arrived in ``show chassis detail`` and was simply not being read, so routers
    reported no alarm state at all while the 1830s produced findings.
    """

    HEALTHY = """
  Critical LED state                : Off
  Major LED state                   : Off
  Minor LED state                   : Off
  Over Temperature state            : OK
Chassis 1 Detail
    Current alarm state             : alarm cleared
    External Alarms Interface
       --------------------------------------------
        Input  Pin  Event           State
       --------------------------------------------
          IN-1   1    Critical      : ok
          IN-2   2    Major         : ok
"""

    ALARMED = """
  Critical LED state                : Red
  Major LED state                   : Off
  Minor LED state                   : Amber
  Over Temperature state            : OK
Chassis 1 Detail
    Current alarm state             : alarm active
    External Alarms Interface
       --------------------------------------------
        Input  Pin  Event           State
       --------------------------------------------
          IN-1   1    Critical      : alarm
          IN-4   12   Minor         : ok
"""

    def _findings(self, chassis_text):
        device = parse_sros_transcript(
            "A:SITE-A# show chassis detail\n"
            "  Name                              : SITE-A\n"
            "  Type                              : 7705 SAR-8 v2\n" + chassis_text
        )
        return device, AuditEngine().run(
            AuditSnapshot(devices={device.device_id: device})
        )

    def test_a_clear_chassis_passes_once(self):
        device, findings = self._findings(self.HEALTHY)
        self.assertTrue(device.chassis.reported)
        chassis = [f for f in findings if f.rule_id.startswith("CHASSIS")]
        self.assertEqual([f.rule_id for f in chassis], ["CHASSIS-000"])
        self.assertEqual(chassis[0].severity, FindingSeverity.PASS)

    def test_a_lit_critical_led_fails(self):
        _device, findings = self._findings(self.ALARMED)
        rules = {f.rule_id: f.severity for f in findings if f.rule_id.startswith("CHASSIS")}
        self.assertEqual(rules.get("CHASSIS-001"), FindingSeverity.FAIL)
        self.assertEqual(rules.get("CHASSIS-002"), FindingSeverity.WARN)  # Minor
        self.assertEqual(rules.get("CHASSIS-004"), FindingSeverity.WARN)  # component
        self.assertNotIn("CHASSIS-000", rules)

    def test_an_asserted_external_input_is_raised_at_its_own_severity(self):
        _device, findings = self._findings(self.ALARMED)
        inputs = [f for f in findings if f.rule_id == "CHASSIS-005"]
        self.assertEqual(len(inputs), 1, "only IN-1 is asserted")
        self.assertEqual(inputs[0].severity, FindingSeverity.FAIL)
        self.assertIn("IN-1", inputs[0].subject)

    def test_over_temperature_fails(self):
        _device, findings = self._findings(
            self.HEALTHY.replace("Over Temperature state            : OK",
                                 "Over Temperature state            : Over Temperature")
        )
        self.assertIn("CHASSIS-003", {f.rule_id for f in findings})

    def test_show_external_alarms_input_rows_are_read(self):
        # Verbatim layout from the Interface Configuration Guide 25.10.R1.
        device = parse_sros_transcript(
            "A:SITE-A# show system information\n"
            "System Type            : 7705 SAR-8 v2\n"
            "A:SITE-A# show external-alarms input\n"
            "===========================================================\n"
            "External Alarm Input Summary\n"
            "===========================================================\n"
            "Input Id     Name          Type       Admin  Value  Alarm State\n"
            "-----------------------------------------------------------\n"
            "alarm.d-1                  Digital-In Up     Open   Ok\n"
            "port-1/5/1   CABINET-DOOR  Oper-State Up     Down   Alarm-Detected\n"
        )
        by_id = {i.input_id: i for i in device.chassis.external_inputs}
        self.assertIn("alarm.d-1", by_id)
        self.assertFalse(by_id["alarm.d-1"].asserted)
        self.assertTrue(by_id["port-1/5/1"].asserted)
        self.assertEqual(by_id["port-1/5/1"].name, "CABINET-DOOR")

    def test_a_capture_without_chassis_detail_raises_nothing(self):
        # Silence is not a pass: an absent section must not claim health.
        device = parse_sros_transcript(
            "A:SITE-A# show system information\nSystem Type : 7705 SAR-8 v2\n"
        )
        self.assertFalse(device.chassis.reported)
        findings = AuditEngine().run(AuditSnapshot(devices={device.device_id: device}))
        self.assertFalse([f for f in findings if f.rule_id.startswith("CHASSIS")])


class SystemTimingTests(unittest.TestCase):
    """``show system sync-if-timing``.

    The text below is the output example from the 7705 SAR Basic System
    Configuration Guide 25.10.R1, re-indented as a terminal prints it. That
    example is for a **SAR-18**: it has BITS references a SAR-8 or 7250 IXR does
    not, so the parser must read whatever blocks are present rather than expect a
    fixed set. Still to be validated against a real SAR-8/7250 capture.
    """

    DOC_OUTPUT = """
A:ALU-1# show system sync-if-timing
===============================================================================
System Interface Timing Operational Info
===============================================================================
System Status CSM A      : Master Locked
Reference Input Mode     : Non-revertive
Quality Level Selection  : Disabled
Reference Order          : bits ref1 ref2

Reference Input 1
    Admin Status              : down
    Configured Quality Level  : none
    Rx Quality Level          : unknown
    Qualified For Use         : No
    Not Qualified Due To      : disabled
    Selected For Use          : No
    Not Selected Due To       : disabled

Reference Input 2
    Admin Status              : down
    Configured Quality Level  : none
    Rx Quality Level          : unknown
    Qualified For Use         : No
    Not Qualified Due To      : disabled
    Selected For Use          : No
    Not Selected Due To       : disabled

Reference BITS 1
    Admin Status              : up
    Configured Quality Level  : stu
    Rx Quality Level          : unknown
    Qualified For Use         : Yes
    Selected For Use          : Yes
    Interface Type            : DS1
    Framing                   : ESF
    Line Coding               : B8ZS

Reference BITS 2
    Admin Status              : up
    Configured Quality Level  : stu
    Rx Quality Level          : unknown
    Qualified For Use         : No
    Not Qualified Due To      : LOS
    Selected For Use          : No
    Not Selected Due To       : not qualified
===============================================================================
"""

    def _device(self, timing_text, header="System Type            : 7705 SAR-8 v2\n"):
        return parse_sros_transcript(
            "A:ALU-1# show system information\n" + header + timing_text
        )

    def test_status_and_header_fields(self):
        timing = self._device(self.DOC_OUTPUT).timing
        self.assertTrue(timing.reported)
        self.assertEqual(timing.status, {"CSM A": "Master Locked"})
        self.assertTrue(timing.locked)
        self.assertEqual(timing.reference_mode, "Non-revertive")
        self.assertEqual(timing.reference_order, "bits ref1 ref2")

    def test_every_reference_block_is_read(self):
        timing = self._device(self.DOC_OUTPUT).timing
        self.assertEqual(
            [r.name for r in timing.references],
            [
                "Reference Input 1",
                "Reference Input 2",
                "Reference BITS 1",
                "Reference BITS 2",
            ],
        )
        by_name = {r.name: r for r in timing.references}
        bits1 = by_name["Reference BITS 1"]
        self.assertTrue(bits1.is_admin_up)
        self.assertTrue(bits1.is_qualified)
        self.assertTrue(bits1.is_selected)
        bits2 = by_name["Reference BITS 2"]
        self.assertFalse(bits2.is_qualified)
        self.assertEqual(bits2.not_qualified_reason, "LOS")
        self.assertEqual(timing.selected_references, ["Reference BITS 1"])

    def test_a_locked_node_with_a_failed_standby_reference_warns_only(self):
        findings = AuditEngine().run(
            AuditSnapshot(devices={"ALU-1": self._device(self.DOC_OUTPUT)})
        )
        timing_findings = {
            f.rule_id: f.severity for f in findings if f.rule_id.startswith("TIMING")
        }
        # Locked, so no failure -- but BITS 2 is enabled and unusable.
        self.assertNotIn("TIMING-001", timing_findings)
        self.assertEqual(timing_findings.get("TIMING-002"), FindingSeverity.WARN)

    def test_an_unlocked_node_fails(self):
        text = self.DOC_OUTPUT.replace("Master Locked", "Master Freerun")
        findings = AuditEngine().run(
            AuditSnapshot(devices={"ALU-1": self._device(text)})
        )
        failures = [f for f in findings if f.rule_id == "TIMING-001"]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].severity, FindingSeverity.FAIL)
        self.assertIn("Master Freerun", failures[0].message)

    def test_a_node_with_no_references_still_passes_when_locked(self):
        # A SAR-8 has no BITS; a capture may show status and nothing else.
        text = """
A:ALU-1# show system sync-if-timing
===============================================================================
System Interface Timing Operational Info
===============================================================================
System Status CSM A      : Master Locked
Reference Order          : ref1 ref2
===============================================================================
"""
        device = self._device(text)
        self.assertEqual(device.timing.references, [])
        findings = AuditEngine().run(AuditSnapshot(devices={"ALU-1": device}))
        rules = {f.rule_id for f in findings}
        self.assertIn("TIMING-000", rules)
        self.assertNotIn("TIMING-003", rules)

    def test_timing_labels_do_not_leak_in_from_port_output(self):
        # "Admin Status" and "Rx Quality Level" also appear in show port detail,
        # so timing is parsed from its own command section only.
        device = parse_sros_transcript(
            (FIXTURES / "sar_8.txt").read_text(encoding="utf-8")
        )
        self.assertFalse(device.timing.reported)
        findings = AuditEngine().run(
            AuditSnapshot(devices={device.device_id: device})
        )
        self.assertFalse([f for f in findings if f.rule_id.startswith("TIMING")])


class LiveSystemOutputTests(unittest.TestCase):
    """Timing, redundancy and CPU against a **live 7705 SAR-8 v2** capture.

    `sar_8_system.txt` is taken verbatim from hardware. It matters because the
    documentation was wrong in ways that silently disabled the timing audit:
    the doc says ``System Status CSM A``, the device says **CPM A**, and the
    device has ``External Reference Input``/``Output`` blocks the doc never
    shows while lacking the BITS blocks the doc does show.
    """

    @classmethod
    def setUpClass(cls):
        cls.device = parse_sros_transcript(load("sar_8_system.txt"))
        cls.findings = AuditEngine().run(
            AuditSnapshot(devices={cls.device.device_id: cls.device})
        )

    def test_the_card_label_is_read_not_assumed(self):
        # Hardcoding "CSM" lost the status entirely, and with it the only signal
        # that says whether the node is locked.
        self.assertEqual(self.device.timing.status, {"CPM A": "Master Locked"})
        self.assertTrue(self.device.timing.locked)

    def test_every_reference_block_is_found_including_external(self):
        names = [r.name for r in self.device.timing.references]
        self.assertEqual(
            names,
            [
                "Reference Input 1",
                "Reference Input 2",
                "Reference Input 3",
                "External Reference Input",
                "External Reference Output",
            ],
        )

    def test_fields_the_documentation_never_showed(self):
        timing = self.device.timing
        self.assertEqual(timing.selected_reference, "ref1")
        self.assertEqual(timing.system_quality_level, "eec2")
        self.assertEqual(timing.quality_level_selection, "Enabled")

    def test_a_reference_is_tied_to_its_source_port(self):
        by_name = {r.name: r for r in self.device.timing.references}
        self.assertEqual(by_name["Reference Input 1"].source_port, "1/1/5")
        self.assertEqual(by_name["Reference Input 2"].source_port, "1/2/6")
        # The device prints the literal string "None" when there is no port.
        self.assertIsNone(by_name["Reference Input 3"].source_port)

    def test_a_healthy_locked_node_passes_timing(self):
        rules = {f.rule_id for f in self.findings}
        self.assertIn("TIMING-000", rules)
        self.assertNotIn("TIMING-001", rules)
        # ref3 and the external input are admin down, so no protection warning.
        self.assertNotIn("TIMING-002", rules)

    def test_redundancy_is_read_from_live_output(self):
        redundancy = self.device.redundancy
        self.assertTrue(redundancy.reported)
        self.assertEqual(redundancy.standby_status, "standby ready")
        self.assertTrue(redundancy.standby_ready)
        self.assertFalse(redundancy.had_failure)
        self.assertEqual(redundancy.config_sync_mode, "Configuration")
        rules = {f.rule_id for f in self.findings}
        self.assertIn("REDUNDANCY-000", rules)

    def test_a_standby_that_is_not_ready_fails(self):
        text = load("sar_8_system.txt").replace(
            "Standby Status               : standby ready",
            "Standby Status               : not equipped",
        )
        device = parse_sros_transcript(text)
        self.assertFalse(device.redundancy.standby_ready)
        findings = AuditEngine().run(AuditSnapshot(devices={"x": device}))
        failures = [f for f in findings if f.rule_id == "REDUNDANCY-001"]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].severity, FindingSeverity.FAIL)

    def test_a_recorded_standby_failure_warns(self):
        text = load("sar_8_system.txt").replace(
            "Last Standby Failure         : N/A",
            "Last Standby Failure         : 2026/08/01 03:14:00",
        )
        device = parse_sros_transcript(text)
        self.assertTrue(device.redundancy.had_failure)
        findings = AuditEngine().run(AuditSnapshot(devices={"x": device}))
        self.assertIn("REDUNDANCY-002", {f.rule_id for f in findings})

    def test_cpu_rows_are_parsed_but_never_audited(self):
        rows = {c.name: c for c in self.device.cpu}
        self.assertIn("IOM", rows)
        self.assertEqual(rows["IOM"].capacity_usage, "15.76%")
        self.assertAlmostEqual(rows["IOM"].capacity_percent, 15.76)
        # "~0.00%" means non-zero but below resolution.
        self.assertAlmostEqual(rows["BFD"].capacity_percent, 0.02)
        # No CPU rule exists: a threshold is a judgement about the network, and
        # the sample is taken while the audit itself is driving the CLI.
        self.assertFalse([f for f in self.findings if "CPU" in f.rule_id.upper()])


class CrossDeviceLagTests(unittest.TestCase):
    """Check a LAG against its far end.

    A LAG reports itself healthy whenever its own members are up, which is
    exactly the case that hides a mismatch: the far end can have a different
    number of members, or members at another rate, and both devices still look
    fine on their own.
    """

    def _pair(self, near_members, far_members, near_id="2", far_id="7"):
        near = Lag(
            near_id,
            system_id="24:f6:8d:3c:90:00",
            partner_system_id="24:f6:8d:8d:ec:00",
            members=near_members,
        )
        far = Lag(
            far_id,
            system_id="24:f6:8d:8d:ec:00",
            partner_system_id="24:f6:8d:3c:90:00",
            members=far_members,
        )
        a = Device(device_id="A", lags={near_id: near})
        b = Device(device_id="B", lags={far_id: far})
        return AuditSnapshot(devices={"A": a, "B": b})

    def _member(self, port, rate="10G", state="up"):
        return LagMember(port, oper_state=state, activity="active", rate=rate)

    def test_matching_ends_pass_even_with_different_lag_numbers(self):
        # Nothing requires both sides to use the same LAG id, so the pairing is
        # on LACP System Id.
        snapshot = self._pair(
            [self._member("1/1/1"), self._member("1/2/1")],
            [self._member("1/1/5"), self._member("1/2/5")],
        )
        findings = AuditEngine().run(snapshot)
        pairs = [f for f in findings if f.rule_id.startswith("LAGPAIR")]
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0].rule_id, "LAGPAIR-000")
        self.assertIn("A:lag-2 <-> B:lag-7", pairs[0].subject)

    def test_member_count_mismatch_fails(self):
        snapshot = self._pair(
            [self._member("1/1/1"), self._member("1/2/1")],
            [self._member("1/1/5")],
        )
        findings = AuditEngine().run(snapshot)
        rules = {f.rule_id for f in findings}
        self.assertIn("LAGPAIR-001", rules)
        self.assertNotIn("LAGPAIR-000", rules)

    def test_member_rate_mismatch_fails(self):
        snapshot = self._pair(
            [self._member("1/1/1", "10G"), self._member("1/2/1", "10G")],
            [self._member("1/1/5", "1G"), self._member("1/2/5", "1G")],
        )
        findings = AuditEngine().run(snapshot)
        self.assertIn("LAGPAIR-002", {f.rule_id for f in findings})

    def test_one_end_with_a_down_member_warns(self):
        snapshot = self._pair(
            [self._member("1/1/1"), self._member("1/2/1")],
            [self._member("1/1/5"), self._member("1/2/5", state="down")],
        )
        findings = AuditEngine().run(snapshot)
        self.assertIn("LAGPAIR-003", {f.rule_id for f in findings})

    def test_each_pair_is_reported_once_not_once_per_end(self):
        snapshot = self._pair(
            [self._member("1/1/1")], [self._member("1/1/5")]
        )
        findings = AuditEngine().run(snapshot)
        self.assertEqual(
            len([f for f in findings if f.rule_id.startswith("LAGPAIR")]), 1
        )

    def test_an_uncaptured_far_end_yields_no_pair_finding(self):
        lag = Lag("2", system_id="aa", partner_system_id="bb", members=[self._member("1/1/1")])
        snapshot = AuditSnapshot(devices={"A": Device(device_id="A", lags={"2": lag})})
        findings = AuditEngine().run(snapshot)
        self.assertFalse([f for f in findings if f.rule_id.startswith("LAGPAIR")])

    def test_real_captures_pair_on_lacp_system_id(self):
        ixr = parse_sros_transcript(load("ixr_r6.txt"))
        sar = parse_sros_transcript(load("sar_8.txt"))
        self.assertEqual(ixr.lags["2"].system_id, "24:f6:8d:3c:90:00")
        self.assertEqual(sar.lags["2"].system_id, "24:f6:8d:8d:ec:00")
        snapshot = AuditSnapshot(
            devices={ixr.device_id: ixr, sar.device_id: sar}
        )
        findings = AuditEngine().run(snapshot)
        pairs = [f for f in findings if f.rule_id.startswith("LAGPAIR")]
        self.assertTrue(pairs)
        self.assertTrue(all(f.rule_id == "LAGPAIR-000" for f in pairs))


class LagCapacityRuleTests(unittest.TestCase):
    def test_capacity_is_not_totalled_from_partial_member_rates(self):
        # Summing a LAG whose member rates were not all captured understates it,
        # which reads as a real capacity shortfall rather than missing data.
        lag = Lag(
            "2",
            members=[
                LagMember("1/1/1", oper_state="up", activity="active", rate="10G"),
                LagMember("1/2/1", oper_state="up", activity="active"),
            ],
        )
        device = Device(device_id="SITE-A", lags={"2": lag})
        findings = AuditEngine().run(AuditSnapshot(devices={"SITE-A": device}))
        rules = {f.rule_id for f in findings}
        self.assertIn("LAG-004", rules)
        self.assertNotIn("LAG-000", rules)


class SonetPortTests(unittest.TestCase):
    """OC3 ports, and the sync quality only SONET carries.

    Blocks are verbatim from live 7705s with an ``a4-choc3/12`` adapter. Note the
    rate label is plain ``Speed`` -- Ethernet says ``Oper Speed`` -- which is why
    every OC3 port in a 128-device network had ``rate=None`` and the SONET rules,
    which gate on a known OC-n rate, silently graded nothing.
    """

    IN_SERVICE = (
        "Description        : ALVF001_7705 1/3/1 to WKMZ001_7705 1/6/1\n"
        "Interface          : 1/3/1                  Speed                : oc3\n"
        "Admin Status       : up                     Oper Status          : up\n"
        "Physical Link      : Yes                    Loopback Mode        : none\n"
        "APS Group          : none                   APS Role             : none\n"
        "Clock Source       : node                   Framing              : sonet\n"
        "Rx S1 Byte         : 0x0a (st3)             Rx K1/K2 Byte        : 0x00/0x00\n"
        "Tx S1 Byte         : 0x0f (dus)             Tx DUS/DNU           : Disabled\n"
        "Cfg Alarm          : loc lrdi lb2er-sf slof slos\n"
        "Alarm Status       :\n"
        "BER SD Threshold   : 6                      BER SF Threshold     : 3\n"
    )
    # A channelised OC3 adapter presents four ports; the spares sit admin-down
    # and quite correctly report loss of signal, because there is no signal.
    DARK_SPARE = (
        "Interface          : 1/3/2                  Speed                : oc3\n"
        "Admin Status       : down                   Oper Status          : down\n"
        "Clock Source       : node                   Framing              : sonet\n"
        "Tx S1 Byte         : 0x00 (stu)\n"
        "Cfg Alarm          : loc lrdi lb2er-sf slof slos\n"
        "Alarm Status       : lais lb2er-sd lb2er-sf slof slos lrei\n"
    )

    def _port(self, block, port_id):
        from nokia_network_audit.parsers.sros import _parse_ports

        banner = "=" * 79 + "\n"
        port = _parse_ports(banner + block)[port_id]
        port.finalize()  # normalises the rate, as Device.finalize() does
        return port

    def test_the_sonet_rate_is_read_from_its_own_label(self):
        port = self._port(self.IN_SERVICE, "1/3/1")
        self.assertEqual(port.rate, "oc3")
        self.assertEqual(port.rate_bps, 155_520_000)

    def test_the_s1_sync_bytes_are_read_in_both_directions(self):
        state = self._port(self.IN_SERVICE, "1/3/1").sonet
        self.assertEqual((state.rx_s1, state.rx_s1_quality), ("0x0a", "st3"))
        self.assertEqual((state.tx_s1, state.tx_s1_quality), ("0x0f", "dus"))
        self.assertIs(state.rx_traceable, False)

    def test_the_remaining_sonet_fields_are_read(self):
        state = self._port(self.IN_SERVICE, "1/3/1").sonet
        self.assertEqual(state.clock_source, "node")
        self.assertEqual((state.rx_k1, state.rx_k2), ("0x00", "0x00"))
        self.assertEqual((state.ber_sd_threshold, state.ber_sf_threshold), ("6", "3"))
        self.assertTrue(state.reported)

    def test_the_configured_alarm_set_is_read_onto_the_port(self):
        # Not SONET-specific -- an Ethernet port reports "remote local" here --
        # so it lives on the port rather than in the SONET state.
        port = self._port(self.IN_SERVICE, "1/3/1")
        self.assertEqual(
            port.configured_alarms, ["loc", "lrdi", "lb2er-sf", "slof", "slos"]
        )

    def test_a_traceable_far_end_is_recognised(self):
        block = self.IN_SERVICE.replace("0x0a (st3)", "0x01 (prs)")
        self.assertIs(self._port(block, "1/3/1").sonet.rx_traceable, True)

    def test_an_ethernet_port_gains_no_sonet_state(self):
        device = parse_sros_transcript(load("ixr_r6.txt"))
        port = device.ports["1/1/1"]
        self.assertFalse(port.sonet.reported)
        self.assertIsNone(port.sonet.rx_s1)


class SonetRuleFiringTests(unittest.TestCase):
    def _device(self, block, port_id, reference_port=None):
        from nokia_network_audit.models import SystemTiming, TimingReference
        from nokia_network_audit.parsers.sros import _parse_ports

        ports = _parse_ports("=" * 79 + "\n" + block)
        for port in ports.values():
            port.finalize()
        device = Device(device_id="MARN001_7705", ports=ports)
        if reference_port:
            device.timing = SystemTiming(status={"CPM A": "Master Locked"})
            device.timing.references = [
                TimingReference(
                    name="Reference Input 1",
                    selected="Yes",
                    source_port=reference_port,
                )
            ]
        return device

    def _rules(self, device):
        snapshot = AuditSnapshot(devices={device.device_id: device})
        return {
            f.rule_id: f
            for f in AuditEngine().run(snapshot)
            if f.rule_id.startswith(("SONET", "PORT"))
        }

    def test_a_dark_spare_channel_produces_nothing(self):
        # The guard that matters. Thirty-four admin-down channels across this
        # network report lais/slof/slos; grading them would bury the real faults
        # under confident failures about equipment working as configured.
        found = self._rules(
            self._device(SonetPortTests.DARK_SPARE, "1/3/2")
        )
        self.assertEqual(found, {})

    def test_an_enabled_but_down_oc3_port_is_a_sonet_failure(self):
        block = SonetPortTests.IN_SERVICE.replace(
            "Admin Status       : up                     Oper Status          : up",
            "Admin Status       : up                     Oper Status          : down",
        )
        found = self._rules(self._device(block, "1/3/1"))
        self.assertIn("SONET-001", found)
        self.assertEqual(found["SONET-001"].severity, FindingSeverity.FAIL)
        # ...and not also reported in Ethernet vocabulary by PORT-001.
        self.assertNotIn("PORT-001", found)

    def test_live_alarms_on_an_enabled_port_are_a_failure(self):
        block = SonetPortTests.IN_SERVICE.replace(
            "Alarm Status       :\n", "Alarm Status       : slos lrdi\n"
        )
        found = self._rules(self._device(block, "1/3/1"))
        self.assertIn("SONET-002", found)
        self.assertIn("slos", found["SONET-002"].message)

    def test_untraceable_sync_is_a_warning_when_it_is_the_reference(self):
        # Why three live 7705s report "Master Locked" at st3: the OC3 port they
        # take timing from is advertising st3, and nothing else showed it.
        found = self._rules(
            self._device(SonetPortTests.IN_SERVICE, "1/3/1", reference_port="1/3/1")
        )
        self.assertEqual(found["SONET-004"].severity, FindingSeverity.WARN)
        self.assertIn("st3", found["SONET-004"].message)
        self.assertIn("selected timing reference", found["SONET-004"].message)

    def test_untraceable_sync_elsewhere_is_only_informational(self):
        found = self._rules(self._device(SonetPortTests.IN_SERVICE, "1/3/1"))
        self.assertEqual(found["SONET-004"].severity, FindingSeverity.INFO)

    def test_a_traceable_reference_raises_nothing(self):
        block = SonetPortTests.IN_SERVICE.replace("0x0a (st3)", "0x01 (prs)")
        found = self._rules(self._device(block, "1/3/1", reference_port="1/3/1"))
        self.assertNotIn("SONET-004", found)


class CoherentOpticTests(unittest.TestCase):
    """Telling a DWDM span apart from a direct fibre.

    This is the only signal in a router capture that an optical shelf sits in
    the span: a transparent wavelength puts the far-end *router* into LLDP and
    OSPF, so the transport layer is otherwise invisible from the routed view.
    """

    COHERENT = (
        "Transceiver Status : operational\n"
        "Transceiver Type   : QSFP+ or later with CMIS   DCO              : Enabled\n"
        "Model Number       : 3HE19775AARA01  NOK  INUIA27GAA\n"
        "TX Laser Wavelength: 1552.524 nm                \n"
        "Laser Tunability   : fully-tunable              \n"
        "Config Freq (MHz)  : 193100000                  Min Freq (MHz)   : 191350000\n"
        "Oper Freq (MHz)    : 193100000                  Max Freq (MHz)   : 196100000\n"
        "Part Number        : FTLC3351S3PL1-A5\n"
        "Optical Compliance : 100GBASE-ZR Custom (192) \n"
    )
    GREY = (
        "Transceiver Status : operational\n"
        "Transceiver Type   : QSFP28                     DCO              : Disabled\n"
        "Model Number       : 3HE11239AARA01  NOK  IPUIBZ8DAA\n"
        "TX Laser Wavelength: 1310 nm                    Diag Capable     : yes\n"
        "Part Number        : SPQCEERCDFMAL   \n"
        "Optical Compliance : 4WDM-40 MSA \n"
    )

    def test_a_coherent_module_is_recognised_with_its_frequency(self):
        from nokia_network_audit.parsers.sros import _optic

        optic = _optic(self.COHERENT)
        self.assertTrue(optic.coherent)
        self.assertEqual(optic.tunability, "fully-tunable")
        self.assertEqual(optic.frequency_thz, 193.1)

    def test_the_itu_channel_matches_the_1830_aid(self):
        # The shelf carrying this wavelength calls it 1/10/9310.
        from nokia_network_audit.parsers.sros import _optic

        self.assertEqual(_optic(self.COHERENT).itu_channel, "9310")

    def test_a_grey_optic_is_not_a_dwdm_span(self):
        # Both print a wavelength, so that is not the test -- the grey module
        # has no Oper Freq and says DCO is disabled.
        from nokia_network_audit.parsers.sros import _optic

        optic = _optic(self.GREY)
        self.assertFalse(optic.coherent)
        self.assertIsNone(optic.frequency_thz)
        self.assertIsNone(optic.itu_channel)


class DwdmSpanRuleTests(unittest.TestCase):
    def _router(self, name, coherent=True):
        from nokia_network_audit.models import DeviceKind, Optic

        optic = Optic(port_id="1/1/c7", part_number="FTLC3351S3PL1-A5")
        if coherent:
            optic.coherent = True
            optic.frequency_thz = 193.2
        return Device(
            device_id=name,
            kind=DeviceKind.ROUTER,
            ports={"1/1/c7": Port(port_id="1/1/c7", optic=optic)},
        )

    def _shelf(self, name):
        from nokia_network_audit.models import DeviceKind

        return Device(device_id=name, kind=DeviceKind.OPTICAL)

    def _rules(self, *devices):
        snapshot = AuditSnapshot(devices={d.device_id: d for d in devices})
        return {
            f.rule_id: f
            for f in AuditEngine().run(snapshot)
            if f.rule_id.startswith("OPTICAL-01")
        }

    def test_a_span_with_no_captured_shelf_is_reported(self):
        found = self._rules(self._router("KEEL001_7250"))
        self.assertIn("OPTICAL-011", found)
        self.assertIn("channel 9320", found["OPTICAL-011"].message)
        self.assertIn("KEEL", found["OPTICAL-011"].message)

    def test_a_span_whose_shelf_was_captured_passes(self):
        found = self._rules(self._router("GRIZ001_7250"), self._shelf("GRIZ001_1830"))
        self.assertIn("OPTICAL-010", found)
        self.assertNotIn("OPTICAL-011", found)

    def test_one_shelf_covers_every_router_at_its_site(self):
        # GRIZ001_1830 carries 9310 and 9320, the wavelengths used by both
        # GRIZ001_7250 and GRIZ002_7250. Keying on the shelf number rather than
        # the site called GRIZ002 unaudited while its shelf sat in the snapshot.
        found = self._rules(self._router("GRIZ002_7250"), self._shelf("GRIZ001_1830"))
        self.assertIn("OPTICAL-010", found)
        self.assertNotIn("OPTICAL-011", found)

    def test_a_direct_fibre_is_not_reported_as_a_span(self):
        self.assertEqual(self._rules(self._router("KEEL001_7250", coherent=False)), {})


class HoldoverCauseTests(unittest.TestCase):
    """Telling a broken span apart from a downstream consequence.

    Six live nodes were in holdover. Four had a timing reference on a port that
    was physically down -- a work order. Two had every reference up and merely
    signalling DUS, because the tree had lost its root elsewhere; those clear
    themselves once the real fault is fixed. TIMING-001 cannot tell them apart.
    """

    def _device(self, name, refs, ports):
        from nokia_network_audit.models import SystemTiming, TimingReference

        device = Device(device_id=name, ports=ports)
        device.timing = SystemTiming(status={"CPM A": "Master Holdover"})
        device.timing.references = [
            TimingReference(name=n, source_port=p, admin_state="up", qualified="No")
            for n, p in refs
        ]
        return device

    def _rules(self, device):
        snapshot = AuditSnapshot(devices={device.device_id: device})
        return {
            f.rule_id: f
            for f in AuditEngine().run(snapshot)
            if f.rule_id.startswith("TIMING")
        }

    def test_a_reference_on_a_down_port_is_named_as_the_cause(self):
        device = self._device(
            "STJO002_7250",
            [("Reference Input 1", "1/2/c7/1")],
            {
                "1/2/c7/1": Port(
                    port_id="1/2/c7/1",
                    admin_state="up",
                    oper_state="down",
                    description="STJO002_7250 1/2/7 to DITT002_7250 1/3/2",
                )
            },
        )
        found = self._rules(device)
        self.assertIn("TIMING-005", found)
        self.assertEqual(found["TIMING-005"].severity, FindingSeverity.FAIL)
        self.assertIn("DITT002_7250", found["TIMING-005"].message)
        self.assertIn("1/2/c7/1", found["TIMING-005"].message)

    def test_a_standoff_is_not_reported_as_a_physical_fault(self):
        # KEEL001: both references up, both receiving DUS. Nothing to dispatch.
        device = self._device(
            "KEEL001_7250",
            [("Reference Input 1", "1/2/c7/1"), ("Reference Input 2", "1/3/c7/1")],
            {
                "1/2/c7/1": Port(port_id="1/2/c7/1", admin_state="up", oper_state="up"),
                "1/3/c7/1": Port(port_id="1/3/c7/1", admin_state="up", oper_state="up"),
            },
        )
        found = self._rules(device)
        self.assertIn("TIMING-001", found)  # still in holdover
        self.assertNotIn("TIMING-005", found)  # but not because a span broke

    def test_both_references_down_are_reported_together(self):
        # BENT: fully cut from timing, both references on broken spans.
        device = self._device(
            "BENT001_7250",
            [("Reference Input 1", "1/2/c7/1"), ("Reference Input 2", "1/1/c7/1")],
            {
                "1/2/c7/1": Port(
                    port_id="1/2/c7/1", admin_state="up", oper_state="down",
                    description="BENT001_7250 1/2/7 to ASHE001_7250 1/3/7",
                ),
                "1/1/c7/1": Port(
                    port_id="1/1/c7/1", admin_state="up", oper_state="down",
                    description="BENT001_7250 1/1/7 to FRAN001_7250 1/4/7",
                ),
            },
        )
        message = self._rules(device)["TIMING-005"].message
        self.assertIn("ASHE001_7250", message)
        self.assertIn("FRAN001_7250", message)

    def test_a_locked_node_is_never_given_a_cause(self):
        from nokia_network_audit.models import SystemTiming, TimingReference

        device = Device(
            device_id="A",
            ports={"1/1/1": Port(port_id="1/1/1", admin_state="up", oper_state="down")},
        )
        device.timing = SystemTiming(status={"CPM A": "Master Locked"})
        device.timing.references = [
            TimingReference(name="Reference Input 1", source_port="1/1/1",
                            admin_state="up", selected="Yes")
        ]
        self.assertNotIn("TIMING-005", self._rules(device))

    def test_an_admin_down_reference_port_is_not_a_break(self):
        # Out of service is a decision, as everywhere else in this audit.
        device = self._device(
            "A",
            [("Reference Input 1", "1/1/1")],
            {"1/1/1": Port(port_id="1/1/1", admin_state="down", oper_state="down")},
        )
        self.assertNotIn("TIMING-005", self._rules(device))


class SyncTreeRuleTests(unittest.TestCase):
    """Locked to a clock that is itself free-running."""

    def _device(self, name, status, source_port=None, upstream=None):
        from nokia_network_audit.models import (
            Adjacency,
            SystemTiming,
            TimingReference,
        )

        device = Device(device_id=name)
        device.timing = SystemTiming(status={"CPM A": status})
        if source_port:
            device.timing.references = [
                TimingReference(
                    name="Reference Input 1", selected="Yes", source_port=source_port
                )
            ]
            device.adjacencies = [
                Adjacency(
                    local_port=source_port,
                    remote=upstream,
                    scope="Ext",
                    protocol="lldp",
                )
            ]
        return device

    def _run(self, *devices):
        snapshot = AuditSnapshot(devices={d.device_id: d for d in devices})
        return [f for f in AuditEngine().run(snapshot) if f.rule_id == "TIMING-004"]

    def test_a_device_locked_to_a_holdover_node_is_reported(self):
        root = self._device("KEEL001_7250", "Master Holdover")
        leaf = self._device(
            "CHEM001_7250", "Master Locked", "1/2/c7/1", "KEEL001_7250"
        )
        findings = self._run(root, leaf)
        self.assertEqual([f.subject for f in findings], ["CHEM001_7250"])
        self.assertIn("KEEL001_7250", findings[0].message)
        self.assertIn("1 hop upstream", findings[0].message)

    def test_the_whole_chain_downstream_is_reported(self):
        # The real shape: a break at the root leaves a line of devices each
        # reporting itself perfectly healthy.
        root = self._device("KEEL001_7250", "Master Holdover")
        mid = self._device("CHEM001_7250", "Master Locked", "1/2/c7/1", "KEEL001_7250")
        leaf = self._device("SALE001_7250", "Master Locked", "1/2/c7/1", "CHEM001_7250")
        findings = {f.subject: f.message for f in self._run(root, mid, leaf)}
        self.assertEqual(sorted(findings), ["CHEM001_7250", "SALE001_7250"])
        self.assertIn("2 hops upstream", findings["SALE001_7250"])

    def test_the_holdover_node_itself_is_left_to_timing_001(self):
        root = self._device("KEEL001_7250", "Master Holdover")
        self.assertEqual(self._run(root), [])
        snapshot = AuditSnapshot(devices={"KEEL001_7250": root})
        rules = {f.rule_id for f in AuditEngine().run(snapshot)}
        self.assertIn("TIMING-001", rules)

    def test_a_healthy_tree_is_not_reported(self):
        root = self._device("GRAND001", "Master Locked")
        leaf = self._device("CHEM001_7250", "Master Locked", "1/2/c7/1", "GRAND001")
        self.assertEqual(self._run(root, leaf), [])

    def test_an_uncaptured_upstream_is_not_guessed_at(self):
        # The far end was never captured, so nothing is known about its clock.
        leaf = self._device("CHEM001_7250", "Master Locked", "1/2/c7/1", "DITT001_7250")
        self.assertEqual(self._run(leaf), [])

    def test_a_mutual_pair_does_not_loop_forever(self):
        a = self._device("A", "Master Locked", "1/1/1", "B")
        b = self._device("B", "Master Locked", "1/1/1", "A")
        self.assertEqual(self._run(a, b), [])


class PortStateRuleTests(unittest.TestCase):
    """A standalone port that is enabled but down was reported by nothing."""

    def _findings(self, device, rule="PORT-001"):
        snapshot = AuditSnapshot(devices={device.device_id: device})
        return [f for f in AuditEngine().run(snapshot) if f.rule_id == rule]

    def test_an_enabled_but_down_port_is_reported(self):
        # Verbatim from STJO001, whose far end is a live field site: the link
        # came up and went down, so this is a break.
        device = Device(
            device_id="STJO001_7250",
            ports={
                "1/2/c7/1": Port(
                    port_id="1/2/c7/1",
                    admin_state="up",
                    oper_state="down",
                    description="STJO001_7250 1/2/7 to DITT001_7250 1/3/2",
                    phys_state_changes=2,
                )
            },
        )
        findings = self._findings(device)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.WARN)
        self.assertIn("DITT001_7250", findings[0].message)
        self.assertIn("carried traffic before", findings[0].message)

    def test_a_link_that_has_never_come_up_is_not_a_break(self):
        # Verbatim from CHEM001, whose far end is not yet fibered in. Reporting
        # this at the same level as a real outage buries the outages.
        device = Device(
            device_id="CHEM001_7250",
            ports={
                "1/1/6": Port(
                    port_id="1/1/6",
                    admin_state="up",
                    oper_state="down",
                    description="CHEM001_7250 1/1/6 to CHEM003_7705 1/1/5",
                    phys_state_changes=0,
                )
            },
        )
        self.assertEqual(self._findings(device, "PORT-001"), [])
        never = self._findings(device, "PORT-002")
        self.assertEqual(len(never), 1)
        self.assertEqual(never[0].severity, FindingSeverity.INFO)
        self.assertIn("not yet connected", never[0].message)

    def test_a_missing_counter_is_graded_as_a_fault(self):
        # TDM and microwave ports do not print the counter. Absent evidence is
        # not evidence the link was never up, so it stays a fault.
        device = Device(
            device_id="SANT001_7705",
            ports={
                "1/5/2": Port(
                    port_id="1/5/2",
                    admin_state="up",
                    oper_state="down",
                    description="DS1/E1",
                )
            },
        )
        self.assertEqual(len(self._findings(device, "PORT-001")), 1)
        self.assertEqual(self._findings(device, "PORT-002"), [])

    def test_an_admin_down_port_is_not_a_fault(self):
        # Taking a port out of service is a decision, not a failure.
        device = Device(
            device_id="A",
            ports={"1/3/c7": Port(port_id="1/3/c7", admin_state="down", oper_state="down")},
        )
        self.assertEqual(self._findings(device), [])

    def test_a_lag_member_is_left_to_the_lag_rules(self):
        device = Device(
            device_id="A",
            ports={"1/1/1": Port(port_id="1/1/1", admin_state="up", oper_state="down")},
            lags={"2": Lag("2", members=[LagMember("1/1/1", oper_state="down")])},
        )
        self.assertEqual(self._findings(device), [])
        # ...but the LAG rule still speaks up, so the fault is not lost.
        snapshot = AuditSnapshot(devices={"A": device})
        rules = {f.rule_id for f in AuditEngine().run(snapshot)}
        self.assertIn("LAG-002", rules)

    def test_one_break_is_not_counted_twice_across_a_sublayer(self):
        # SR OS reports oper state on the connector and on its channel. Both go
        # down together, and grading both turns one dead link into two findings.
        device = Device(
            device_id="A",
            ports={
                "1/2/c7": Port(port_id="1/2/c7", admin_state="up", oper_state="down"),
                "1/2/c7/1": Port(
                    port_id="1/2/c7/1", admin_state="up", oper_state="down"
                ),
            },
        )
        findings = self._findings(device)
        self.assertEqual([f.subject for f in findings], ["A:1/2/c7/1"])

    def test_the_physical_change_counter_is_read_from_a_capture(self):
        device = parse_sros_transcript(load("ixr_r6.txt"))
        self.assertEqual(device.ports["1/1/1"].phys_state_changes, 2)

    def test_a_healthy_port_produces_nothing(self):
        device = Device(
            device_id="A",
            ports={"1/1/1": Port(port_id="1/1/1", admin_state="up", oper_state="up")},
        )
        self.assertEqual(self._findings(device), [])


class LldpNeighbourTests(unittest.TestCase):
    """``show system lldp neighbor``, from real 7705 SAR-8 v2 output.

    LLDP is the only source that pairs LAG *member* ports. OSPF reports a LAG as
    a single interface, so the routing view can say "these two shelves are
    adjacent" but never which fibre lands in which slot. Cabling errors live at
    exactly that level.
    """

    @classmethod
    def setUpClass(cls):
        cls.device = parse_sros_transcript(load("sar_8_system.txt"))

    def test_every_neighbour_row_is_read(self):
        lldp = [a for a in self.device.adjacencies if a.protocol == "lldp"]
        self.assertEqual(len(lldp), 4)

    def test_local_and_remote_ports_pair_up(self):
        pairs = {
            (a.local_port, a.remote, a.remote_port)
            for a in self.device.adjacencies
            if a.protocol == "lldp"
        }
        self.assertEqual(
            pairs,
            {
                ("1/2/6", "MOPN001_7250", "1/2/2"),
                ("1/1/6", "MOPN001_7250", "1/1/2"),
                ("1/1/5", "MOPN002_7250", "1/1/1"),
                ("1/2/5", "MOPN002_7250", "1/2/1"),
            },
        )

    def test_the_truncated_remote_port_column_is_cut_at_the_comma(self):
        # The device prints "1/2/2, 1-Gig/1*" and footnotes that the row may have
        # been truncated. Only the port id ahead of the comma is dependable, and
        # keeping the description would stop it matching the peer's own port id.
        ports = {
            a.remote_port for a in self.device.adjacencies if a.protocol == "lldp"
        }
        for port in ports:
            self.assertNotIn(",", port)
            self.assertNotIn("*", port)

    def test_remote_chassis_id_is_captured_and_case_folded(self):
        # The peer's Remote Chassis ID is its base MAC, which is also its LACP
        # System Id -- a third join key, independent of routing. SR OS prints it
        # upper case here and lower case in "show chassis detail".
        chassis = {
            a.remote_chassis_id
            for a in self.device.adjacencies
            if a.protocol == "lldp"
        }
        self.assertEqual(chassis, {"24:f6:8d:3c:90:00", "24:f6:8d:32:10:00"})

    def test_base_mac_is_read_and_answers_as_an_identity(self):
        self.assertEqual(self.device.base_mac, "24:f6:8d:8d:2c:00")
        self.assertIn("24:f6:8d:8d:2c:00", self.device.identities())

    def test_an_unconfigured_protocol_does_not_become_an_adjacency(self):
        # The same capture answers three IS-IS commands with "MINOR: CLI ISIS
        # instance 0 is not configured."
        self.assertFalse(
            [a for a in self.device.adjacencies if a.protocol == "isis"]
        )

    def test_a_system_name_containing_a_space_is_not_truncated(self):
        # Verbatim from a 7705 facing a microwave radio. Taking the last word as
        # the name turned "MSS SiteA" into "SiteA", and that truncated name then
        # appeared on the capture worklist as though it were a device.
        from nokia_network_audit.parsers.sros import _lldp_adjacencies

        table = (
            "Lcl Port      Scope Remote Chassis ID  Index  Remote Port     "
            "Remote Sys Name\n"
            "----------------------------------------------------------------\n"
            "1/1/1         NB    00:11:3F:A4:07:DD  1      Ethernet Slot#* "
            "MSS SiteA\n"
            "1/1/6         NB    24:F6:8D:3C:90:00  2      1/1/2, 1-Gig/1* "
            "MOPN001_7250\n"
        )
        found = {a.local_port: a for a in _lldp_adjacencies(table)}
        self.assertEqual(found["1/1/1"].remote, "MSS SiteA")
        self.assertEqual(found["1/1/1"].remote_chassis_id, "00:11:3f:a4:07:dd")
        # The ordinary single-word case must be unchanged.
        self.assertEqual(found["1/1/6"].remote, "MOPN001_7250")
        self.assertEqual(found["1/1/6"].remote_port, "1/1/2")

    def test_rows_still_parse_when_the_header_is_absent(self):
        # A capture trimmed to the rows alone still has to yield neighbours; the
        # last-word split is right whenever the name holds no space.
        from nokia_network_audit.parsers.sros import _lldp_adjacencies

        rows = (
            "1/1/6         NB    24:F6:8D:3C:90:00  2      1/1/2, 1-Gig/1* "
            "MOPN001_7250\n"
        )
        found = _lldp_adjacencies(rows)
        self.assertEqual([a.remote for a in found], ["MOPN001_7250"])

    def test_lldp_rows_are_not_invented_from_other_output(self):
        # The row pattern is loose enough to worry about: port-like token, short
        # word, MAC, integer. Every other fixture must yield no LLDP rows.
        for name in ("sar_8.txt", "ixr_r6.txt"):
            with self.subTest(name):
                other = parse_sros_transcript(load(name))
                self.assertFalse(
                    [a for a in other.adjacencies if a.protocol == "lldp"]
                )


if __name__ == "__main__":
    unittest.main()
