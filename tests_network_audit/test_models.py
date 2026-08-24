import unittest

from nokia_network_audit.models import (
    Lag,
    LagMember,
    frequency_to_wavelength_nm,
    normalize_rate,
)
from nokia_network_audit.wavelengths import sfdc8b_channels


class ModelTests(unittest.TestCase):
    def test_rates_and_sfdc8b_map(self):
        self.assertEqual(normalize_rate("100GE"), ("100g", 100_000_000_000))
        self.assertEqual(normalize_rate("STM-4"), ("oc12", 622_080_000))
        self.assertEqual(frequency_to_wavelength_nm(193.30), 1550.92)
        channels = sfdc8b_channels("1/4")
        self.assertEqual(len(channels), 8)
        self.assertEqual(channels["1/4/9330"].port_number, 5)

    def test_speeds_as_sr_os_actually_prints_them(self):
        # "show port detail" reports "10 Gbps", not "10GE" -- and the 7705 CSM
        # ports lowercase it.
        self.assertEqual(normalize_rate("10 Gbps"), ("10g", 10_000_000_000))
        self.assertEqual(normalize_rate("100 Gbps"), ("100g", 100_000_000_000))
        self.assertEqual(normalize_rate("1 Gbps"), ("1g", 1_000_000_000))
        self.assertEqual(normalize_rate("100 Mbps"), ("100m", 100_000_000))
        self.assertEqual(normalize_rate("100 mbps"), ("100m", 100_000_000))

    def test_placeholder_speeds_are_not_rates(self):
        # An unequipped or connector port reports "N/A"; treating that as a rate
        # token leaves a junk value on the port.
        for value in ("N/A", "", "Default", "unknown"):
            self.assertEqual(normalize_rate(value), (None, None))

    def test_power_thresholds_classify_against_module_limits(self):
        from nokia_network_audit.models import PowerThresholds

        limits = PowerThresholds(
            high_alarm=2.00, high_warn=1.00, low_warn=-21.02, low_alarm=-23.01
        )
        # The reading the 7250 itself flagged as "5.89/H-WA".
        self.assertEqual(limits.classify(5.88), "alarm")
        self.assertEqual(limits.classify(1.50), "warn")
        self.assertIsNone(limits.classify(-10.0))
        self.assertIsNone(limits.classify(None))

    def test_lag_capacity_uses_active_up_members(self):
        lag = Lag(
            "10",
            members=[
                LagMember("1/1/1", oper_state="up", activity="active", rate="100G"),
                LagMember("1/1/2", oper_state="up", activity="standby", rate="100G"),
            ],
        )
        for member in lag.members:
            member.finalize()
        self.assertEqual(lag.configured_capacity_bps, 200_000_000_000)
        self.assertEqual(lag.operational_capacity_bps, 100_000_000_000)


if __name__ == "__main__":
    unittest.main()
