import unittest
from queue import Queue

from script_interface import DeviceIdentifier


class TestDeviceIdentifierParse(unittest.TestCase):
    def test_parse_psi_from_system_identification(self):
        q = Queue()
        output = (
            "ramantest1#  show general system-identification\n\n"
            "Vendor                   : Nokia\n"
            "Product                  : 1830\n"
            "Shelf type               : PSI-4L\n"
            "EC type                  : MEC2L\n"
            "Serial number            : CN2503MAB0D\n"
            "Current OAMP MAC address : 0c:4b:48:2c:52:3d\n\n"
            "ramantest1#\n"
        )

        device_type, device_name = DeviceIdentifier.parse_device_info(output, q)

        messages = []
        while not q.empty():
            messages.append(q.get())

        self.assertEqual(device_type, "psi")
        self.assertEqual(device_name, "ramantest1")
        self.assertTrue(any("PSI shelf type detected: PSI-4L" in msg for msg in messages))

    def test_parse_1830_when_no_psi_shelf_type(self):
        output = (
            "Vendor                   : Nokia\n"
            "Product                  : 1830\n"
            "Shelf type               : PSS-16II\n"
        )

        device_type, _device_name = DeviceIdentifier.parse_device_info(output, Queue())

        self.assertEqual(device_type, "1830")

    def test_parse_psim_from_general_detail(self):
        q = Queue()
        output = (
            "ChiM1# show general detail\n"
            "Name                   : ChiM1\n"
            "System Description     : Nokia 1830 PSIM v23.12.0 SONET ADM\n"
            "S/W Version            : 1830PSIM-0.0-12\n"
            "Current Date           : 2026/03/26 12:29:53 (UTC)\n"
            "Loopback IPV4 Address  : 10.9.1.1/32\n"
            "ChiM1#\n"
        )
        device_type, device_name = DeviceIdentifier.parse_device_info(output, q)
        self.assertEqual(device_type, "psim")
        self.assertEqual(device_name, "ChiM1")

    def test_parse_psim_from_shelf_inventory(self):
        output = (
            "ChiM1# show shelf inventory *\n"
            "Shelf  Type      Part Number       Serial Number       CLEI\n"
            "----------------------------------------------------------\n"
            "    1  PSI-M   3KC81791AAHC04      RT261300392        WOMSG00ERD\n"
        )
        device_type, _ = DeviceIdentifier.parse_device_info(output, Queue())
        self.assertEqual(device_type, "psim")


class _FakeTelnet:
    """Minimal Telnet stand-in: replays one canned response, records writes."""

    def __init__(self, response: bytes):
        self._response = response
        self.written = []

    def write(self, data):
        self.written.append(data)

    def read_until(self, _match, timeout=None):
        out, self._response = self._response, b""
        return out

    def read_very_eager(self):
        return b""


class TestTelnetShelfTypeRefinement(unittest.TestCase):
    """A PSI answers 'show general detail' with "Nokia 1830 OLS <ver> SONET
    ADM" — no "PSI" in the System Description. Refining on that string alone
    sent real PSI shelves to the generic 1830 script, which collects a
    fraction of the PSI command set and writes the default workbook instead
    of the PSI report. The shelf type is the authoritative marker.
    """

    @staticmethod
    def _refine(response: bytes) -> str:
        return DeviceIdentifier._refine_1830_shelf_type(
            _FakeTelnet(response), "172.21.109.3", Queue(), lambda _s: False,
        )

    def test_psi_shelf_type_promotes_generic_1830_to_psi(self):
        self.assertEqual(
            self._refine(
                b"show general system-identification\r\n\r\n"
                b"Vendor                   : Nokia\r\n"
                b"Product                  : 1830\r\n"
                b"Shelf type               : PSI-4L\r\n"
                b"usuee1-l9i2#"
            ),
            "psi",
        )

    def test_psi_8l_also_promotes(self):
        self.assertEqual(
            self._refine(b"Shelf type               : PSI-8L\r\nx#"), "psi"
        )

    def test_psim_shelf_type_promotes_to_psim(self):
        self.assertEqual(
            self._refine(b"Shelf type               : PSI-M\r\nx#"), "psim"
        )

    def test_pss_shelf_stays_generic_1830(self):
        self.assertEqual(
            self._refine(b"Shelf type               : PSS-16II\r\nx#"), "1830"
        )

    def test_missing_shelf_type_stays_generic_1830(self):
        # Refinement is an optimisation — never a reason to fail identification.
        self.assertEqual(self._refine(b"Vendor : Nokia\r\nx#"), "1830")

    def test_command_actually_sent(self):
        tn = _FakeTelnet(b"Shelf type : PSI-4L\r\nx#")
        DeviceIdentifier._refine_1830_shelf_type(
            tn, "1.2.3.4", Queue(), lambda _s: False,
        )
        self.assertIn(b"show general system-identification\n", tn.written)

    def test_abort_mid_probe_stays_generic(self):
        tn = _FakeTelnet(b"Shelf type : PSI-4L\r\nx#")
        self.assertEqual(
            DeviceIdentifier._refine_1830_shelf_type(
                tn, "1.2.3.4", Queue(), lambda _s: True,  # abort requested
            ),
            "1830",
        )


class TestMuteSshShellShortCircuit(unittest.TestCase):
    """SSH auth succeeding while every ident command returns nothing is the
    1830-family "SSH up, no usable CLI" signature. Rotating credentials cannot
    unmute the shell — the account already authenticated — so identification
    must break out to the Telnet probe instead of burning all five defaults,
    their lockout backoff, and an operator prompt first.
    """

    def test_flag_defaults_to_false(self):
        self.assertFalse(DeviceIdentifier()._ssh_cli_unusable)

    def test_credential_loop_breaks_on_mute_shell(self):
        import inspect

        src = inspect.getsource(DeviceIdentifier.identify_device)
        self.assertIn("self._ssh_cli_unusable", src)
        # The break must sit in the "auth ok, no device_type" branch, before
        # handle_credential_failure dispenses the next default credential.
        self.assertLess(
            src.index("if self._ssh_cli_unusable"),
            src.index("handle_credential_failure"),
        )

    def test_attempt_sets_flag_only_when_nothing_echoed(self):
        import inspect

        src = inspect.getsource(DeviceIdentifier._ssh_identify_attempt)
        self.assertIn("any_shell_output", src)
        self.assertIn("if not any_shell_output:", src)


if __name__ == "__main__":
    unittest.main()
