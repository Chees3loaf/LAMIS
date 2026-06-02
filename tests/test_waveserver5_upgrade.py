"""Tests for the Waveserver 5 upgrade flow (serial + SSH).

The hardware integration isn't testable in unit tests, but we can pin
down the parts that ARE pure logic — version derivation from a filename,
the status-table parser, and the prompt regex extension. We also add a
source-level shape check so a future refactor that removes a required
constructor kwarg gets caught at import time.
"""
from __future__ import annotations
import inspect
import unittest

from utils.serial_helpers import _PROMPT_RE, _SHELL_RE


class TestPromptRegexAcceptsWaveserverAsterisk(unittest.TestCase):
    """Waveserver-5 prepends ``*`` to the prompt while config changes are
    pending (``WS5_1*#``). Before this fix the shared regex stalled on
    those prompts because it required ``#`` immediately after the
    hostname — the asterisk broke the match."""

    def test_pending_changes_prompt_matches_shell_re(self):
        self.assertIsNotNone(_SHELL_RE.search(b"Waveserver-5*#"))
        self.assertIsNotNone(_SHELL_RE.search(b"WS5_1*#"))

    def test_saved_prompt_still_matches_shell_re(self):
        # No asterisk = config committed. Must still match.
        self.assertIsNotNone(_SHELL_RE.search(b"WS5_1#"))
        self.assertIsNotNone(_SHELL_RE.search(b"Waveserver-5#"))

    def test_pending_changes_prompt_matches_prompt_re(self):
        self.assertIsNotNone(_PROMPT_RE.search(b"WS5_1*#\n"[:-1]))
        self.assertIsNotNone(_PROMPT_RE.search(b"Waveserver-5*#"))

    def test_sros_a_prompt_still_matches(self):
        # Backwards-compat: the existing Nokia SROS prompt forms must
        # keep matching after the asterisk relaxation.
        self.assertIsNotNone(_SHELL_RE.search(b"A:lrt2#"))
        self.assertIsNotNone(_SHELL_RE.search(b"*A:lrt2#"))
        self.assertIsNotNone(_SHELL_RE.search(b"B:lrt2>"))


class TestWaveserver5VersionDerivation(unittest.TestCase):
    """``software activate version <X>`` takes the tarball name minus
    the ``.tar.gz`` — which is also what the device echoes back as
    Upgrade-To-Version in the status table."""

    def setUp(self):
        from scripts.Network.Ciena_Waveserver5_Upgrade import (
            Waveserver5UpgradeScript,
        )
        self.derive = Waveserver5UpgradeScript._derive_version

    def test_tar_gz_extension_stripped(self):
        self.assertEqual(
            self.derive("waveserver-2.4.52.21-GA.tar.gz"),
            "waveserver-2.4.52.21-GA",
        )

    def test_tgz_extension_also_supported(self):
        self.assertEqual(
            self.derive("waveserver-2.4.52.21-GA.tgz"),
            "waveserver-2.4.52.21-GA",
        )

    def test_unknown_extension_returns_filename_as_is(self):
        # Avoids accidentally chopping something useful off if the
        # operator picked a non-tarball by mistake — the device will
        # then reject the activate command and surface the error.
        self.assertEqual(self.derive("weird-name"), "weird-name")

    def test_case_insensitive_extension_match(self):
        self.assertEqual(
            self.derive("Waveserver-2.4.52.21-GA.TAR.GZ"),
            "Waveserver-2.4.52.21-GA",
        )


class TestWaveserver5StatusTableParser(unittest.TestCase):
    """The device prints ``software show upgrade-status`` as a boxed
    table. We only need the ``Upgrade State`` row's value cell — the
    parser splits on the pipe and takes the rightmost non-empty token."""

    def setUp(self):
        from scripts.Network.Ciena_Waveserver5_Upgrade import (
            Waveserver5UpgradeScript,
        )
        self.parse = Waveserver5UpgradeScript._parse_upgrade_state

    _SAMPLE_DOWNLOADING = (
        "WS5_1# software show upgrade-status\n"
        "+----------------------------------- UPGRADE STATUS INFORMATION ----+\n"
        "|         Parameter             |                Value              |\n"
        "+-------------------------------+-----------------------------------+\n"
        "| Committed Release Version     | waveserver-2.3.11.180-GA          |\n"
        "| Active Release Version        | waveserver-2.3.11.180-GA          |\n"
        "| Upgrade To Version            |                                   |\n"
        "| Upgrade State                 | Download In Progress              |\n"
        "| Last Upgrade Operation        | Downloading release file          |\n"
        "+-------------------------------+-----------------------------------+\n"
        "WS5_1#"
    )
    _SAMPLE_DOWNLOAD_DONE = _SAMPLE_DOWNLOADING.replace(
        "Download In Progress", "Download Complete"
    )
    _SAMPLE_ACTIVATING = _SAMPLE_DOWNLOADING.replace(
        "Download In Progress", "Activation In Progress"
    )

    def test_download_in_progress(self):
        self.assertEqual(
            self.parse(self._SAMPLE_DOWNLOADING), "Download In Progress"
        )

    def test_download_complete(self):
        self.assertEqual(
            self.parse(self._SAMPLE_DOWNLOAD_DONE), "Download Complete"
        )

    def test_activation_in_progress(self):
        self.assertEqual(
            self.parse(self._SAMPLE_ACTIVATING), "Activation In Progress"
        )

    def test_returns_empty_when_table_missing(self):
        self.assertEqual(self.parse("garbage output"), "")


class TestWaveserver5ScriptShape(unittest.TestCase):
    """Source-level guard against silent constructor / method-signature
    changes that would break the GUI worker. The frame wires up a
    specific set of kwargs and a single ``run()`` entry point — pin
    them down here."""

    def setUp(self):
        from scripts.Network.Ciena_Waveserver5_Upgrade import (
            Waveserver5UpgradeScript,
        )
        self.cls = Waveserver5UpgradeScript

    def test_constructor_accepts_documented_kwargs(self):
        sig = inspect.signature(self.cls.__init__)
        params = sig.parameters
        for required in (
            "serial_port", "software_filename", "server_url",
            "device_ip", "device_ip_cidr", "gateway_ip",
            "hostname", "ssh_user", "ssh_pass",
            "output_callback", "stop_callback",
        ):
            self.assertIn(
                required, params,
                f"Waveserver5UpgradeScript.__init__ must accept {required!r} "
                f"(GUI worker passes it in)",
            )

    def test_run_method_orchestrates_both_phases(self):
        src = inspect.getsource(self.cls.run)
        # The serial → SSH ordering is load-bearing: if SSH ran first
        # the device wouldn't have a usable IP yet. Confirm via call
        # ordering in the source.
        serial_pos = src.find("_provision_via_serial")
        ssh_pos = src.find("_install_software_via_ssh")
        self.assertGreater(serial_pos, 0)
        self.assertGreater(ssh_pos, serial_pos)

    def test_serial_phase_sends_required_commands(self):
        src = inspect.getsource(self.cls._provision_via_serial)
        for needle in (
            "system set host-name",
            "dhcp client disable",
            "interface set interface local ip",
            "interface set gateway",
            "ntp client disable",
            "system set date",
            "system set time",
            "configuration save",
        ):
            self.assertIn(
                needle, src,
                f"Phase 1 serial command {needle!r} is missing from "
                f"_provision_via_serial",
            )

    def test_ssh_phase_sends_required_commands(self):
        # Check the whole class — ``software show upgrade-status`` is
        # only literal in ``_wait_for_state`` (the polling helper),
        # while the rest live in ``_install_software_via_ssh``.
        src = inspect.getsource(self.cls)
        for needle in (
            "software download url",
            "software show upgrade-status",
            "system server grpc disable",
            "system server https disable",
            "system server netconf disable",
            "system server sftp disable",
            "system server scp disable",
            "user create user diag password diagdiag access-level diag",
            "software activate version",
        ):
            self.assertIn(
                needle, src,
                f"Phase 2 SSH command {needle!r} is missing from the "
                f"Waveserver5UpgradeScript class",
            )


class TestSoftwareUpgradeFrameRegistersWaveserver5(unittest.TestCase):
    """The dropdown must list ``Ciena Waveserver 5`` or the user can't
    pick it. Source-level check avoids needing a Tk root."""

    def test_supported_upgrades_includes_waveserver5(self):
        from gui import software_upgrade_frame as suf
        self.assertIn("Ciena Waveserver 5", suf._SUPPORTED_UPGRADES)

    def test_ws5_network_constants_present(self):
        from gui import software_upgrade_frame as suf
        self.assertEqual(suf._WS5_NET["pc_ip"], "10.9.49.101")
        self.assertEqual(suf._WS5_NET["device_ip"], "10.9.49.36")
        self.assertEqual(suf._WS5_NET["device_ip_cidr"], "10.9.49.36/22")
        # /22 = 255.255.252.0; getting this wrong would silently put the
        # PC and the shelf on different subnets.
        self.assertEqual(suf._WS5_NET["mask"], "255.255.252.0")
        self.assertEqual(suf._WS5_HOSTNAME, "WS5_1")


if __name__ == "__main__":
    unittest.main()
