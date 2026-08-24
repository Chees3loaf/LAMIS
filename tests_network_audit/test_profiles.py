import unittest
from pathlib import Path

from nokia_network_audit.profiles import (
    PROFILES,
    CommandProfile,
    is_paging_command,
    is_read_only_command,
    session_commands,
    validate_profile,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_DIR = REPO_ROOT / "baseline_commands"

# baseline_commands/<file>.txt is the manual-capture copy of a profile.
BASELINE_FILES = {
    "7705-sar-8": "7705-sar-8.txt",
    "7250-ixr-r6": "7250-ixr-r6.txt",
    "1830-pss-8": "1830-pss-8.txt",
}


class ProfileSafetyTests(unittest.TestCase):
    def test_command_lists_are_show_only(self):
        for profile in PROFILES.values():
            validate_profile(profile)
            for command in profile.commands:
                self.assertTrue(
                    is_read_only_command(command),
                    f"{profile.name}: {command!r}",
                )

    def test_paging_command_is_not_in_the_show_allowlist(self):
        # Pagination setup is session display state, tracked separately so the
        # command allowlist can stay strictly "show".
        self.assertFalse(is_read_only_command("environment no more"))
        self.assertTrue(is_paging_command("environment no more"))
        self.assertTrue(is_paging_command("paging status disabled"))
        self.assertFalse(is_paging_command("paging status disable"))

    def test_each_platform_gets_its_documented_paging_command(self):
        # 1830 PSS R24.12 CLI Guide 2.16 spells the value "disabled".
        self.assertEqual(
            PROFILES["1830-pss-8"].paging_command, "paging status disabled"
        )
        for name in ("7705-sar-8", "7250-ixr-r6", "7250-ixr-r6d", "7250-ixr-r6dl"):
            self.assertEqual(PROFILES[name].paging_command, "environment no more")

    def test_session_commands_lead_with_paging(self):
        for profile in PROFILES.values():
            commands = session_commands(profile)
            self.assertEqual(commands[0], profile.paging_command)
            self.assertEqual(len(commands), len(profile.commands) + 1)

    def test_mutating_command_is_rejected(self):
        profile = CommandProfile("unsafe", "unsafe", ("show port", "clear port 1/1/1"))
        with self.assertRaises(ValueError):
            validate_profile(profile)

    def test_unknown_paging_command_is_rejected(self):
        profile = CommandProfile(
            "unsafe", "unsafe", ("show port",), paging_command="configure system"
        )
        with self.assertRaises(ValueError):
            validate_profile(profile)

    def test_baseline_files_match_the_profiles(self):
        for profile_name, filename in BASELINE_FILES.items():
            path = BASELINE_DIR / filename
            lines = [
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            ]
            self.assertEqual(
                lines,
                list(session_commands(PROFILES[profile_name])),
                f"{filename} has drifted from profile {profile_name!r}",
            )


if __name__ == "__main__":
    unittest.main()
