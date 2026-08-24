import unittest

from nokia_network_audit.capture import safe_filename, transcript_path
from nokia_network_audit.profiles import (
    PROFILES,
    CommandProfile,
    is_read_only_command,
    validate_profile,
)


class CaptureSafetyTests(unittest.TestCase):
    def test_all_shipped_profiles_are_read_only(self):
        for profile in PROFILES.values():
            validate_profile(profile)
            self.assertTrue(all(is_read_only_command(c) for c in profile.commands))

    def test_mutating_command_is_rejected(self):
        profile = CommandProfile("unsafe", "unsafe", ("show port", "clear port 1/1/1"))
        with self.assertRaises(ValueError):
            validate_profile(profile)

    def test_safe_capture_filename(self):
        self.assertEqual(safe_filename("10.1.2.3:22"), "10.1.2.3_22")
        path = transcript_path(__import__("pathlib").Path("out"), "router/a", "7705")
        self.assertEqual(path.parent.name, "out")
        self.assertNotIn("/", path.name)


if __name__ == "__main__":
    unittest.main()
