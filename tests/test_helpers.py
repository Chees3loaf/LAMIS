"""Unit tests for utils/helpers.py"""

import os
import tempfile
import unittest
from pathlib import Path

from utils.helpers import (
    clear_known_host_entry,
    extract_ip_sort_key,
    get_database_path,
    get_project_root,
)


class TestExtractIpSortKey(unittest.TestCase):

    # --- Valid IPs ---

    def test_valid_ip_returns_zero_prefix(self):
        key = extract_ip_sort_key("10.9.100.5")
        self.assertEqual(key[0], 0)

    def test_valid_ip_octets_parsed_correctly(self):
        key = extract_ip_sort_key("192.168.1.255")
        self.assertEqual(key[1:5], (192, 168, 1, 255))

    def test_ip_at_start_of_string(self):
        key = extract_ip_sort_key("10.0.0.1 - router")
        self.assertEqual(key[0], 0)
        self.assertEqual(key[1:5], (10, 0, 0, 1))

    def test_all_zeros_ip(self):
        key = extract_ip_sort_key("0.0.0.0")
        self.assertEqual(key[0], 0)
        self.assertEqual(key[1:5], (0, 0, 0, 0))

    def test_max_valid_ip(self):
        key = extract_ip_sort_key("255.255.255.255")
        self.assertEqual(key[1:5], (255, 255, 255, 255))

    # --- Sorting behaviour ---

    def test_ips_sort_numerically_not_lexicographically(self):
        ips = ["10.9.100.20", "10.9.100.3", "10.9.100.100"]
        sorted_ips = sorted(ips, key=extract_ip_sort_key)
        self.assertEqual(sorted_ips, ["10.9.100.3", "10.9.100.20", "10.9.100.100"])

    def test_ips_sort_across_octets(self):
        ips = ["10.9.101.1", "10.9.100.200", "10.8.100.1"]
        sorted_ips = sorted(ips, key=extract_ip_sort_key)
        self.assertEqual(sorted_ips, ["10.8.100.1", "10.9.100.200", "10.9.101.1"])

    def test_non_ip_sorts_after_valid_ip(self):
        values = ["device_name", "10.0.0.1"]
        sorted_values = sorted(values, key=extract_ip_sort_key)
        self.assertEqual(sorted_values, ["10.0.0.1", "device_name"])

    # --- Non-IP / edge cases ---

    def test_plain_string_returns_one_prefix(self):
        key = extract_ip_sort_key("device_name")
        self.assertEqual(key[0], 1)

    def test_plain_string_lowercase_in_key(self):
        key = extract_ip_sort_key("DeviceName")
        self.assertEqual(key[1], "devicename")

    def test_none_returns_one_prefix(self):
        key = extract_ip_sort_key(None)
        self.assertEqual(key[0], 1)

    def test_empty_string_returns_one_prefix(self):
        key = extract_ip_sort_key("")
        self.assertEqual(key[0], 1)

    def test_out_of_range_octet_falls_back(self):
        # 256 is not a valid octet value
        key = extract_ip_sort_key("256.0.0.1")
        self.assertEqual(key[0], 1)

    def test_partial_ip_falls_back(self):
        key = extract_ip_sort_key("10.0.1")
        self.assertEqual(key[0], 1)


class TestGetProjectRoot(unittest.TestCase):

    def test_returns_path_object(self):
        root = get_project_root()
        self.assertIsInstance(root, Path)

    def test_root_contains_main_py(self):
        root = get_project_root()
        self.assertTrue((root / "main.py").exists())

    def test_root_contains_config_py(self):
        root = get_project_root()
        self.assertTrue((root / "config.py").exists())


class TestGetDatabasePath(unittest.TestCase):

    def test_returns_path_object(self):
        path = get_database_path()
        self.assertIsInstance(path, Path)

    def test_filename_is_correct(self):
        path = get_database_path()
        self.assertEqual(path.name, "network_inventory.db")

    def test_parent_dir_is_atlas_appdata(self):
        # F019: DB lives under %APPDATA%\ATLAS so non-Admin installs (Program
        # Files is read-only for standard users) can still write to it.
        path = get_database_path()
        self.assertEqual(path.parent.name, "ATLAS")

    def test_path_is_inside_appdata(self):
        # The path should resolve under the user's APPDATA (or HOME fallback).
        import os
        app_data = os.environ.get("APPDATA", os.path.expanduser("~"))
        db = get_database_path()
        self.assertTrue(
            str(db).startswith(str(Path(app_data).resolve())),
            f"Expected DB under {app_data}, got {db}",
        )


class TestClearKnownHostEntry(unittest.TestCase):
    """``clear_known_host_entry`` powers the LAN-mode auto-reset: same
    management IP often maps to different physical devices between runs,
    so stale TOFU keys would block the next pull. The helper deletes the
    matching line(s) from the ATLAS known_hosts file and returns whether
    anything changed."""

    def _temp_known_hosts(self) -> Path:
        fd, name = tempfile.mkstemp(suffix="_known_hosts")
        os.close(fd)
        p = Path(name)
        self.addCleanup(lambda: p.exists() and p.unlink())
        return p

    def _seed(self, path: Path, hostnames: list) -> None:
        """Populate *path* with real paramiko-valid RSA host keys for
        each name in *hostnames*. Avoids hand-crafting key blobs that
        paramiko's strict parser would reject."""
        import paramiko
        kh = paramiko.HostKeys()
        for i, host in enumerate(hostnames):
            # Fresh 2048-bit RSA key per host — paramiko accepts these
            # and the keys are distinct so dedupe behaviour is exercised.
            key = paramiko.RSAKey.generate(2048)
            kh.add(host, "ssh-rsa", key)
        kh.save(str(path))

    def test_returns_false_when_file_missing(self):
        missing = Path(tempfile.gettempdir()) / "atlas_no_such_known_hosts"
        if missing.exists():
            missing.unlink()
        self.assertFalse(clear_known_host_entry("10.0.0.1", missing))

    def test_returns_false_when_ip_not_present(self):
        p = self._temp_known_hosts()
        self._seed(p, ["10.9.100.5"])
        self.assertFalse(clear_known_host_entry("10.0.0.1", p))
        # File untouched.
        self.assertIn("10.9.100.5", p.read_text(encoding="utf-8"))

    def test_removes_matching_ip_returns_true(self):
        p = self._temp_known_hosts()
        self._seed(p, ["10.0.0.1", "10.9.100.5"])
        self.assertTrue(clear_known_host_entry("10.0.0.1", p))
        text = p.read_text(encoding="utf-8")
        # The 10.0.0.1 line is gone, 10.9.100.5 is preserved.
        self.assertNotIn("10.0.0.1", text)
        self.assertIn("10.9.100.5", text)

    def test_calling_twice_is_idempotent(self):
        """The user might double-click run; the second call should be a
        clean no-op rather than raising."""
        p = self._temp_known_hosts()
        self._seed(p, ["10.0.0.1"])
        self.assertTrue(clear_known_host_entry("10.0.0.1", p))
        self.assertFalse(clear_known_host_entry("10.0.0.1", p))


class TestLanModeClearsKnownHostsAfterRun(unittest.TestCase):
    """Source-level guard: the LAN branch of ``run_inventory_worker``
    must call ``clear_known_host_entry`` after the task queue drains.
    Without this the user keeps hitting host-key mismatch errors every
    time the device behind 10.0.0.1 changes."""

    def test_lan_branch_calls_clear_known_host_entry(self):
        import inspect
        from gui.gui4_0 import InventoryGUI
        src = inspect.getsource(InventoryGUI.run_inventory_worker)
        # Must import and call the helper.
        self.assertIn("clear_known_host_entry", src)
        # Must guard so Serial mode (no SSH, no host key) doesn't try it.
        self.assertIn('context.get("connection_mode") == "LAN"', src)


if __name__ == "__main__":
    unittest.main()
