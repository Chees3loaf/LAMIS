"""Unit tests for utils/helpers.py"""

import unittest
from pathlib import Path

from utils.helpers import extract_ip_sort_key, get_database_path, get_project_root


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

    def test_parent_dir_is_data(self):
        path = get_database_path()
        self.assertEqual(path.parent.name, "data")

    def test_path_is_inside_project_root(self):
        root = get_project_root()
        db = get_database_path()
        self.assertTrue(str(db).startswith(str(root)))


if __name__ == "__main__":
    unittest.main()
