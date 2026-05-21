"""Tests for the installed-mode (PyInstaller frozen) update path."""
import io
import json
import os
import unittest
from unittest.mock import patch, MagicMock

from utils import update as upd
from utils.update import Updater, _parse_version, _is_newer


class TestVersionParsing(unittest.TestCase):

    def test_parses_plain_semver(self):
        self.assertEqual(_parse_version("2.0.0"), (2, 0, 0))

    def test_parses_with_v_prefix(self):
        self.assertEqual(_parse_version("v2.0.1"), (2, 0, 1))

    def test_parses_with_prerelease_suffix(self):
        self.assertEqual(_parse_version("2.1.0-rc.1"), (2, 1, 0))
        self.assertEqual(_parse_version("v2.1.0+build.42"), (2, 1, 0))

    def test_returns_none_for_garbage(self):
        self.assertIsNone(_parse_version(""))
        self.assertIsNone(_parse_version(None))
        self.assertIsNone(_parse_version("latest"))
        self.assertIsNone(_parse_version("2.0"))  # need three components

    def test_is_newer(self):
        self.assertTrue(_is_newer("v2.0.1", "2.0.0"))
        self.assertTrue(_is_newer("2.1.0", "2.0.99"))
        self.assertFalse(_is_newer("2.0.0", "2.0.0"))
        self.assertFalse(_is_newer("1.99.99", "2.0.0"))
        self.assertFalse(_is_newer("garbage", "2.0.0"))


class TestModeDetection(unittest.TestCase):

    def test_dev_mode_requires_repo_path(self):
        with patch.object(upd, "_running_as_frozen", return_value=False):
            with self.assertRaises(FileNotFoundError):
                Updater(repo_path="/nonexistent/path/x")

    def test_installed_mode_ignores_repo_path(self):
        with patch.object(upd, "_running_as_frozen", return_value=True):
            up = Updater(repo_path="/whatever/this/is")
            self.assertTrue(up.installed_mode)
            self.assertEqual(up.repo_path, "/whatever/this/is")  # stored but unused


def _make_installed_updater(current_version="2.0.0"):
    with patch.object(upd, "_running_as_frozen", return_value=True):
        up = Updater(
            github_owner="acme",
            github_repo="atlas",
            current_version=current_version,
        )
    return up


class TestSha256HintExtraction(unittest.TestCase):

    def test_pulls_hash_from_release_body(self):
        body = (
            "Bunch of release notes here.\n"
            "ATLAS_Setup.exe sha256: "
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"
            "Some footer text.\n"
        )
        rel = {"body": body}
        self.assertEqual(
            Updater._extract_sha256_hint(rel),
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )

    def test_returns_none_when_no_hash(self):
        rel = {"body": "Plain notes with no hash and no installer mention."}
        self.assertIsNone(Updater._extract_sha256_hint(rel))

    def test_handles_empty_body(self):
        self.assertIsNone(Updater._extract_sha256_hint({}))
        self.assertIsNone(Updater._extract_sha256_hint({"body": ""}))


class TestCheckForUpdatesInstalled(unittest.TestCase):

    def _mock_release(self, tag):
        body = io.BytesIO(json.dumps({"tag_name": tag, "assets": []}).encode("utf-8"))
        body.__enter__ = lambda self_=body: self_
        body.__exit__ = lambda *_: None
        return body

    def test_newer_release_returns_true(self):
        up = _make_installed_updater("2.0.0")
        with patch.object(upd.urllib.request, "urlopen") as op:
            op.return_value = self._mock_release("v2.0.1")
            self.assertTrue(up.check_for_updates())
            self.assertIsNotNone(up._latest_release)

    def test_same_version_returns_false(self):
        up = _make_installed_updater("2.0.0")
        with patch.object(upd.urllib.request, "urlopen") as op:
            op.return_value = self._mock_release("v2.0.0")
            self.assertFalse(up.check_for_updates())

    def test_older_release_returns_false(self):
        up = _make_installed_updater("2.0.5")
        with patch.object(upd.urllib.request, "urlopen") as op:
            op.return_value = self._mock_release("v1.9.0")
            self.assertFalse(up.check_for_updates())

    def test_network_failure_returns_false(self):
        up = _make_installed_updater("2.0.0")
        import urllib.error
        with patch.object(upd.urllib.request, "urlopen",
                          side_effect=urllib.error.URLError("offline")):
            self.assertFalse(up.check_for_updates())


class TestApplyUpdateInstalled(unittest.TestCase):

    def test_no_release_aborts(self):
        up = _make_installed_updater("2.0.0")
        with patch.object(up, "_fetch_latest_release", return_value=None):
            ok, msg = up.apply_update()
            self.assertFalse(ok)
            self.assertIn("release information", msg.lower())

    def test_up_to_date_aborts(self):
        up = _make_installed_updater("2.0.5")
        up._latest_release = {"tag_name": "v2.0.5"}
        ok, msg = up.apply_update()
        self.assertFalse(ok)
        self.assertIn("up to date", msg.lower())

    def test_missing_installer_asset_aborts(self):
        up = _make_installed_updater("2.0.0")
        up._latest_release = {
            "tag_name": "v2.0.1",
            "assets": [{"name": "something_else.zip"}],
        }
        ok, msg = up.apply_update()
        self.assertFalse(ok)
        self.assertIn("installer asset", msg.lower())

    def test_cancelled_by_user_cleans_up(self):
        up = _make_installed_updater("2.0.0")
        up._latest_release = {
            "tag_name": "v2.0.1",
            "body": "",
            "assets": [{
                "name": "ATLAS_Setup.exe",
                "browser_download_url": "https://example.com/ATLAS_Setup.exe",
                "size": 4,
            }],
        }
        up.set_confirmation_callback(lambda _msg: False)
        # Mock the download so we don't actually hit the network.
        fake_path = os.path.join(os.getcwd(), "_fake_installer.exe")
        with open(fake_path, "wb") as f:
            f.write(b"data")
        try:
            with patch.object(up, "_download_installer",
                              return_value=(fake_path, None)):
                ok, msg = up.apply_update()
            self.assertFalse(ok)
            self.assertIn("cancelled", msg.lower())
            # And the cleanup ran.
            self.assertFalse(os.path.exists(fake_path))
        finally:
            if os.path.exists(fake_path):
                os.unlink(fake_path)

    def test_approved_launches_installer_and_returns_success(self):
        up = _make_installed_updater("2.0.0")
        up._latest_release = {
            "tag_name": "v2.0.1",
            "body": "",
            "assets": [{
                "name": "ATLAS_Setup.exe",
                "browser_download_url": "https://example.com/ATLAS_Setup.exe",
                "size": 4,
            }],
        }
        up.set_confirmation_callback(lambda _msg: True)
        fake_path = os.path.abspath("_fake_installer.exe")
        with open(fake_path, "wb") as f:
            f.write(b"data")
        try:
            with patch.object(up, "_download_installer",
                              return_value=(fake_path, None)), \
                 patch.object(upd.subprocess, "Popen") as popen:
                ok, msg = up.apply_update()
            self.assertTrue(ok, msg)
            self.assertIn("launched", msg.lower())
            popen.assert_called_once()
            launched_args = popen.call_args[0][0]
            self.assertEqual(launched_args[0], fake_path)
        finally:
            if os.path.exists(fake_path):
                os.unlink(fake_path)


if __name__ == "__main__":
    unittest.main()
