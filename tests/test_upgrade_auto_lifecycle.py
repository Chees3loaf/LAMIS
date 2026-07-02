"""Regression test for the Software Upgrade tab auto-lifecycle.

Field bug this guards: the upgrade tab used to expose four manual
buttons -- Apply Static IP, Restore DHCP, Start Server, Stop Server --
that the operator had to drive in sequence around the Run Upgrade
button. In practice every Run Upgrade press triggered the same
sequence regardless, and operators routinely forgot to click
Restore DHCP at the end, leaving their NIC stuck on the device-side
static IP after the laptop moved to the next bay.

The fix removes the buttons entirely and makes ``_run_<dtype>_upgrade``
do the full lifecycle inside its worker thread:

  1. Apply the static IP for the device family.
  2. Start the HTTP server (G42 / RLS / WS5 only -- PSI uses FTP).
  3. Run the upgrade script.
  4. In a ``finally``, stop the server (if we started it) and
     restore DHCP (if we applied the static IP).

The static-IP for each device family is auto-populated into the
form when its name is picked from the device-type dropdown, so the
operator never types it.
"""
from __future__ import annotations
import inspect
import unittest


class TestManualNicAndServerButtonsRemoved(unittest.TestCase):
    """Pin that the four manual buttons are gone from the source.

    Pin via button *label*, not attribute name -- ``self._stop_btn``
    is in active use as the G42 Stop *Upgrade* button (distinct from
    the removed Stop *Server* button), so an attribute-name check
    would either miss the regression or false-fire.
    """

    def setUp(self):
        from gui import software_upgrade_frame
        self.src = inspect.getsource(
            software_upgrade_frame.SoftwareUpgradeFrame
        )

    def test_apply_static_ip_button_label_removed(self):
        # The button used to read "Apply Static IP" -- match the
        # verbatim label so a refactor that renames the attribute
        # but keeps the user-facing button still trips this.
        self.assertNotIn(
            '"Apply Static IP"', self.src,
            "the manual 'Apply Static IP' button must not be present "
            "-- the worker applies the IP automatically now",
        )

    def test_restore_dhcp_button_label_removed(self):
        self.assertNotIn(
            '"Restore DHCP"', self.src,
            "the manual 'Restore DHCP' button must not be present "
            "-- the worker restores DHCP automatically now",
        )

    def test_start_server_button_label_removed(self):
        self.assertNotIn(
            '"Start Server"', self.src,
            "the manual 'Start Server' button must not be present "
            "-- the worker starts the server automatically now",
        )

    def test_stop_server_button_label_removed(self):
        self.assertNotIn(
            '"Stop Server"', self.src,
            "the manual 'Stop Server' button must not be present "
            "-- the worker stops the server automatically now",
        )


class TestDeviceTypeAutoPopulatesPcIp(unittest.TestCase):
    """``_on_dtype_change`` is the dropdown handler. It must seed the
    PC-IP field with the per-device-family service IP so the operator
    doesn't have to memorise four different /24s. Without this, the
    netsh apply step in the worker would fall back to whatever stale
    value was in the field from a previous run.
    """

    def setUp(self):
        from gui import software_upgrade_frame
        self.mod = software_upgrade_frame
        self.handler_src = inspect.getsource(
            software_upgrade_frame.SoftwareUpgradeFrame._on_dtype_change
        )

    def test_handler_branches_on_each_device_type(self):
        # The four device-type strings the dropdown emits.
        self.assertIn('"Ciena RLS"', self.handler_src)
        self.assertIn('"Ciena Waveserver 5"', self.handler_src)
        self.assertIn('"Nokia G42"', self.handler_src)
        self.assertIn('"Nokia PSI"', self.handler_src)
        self.assertIn('"Nokia PSS"', self.handler_src)

    def test_g42_branch_writes_169_254_pc_ip(self):
        # G42 PC IP is fixed at 169.254.0.101 -- pin the value as it
        # appears in the per-device network dict.
        self.assertEqual(self.mod._G42_NET["pc_ip"], "169.254.0.101")
        self.assertIn("_G42_NET", self.handler_src)
        self.assertIn(
            "self._pc_ip_var.set(_G42_NET[\"pc_ip\"])", self.handler_src,
            "G42 branch must seed pc_ip_var from _G42_NET so it tracks "
            "the constant rather than a hardcoded duplicate",
        )

    def test_ws5_branch_writes_per_family_pc_ip_and_mask(self):
        # WS5 uses a /22 -- distinct from the others, so the mask
        # must come from _WS5_NET, not _DEFAULT_MASK.
        self.assertIn("_WS5_NET", self.handler_src)
        self.assertIn("self._mask_var.set(_WS5_NET[\"mask\"])", self.handler_src)

    def test_psi_branch_writes_per_family_pc_ip(self):
        self.assertIn("_PSI_NET", self.handler_src)
        self.assertIn(
            "self._pc_ip_var.set(_PSI_NET[\"pc_ip\"])", self.handler_src,
        )

    def test_rls_branch_defers_to_ctm_change(self):
        # RLS has two CTM variants with different /24s, so the handler
        # delegates to the CTM-specific change handler instead of
        # writing a single PC IP.
        self.assertIn("self._on_rls_ctm_change()", self.handler_src)


class TestUpgradeWorkersAutoRestoreDhcp(unittest.TestCase):
    """All four upgrade workers must call ``_restore_dhcp`` in their
    finally block when they applied a static IP. The flag-guard is
    important -- if the netsh apply step itself fails, the NIC was
    never touched and ``_restore_dhcp`` would either no-op or, worse,
    clobber a manually-set address.
    """

    def setUp(self):
        from gui import software_upgrade_frame
        self.cls = software_upgrade_frame.SoftwareUpgradeFrame
        self.workers = {
            "g42": inspect.getsource(self.cls._run_g42_upgrade),
            "rls": inspect.getsource(self.cls._run_rls_upgrade),
            "psi": inspect.getsource(self.cls._run_psi_upgrade),
            "pss": inspect.getsource(self.cls._run_pss_upgrade),
            "ws5": inspect.getsource(self.cls._run_ws5_upgrade),
        }

    def test_each_worker_tracks_static_ip_ownership_flag(self):
        # The flag pattern -- ``static_ip_owned_by_us = False`` at the
        # top of the try, flipped to True after a successful netsh
        # apply -- is what guards the finally cleanup.
        for name, src in self.workers.items():
            with self.subTest(worker=name):
                self.assertIn(
                    "static_ip_owned_by_us = False", src,
                    f"{name} worker missing the static-IP ownership flag",
                )
                self.assertIn(
                    "static_ip_owned_by_us = True", src,
                    f"{name} worker missing the flag-set after netsh "
                    "apply",
                )

    def test_each_worker_calls_restore_dhcp_in_finally(self):
        for name, src in self.workers.items():
            with self.subTest(worker=name):
                self.assertIn(
                    "self.after(0, self._restore_dhcp)", src,
                    f"{name} worker must schedule _restore_dhcp on the "
                    "Tk thread in its finally block",
                )
                # Pin the guard, not just the call -- without the
                # flag check we'd hit _restore_dhcp on every error
                # path, including ones where netsh never ran.
                self.assertIn(
                    "if static_ip_owned_by_us:", src,
                    f"{name} worker must guard the _restore_dhcp call "
                    "behind the ownership flag",
                )


class TestServerUsingWorkersAutoStopServer(unittest.TestCase):
    """G42, RLS, and WS5 all have the device pull the upgrade
    artefact over HTTP from the laptop. Each worker must start the
    server if it isn't already running and stop it in the finally if
    *it* started it. PSI uses FTP (handled inside the script) and is
    intentionally excluded -- its worker has no server lifecycle.
    """

    def setUp(self):
        from gui import software_upgrade_frame
        self.cls = software_upgrade_frame.SoftwareUpgradeFrame
        self.http_workers = {
            "g42": inspect.getsource(self.cls._run_g42_upgrade),
            "rls": inspect.getsource(self.cls._run_rls_upgrade),
            "ws5": inspect.getsource(self.cls._run_ws5_upgrade),
        }
        self.psi_src = inspect.getsource(self.cls._run_psi_upgrade)

    def test_http_workers_track_server_ownership_flag(self):
        for name, src in self.http_workers.items():
            with self.subTest(worker=name):
                self.assertIn(
                    "server_started_by_us = False", src,
                    f"{name} worker missing server-ownership flag init",
                )
                self.assertIn(
                    "server_started_by_us = True", src,
                    f"{name} worker missing the flag-set after server "
                    "start",
                )

    def test_http_workers_auto_start_server_if_not_running(self):
        for name, src in self.http_workers.items():
            with self.subTest(worker=name):
                # The auto-start branch -- ``if self._server is None``
                # followed by an ``self.after(0, self._start_server)``
                # call -- replaces the old "HTTP server not running,
                # start now?" askyesno gate.
                self.assertIn("if self._server is None:", src)
                self.assertIn(
                    "self.after(0, self._start_server)", src,
                    f"{name} worker must auto-start the HTTP server "
                    "rather than prompting the operator",
                )

    def test_http_workers_call_stop_server_in_finally(self):
        for name, src in self.http_workers.items():
            with self.subTest(worker=name):
                self.assertIn(
                    "self.after(0, self._stop_server)", src,
                    f"{name} worker must schedule _stop_server in its "
                    "finally block",
                )
                self.assertIn(
                    "if server_started_by_us:", src,
                    f"{name} worker must guard the _stop_server call "
                    "behind the ownership flag",
                )

    def test_psi_worker_has_no_server_lifecycle(self):
        # PSI uses FTP (the script wires it up via the on-device FTP
        # client) so there's no HTTP server to start or stop. Pin
        # that the worker doesn't accidentally pick up the server
        # ownership pattern -- it'd start a port-8000 listener for
        # no reason and trip the next G42/RLS/WS5 run's auto-start.
        self.assertNotIn(
            "server_started_by_us", self.psi_src,
            "PSI worker should not be tracking HTTP server "
            "ownership -- PSI uses FTP, not the HTTP server",
        )
        self.assertNotIn(
            "self.after(0, self._start_server)", self.psi_src,
            "PSI worker should not be starting the HTTP server",
        )


class TestRunUpgradePromptsDoNotGateOnHttpServer(unittest.TestCase):
    """The pre-flight ``askokcancel`` / ``askyesno`` dialogs that
    used to ask "HTTP server not running, start now?" are now an
    operator-facing footgun -- the worker handles it. Pin that the
    gate is gone from each Run Upgrade entry point.
    """

    def setUp(self):
        from gui import software_upgrade_frame
        self.cls = software_upgrade_frame.SoftwareUpgradeFrame
        self.workers = {
            "g42": inspect.getsource(self.cls._run_g42_upgrade),
            "rls": inspect.getsource(self.cls._run_rls_upgrade),
            "ws5": inspect.getsource(self.cls._run_ws5_upgrade),
        }

    def test_run_upgrade_does_not_block_on_server_not_running_prompt(self):
        for name, src in self.workers.items():
            with self.subTest(worker=name):
                # The old gate -- ``askyesno("HTTP server not
                # running", ...)`` -- would silently abort the run
                # if the operator missed the dialog.
                self.assertNotIn(
                    '"HTTP server not running"', src,
                    f"{name} Run Upgrade must not gate on a 'server "
                    "not running' dialog -- start it automatically",
                )


if __name__ == "__main__":
    unittest.main()
