import csv
import os
import tempfile
import unittest
from unittest import mock

from scripts.Network.Ciena_RLS_Upgrade import RLSUpgradeScript
from scripts.TDS import RLS_Network_Audit as audit


class TestRLSUpgradeRegressions(unittest.TestCase):
    def test_poll_until_done_accepts_idle_transition(self):
        script = RLSUpgradeScript(
            ip_address="127.0.0.1",
            username="user",
            password="pass",
            server_url="http://example.invalid/test.tgz",
            poll_interval=0,
            timeout=5,
        )
        script._log = lambda _msg: None

        responses = iter([
            "software:\n  upgrade-operational-state   : load-in-progress\nrls#",
            "software:\n  upgrade-operational-state   : idle\nrls#",
        ])
        script._send = lambda _session, _cmd, timeout=20: next(responses)

        self.assertTrue(script._poll_until_done(object()))


class TestRLSNetworkAuditRegressions(unittest.TestCase):
    def _write_walk_artifacts(self, workdir: str, host: str = "seed") -> tuple[str, str]:
        validation_csv = os.path.join(workdir, f"{host}_RLS_Validation.csv")
        neighbors_csv = os.path.join(workdir, f"{host}_RLS_Walk_Neighbors.csv")
        with open(validation_csv, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Status"])
            writer.writerow(["PASS"])
        with open(neighbors_csv, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Management Address"])
        return validation_csv, neighbors_csv

    def test_run_audit_preserves_csvs_when_workbook_compose_fails(self):
        with tempfile.TemporaryDirectory() as workdir:
            validation_csv, neighbors_csv = self._write_walk_artifacts(workdir)

            with mock.patch.object(audit, "_run_tds_for_host", return_value=0), \
                 mock.patch.object(audit, "compose_network_workbook", return_value=""):
                result = audit.run_audit(
                    seeds=["seed"],
                    username="user",
                    max_hops=0,
                    workdir=workdir,
                    compose_workbook=True,
                    log=lambda _msg: None,
                )

            self.assertEqual(result, os.path.join(workdir, "Walk_Summary.csv"))
            self.assertTrue(os.path.exists(validation_csv))
            self.assertTrue(os.path.exists(neighbors_csv))

    def test_run_audit_removes_csvs_after_workbook_compose_succeeds(self):
        with tempfile.TemporaryDirectory() as workdir:
            validation_csv, neighbors_csv = self._write_walk_artifacts(workdir)
            workbook_path = os.path.join(workdir, "seed_RLS_Network.xlsx")

            with mock.patch.object(audit, "_run_tds_for_host", return_value=0), \
                 mock.patch.object(audit, "compose_network_workbook", return_value=workbook_path):
                result = audit.run_audit(
                    seeds=["seed"],
                    username="user",
                    max_hops=0,
                    workdir=workdir,
                    compose_workbook=True,
                    log=lambda _msg: None,
                )

            self.assertEqual(result, workbook_path)
            self.assertFalse(os.path.exists(validation_csv))
            self.assertFalse(os.path.exists(neighbors_csv))


if __name__ == "__main__":
    unittest.main()