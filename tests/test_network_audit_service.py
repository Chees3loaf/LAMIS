"""Tests for the Qt-facing network-audit service."""
from pathlib import Path
from unittest.mock import patch

import pytest

from services.network_audit_service import NetworkAuditRequest, is_valid_audit_host, run_network_audit, validate_network_audit_request


def _request(tmp_path: Path, **changes) -> NetworkAuditRequest:
    values = dict(
        network_type="rls", seed="10.0.0.1", username="user", password="secret",
        output_path=tmp_path / "audit.xlsx",
    )
    values.update(changes)
    return NetworkAuditRequest(**values)


def test_host_validation_accepts_ip_and_safe_hostname() -> None:
    assert is_valid_audit_host("10.0.0.1")
    assert is_valid_audit_host("node-1.example.net")
    assert not is_valid_audit_host("node & command")


def test_request_requires_xlsx_output(tmp_path) -> None:
    with pytest.raises(ValueError, match="xlsx"):
        validate_network_audit_request(_request(tmp_path, output_path=tmp_path / "audit.csv"))


def test_rls_audit_delegates_all_collection_options(tmp_path) -> None:
    request = _request(tmp_path, capture_alarms=True, capture_alarm_history=True, debug=True)
    messages = []
    with patch("scripts.Network.RLS_Audit.run_audit") as run:
        result = run_network_audit(request, progress=messages.append)
    assert result == request.output_path
    run.assert_called_once_with(
        seed_host="10.0.0.1", username="user", password="secret",
        output_path=str(request.output_path), capture_alarms=True,
        capture_alarm_history=True, debug=True, log_callback=messages.append,
    )


def test_psi_audit_uses_psi_engine(tmp_path) -> None:
    request = _request(tmp_path, network_type="psi")
    with patch("scripts.Network.Nokia_PSI_Audit.run_audit") as run:
        run_network_audit(request)
    run.assert_called_once()
