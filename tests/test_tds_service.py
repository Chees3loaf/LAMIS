"""Tests for the UI-independent TDS launcher."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from services.tds_service import TdsRequest, is_valid_tds_host, run_tds, validate_tds_request


def test_tds_host_validation_accepts_ip_and_safe_hostname() -> None:
    assert is_valid_tds_host("10.0.0.1")
    assert is_valid_tds_host("shelf-1.example.net")
    assert not is_valid_tds_host("shelf & command")


def test_tds_rejects_output_directory_in_file_name() -> None:
    with pytest.raises(ValueError, match="file name"):
        validate_tds_request(TdsRequest("10.0.0.1", "rls", "folder/report"))


def test_rls_tds_preserves_walk_and_validation_flags() -> None:
    request = TdsRequest("10.0.0.1", "rls", "report")
    runner = MagicMock(return_value=SimpleNamespace(returncode=0, stdout="complete", stderr=""))
    with patch("services.tds_service.get_default_credential_for_vendor", return_value=("user", "secret")):
        outcome = run_tds(request, verify_host_key=lambda _host: True, subprocess_runner=runner)
    command = runner.call_args.args[0]
    assert "--validate" in command
    assert "--walk-mode" in command
    assert runner.call_args.kwargs["input"] == "secret"
    assert outcome.output == "complete"


def test_tds_retries_auth_failure_with_operator_credentials() -> None:
    request = TdsRequest("10.0.0.1", "6500", "report")
    runner = MagicMock(side_effect=[
        SimpleNamespace(returncode=1, stdout="", stderr="Permission denied"),
        SimpleNamespace(returncode=0, stdout="complete", stderr=""),
    ])
    with patch("services.tds_service.get_default_credential_for_vendor", return_value=("default", "bad")):
        run_tds(
            request, verify_host_key=lambda _host: True,
            request_credentials=lambda _host: ("operator", "working"),
            subprocess_runner=runner,
        )
    assert runner.call_count == 2
    assert runner.call_args.kwargs["input"] == "working"


def test_tds_stops_when_host_key_is_rejected() -> None:
    with pytest.raises(RuntimeError, match="host-key verification"):
        run_tds(
            TdsRequest("10.0.0.1", "rls", "report"),
            verify_host_key=lambda _host: False,
        )
