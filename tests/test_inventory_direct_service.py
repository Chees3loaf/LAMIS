"""Tests for the extracted direct-connection inventory service."""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import script_interface

from services.inventory_direct_service import DirectInventoryRequest, InventoryRunControl, NetworkInventoryRequest, combine_network_ranges, expand_network_range, run_direct_inventory, run_network_inventory, validate_direct_request


def _request(tmp_path: Path, **changes) -> DirectInventoryRequest:
    values = dict(
        mode="LAN", script_name="Ciena RLS", target="10.0.0.1",
        output_path=tmp_path / "inventory.xlsx", customer="Customer",
        project="Project", purchase_order="PO", sales_order="SO",
    )
    values.update(changes)
    return DirectInventoryRequest(**values)


def test_validation_rejects_wrong_script_for_mode(tmp_path) -> None:
    with pytest.raises(ValueError, match="not supported"):
        validate_direct_request(_request(tmp_path, script_name="Nokia SAR"))


def test_validation_rejects_invalid_lan_target(tmp_path) -> None:
    with pytest.raises(ValueError, match="valid IP"):
        validate_direct_request(_request(tmp_path, target="not-an-ip"))


def test_direct_run_collects_and_routes_rls_template(tmp_path) -> None:
    request = _request(tmp_path)
    script = MagicMock()
    script.get_commands.return_value = ["show inventory"]
    script.execute_commands.return_value = (["device output"], None)
    script.process_outputs.side_effect = lambda _raw, target, outputs: outputs.update({target: {"data": {}}})
    script.__class__.__module__ = "scripts.Ciena_RLS"
    builder = MagicMock()
    messages = []
    with patch("services.inventory_direct_service._build_script", return_value=script), patch("services.inventory_direct_service.clear_known_host_entry"):
        outcome = run_direct_inventory(request, progress=messages.append, builder=builder)
    assert outcome.family == "rls"
    builder.build_psi_report_workbook.assert_called_once()
    assert "Ciena_RLS_Report_Template.xlsx" in builder.build_psi_report_workbook.call_args.kwargs["psi_template_path"]
    assert messages[-1].startswith("Saved inventory report:")


def test_control_aborts_active_connection() -> None:
    control = InventoryRunControl()
    script = MagicMock()
    control.set_script(script)
    control.cancel()
    assert control.should_stop()
    script.abort_connection.assert_called_once_with()


def test_direct_run_retries_rejected_defaults_with_operator_credentials(tmp_path) -> None:
    request = _request(tmp_path, script_name="Ciena 6500")
    script = MagicMock()
    script.get_commands.return_value = ["show inventory"]
    script.execute_commands.side_effect = [
        ([], "NEEDS_CREDENTIALS"),
        (["device output"], None),
    ]
    script.process_outputs.side_effect = lambda _raw, target, outputs: outputs.update({target: {"data": {}}})
    builder = MagicMock()
    with patch("services.inventory_direct_service._build_script", return_value=script), patch("services.inventory_direct_service.clear_known_host_entry"), patch.object(script_interface, "NEEDS_CREDENTIALS_SENTINEL", "NEEDS_CREDENTIALS"):
        run_direct_inventory(
            request, builder=builder,
            request_credentials=lambda _target: ("operator", "secret"),
        )
    assert script.username == "operator"
    assert script.password == "secret"
    assert script.execute_commands.call_count == 2


def test_pod_and_cross_subnet_lab_ranges_follow_legacy_addressing() -> None:
    assert expand_network_range("Pod 2", "10", "12") == [
        "172.21.102.10", "172.21.102.11", "172.21.102.12",
    ]
    assert expand_network_range("Lab", "255", "1", "4", "5") == [
        "10.9.4.255", "10.9.5.0", "10.9.5.1",
    ]


def test_combined_ranges_remove_overlapping_addresses() -> None:
    assert combine_network_ranges(
        ["172.21.101.1", "172.21.101.2"],
        ["172.21.101.2", "172.21.101.3"],
    ) == ("172.21.101.1", "172.21.101.2", "172.21.101.3")


def test_network_run_exports_partial_success_and_reports_failures(tmp_path) -> None:
    request = NetworkInventoryRequest(
        targets=("10.0.0.1", "10.0.0.2"), output_path=tmp_path / "network.xlsx",
        customer="Customer", project="Project", purchase_order="PO", sales_order="SO",
    )
    builder = MagicMock()
    messages = []

    def collect(ip, outputs, families, _lock, _control, _emit, _credentials):
        if ip.endswith("1"):
            outputs[ip] = {"data": {}}
            families[ip] = "default"
            return ip, None
        return ip, "Authentication failed"

    with patch("services.inventory_direct_service.script_interface.probe_host", return_value=(True, "")), patch("services.inventory_direct_service._collect_network_device", side_effect=collect):
        outcome = run_network_inventory(request, builder=builder, progress=messages.append)

    assert outcome.collected == 1
    assert outcome.failed == {"10.0.0.2": "Authentication failed"}
    assert "10.0.0.2: Authentication failed" in messages
    builder.build_report_workbook.assert_called_once()


def test_network_run_uses_unified_export_for_mixed_families(tmp_path) -> None:
    request = NetworkInventoryRequest(
        targets=("10.0.0.1", "10.0.0.2"), output_path=tmp_path / "network.xlsx",
        customer="Customer", project="Project", purchase_order="PO", sales_order="SO",
    )
    builder = MagicMock()

    def collect(ip, outputs, families, _lock, _control, _emit, _credentials):
        outputs[ip] = {"data": {}}
        families[ip] = "rls" if ip.endswith("1") else "psi"
        return ip, None

    with patch("services.inventory_direct_service.script_interface.probe_host", return_value=(True, "")), patch("services.inventory_direct_service._collect_network_device", side_effect=collect):
        run_network_inventory(request, builder=builder)

    builder.build_unified_report_workbook.assert_called_once()
