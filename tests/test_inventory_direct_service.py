"""Tests for the extracted direct-connection inventory service."""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from services.inventory_direct_service import DirectInventoryRequest, InventoryRunControl, run_direct_inventory, validate_direct_request


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
