"""Smoke tests for the opt-in PySide6 Asset Import page."""
from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QFileDialog, QLabel, QMessageBox

from gui_qt.asset_import_page import AssetImportPage
from gui_qt.bom_build_page import BomBuildPage
from gui_qt.bom_compare_page import BomComparePage
from gui_qt.inventory_page import InventoryPage
from gui_qt.diagnostics_page import DiagnosticsPage
from gui_qt.part_lookup_page import PartLookupPage
from gui_qt.raw_processing_page import RawProcessingPage
from gui_qt.packing_slip_page import PackingSlipPage
from gui_qt.sales_bom_import_page import SalesBomImportPage
from gui_qt.main_window import AtlasPilotWindow


def _application() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_pilot_window_constructs() -> None:
    _application()
    window = AtlasPilotWindow()

    assert window.windowTitle() == "ATLAS"
    assert window.page_stack.currentWidget() is window.pages["overview"]
    assert isinstance(window.pages["asset-import"], AssetImportPage)
    assert isinstance(window.pages["bom-build"], BomBuildPage)
    assert isinstance(window.pages["bom-compare"], BomComparePage)
    assert isinstance(window.pages["inventory"], InventoryPage)
    assert isinstance(window.pages["diagnostics"], DiagnosticsPage)
    assert isinstance(window.pages["part-lookup"], PartLookupPage)
    assert isinstance(window.pages["raw-processing"], RawProcessingPage)
    assert isinstance(window.pages["packing-slip"], PackingSlipPage)
    assert isinstance(window.pages["sales-bom-import"], SalesBomImportPage)
    assert window.nav_buttons["overview"].isChecked()
    window.close()


def test_shell_navigates_to_asset_import() -> None:
    _application()
    window = AtlasPilotWindow()

    window.show_page("asset-import")

    assert window.page_stack.currentWidget() is window.pages["asset-import"]
    assert window.nav_buttons["asset-import"].isChecked()
    assert not window.nav_buttons["overview"].isChecked()
    window.close()


def test_shell_navigates_to_inventory() -> None:
    _application()
    window = AtlasPilotWindow()
    window.show_page("inventory")
    assert window.page_stack.currentWidget() is window.pages["inventory"]
    assert window.nav_buttons["inventory"].isChecked()
    assert window.pages["inventory"].mode_combo.currentText() == "Network"
    assert not window.pages["inventory"].ranges_box.isHidden()
    window.close()


def test_shell_navigates_to_diagnostics() -> None:
    _application()
    window = AtlasPilotWindow()
    window.show_page("diagnostics")
    assert window.page_stack.currentWidget() is window.pages["diagnostics"]
    assert window.nav_buttons["diagnostics"].isChecked()
    window.close()


def test_inventory_pod_selector_updates_visible_ip_prefix() -> None:
    _application()
    page = InventoryPage()
    _card, pod, start_third, _start_host, end_third, _end_host = page.range_controls[0]
    pod.setCurrentText("Pod 2")
    labels = {label.text() for label in page.findChildren(QLabel)}
    assert "Start IP: 172.21.102." in labels
    assert "End IP: 172.21.102." in labels
    assert start_third.isHidden()
    assert end_third.isHidden()

    pod.setCurrentText("Lab")
    labels = {label.text() for label in page.findChildren(QLabel)}
    assert "Start IP: 10.9." in labels
    assert "End IP: 10.9." in labels
    assert not start_third.isHidden()
    assert not end_third.isHidden()
    page.close()


def test_inventory_network_mode_hides_irrelevant_direct_fields() -> None:
    _application()
    page = InventoryPage()
    assert page.mode_combo.minimumHeight() == 30
    assert page.range_controls[0][1].minimumHeight() == 30
    assert not page.connection_form.isRowVisible(page.script_combo)
    assert not page.connection_form.isRowVisible(page.target_edit)
    assert not page.connection_form.isRowVisible(page.baud_combo)

    page.mode_combo.setCurrentText("LAN")
    assert page.connection_form.isRowVisible(page.script_combo)
    assert page.connection_form.isRowVisible(page.target_edit)
    assert not page.connection_form.isRowVisible(page.baud_combo)
    page.close()


def test_inventory_new_report_clears_previous_append_target() -> None:
    _application()
    page = InventoryPage()
    page._append_mode = True
    page.output_edit.setText("existing.xlsx")
    page.report_mode_label.setText("Append to existing.xlsx")
    page._new_report()
    assert not page._append_mode
    assert not page.output_edit.text()
    assert page.report_mode_label.text() == "New report"
    page.close()


def test_inventory_run_prompts_for_missing_new_report_destination() -> None:
    _application()
    page = InventoryPage()
    page.customer_edit.setText("RPA")
    page.project_edit.setText("Task Order 3")
    with patch.object(QFileDialog, "getSaveFileName", return_value=("C:/tmp/inventory.xlsx", "")):
        assert page._choose_output()
    assert page.output_edit.text() == "C:/tmp/inventory.xlsx"
    assert not page._append_mode
    page.close()


def test_inventory_runtime_popup_includes_actual_error_and_action() -> None:
    _application()
    page = InventoryPage()
    with patch.object(QMessageBox, "critical") as critical:
        page._on_failure("No reachable devices were found")
    popup_text = critical.call_args.args[2]
    assert "Error: No reachable devices were found" in popup_text
    assert "What to do:" in popup_text
    page.close()


def test_inventory_empty_worker_error_still_has_a_reason() -> None:
    _application()
    page = InventoryPage()
    with patch.object(QMessageBox, "critical") as critical:
        page._on_failure("")
    assert "without an error description" in critical.call_args.args[2]
    page.close()


def test_shell_navigates_to_bom_build() -> None:
    _application()
    window = AtlasPilotWindow()
    window.show_page("bom-build")
    assert window.page_stack.currentWidget() is window.pages["bom-build"]
    assert window.nav_buttons["bom-build"].isChecked()
    window.close()


def test_shell_navigates_to_bom_compare() -> None:
    _application()
    window = AtlasPilotWindow()
    window.show_page("bom-compare")
    assert window.page_stack.currentWidget() is window.pages["bom-compare"]
    assert window.nav_buttons["bom-compare"].isChecked()
    window.close()


def test_shell_navigates_to_part_lookup() -> None:
    _application()
    window = AtlasPilotWindow()
    window.show_page("part-lookup")
    assert window.page_stack.currentWidget() is window.pages["part-lookup"]
    assert window.nav_buttons["part-lookup"].isChecked()
    window.close()


def test_shell_navigates_to_raw_processing() -> None:
    _application()
    window = AtlasPilotWindow()
    window.show_page("raw-processing")
    assert window.page_stack.currentWidget() is window.pages["raw-processing"]
    assert window.nav_buttons["raw-processing"].isChecked()
    window.close()


def test_shell_navigates_to_sales_bom_import() -> None:
    _application()
    window = AtlasPilotWindow()
    window.show_page("sales-bom-import")
    assert window.page_stack.currentWidget() is window.pages["sales-bom-import"]
    assert window.nav_buttons["sales-bom-import"].isChecked()
    window.close()


def test_shell_navigates_to_packing_slips() -> None:
    _application()
    window = AtlasPilotWindow()
    window.show_page("packing-slip")
    assert window.page_stack.currentWidget() is window.pages["packing-slip"]
    assert window.nav_buttons["packing-slip"].isChecked()
    window.close()


def test_asset_import_page_starts_ready() -> None:
    _application()
    page = AssetImportPage()

    assert page.run_button.isEnabled()
    assert page.status_label.text() == "Ready"
    assert not page.inventory_edit.text()
    assert not page.asset_edit.text()
    page.close()
