"""Smoke tests for the opt-in PySide6 Asset Import page."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gui_qt.asset_import_page import AssetImportPage
from gui_qt.bom_build_page import BomBuildPage
from gui_qt.bom_compare_page import BomComparePage
from gui_qt.inventory_page import InventoryPage
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

    assert window.windowTitle() == "ATLAS — PySide6 Proof of Concept"
    assert window.page_stack.currentWidget() is window.pages["overview"]
    assert isinstance(window.pages["asset-import"], AssetImportPage)
    assert isinstance(window.pages["bom-build"], BomBuildPage)
    assert isinstance(window.pages["bom-compare"], BomComparePage)
    assert isinstance(window.pages["inventory"], InventoryPage)
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
