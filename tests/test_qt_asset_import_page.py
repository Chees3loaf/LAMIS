"""Smoke tests for the opt-in PySide6 Asset Import page."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gui_qt.asset_import_page import AssetImportPage
from gui_qt.bom_build_page import BomBuildPage
from gui_qt.part_lookup_page import PartLookupPage
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
    assert isinstance(window.pages["part-lookup"], PartLookupPage)
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


def test_shell_navigates_to_bom_build() -> None:
    _application()
    window = AtlasPilotWindow()
    window.show_page("bom-build")
    assert window.page_stack.currentWidget() is window.pages["bom-build"]
    assert window.nav_buttons["bom-build"].isChecked()
    window.close()


def test_shell_navigates_to_part_lookup() -> None:
    _application()
    window = AtlasPilotWindow()
    window.show_page("part-lookup")
    assert window.page_stack.currentWidget() is window.pages["part-lookup"]
    assert window.nav_buttons["part-lookup"].isChecked()
    window.close()


def test_asset_import_page_starts_ready() -> None:
    _application()
    page = AssetImportPage()

    assert page.run_button.isEnabled()
    assert page.status_label.text() == "Ready"
    assert not page.inventory_edit.text()
    assert not page.asset_edit.text()
    page.close()
