"""Smoke tests for the opt-in PySide6 Asset Import page."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gui_qt.asset_import_page import AssetImportPage
from gui_qt.main_window import AtlasPilotWindow


def _application() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_pilot_window_constructs() -> None:
    _application()
    window = AtlasPilotWindow()

    assert window.windowTitle() == "ATLAS — PySide6 Proof of Concept"
    assert isinstance(window.centralWidget(), AssetImportPage)
    window.close()


def test_asset_import_page_starts_ready() -> None:
    _application()
    page = AssetImportPage()

    assert page.run_button.isEnabled()
    assert page.status_label.text() == "Ready"
    assert not page.inventory_edit.text()
    assert not page.asset_edit.text()
    page.close()
