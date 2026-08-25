"""Tests for the native PySide6 Part Lookup page."""
from __future__ import annotations

import os
import sqlite3

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gui_qt.part_lookup_page import PartLookupPage


def _application() -> QApplication:
    return QApplication.instance() or QApplication([])


def _parts_db(path) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE parts (part_number TEXT NOT NULL, description TEXT NOT NULL)"
    )
    connection.executemany(
        "INSERT INTO parts VALUES (?, ?)",
        [
            ("XCVR-A10Y31", "10 KM SFP optic"),
            ("XCVR-A10Y32", "40 KM SFP optic"),
        ],
    )
    connection.commit()
    connection.close()


def test_exact_lookup_and_vendor_prefix(tmp_path) -> None:
    _application()
    database = tmp_path / "parts.db"
    _parts_db(database)
    page = PartLookupPage(db_path=database)
    page.query_edit.setText("1Pxcvr-a10y31")

    page.search()

    assert page.result_label.text() == "10 KM SFP optic"
    assert page.copy_button.isEnabled()
    page.close()


def test_partial_lookup_populates_suggestions(tmp_path) -> None:
    _application()
    database = tmp_path / "parts.db"
    _parts_db(database)
    page = PartLookupPage(db_path=database)
    page.query_edit.setText("XCVR-A10")

    page.search()

    assert page.suggestions.rowCount() == 2
    assert page.suggestions.item(0, 0).text() == "XCVR-A10Y31"
    page.close()
