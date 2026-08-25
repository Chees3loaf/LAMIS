"""Native PySide6 part-number lookup page."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Slot
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.part_lookup_dialog import lookup_part
from utils.helpers import get_database_path


class PartLookupPage(QWidget):
    def __init__(
        self, parent: QWidget | None = None, *, db_path: str | Path | None = None
    ) -> None:
        super().__init__(parent)
        self.db_path = Path(db_path) if db_path is not None else get_database_path()

        heading = QLabel("Part Lookup")
        heading.setObjectName("pageHeading")
        intro = QLabel(
            "Search the ATLAS parts database by complete or partial part number. "
            "Vendor prefixes such as 1P and P are handled automatically."
        )
        intro.setObjectName("pageIntro")
        intro.setWordWrap(True)

        search_box = QGroupBox("Part number")
        search_layout = QHBoxLayout(search_box)
        self.query_edit = QLineEdit()
        self.query_edit.setPlaceholderText("Example: 3HE048 or 1PXCVR-A10Y31")
        self.query_edit.returnPressed.connect(self.search)
        search_button = QPushButton("Search")
        search_button.clicked.connect(self.search)
        search_layout.addWidget(self.query_edit, 1)
        search_layout.addWidget(search_button)

        result_box = QGroupBox("Exact match")
        result_layout = QHBoxLayout(result_box)
        self.result_label = QLabel("Enter a part number to begin.")
        self.result_label.setWordWrap(True)
        self.copy_button = QPushButton("Copy description")
        self.copy_button.setEnabled(False)
        self.copy_button.clicked.connect(self.copy_description)
        result_layout.addWidget(self.result_label, 1)
        result_layout.addWidget(self.copy_button)

        suggestions_box = QGroupBox("Other prefix matches")
        suggestions_layout = QVBoxLayout(suggestions_box)
        self.suggestions = QTableWidget(0, 2)
        self.suggestions.setHorizontalHeaderLabels(["Part number", "Description"])
        self.suggestions.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.suggestions.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.suggestions.verticalHeader().setVisible(False)
        self.suggestions.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.suggestions.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.suggestions.cellDoubleClicked.connect(self._select_suggestion)
        suggestions_layout.addWidget(self.suggestions)

        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(intro)
        layout.addWidget(search_box)
        layout.addWidget(result_box)
        layout.addWidget(suggestions_box, 1)

    @Slot()
    def search(self) -> None:
        query = self.query_edit.text().strip()
        self.suggestions.setRowCount(0)
        self.copy_button.setEnabled(False)
        if not query:
            self.result_label.setText("Enter a part number to begin.")
            return
        if not self.db_path.is_file():
            self.result_label.setText("Parts database is unavailable.")
            return
        try:
            exact, suggestions = lookup_part(str(self.db_path), query)
        except Exception as exc:
            self.result_label.setText(f"Lookup failed: {exc}")
            return

        if exact:
            self.result_label.setText(exact)
            self.copy_button.setEnabled(True)
        else:
            self.result_label.setText(f"No exact match for {query!r}.")

        self.suggestions.setRowCount(len(suggestions))
        for row, (part_number, description) in enumerate(suggestions):
            self.suggestions.setItem(row, 0, QTableWidgetItem(part_number))
            self.suggestions.setItem(row, 1, QTableWidgetItem(description))

    @Slot()
    def copy_description(self) -> None:
        if self.copy_button.isEnabled():
            QApplication.clipboard().setText(self.result_label.text())

    @Slot(int, int)
    def _select_suggestion(self, row: int, _column: int) -> None:
        item = self.suggestions.item(row, 0)
        if item is None:
            return
        self.query_edit.setText(item.text())
        self.search()
