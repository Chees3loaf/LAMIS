"""PySide6 Asset Import proof-of-concept page."""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from services.asset_import_service import AssetImportOutcome, run_asset_import


class AssetImportWorker(QObject):
    progress = Signal(str)
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, inventory_path: str, asset_path: str) -> None:
        super().__init__()
        self.inventory_path = inventory_path
        self.asset_path = asset_path

    @Slot()
    def run(self) -> None:
        try:
            outcome = run_asset_import(
                self.inventory_path,
                self.asset_path,
                progress=self.progress.emit,
            )
        except Exception as exc:
            logging.exception("Qt Asset Import failed")
            self.failed.emit(str(exc))
        else:
            self.succeeded.emit(outcome)
        finally:
            self.finished.emit()


class AssetImportPage(QWidget):
    """Select two workbooks and run the Asset Import service."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: AssetImportWorker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        heading = QLabel("Asset Import")
        heading.setObjectName("pageHeading")
        description = QLabel(
            "Match an ASN asset document to an ATLAS inventory workbook. "
            "The inventory file is backed up before any changes are saved."
        )
        description.setWordWrap(True)

        files = QGroupBox("Input files")
        form = QFormLayout(files)
        self.inventory_edit = QLineEdit()
        self.inventory_edit.setPlaceholderText("Select the inventory workbook to update")
        self.asset_edit = QLineEdit()
        self.asset_edit.setPlaceholderText("Select the ASN asset document")
        form.addRow("Inventory workbook", self._file_row(self.inventory_edit, self._browse_inventory))
        form.addRow("Asset document", self._file_row(self.asset_edit, self._browse_asset))

        controls = QHBoxLayout()
        self.run_button = QPushButton("Apply Asset Tags")
        self.run_button.clicked.connect(self._start)
        self.status_label = QLabel("Ready")
        controls.addWidget(self.run_button)
        controls.addWidget(self.status_label, 1)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setPlaceholderText("Import activity will appear here.")

        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(description)
        layout.addWidget(files)
        layout.addLayout(controls)
        layout.addWidget(self.log, 1)

    def _file_row(self, edit: QLineEdit, callback) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        button = QPushButton("Browse…")
        button.clicked.connect(callback)
        layout.addWidget(edit, 1)
        layout.addWidget(button)
        return row

    @Slot()
    def _browse_inventory(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select inventory workbook", "", "Excel workbooks (*.xlsx)"
        )
        if path:
            self.inventory_edit.setText(path)

    @Slot()
    def _browse_asset(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select asset document", "", "Excel workbooks (*.xlsx)"
        )
        if path:
            self.asset_edit.setText(path)

    @Slot()
    def _start(self) -> None:
        inventory = self.inventory_edit.text().strip()
        asset_doc = self.asset_edit.text().strip()
        if not inventory or not asset_doc:
            QMessageBox.warning(self, "Asset Import", "Select both workbooks first.")
            return
        if not Path(inventory).is_file() or not Path(asset_doc).is_file():
            QMessageBox.warning(self, "Asset Import", "One or both selected files do not exist.")
            return

        self.log.clear()
        self.run_button.setEnabled(False)
        self.status_label.setText("Running…")

        thread = QThread(self)
        worker = AssetImportWorker(inventory, asset_doc)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._append_log)
        worker.succeeded.connect(self._on_success)
        worker.failed.connect(self._on_failure)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._on_thread_finished)
        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(str)
    def _append_log(self, message: str) -> None:
        self.log.appendPlainText(message)

    @Slot(object)
    def _on_success(self, outcome: AssetImportOutcome) -> None:
        result = outcome.result
        self._append_log("")
        self._append_log(f"Tabs touched: {result.tabs_touched}")
        self._append_log(f"Rows matched: {result.rows_matched}")
        self._append_log(f"Inventory serials without a match: {result.serials_not_in_asset_doc}")
        if result.tabs_with_no_matches:
            self._append_log(
                "Tabs with no matches: " + ", ".join(result.tabs_with_no_matches)
            )
        if result.po_conflicts:
            self._append_log("PO conflicts:")
            for tab, purchase_orders in result.po_conflicts:
                self._append_log(f"  {tab}: {', '.join(purchase_orders)}")
        self.status_label.setText(
            f"Done — {result.rows_matched} row(s) updated across "
            f"{result.tabs_touched} tab(s)"
        )

    @Slot(str)
    def _on_failure(self, message: str) -> None:
        self.status_label.setText("Failed")
        self._append_log(f"ERROR: {message}")
        QMessageBox.critical(self, "Asset Import failed", message)

    @Slot()
    def _on_thread_finished(self) -> None:
        self.run_button.setEnabled(True)
        self._thread = None
        self._worker = None
