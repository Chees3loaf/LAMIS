"""PySide6 page for converting Sales BOM sheets into per-site workbooks."""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QAbstractItemView, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from gui_qt.dialogs import show_problem
from services.sales_bom_import_service import SalesBomSource, inspect_sales_bom, run_sales_bom_import


class SalesBomImportWorker(QObject):
    progress = Signal(str)
    succeeded = Signal(str)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, source: SalesBomSource, sheets: list[str], output: str, customer: str, project: str) -> None:
        super().__init__()
        self.source, self.sheets, self.output = source, sheets, output
        self.customer, self.project = customer, project

    @Slot()
    def run(self) -> None:
        try:
            result = run_sales_bom_import(
                self.source, self.sheets, self.output,
                customer=self.customer, project=self.project,
                progress=self.progress.emit,
            )
        except Exception as exc:
            logging.exception("Qt Sales BOM Import failed")
            self.failed.emit(str(exc))
        else:
            self.succeeded.emit(str(result))
        finally:
            self.finished.emit()


class SalesBomImportPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._source: SalesBomSource | None = None
        self._thread: QThread | None = None
        self._worker: SalesBomImportWorker | None = None

        heading = QLabel("Sales BOM Import")
        heading.setObjectName("pageHeading")
        intro = QLabel(
            "Convert one or more Sales BOM worksheets into a combined workbook "
            "with Summary, Inventory by Site, and per-site packing tabs."
        )
        intro.setObjectName("pageIntro")
        intro.setWordWrap(True)

        files = QGroupBox("Input and output")
        file_form = QFormLayout(files)
        self.source_edit = QLineEdit()
        self.source_edit.setReadOnly(True)
        self.output_edit = QLineEdit()
        file_form.addRow("Sales BOM", self._path_row(self.source_edit, "Browse…", self._browse_source))
        file_form.addRow("Output", self._path_row(self.output_edit, "Save as…", self._browse_output))

        selection = QGroupBox("Worksheets")
        selection_layout = QVBoxLayout(selection)
        hint = QLabel("Select one or more sheets. Ctrl-click or Shift-click to select multiple.")
        hint.setObjectName("mutedText")
        self.sheet_list = QListWidget()
        self.sheet_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        selection_layout.addWidget(hint)
        selection_layout.addWidget(self.sheet_list)

        metadata = QGroupBox("Workbook details")
        metadata_form = QFormLayout(metadata)
        self.customer_edit = QLineEdit()
        self.project_edit = QLineEdit()
        metadata_form.addRow("Customer", self.customer_edit)
        metadata_form.addRow("Project", self.project_edit)

        controls = QHBoxLayout()
        self.run_button = QPushButton("Build Sales BOM Workbook")
        self.run_button.clicked.connect(self._start)
        self.status_label = QLabel("Ready")
        controls.addWidget(self.run_button)
        controls.addWidget(self.status_label, 1)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(intro)
        layout.addWidget(files)
        layout.addWidget(selection, 1)
        layout.addWidget(metadata)
        layout.addLayout(controls)
        layout.addWidget(self.log, 1)

    @staticmethod
    def _path_row(edit: QLineEdit, label: str, callback) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        button = QPushButton(label)
        button.clicked.connect(callback)
        layout.addWidget(edit, 1)
        layout.addWidget(button)
        return row

    @Slot()
    def _browse_source(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Sales BOM", "", "Excel workbooks (*.xlsx)")
        if not path:
            return
        try:
            source = inspect_sales_bom(path)
        except Exception as exc:
            show_problem(self, "Sales BOM Import", exc, "Select a readable Sales BOM workbook, then retry.", critical=True)
            return
        self._source = source
        self.source_edit.setText(str(source.path))
        self.sheet_list.clear()
        self.sheet_list.addItems(source.sheet_names)
        if self.sheet_list.count():
            self.sheet_list.item(0).setSelected(True)
        if not self.output_edit.text().strip():
            self.output_edit.setText(str(source.path.with_name(f"{source.path.stem}_Site_Packing.xlsx")))
        self.status_label.setText(f"Loaded {len(source.sheet_names)} worksheet(s)")

    @Slot()
    def _browse_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save Sales BOM workbook", self.output_edit.text(), "Excel workbooks (*.xlsx)")
        if path:
            self.output_edit.setText(path if path.lower().endswith(".xlsx") else path + ".xlsx")

    @Slot()
    def _start(self) -> None:
        selected = [item.text() for item in self.sheet_list.selectedItems()]
        output = self.output_edit.text().strip()
        if self._source is None:
            show_problem(self, "Sales BOM Import", "No Sales BOM workbook has been loaded.", "Select and load a Sales BOM workbook, then retry.")
            return
        if not selected:
            show_problem(self, "Sales BOM Import", "No worksheet is selected.", "Select at least one worksheet to import, then retry.")
            return
        if not output or Path(output).suffix.lower() != ".xlsx":
            show_problem(self, "Sales BOM Import", "The output path is not an .xlsx workbook.", "Choose an .xlsx output workbook, then retry.")
            return

        self.log.clear()
        self.run_button.setEnabled(False)
        self.status_label.setText("Building…")
        thread = QThread(self)
        worker = SalesBomImportWorker(
            self._source, selected, output,
            self.customer_edit.text(), self.project_edit.text(),
        )
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self.log.appendPlainText)
        worker.succeeded.connect(self._on_success)
        worker.failed.connect(self._on_failure)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._on_finished)
        self._thread, self._worker = thread, worker
        thread.start()

    @Slot(str)
    def _on_success(self, output: str) -> None:
        self.status_label.setText(f"Done — {Path(output).name}")

    @Slot(str)
    def _on_failure(self, message: str) -> None:
        self.log.appendPlainText(f"ERROR: {message}")
        self.status_label.setText("Failed")
        show_problem(self, "Sales BOM Import failed", message, "Review the log, correct the reported workbook issue, and run the import again.", critical=True)

    @Slot()
    def _on_finished(self) -> None:
        self.run_button.setEnabled(True)
        self._thread = None
        self._worker = None
