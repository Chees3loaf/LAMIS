"""PySide6 page for comparing live inventory and sales BOM workbooks."""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from gui_qt.dialogs import show_problem
from services.bom_compare_service import default_compare_output, run_bom_compare


class BomCompareWorker(QObject):
    progress = Signal(str)
    succeeded = Signal(str)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, factory: str, sales: str, output: str) -> None:
        super().__init__()
        self.factory = factory
        self.sales = sales
        self.output = output

    @Slot()
    def run(self) -> None:
        try:
            result = run_bom_compare(
                self.factory, self.sales, output_path=self.output,
                progress=self.progress.emit,
            )
        except Exception as exc:
            logging.exception("Qt BOM Compare failed")
            self.failed.emit(str(exc))
        else:
            self.succeeded.emit(str(result))
        finally:
            self.finished.emit()


class BomComparePage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: BomCompareWorker | None = None

        heading = QLabel("Compare BOMs")
        heading.setObjectName("pageHeading")
        intro = QLabel(
            "Compare current live inventory against a Sales BOM. The output includes "
            "shortfall, site allocation, trace, and source-reference tabs."
        )
        intro.setObjectName("pageIntro")
        intro.setWordWrap(True)

        files = QGroupBox("Workbooks")
        form = QFormLayout(files)
        self.factory_edit = QLineEdit()
        self.sales_edit = QLineEdit()
        self.output_edit = QLineEdit()
        form.addRow("Live inventory", self._path_row(self.factory_edit, self._browse_factory))
        form.addRow("Sales BOM", self._path_row(self.sales_edit, self._browse_sales))
        form.addRow("Comparison output", self._path_row(self.output_edit, self._browse_output))

        controls = QHBoxLayout()
        self.run_button = QPushButton("Compare BOMs")
        self.run_button.clicked.connect(self._start)
        self.status_label = QLabel("Ready")
        controls.addWidget(self.run_button)
        controls.addWidget(self.status_label, 1)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setPlaceholderText("Comparison activity will appear here.")

        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(intro)
        layout.addWidget(files)
        layout.addLayout(controls)
        layout.addWidget(self.log, 1)

    @staticmethod
    def _path_row(edit: QLineEdit, callback) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        browse = QPushButton("Browse…")
        browse.clicked.connect(callback)
        layout.addWidget(edit, 1)
        layout.addWidget(browse)
        return row

    @Slot()
    def _browse_factory(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select live inventory", "", "Excel workbooks (*.xlsx)")
        if path:
            self.factory_edit.setText(path)
            if not self.output_edit.text().strip():
                self.output_edit.setText(str(default_compare_output(path)))

    @Slot()
    def _browse_sales(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Sales BOM", "", "Excel workbooks (*.xlsx)")
        if path:
            self.sales_edit.setText(path)

    @Slot()
    def _browse_output(self) -> None:
        suggested = self.output_edit.text().strip() or self.factory_edit.text().strip()
        path, _ = QFileDialog.getSaveFileName(self, "Save comparison workbook", suggested, "Excel workbooks (*.xlsx)")
        if path:
            self.output_edit.setText(path)

    @Slot()
    def _start(self) -> None:
        factory = self.factory_edit.text().strip()
        sales = self.sales_edit.text().strip()
        output = self.output_edit.text().strip()
        if not factory or not Path(factory).is_file() or not sales or not Path(sales).is_file():
            show_problem(self, "BOM Compare", "Valid live-inventory and Sales BOM .xlsx files were not selected.", "Browse to both existing workbooks, then retry.")
            return
        if not output:
            output = str(default_compare_output(factory))
            self.output_edit.setText(output)
        if Path(output).suffix.lower() != ".xlsx":
            show_problem(self, "BOM Compare", "The output path is not an .xlsx workbook.", "Choose an .xlsx output workbook, then retry.")
            return

        self.log.clear()
        self.run_button.setEnabled(False)
        self.status_label.setText("Comparing…")
        thread = QThread(self)
        worker = BomCompareWorker(factory, sales, output)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self.log.appendPlainText)
        worker.succeeded.connect(self._on_success)
        worker.failed.connect(self._on_failure)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._on_finished)
        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(str)
    def _on_success(self, output_path: str) -> None:
        self.log.appendPlainText(f"Wrote: {output_path}")
        self.status_label.setText(f"Done — {Path(output_path).name}")

    @Slot(str)
    def _on_failure(self, message: str) -> None:
        self.log.appendPlainText(f"ERROR: {message}")
        self.status_label.setText("Failed")
        show_problem(self, "BOM Compare failed", message, "Review the log, correct the reported workbook issue, and run the comparison again.", critical=True)

    @Slot()
    def _on_finished(self) -> None:
        self.run_button.setEnabled(True)
        self._thread = None
        self._worker = None
