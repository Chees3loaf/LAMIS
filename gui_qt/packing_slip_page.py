"""PySide6 Packing Slip Generator page."""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from services.packing_slip_service import PackingSlipRequest, PackingSlipSource, inspect_packing_slip_source, run_packing_slip_generation


class PackingSlipWorker(QObject):
    progress = Signal(str)
    succeeded = Signal(str)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, request: PackingSlipRequest) -> None:
        super().__init__()
        self.request = request

    @Slot()
    def run(self) -> None:
        try:
            output = run_packing_slip_generation(self.request, progress=self.progress.emit)
        except Exception as exc:
            logging.exception("Qt Packing Slip generation failed")
            self.failed.emit(str(exc))
        else:
            self.succeeded.emit(str(output))
        finally:
            self.finished.emit()


class PackingSlipPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.source: PackingSlipSource | None = None
        self._thread: QThread | None = None
        self._worker: PackingSlipWorker | None = None
        heading = QLabel("Packing Slip Generator")
        heading.setObjectName("pageHeading")
        intro = QLabel("Generate a multi-device packing-slip workbook from an inventory workbook, existing packing slip, or CSV export.")
        intro.setObjectName("pageIntro")
        intro.setWordWrap(True)

        files = QGroupBox("Source and destination")
        file_form = QFormLayout(files)
        self.source_edit = QLineEdit()
        self.source_edit.setReadOnly(True)
        self.output_edit = QLineEdit()
        file_form.addRow("Source", self._path_row(self.source_edit, self._browse_source, "Browse…"))
        file_form.addRow("Output folder", self._path_row(self.output_edit, self._browse_output, "Browse…"))

        metadata = QGroupBox("Project information")
        metadata_form = QFormLayout(metadata)
        self.customer_edit = QLineEdit()
        self.project_edit = QLineEdit()
        self.po_edit = QLineEdit()
        self.so_edit = QLineEdit()
        metadata_form.addRow("Customer", self.customer_edit)
        metadata_form.addRow("Project", self.project_edit)
        metadata_form.addRow("Purchase order", self.po_edit)
        metadata_form.addRow("Sales order", self.so_edit)

        controls = QHBoxLayout()
        self.run_button = QPushButton("Generate Packing Slips")
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
        layout.addWidget(metadata)
        layout.addLayout(controls)
        layout.addWidget(self.log, 1)

    def _path_row(self, edit, callback, text):
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        button = QPushButton(text)
        button.clicked.connect(callback)
        layout.addWidget(edit, 1)
        layout.addWidget(button)
        return row

    @Slot()
    def _browse_source(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select inventory source", "", "Supported files (*.xlsx *.xls *.csv)")
        if not path:
            return
        try:
            self.source = inspect_packing_slip_source(path)
        except Exception as exc:
            QMessageBox.critical(self, "Packing Slip", str(exc))
            return
        self.source_edit.setText(path)
        self.customer_edit.setText(self.source.customer)
        self.project_edit.setText(self.source.project)
        self.po_edit.setText(self.source.purchase_order)
        self.so_edit.setText(self.source.sales_order)
        if not self.output_edit.text():
            self.output_edit.setText(str(Path(path).parent))
        self.status_label.setText(f"Loaded — {self.source.device_count} device(s)")

    @Slot()
    def _browse_output(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select output folder", self.output_edit.text())
        if path:
            self.output_edit.setText(path)

    @Slot()
    def _start(self) -> None:
        if self.source is None:
            QMessageBox.warning(self, "Packing Slip", "Select a source file first.")
            return
        output_text = self.output_edit.text().strip()
        if not output_text:
            QMessageBox.warning(self, "Packing Slip", "Select an output folder.")
            return
        request = PackingSlipRequest(
            source=self.source,
            output_directory=Path(output_text),
            customer=self.customer_edit.text(),
            project=self.project_edit.text(),
            purchase_order=self.po_edit.text(),
            sales_order=self.so_edit.text(),
        )
        self.log.clear()
        self.run_button.setEnabled(False)
        self.status_label.setText("Generating…")
        thread = QThread(self)
        worker = PackingSlipWorker(request)
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
        QMessageBox.critical(self, "Packing Slip generation failed", message)

    @Slot()
    def _on_finished(self) -> None:
        self.run_button.setEnabled(True)
        self._thread = None
        self._worker = None
