"""PySide6 page for converting captured CLI transcripts into reports."""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from services.raw_processing_core import AUTO_DETECT_NOKIA, SALES_BOM_IMPORT, SCRIPT_OPTIONS
from services.raw_processing_service import RawProcessingRequest, run_raw_processing


class RawProcessingWorker(QObject):
    progress = Signal(str)
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, request: RawProcessingRequest) -> None:
        super().__init__()
        self.request = request

    @Slot()
    def run(self) -> None:
        try:
            outcome = run_raw_processing(self.request, progress=self.progress.emit)
        except Exception as exc:
            logging.exception("Qt Raw Processing failed")
            self.failed.emit(str(exc))
        else:
            self.succeeded.emit(outcome)
        finally:
            self.finished.emit()


class RawProcessingPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: RawProcessingWorker | None = None

        heading = QLabel("Raw Processing")
        heading.setObjectName("pageHeading")
        intro = QLabel(
            "Convert manually captured CLI transcripts into an ATLAS Device Report. "
            "Text files, transcript workbooks, and folders of text files are supported."
        )
        intro.setObjectName("pageIntro")
        intro.setWordWrap(True)

        source_box = QGroupBox("Input and output")
        source_form = QFormLayout(source_box)
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("Select a transcript file or folder")
        source_form.addRow("Input", self._path_row(self.input_edit, self._browse_input, "Browse…"))
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Select the output .xlsx report")
        source_form.addRow("Output", self._path_row(self.output_edit, self._browse_output, "Save as…"))

        options_box = QGroupBox("Processing options")
        options_form = QFormLayout(options_box)
        self.script_combo = QComboBox()
        self.script_combo.addItems([name for name in SCRIPT_OPTIONS if name != SALES_BOM_IMPORT])
        self.script_combo.setCurrentText(AUTO_DETECT_NOKIA)
        self.device_id_edit = QLineEdit()
        self.device_id_edit.setPlaceholderText("Optional for a single text file")
        self.customer_edit = QLineEdit()
        self.project_edit = QLineEdit()
        self.po_edit = QLineEdit()
        self.so_edit = QLineEdit()
        options_form.addRow("Device type", self.script_combo)
        options_form.addRow("Device ID", self.device_id_edit)
        options_form.addRow("Customer", self.customer_edit)
        options_form.addRow("Project", self.project_edit)
        options_form.addRow("Purchase order", self.po_edit)
        options_form.addRow("Sales order", self.so_edit)

        controls = QHBoxLayout()
        self.run_button = QPushButton("Process Input")
        self.run_button.clicked.connect(self._start)
        self.status_label = QLabel("Ready")
        controls.addWidget(self.run_button)
        controls.addWidget(self.status_label, 1)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(intro)
        layout.addWidget(source_box)
        layout.addWidget(options_box)
        layout.addLayout(controls)
        layout.addWidget(self.log, 1)

    def _path_row(self, edit: QLineEdit, callback, label: str) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        button = QPushButton(label)
        button.clicked.connect(callback)
        layout.addWidget(edit, 1)
        layout.addWidget(button)
        return row

    @Slot()
    def _browse_input(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select raw transcript", "", "Supported files (*.txt *.xlsx *.xls);;All files (*.*)")
        if not path:
            path = QFileDialog.getExistingDirectory(self, "Select transcript folder")
        if path:
            self.input_edit.setText(path)
            if not self.output_edit.text():
                source = Path(path)
                base = source.stem if source.is_file() else source.name
                self.output_edit.setText(str(source.parent / f"{base}_Raw_Report.xlsx"))

    @Slot()
    def _browse_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save Device Report", self.output_edit.text(), "Excel workbook (*.xlsx)")
        if path:
            self.output_edit.setText(path if path.lower().endswith(".xlsx") else path + ".xlsx")

    @Slot()
    def _start(self) -> None:
        input_text = self.input_edit.text().strip()
        output_text = self.output_edit.text().strip()
        input_path = Path(input_text)
        output_path = Path(output_text)
        if not input_text or not input_path.exists():
            QMessageBox.warning(self, "Raw Processing", "Select a valid input file or folder.")
            return
        if not output_text or output_path.suffix.lower() != ".xlsx":
            QMessageBox.warning(self, "Raw Processing", "Select an .xlsx output file.")
            return
        request = RawProcessingRequest(
            input_path=input_path,
            output_path=output_path,
            script_name=self.script_combo.currentText(),
            device_id=self.device_id_edit.text().strip(),
            customer=self.customer_edit.text().strip(),
            project=self.project_edit.text().strip(),
            purchase_order=self.po_edit.text().strip(),
            sales_order=self.so_edit.text().strip(),
        )
        self.log.clear()
        self.run_button.setEnabled(False)
        self.status_label.setText("Processing…")
        thread = QThread(self)
        worker = RawProcessingWorker(request)
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

    @Slot(object)
    def _on_success(self, outcome) -> None:
        self.status_label.setText(f"Done — {outcome.devices_parsed}/{outcome.devices_found} device(s)")

    @Slot(str)
    def _on_failure(self, message: str) -> None:
        self.log.appendPlainText(f"ERROR: {message}")
        self.status_label.setText("Failed")
        QMessageBox.critical(self, "Raw Processing failed", message)

    @Slot()
    def _on_finished(self) -> None:
        self.run_button.setEnabled(True)
        self._thread = None
        self._worker = None
