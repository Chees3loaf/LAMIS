"""PySide6 direct-connection inventory workflow."""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QVBoxLayout, QWidget

from services.inventory_direct_service import DirectInventoryRequest, InventoryRunControl, LAN_SCRIPTS, SERIAL_SCRIPTS, run_direct_inventory
from utils.workbook_metadata import extract_workbook_metadata


class InventoryWorker(QObject):
    progress = Signal(str)
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, request: DirectInventoryRequest, control: InventoryRunControl) -> None:
        super().__init__()
        self.request, self.control = request, control

    @Slot()
    def run(self) -> None:
        try:
            result = run_direct_inventory(self.request, progress=self.progress.emit, control=self.control)
        except Exception as exc:
            logging.exception("Qt direct inventory failed")
            self.failed.emit(str(exc))
        else:
            self.succeeded.emit(result)
        finally:
            self.finished.emit()


class InventoryPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: InventoryWorker | None = None
        self._control: InventoryRunControl | None = None
        self._append_mode = False

        heading = QLabel("Inventory — Direct Connection")
        heading.setObjectName("pageHeading")
        intro = QLabel(
            "Collect live inventory from one LAN or serial-connected device. "
            "Concurrent Pod/Lab network scanning is the next migration stage."
        )
        intro.setObjectName("pageIntro")
        intro.setWordWrap(True)

        connection = QGroupBox("Connection")
        connection_form = QFormLayout(connection)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["LAN", "Serial"])
        self.mode_combo.currentTextChanged.connect(self._mode_changed)
        self.script_combo = QComboBox()
        self.target_edit = QLineEdit()
        self.baud_combo = QComboBox()
        self.baud_combo.addItems(["9600", "19200", "38400", "57600", "115200"])
        connection_form.addRow("Connection type", self.mode_combo)
        connection_form.addRow("Device family", self.script_combo)
        connection_form.addRow("IP address / serial port", self.target_edit)
        connection_form.addRow("Baud rate", self.baud_combo)

        report = QGroupBox("Report")
        report_form = QFormLayout(report)
        self.output_edit = QLineEdit()
        output_row = QWidget()
        output_layout = QHBoxLayout(output_row)
        output_layout.setContentsMargins(0, 0, 0, 0)
        save = QPushButton("Save as…")
        save.clicked.connect(self._browse_output)
        append = QPushButton("Append existing…")
        append.clicked.connect(self._browse_append)
        clear = QPushButton("New report")
        clear.clicked.connect(self._clear_append)
        output_layout.addWidget(self.output_edit, 1)
        output_layout.addWidget(save)
        output_layout.addWidget(append)
        output_layout.addWidget(clear)
        report_form.addRow("Output", output_row)
        self.report_mode_label = QLabel("New report")
        self.report_mode_label.setObjectName("mutedText")
        report_form.addRow("Mode", self.report_mode_label)

        details = QGroupBox("Report details")
        details_form = QFormLayout(details)
        self.customer_edit = QLineEdit()
        self.project_edit = QLineEdit()
        self.po_edit = QLineEdit()
        self.so_edit = QLineEdit()
        details_form.addRow("Customer", self.customer_edit)
        details_form.addRow("Project", self.project_edit)
        details_form.addRow("Purchase order", self.po_edit)
        details_form.addRow("Sales order", self.so_edit)

        controls = QHBoxLayout()
        self.run_button = QPushButton("Run Inventory")
        self.run_button.clicked.connect(self._start)
        self.pause_button = QPushButton("Pause")
        self.pause_button.setEnabled(False)
        self.pause_button.clicked.connect(self._toggle_pause)
        self.abort_button = QPushButton("Abort")
        self.abort_button.setEnabled(False)
        self.abort_button.clicked.connect(self._abort)
        self.status_label = QLabel("Ready")
        controls.addWidget(self.run_button)
        controls.addWidget(self.pause_button)
        controls.addWidget(self.abort_button)
        controls.addWidget(self.status_label, 1)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(intro)
        layout.addWidget(connection)
        layout.addWidget(report)
        layout.addWidget(details)
        layout.addLayout(controls)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.log, 1)
        self._mode_changed("LAN")

    @Slot(str)
    def _mode_changed(self, mode: str) -> None:
        options = LAN_SCRIPTS if mode == "LAN" else SERIAL_SCRIPTS
        self.script_combo.clear()
        self.script_combo.addItems(options)
        self.baud_combo.setEnabled(mode == "Serial")
        self.target_edit.setPlaceholderText("Example: 10.0.0.1" if mode == "LAN" else "Example: COM3")

    @Slot()
    def _browse_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save inventory report", self.output_edit.text(), "Excel workbooks (*.xlsx)")
        if path:
            self.output_edit.setText(path if path.lower().endswith(".xlsx") else path + ".xlsx")
            self._clear_append()

    @Slot()
    def _browse_append(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select existing inventory report", "", "Excel workbooks (*.xlsx)")
        if not path:
            return
        self.output_edit.setText(path)
        self._append_mode = True
        self.report_mode_label.setText(f"Append to {Path(path).name}")
        try:
            metadata = extract_workbook_metadata(path)
        except Exception as exc:
            logging.warning("Inventory metadata extraction failed: %s", exc)
            return
        self.customer_edit.setText(metadata.get("customer", ""))
        self.project_edit.setText(metadata.get("project", ""))
        self.po_edit.setText(metadata.get("po", ""))
        self.so_edit.setText(metadata.get("so", ""))

    @Slot()
    def _clear_append(self) -> None:
        self._append_mode = False
        self.report_mode_label.setText("New report")

    @Slot()
    def _start(self) -> None:
        try:
            request = DirectInventoryRequest(
                mode=self.mode_combo.currentText(), script_name=self.script_combo.currentText(),
                target=self.target_edit.text().strip(), output_path=Path(self.output_edit.text().strip()),
                customer=self.customer_edit.text(), project=self.project_edit.text(),
                purchase_order=self.po_edit.text(), sales_order=self.so_edit.text(),
                baud_rate=int(self.baud_combo.currentText()), append_mode=self._append_mode,
            )
        except Exception as exc:
            QMessageBox.warning(self, "Inventory", str(exc))
            return
        control = InventoryRunControl()
        thread = QThread(self)
        worker = InventoryWorker(request, control)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self.log.appendPlainText)
        worker.succeeded.connect(self._on_success)
        worker.failed.connect(self._on_failure)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._on_finished)
        self.log.clear()
        self.run_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.abort_button.setEnabled(True)
        self.status_label.setText("Running…")
        self.progress_bar.setRange(0, 0)
        self._thread, self._worker, self._control = thread, worker, control
        thread.start()

    @Slot()
    def _toggle_pause(self) -> None:
        if self._control is None:
            return
        if self._control.paused.is_set():
            self._control.paused.clear()
            self.pause_button.setText("Pause")
            self.status_label.setText("Running…")
        else:
            self._control.paused.set()
            self.pause_button.setText("Resume")
            self.status_label.setText("Paused")

    @Slot()
    def _abort(self) -> None:
        if self._control is not None:
            self.status_label.setText("Aborting…")
            self._control.cancel()

    @Slot(object)
    def _on_success(self, outcome) -> None:
        self.status_label.setText(f"Done — {outcome.output_path.name}")
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)

    @Slot(str)
    def _on_failure(self, message: str) -> None:
        self.log.appendPlainText(f"ERROR: {message}")
        self.status_label.setText("Aborted" if "aborted" in message.lower() else "Failed")
        if "aborted" not in message.lower():
            QMessageBox.critical(self, "Inventory failed", message)

    @Slot()
    def _on_finished(self) -> None:
        self.run_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.pause_button.setText("Pause")
        self.abort_button.setEnabled(False)
        if self.progress_bar.maximum() == 0:
            self.progress_bar.setRange(0, 1)
        self._thread = self._worker = self._control = None
