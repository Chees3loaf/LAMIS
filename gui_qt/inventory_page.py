"""PySide6 direct-connection inventory workflow."""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from queue import Queue
import threading

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QVBoxLayout, QWidget, QInputDialog

import config
from services.inventory_direct_service import DirectInventoryRequest, InventoryRunControl, LAN_SCRIPTS, NetworkInventoryRequest, SERIAL_SCRIPTS, combine_network_ranges, expand_network_range, run_direct_inventory, run_network_inventory
from utils.workbook_metadata import extract_workbook_metadata
from utils.helpers import sanitize_filename_component


class InventoryWorker(QObject):
    progress = Signal(str)
    numeric_progress = Signal(int, int, str)
    credentials_requested = Signal(str)
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, request: DirectInventoryRequest | NetworkInventoryRequest, control: InventoryRunControl) -> None:
        super().__init__()
        self.request, self.control = request, control
        self._credential_queues: dict[str, Queue] = {}
        self._credential_lock = threading.Lock()

    def submit_credentials(self, ip: str, credentials: tuple[str, str] | None) -> None:
        with self._credential_lock:
            response = self._credential_queues.get(ip)
        if response is not None:
            response.put(credentials)

    def _request_credentials(self, ip: str) -> tuple[str, str] | None:
        response: Queue = Queue(maxsize=1)
        with self._credential_lock:
            self._credential_queues[ip] = response
        self.credentials_requested.emit(ip)
        try:
            while not self.control.should_stop():
                try:
                    return response.get(timeout=0.25)
                except Exception:
                    continue
            return None
        finally:
            with self._credential_lock:
                self._credential_queues.pop(ip, None)

    @Slot()
    def run(self) -> None:
        try:
            if isinstance(self.request, NetworkInventoryRequest):
                result = run_network_inventory(
                    self.request, progress=self.progress.emit,
                    numeric_progress=self.numeric_progress.emit,
                    request_credentials=self._request_credentials,
                    control=self.control,
                )
            else:
                result = run_direct_inventory(
                    self.request, progress=self.progress.emit,
                    request_credentials=self._request_credentials,
                    control=self.control,
                )
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

        heading = QLabel("Inventory")
        heading.setObjectName("pageHeading")
        intro = QLabel(
            "Collect live inventory across Pod/Lab ranges or from one directly "
            "connected LAN or serial device."
        )
        intro.setObjectName("pageIntro")
        intro.setWordWrap(True)

        connection = QGroupBox("Connection")
        connection_form = QFormLayout(connection)
        self.connection_form = connection_form
        self.mode_combo = QComboBox()
        self.mode_combo.setMinimumHeight(30)
        self.mode_combo.addItems(["Network", "LAN", "Serial"])
        self.mode_combo.currentTextChanged.connect(self._mode_changed)
        self.script_combo = QComboBox()
        self.script_combo.setMinimumHeight(30)
        self.target_edit = QLineEdit()
        self.baud_combo = QComboBox()
        self.baud_combo.setMinimumHeight(30)
        self.baud_combo.addItems(["9600", "19200", "38400", "57600", "115200"])
        connection_form.addRow("Connection type", self.mode_combo)
        connection_form.addRow("Device family", self.script_combo)
        connection_form.addRow("IP address / serial port", self.target_edit)
        connection_form.addRow("Baud rate", self.baud_combo)

        self.ranges_box = QGroupBox("Pod / Lab ranges")
        self.ranges_box.setMinimumHeight(155)
        ranges_layout = QHBoxLayout(self.ranges_box)
        self.range_controls = [self._range_row(1), self._range_row(2)]
        ranges_layout.addWidget(self.range_controls[0][0], 1)
        ranges_layout.addWidget(self.range_controls[1][0], 1)

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
        clear.clicked.connect(self._new_report)
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
        layout.addWidget(self.ranges_box)
        layout.addWidget(report)
        layout.addWidget(details)
        layout.addLayout(controls)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.log, 1)
        self._mode_changed("Network")

    def _range_row(self, number: int):
        card = QWidget()
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(4, 2, 4, 2)

        pod_box = QGroupBox(f"Pod Selection {number}")
        pod_box.setMinimumHeight(62)
        pod_layout = QHBoxLayout(pod_box)
        pod_layout.addWidget(QLabel("Pod:"))
        pod = QComboBox()
        pod.addItems([f"Pod {number}" for number in range(1, config.POD_COUNT + 1)] + [config.LAB_LABEL])
        pod.setMinimumWidth(125)
        pod.setMinimumHeight(30)
        pod_layout.addWidget(pod)
        pod_layout.addStretch(1)

        ip_box = QGroupBox(f"IP Selection {number}" + (" (Optional)" if number == 2 else ""))
        ip_box.setMinimumHeight(68)
        ip_layout = QHBoxLayout(ip_box)
        start_third, start_host, end_third, end_host = (QLineEdit() for _ in range(4))
        for edit in (start_third, start_host, end_third, end_host):
            edit.setMaximumWidth(48)
            edit.setMinimumHeight(30)
        start_host.setPlaceholderText("host")
        end_host.setPlaceholderText("host")
        start_third.setPlaceholderText("3rd")
        end_third.setPlaceholderText("3rd")
        start_prefix = QLabel()
        end_prefix = QLabel()
        start_dot = QLabel(".")
        end_dot = QLabel(".")
        ip_layout.addWidget(start_prefix)
        ip_layout.addWidget(start_third)
        ip_layout.addWidget(start_dot)
        ip_layout.addWidget(start_host)
        ip_layout.addSpacing(10)
        ip_layout.addWidget(end_prefix)
        ip_layout.addWidget(end_third)
        ip_layout.addWidget(end_dot)
        ip_layout.addWidget(end_host)
        ip_layout.addStretch(1)
        card_layout.addWidget(pod_box)
        card_layout.addWidget(ip_box)

        def update_third(selection: str) -> None:
            lab = selection == config.LAB_LABEL
            if lab:
                prefix = config.LAB_NETWORK_PREFIX
            else:
                pod_number = int(selection.removeprefix("Pod "))
                prefix = f"{config.POD_NETWORK_PREFIX}.{config.POD_THIRD_OCTET_BASE + pod_number}"
            start_prefix.setText(f"Start IP: {prefix}.")
            end_prefix.setText(f"End IP: {prefix}.")
            for widget in (start_third, end_third, start_dot, end_dot):
                widget.setVisible(lab)
        pod.currentTextChanged.connect(update_third)
        update_third(pod.currentText())
        return card, pod, start_third, start_host, end_third, end_host

    @Slot(str)
    def _mode_changed(self, mode: str) -> None:
        network = mode == "Network"
        options = LAN_SCRIPTS if mode in {"LAN", "Network"} else SERIAL_SCRIPTS
        self.script_combo.clear()
        self.script_combo.addItems(options)
        self.script_combo.setEnabled(not network)
        self.target_edit.setEnabled(not network)
        self.baud_combo.setEnabled(mode == "Serial")
        self.connection_form.setRowVisible(self.script_combo, not network)
        self.connection_form.setRowVisible(self.target_edit, not network)
        self.connection_form.setRowVisible(self.baud_combo, mode == "Serial")
        self.ranges_box.setVisible(network)
        self.target_edit.setPlaceholderText("Example: 10.0.0.1" if mode != "Serial" else "Example: COM3")

    @Slot()
    def _browse_output(self) -> None:
        self._choose_output()

    def _suggested_output_name(self) -> str:
        customer = sanitize_filename_component(self.customer_edit.text(), fallback="Customer")
        project = sanitize_filename_component(self.project_edit.text(), fallback="Project")
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        return f"ATLAS_{customer}_{project}_Inventory_{timestamp}.xlsx"

    def _choose_output(self) -> bool:
        suggested = self.output_edit.text().strip() or self._suggested_output_name()
        path, _ = QFileDialog.getSaveFileName(
            self, "Save inventory report", suggested, "Excel workbooks (*.xlsx)"
        )
        if path:
            self.output_edit.setText(path if path.lower().endswith(".xlsx") else path + ".xlsx")
            self._set_new_report(clear_output=False)
            return True
        return False

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
    def _set_new_report(self, *, clear_output: bool) -> None:
        self._append_mode = False
        self.report_mode_label.setText("New report")
        if clear_output:
            self.output_edit.clear()

    @Slot()
    def _new_report(self) -> None:
        self._set_new_report(clear_output=True)

    @Slot()
    def _start(self) -> None:
        if not self._append_mode and not self.output_edit.text().strip():
            if not self._choose_output():
                return
        output_path = Path(self.output_edit.text().strip())
        if output_path.suffix.lower() != ".xlsx":
            QMessageBox.warning(self, "Inventory", "Choose an .xlsx output file.")
            return
        try:
            common = dict(
                output_path=output_path,
                customer=self.customer_edit.text(), project=self.project_edit.text(),
                purchase_order=self.po_edit.text(), sales_order=self.so_edit.text(),
                append_mode=self._append_mode,
            )
            if self.mode_combo.currentText() == "Network":
                expanded = []
                for index, (_row, pod, start_third, start_host, end_third, end_host) in enumerate(self.range_controls):
                    if not any(edit.text().strip() for edit in (start_third, start_host, end_third, end_host)):
                        if index == 0:
                            raise ValueError("Enter IP Selection 1.")
                        continue
                    expanded.append(expand_network_range(
                        pod.currentText(), start_host.text(), end_host.text(),
                        start_third.text(), end_third.text(),
                    ))
                request = NetworkInventoryRequest(targets=combine_network_ranges(*expanded), **common)
            else:
                request = DirectInventoryRequest(
                    mode=self.mode_combo.currentText(), script_name=self.script_combo.currentText(),
                    target=self.target_edit.text().strip(), baud_rate=int(self.baud_combo.currentText()),
                    **common,
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
        worker.numeric_progress.connect(self._on_progress)
        worker.credentials_requested.connect(self._prompt_credentials)
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

    @Slot(int, int, str)
    def _on_progress(self, current: int, total: int, label: str) -> None:
        self.progress_bar.setRange(0, max(total, 1))
        self.progress_bar.setValue(current)
        self.status_label.setText(label)

    @Slot(str)
    def _prompt_credentials(self, ip: str) -> None:
        worker = self._worker
        if worker is None:
            return
        username, accepted = QInputDialog.getText(self, "Device credentials", f"Username for {ip}:")
        if not accepted or not username.strip():
            worker.submit_credentials(ip, None)
            return
        password, accepted = QInputDialog.getText(
            self, "Device credentials", f"Password for {ip}:",
            QLineEdit.EchoMode.Password,
        )
        worker.submit_credentials(ip, (username.strip(), password) if accepted else None)

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
        failed = getattr(outcome, "failed", {})
        if failed:
            lines = [f"{ip}: {reason}" for ip, reason in list(failed.items())[:15]]
            remaining = len(failed) - len(lines)
            if remaining:
                lines.append(f"…and {remaining} more; see the activity log.")
            QMessageBox.warning(
                self, "Some devices failed",
                f"{len(failed)} device(s) did not return inventory data.\n\n" + "\n".join(lines),
            )

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
