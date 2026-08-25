"""PySide6 Diagnostics workspace, beginning with Network Audit."""
from __future__ import annotations

from datetime import datetime
import logging
from pathlib import Path
from queue import Queue

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget

from services.network_audit_service import NetworkAuditRequest, run_network_audit, validate_network_audit_request
from services.tds_service import TdsRequest, run_tds, validate_tds_request
from utils.credentials import get_default_credential_for_vendor
from utils.helpers import ensure_host_key_known, set_host_key_prompt


class NetworkAuditWorker(QObject):
    progress = Signal(str)
    succeeded = Signal(str)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, request: NetworkAuditRequest) -> None:
        super().__init__()
        self.request = request

    @Slot()
    def run(self) -> None:
        try:
            output = run_network_audit(self.request, progress=self.progress.emit)
        except Exception as exc:
            logging.exception("Qt Network Audit failed")
            self.failed.emit(str(exc) or exc.__class__.__name__)
        else:
            self.succeeded.emit(str(output))
        finally:
            self.finished.emit()


class TdsWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    credentials_requested = Signal(str)
    host_key_requested = Signal(str, str, str)
    finished = Signal()

    def __init__(self, request: TdsRequest) -> None:
        super().__init__()
        self.request = request
        self._credential_response: Queue = Queue(maxsize=1)
        self._host_key_response: Queue = Queue(maxsize=1)

    def submit_credentials(self, credentials: tuple[str, str] | None) -> None:
        self._credential_response.put(credentials)

    def submit_host_key(self, accepted: bool) -> None:
        self._host_key_response.put(accepted)

    def _request_credentials(self, host: str) -> tuple[str, str] | None:
        self.credentials_requested.emit(host)
        return self._credential_response.get()

    def _host_key_prompt(self, hostname: str, key_type: str, fingerprint: str) -> bool:
        self.host_key_requested.emit(hostname, key_type, fingerprint)
        return bool(self._host_key_response.get())

    def _verify_host_key(self, host: str) -> bool:
        set_host_key_prompt(self._host_key_prompt)
        try:
            return ensure_host_key_known(host)
        finally:
            set_host_key_prompt(None)

    @Slot()
    def run(self) -> None:
        try:
            outcome = run_tds(
                self.request, request_credentials=self._request_credentials,
                verify_host_key=self._verify_host_key,
            )
        except Exception as exc:
            logging.exception("Qt TDS failed")
            self.failed.emit(str(exc) or exc.__class__.__name__)
        else:
            self.succeeded.emit(outcome)
        finally:
            self.finished.emit()


class NetworkAuditPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: NetworkAuditWorker | None = None

        config_box = QGroupBox("Network Audit configuration")
        form = QFormLayout(config_box)
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Ciena RLS", "Nokia PSI"])
        self.type_combo.currentTextChanged.connect(self._type_changed)
        self.seed_edit = QLineEdit()
        self.seed_edit.setPlaceholderText("One seed IP or hostname; topology is discovered automatically")
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.output_edit = QLineEdit()
        output_row = QWidget()
        output_layout = QHBoxLayout(output_row)
        output_layout.setContentsMargins(0, 0, 0, 0)
        browse = QPushButton("Save as…")
        browse.clicked.connect(self._browse_output)
        output_layout.addWidget(self.output_edit, 1)
        output_layout.addWidget(browse)
        form.addRow("Network type", self.type_combo)
        form.addRow("Seed IP / hostname", self.seed_edit)
        form.addRow("Username", self.username_edit)
        form.addRow("Password", self.password_edit)
        form.addRow("Output", output_row)

        options = QGroupBox("Optional collection")
        options_layout = QVBoxLayout(options)
        self.capture_alarms = QCheckBox("Capture active alarms")
        self.capture_history = QCheckBox("Capture alarm history")
        self.debug = QCheckBox("Debug mode (verbose logging)")
        options_layout.addWidget(self.capture_alarms)
        options_layout.addWidget(self.capture_history)
        options_layout.addWidget(self.debug)

        controls = QHBoxLayout()
        self.run_button = QPushButton("Run Network Audit")
        self.run_button.clicked.connect(self._start)
        self.status_label = QLabel("Ready")
        controls.addWidget(self.run_button)
        controls.addWidget(self.status_label, 1)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.addWidget(config_box)
        layout.addWidget(options)
        layout.addLayout(controls)
        layout.addWidget(self.log, 1)
        self._type_changed("Ciena RLS")

    def _show_error(self, detail: str, action: str) -> None:
        QMessageBox.critical(
            self, "Network Audit error",
            f"Error: {detail or 'Unknown error'}\n\nWhat to do: {action}",
        )

    @Slot(str)
    def _type_changed(self, label: str) -> None:
        psi = label.startswith("Nokia")
        vendor = "nokia" if psi else "ciena-rls-rest"
        fallback = ("admin", "admin") if psi else ("diaguser", "Ciena123")
        username, password = get_default_credential_for_vendor(vendor) or fallback
        self.username_edit.setText(username)
        self.password_edit.setText(password)
        self.capture_alarms.setVisible(not psi)
        self.capture_history.setVisible(not psi)
        if not self.output_edit.text().strip() or Path(self.output_edit.text()).name.startswith(("RLS_Audit_", "PSI_Audit_")):
            prefix = "PSI" if psi else "RLS"
            self.output_edit.setText(f"{prefix}_Audit_{datetime.now():%Y-%m-%d_%H%M%S}.xlsx")

    @Slot()
    def _browse_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save Network Audit", self.output_edit.text(), "Excel workbooks (*.xlsx)")
        if path:
            self.output_edit.setText(path if path.lower().endswith(".xlsx") else path + ".xlsx")

    @Slot()
    def _start(self) -> None:
        request = NetworkAuditRequest(
            network_type="psi" if self.type_combo.currentText().startswith("Nokia") else "rls",
            seed=self.seed_edit.text().strip(), username=self.username_edit.text().strip(),
            password=self.password_edit.text(), output_path=Path(self.output_edit.text().strip()),
            capture_alarms=self.capture_alarms.isChecked(),
            capture_alarm_history=self.capture_history.isChecked(), debug=self.debug.isChecked(),
        )
        try:
            validate_network_audit_request(request)
        except Exception as exc:
            self._show_error(str(exc), "Correct the seed, credentials, or .xlsx output path and run the audit again.")
            return
        self.log.clear()
        self.run_button.setEnabled(False)
        self.status_label.setText("Discovering…")
        thread = QThread(self)
        worker = NetworkAuditWorker(request)
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
        self.password_edit.clear()
        self.status_label.setText(f"Done — {Path(output).name}")
        QMessageBox.information(self, "Network Audit complete", f"Report: {output}")

    @Slot(str)
    def _on_failure(self, detail: str) -> None:
        self.password_edit.clear()
        self.status_label.setText("Failed")
        self.log.appendPlainText(f"ERROR: {detail}")
        self._show_error(detail, "Review the audit log, verify the seed and credentials, then run the audit again.")

    @Slot()
    def _on_finished(self) -> None:
        self.run_button.setEnabled(True)
        self._thread = self._worker = None


class TdsPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: TdsWorker | None = None

        config_box = QGroupBox("TDS diagnostics")
        form = QFormLayout(config_box)
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("Device IP address or hostname")
        self.platform_combo = QComboBox()
        self.platform_combo.addItems(["RLS", "6500"])
        self.file_name_edit = QLineEdit()
        self.file_name_edit.setPlaceholderText("Diagnostic output file name")
        default = get_default_credential_for_vendor("ciena")
        credential_hint = QLabel(
            f"Login: {default[0]} (Ciena default; prompts on failure)"
            if default else "Login: prompts on connect because no default is available"
        )
        credential_hint.setObjectName("mutedText")
        form.addRow("IP address / hostname", self.host_edit)
        form.addRow("Platform", self.platform_combo)
        form.addRow("File name", self.file_name_edit)
        form.addRow("Credentials", credential_hint)

        controls = QHBoxLayout()
        self.run_button = QPushButton("Run TDS Diagnostics")
        self.run_button.clicked.connect(self._start)
        self.status_label = QLabel("Ready")
        controls.addWidget(self.run_button)
        controls.addWidget(self.status_label, 1)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.addWidget(config_box)
        layout.addLayout(controls)
        layout.addWidget(self.log, 1)

    def _show_error(self, detail: str, action: str) -> None:
        QMessageBox.critical(
            self, "TDS error",
            f"Error: {detail or 'Unknown error'}\n\nWhat to do: {action}",
        )

    @Slot()
    def _start(self) -> None:
        request = TdsRequest(
            host=self.host_edit.text().strip(),
            platform=self.platform_combo.currentText().lower(),
            file_name=self.file_name_edit.text().strip(),
        )
        try:
            validate_tds_request(request)
        except Exception as exc:
            self._show_error(
                str(exc),
                "Correct the device address, platform, or output file name and run TDS again.",
            )
            return
        self.log.clear()
        self.run_button.setEnabled(False)
        self.status_label.setText("Running…")
        thread = QThread(self)
        worker = TdsWorker(request)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.credentials_requested.connect(self._prompt_credentials)
        worker.host_key_requested.connect(self._prompt_host_key)
        worker.succeeded.connect(self._on_success)
        worker.failed.connect(self._on_failure)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._on_finished)
        self._thread, self._worker = thread, worker
        thread.start()

    @Slot(str)
    def _prompt_credentials(self, host: str) -> None:
        worker = self._worker
        if worker is None:
            return
        username, accepted = QInputDialog.getText(self, "TDS credentials", f"Username for {host}:")
        if not accepted or not username.strip():
            worker.submit_credentials(None)
            return
        password, accepted = QInputDialog.getText(
            self, "TDS credentials", f"Password for {host}:",
            QLineEdit.EchoMode.Password,
        )
        worker.submit_credentials((username.strip(), password) if accepted else None)

    @Slot(str, str, str)
    def _prompt_host_key(self, host: str, key_type: str, fingerprint: str) -> None:
        accepted = QMessageBox.question(
            self,
            "Verify SSH host key",
            f"Host: {host}\nKey type: {key_type}\nFingerprint: {fingerprint}\n\n"
            "Trust and save this host key?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) == QMessageBox.StandardButton.Yes
        if self._worker is not None:
            self._worker.submit_host_key(accepted)

    @Slot(object)
    def _on_success(self, outcome) -> None:
        if outcome.output:
            self.log.setPlainText(outcome.output)
        self.status_label.setText("Done")
        QMessageBox.information(self, "TDS complete", f"Diagnostics completed for {outcome.host}.")

    @Slot(str)
    def _on_failure(self, detail: str) -> None:
        self.log.appendPlainText(f"ERROR: {detail}")
        self.status_label.setText("Failed")
        self._show_error(
            detail,
            "Review the diagnostic output, verify connectivity and credentials, then run TDS again.",
        )

    @Slot()
    def _on_finished(self) -> None:
        self.run_button.setEnabled(True)
        self._thread = self._worker = None


class DiagnosticsPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        heading = QLabel("Diagnostics")
        heading.setObjectName("pageHeading")
        intro = QLabel("Run single-device TDS diagnostics and topology-aware network audits.")
        intro.setObjectName("pageIntro")
        tabs = QTabWidget()
        self.tds_page = TdsPage()
        self.network_audit_page = NetworkAuditPage()
        tabs.addTab(self.tds_page, "TDS")
        tabs.addTab(self.network_audit_page, "Network Audit")
        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(intro)
        layout.addWidget(tabs, 1)
