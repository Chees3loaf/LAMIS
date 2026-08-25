"""PySide6 Diagnostics workspace, beginning with Network Audit."""
from __future__ import annotations

from datetime import datetime
import logging
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget

from services.network_audit_service import NetworkAuditRequest, run_network_audit, validate_network_audit_request
from utils.credentials import get_default_credential_for_vendor


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


class DiagnosticsPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        heading = QLabel("Diagnostics")
        heading.setObjectName("pageHeading")
        intro = QLabel("Run topology-aware network audits. TDS migration is the next Diagnostics slice.")
        intro.setObjectName("pageIntro")
        tabs = QTabWidget()
        tabs.addTab(NetworkAuditPage(), "Network Audit")
        tds_pending = QLabel("TDS is being migrated next; use the Tkinter interface for TDS until then.")
        tds_pending.setWordWrap(True)
        tabs.addTab(tds_pending, "TDS — migration pending")
        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(intro)
        layout.addWidget(tabs, 1)
