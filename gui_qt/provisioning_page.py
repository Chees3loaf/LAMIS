"""PySide6 live provisioning workspace."""
from __future__ import annotations

import logging
import threading

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from services.provisioning_service import DEVICE_TYPES, ProvisioningDevice, ProvisioningRequest, read_provisioning_devices, run_live_provisioning, validate_provisioning_request
from services.rls_route_service import evaluate_route, load_route_draft, publish_route_bundle, review_route, save_route_draft


class ProvisioningWorker(QObject):
    progress = Signal(str)
    succeeded = Signal()
    stopped = Signal()
    failed = Signal(str)
    finished = Signal()

    def __init__(self, request: ProvisioningRequest) -> None:
        super().__init__()
        self.request = request
        self.cancelled = threading.Event()

    @Slot()
    def run(self) -> None:
        try:
            success = run_live_provisioning(self.request, progress=self.progress.emit, should_stop=self.cancelled.is_set)
        except Exception as exc:
            logging.exception("Qt live provisioning failed")
            self.failed.emit(str(exc) or exc.__class__.__name__)
        else:
            (self.stopped if self.cancelled.is_set() or not success else self.succeeded).emit()
        finally:
            self.finished.emit()


class LiveProvisioningPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.devices: list[ProvisioningDevice] = []
        self.thread: QThread | None = None
        self.worker: ProvisioningWorker | None = None

        source = QGroupBox("Target device")
        source_form = QFormLayout(source)
        self.file_edit = QLineEdit()
        file_row = QWidget(); file_layout = QHBoxLayout(file_row); file_layout.setContentsMargins(0, 0, 0, 0)
        browse = QPushButton("Browse…"); browse.clicked.connect(self._browse_devices)
        file_layout.addWidget(self.file_edit, 1); file_layout.addWidget(browse)
        self.device_combo = QComboBox(); self.device_combo.currentIndexChanged.connect(self._selected_device_changed)
        self.ip_edit = QLineEdit(); self.ip_edit.setPlaceholderText("Manual IP overrides the workbook selection")
        self.hostname_edit = QLineEdit(); self.hostname_edit.setPlaceholderText("Required for Auto and Nokia 7705/7250")
        self.type_combo = QComboBox(); self.type_combo.addItems(DEVICE_TYPES); self.type_combo.currentTextChanged.connect(self._device_type_changed)
        source_form.addRow("Device list (.xlsx)", file_row); source_form.addRow("Workbook device", self.device_combo)
        source_form.addRow("Target IP", self.ip_edit); source_form.addRow("Hostname", self.hostname_edit); source_form.addRow("Device type", self.type_combo)

        connection = QGroupBox("Connection and network")
        connection_form = QFormLayout(connection)
        self.connection_combo = QComboBox(); self.connection_combo.addItems(["LAN (SSH)", "Serial (Console)"]); self.connection_combo.currentIndexChanged.connect(self._connection_changed)
        self.connect_ip_edit = QLineEdit(); self.connect_ip_edit.setPlaceholderText("Defaults to target IP")
        self.serial_edit = QLineEdit("COM1")
        self.baud_edit = QLineEdit("115200")
        self.username_edit = QLineEdit(); self.password_edit = QLineEdit(); self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.prefix_edit = QLineEdit("22"); self.gateway_edit = QLineEdit(); self.route_edit = QLineEdit("10.0.0.0/8")
        connection_form.addRow("Connection", self.connection_combo); connection_form.addRow("SSH connect IP", self.connect_ip_edit)
        connection_form.addRow("Serial port", self.serial_edit); connection_form.addRow("Baud rate", self.baud_edit)
        connection_form.addRow("Username", self.username_edit); connection_form.addRow("Password", self.password_edit)
        connection_form.addRow("Subnet prefix", self.prefix_edit); connection_form.addRow("Gateway", self.gateway_edit); connection_form.addRow("Static route", self.route_edit)

        self.options = QGroupBox("Device options")
        options_form = QFormLayout(self.options)
        self.configure_card = QCheckBox("Configure card type"); self.sync = QCheckBox("Synchronize redundancy")
        self.vlan_edit = QLineEdit("4000"); self.iface_edit = QLineEdit("mgmt"); self.vlan_name_edit = QLineEdit("mgmt"); self.mgmt_port_edit = QLineEdit()
        self.update_existing = QCheckBox("Update existing configuration"); self.src_iface_edit = QLineEdit()
        self.shelf_combo = QComboBox(); self.shelf_combo.addItem("Auto-detect", "auto"); self.shelf_combo.addItem("PSI-4L / PSI-8L (MFC)", "psi"); self.shelf_combo.addItem("PSS-16II (USRPNL)", "pss16")
        self.loopback = QCheckBox("Set loopback")
        for label, widget in (("Nokia", self.configure_card), ("Nokia redundancy", self.sync), ("SAOS VLAN ID", self.vlan_edit), ("SAOS interface", self.iface_edit), ("SAOS VLAN name", self.vlan_name_edit), ("SAOS management port", self.mgmt_port_edit), ("SAOS update", self.update_existing), ("SAOS 10 source interface", self.src_iface_edit), ("OLS shelf", self.shelf_combo), ("OLS loopback", self.loopback)):
            options_form.addRow(label, widget)

        controls = QHBoxLayout()
        self.run_button = QPushButton("Run Provisioning"); self.run_button.clicked.connect(self._start)
        self.stop_button = QPushButton("Stop"); self.stop_button.clicked.connect(self._stop); self.stop_button.setEnabled(False)
        self.status = QLabel("Ready")
        controls.addWidget(self.run_button); controls.addWidget(self.stop_button); controls.addWidget(self.status, 1)
        self.log = QPlainTextEdit(); self.log.setReadOnly(True); self.log.setMinimumHeight(150)

        content = QWidget(); layout = QVBoxLayout(content)
        layout.addWidget(source); layout.addWidget(connection); layout.addWidget(self.options); layout.addLayout(controls); layout.addWidget(self.log)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setWidget(content)
        outer = QVBoxLayout(self); outer.setContentsMargins(0, 0, 0, 0); outer.addWidget(scroll)
        self._connection_changed(0); self._device_type_changed(self.type_combo.currentText())

    def _error(self, detail: str, action: str) -> None:
        QMessageBox.critical(self, "Provisioning error", f"Error: {detail or 'Unknown error'}\n\nWhat to do: {action}")

    def _browse_devices(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select provisioning device list", "", "Excel workbooks (*.xlsx)")
        if not path: return
        self.file_edit.setText(path)
        try: self.devices = read_provisioning_devices(path)
        except Exception as exc:
            self._error(str(exc), "Choose an .xlsx workbook containing IP and Hostname columns, then try again."); return
        self.device_combo.clear(); self.device_combo.addItems([device.label for device in self.devices]); self._selected_device_changed(0)
        self.log.appendPlainText(f"Loaded {len(self.devices)} device(s) from {path}")

    def _selected_device_changed(self, index: int) -> None:
        if not 0 <= index < len(self.devices): return
        device = self.devices[index]; self.ip_edit.setText(device.ip); self.hostname_edit.setText(device.hostname); self.connect_ip_edit.setText(device.ip)
        if device.prefix: self.prefix_edit.setText(device.prefix)
        if device.gateway: self.gateway_edit.setText(device.gateway)
        if device.static_route: self.route_edit.setText(device.static_route)

    def _connection_changed(self, index: int) -> None:
        ssh = index == 0; self.connect_ip_edit.setEnabled(ssh); self.username_edit.setEnabled(ssh); self.password_edit.setEnabled(ssh); self.serial_edit.setEnabled(not ssh)

    def _device_type_changed(self, label: str) -> None:
        nokia = label in {"Auto (from hostname)", "Nokia 7705 SAR", "Nokia 7250 IXR"}; saos = label == "Ciena SAOS 6.21.5"; saos10 = label == "Ciena SAOS 10"; ols = label == "Nokia 1830 OLS"
        visibility = {
            self.configure_card: nokia, self.sync: nokia, self.vlan_edit: saos,
            self.iface_edit: saos, self.vlan_name_edit: saos,
            self.mgmt_port_edit: saos, self.update_existing: saos or saos10,
            self.src_iface_edit: saos10, self.shelf_combo: ols, self.loopback: ols,
        }
        form = self.options.layout()
        for widget, visible in visibility.items():
            widget.setVisible(visible)
            label_widget = form.labelForField(widget)
            if label_widget is not None: label_widget.setVisible(visible)
        defaults = {"Ciena SAOS 6.21.5": ("9600", "0.0.0.0/0"), "Ciena SAOS 10": ("115200", "0.0.0.0/0"), "Nokia 1830 OLS": ("38400", "0.0.0.0/0")}
        baud, route = defaults.get(label, ("115200", "10.0.0.0/8")); self.baud_edit.setText(baud); self.route_edit.setText(route)

    def _request(self) -> ProvisioningRequest:
        device = ProvisioningDevice(self.ip_edit.text().strip(), self.hostname_edit.text().strip())
        try: baud = int(self.baud_edit.text()); prefix = int(self.prefix_edit.text())
        except ValueError as exc: raise ValueError("Baud rate and subnet prefix must be whole numbers.") from exc
        request = ProvisioningRequest(device=device, device_type_label=self.type_combo.currentText(), connection_type="ssh" if self.connection_combo.currentIndex() == 0 else "serial", connect_ip=self.connect_ip_edit.text().strip(), serial_port=self.serial_edit.text().strip(), baud_rate=baud, username=self.username_edit.text(), password=self.password_edit.text(), prefix_len=prefix, gateway=self.gateway_edit.text().strip(), static_route_dest=self.route_edit.text().strip(), configure_card=self.configure_card.isChecked(), sync_redundancy=self.sync.isChecked(), saos_vlan_id=self.vlan_edit.text().strip(), saos_iface_name=self.iface_edit.text().strip(), saos_vlan_name=self.vlan_name_edit.text().strip(), saos_mgmt_port=self.mgmt_port_edit.text().strip(), update_existing=self.update_existing.isChecked(), saos10_src_iface=self.src_iface_edit.text().strip(), ols_shelf_type=self.shelf_combo.currentData(), ols_set_loopback=self.loopback.isChecked())
        validate_provisioning_request(request); return request

    def _start(self) -> None:
        try: request = self._request()
        except Exception as exc:
            self._error(str(exc), "Correct the highlighted connection, addressing, or device details and run provisioning again."); return
        self.thread = QThread(self); self.worker = ProvisioningWorker(request); self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run); self.worker.progress.connect(self.log.appendPlainText); self.worker.succeeded.connect(lambda: self._done("Completed")); self.worker.stopped.connect(lambda: self._done("Stopped")); self.worker.failed.connect(self._failed); self.worker.finished.connect(self.thread.quit); self.worker.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater)
        self.run_button.setEnabled(False); self.stop_button.setEnabled(True); self.status.setText("Running"); self.thread.start()

    def _stop(self) -> None:
        if self.worker: self.worker.cancelled.set(); self.status.setText("Stopping…"); self.log.appendPlainText("Stop requested; waiting for the current device command to return.")

    def _done(self, status: str) -> None:
        self.status.setText(status); self.run_button.setEnabled(True); self.stop_button.setEnabled(False)

    def _failed(self, detail: str) -> None:
        self._done("Failed"); self.log.appendPlainText(f"ERROR: {detail}"); self._error(detail, "Review the connection and device output, correct the rejected setting or credentials, then retry.")


class ProvisioningPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        heading = QLabel("Provisioning"); heading.setObjectName("pageHeading")
        intro = QLabel("Configure live Nokia or Ciena devices and review audited Ciena RLS R4.0 route projects."); intro.setObjectName("pageIntro"); intro.setWordWrap(True)
        tabs = QTabWidget(); tabs.addTab(LiveProvisioningPage(), "Live Device Provisioning"); tabs.addTab(RlsRouteProjectPage(), "Ciena RLS Route Builder")
        layout = QVBoxLayout(self); layout.addWidget(heading); layout.addWidget(intro); layout.addWidget(tabs, 1)


class RouteBundleWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, project, output_directory: str) -> None:
        super().__init__(); self.project = project; self.output_directory = output_directory

    @Slot()
    def run(self) -> None:
        try: result = publish_route_bundle(self.project, self.output_directory)
        except Exception as exc:
            logging.exception("Qt RLS route bundle export failed"); self.failed.emit(str(exc) or exc.__class__.__name__)
        else: self.succeeded.emit(dict(result))
        finally: self.finished.emit()


class RlsRouteProjectPage(QWidget):
    """Review and publish existing audited route projects without reimplementing their core."""
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.project = None; self.path = ""; self.thread = None; self.worker = None
        project_box = QGroupBox("Route project")
        project_form = QFormLayout(project_box)
        self.path_edit = QLineEdit(); self.path_edit.setReadOnly(True)
        open_button = QPushButton("Open project…"); open_button.clicked.connect(self._open)
        save_button = QPushButton("Save copy…"); save_button.clicked.connect(self._save_copy)
        path_row = QWidget(); path_layout = QHBoxLayout(path_row); path_layout.setContentsMargins(0, 0, 0, 0); path_layout.addWidget(self.path_edit, 1); path_layout.addWidget(open_button); path_layout.addWidget(save_button)
        self.route_label = QLabel("No project loaded")
        project_form.addRow("File", path_row); project_form.addRow("Route", self.route_label)
        self.table = QTableWidget(0, 6); self.table.setHorizontalHeaderLabels(["Order", "Site", "TID", "Role", "OAM IP", "Review"]); self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents); self.table.horizontalHeader().setStretchLastSection(True)
        controls = QHBoxLayout(); self.validate_button = QPushButton("Validate / Evaluate CLI"); self.validate_button.clicked.connect(self._validate); self.export_button = QPushButton("Export Route Bundle…"); self.export_button.clicked.connect(self._export); self.validate_button.setEnabled(False); self.export_button.setEnabled(False); self.status = QLabel("Open a route project to begin")
        controls.addWidget(self.validate_button); controls.addWidget(self.export_button); controls.addWidget(self.status, 1)
        self.results = QPlainTextEdit(); self.results.setReadOnly(True); self.results.setMinimumHeight(150)
        note = QLabel("This migration slice preserves reviewed provider payloads and route ordering. Exact-provider editing and diagram transcription remain in the Tkinter Route Builder until their Qt panels complete."); note.setObjectName("mutedText"); note.setWordWrap(True)
        layout = QVBoxLayout(self); layout.addWidget(project_box); layout.addWidget(self.table, 1); layout.addLayout(controls); layout.addWidget(self.results); layout.addWidget(note)

    def _error(self, detail: str, action: str) -> None:
        QMessageBox.critical(self, "RLS Route Builder error", f"Error: {detail or 'Unknown error'}\n\nWhat to do: {action}")

    def _open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open Ciena RLS route project", "", "Route projects (*.json);;All files (*)")
        if not path: return
        try: project = load_route_draft(path)
        except Exception as exc:
            self._error(str(exc), "Choose an ATLAS RLS R4.0 route-project JSON file and try again."); return
        self.project = project; self.path = path; self.path_edit.setText(path); self.route_label.setText(f"{project.route_code} — {project.title}  |  Revision {project.revision}"); self.validate_button.setEnabled(True); self.export_button.setEnabled(True); self._render_review()

    def _render_review(self) -> None:
        review = review_route(self.project); self.table.setRowCount(len(review.shelves))
        for row_index, shelf in enumerate(review.shelves):
            for column, value in enumerate((shelf.order, shelf.site, shelf.tid, shelf.role, shelf.oam_ip, shelf.review_state)):
                self.table.setItem(row_index, column, QTableWidgetItem(str(value)))
        self.results.clear(); self.results.appendPlainText(f"Shelves: {len(review.shelves)}\nDeployment ready: {'Yes' if review.ready else 'No'}")
        if review.errors: self.results.appendPlainText("\nValidation errors:\n- " + "\n- ".join(review.errors))
        if review.warnings: self.results.appendPlainText("\nWarnings:\n- " + "\n- ".join(review.warnings))
        if review.blockers: self.results.appendPlainText("\nDeployment blockers:\n- " + "\n- ".join(review.blockers))
        self.status.setText("Ready for export" if review.ready else f"Review required ({len(review.errors)} error(s))")

    def _save_copy(self) -> None:
        if self.project is None:
            self._error("No route project is loaded.", "Open a route-project JSON file first."); return
        path, _ = QFileDialog.getSaveFileName(self, "Save route project copy", "", "Route projects (*.json)")
        if not path: return
        if not path.lower().endswith(".json"): path += ".json"
        try: output = save_route_draft(self.project, path)
        except Exception as exc:
            self._error(str(exc), "Choose a writable destination and confirm the loaded project is structurally safe."); return
        self.status.setText(f"Saved {output.name}")

    def _validate(self) -> None:
        if self.project is None: return
        self._render_review()
        try: build = evaluate_route(self.project)
        except Exception as exc:
            self._error(str(exc), "Review the route validation findings and exact-provider selections, then evaluate again."); return
        if build.ready: self.results.appendPlainText(f"\nConfiguration evaluation passed: {build.config_count} complete shelf candidate(s).")
        else: self.results.appendPlainText("\nConfiguration evaluation blocked:\n- " + "\n- ".join(build.blocking_reasons))

    def _export(self) -> None:
        if self.project is None: return
        directory = QFileDialog.getExistingDirectory(self, "Choose route bundle output folder")
        if not directory: return
        self.thread = QThread(self); self.worker = RouteBundleWorker(self.project, directory); self.worker.moveToThread(self.thread); self.thread.started.connect(self.worker.run); self.worker.succeeded.connect(self._exported); self.worker.failed.connect(self._export_failed); self.worker.finished.connect(self.thread.quit); self.worker.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater); self.export_button.setEnabled(False); self.status.setText("Exporting audited bundle…"); self.thread.start()

    @Slot(object)
    def _exported(self, files) -> None:
        self.export_button.setEnabled(True); destinations = sorted({str(path.parent) for path in files.values()}); destination = destinations[0] if destinations else "the selected folder"; self.status.setText("Bundle exported"); QMessageBox.information(self, "Route bundle exported", f"The audited route bundle was exported to:\n{destination}")

    @Slot(str)
    def _export_failed(self, detail: str) -> None:
        self.export_button.setEnabled(True); self.status.setText("Export blocked"); self._error(detail, "Resolve every validation, provider-review, fiber-review, or diagram-attachment blocker, then export again.")
