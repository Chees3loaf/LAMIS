"""PySide6 live provisioning workspace."""
from __future__ import annotations

import logging
import threading
import json

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from services.provisioning_service import DEVICE_TYPES, ProvisioningDevice, ProvisioningRequest, read_provisioning_devices, run_live_provisioning, validate_provisioning_request
from services.rls_route_service import apply_diagram_transcription, apply_exact_payload, evaluate_route, exact_payload_template, exact_provider_choices, load_route_draft, move_route_shelf, new_route_project, publish_route_bundle, reattach_route_diagram, remove_route_shelf, review_route, route_profile_choices, save_route_draft, transcribe_route_diagram, update_route_details, upsert_route_shelf, validate_exact_payload


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
        source_form.setHorizontalSpacing(16); source_form.setVerticalSpacing(10)
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
        connection_form.setHorizontalSpacing(16); connection_form.setVerticalSpacing(10)
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
        options_form.setHorizontalSpacing(16); options_form.setVerticalSpacing(10)
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

        content = QWidget(); layout = QVBoxLayout(content); layout.setContentsMargins(4, 4, 4, 8); layout.setSpacing(14)
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

    def __init__(self, project, output_directory: str, diagram=None) -> None:
        super().__init__(); self.project = project; self.output_directory = output_directory; self.diagram = diagram

    @Slot()
    def run(self) -> None:
        try: result = publish_route_bundle(self.project, self.output_directory, diagram=self.diagram)
        except Exception as exc:
            logging.exception("Qt RLS route bundle export failed"); self.failed.emit(str(exc) or exc.__class__.__name__)
        else: self.succeeded.emit(dict(result))
        finally: self.finished.emit()


class DiagramTranscriptionWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()
    def __init__(self, path: str, raman_enabled: bool) -> None:
        super().__init__(); self.path = path; self.raman_enabled = raman_enabled
    @Slot()
    def run(self) -> None:
        try: result = transcribe_route_diagram(self.path, raman_callout_enabled=self.raman_enabled)
        except Exception as exc:
            logging.exception("Qt RLS diagram transcription failed"); self.failed.emit(str(exc) or exc.__class__.__name__)
        else: self.succeeded.emit(result)
        finally: self.finished.emit()


class RlsRouteProjectPage(QWidget):
    """Review and publish existing audited route projects without reimplementing their core."""
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.project = None; self.path = ""; self.thread = None; self.worker = None; self.attached_diagram = None
        project_box = QGroupBox("Route project")
        project_form = QFormLayout(project_box)
        project_form.setHorizontalSpacing(16); project_form.setVerticalSpacing(10)
        self.path_edit = QLineEdit(); self.path_edit.setReadOnly(True)
        new_button = QPushButton("New"); new_button.clicked.connect(self._new)
        open_button = QPushButton("Open project…"); open_button.clicked.connect(self._open)
        save_button = QPushButton("Save copy…"); save_button.clicked.connect(self._save_copy)
        path_row = QWidget(); path_layout = QHBoxLayout(path_row); path_layout.setContentsMargins(0, 0, 0, 0); path_layout.addWidget(self.path_edit, 1); path_layout.addWidget(new_button); path_layout.addWidget(open_button); path_layout.addWidget(save_button)
        self.route_label = QLabel("No project loaded")
        project_form.addRow("File", path_row); project_form.addRow("Route", self.route_label)
        details = QGroupBox("Project details"); details_form = QFormLayout(details); details_form.setHorizontalSpacing(16); details_form.setVerticalSpacing(10)
        self.route_edit = QLineEdit(); self.title_edit = QLineEdit(); self.revision_edit = QLineEdit("1"); self.ospf_edit = QLineEdit(); self.notes_edit = QLineEdit()
        for label, widget in (("Route code", self.route_edit), ("Title", self.title_edit), ("Revision", self.revision_edit), ("OSPF area", self.ospf_edit), ("Notes", self.notes_edit)): details_form.addRow(label, widget)
        self.table = QTableWidget(0, 6); self.table.setHorizontalHeaderLabels(["Order", "Site", "TID", "Role", "OAM IP", "Review"]); self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection); self.table.itemSelectionChanged.connect(self._load_selected_shelf); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents); self.table.horizontalHeader().setStretchLastSection(True); self.table.verticalHeader().setDefaultSectionSize(34); self.table.setMinimumHeight(210)
        shelf_box = QGroupBox("Shelf editor"); shelf_form = QFormLayout(shelf_box)
        self.selected_shelf_id = ""; self.site_code_edit = QLineEdit(); self.site_name_edit = QLineEdit(); self.tid_edit = QLineEdit(); self.oam_edit = QLineEdit(); self.release_edit = QLineEdit("RLS R4.0"); self.variant_edit = QLineEdit("RLS"); self.power_edit = QLineEdit("A/B -48 VDC"); self.raman_edit = QLineEdit(); self.shelf_notes_edit = QLineEdit(); self.role_combo = QComboBox()
        for profile_id, label in route_profile_choices(): self.role_combo.addItem(label, profile_id)
        for label, widget in (("Site code", self.site_code_edit), ("Site name", self.site_name_edit), ("Role", self.role_combo), ("TID", self.tid_edit), ("Primary OAM IP", self.oam_edit), ("Software release", self.release_edit), ("Shelf variant", self.variant_edit), ("Power label", self.power_edit), ("Raman label", self.raman_edit), ("Notes", self.shelf_notes_edit)): shelf_form.addRow(label, widget)
        shelf_buttons = QHBoxLayout(); add_update = QPushButton("Add / Update Shelf"); add_update.clicked.connect(self._upsert_shelf); clear = QPushButton("Clear Editor"); clear.clicked.connect(self._clear_shelf_editor); remove = QPushButton("Remove"); remove.clicked.connect(self._remove_shelf); up = QPushButton("Move Up"); up.clicked.connect(lambda: self._move_shelf(-1)); down = QPushButton("Move Down"); down.clicked.connect(lambda: self._move_shelf(1))
        for button in (add_update, clear, remove, up, down): shelf_buttons.addWidget(button)
        shelf_form.addRow(shelf_buttons)
        exact_box = QGroupBox("Exact RLS R4.0 provider review")
        exact_layout = QVBoxLayout(exact_box)
        provider_row = QHBoxLayout(); self.provider_combo = QComboBox(); template_button = QPushButton("Create Review Template"); template_button.clicked.connect(self._create_exact_template); validate_exact = QPushButton("Validate / Preview CLI"); validate_exact.clicked.connect(self._validate_exact); apply_exact = QPushButton("Apply Validated Payload"); apply_exact.clicked.connect(self._apply_exact)
        provider_row.addWidget(QLabel("Compatible provider")); provider_row.addWidget(self.provider_combo, 1); provider_row.addWidget(template_button); provider_row.addWidget(validate_exact); provider_row.addWidget(apply_exact)
        self.exact_json = QPlainTextEdit(); self.exact_json.setPlaceholderText("Select a shelf, choose a compatible provider, and create a review template. Every placeholder must be reviewed before validation can pass."); self.exact_json.setMinimumHeight(220)
        self.exact_preview = QPlainTextEdit(); self.exact_preview.setReadOnly(True); self.exact_preview.setPlaceholderText("Validation report and candidate CLI preview"); self.exact_preview.setMinimumHeight(180)
        exact_layout.addLayout(provider_row); exact_layout.addWidget(self.exact_json); exact_layout.addWidget(self.exact_preview)
        diagram_box = QGroupBox("Customer route diagram")
        diagram_layout = QVBoxLayout(diagram_box); diagram_buttons = QHBoxLayout(); upload = QPushButton("Transcribe Diagram…"); upload.clicked.connect(self._upload_diagram); reattach = QPushButton("Reattach Original…"); reattach.clicked.connect(self._reattach_diagram); self.diagram_status = QLabel("No diagram attached")
        diagram_buttons.addWidget(upload); diagram_buttons.addWidget(reattach); diagram_buttons.addWidget(self.diagram_status, 1)
        diagram_note = QLabel("Supported sources: DOCX, PNG, JPG, and JPEG. Transcription sends normalized diagram images to the configured external AI provider only after confirmation. Reattachment is local and performs no AI processing."); diagram_note.setObjectName("mutedText"); diagram_note.setWordWrap(True)
        diagram_layout.addLayout(diagram_buttons); diagram_layout.addWidget(diagram_note)
        controls = QHBoxLayout(); self.validate_button = QPushButton("Validate / Evaluate CLI"); self.validate_button.clicked.connect(self._validate); self.export_button = QPushButton("Export Route Bundle…"); self.export_button.clicked.connect(self._export); self.validate_button.setEnabled(False); self.export_button.setEnabled(False); self.status = QLabel("Open a route project to begin")
        controls.addWidget(self.validate_button); controls.addWidget(self.export_button); controls.addWidget(self.status, 1)
        self.results = QPlainTextEdit(); self.results.setReadOnly(True); self.results.setMinimumHeight(150)
        note = QLabel("Route drafts, exact-provider review, diagram transcription, validation, and audited bundle export are available in this workspace."); note.setObjectName("mutedText"); note.setWordWrap(True)
        editor_content = QWidget(); editor_layout = QVBoxLayout(editor_content); editor_layout.setContentsMargins(4, 4, 4, 8); editor_layout.setSpacing(14); editor_layout.addWidget(project_box); editor_layout.addWidget(details); editor_layout.addWidget(self.table); editor_layout.addWidget(shelf_box); editor_layout.addWidget(exact_box); editor_layout.addWidget(diagram_box); editor_layout.addLayout(controls); editor_layout.addWidget(self.results); editor_layout.addWidget(note)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setWidget(editor_content)
        layout = QVBoxLayout(self); layout.setContentsMargins(0, 0, 0, 0); layout.addWidget(scroll)

    def _error(self, detail: str, action: str) -> None:
        QMessageBox.critical(self, "RLS Route Builder error", f"Error: {detail or 'Unknown error'}\n\nWhat to do: {action}")

    def _open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open Ciena RLS route project", "", "Route projects (*.json);;All files (*)")
        if not path: return
        try: project = load_route_draft(path)
        except Exception as exc:
            self._error(str(exc), "Choose an ATLAS RLS R4.0 route-project JSON file and try again."); return
        self.project = project; self.path = path; self.attached_diagram = None; self.path_edit.setText(path); self._load_project_fields(); self.validate_button.setEnabled(True); self.export_button.setEnabled(True); self._render_review(); self.diagram_status.setText("Original diagram must be reattached" if project.diagram_source.get("workbook_diagram") else "No diagram required")

    def _new(self) -> None:
        self.project = new_route_project(); self.path = ""; self.attached_diagram = None; self.path_edit.clear(); self._load_project_fields(); self.validate_button.setEnabled(True); self.export_button.setEnabled(True); self._clear_shelf_editor(); self._render_review(); self.diagram_status.setText("No diagram attached")

    def _load_project_fields(self) -> None:
        project = self.project; self.route_edit.setText(project.route_code); self.title_edit.setText(project.title); self.revision_edit.setText(project.revision); self.ospf_edit.setText(project.ospf_area); self.notes_edit.setText(project.notes); self.route_label.setText(f"{project.route_code or '(new route)'} — {project.title or '(untitled)'}  |  Revision {project.revision}")

    def _apply_project_fields(self) -> None:
        self.project = update_route_details(self.project, route_code=self.route_edit.text(), title=self.title_edit.text(), revision=self.revision_edit.text(), ospf_area=self.ospf_edit.text(), notes=self.notes_edit.text())
        self.route_label.setText(f"{self.project.route_code or '(new route)'} — {self.project.title or '(untitled)'}  |  Revision {self.project.revision}")

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
        self._apply_project_fields()
        path, _ = QFileDialog.getSaveFileName(self, "Save route project copy", "", "Route projects (*.json)")
        if not path: return
        if not path.lower().endswith(".json"): path += ".json"
        try: output = save_route_draft(self.project, path)
        except Exception as exc:
            self._error(str(exc), "Choose a writable destination and confirm the loaded project is structurally safe."); return
        self.status.setText(f"Saved {output.name}")

    def _validate(self) -> None:
        if self.project is None: return
        self._apply_project_fields()
        self._render_review()
        try: build = evaluate_route(self.project)
        except Exception as exc:
            self._error(str(exc), "Review the route validation findings and exact-provider selections, then evaluate again."); return
        if build.ready: self.results.appendPlainText(f"\nConfiguration evaluation passed: {build.config_count} complete shelf candidate(s).")
        else: self.results.appendPlainText("\nConfiguration evaluation blocked:\n- " + "\n- ".join(build.blocking_reasons))

    def _export(self) -> None:
        if self.project is None: return
        self._apply_project_fields()
        directory = QFileDialog.getExistingDirectory(self, "Choose route bundle output folder")
        if not directory: return
        self.thread = QThread(self); self.worker = RouteBundleWorker(self.project, directory, self.attached_diagram); self.worker.moveToThread(self.thread); self.thread.started.connect(self.worker.run); self.worker.succeeded.connect(self._exported); self.worker.failed.connect(self._export_failed); self.worker.finished.connect(self.thread.quit); self.worker.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater); self.export_button.setEnabled(False); self.status.setText("Exporting audited bundle…"); self.thread.start()

    @Slot(object)
    def _exported(self, files) -> None:
        self.export_button.setEnabled(True); destinations = sorted({str(path.parent) for path in files.values()}); destination = destinations[0] if destinations else "the selected folder"; self.status.setText("Bundle exported"); QMessageBox.information(self, "Route bundle exported", f"The audited route bundle was exported to:\n{destination}")

    @Slot(str)
    def _export_failed(self, detail: str) -> None:
        self.export_button.setEnabled(True); self.status.setText("Export blocked"); self._error(detail, "Resolve every validation, provider-review, fiber-review, or diagram-attachment blocker, then export again.")

    def _load_selected_shelf(self) -> None:
        if self.project is None or not self.table.selectionModel().selectedRows(): return
        row = self.table.selectionModel().selectedRows()[0].row()
        if not 0 <= row < len(self.project.shelves): return
        shelf = self.project.shelves[row]; site = self.project.site_by_key(shelf.site_key); self.selected_shelf_id = shelf.shelf_id
        self.site_code_edit.setText(site.code if site else ""); self.site_name_edit.setText(site.name if site else ""); self.tid_edit.setText(shelf.tid); self.oam_edit.setText(shelf.primary_oam_ip); self.release_edit.setText(shelf.software_release); self.variant_edit.setText(shelf.shelf_variant); self.power_edit.setText(shelf.power_label); self.raman_edit.setText(shelf.raman_label); self.shelf_notes_edit.setText(shelf.notes)
        index = self.role_combo.findData(shelf.profile_id)
        if index >= 0: self.role_combo.setCurrentIndex(index)
        self._refresh_provider_choices(shelf.profile_id)
        self.exact_json.setPlainText(json.dumps(dict(shelf.profile_payload), indent=2, ensure_ascii=False) if shelf.profile_payload else "")
        self.exact_preview.clear()

    def _clear_shelf_editor(self) -> None:
        self.selected_shelf_id = ""; self.table.clearSelection()
        for widget in (self.site_code_edit, self.site_name_edit, self.tid_edit, self.oam_edit, self.raman_edit, self.shelf_notes_edit): widget.clear()
        self.release_edit.setText("RLS R4.0"); self.variant_edit.setText("RLS"); self.power_edit.setText("A/B -48 VDC"); self.role_combo.setCurrentIndex(0)
        self.provider_combo.clear(); self.exact_json.clear(); self.exact_preview.clear()

    def _upsert_shelf(self) -> None:
        if self.project is None: self._new()
        try:
            self._apply_project_fields(); self.project = upsert_route_shelf(self.project, shelf_id=self.selected_shelf_id, site_code=self.site_code_edit.text(), site_name=self.site_name_edit.text(), profile_id=self.role_combo.currentData(), tid=self.tid_edit.text(), primary_oam_ip=self.oam_edit.text(), software_release=self.release_edit.text(), shelf_variant=self.variant_edit.text(), power_label=self.power_edit.text(), raman_label=self.raman_edit.text(), notes=self.shelf_notes_edit.text())
        except Exception as exc:
            self._error(str(exc), "Correct the site, role, TID, addressing, or release fields and apply the shelf again."); return
        self._clear_shelf_editor(); self._render_review(); self.status.setText("Shelf applied — save the project draft")

    def _remove_shelf(self) -> None:
        if self.project is None or not self.selected_shelf_id:
            self._error("No shelf is selected.", "Select one shelf row before removing it."); return
        if QMessageBox.question(self, "Remove shelf", "Remove the selected shelf and any links attached to it?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes: return
        try: self.project = remove_route_shelf(self.project, self.selected_shelf_id)
        except Exception as exc: self._error(str(exc), "Refresh the project and select the shelf again."); return
        self._clear_shelf_editor(); self._render_review(); self.status.setText("Shelf removed — save the project draft")

    def _move_shelf(self, offset: int) -> None:
        if self.project is None or not self.selected_shelf_id:
            self._error("No shelf is selected.", "Select one shelf row before changing route order."); return
        shelf_id = self.selected_shelf_id
        try: self.project = move_route_shelf(self.project, shelf_id, offset)
        except Exception as exc: self._error(str(exc), "Review or rebuild the linked topology before changing shelf order."); return
        self._render_review(); row = next((i for i, shelf in enumerate(self.project.shelves) if shelf.shelf_id == shelf_id), -1)
        if row >= 0: self.table.selectRow(row)
        self.status.setText("Shelf order changed — save the project draft")

    def _refresh_provider_choices(self, profile_id: str) -> None:
        self.provider_combo.clear()
        for provider_id, label in exact_provider_choices(profile_id): self.provider_combo.addItem(label, provider_id)

    def _create_exact_template(self) -> None:
        if self.project is None or not self.selected_shelf_id:
            self._error("No shelf is selected.", "Select a shelf row before creating an exact-provider review template."); return
        provider_id = self.provider_combo.currentData()
        if not provider_id:
            self._error("No compatible exact provider is selected.", "Choose a compatible registered provider for this route role."); return
        if self.exact_json.toPlainText().strip() and QMessageBox.question(self, "Replace provider review", "Replace the current exact-provider JSON with a new template?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes: return
        try: payload = exact_payload_template(self.project, self.selected_shelf_id, provider_id)
        except Exception as exc: self._error(str(exc), "Confirm the shelf role and provider selection, then create the template again."); return
        self.exact_json.setPlainText(payload); self.exact_preview.setPlainText("Template created. Review every identity, management, routing, line-path, loss, and provider-control field before validation.")

    def _validate_exact(self) -> None:
        if self.project is None or not self.selected_shelf_id:
            self._error("No shelf is selected.", "Select a shelf and provide its exact-provider JSON first."); return
        try: _payload, artifact = validate_exact_payload(self.project, self.selected_shelf_id, self.exact_json.toPlainText())
        except Exception as exc:
            self.exact_preview.setPlainText(f"VALIDATION FAILED — no payload was applied and no deployable artifact was retained.\n\n{exc}"); self._error(str(exc), "Correct every listed exact-provider field and validate again. No shelf data has been changed."); return
        warning_count = sum(issue.severity == "warning" for issue in artifact.issues)
        self.exact_preview.setPlainText(f"VALIDATION PASSED\nCommands: {artifact.command_count}\nWarnings: {warning_count}\nCommit commands: 0\n\n{artifact.validation_report}\n\n--- CANDIDATE CLI ---\n{artifact.cli_text}")

    def _apply_exact(self) -> None:
        if self.project is None or not self.selected_shelf_id:
            self._error("No shelf is selected.", "Select a shelf and validate its exact-provider JSON first."); return
        try: self.project, artifact = apply_exact_payload(self.project, self.selected_shelf_id, self.exact_json.toPlainText())
        except Exception as exc:
            self._error(str(exc), "Correct every validation error and apply again. The existing shelf payload remains unchanged."); return
        shelf_id = self.selected_shelf_id; self._render_review(); row = next((i for i, shelf in enumerate(self.project.shelves) if shelf.shelf_id == shelf_id), -1)
        if row >= 0: self.table.selectRow(row)
        self.status.setText(f"Exact provider applied ({artifact.command_count} candidate commands) — save the project draft")

    def _upload_diagram(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Upload customer Ciena RLS route diagram", "", "Supported diagrams (*.docx *.png *.jpg *.jpeg);;All files (*)")
        if not path: return
        if self.project is not None and self.project.shelves and QMessageBox.question(self, "Replace route from diagram", "A successful complete transcription will replace the current route project and shelves. Continue?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes: return
        raman = QMessageBox.question(self, "RAMAN slot/port convention", "Does this source use small red N/5 and N/6 boxes as RAMAN slot/port annotations? Choose Yes only when that customer convention is confirmed.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes
        privacy = QMessageBox.question(self, "External AI privacy confirmation", f"Normalized images from {path} will be sent to the configured external AI provider for transcription. No credentials are included by ATLAS. Continue?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if privacy != QMessageBox.StandardButton.Yes: return
        self.thread = QThread(self); self.worker = DiagramTranscriptionWorker(path, raman); self.worker.moveToThread(self.thread); self.thread.started.connect(self.worker.run); self.worker.succeeded.connect(self._diagram_transcribed); self.worker.failed.connect(self._diagram_failed); self.worker.finished.connect(self.thread.quit); self.worker.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater); self.status.setText("Transcribing diagram…"); self.diagram_status.setText("External AI transcription running"); self.thread.start()

    @Slot(object)
    def _diagram_transcribed(self, result) -> None:
        try: project, diagram = apply_diagram_transcription(result)
        except Exception as exc:
            self._diagram_failed(str(exc)); return
        self.project = project; self.attached_diagram = diagram; self.path = ""; self.path_edit.clear(); self._load_project_fields(); self._clear_shelf_editor(); self._render_review(); self.diagram_status.setText(f"Attached: {diagram.source_file_name} ({len(diagram.images)} image(s))"); self.status.setText("Diagram draft imported — every pending field requires human review")
        review = review_route(project); QMessageBox.warning(self, "Diagram imported — human review required", f"Imported {len(project.shelves)} active shelf draft(s) and {len(project.links)} route link(s).\n\nValidation errors: {len(review.errors)}\nDeployment blockers: {len(review.blockers)}\n\nReview every shelf, link, fiber value, provider selection, and source discrepancy before export. Diagram transcription does not authorize deployment.")

    @Slot(str)
    def _diagram_failed(self, detail: str) -> None:
        self.status.setText("Diagram transcription failed — current route unchanged"); self.diagram_status.setText("Diagram not applied"); self._error(detail, "Verify the source type and AI configuration, then correct every reported topology or evidence blocker before trying again. The current route was not changed.")

    def _reattach_diagram(self) -> None:
        if self.project is None:
            self._error("No route project is loaded.", "Open the saved route project before reattaching its original diagram."); return
        path, _ = QFileDialog.getOpenFileName(self, "Reattach original customer route diagram", "", "Supported diagrams (*.docx *.png *.jpg *.jpeg);;All files (*)")
        if not path: return
        try: diagram = reattach_route_diagram(self.project, path)
        except Exception as exc:
            self._error(str(exc), "Select the exact original source whose hash and normalized image provenance match this project."); return
        self.attached_diagram = diagram; self.diagram_status.setText(f"Reattached locally: {diagram.source_file_name}"); self.status.setText("Original diagram reattached — no external AI processing used")


class _ProvisioningWorkspace(QWidget):
    def __init__(self, title: str, description: str, workspace: QWidget, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        heading = QLabel(title); heading.setObjectName("pageHeading")
        intro = QLabel(description); intro.setObjectName("pageIntro"); intro.setWordWrap(True)
        layout = QVBoxLayout(self); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(12)
        layout.addWidget(heading); layout.addWidget(intro); layout.addWidget(workspace, 1)


class LiveProvisioningWorkspace(_ProvisioningWorkspace):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            "Live Provisioning",
            "Configure a directly connected Nokia or Ciena device over SSH or serial console.",
            LiveProvisioningPage(),
            parent,
        )


class RlsRouteWorkspace(_ProvisioningWorkspace):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            "Ciena Route Builder",
            "Build, review, validate, and export audited Ciena RLS R4.0 route projects.",
            RlsRouteProjectPage(),
            parent,
        )
