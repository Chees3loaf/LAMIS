"""PySide6 Software Upgrades workspace."""
from __future__ import annotations
import logging
import threading
from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget
from services.software_upgrade_service import FAMILIES, SoftwareUpgradeRequest, list_upgrade_nics, run_software_upgrade, validate_software_upgrade


class UpgradeWorker(QObject):
    progress = Signal(str); succeeded = Signal(object); failed = Signal(str); finished = Signal()
    def __init__(self, request): super().__init__(); self.request = request; self.cancelled = threading.Event()
    @Slot()
    def run(self):
        try: outcome = run_software_upgrade(self.request, progress=self.progress.emit, should_stop=self.cancelled.is_set)
        except Exception as exc: logging.exception("Qt software upgrade failed"); self.failed.emit(str(exc) or exc.__class__.__name__)
        else: self.succeeded.emit(outcome)
        finally: self.finished.emit()


class SoftwareUpgradePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent); self.thread = None; self.worker = None
        heading = QLabel("Software Upgrades"); heading.setObjectName("pageHeading")
        intro = QLabel("Stage software on a temporary service network, run the supported device upgrade, then automatically stop the HTTP server and restore DHCP/DNS."); intro.setObjectName("pageIntro"); intro.setWordWrap(True)
        box = QGroupBox("Upgrade configuration"); form = QFormLayout(box)
        self.family = QComboBox(); self.family.addItems(FAMILIES); self.family.currentTextChanged.connect(self._family_changed)
        self.path = QLineEdit(); path_row = QWidget(); path_layout = QHBoxLayout(path_row); path_layout.setContentsMargins(0,0,0,0); file_button = QPushButton("File…"); file_button.clicked.connect(self._file); folder_button = QPushButton("Folder…"); folder_button.clicked.connect(self._folder); path_layout.addWidget(self.path,1); path_layout.addWidget(file_button); path_layout.addWidget(folder_button)
        self.nic = QComboBox(); refresh = QPushButton("Refresh"); refresh.clicked.connect(self._refresh_nics); nic_row=QWidget(); nic_layout=QHBoxLayout(nic_row); nic_layout.setContentsMargins(0,0,0,0); nic_layout.addWidget(self.nic,1); nic_layout.addWidget(refresh)
        self.ctm = QComboBox(); self.ctm.addItems(["CTM41","CTM42"])
        self.user=QLineEdit(); self.password=QLineEdit(); self.password.setEchoMode(QLineEdit.EchoMode.Password); self.inner_user=QLineEdit(); self.inner_password=QLineEdit(); self.inner_password.setEchoMode(QLineEdit.EchoMode.Password); self.serial=QLineEdit("COM1")
        form.addRow("Device family",self.family); form.addRow("Software file / folder",path_row); form.addRow("Wired interface",nic_row); form.addRow("RLS CTM",self.ctm); form.addRow("Username",self.user); form.addRow("Password",self.password); form.addRow("Inner username",self.inner_user); form.addRow("Inner password",self.inner_password); form.addRow("Serial console",self.serial)
        warning=QLabel("Stop halts ATLAS polling where supported; it does not cancel an install already running on the device. Do not remove power during an upgrade."); warning.setWordWrap(True); warning.setObjectName("mutedText")
        controls=QHBoxLayout(); self.run_button=QPushButton("Run Upgrade"); self.run_button.clicked.connect(self._start); self.stop_button=QPushButton("Stop Monitoring"); self.stop_button.clicked.connect(self._stop); self.stop_button.setEnabled(False); self.status=QLabel("Ready"); controls.addWidget(self.run_button); controls.addWidget(self.stop_button); controls.addWidget(self.status,1)
        self.log=QPlainTextEdit(); self.log.setReadOnly(True)
        layout=QVBoxLayout(self); layout.addWidget(heading); layout.addWidget(intro); layout.addWidget(box); layout.addWidget(warning); layout.addLayout(controls); layout.addWidget(self.log,1)
        self._refresh_nics(); self._family_changed(self.family.currentText())

    def _error(self, detail, action): QMessageBox.critical(self,"Software Upgrade error",f"Error: {detail or 'Unknown error'}\n\nWhat to do: {action}")
    def _file(self):
        path,_=QFileDialog.getOpenFileName(self,"Select software artifact","","All files (*)")
        if path:self.path.setText(path)
    def _folder(self):
        path=QFileDialog.getExistingDirectory(self,"Select software folder")
        if path:self.path.setText(path)
    def _refresh_nics(self):
        current=self.nic.currentText(); self.nic.clear(); self.nic.addItems(list_upgrade_nics()); index=self.nic.findText(current)
        if index>=0:self.nic.setCurrentIndex(index)
    def _family_changed(self, family):
        rls=family=="Ciena RLS"; inner=family in {"Nokia PSI","Nokia PSS"}; ws=family=="Ciena Waveserver 5"
        self.ctm.setVisible(rls); self.serial.setVisible(ws)
        form=self.ctm.parentWidget().layout()
        for widget,visible in ((self.ctm,rls),(self.serial,ws),(self.inner_user,inner),(self.inner_password,inner)):
            widget.setVisible(visible); label=form.labelForField(widget); label.setVisible(visible) if label else None
        defaults={"Ciena RLS":"su","Nokia G42":"admin","Nokia PSI":"cli","Nokia PSS":"cli","Ciena Waveserver 5":""}; self.user.setText(defaults[family]); self.inner_user.setText("admin" if inner else "")
    def _request(self): return SoftwareUpgradeRequest(self.family.currentText(),self.path.text().strip(),self.nic.currentText().strip(),self.ctm.currentText(),self.user.text(),self.password.text(),self.inner_user.text(),self.inner_password.text(),self.serial.text().strip())
    def _start(self):
        request=self._request()
        try: validate_software_upgrade(request)
        except Exception as exc:self._error(str(exc),"Select the correct software artifact or unzipped CC folder, wired NIC, CTM, and serial port, then retry.");return
        if QMessageBox.question(self,"Confirm software upgrade","Confirm the device is cabled to the selected wired interface and stable power is available. ATLAS will temporarily change this NIC's IPv4 configuration. Continue?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes:return
        self.thread=QThread(self);self.worker=UpgradeWorker(request);self.worker.moveToThread(self.thread);self.thread.started.connect(self.worker.run);self.worker.progress.connect(self.log.appendPlainText);self.worker.succeeded.connect(self._success);self.worker.failed.connect(self._failed);self.worker.finished.connect(self.thread.quit);self.worker.finished.connect(self.worker.deleteLater);self.thread.finished.connect(self.thread.deleteLater);self.run_button.setEnabled(False);self.stop_button.setEnabled(True);self.status.setText("Running");self.thread.start()
    def _stop(self):
        if self.worker:self.worker.cancelled.set();self.status.setText("Stopping monitoring…");self.log.appendPlainText("Stop requested. The device-side operation may continue independently.")
    @Slot(object)
    def _success(self,outcome): self.run_button.setEnabled(True);self.stop_button.setEnabled(False);self.status.setText("Completed");QMessageBox.information(self,"Software Upgrade",outcome.completion_note)
    @Slot(str)
    def _failed(self,detail): self.run_button.setEnabled(True);self.stop_button.setEnabled(False);self.status.setText("Failed");self.log.appendPlainText(f"ERROR: {detail}");self._error(detail,"Review the log, confirm cabling, credentials, artifact layout, and NIC restoration, then retry only when the device is in a safe upgrade state.")
