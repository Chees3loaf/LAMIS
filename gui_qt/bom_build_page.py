"""PySide6 page for building or refreshing a workbook BOM."""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QFileDialog, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from services.bom_build_service import run_bom_build


class BomBuildWorker(QObject):
    progress = Signal(str)
    succeeded = Signal(str)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, source_path: str) -> None:
        super().__init__()
        self.source_path = source_path

    @Slot()
    def run(self) -> None:
        try:
            output = run_bom_build(self.source_path, progress=self.progress.emit)
        except Exception as exc:
            logging.exception("Qt BOM Build failed")
            self.failed.emit(str(exc))
        else:
            self.succeeded.emit(str(output))
        finally:
            self.finished.emit()


class BomBuildPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: BomBuildWorker | None = None

        heading = QLabel("Build / Refresh BOM")
        heading.setObjectName("pageHeading")
        intro = QLabel(
            "Create an Inventory by Site BOM from an ATLAS inventory workbook. "
            "The result is written beside the source as a separate .BOM.xlsx file."
        )
        intro.setObjectName("pageIntro")
        intro.setWordWrap(True)

        files = QGroupBox("Input workbook")
        file_layout = QHBoxLayout(files)
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Select an ATLAS inventory workbook")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        file_layout.addWidget(self.source_edit, 1)
        file_layout.addWidget(browse)

        controls = QHBoxLayout()
        self.run_button = QPushButton("Build / Refresh BOM")
        self.run_button.clicked.connect(self._start)
        self.status_label = QLabel("Ready")
        controls.addWidget(self.run_button)
        controls.addWidget(self.status_label, 1)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setPlaceholderText("BOM build activity will appear here.")

        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(intro)
        layout.addWidget(files)
        layout.addLayout(controls)
        layout.addWidget(self.log, 1)

    @Slot()
    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select inventory workbook", "", "Excel workbooks (*.xlsx)"
        )
        if path:
            self.source_edit.setText(path)

    @Slot()
    def _start(self) -> None:
        source = self.source_edit.text().strip()
        if not source or not Path(source).is_file():
            QMessageBox.warning(self, "BOM Build", "Select a valid .xlsx workbook first.")
            return
        self.log.clear()
        self.run_button.setEnabled(False)
        self.status_label.setText("Building…")

        thread = QThread(self)
        worker = BomBuildWorker(source)
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
        QMessageBox.critical(self, "BOM Build failed", message)

    @Slot()
    def _on_finished(self) -> None:
        self.run_button.setEnabled(True)
        self._thread = None
        self._worker = None
