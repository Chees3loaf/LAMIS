"""Application entry point for the ATLAS PySide6 pilot."""
from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from gui_qt.main_window import AtlasPilotWindow


ATLAS_STYLESHEET = (
    "QWidget { font-family: 'Segoe UI'; font-size: 10pt; color: #172033; }"
    "QMainWindow, QFrame#contentPanel { background: #f5f7fb; }"
    "QFrame#navigation { background: #102a43; }"
    "QLabel#brand { color: white; font-size: 25px; font-weight: 700; }"
    "QLabel#navSubtitle { color: #9fb3c8; }"
    "QLabel#navSection { color: #829ab1; font-size: 8pt; font-weight: 700; }"
    "QPushButton#navButton { color: #d9e2ec; background: transparent; border: 0; "
    "text-align: left; padding: 9px 10px; border-radius: 5px; }"
    "QPushButton#navButton:hover { background: #243b53; }"
    "QPushButton#navButton:checked { color: white; background: #2f80ed; font-weight: 600; }"
    "QPushButton#navButton:disabled { color: #627d98; background: transparent; }"
    "QLabel#pilotBadge { color: #b3ecff; background: #243b53; border-radius: 4px; "
    "font-size: 8pt; font-weight: 700; padding: 7px; }"
    "QLabel#pageHeading { font-size: 23px; font-weight: 650; }"
    "QLabel#pageIntro, QLabel#mutedText { color: #52616f; }"
    "QLabel#cardHeading { font-size: 13pt; font-weight: 600; }"
    "QFrame#workflowCard { background: white; border: 1px solid #d9e2ec; border-radius: 8px; }"
    "QGroupBox { background: white; border: 1px solid #d9e2ec; "
    "border-radius: 7px; font-weight: 600; margin-top: 12px; }"
    "QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }"
    "QLineEdit, QPlainTextEdit { color: #172033; background: white; "
    "border: 1px solid #bcccdc; border-radius: 5px; padding: 6px; }"
    "QPushButton, QComboBox { color: #172033; background: #ffffff; "
    "border: 1px solid #9fb3c8; border-radius: 5px; padding: 7px 13px; }"
    "QPushButton:hover, QComboBox:hover { color: #ffffff; background: #243b53; "
    "border-color: #243b53; }"
    "QPushButton:pressed, QComboBox:on { color: #ffffff; background: #102a43; "
    "border-color: #102a43; }"
    "QPushButton:focus, QComboBox:focus { border: 2px solid #2f80ed; padding: 6px 12px; }"
    "QPushButton:disabled, QComboBox:disabled { color: #829ab1; background: #edf2f7; "
    "border-color: #d9e2ec; }"
    "QComboBox { padding-right: 30px; }"
    "QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: top right; "
    "width: 26px; background: #e6edf4; border: 0; border-left: 1px solid #9fb3c8; "
    "border-top-right-radius: 4px; border-bottom-right-radius: 4px; }"
    "QComboBox:hover::drop-down, QComboBox:on::drop-down { background: #102a43; "
    "border-left-color: #526d82; }"
    "QComboBox QAbstractItemView { color: #172033; background: #ffffff; "
    "border: 1px solid #9fb3c8; selection-color: #ffffff; "
    "selection-background-color: #243b53; outline: 0; }"
    "QStatusBar { background: white; color: #627d98; }"
)


def run_asset_import_pilot() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("ATLAS")
    app.setOrganizationName("LightRiver Technologies")
    app.setStyleSheet(ATLAS_STYLESHEET)
    window = AtlasPilotWindow()
    window.show()
    return app.exec()
