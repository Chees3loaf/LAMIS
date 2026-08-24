"""Application entry point for the ATLAS PySide6 pilot."""
from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from gui_qt.main_window import AtlasPilotWindow


def run_asset_import_pilot() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("ATLAS")
    app.setOrganizationName("LightRiver Technologies")
    app.setStyleSheet(
        "QLabel#pageHeading { font-size: 22px; font-weight: 600; }"
        "QGroupBox { font-weight: 600; margin-top: 8px; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }"
        "QPushButton { padding: 6px 12px; }"
    )
    window = AtlasPilotWindow()
    window.show()
    return app.exec()
