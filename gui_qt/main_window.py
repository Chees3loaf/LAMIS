"""Main window for the PySide6 proof of concept."""
from PySide6.QtWidgets import QMainWindow

from gui_qt.asset_import_page import AssetImportPage


class AtlasPilotWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ATLAS — PySide6 Proof of Concept")
        self.resize(900, 650)
        self.setMinimumSize(720, 520)
        self.setCentralWidget(AssetImportPage(self))
