"""Main window and navigation shell for ATLAS."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QMainWindow, QPushButton, QStackedWidget, QVBoxLayout, QWidget

import config
from gui_qt.asset_import_page import AssetImportPage
from gui_qt.inventory_page import InventoryPage
from gui_qt.diagnostics_page import DiagnosticsPage
from gui_qt.bom_build_page import BomBuildPage
from gui_qt.bom_compare_page import BomComparePage
from gui_qt.part_lookup_page import PartLookupPage
from gui_qt.raw_processing_page import RawProcessingPage
from gui_qt.sales_bom_import_page import SalesBomImportPage
from gui_qt.packing_slip_page import PackingSlipPage
from gui_qt.provisioning_page import ProvisioningPage
from gui_qt.software_upgrade_page import SoftwareUpgradePage
from gui_qt.pages import OverviewPage, PlannedPage


class AtlasPilotWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ATLAS")
        self.resize(1120, 760)
        self.setMinimumSize(840, 600)
        self.page_stack = QStackedWidget()
        self.pages: dict[str, QWidget] = {
            "overview": OverviewPage(),
            "asset-import": AssetImportPage(),
            "bom-build": BomBuildPage(),
            "bom-compare": BomComparePage(),
            "part-lookup": PartLookupPage(),
            "raw-processing": RawProcessingPage(),
            "sales-bom-import": SalesBomImportPage(),
            "inventory": InventoryPage(),
            "diagnostics": DiagnosticsPage(),
            "packing-slip": PackingSlipPage(),
            "file-processing": PlannedPage("File Processing"),
            "provisioning": ProvisioningPage(),
            "upgrades": SoftwareUpgradePage(),
        }
        for page in self.pages.values():
            self.page_stack.addWidget(page)
        self.pages["overview"].navigate.connect(self.show_page)

        shell = QWidget()
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        shell_layout.addWidget(self._build_navigation())
        content = QFrame()
        content.setObjectName("contentPanel")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(28, 24, 28, 24)
        content_layout.addWidget(self.page_stack)
        shell_layout.addWidget(content, 1)
        self.setCentralWidget(shell)
        self.statusBar().showMessage(f"ATLAS {config.APP_VERSION}")
        self.show_page("overview")

    def _build_navigation(self) -> QWidget:
        navigation = QFrame()
        navigation.setObjectName("navigation")
        navigation.setFixedWidth(230)
        layout = QVBoxLayout(navigation)
        layout.setContentsMargins(18, 22, 18, 18)
        layout.setSpacing(5)
        brand = QLabel("ATLAS")
        brand.setObjectName("brand")
        subtitle = QLabel("Operations workspace")
        subtitle.setObjectName("navSubtitle")
        layout.addWidget(brand)
        layout.addWidget(subtitle)
        layout.addSpacing(22)
        self.nav_buttons: dict[str, QPushButton] = {}
        self._add_nav_button(layout, "Overview", "overview")
        layout.addSpacing(14)
        self._add_section_label(layout, "WORKFLOWS")
        self._add_nav_button(layout, "Inventory", "inventory")
        self._add_nav_button(layout, "Diagnostics", "diagnostics")
        self._add_nav_button(layout, "Packing Slips", "packing-slip")
        self._add_nav_button(layout, "Provisioning", "provisioning")
        self._add_nav_button(layout, "Software Upgrades", "upgrades")
        layout.addSpacing(14)
        self._add_section_label(layout, "FILE PROCESSING")
        self._add_nav_button(layout, "Asset Import", "asset-import")
        self._add_nav_button(layout, "Build / Refresh BOM", "bom-build")
        self._add_nav_button(layout, "Compare BOMs", "bom-compare")
        self._add_nav_button(layout, "Raw Processing", "raw-processing")
        self._add_nav_button(layout, "Sales BOM Import", "sales-bom-import")
        layout.addSpacing(14)
        self._add_section_label(layout, "TOOLS")
        self._add_nav_button(layout, "Part Lookup", "part-lookup")
        layout.addStretch(1)
        pilot = QLabel("ATLAS")
        pilot.setObjectName("pilotBadge")
        pilot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(pilot)
        return navigation

    @staticmethod
    def _add_section_label(layout: QVBoxLayout, text: str) -> None:
        label = QLabel(text)
        label.setObjectName("navSection")
        layout.addWidget(label)

    def _add_nav_button(self, layout: QVBoxLayout, label: str, page_key: str, *, available: bool = True) -> None:
        button = QPushButton(label if available else f"{label}  ·")
        button.setObjectName("navButton")
        button.setCheckable(True)
        button.setEnabled(available)
        button.clicked.connect(lambda _checked=False, key=page_key: self.show_page(key))
        layout.addWidget(button)
        self.nav_buttons[page_key] = button

    def show_page(self, page_key: str) -> None:
        page = self.pages.get(page_key)
        if page is None:
            return
        self.page_stack.setCurrentWidget(page)
        for key, button in self.nav_buttons.items():
            button.setChecked(key == page_key)
