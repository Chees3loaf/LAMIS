"""Shared pages used by the ATLAS Qt navigation shell."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QGridLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class WorkflowCard(QFrame):
    selected = Signal(str)

    def __init__(self, title: str, description: str, page_key: str, *, available: bool) -> None:
        super().__init__()
        self.setObjectName("workflowCard")
        heading = QLabel(title)
        heading.setObjectName("cardHeading")
        body = QLabel(description)
        body.setWordWrap(True)
        body.setObjectName("mutedText")
        action = QPushButton("Open" if available else "Migration planned")
        action.setEnabled(available)
        action.clicked.connect(lambda: self.selected.emit(page_key))
        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(body, 1)
        layout.addWidget(action, 0, Qt.AlignmentFlag.AlignLeft)


class OverviewPage(QWidget):
    navigate = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        heading = QLabel("ATLAS workspace")
        heading.setObjectName("pageHeading")
        intro = QLabel(
            "The PySide6 migration is being introduced workflow by workflow. "
            "Asset Import is ready for evaluation; the production Tkinter "
            "application remains available for every other operation."
        )
        intro.setWordWrap(True)
        intro.setObjectName("pageIntro")
        grid = QGridLayout()
        definitions = (
            ("Asset Import", "Apply ASN asset tags and customer purchase orders with an automatic backup.", "asset-import", True),
            ("Inventory", "Collect and assemble network inventory workbooks.", "inventory", False),
            ("Diagnostics", "Run TDS and Nokia network-audit workflows.", "diagnostics", False),
            ("Provisioning", "Generate and execute supported provisioning workflows.", "provisioning", False),
        )
        for index, definition in enumerate(definitions):
            card = WorkflowCard(*definition[:3], available=definition[3])
            card.selected.connect(self.navigate)
            grid.addWidget(card, index // 2, index % 2)
        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(intro)
        layout.addSpacing(12)
        layout.addLayout(grid)
        layout.addStretch(1)


class PlannedPage(QWidget):
    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        heading = QLabel(title)
        heading.setObjectName("pageHeading")
        message = QLabel(
            "This workflow has not been migrated to PySide6 yet. Use the "
            "production Tkinter interface while migration work continues."
        )
        message.setWordWrap(True)
        message.setObjectName("pageIntro")
        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(message)
        layout.addStretch(1)
