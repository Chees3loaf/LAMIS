"""Consistent, actionable dialogs for the PySide6 interface."""
from __future__ import annotations

from PySide6.QtWidgets import QMessageBox, QWidget


def problem_text(detail: object, action: str) -> str:
    reason = str(detail or "Unknown error").strip() or "Unknown error"
    return f"Error: {reason}\n\nWhat to do: {action}"


def show_problem(parent: QWidget, title: str, detail: object, action: str, *, critical: bool = False) -> None:
    method = QMessageBox.critical if critical else QMessageBox.warning
    method(parent, title, problem_text(detail, action))
