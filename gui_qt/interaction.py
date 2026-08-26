"""Application-wide Qt interaction safeguards."""
from __future__ import annotations

from PySide6.QtCore import QEvent, QObject
from PySide6.QtWidgets import QComboBox


class ComboBoxWheelGuard(QObject):
    """Prevent a closed combo box from changing selection while scrolling."""

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt API
        if isinstance(watched, QComboBox) and event.type() == QEvent.Type.Wheel:
            # An open popup receives wheel events through its item-view viewport,
            # so consuming events delivered to the combo itself only blocks the
            # accidental closed-control selection change.
            return True
        return super().eventFilter(watched, event)
