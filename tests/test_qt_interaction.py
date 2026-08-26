import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEvent
from PySide6.QtWidgets import QApplication, QComboBox, QWidget

from gui_qt.interaction import ComboBoxWheelGuard


def test_combo_wheel_guard_consumes_closed_combo_wheel_events() -> None:
    app = QApplication.instance() or QApplication([])
    guard = ComboBoxWheelGuard(app)
    combo = QComboBox()
    combo.addItems(["First", "Second"])
    assert guard.eventFilter(combo, QEvent(QEvent.Type.Wheel)) is True
    assert combo.currentIndex() == 0


def test_combo_wheel_guard_leaves_other_widgets_and_events_alone() -> None:
    app = QApplication.instance() or QApplication([])
    guard = ComboBoxWheelGuard(app)
    assert guard.eventFilter(QWidget(), QEvent(QEvent.Type.Wheel)) is False
    assert guard.eventFilter(QComboBox(), QEvent(QEvent.Type.FocusIn)) is False
