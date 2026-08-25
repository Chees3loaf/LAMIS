"""Regression checks for readable interactive controls in the Qt theme."""
from gui_qt.app import ATLAS_STYLESHEET


def test_buttons_have_contrasting_rest_hover_and_pressed_states() -> None:
    assert "QPushButton, QComboBox { color: #172033; background: #ffffff;" in ATLAS_STYLESHEET
    assert "QPushButton:hover, QComboBox:hover { color: #ffffff; background: #243b53;" in ATLAS_STYLESHEET
    assert "QPushButton:pressed, QComboBox:on { color: #ffffff; background: #102a43;" in ATLAS_STYLESHEET


def test_combo_popup_has_explicit_readable_colors() -> None:
    assert "QComboBox QAbstractItemView { color: #172033; background: #ffffff;" in ATLAS_STYLESHEET
    assert "selection-background-color: #243b53" in ATLAS_STYLESHEET
