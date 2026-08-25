"""Regression checks for readable interactive controls in the Qt theme."""
from gui_qt.app import ATLAS_STYLESHEET


def test_buttons_have_contrasting_rest_hover_and_pressed_states() -> None:
    assert "QPushButton { color: #172033; background: #ffffff;" in ATLAS_STYLESHEET
    assert "QPushButton:hover { color: #ffffff; background: #243b53;" in ATLAS_STYLESHEET
    assert "QPushButton:pressed { color: #ffffff; background: #102a43;" in ATLAS_STYLESHEET


def test_combo_popup_has_explicit_readable_colors() -> None:
    assert "QComboBox { color: #172033; background: #ffffff;" in ATLAS_STYLESHEET
    assert "QComboBox:hover, QComboBox:focus, QComboBox:on { color: #172033; " in ATLAS_STYLESHEET
    assert "background: #ffffff; border-color: #2f80ed;" in ATLAS_STYLESHEET
    assert "QComboBox QAbstractItemView { color: #172033; background: #ffffff;" in ATLAS_STYLESHEET
    assert "selection-background-color: #243b53" in ATLAS_STYLESHEET


def test_line_edits_cannot_collapse_below_readable_height() -> None:
    assert "QLineEdit { min-height: 20px; }" in ATLAS_STYLESHEET
