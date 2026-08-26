from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gui_qt.app import atlas_splash_path, create_atlas_splash


def test_qt_splash_uses_the_bundled_atlas_logo() -> None:
    path = atlas_splash_path()
    assert path.name == "ATLAS Logo.png"
    assert path.is_file()


def test_qt_splash_constructs_from_project_asset() -> None:
    app = QApplication.instance() or QApplication([])
    splash = create_atlas_splash(app)
    assert splash is not None
    assert not splash.pixmap().isNull()
    splash.close()
