import sys

import pytest


def test_qt_is_default_dispatch(monkeypatch):
    import atlas_launcher
    import gui_qt.app
    monkeypatch.setattr(sys, "argv", ["main.py"])
    monkeypatch.setattr(gui_qt.app, "run_atlas_qt", lambda: 17)
    with pytest.raises(SystemExit) as exc:
        atlas_launcher.maybe_dispatch_to_qt()
    assert exc.value.code == 17


def test_tk_legacy_bypasses_qt(monkeypatch):
    import atlas_launcher
    monkeypatch.setattr(sys, "argv", ["main.py", "--tk-legacy"])
    assert atlas_launcher.maybe_dispatch_to_qt() is None
    assert sys.argv == ["main.py"]


def test_tds_dispatch_is_not_intercepted(monkeypatch):
    import atlas_launcher
    monkeypatch.setattr(sys, "argv", ["main.py", "--tds-mode"])
    assert atlas_launcher.maybe_dispatch_to_qt() is None
