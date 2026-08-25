"""Import-safe ATLAS GUI dispatch helpers."""
from __future__ import annotations
import sys


def maybe_dispatch_to_qt() -> None:
    if "--tds-mode" in sys.argv:
        return
    if "--tk-legacy" in sys.argv:
        sys.argv.remove("--tk-legacy")
        return
    if "--qt-pilot" in sys.argv:
        flag_index = sys.argv.index("--qt-pilot")
        if flag_index + 1 < len(sys.argv) and sys.argv[flag_index + 1] == "asset-import":
            del sys.argv[flag_index:flag_index + 2]
        else:
            del sys.argv[flag_index]
    try:
        from gui_qt.app import run_atlas_qt
    except ModuleNotFoundError as exc:
        if exc.name == "PySide6":
            sys.stderr.write("ATLAS requires PySide6. Install the project requirements and try again.\n")
            raise SystemExit(2) from exc
        raise
    raise SystemExit(run_atlas_qt())
