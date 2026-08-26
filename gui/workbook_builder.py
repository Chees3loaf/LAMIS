"""Compatibility import for the legacy Tk package.

The workbook engine is front-end neutral and now lives under ``services``.
"""
from services import workbook_builder as _workbook_builder

# Preserve every historical name, including private compatibility constants.
globals().update(
    {
        name: value
        for name, value in vars(_workbook_builder).items()
        if not name.startswith("__")
    }
)
__all__ = [name for name in globals() if not name.startswith("__")]
