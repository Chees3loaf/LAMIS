# PySide6 proof of concept

ATLAS currently keeps its production Tkinter interface as the default. The
PySide6 proof of concept is an opt-in ATLAS navigation shell with a working
Asset Import, BOM Build/Refresh, Raw Processing, and Part Lookup pages that
share production logic through UI-independent boundaries. Workflows that have
not been migrated are visibly disabled.

## Run the pilot

Install the project requirements, then run from the repository root:

```powershell
python main.py --qt-pilot asset-import
```

The pilot asks for an ATLAS inventory workbook and an ASN asset document. It
creates a timestamped backup next to the inventory workbook before updating
asset tags and customer purchase-order values.

Running `python main.py` without the pilot flag continues to launch the
existing Tkinter application.

## Test the pilot

```powershell
python -m pytest tests/test_asset_import_service.py tests/test_qt_asset_import_page.py -q
```

The widget tests select Qt's offscreen platform automatically and therefore do
not display a window.
