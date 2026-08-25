# PySide6 proof of concept

ATLAS currently keeps its production Tkinter interface as the default. The
PySide6 proof of concept is an opt-in ATLAS navigation shell with a working
Asset Import, BOM Build/Refresh, BOM Compare, Raw Processing, Sales BOM Import,
Packing Slip Generator, and Part Lookup pages that share production logic through UI-independent
boundaries. Workflows that have not been migrated are visibly disabled.

## Run the pilot

Install the project requirements, then run from the repository root:

```powershell
python main.py --qt-pilot asset-import
```

The pilot asks for an ATLAS inventory workbook and an ASN asset document. It
creates a timestamped backup next to the inventory workbook before updating
asset tags and customer purchase-order values.

Packing Slip Generator supports both a workbook containing individual device
sheets and a consolidated single-sheet output. Device counts exclude Summary
and aggregate BOM sheets.

Sales BOM Import supports multi-select worksheet input and merges selected
sheets into one per-site output workbook.

Inventory supports direct LAN and Serial collection plus concurrent Pod/Lab
network scanning, credential retries, partial-failure summaries, append mode,
and family-aware report export.

Diagnostics currently includes Ciena RLS and Nokia PSI Network Audit. TDS is
the remaining Diagnostics sub-mode awaiting migration.

Running `python main.py` without the pilot flag continues to launch the
existing Tkinter application.

## Test the pilot

```powershell
python -m pytest tests/test_asset_import_service.py tests/test_qt_asset_import_page.py -q
```

The widget tests select Qt's offscreen platform automatically and therefore do
not display a window.
