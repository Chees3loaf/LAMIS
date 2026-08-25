# PySide6 proof of concept

ATLAS currently keeps its production Tkinter interface as the default. The
PySide6 proof of concept is an opt-in ATLAS navigation shell with a working
Asset Import, BOM Build/Refresh, BOM Compare, Raw Processing, Sales BOM Import,
Packing Slip Generator, Inventory, Diagnostics, Part Lookup, and live
Provisioning pages that share production logic through UI-independent
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

Diagnostics includes TDS plus Ciena RLS and Nokia PSI Network Audit, including
strict host-key confirmation and credential retry prompts.

Live Provisioning supports one Nokia 7705/7250, Nokia 1830 OLS, Ciena SAOS 6,
or Ciena SAOS 10 device over LAN (SSH) or serial. Targets can be entered
directly or selected from an `.xlsx` file with IP and Hostname columns. Device
options change with the selected platform, execution remains in a background
worker, and Stop uses the existing scripts' cooperative cancellation contract.
The audited Ciena RLS Route Builder remains on Tkinter until its dedicated
migration phase is complete.

Running `python main.py` without the pilot flag continues to launch the
existing Tkinter application.

## Test the pilot

```powershell
python -m pytest tests/test_provisioning_service.py -q
```

The widget tests select Qt's offscreen platform automatically and therefore do
not display a window.
