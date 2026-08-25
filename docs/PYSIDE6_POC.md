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
The Ciena RLS Route Builder can open and save safe project drafts, display the
ordered shelf review state, run fail-closed project/configuration evaluation,
and publish ready projects through the existing audited atomic bundle
exporter. It can also create projects and add, update, remove, or reorder
planning shelves. Updating a shelf preserves its audited provider payload and
source evidence; reordering is refused when reviewed topology links exist.
Exact RLS R4.0 provider review is also available in Qt: provider choices are
role-compatible, templates use the strict versioned payload schema, and the
payload must decode, validate, and generate a complete no-commit candidate
before it can replace a shelf review. Diagram transcription is available in
the Qt Route Builder as well: supported sources are normalized and sent to the
configured external vision provider only after an explicit privacy prompt;
incomplete topology leaves the current route unchanged. Accepted drafts retain
hash-only provenance in JSON and session-only pixels for the Diagram worksheet.
Saved projects can reattach the exact original locally without AI processing.

Software Upgrades supports Ciena RLS, Ciena Waveserver 5, Nokia G42, Nokia
PSI, and Nokia PSS. Qt preserves temporary wired-NIC addressing, byte-level
HTTP transfer progress, device-specific execution, cooperative Stop, automatic
server shutdown, and DHCP/DNS restoration. PSI/PSS inputs must contain an
unzipped release beneath `CC/`; Waveserver 5 retains its serial-plus-DCN
preflight requirements.

Running `python main.py` without the pilot flag continues to launch the
existing Tkinter application.

## Test the pilot

```powershell
python -m pytest tests/test_provisioning_service.py -q
```

The widget tests select Qt's offscreen platform automatically and therefore do
not display a window.
