# Packing Slip Logic Flow — Complete Walkthrough

## Overview

There are two completely separate entry points for generating packing slips in LAMIS:

1. **"Packing Slip (From File)" mode** — standalone mode; user uploads an existing inventory file
2. **Post-inventory path** — triggered automatically after a full device scan completes

Both paths ultimately call the same `WorkbookBuilder.build_packing_slip_workbook()` method to produce the Excel output.

---

## Entry Point 1: "Packing Slip (From File)" Mode

The user selects this mode from the radio buttons at the top of the GUI. `PackingSlipFrame` (`gui/packing_slip_frame.py`) owns all widgets and logic for this path.

---

### Step 1 — File Upload (`upload_file`)

The user clicks **Browse** and selects a CSV or Excel file. The frame detects the file type:

| File Type | Handling |
|---|---|
| `.csv` | Read with `pd.read_csv()` into a flat DataFrame |
| `.xlsx` — single sheet | Read with `pd.read_excel()` into a flat DataFrame |
| `.xlsx` — multi-sheet (device report) | Detected as `_multisheet_device_file = True`; non-Summary sheets counted as individual devices |

The file label updates to `✓ filename (N rows)` or `✓ filename (N device(s))` in green. Unsupported formats show an error dialog.

---

### Step 2 — Project Info + Generate

The user fills in four required fields:
- **Customer**
- **Project**
- **Purchase Order**
- **Sales Order**

Clicking **Generate Packing Slips** calls `generate_packing_slips_from_file()`, which:
1. Validates all four fields are filled
2. Disables the Run button and sets status to "Processing..."
3. Creates a `tempfile.mkdtemp()` working directory
4. Routes to one of two file parsers based on `_multisheet_device_file` flag

---

### Step 3 — File Parsing (Two Paths)

#### Parser A — `_process_multisheet_device_file(file_path)` (multi-sheet Excel)

Used when the uploaded file has multiple sheets (e.g., a full device inventory report).

```
For each sheet in workbook:
  ├─ Extract source IP from cell [row 4, col 5] → use as dict key
  │   └─ Falls back to sheet name if cell is blank/nan
  │   └─ Appends sheet name suffix if key already exists (deduplication)
  ├─ Scan rows to find header row containing 'PART NUMBER' or 'SERIAL NUMBER'
  │   └─ Sheets with no matching header (e.g., Summary) are silently skipped
  ├─ Read sheet data starting from detected header row
  ├─ Drop rows where Part Number, Serial Number, AND Description are all empty/nan
  ├─ Insert 'System Name' column = sheet name (for workbook builder device naming)
  └─ processed_data[ip_address] = cleaned DataFrame
```

#### Parser B — `_process_file_for_packing_slip(df)` (flat CSV or single-sheet Excel)

Used when the uploaded file is a single flat table.

```
Detect device grouping column by scanning column names (priority order):
  1. 'system name'
  2. 'device'
  3. 'ip address'
  4. ' ip' (bare 'ip' avoided — matches 'Description')
  5. 'name' (fallback)

If grouping column found:
  └─ groupby(device_key) → one DataFrame per unique device ID value

If no grouping column found:
  └─ Entire file treated as one device → {'Device_0': df}
```

Both parsers return `processed_data: Dict[str, DataFrame]` mapping device ID → rows.

---

### Step 4 — Workbook Builder (`WorkbookBuilder.build_packing_slip_workbook`)

Called with `processed_data`, the project info fields, and the temp directory as save folder.

```
build_packing_slip_workbook(processed_data, ip_list, customer, project, po, so, tmp_dir)
  │
  ├─ Verify data/LAMIS_Packing_Slip.xlsx template exists (raises FileNotFoundError if not)
  ├─ Copy template → PackingSlip_Temp.xlsx (working copy, cleaned up in finally block)
  ├─ Detect summary sheet and device template sheet by name ("summary" substring)
  ├─ Sort devices by IP sort key (numeric octets where possible)
  │
  └─ For each device (sorted order):
      │
      ├─ Detect device name — scans columns in priority order:
      │     1. 'system name'
      │     2. 'device name'
      │     3. 'hostname'
      │     4. any column containing 'name'
      │     Falls back to 'Device_N' if none found
      │
      ├─ Copy template sheet → new sheet (title = device_name, max 31 chars, alphanumeric)
      │
      ├─ Write header cells:
      │     A1 = "Return" hyperlink → Summary sheet
      │     C5 = Customer
      │     C6 = Project
      │     C7 = Device Name
      │
      ├─ Write inventory rows starting at row 15 (case-insensitive column lookup):
      │     B = Sales Order
      │     C = Customer PO
      │     D = Part Number  (fallback: Model Number if Part Number empty)
      │     E = Serial Number
      │     F = Description
      │     Rows where all three of Part#/Serial#/Description are empty → skipped
      │
      └─ autosize_sheet_columns(new_sheet)
  │
  ├─ Populate Summary sheet rows (starting row 7):
  │     B = Customer, D = Project, F = IP Address
  │     H = Device Name (hyperlinked to that device's sheet)
  │
  ├─ autosize Summary sheet columns
  ├─ Move Summary sheet to first tab position
  ├─ Delete the original blank device template sheet
  └─ Save → PackingSlip_{Customer}_{Project}_{YYYY-MM-DD}.xlsx in tmp_dir

Returns: absolute path to the saved temp file
```

---

### Step 5 — Print Selection Dialog (`_show_print_selection_dialog`)

After the workbook builder returns, a `Toplevel` dialog opens with:
- A **scrollable checklist** of all device sheet names (all checked by default)
- **Select All / Deselect All** buttons
- An **Output Mode** toggle:

| Mode | Behavior |
|---|---|
| **Consolidated** | All selected devices merged into a single workbook using `data/LAMIS_Consolidated_Packing_Slip.xlsx` |
| **Individual** | One separate workbook per selected device |

Clicking **Save / Open** calls `_print_selected_sheets()`.

---

### Step 6 — Output (`_print_selected_sheets`)

#### Consolidated Mode

```
Prompt for save path (initialfile = PackingSlip_{Customer}_{Project}_Consolidated.xlsx)

Load data/LAMIS_Consolidated_Packing_Slip.xlsx (falls back to per-device template if missing)

Write header cells:
  C5 = Customer, C6 = Project

For each selected device sheet (in selection order):
  Read rows 15+ from source workbook
  For each row: skip if Part#, Serial#, and Description are all empty/None/nan
  Write to consolidated sheet:
    B = Device ID (sheet name)
    C = Customer PO
    D = Part Number
    E = Serial Number
    F = Description

autosize_sheet_columns()
Save → user-chosen path
os.startfile(save_path)  → opens in Excel
```

#### Individual Mode

```
Prompt for save folder

For each selected device sheet:
  Load source workbook
  Delete all sheets EXCEPT Summary + this device's sheet
  autosize all remaining sheets
  Save → {base_name}_{DeviceName}.xlsx in chosen folder
  os.startfile(save_path)  → opens each file in Excel

Log: "Saved N individual packing slip(s) to: folder"
```

---

### Cleanup

The temp directory (`tempfile.mkdtemp()`) and `PackingSlip_Temp.xlsx` working copy are both deleted in `finally` blocks regardless of success or failure.

---

## Entry Point 2: Post-Inventory Path (After Scan)

After a full device scan and Excel export complete, `poll_run_queue()` can trigger packing slip generation if the export worker was called with `packing_slip=True`. This uses `self.outputs` (the live scan data dictionary) rather than an uploaded file.

```
poll_run_queue() receives "export_complete"
  └─ (if packing slip requested) start_export_worker(processed_data, packing_slip=True)
      └─ run_packing_slip_worker(context, processed_data)
          └─ WorkbookBuilder.build_packing_slip_workbook(
               processed_data=self.outputs,
               ip_list=context["ip_list"],
               customer=context["customer"],
               project=context["project"],
               customer_po=context["customer_po"],
               sales_order=context["sales_order"],
               save_folder=<user-chosen folder>
             )

Result arrives on queue:
  "packing_complete" → messagebox.showinfo("Packing slips saved to: ...")
  "packing_error"    → messagebox.showerror(...)
```

---

## Template Files

| Template | Location | Used By |
|---|---|---|
| `LAMIS_Packing_Slip.xlsx` | `data/` | Per-device workbook (has Summary sheet + one blank device sheet) |
| `LAMIS_Consolidated_Packing_Slip.xlsx` | `data/` | Consolidated output (single sheet; Device ID in col B) |

---

## Key Data Flow Summary

```
User uploads file (CSV / single-sheet Excel / multi-sheet device report)
    ↓
File parser detects structure → processed_data: {device_id: DataFrame}
    ↓
WorkbookBuilder.build_packing_slip_workbook()
  Copy template → per-device sheets (row 15+ = inventory rows)
  Summary sheet (row 7+ = device index with hyperlinks)
  Save to temp dir
    ↓
Print Selection dialog
  User selects devices + output mode (Consolidated or Individual)
    ↓
  Consolidated: merge all selected rows → single workbook → os.startfile
  Individual:   one workbook per device → os.startfile each
    ↓
Temp directory cleaned up
```
