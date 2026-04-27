# LAMIS Inventory Logic Flow - Complete Walkthrough

## 1. STARTUP & INITIALIZATION (main.py)

- Logging configured → writes to `logs/LAMIS_YYYY-MM-DD_HH-MM-SS.log`
  - PIL debug logs suppressed: `logging.getLogger("PIL").setLevel(WARNING)`
  - Paramiko debug logs suppressed: `logging.getLogger("paramiko").setLevel(WARNING)` (eliminates kex handshake noise per connection)
- **LoadingScreen** appears with logo
- **check_updates()** checks for program updates via `utils.update.Updater`
- **start_gui()** creates:
  - `CommandTracker`: Tracks which commands have executed per IP/connection type (singleton via `get_tracker()`)
  - `DatabaseCache`: Caches part descriptions from SQLite DB (singleton via `get_cache()`)
  - `InventoryGUI`: Main GUI window (`gui/gui4_0.py`)

---

## 2. GUI SETUP (InventoryGUI.__init__)

- Three-mode radio button selector: **Inventory | TDS | Packing Slip**
- **Inventory mode frame** builds:
  - Pod selection (100-112) with dual-pod support
  - IP range selection (start/end for each pod)
  - Device Report upload section (optional append mode)
  - Run/Pause/Abort buttons
  - Output terminal (ScrolledText widget)
- **ThreadPoolExecutor** (max_workers=2) created for background inventory/export jobs
- **ConsoleRedirector** redirects stdout to the ScrolledText output terminal
- Workbook operations delegated to `WorkbookBuilder` (imported from `utils.packing_slip`)

---

## 3. USER INITIATES INVENTORY RUN

### Step 3a: run_script() — User clicks "Run"
```
run_script()
  ├─ Check no other run is in progress
  ├─ Clear self.outputs{} dictionary
  ├─ Call collect_run_context() → returns user inputs
  └─ start_run_worker() → spawn inventory thread
```

### Step 3b: collect_run_context() — Gather User Inputs
```
collect_run_context()
  ├─ Show popup: Customer, Project, PO, SO, Filename fields
  ├─ Check append_mode: if self.inventory_report_path exists → append mode ON
  ├─ Validate IP ranges:
  │   ├─ start ≤ end for each pod (error if not)
  │   └─ Detect overlapping ranges between Pod 1 and Pod 2 (warn user)
  ├─ Build IP list from:
  │   ├─ Pod Selection 1: 10.9.{pod1}.{start1 to end1}
  │   └─ Pod Selection 2 (optional): 10.9.{pod2}.{start2 to end2}
  ├─ If append mode: use existing .xlsx file path
  └─ If new mode: generate filename with timestamp, ask for save location
  
  Returns context dict:
  {
    "customer": str,
    "project": str,
    "customer_po": str,
    "sales_order": str,
    "output_file": path,
    "ip_list": [list of IPs],
    "append_mode": bool
  }
```

---

## 4. BACKGROUND INVENTORY WORKER THREAD

### Step 4a: run_inventory_worker(context) — Main orchestrator
```
run_inventory_worker(context)
  │
  ├─ PHASE 1: PING ALL IPs
  │   └─ is_reachable(ip) for each IP → filter to reachable_ips
  │
  ├─ PHASE 2: DEVICE IDENTIFICATION (per reachable IP)
  │   │
  │   └─ For each IP:
  │       ├─ identify_device(ip, queue, None, should_stop)
  │       │   ├─ Step 1: SSH banner inspection (no login)
  │       │   ├─ Step 2: SSH login — SSH(admin/admin)
  │       │   │   └─ Run identification commands
  │       │   ├─ Step 3: If SSH fails → Telnet fallback: Telnet(admin/admin)
  │       │   │   ├─ Run: "show general system-identification"
  │       │   │   └─ Run: "show general name"
  │       │   └─ parse_device_info(output) → (device_type, device_name)
  │       │       └─ Returns: "7250 IXR-R6", "7705 SAR-8 v2", "1830", "6500", etc.
  │       │
  │       ├─ select_script(device_type, ip, connection_type, stop_callback)
  │       │   └─ ScriptSelector maps normalized type → script class:
  │       │       ├─ "7250 ixr-r6" / "7250 ixr-r6d" → Nokia_IXR
  │       │       ├─ "7705 sar-8 v2" → Nokia_SAR
  │       │       ├─ "1830" → Nokia_1830
  │       │       ├─ "6500" / "ciena 6500 optical" → Ciena_6500
  │       │       └─ No match → Skip device
  │       │
  │       └─ Queue task: (ip, script_instance)
  │
  ├─ PHASE 3: EXECUTE ALL QUEUED SCRIPTS
  │   └─ process_task_queue(queue)
  │       └─ For each (ip, script_instance) in queue:
  │           ├─ Check should_stop() & is_paused flags
  │           ├─ script_instance.get_commands() → List of SSH commands
  │           ├─ script_instance.execute_commands(commands)
  │           │   └─ SSH to device → Run each command → Collect outputs
  │           ├─ script_instance.process_outputs(outputs_list, ip, self.outputs)
  │           │   └─ Parse command outputs → Extract inventory data
  │           │   └─ Populate self.outputs[ip] with DataFrames keyed by data type:
  │           │
  │           │       Nokia SAR (7705) / Nokia IXR (7250):
  │           │         'hardware_data'  — chassis: System Name/Type, Part/Serial #
  │           │         'Card A_data'    — slot A card inventory
  │           │         'Card B_data'    — slot B card inventory
  │           │         'mda_data'       — MDA cards (type regex: [\w\(\)\-\+]+)
  │           │         'port_data'      — SFP/transceiver optical inventory
  │           │
  │           │       Nokia 1830:
  │           │         'system_name'         — device name/source
  │           │         'shelf_inventory'      — shelf hardware
  │           │         'card data'            — card inventory
  │           │         'interface_inventory'  — interface hardware
  │           │
  │           │       Ciena 6500:
  │           │         'equipment_inventory'  — fan/IO/equipment rows
  │           │
  │           │   All DataFrames share common columns:
  │           │   System Name, System Type, Type, Part Number, Serial Number,
  │           │   Description, Name, Source
  │           └─ Log completion
  │
  └─ Put ("inventory_complete", True) on self.run_queue
```

---

## 5. TRANSITION TO EXPORT PHASE

### Step 5a: poll_run_queue() — Main thread polling
- Every 100ms, main thread checks `self.run_queue` for events
- Event types handled:
  - `"log"` — append message to output terminal
  - `"progress"` — update progress indicator
  - `"error"` — display error, reset UI state
  - `"aborted"` — display abort message, reset UI state
  - `"inventory_complete"` → update status to "Exporting...", call `start_export_worker(None)`
  - `"export_complete"` → prompt user for packing slips
  - `"export_error"` — display export error, reset UI state
  - `"packing_complete"` — display success, reset UI state
  - `"packing_error"` — display packing slip error, reset UI state

---

## 6. EXCEL WORKBOOK GENERATION

### Step 5b: run_export_worker(context, _processed_data) — Export orchestrator
```
run_export_worker(context, _)
  └─ Call WorkbookBuilder.build_report_workbook(
       outputs=self.outputs,      # Dict of IP → {key → DataFrame}
       output_file=context["output_file"],
       customer/project/po/so=context["..."],
       append_mode=context["append_mode"]
     )
```

### Step 5c: WorkbookBuilder.build_report_workbook(outputs, output_file, ..., append_mode)
```
build_report_workbook()
  │
  ├─ LOAD TEMPLATE OR EXISTING WORKBOOK
  │   ├─ If append_mode=False: Load Device_Report_Template.xlsx
  │   └─ If append_mode=True: Load existing .xlsx file
  │
  ├─ CREATE/GET SUMMARY SHEET
  │   ├─ Set capture timestamp in A1 (black bg, green font)
  │   ├─ Set Customer/Project in rows 5-7
  │   ├─ Create device table headers: #, IP Address, Device Name
  │
  ├─ IF APPEND_MODE: Read existing summary to detect duplicate IPs
  │   ├─ Extract IP list from existing Summary sheet rows 10+
  │   └─ Extract device sheet titles from hyperlinks
  │
  ├─ PROCESS EACH IP'S INVENTORY DATA (sorted by IP)
  │   │
  │   └─ For each IP in sorted order:
  │       ├─ combine_and_format_data(data_dict)
  │       │   └─ Merge all command outputs into unified DataFrame
  │       │
  │       ├─ Extract System Name, System Type, Source
  │       │
  │       ├─ IF APPEND_MODE && IP exists in summary_index:
  │       │   └─ Delete old sheet for this IP (replace)
  │       │
  │       ├─ Create new sheet (copy from template)
  │       ├─ Add "Back to Summary" hyperlink in A1
  │       ├─ Populate headers: Customer, Project, PO, SO, Source, System Name, Type
  │       │
  │       ├─ FOR EACH inventory row (Part Number, Serial, Type, Name):
  │       │   ├─ Lookup part description from DB cache
  │       │   ├─ Write to Excel row 15+: Name, Type, Part #, Serial #, Description
  │       │   └─ db_cache.lookup_part(part_number[:10])
  │       │
  │       ├─ autosize_sheet_columns(new_sheet)
  │       └─ Add to summary_index[ip] = (system_name, sheet_title)
  │
  ├─ POPULATE SUMMARY SHEET ROWS 10+
  │   ├─ For each IP in summary_index (sorted by IP):
  │   │   ├─ Row #: Sequence number
  │   │   ├─ Column C: IP address
  │   │   ├─ Column D: Device name (hyperlinked to device tab)
  │   │   └─ F7: Comma-separated IP list
  │
  ├─ REORDER WORKBOOK TABS
  │   ├─ Summary first
  │   ├─ Device tabs in IP order
  │   └─ Any remaining tabs at end
  │
  ├─ SAVE WORKBOOK
  │   └─ wb.save(output_file)
  │
  └─ Return processed_data dict
```

---

## 7. POST-EXPORT: OPTIONAL PACKING SLIP GENERATION

### Step 6: Prompt user for packing slips
```
poll_run_queue() receives ("export_complete", {...})
  ├─ Show dialog: "Do you need packing slips?"
  ├─ If YES:
  │   ├─ Ask user for save location
  │   └─ start_export_worker(processed_data, packing_slip=True)
  │       └─ run_packing_slip_worker(context, processed_data)
  │           └─ build_packing_slip_workbook(...)
  │               ├─ Load packing slip template
  │               ├─ Create Summary sheet with IP table
  │               ├─ For each device: create sheet with part/serial/description
  │               ├─ Auto-fit columns
  │               └─ Save workbook
  │
  └─ If NO: Finish run
```

---

## 8. ABORT/PAUSE LOGIC

**Pause:**
- Sets `self.is_paused = True`
- All script threads check `while is_paused and not stop_threads: sleep(0.1)`

**Abort:**
- Sets `self.stop_threads = True`
- Calls `current_script_instance.abort_connection()` → Forcefully close SSH/Telnet
- All workers check `if stop_threads: return` and put `("aborted", None)` signal

---

## Key Data Flow Summary

```
User Input → Ping IPs → Identify devices → Select scripts
    ↓
Execute commands on each device → Parse outputs → Populate self.outputs{}
    ↓
Export to Excel with Summary sheet + Device tabs (IP-sorted)
    ↓
(Optional) Generate packing slips from processed data
```

The entire process is **threaded** to avoid GUI freezing, with **cooperative abort** via `should_stop()` callbacks.

---

## Key Components

### Threading Architecture
- **Main Thread**: GUI event loop, polling `self.run_queue` every 100ms
- **ThreadPoolExecutor** (max_workers=2): Runs inventory worker and export worker as futures
- **Inventory Worker**: Ping → Identify → Execute commands → puts events on queue
- **Export Worker**: Excel workbook generation → puts events on queue
- **Device Scripts**: Directly imported and instantiated (no subprocess); support `stop_callback()`

### Data Structures
- **self.outputs{}**: Nested dict — `{ip: {data_key: DataFrame}}`
  - Keys (outer): IP address strings
  - Keys (inner): Device-type-specific data keys (e.g., `'hardware_data'`, `'port_data'`)
  - All DataFrames share columns: System Name, System Type, Type, Part Number, Serial Number, Description, Name, Source

- **self.run_queue**: Queue for inter-thread communication
  - Event types: `"log"`, `"progress"`, `"inventory_complete"`, `"export_complete"`, `"export_error"`, `"packing_complete"`, `"packing_error"`, `"error"`, `"aborted"`

- **summary_index{}**: Dict mapping IP → (device_name, sheet_title)
  - Used to track existing devices in append mode

### Singleton Infrastructure (script_interface.py)
- **`get_tracker()`** → returns process-wide `CommandTracker` singleton
  - Deduplicates CLI commands per (IP, connection_type) pair across the session
  - Methods: `has_executed()`, `mark_as_executed()`, `reset()`
- **`get_cache()`** → returns process-wide `DatabaseCache` singleton
  - Write-through cache for SQLite part lookups (caches first 10 chars of part number)
  - Returns `"Not Found"` or `"DB Error: ..."` on miss/failure

### External Dependencies
- **script_interface.DeviceIdentifier**: Probes devices via SSH banner → SSH login → Telnet fallback
- **script_interface.ScriptSelector**: Dynamically imports and instantiates device-specific scripts
- **script_interface.is_reachable()**: ICMP ping check (Windows `ping -n 1`)
- **openpyxl**: Excel workbook manipulation
- **pandas**: DataFrame operations for inventory data
- **sqlite3**: Part description lookups (`data/network_inventory.db`)
- **paramiko**: SSH transport (debug logs suppressed to WARNING in main.py)

### Device Scripts (scripts/*.py)
All inherit from `BaseScript` (ABC defined in `script_interface.py`).
Required interface:
- `get_commands()` → `List[str]`: SSH/Telnet commands to run on device
- `execute_commands(commands)` → `Tuple[List[str], Optional[str]]`: Runs commands, returns (outputs, error)
- `process_outputs(outputs, ip, outputs_dict)`: Parses outputs and populates `outputs_dict[ip]`
- `abort_connection()`: Forcefully closes SSH/Telnet connection
- `should_stop()`: Checks `stop_callback` — called between commands for cooperative abort

**Note:** `utils/device_type.py` contains a legacy `DeviceIdentifier` / `ScriptSelector` (3-tuple return, no GUI queue). It is kept for backward compatibility but the active path uses `script_interface.py`.
