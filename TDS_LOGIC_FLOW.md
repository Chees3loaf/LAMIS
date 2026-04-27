# TDS Logic Flow — Complete Walkthrough

## 1. User Input (TDSFrame — `gui/tds_frame.py`)

The TDS mode presents a configuration form with five required fields:

| Field | Description |
|---|---|
| **IP Address** | Target device host (IP or hostname) |
| **Platform** | `rls` (default) or `6500` |
| **Username** | Login credential |
| **Password** | Login credential (masked) |
| **File Name** | Used as the TID label for all output files |

When the user clicks **Run Diagnostics**, `run_tds()` validates that all five fields are populated and that platform is one of the two accepted values. Any validation failure shows a `messagebox.showerror` and returns early.

---

## 2. Subprocess Launch

`TDSFrame` does **not** call the TDS script directly — it launches it as a **child process** via `subprocess.run()`:

```
sys.executable  scripts/TDS/TDS_v6.2.py
  --non-interactive
  --host       <ip>
  --platform   <rls|6500>
  --username   <user>
  --file-name  <file_name>
```

**Security note:** The password is passed via the `TDS_PASSWORD` **environment variable**, not a CLI argument, to prevent it from appearing in process listings or logs.

The call runs with a timeout from `config.TDS_TIMEOUT`. The entire `subprocess.run()` call is wrapped in a **daemon thread** so the GUI stays responsive while the diagnostic runs. On completion, `root.after(0, on_complete)` marshals the result back to the main thread safely.

**Thread outcome handling:**

| Outcome | Action |
|---|---|
| Return code 0 | `messagebox.showinfo("TDS Complete")` |
| Return code ≠ 0 | `messagebox.showerror("TDS Error", "exited with code N")` |
| Timeout (`config.TDS_TIMEOUT` exceeded) | `messagebox.showerror("TDS Timeout")` |
| Exception | `messagebox.showerror("TDS Error", str(exc))` |

In all cases the Run button is re-enabled and the status label resets to "Status: Ready". stdout + stderr from the subprocess are appended to the shared output terminal.

---

## 3. TDS Script Startup (`scripts/TDS/TDS_v6.2.py`)

At **module level** (runs on exec), before `main()` is called:

1. **`_resolve_startup_inputs()`** — Parses CLI args and `TDS_PASSWORD` env var. Validates:
   - `--host` is a valid IP address or hostname (no shell-injection characters)
   - `--platform` is `6500` or `RLS` (defaults to `RLS` if missing/unrecognized)
   - `--username` and password are non-empty
   - `--file-name` is non-empty
   - Calls `sys.exit()` with a descriptive print on any failure

2. **Transport selection** based on platform:
   - `RLS` → `METHOD = 'SSH'`, `PORT = '22'`
   - `6500` → `METHOD = 'TELNET'`, `PORT = '23'`

3. **`Debug.txt`** is opened for write — connection trace log, always created

4. **Lazy imports**: `paramiko` and `tkinter` are imported on first use (not at startup) to avoid slow startup on constrained environments

---

## 4. `main()` — Two Platform Branches

### Branch A: Platform = `RLS` (SSH)

```
RLS_LOGIN_SSH()
  ├─ paramiko.SSHClient() with AutoAddPolicy
  ├─ ssh.connect(HOST, port=22, username, password, timeout=120)
  ├─ invoke_shell() → rls_chan
  └─ Reads banner, extracts shell prompt (line ending in #, >, or $)
      └─ Stored as RLS_SHELL_PROMPT for prompt detection during command reads

     If login fails → WARNING() popup + missingTID = 'YES' + exit

RLS_SMOKE_TEST(WindowsHostName)
  └─ [See Section 5 below]

PARSE_COLLECTED_DATA_RLS(WindowsHostName)
  └─ [See Section 6 below]

RLS_LOGOUT_SSH()
  └─ Sends 'logout' then 'exit' to shell
  └─ Closes rls_chan and rls_ssh_client
```

### Branch B: Platform = `6500` (Telnet)

```
LOGIN_TELNET()
  ├─ telnetlib.Telnet(HOST, 23, TIMEOUT=120)
  └─ Returns 'YES' / 'NO'

     If login fails → WARNING() popup + missingTID = 'YES' + exit

COLLECT_DATA(mcemon, WindowsHostName)
  └─ Runs the 6500 TL1 command set over the Telnet session
  └─ Writes raw session output to <HOST>.txt

DETECT_6500_VARIANT(WindowsHostName)
  ├─ Checks for existing RLS artifact files (e.g., *_RLS_Smoke_Summary.csv)
  ├─ Reads <HOST>.txt and scans for RLS keyword markers
  │   ('RECONFIGURABLE LINE SYSTEM', '6500 RLS', 'RLS-OS', etc.)
  └─ Returns 'RLS' or '6500'

PARSE_COLLECTED_DATA(WindowsHostName)
  └─ Parses 6500 TL1 output from <HOST>.txt
  └─ Generates report CSV/TXT files
```

---

## 5. `RLS_SMOKE_TEST` — Command Execution Detail

Runs approximately 30 commands grouped by category. Each command goes through `_record_rls_command()`:

```
_record_rls_command(summary_writer, host, group, label, cmd, timeout)
  ├─ RLS_CMD(cmd, timeout)
  │   ├─ _sync_rls_prompt() — drain channel, send \n, wait for prompt
  │   ├─ rls_chan.send(command + '\n')
  │   ├─ Read loop: collect chunks, handle '--More--' pagination (sends space)
  │   ├─ Idle detection: break when prompt seen + 3 idle loops with no new data
  │   └─ Grace period: extra read if output seems incomplete
  ├─ Write output to <HOST>_RLS_<label>.csv  [command, line_number, output]
  ├─ _classify_rls_output() → 'OK' or 'WARN'
  │   ├─ WARN: 'CLI SYNTAX ERROR', 'UNKNOWN KEYWORD', 'COMMAND ERROR', 'TRACEBACK'
  │   ├─ WARN: empty/echo-only response
  │   └─ OK: meaningful output lines present
  └─ Append row to <HOST>_RLS_Smoke_Summary.csv
```

**Command groups:**

| Group | Commands |
|---|---|
| **software** | show software, active-version, running-version, committed-version, upgrade-state, upgrade-target, operation-info, ztp, ztp admin-state |
| **platform** | show shelf, show system, show lldp, alarm-history, alarm-counts |
| **logging_pm** | show logs remote-config, logs retrieve-status, command-log, syslog-history, pm current, pm historical, pm-tca, osrp snc diagnostics, osrp snc-group diagnostics |
| **hardware** | show slots |

**Dynamic discovery after base commands:**

- **LLDP interfaces** — Parsed from `show lldp` output via `_extract_rls_lldp_interfaces()`. For each discovered interface (up to 8): runs `show lldp interfaces interface <iface> state` and (if neighbors exist) `show lldp interfaces interface <iface> neighbors`. Falls back to a default interface list if LLDP returns nothing.

- **Slot hardware** — Parsed from `show slots` output via `_extract_rls_slot_details()`. Filters to slots with form-factor: `access-panel`, `ctm`, `fan`, or `power`. For each slot: runs inventory, config circuit-pack, operational-state, and software component commands. Falls back to a default slot list if discovery returns nothing.

All command totals (OK count, WARN count) are written as footer rows in the summary CSV.

---

## 6. `PARSE_COLLECTED_DATA_RLS` — Report Generation

Reads all the per-label CSV artifacts produced by the smoke test and generates `<HOST>_RLS_Report.csv`:

| Data Extracted | Source Artifact |
|---|---|
| Software versions (active, running, committed) | `_RLS_active_version`, `_RLS_running_version`, `_RLS_committed_version` |
| Upgrade state & target version | `_RLS_upgrade_state`, `_RLS_upgrade_target` |
| ZTP admin state | `_RLS_ztp_admin_state` |
| Operation in progress (result, start/end timestamps) | `_RLS_operation_info` |
| Alarm counts (critical, major, minor, warning) | `_RLS_alarm_counts` |
| Alarm highlights (top 5 unique alarms) | `_RLS_alarm_history` |
| Shelf product, type, serial number, hardware release | `_RLS_shelf` |
| System admin state, debug logging, CPU idle %, memory used % | `_RLS_system` |
| PM current / historical / TCA data | `_RLS_pm_current`, `_RLS_pm_history`, `_RLS_pm_tca` |
| Command log history (filtered by session/user) | `_RLS_command_log` |
| LLDP neighbor details per interface | `_RLS_lldp_<iface>_neighbors` |
| Slot-level inventory and circuit pack state | `_RLS_slot_<N>_inventory`, etc. |

**Command log filtering** (`_extract_rls_device_command_log_entries`):
- Detects timestamp ordering (ascending or descending)
- Filters to the most recent contiguous session for the target user
- Breaks on session-start markers (`login`, `authentication ok`, etc.) or session gaps > 45 minutes
- Falls back to newest contiguous timestamp block if user filtering removes everything

---

## 7. Output Files

All files are written to the **working directory of the TDS script** (`scripts/TDS/`):

| File | Contents |
|---|---|
| `<HOST>_RLS_<label>.csv` | Raw output of each individual command (`command`, `line_number`, `output` columns) |
| `<HOST>_RLS_Smoke_Summary.csv` | Per-command status (OK/WARN), group, note, first output line |
| `<HOST>_RLS_Report.csv` | Parsed consolidated diagnostic report |
| `<HOST>_RLS_Detected.csv` | Platform variant detection result |
| `<HOST>.txt` | Raw 6500 Telnet session capture (platform=6500 only) |
| `Debug.txt` | Full connection trace log (always created) |
| `MissingTID.txt` | Created only when the run fails to identify/connect to the device |

---

## 8. End-of-Run Summary

Back in `main()`:

```python
REPORT = 'YES'
f1 = 'Testers Diagnostic Script 6.2'
if missingTID == 'NO':
    WARNING(f1, 'Finished successfully')
else:
    WARNING(f1, 'See MissingTID.txt for more information')
```

`WARNING()` shows a `tkinter.messagebox` if Tk is available, otherwise just prints to stdout (which is captured by the GUI subprocess and shown in the output terminal).

---

## Key Data Flow Summary

```
User fills TDS form → run_tds() validates inputs
    ↓
Daemon thread: subprocess.run(TDS_v6.2.py --non-interactive ...)
    │  Password passed via TDS_PASSWORD env var (not CLI)
    ↓
TDS script resolves inputs → selects SSH (RLS) or Telnet (6500)
    ↓
  [RLS path]                          [6500 path]
  RLS_LOGIN_SSH()                     LOGIN_TELNET()
       ↓                                    ↓
  RLS_SMOKE_TEST()                    COLLECT_DATA()
  ~30 commands → per-label CSVs       Raw TL1 → <HOST>.txt
       ↓                                    ↓
  PARSE_COLLECTED_DATA_RLS()          DETECT_6500_VARIANT()
  Consolidated _RLS_Report.csv        PARSE_COLLECTED_DATA()
       ↓                                    ↓
  RLS_LOGOUT_SSH()                    (Telnet closes on exit)
    ↓
subprocess exits (code 0 = success, non-zero = error)
    ↓
root.after(0) → GUI thread shows result dialog, re-enables Run button
```
