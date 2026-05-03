# ATLAS — User Guide

> **Automated Toolkit for LightRiver Asset & Systems**
> Version 2.0.0 · Windows Desktop Application · LightRiver Technologies

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Application Layout](#2-application-layout)
3. [Tab: Inventory](#3-tab-inventory)
   - 3.1 [Connection Type — Network Mode](#31-connection-type--network-mode)
   - 3.2 [Connection Type — LAN Mode](#32-connection-type--lan-mode)
   - 3.3 [Connection Type — Serial Mode](#33-connection-type--serial-mode)
   - 3.4 [Optional: Append to an Existing Report](#34-optional-append-to-an-existing-report)
   - 3.5 [Pod & IP Range Selection](#35-pod--ip-range-selection)
   - 3.6 [Running the Inventory (Network)](#36-running-the-inventory-network)
   - 3.7 [Running the Inventory (LAN / Serial)](#37-running-the-inventory-lan--serial)
   - 3.8 [During a Run — Progress, Pause, and Abort](#38-during-a-run--progress-pause-and-abort)
   - 3.9 [Credential Prompts](#39-credential-prompts)
   - 3.10 [After the Inventory — Packing Slip Prompt](#310-after-the-inventory--packing-slip-prompt)
   - 3.11 [Output File](#311-output-file)
4. [Tab: Packing Slip (From File)](#4-tab-packing-slip-from-file)
   - 4.1 [Uploading a File](#41-uploading-a-file)
   - 4.2 [Filling in Project Information](#42-filling-in-project-information)
   - 4.3 [Generating Packing Slips](#43-generating-packing-slips)
5. [Tab: TDS Diagnostics](#5-tab-tds-diagnostics)
   - 5.1 [Configuring and Running TDS](#51-configuring-and-running-tds)
6. [Credential Management](#6-credential-management)
   - 6.1 [Default Credential Order](#61-default-credential-order)
   - 6.2 [Saving New Credentials](#62-saving-new-credentials)
7. [Output Files Reference](#7-output-files-reference)
8. [Logs & Troubleshooting](#8-logs--troubleshooting)
9. [Supported Devices Quick-Reference](#9-supported-devices-quick-reference)

---

## 1. Getting Started

### Installation

ATLAS ships as a self-contained Windows installer (`ATLAS_Setup.exe`). No Python installation is required.

1. Run `ATLAS_Setup.exe` and follow the installer prompts.
2. A shortcut is placed on your Desktop and in the Start Menu.
3. Launch **ATLAS** from either location.

### First Launch

On the very first launch ATLAS will:

- Create an application data folder at `%APPDATA%\ATLAS\`
- Write an encrypted credential file (`credentials_config.json`) with three default device credentials already seeded
- Check for any available updates (requires internet access — the check is skipped silently if offline)
- Display a brief loading screen, then open the main window

> **Tip:** If you see a Windows Defender SmartScreen warning on first run, click **More info → Run anyway**. The executable is unsigned but is built from this repository.

---

## 2. Application Layout

When ATLAS opens you will see three tabs across the top of the window:

| Tab | Purpose |
|-----|---------|
| **Inventory** | Scan a range of network devices, collect hardware inventory, and export an Excel report. |
| **Packing Slip** | Generate packing slips from an uploaded Excel or CSV file without scanning any devices. |
| **TDS** | Run a targeted diagnostic script against a single Ciena 6500 or RLS node. |

Below the tabs is a shared **output terminal** — a scrollable text area that displays all log messages, scan progress, and error details during any operation.

---

## 3. Tab: Inventory

The Inventory tab is where most day-to-day work happens. It has three connection modes — **Network**, **LAN**, and **Serial** — selected via radio buttons at the top of the tab.

---

### 3.1 Connection Type — Network Mode

> **Use this when:** You want to scan a range of IPs on the 10.9.x.x network.

Network mode is the default and most common mode. It:

1. Pings every IP in the range you specify.
2. Identifies each reachable device automatically.
3. Pulls full hardware inventory from all identified devices in parallel (up to 5 at a time).
4. Exports the results to an Excel workbook.

When **Network** is selected, the lower portion of the tab shows the **Pod Selection** and **IP Range** controls (see [Section 3.5](#35-pod--ip-range-selection)).

---

### 3.2 Connection Type — LAN Mode

> **Use this when:** You have a single device connected directly to your laptop via a crossover cable or a small local switch, and you know its IP address.

Selecting **LAN** reveals the **Direct Connection** panel with the following fields:

| Field | Description |
|-------|-------------|
| **Script** | Select the device type from the dropdown. Options: Nokia 1830, Nokia PSI, Ciena 6500, Ciena RLS. |
| **IP** | Enter the four octets of the device's IP address. Press `.` or `Tab` to jump between octets automatically. |
| **Username** | The login username for this device. |
| **Password** | The login password (masked). |
| **Save Creds** | Click to save the username/password to the encrypted credential store for future use. |

> **Note:** In LAN mode there is no ping sweep or auto-identification step. ATLAS goes straight to running the selected script against the IP you entered.

**How to run:**
1. Select **LAN**.
2. Choose the correct script from the dropdown.
3. Enter the device IP (four octets).
4. Enter credentials (or leave blank if already saved — ATLAS will use stored creds).
5. Click **Run** (see [Section 3.7](#37-running-the-inventory-lan--serial)).

---

### 3.3 Connection Type — Serial Mode

> **Use this when:** You are connected to a device via a console/serial cable (RS-232 to USB adapter).

Selecting **Serial** reveals the **Direct Connection** panel with:

| Field | Description |
|-------|-------------|
| **Script** | Select the device type. Options: Nokia SAR, Nokia IXR. |
| **Serial Port** | Select the COM port the cable is on (e.g., COM3). Click **Refresh** to re-scan available ports. |
| **Baud Rate** | Select from 9600, 19200, 38400, 57600, or 115200. Default is 9600. |
| **Username** | Login username. |
| **Password** | Login password (masked). |
| **Save Creds** | Saves credentials to the encrypted store. |

> **Note:** Like LAN mode, Serial mode skips ping and identification and runs the selected script directly over the serial connection.

**How to run:**
1. Select **Serial**.
2. Plug in your console cable and click **Refresh** to confirm the COM port.
3. Set the correct baud rate (check device documentation if unsure — most Nokia devices default to 9600).
4. Choose the correct script.
5. Enter credentials.
6. Click **Run** (see [Section 3.7](#37-running-the-inventory-lan--serial)).

---

### 3.4 Optional: Append to an Existing Report

The **Device Report (Optional)** section allows you to add new devices to a report file that already exists from a previous run instead of creating a brand-new workbook.

**To use append mode:**

1. Click **Browse** in the Device Report section.
2. Select an existing ATLAS `.xlsx` report file.
3. The filename will appear in green with a checkmark. ATLAS reads the existing report's customer/project metadata automatically.
4. Run the inventory normally. New devices will be added as new tabs; any IP that already exists in the file will have its sheet replaced with fresh data.

**To go back to creating a new file:**

- Click **Clear** next to the file label. The label returns to "No report selected (new workbook will be created)".

> **Tip:** Append mode is useful for multi-day projects where you scan different pods on different days. Each scan adds to the same master report without losing previous data.

---

### 3.5 Pod & IP Range Selection

The Inventory tab has two side-by-side pod/IP selection columns — **Pod Selection 1** (left) and **Pod Selection 2** (right). You must fill in Pod 1 at minimum; Pod 2 is optional and used when you need to scan two different subnets in a single run.

**Each column has:**

| Control | Description |
|---------|-------------|
| **Pod** | A dropdown (100–112). This is the third octet of the IP. Selecting pod 105 gives IPs in the 10.9.105.x range. |
| **Start IP** | The last octet of the first IP to include (e.g., `1`). The full IP prefix is shown as a label to the left. |
| **End IP** | The last octet of the last IP to include (e.g., `20`). |

**Example — Single pod:**
```
Pod 1: 105    Start IP: 1    End IP: 20
→ Scans 10.9.105.1 through 10.9.105.20
```

**Example — Dual pod:**
```
Pod 1: 105    Start IP: 1    End IP: 10
Pod 2: 106    Start IP: 1    End IP: 5
→ Scans 10.9.105.1–10 and 10.9.106.1–5 in one run
```

> **Warning:** ATLAS will alert you if the two pod ranges overlap. Overlapping ranges are allowed but produce a warning because they will cause duplicate device entries.

> **Tip:** Leave Pod 2 blank (or leave the IP fields empty) if you only need one subnet.

---

### 3.6 Running the Inventory (Network)

Once your pod/IP range is set (and optionally an existing report is loaded), click **Run**.

#### Step 1 — Project Information Popup

A dialog box appears asking for:

| Field | Description |
|-------|-------------|
| **Customer** | Customer name printed on all report sheets. |
| **Project** | Project name or number. |
| **Purchase Order** | PO number (can be left as TBD). |
| **Sales Order** | SO number (can be left as TBD). |
| **Filename** | Output filename (auto-generated with timestamp, but editable). |

If you loaded an existing report in append mode, these fields are pre-filled from that file.

Click **OK** to continue. A save-location dialog then opens — choose where to save the output Excel file and click **Save**.

> **Note:** In append mode the save dialog is skipped — the output is written back to the file you already selected.

#### Step 2 — Ping Sweep

ATLAS pings every IP in the range simultaneously (up to 20 at a time). The output terminal shows:

```
Pinging 1/20...
Pinging 5/20...
...
Pinging complete. 14 reachable, 6 unreachable.
```

Unreachable IPs are listed and skipped. Only reachable IPs move to the next step.

#### Step 3 — Concurrent Device Identification & Inventory

ATLAS processes up to **5 devices at a time**. For each device it:

1. Probes the SSH banner to get a preliminary device type hint.
2. Logs in via SSH, trying credentials in order: `admin/admin` → `cli/admin` → `su/Ciena123` → any saved user credentials.
3. Runs a short set of identification commands to confirm the device type and name.
4. Selects the correct device script automatically.
5. Keeps the SSH connection open and immediately begins running inventory commands on the same connection (no second login required for Nokia SAR, IXR, and Smartoptics DCP).
6. Parses the command output and stores the inventory data.

The output terminal updates as each device completes:

```
Scanning 1/14 — 10.9.105.3 identified as Nokia 7705 SAR-8 v2
Scanning 2/14 — 10.9.105.7 identified as Nokia 7250 IXR-R6
...
Scanning 14/14 — Complete
```

> **If a device cannot be identified:** It is logged as "Unknown" and skipped. Its IP appears in the terminal with an explanation. This does not stop the other devices from being scanned.

#### Step 4 — Export

After all devices complete, ATLAS automatically builds the Excel workbook:

- A **Summary** sheet listing all devices with IP addresses and hyperlinks to their individual tabs.
- One **device tab per IP** containing the full hardware inventory (chassis, cards, MDAs, transceivers, part numbers, serial numbers, descriptions).

The terminal shows:

```
Exporting workbook...
Report saved: C:\Users\...\CustomerName_ProjectName_2026-05-02.xlsx
```

#### Step 5 — Packing Slip Prompt

After the export, a dialog asks:

> **Do you need packing slips for this inventory?**

- **Yes** — See [Section 3.10](#310-after-the-inventory--packing-slip-prompt).
- **No** — The run is complete.

---

### 3.7 Running the Inventory (LAN / Serial)

For LAN and Serial modes the flow is simpler — there is no ping sweep or auto-identification.

1. Fill in all Direct Connection fields (script, IP or COM port, credentials).
2. Click **Run**.
3. The Project Information popup appears — fill it in and choose a save location.
4. ATLAS connects directly to the device and runs the selected script.
5. Results are exported to the Excel workbook.
6. The packing slip prompt appears.

> **Tip:** If you saved credentials with **Save Creds**, you can leave the Username and Password fields blank when running — ATLAS will use the stored values automatically.

---

### 3.8 During a Run — Progress, Pause, and Abort

While a scan is in progress, three buttons are active:

| Button | What It Does |
|--------|-------------|
| **Run** | Greyed out during a run — prevents double-starts. |
| **Pause** | Pauses processing between devices. In-progress device connections are allowed to finish before the pause takes effect. Click **Resume** (same button, label changes) to continue. |
| **Abort** | Immediately stops all active device connections and cancels any queued devices that have not yet started. A partial result set is **not** exported — the run ends with an "Aborted" message. |

> **Note:** Abort stops **all** concurrent connections simultaneously — not just the most recent one.

---

### 3.9 Credential Prompts

If all stored credentials fail for a particular device, ATLAS shows a **Credential Required** dialog:

```
Could not authenticate to 10.9.105.12.
All stored credentials failed.

Username: [          ]
Password: [          ]
[ ] Save these credentials for future runs

   [Retry]   [Skip Device]
```

| Option | Result |
|--------|--------|
| Enter credentials and click **Retry** | ATLAS tries the new credentials and continues if successful. |
| Check **Save for future runs** | The new credentials are added to the encrypted store and tried automatically on future scans. |
| Click **Skip Device** | This device is skipped. The scan continues with remaining devices. |

---

### 3.10 After the Inventory — Packing Slip Prompt

When the export finishes, ATLAS asks:

> **Do you need packing slips for this inventory?**

Clicking **Yes** opens a mode selection:

| Mode | Description |
|------|-------------|
| **Individual** | Creates one Excel workbook per device. Each file contains that device's inventory using the packing slip template. Good for labeling individual boxes for shipment. |
| **Consolidated** | Creates a single Excel workbook with all devices on separate sheets. Good for a receiving department or a project manager who needs one file. |

After selecting a mode you are prompted to choose a save location (folder for Individual, file path for Consolidated). ATLAS then generates the packing slips and reports completion in the terminal.

---

### 3.11 Output File

The inventory Excel report contains:

- **Summary sheet** — Timestamp, customer/project metadata, device list table with clickable hyperlinks to each device tab. Cell F7 contains a comma-separated list of all IPs scanned.
- **Per-device sheets** (one per IP) — Named by device name or IP. Contains:
  - Customer, Project, PO, SO, Source (device name), System Type
  - Hardware inventory rows starting at row 15: Name, Type, Part Number, Serial Number, Description
  - A "Back to Summary" hyperlink in cell A1
  - Auto-sized columns

---

## 4. Tab: Packing Slip (From File)

> **Use this when:** You already have an Excel or CSV file with device inventory data and want to generate packing slips without scanning any devices.

This tab is completely independent of the Inventory tab. It generates packing slips directly from data you upload.

---

### 4.1 Uploading a File

Click **Browse** under the **Upload File** header. Supported formats:

| Format | How It Is Treated |
|--------|-------------------|
| `.csv` | Loaded as a single flat table. |
| `.xlsx` / `.xls` (single sheet) | Loaded as a single flat table. |
| `.xlsx` / `.xls` (multiple sheets) | Treated as a **multi-device file**: each non-Summary sheet is one device. |

**Multi-sheet Excel files** are the most common input. ATLAS will:
- Detect all sheets in the file.
- Show `✓ filename.xlsx (X device(s))` in green when loaded.
- Auto-populate Customer, Project, PO, and SO fields if those values are found in the template cells (C5, C6, C7, D7) on the first device sheet, or in the Summary sheet (B7, D7).

**File validation:** ATLAS checks that the file has an allowed extension, is not too large, and matches its claimed format. Files that fail validation are rejected with an error message.

---

### 4.2 Filling in Project Information

The **Project Information** section has four fields:

| Field | Description |
|-------|-------------|
| **Customer** | Customer name printed on the packing slip header. |
| **Project** | Project name or number. |
| **Purchase Order** | PO number. |
| **Sales Order** | SO number. |

These fields are auto-populated when you upload an Excel file that contains them. You can edit any field before generating.

---

### 4.3 Generating Packing Slips

Click **Generate Packing Slips**.

ATLAS will ask:

1. **Output mode** — Individual (one file per device) or Consolidated (one file, all devices).
2. **Save location** — A folder (Individual) or file path (Consolidated).

**What ATLAS does for each device sheet:**

1. Reads the inventory rows (looks for Part Number and Serial Number columns starting at row 15).
2. Opens the packing slip template.
3. Writes customer/project metadata into the template header cells.
4. Writes each inventory row into the template body.
5. Optionally auto-sizes columns.
6. Saves the file.

The output terminal confirms each file as it is saved. A completion message appears when done.

> **Note:** Any sheet named "Summary" (case-insensitive) in the uploaded file is automatically skipped — it is treated as metadata, not device inventory.

---

## 5. Tab: TDS Diagnostics

> **Use this when:** You need to run a targeted Ciena TDS diagnostic script against a single device.

TDS (Test Diagnostic System) runs a specialized external script (`TDS_v6.2.py`) against a Ciena 6500 or RLS node. It is designed for in-lab or in-field diagnostics separate from full inventory collection.

---

### 5.1 Configuring and Running TDS

Fill in the **TDS Configuration** fields:

| Field | Description |
|-------|-------------|
| **IP Address** | IP or resolvable hostname of the target device. |
| **Platform** | `rls` (Ciena RLS) or `6500` (Ciena 6500). |
| **Username** | Device login username. |
| **Password** | Device login password (masked). |
| **File Name** | Base name for the output file(s) that TDS will generate. |

Click **Run Diagnostics**.

**What happens before the script runs:**

1. ATLAS validates all fields (IP format, platform value, non-empty username/password/filename).
2. ATLAS verifies the device's SSH host key — a dialog may appear asking you to confirm an unknown host key fingerprint. You must accept it for TDS to proceed.
3. If the TDS script file is not found, an error is shown and the run is cancelled.

**What happens during the run:**

- The TDS script runs as a subprocess in the background.
- Output is streamed to the ATLAS terminal in real time.
- The **Run Diagnostics** button is disabled until the script completes.
- The status label shows **Running...** and returns to **Ready** when done.
- The password field is cleared immediately after the credentials are passed to the subprocess.

> **Timeout:** If TDS takes longer than the configured timeout (see `config.TDS_TIMEOUT`), the subprocess is terminated and an error is shown.

---

## 6. Credential Management

ATLAS stores device credentials in an encrypted file at `%APPDATA%\ATLAS\credentials_config.json`. Credentials are encrypted with Fernet symmetric encryption. The key is unique to your machine and user account.

---

### 6.1 Default Credential Order

When ATLAS attempts to log into a device it tries credentials in this order:

| # | Username | Password | Primary Devices |
|---|----------|----------|-----------------|
| 1 | `admin` | `admin` | Nokia SAR, Nokia IXR, Smartoptics DCP |
| 2 | `cli` | `admin` | Nokia 1830 |
| 3 | `su` | `Ciena123` | Ciena 6500, Ciena RLS |
| 4 | *(user input)* | *(user input)* | Any device — prompted when all above fail |

This order is automatically set on first launch and re-applied on upgrade.

---

### 6.2 Saving New Credentials

There are three ways to add or update credentials:

**Method 1 — During a scan (Credential Prompt)**
When a device rejects all stored credentials, the prompt dialog appears. Enter the correct credentials, check **Save for future runs**, and click **Retry**. The new credential is appended to the store and tried automatically on all future scans.

**Method 2 — LAN / Serial mode Save Creds button**
Enter a username and password in the LAN or Serial Direct Connection panel and click **Save Creds**. The credentials are saved and pre-populated the next time you switch to that mode.

**Method 3 — Edit credentials_config.json**
For advanced users: the file at `%APPDATA%\ATLAS\credentials_config.json` is Fernet-encrypted and cannot be edited by hand in a useful way. Use Method 1 or 2 for all credential management.

> **Security note:** Credentials are never written to log files in plain text. Passwords visible in the UI are masked with `*`. Password entry fields are scrubbed (cleared) from memory immediately after use.

---

## 7. Output Files Reference

| File | Location | Created By |
|------|----------|------------|
| Inventory report | Location you chose at run-time | Inventory tab → Run (Network/LAN/Serial) |
| Individual packing slips | Folder you chose | Packing slip prompt after inventory, or Packing Slip tab |
| Consolidated packing slip | File path you chose | Same as above |
| TDS output files | Location set inside TDS script | TDS tab → Run Diagnostics |
| Run log | `%APPDATA%\ATLAS\logs\ATLAS_YYYY-MM-DD_HH-MM-SS.log` | Automatically on every launch |

### Inventory Report Structure

```
Summary (sheet 1)
  A1: Capture timestamp
  B5/D5: Customer / Project
  Row 10+: # | IP Address | Device Name (hyperlinked to device tab)
  F7: Comma-separated IP list

Device Sheet (one per IP)
  A1: "Back to Summary" hyperlink
  C5: Customer
  C6: Project
  C7: Purchase Order  / D7: Sales Order
  C8: Source (device system name)
  C9: System Type
  Row 15+: Name | Type | Part Number | Serial Number | Description
```

---

## 8. Logs & Troubleshooting

### Log Files

Every ATLAS run writes a timestamped log file to `%APPDATA%\ATLAS\logs\`. Log level detail:

| Level | Content |
|-------|---------|
| INFO | Run start/end, devices found, files saved |
| DEBUG | Every CLI command sent, every response received, all SSH connection events |
| WARNING | SSH key exchange issues, file validation rejections |
| ERROR | Unexpected exceptions |

To open the logs folder: press `Win + R`, type `%APPDATA%\ATLAS\logs`, press Enter.

### Common Issues

**Device shows as "Unreachable" but I can ping it manually**

- Confirm the pod and IP range are set correctly (the prefix is `10.9.<pod>.<last octet>`).
- Ensure the device is on the same network segment as your laptop.
- Check if a firewall or VPN is blocking ICMP.

**Device is reachable but not identified**

- ATLAS attempts SSH banner → SSH login → Telnet fallback. If all three fail the device is skipped.
- Check the terminal output for the specific error (e.g., "Authentication failed", "Connection refused").
- Try LAN mode with the exact IP and credentials to isolate the issue.

**"Authentication failed" for every device**

- All three default credentials have been tried and failed.
- The Credential Prompt will appear. Enter the correct credentials and check **Save for future runs**.

**Output Excel file will not open**

- Check the logs for an export error.
- Ensure the file is not already open in Excel (Excel locks the file for writing).
- Try a different save location (avoid network shares for first runs).

**Packing slips show "TBD" for PO/SO**

- Normal when no PO/SO was entered at the project information popup.
- Re-run and fill in the fields, or edit the cells in the generated file directly.

**TDS button is disabled / grayed out**

- TDS will not run if a required field is blank or if the SSH host key verification failed.
- Check that all four fields (IP, platform, username, password) are filled.
- If the host-key dialog appeared and you clicked Cancel, re-run and accept the key.

---

## 9. Supported Devices Quick-Reference

| Device | Auto-ID? | Connection | Script Used |
|--------|----------|------------|-------------|
| Nokia 7705 SAR-8 v2 | ✅ Yes | SSH | Nokia_SAR.py |
| Nokia 7250 IXR-R6 | ✅ Yes | SSH | Nokia_IXR.py |
| Nokia 7250 IXR-R6d | ✅ Yes | SSH | Nokia_IXR.py |
| Nokia 1830 | ✅ Yes | SSH → Telnet | Nokia_1830.py |
| Nokia 1830 PSI | ⚠️ Partial | SSH → Telnet | Nokia_PSI.py |
| Ciena 6500 | ✅ Yes | SSH → Telnet | Ciena_6500.py |
| Ciena RLS | ⚠️ Partial | SSH → Telnet | Ciena_RLS.py |
| Smartoptics DCP-R | ✅ Yes | SSH | Smartoptics_DCP.py |
| Smartoptics DCP-2 | ✅ Yes | SSH | Smartoptics_DCP.py |

**⚠️ Partial** = The device can be connected to and identified, but some data fields may be incomplete pending full pipeline integration in a future release.

---

*For developer documentation, architecture details, and bug fix history see [ATLAS_Development_Document.docx](ATLAS_Development_Document.docx) and [INVENTORY_LOGIC_FLOW.md](INVENTORY_LOGIC_FLOW.md).*
