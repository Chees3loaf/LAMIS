from datetime import datetime
import os
import logging
import re
import shutil
import sqlite3
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from queue import Empty, Queue
from tkinter import filedialog
from typing import Dict
import time
from pathlib import Path
import openpyxl
from openpyxl.utils import get_column_letter
from openpyxl.styles import Font, PatternFill
import pandas as pd
import script_interface
import csv

command_tracker = script_interface.CommandTracker()
db_cache = script_interface.get_cache()
DATA_DIR = Path(script_interface.get_inventory_db_path()).resolve().parent
# Configure logging with a debug flag
debug_mode = False  # Toggle this for verbose logging
logging.basicConfig(level=logging.DEBUG if debug_mode else logging.INFO)

class InventoryGUI:
    def __init__(self, root, update_available, command_tracker, db_cache):
        self.root = root
        self.update_available = update_available
        self.command_tracker = command_tracker
        self.db_cache = db_cache
        self.outputs = {}
        self.task_queue = Queue()
        self.stop_threads = False
        self.is_paused = False
        self.save_location = None
        self.run_queue = Queue()
        self.run_thread = None
        self.run_context = None
        self.export_thread = None
        self._stdout_original = sys.stdout
        self.db_file = str(DATA_DIR / "network_inventory.db")
        self.current_script_instance = None
        self.current_mode = tk.StringVar(value="inventory")
        self.output_screen = None
        self.inventory_report_path = None

        # Packing slip from file specific variables
        self.uploaded_file_path = None
        self.uploaded_file_data = None

        if os.path.isfile(self.db_file):
            if self.db_cache.db_path != self.db_file:
                logging.warning(f"[DB] Fixing db_cache path from {self.db_cache.db_path} to {self.db_file}")
                self.db_cache.db_path = self.db_file
                try:
                    self.db_cache.cache.clear()
                except Exception:
                    pass
        else:
            logging.error(f"[DB] Expected DB file not found: {self.db_file}")
        self.template_path = str(DATA_DIR / "Device_Report_Template.xlsx")
        self.packing_slip_template = str(DATA_DIR / "LAMIS_Packing_Slip.xlsx")
        self.lock = threading.Lock()

        # Setup GUI Components
        self.setup_gui()

        # Initialize ScrolledText for Output at the bottom
        self.output_screen = scrolledtext.ScrolledText(self.root, height=8, width=120)
        self.output_screen.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.output_screen.insert(tk.END, "Lightriver Automated Multivendor Inventory System Started\n")
        self.output_screen.insert(tk.END, "Select mode above to begin\n")

    def setup_gui(self):
        self.root.title("Lightriver Automated Multivendor Inventory System")
        self.root.geometry('900x750')
        
        # Top frame: Mode selector
        mode_frame = ttk.LabelFrame(self.root, text="Select Mode")
        mode_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Radiobutton(mode_frame, text="Inventory (Network Scan)", variable=self.current_mode, value="inventory", command=self.switch_mode).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="TDS (Diagnostics)", variable=self.current_mode, value="tds", command=self.switch_mode).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="Packing Slip (From File)", variable=self.current_mode, value="packing_slip", command=self.switch_mode).pack(side=tk.LEFT, padx=10)
        
        # Container frame for all mode frames
        self.content_frame = ttk.Frame(self.root)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create frames for each mode
        self.inventory_frame = None
        self.tds_frame = None
        self.packing_slip_frame = None
        
        self.build_inventory_frame()
        self.build_tds_frame()
        self.build_packing_slip_frame()
        
        # Show the initial frame
        self.switch_mode()

    def switch_mode(self):
        """Hide all frames and show the selected one."""
        mode = self.current_mode.get()
        
        if self.inventory_frame:
            self.inventory_frame.pack_forget()
        if self.tds_frame:
            self.tds_frame.pack_forget()
        if self.packing_slip_frame:
            self.packing_slip_frame.pack_forget()
        
        if mode == "inventory":
            self.inventory_frame.pack(fill=tk.BOTH, expand=True)
        elif mode == "tds":
            self.tds_frame.pack(fill=tk.BOTH, expand=True)
        elif mode == "packing_slip":
            self.packing_slip_frame.pack(fill=tk.BOTH, expand=True)

    def build_inventory_frame(self):
        """Build the Inventory scanning frame."""
        self.inventory_frame = ttk.Frame(self.content_frame)
        
        # Connection Type
        connection_frame = ttk.LabelFrame(self.inventory_frame, text="Connection Type")
        connection_frame.pack(fill=tk.X, pady=5)
        self.connection_type = tk.StringVar(value="Network")
        tk.Radiobutton(connection_frame, text="Network", variable=self.connection_type, value="Network").pack(side=tk.LEFT, padx=10)

        report_frame = ttk.LabelFrame(self.inventory_frame, text="Device Report (Optional)")
        report_frame.pack(fill=tk.X, pady=5)
        self.inventory_file_label = tk.Label(report_frame, text="No report selected (new workbook will be created)", foreground="gray")
        self.inventory_file_label.pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(report_frame, text="Browse", command=self.upload_inventory_report).pack(side=tk.LEFT, padx=5)
        tk.Button(report_frame, text="Clear", command=self.clear_inventory_report_upload).pack(side=tk.LEFT, padx=5)

        # Middle section with Pod and IP Selections
        middle_frame = ttk.Frame(self.inventory_frame)
        middle_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=20)

        left_middle_frame = ttk.Frame(middle_frame)
        left_middle_frame.pack(side=tk.LEFT, expand=True, padx=10, pady=20)

        right_middle_frame = ttk.Frame(middle_frame)
        right_middle_frame.pack(side=tk.RIGHT, expand=True, padx=10, pady=20)

        pod_options = [f"{100 + i}" for i in range(0, 13)]
        
        # Pod Selection 1 (Left)
        pod_frame_1 = ttk.LabelFrame(left_middle_frame, text="Pod Selection 1")
        pod_frame_1.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(pod_frame_1, text="Pod:").pack(side=tk.LEFT, padx=5)
        self.pod_var_1 = tk.StringVar()
        self.pod_combobox_1 = ttk.Combobox(pod_frame_1, textvariable=self.pod_var_1, values=pod_options)
        self.pod_combobox_1.pack(side=tk.LEFT, padx=5)
        self.pod_combobox_1.set('100')
        
        # IP Selection 1
        ip_frame_1 = ttk.LabelFrame(left_middle_frame, text="IP Selection 1")
        ip_frame_1.pack(fill=tk.X, padx=10, pady=5)
        ip_container_1 = ttk.Frame(ip_frame_1)
        ip_container_1.pack()
        self.start_ip_label_1 = tk.Label(ip_container_1, text=f"Start IP: 10.9.{self.pod_var_1.get()}.")
        self.start_ip_label_1.pack(side=tk.LEFT)
        self.start_ip_entry_1 = tk.Entry(ip_container_1, width=3, justify='center')
        self.start_ip_entry_1.pack(side=tk.LEFT)
        self.end_ip_label_1 = tk.Label(ip_container_1, text=f"End IP: 10.9.{self.pod_var_1.get()}.")
        self.end_ip_label_1.pack(side=tk.LEFT)
        self.end_ip_entry_1 = tk.Entry(ip_container_1, width=3, justify='center')
        self.end_ip_entry_1.pack(side=tk.LEFT)
        self.pod_var_1.trace_add("write", lambda *args: self.update_ip_labels(self.pod_var_1, self.start_ip_label_1, self.end_ip_label_1))

        # Pod Selection 2 (Right)
        pod_frame_2 = ttk.LabelFrame(right_middle_frame, text="Pod Selection 2")
        pod_frame_2.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(pod_frame_2, text="Pod:").pack(side=tk.LEFT, padx=5)
        self.pod_var_2 = tk.StringVar()
        self.pod_combobox_2 = ttk.Combobox(pod_frame_2, textvariable=self.pod_var_2, values=pod_options)
        self.pod_combobox_2.pack(side=tk.LEFT, padx=5)
        self.pod_combobox_2.set('100')
        
        # IP Selection 2
        ip_frame_2 = ttk.LabelFrame(right_middle_frame, text="IP Selection 2")
        ip_frame_2.pack(fill=tk.X, padx=10, pady=5)
        ip_container_2 = ttk.Frame(ip_frame_2)
        ip_container_2.pack()
        self.start_ip_label_2 = tk.Label(ip_container_2, text=f"Start IP: 10.9.{self.pod_var_2.get()}.")
        self.start_ip_label_2.pack(side=tk.LEFT)
        self.start_ip_entry_2 = tk.Entry(ip_container_2, width=3, justify='center')
        self.start_ip_entry_2.pack(side=tk.LEFT)
        self.end_ip_label_2 = tk.Label(ip_container_2, text=f"End IP: 10.9.{self.pod_var_2.get()}.")
        self.end_ip_label_2.pack(side=tk.LEFT)
        self.end_ip_entry_2 = tk.Entry(ip_container_2, width=3, justify='center')
        self.end_ip_entry_2.pack(side=tk.LEFT)
        self.pod_var_2.trace_add("write", lambda *args: self.update_ip_labels(self.pod_var_2, self.start_ip_label_2, self.end_ip_label_2))
        
        # Control frame for inventory
        control_frame = ttk.Frame(self.inventory_frame)
        control_frame.pack(fill=tk.X, pady=10)

        # Right side: Action buttons
        self.run_button = tk.Button(control_frame, text="Run", command=self.run_script)
        self.run_button.pack(side=tk.RIGHT, padx=5)
        self.pause_button = tk.Button(control_frame, text="Pause", command=self.pause_program, state=tk.DISABLED)
        self.pause_button.pack(side=tk.RIGHT, padx=5)
        self.abort_button = tk.Button(control_frame, text="Abort", command=self.abort_program, state=tk.DISABLED)
        self.abort_button.pack(side=tk.RIGHT, padx=5)

        # Status label
        self.status_label = tk.Label(control_frame, text="Status: Ready", anchor="w")
        self.status_label.pack(side=tk.RIGHT, padx=10)

    def build_tds_frame(self):
        """Build the TDS diagnostics frame."""
        self.tds_frame = ttk.Frame(self.content_frame)
        
        # TDS configuration
        config_frame = ttk.LabelFrame(self.tds_frame, text="TDS Configuration")
        config_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(config_frame, text="IP Address:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.tds_ip_entry = tk.Entry(config_frame, width=25)
        self.tds_ip_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(config_frame, text="Platform (6500/rls):").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.tds_platform_var = tk.StringVar(value="rls")
        self.tds_platform_combo = ttk.Combobox(config_frame, textvariable=self.tds_platform_var, values=["rls", "6500"], width=10, state="readonly")
        self.tds_platform_combo.grid(row=0, column=3, padx=5, pady=5)

        tk.Label(config_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.tds_username_entry = tk.Entry(config_frame, width=25)
        self.tds_username_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(config_frame, text="Password:").grid(row=1, column=2, sticky="w", padx=5, pady=5)
        self.tds_password_entry = tk.Entry(config_frame, width=25, show="*")
        self.tds_password_entry.grid(row=1, column=3, padx=5, pady=5)

        tk.Label(config_frame, text="File Name:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.tds_filename_entry = tk.Entry(config_frame, width=25)
        self.tds_filename_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # TDS control frame
        tds_control_frame = ttk.Frame(self.tds_frame)
        tds_control_frame.pack(fill=tk.X, pady=10)
        
        self.tds_run_button = tk.Button(tds_control_frame, text="Run Diagnostics", command=self.run_tds)
        self.tds_run_button.pack(side=tk.RIGHT, padx=5)
        
        self.tds_status_label = tk.Label(tds_control_frame, text="Status: Ready", anchor="w")
        self.tds_status_label.pack(side=tk.RIGHT, padx=10)

    def build_packing_slip_frame(self):
        """Build the Packing Slip frame with file upload."""
        self.packing_slip_frame = ttk.Frame(self.content_frame)
        
        # File upload section
        file_frame = ttk.LabelFrame(self.packing_slip_frame, text="Upload File")
        file_frame.pack(fill=tk.X, pady=5)
        
        self.file_path_label = tk.Label(file_frame, text="No file selected", foreground="gray")
        self.file_path_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.upload_button = tk.Button(file_frame, text="Browse", command=self.upload_file)
        self.upload_button.pack(side=tk.LEFT, padx=5)
        
        # Project information section
        info_frame = ttk.LabelFrame(self.packing_slip_frame, text="Project Information")
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(info_frame, text="Customer:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.ps_customer_entry = tk.Entry(info_frame, width=40)
        self.ps_customer_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(info_frame, text="Project:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.ps_project_entry = tk.Entry(info_frame, width=40)
        self.ps_project_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(info_frame, text="Purchase Order:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.ps_po_entry = tk.Entry(info_frame, width=40)
        self.ps_po_entry.grid(row=2, column=1, padx=5, pady=5)
        
        tk.Label(info_frame, text="Sales Order:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.ps_so_entry = tk.Entry(info_frame, width=40)
        self.ps_so_entry.grid(row=3, column=1, padx=5, pady=5)
        
        # Control frame for packing slip
        ps_control_frame = ttk.Frame(self.packing_slip_frame)
        ps_control_frame.pack(fill=tk.X, pady=10)
        
        self.ps_run_button = tk.Button(ps_control_frame, text="Generate Packing Slips", command=self.generate_packing_slips_from_file)
        self.ps_run_button.pack(side=tk.RIGHT, padx=5)
        
        self.ps_status_label = tk.Label(ps_control_frame, text="Status: Ready", anchor="w")
        self.ps_status_label.pack(side=tk.RIGHT, padx=10)
        
    def update_ip_labels(self, pod_var, start_ip_label, end_ip_label):
        # Update IP labels when the pod selection changes
        pod_number = pod_var.get()
        start_ip_label.config(text=f"Start IP: 10.9.{pod_number}.")
        end_ip_label.config(text=f"End IP: 10.9.{pod_number}.")

    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update_idletasks()

    def set_run_controls(self, running: bool):
        self.run_button.config(state=tk.DISABLED if running else tk.NORMAL)
        pause_abort_state = tk.NORMAL if running else tk.DISABLED
        self.pause_button.config(state=pause_abort_state)
        self.abort_button.config(state=pause_abort_state)

    def autosize_sheet_columns(self, sheet, min_width=10, max_width=60):
        """Auto-size all populated columns in a worksheet with sane bounds."""
        max_col = sheet.max_column or 0
        max_row = sheet.max_row or 0
        if max_col <= 0 or max_row <= 0:
            return

        for col_idx in range(1, max_col + 1):
            longest = 0
            for row_idx in range(1, max_row + 1):
                val = sheet.cell(row=row_idx, column=col_idx).value
                if val is None:
                    continue
                text_len = len(str(val))
                if text_len > longest:
                    longest = text_len

            if longest == 0:
                continue

            width = min(max(longest + 2, min_width), max_width)
            sheet.column_dimensions[get_column_letter(col_idx)].width = width
        
    def combine_and_format_data(self, ip_data: Dict[str, pd.DataFrame]) -> pd.DataFrame:
        all_data = []
        logging.info(f"Starting combination of {len(ip_data)} data entries.")

        for key, value in ip_data.items():
            if isinstance(value, pd.DataFrame):
                all_data.append(value)
                logging.info(f"Processed DataFrame under key '{key}' with {len(value)} rows.")
            elif isinstance(value, dict) and "DataFrame" in value and isinstance(value["DataFrame"], pd.DataFrame):
                df = value["DataFrame"]
                all_data.append(df)
                logging.info(f"Unwrapped DataFrame under key '{key}' with {len(df)} rows.")
            else:
                logging.warning(f"Expected DataFrame under key '{key}' but got {type(value)}. Skipping.")

        if all_data:
            combined_df = pd.concat(all_data, ignore_index=True)
            logging.info(f"Combined DataFrame created with {len(combined_df)} rows from {len(all_data)} DataFrames.")
        else:
            combined_df = pd.DataFrame()
            logging.warning("No data to combine. Returning empty DataFrame.")

        return combined_df

        
    def output_to_excel(self, outputs, output_file, customer="", project="", customer_po="", sales_order=""):
        processed_data = self.build_report_workbook(
            outputs,
            output_file,
            customer=customer,
            project=project,
            customer_po=customer_po,
            sales_order=sales_order,
        )

        user_wants_packing_slips = messagebox.askyesno(
            "Success",
            f"Report saved successfully as:\n{output_file}\n\nDo you need packing slips?"
        )

        if user_wants_packing_slips:
            logging.info("User requested packing slips. Generating now...")
            self.generate_packing_slips(
                processed_data,
                output_file,
                list(outputs.keys()),
                customer,
                project,
                customer_po,
                sales_order
            )
        else:
            logging.info("User skipped packing slip generation.")

    def build_report_workbook(self, outputs, output_file, customer="", project="", customer_po="", sales_order="", append_mode=False):
        if getattr(self, "_export_running", False):
            raise RuntimeError("Export already running")
        self._export_running = True

        logging.info("Starting Excel export process...")
        try:
            def clean_str(v: object) -> str:
                if v is None:
                    return ""
                s = str(v).strip()
                return "" if s.lower() == "nan" else s

            def nonempty_col(col):
                if col is None:
                    return None
                s = col.astype(str).str.strip()
                return s.ne("") & s.str.lower().ne("nan")

            def first_nonempty(series, fallback=""):
                if series is None:
                    return fallback
                for v in series:
                    s = clean_str(v)
                    if s:
                        return s
                return fallback

            if not os.path.exists(self.template_path):
                raise FileNotFoundError(f"Template file not found at {self.template_path}")

            if append_mode:
                if not os.path.exists(output_file):
                    raise FileNotFoundError(f"Existing report file not found at {output_file}")
                wb = openpyxl.load_workbook(output_file)
                sheet = None
            else:
                wb = openpyxl.load_workbook(self.template_path)
                sheet = wb.active

            template_wb = openpyxl.load_workbook(self.template_path)
            template_sheet = template_wb.active

            def extract_ip_sort_key(value):
                s = str(value or "").strip()
                match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", s)
                if not match:
                    return (1, s.lower())

                ip = match.group(1)
                try:
                    octets = [int(x) for x in ip.split(".")]
                except ValueError:
                    return (1, s.lower())

                if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
                    return (1, s.lower())

                return (0, octets[0], octets[1], octets[2], octets[3], s.lower())

            db_exists = os.path.isfile(self.db_cache.db_path)
            logging.info(f"[EXCEL] Using DB cache path: {self.db_cache.db_path} (exists={db_exists})")
            logging.info(f"Starting Excel export for {len(outputs)} devices.")

            processed_data = {}
            summary_index = {}

            if "Summary" in wb.sheetnames:
                summary_sheet = wb["Summary"]
            else:
                summary_sheet = wb.create_sheet(title="Summary", index=0)

            if append_mode:
                for row_num in range(10, summary_sheet.max_row + 1):
                    existing_ip = summary_sheet[f"C{row_num}"].value
                    existing_name = summary_sheet[f"D{row_num}"].value
                    if existing_ip is None or existing_name is None:
                        continue

                    existing_ip_str = str(existing_ip).strip()
                    existing_name_str = str(existing_name).strip()
                    if not existing_ip_str:
                        continue

                    sheet_title = None
                    if summary_sheet[f"D{row_num}"].hyperlink and summary_sheet[f"D{row_num}"].hyperlink.target:
                        target = summary_sheet[f"D{row_num}"].hyperlink.target
                        match = re.match(r"#'(.+)'!", str(target))
                        if match:
                            sheet_title = match.group(1)

                    if sheet_title and sheet_title in wb.sheetnames:
                        summary_index[existing_ip_str] = (existing_name_str, sheet_title)

            summary_sheet["B5"] = "Customer"
            summary_sheet["B7"] = customer or ""
            summary_sheet["D5"] = "Project"
            summary_sheet["D7"] = project or ""
            capture_time = datetime.now().strftime('%Y-%m-%d @ %H:%M:%S')
            summary_sheet["A1"] = f"Capture Time = {capture_time}"
            summary_sheet["A1"].font = Font(color="00FF00", bold=True)
            summary_sheet["A1"].fill = PatternFill(start_color="000000", end_color="000000", fill_type="solid")
            summary_sheet["B9"] = "#"
            summary_sheet["C9"] = "IP Address"
            summary_sheet["D9"] = "Device Name"

            def make_unique_sheet_title(base_name):
                clean_base = re.sub(r'[^a-zA-Z0-9_]', '_', str(base_name).strip())[:31]
                if not clean_base:
                    clean_base = "Device"

                if clean_base not in wb.sheetnames:
                    return clean_base

                counter = 2
                while True:
                    suffix = f"_{counter}"
                    candidate = f"{clean_base[:31 - len(suffix)]}{suffix}"
                    if candidate not in wb.sheetnames:
                        return candidate
                    counter += 1

            ordered_outputs = sorted(outputs.items(), key=lambda item: extract_ip_sort_key(item[0]))
            for seq, (ip, data_dict) in enumerate(ordered_outputs, start=1):
                try:
                    logging.info(f"Processing data for IP {ip}.")
                    combined_df = self.combine_and_format_data(data_dict)
                    if combined_df.empty:
                        logging.warning(f"No data to write for IP {ip}")
                        continue

                    system_name = clean_str(first_nonempty(
                        combined_df.get("System Name"),
                        f"System_{ip.replace('.', '_')}"
                    ))[:31].replace(":", "_").replace("/", "_")

                    system_type = clean_str(first_nonempty(combined_df.get("System Type"), ""))
                    if not system_type:
                        system_type = clean_str(first_nonempty(combined_df.get("Type"), ""))
                    system_type = system_type[:31].replace(":", "_").replace("/", "_")

                    source_val = clean_str(first_nonempty(combined_df.get("Source"), ""))

                    logging.info(f"Creating sheet for system '{system_name}' with {len(combined_df)} rows.")
                    ip_key = str(ip)
                    if append_mode and ip_key in summary_index:
                        prior_sheet_title = summary_index[ip_key][1]
                        if prior_sheet_title in wb.sheetnames and prior_sheet_title != summary_sheet.title:
                            del wb[prior_sheet_title]

                    new_sheet_title = make_unique_sheet_title(system_name)
                    if append_mode:
                        new_sheet = self.copy_sheet(template_sheet, wb, new_sheet_title)
                    else:
                        new_sheet = wb.copy_worksheet(sheet)
                        new_sheet.title = new_sheet_title

                    # Add quick navigation back to summary for easier review workflow.
                    new_sheet["A1"] = "Back to Summary"
                    new_sheet["A1"].hyperlink = f"#'{summary_sheet.title}'!A1"
                    new_sheet["A1"].style = "Hyperlink"

                    new_sheet["C5"] = customer
                    new_sheet["C6"] = project
                    new_sheet["C7"] = customer_po
                    new_sheet["D7"] = sales_order
                    new_sheet["F5"] = source_val
                    new_sheet["F6"] = system_name
                    new_sheet["F7"] = system_type

                    has_part = combined_df.get("Part Number")
                    has_model = combined_df.get("Model Number")

                    mask_part = nonempty_col(has_part)
                    mask_model = nonempty_col(has_model)

                    if mask_part is not None and mask_model is not None:
                        write_df = combined_df[mask_part | mask_model].copy()
                    elif mask_part is not None:
                        write_df = combined_df[mask_part].copy()
                    elif mask_model is not None:
                        write_df = combined_df[mask_model].copy()
                    else:
                        write_df = combined_df.iloc[0:0].copy()

                    start_row = 15
                    for i, row in write_df.reset_index(drop=True).iterrows():
                        row_num = start_row + i

                        part_number = clean_str(row.get("Part Number", "")) or clean_str(row.get("Model Number", ""))
                        info_type = clean_str(row.get("Information Type", "")).lower()
                        name_value = clean_str(row.get("Name", ""))

                        if "mda card" in info_type:
                            match = re.search(r"\d+", name_value)
                            mda_number = match.group() if match else "Unknown"
                            name_value = f"MDA {mda_number}"

                        type_value = clean_str(row.get("Type", ""))
                        serial_val = clean_str(row.get("Serial Number", ""))

                        if not any([name_value, type_value, part_number, serial_val]):
                            continue

                        description = ""
                        if part_number and db_exists:
                            description = self.db_cache.lookup_part(part_number[:10])
                            if not description or description == "Not Found":
                                try:
                                    with sqlite3.connect(self.db_cache.db_path) as tmpconn:
                                        tcur = tmpconn.cursor()
                                        tcur.execute(
                                            "SELECT description FROM parts WHERE part_number LIKE ?",
                                            (part_number[:10] + "%",),
                                        )
                                        res = tcur.fetchone()
                                        if res:
                                            description = res[0]
                                except Exception as exc:
                                    logging.debug(f"[EXCEL] Fallback DB lookup failed: {exc}")

                        new_sheet[f"B{row_num}"] = name_value
                        new_sheet[f"C{row_num}"] = type_value
                        new_sheet[f"D{row_num}"] = part_number
                        new_sheet[f"E{row_num}"] = serial_val
                        new_sheet[f"F{row_num}"] = description
                        write_df.at[row.name, "Description"] = description

                    self.autosize_sheet_columns(new_sheet)

                    processed_data[ip] = write_df
                    summary_index[str(ip)] = (system_name, new_sheet.title)
                except Exception as exc:
                    logging.error(f"Failed to process data for IP {ip}. Error: {exc}")

            if summary_sheet.max_row >= 10:
                for row_num in range(10, summary_sheet.max_row + 1):
                    summary_sheet[f"B{row_num}"] = None
                    summary_sheet[f"C{row_num}"] = None
                    summary_sheet[f"D{row_num}"] = None

            summary_start_row = 10
            ordered_summary_items = sorted(summary_index.items(), key=lambda item: extract_ip_sort_key(item[0]))
            summary_sheet["F5"] = "IP Addresses"
            summary_sheet["F7"] = ", ".join([item[0] for item in ordered_summary_items])

            for row_offset, (ip, (device_name, sheet_title)) in enumerate(ordered_summary_items):
                row_num = summary_start_row + row_offset
                summary_sheet[f"B{row_num}"] = row_offset + 1
                summary_sheet[f"C{row_num}"] = str(ip)
                summary_sheet[f"D{row_num}"] = str(device_name)
                summary_sheet[f"D{row_num}"].hyperlink = f"#'{sheet_title}'!A1"
                summary_sheet[f"D{row_num}"].style = "Hyperlink"

            self.autosize_sheet_columns(summary_sheet)

            if not append_mode and len(wb.sheetnames) > 1 and sheet and sheet.title in wb.sheetnames:
                wb.remove(sheet)

            # Keep tabs ordered by IP sequence, with Summary first.
            ordered_device_tabs = [sheet_title for _, (_, sheet_title) in ordered_summary_items if sheet_title in wb.sheetnames]
            pinned_tabs = [summary_sheet.title] + ordered_device_tabs
            remaining_tabs = [name for name in wb.sheetnames if name not in pinned_tabs]
            ordered_tabs = pinned_tabs + remaining_tabs
            wb._sheets = [wb[name] for name in ordered_tabs]

            save_dir = os.path.dirname(output_file)
            os.makedirs(save_dir, exist_ok=True)
            wb.save(output_file)
            logging.info(f"Data successfully saved to {output_file}")
            template_wb.close()
            return processed_data
        finally:
            self._export_running = False


    def copy_sheet(self, source_sheet, target_wb, new_sheet_name):
    
        # Copies an entire sheet from one workbook to another while preserving formatting.
        
        new_sheet = target_wb.create_sheet(title=new_sheet_name)

        for row in source_sheet.iter_rows():
            for cell in row:
                new_sheet[cell.coordinate].value = cell.value  # Copy cell values

                # Copy formatting
                if cell.has_style:
                    new_sheet[cell.coordinate].font = cell.font
                    new_sheet[cell.coordinate].border = cell.border
                    new_sheet[cell.coordinate].fill = cell.fill
                    new_sheet[cell.coordinate].number_format = cell.number_format
                    new_sheet[cell.coordinate].protection = cell.protection
                    new_sheet[cell.coordinate].alignment = cell.alignment

        return new_sheet


    def generate_packing_slips(self, processed_data, file_path, ip_list, customer, project, customer_po, sales_order):
        save_folder = filedialog.askdirectory(title="Select Packing Slip Save Location")
        if not save_folder:
            save_folder = os.getcwd()

        save_path = self.build_packing_slip_workbook(
            processed_data,
            ip_list,
            customer,
            project,
            customer_po,
            sales_order,
            save_folder,
        )
        messagebox.showinfo("Success", f"Packing slips saved to:\n{save_path}")

    def build_packing_slip_workbook(self, processed_data, ip_list, customer, project, customer_po, sales_order, save_folder):
        packing_template_path = self.packing_slip_template
        logging.info(f"Loading packing slip template: {packing_template_path}")

        if not os.path.exists(packing_template_path):
            raise FileNotFoundError(f"Packing slip template not found at: {packing_template_path}")

        temp_packing_slip = os.path.join(os.getcwd(), "PackingSlip_Temp.xlsx")
        shutil.copy(packing_template_path, temp_packing_slip)

        try:
            wb_final = openpyxl.load_workbook(temp_packing_slip)

            if "Packing Slip" not in wb_final.sheetnames:
                raise ValueError(f"'Packing Slip' template sheet not found. Available: {wb_final.sheetnames}")

            template_sheet = wb_final["Packing Slip"]
            summary_sheet = None
            for name in wb_final.sheetnames:
                if "summary" in name.lower():
                    summary_sheet = wb_final[name]
                    break

            if not summary_sheet:
                raise ValueError(f"No summary sheet found. Available: {wb_final.sheetnames}")

            timestamp = datetime.now().strftime('%Y-%m-%d')
            safe_customer = re.sub(r'[^a-zA-Z0-9_]', '_', (customer or "Unknown").strip())
            safe_project = re.sub(r'[^a-zA-Z0-9_]', '_', (project or "Unknown").strip())

            filename = f"PackingSlip_{safe_customer}_{safe_project}_{timestamp}.xlsx"
            save_path = os.path.join(save_folder, filename)

            logging.info(f"Packing slips will be saved as: {save_path}")

            summary_sheet["B5"] = "Customer"
            summary_sheet["B7"] = customer or ""
            summary_sheet["D5"] = "Project"
            summary_sheet["D7"] = project or ""
            capture_time = datetime.now().strftime('%Y-%m-%d @ %H:%M:%S')
            summary_sheet["A1"] = f"Capture Time = {capture_time}"
            summary_sheet["A1"].font = Font(color="00FF00", bold=True)
            summary_sheet["A1"].fill = PatternFill(start_color="000000", end_color="000000", fill_type="solid")
            summary_sheet["F5"] = "IP Addresses"
            summary_sheet["F7"] = ", ".join(ip_list)

            def extract_ip_sort_key(value):
                s = str(value or "").strip()
                match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", s)
                if not match:
                    return (1, s.lower())

                ip = match.group(1)
                try:
                    octets = [int(x) for x in ip.split(".")]
                except ValueError:
                    return (1, s.lower())

                if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
                    return (1, s.lower())

                return (0, octets[0], octets[1], octets[2], octets[3], s.lower())

            ordered_items = sorted(processed_data.items(), key=lambda item: extract_ip_sort_key(item[0]))
            summary_sheet["B9"] = "#"
            summary_sheet["C9"] = "IP / Device ID"
            summary_sheet["D9"] = "Device Name"

            summary_start_row = 10
            summary_rows = []

            logging.info(f"Generating packing slips for {len(processed_data)} device(s)")

            for seq, (ip, device_data) in enumerate(ordered_items, start=1):
                if device_data.empty:
                    logging.warning(f"No data for {ip} - skipping")
                    continue

                logging.info(f"Columns for {ip}: {list(device_data.columns)}")

                try:
                    device_name = "Unknown_Device"
                    for col in device_data.columns:
                        if any(x in col.lower() for x in ["system name", "name"]):
                            device_name = str(device_data.iloc[0].get(col, "Unknown_Device"))
                            break

                    device_name_clean = re.sub(r'[^a-zA-Z0-9_]', '_', device_name.strip())[:31]

                    new_sheet = wb_final.copy_worksheet(template_sheet)
                    new_sheet.title = device_name_clean

                    # Add quick navigation back to summary for easier review workflow.
                    new_sheet["A1"] = "Back to Summary"
                    new_sheet["A1"].hyperlink = f"#'{summary_sheet.title}'!A1"
                    new_sheet["A1"].style = "Hyperlink"

                    for merged in template_sheet.merged_cells.ranges:
                        new_sheet.merge_cells(str(merged))

                    new_sheet["B5"] = "Customer"
                    new_sheet["C5"] = customer or ""
                    new_sheet["B6"] = "Project"
                    new_sheet["C6"] = project or ""
                    new_sheet["B7"] = "Device ID"
                    new_sheet["C7"] = device_name
                    new_sheet["B14"] = "Sales Order"
                    new_sheet["B15"] = sales_order or ""
                    new_sheet["C14"] = "Customer PO"
                    new_sheet["C15"] = customer_po or ""

                    start_row = 15
                    for idx, row_dict in enumerate(device_data.to_dict('records')):
                        row_num = start_row + idx

                        part_number = str(row_dict.get("Part Number", "")).strip()
                        serial_number = str(row_dict.get("Serial Number", "")).strip()
                        description = str(row_dict.get("Description", "")).strip()

                        if not part_number:
                            part_number = str(row_dict.get("Model Number", "")).strip()

                        if part_number.lower() in ("nan", ""):
                            part_number = ""
                        if serial_number.lower() in ("nan", ""):
                            serial_number = ""
                        if description.lower() in ("nan", ""):
                            description = ""

                        if part_number or serial_number or description:
                            new_sheet[f"B{row_num}"] = sales_order or ""
                            new_sheet[f"C{row_num}"] = customer_po or ""
                            new_sheet[f"D{row_num}"] = part_number
                            new_sheet[f"E{row_num}"] = serial_number
                            new_sheet[f"F{row_num}"] = description

                    self.autosize_sheet_columns(new_sheet)

                    summary_rows.append((seq, ip, device_name, new_sheet.title))

                    logging.debug(f"Written {len(device_data)} line items for device '{device_name}' with SO/PO")
                except Exception as exc:
                    logging.error(f"Error creating sheet for {ip}: {exc}")

            for row_offset, (seq, ip, device_name, sheet_title) in enumerate(summary_rows):
                row_num = summary_start_row + row_offset
                summary_sheet[f"B{row_num}"] = seq
                summary_sheet[f"C{row_num}"] = str(ip)
                summary_sheet[f"D{row_num}"] = str(device_name)
                summary_sheet[f"D{row_num}"].hyperlink = f"#'{sheet_title}'!A1"
                summary_sheet[f"D{row_num}"].style = "Hyperlink"

            self.autosize_sheet_columns(summary_sheet)

            if summary_sheet.title in wb_final.sheetnames:
                idx = wb_final.sheetnames.index(summary_sheet.title)
                wb_final._sheets.insert(0, wb_final._sheets.pop(idx))

            if "Packing Slip" in wb_final.sheetnames:
                del wb_final["Packing Slip"]

            wb_final.save(save_path)
            logging.info(f"Packing slips saved successfully: {save_path}")
            return save_path
        finally:
            if os.path.exists(temp_packing_slip):
                try:
                    os.remove(temp_packing_slip)
                except OSError:
                    pass
    
    def upload_file(self):
        """Handle file upload for packing slip generation."""
        file_path = filedialog.askopenfilename(
            title="Select File (CSV or Excel)",
            filetypes=[("Excel files", "*.xlsx *.xls"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            self.uploaded_file_path = file_path
            
            # Try to read the file
            if file_path.endswith('.csv'):
                self.uploaded_file_data = pd.read_csv(file_path)
            elif file_path.endswith(('.xlsx', '.xls')):
                self.uploaded_file_data = pd.read_excel(file_path)
            else:
                messagebox.showerror("File Error", "Unsupported file format. Please use CSV or Excel files.")
                return
            
            # Show success
            file_name = os.path.basename(file_path)
            self.file_path_label.config(text=f"✓ {file_name} ({len(self.uploaded_file_data)} rows)", foreground="green")
            self.output_screen.insert(tk.END, f"Loaded file: {file_name} with {len(self.uploaded_file_data)} rows\n")
            self.output_screen.see(tk.END)
            logging.info(f"File uploaded: {file_path} with {len(self.uploaded_file_data)} rows")
            
        except Exception as e:
            messagebox.showerror("File Error", f"Failed to load file:\n{str(e)}")
            logging.error(f"File upload error: {e}")

    def upload_inventory_report(self):
        """Handle inventory report upload for append mode."""
        file_path = filedialog.askopenfilename(
            title="Select Existing Device Report",
            filetypes=[("Excel files", "*.xlsx *.xls"), ("All files", "*.*")]
        )

        if not file_path:
            return

        self.inventory_report_path = file_path
        file_name = os.path.basename(file_path)
        self.inventory_file_label.config(text=f"Using existing report: {file_name}", foreground="green")
        self.output_screen.insert(tk.END, f"Inventory append mode enabled: {file_name}\n")
        self.output_screen.see(tk.END)
        logging.info(f"Inventory report selected for append: {file_path}")

    def clear_inventory_report_upload(self):
        """Clear inventory report upload selection and revert to new workbook mode."""
        self.inventory_report_path = None
        self.inventory_file_label.config(text="No report selected (new workbook will be created)", foreground="gray")
        self.output_screen.insert(tk.END, "Inventory append mode disabled; a new report will be created.\n")
        self.output_screen.see(tk.END)

    def generate_packing_slips_from_file(self):
        """Generate packing slips from uploaded file."""
        if self.uploaded_file_data is None:
            messagebox.showwarning("No File", "Please upload a file first.")
            return
        
        # Get project information
        customer = self.ps_customer_entry.get().strip()
        project = self.ps_project_entry.get().strip()
        customer_po = self.ps_po_entry.get().strip()
        sales_order = self.ps_so_entry.get().strip()
        
        if not all([customer, project, customer_po, sales_order]):
            messagebox.showerror("Missing Info", "Please fill in all project information fields.")
            return
        
        # Ask for save location
        save_folder = filedialog.askdirectory(title="Select Packing Slip Save Location")
        if not save_folder:
            return
        
        self.ps_status_label.config(text="Status: Processing...")
        self.root.update_idletasks()
        
        try:
            # Convert uploaded data to packing slip format
            processed_data = self._process_file_for_packing_slip(self.uploaded_file_data)
            
            if not processed_data:
                messagebox.showwarning("No Data", "No valid data found in the file.")
                return
            
            # Generate packing slips
            ip_list = list(processed_data.keys())
            save_path = self.build_packing_slip_workbook(
                processed_data,
                ip_list,
                customer,
                project,
                customer_po,
                sales_order,
                save_folder,
            )
            
            self.ps_status_label.config(text="Status: Ready")
            messagebox.showinfo("Success", f"Packing slips saved to:\n{save_path}")
            self.output_screen.insert(tk.END, f"Packing slips generated successfully: {save_path}\n")
            self.output_screen.see(tk.END)
            
        except Exception as e:
            self.ps_status_label.config(text="Status: Error")
            messagebox.showerror("Generation Error", f"Failed to generate packing slips:\n{str(e)}")
            logging.error(f"Packing slip generation error: {e}")

    def _process_file_for_packing_slip(self, df):
        """Convert uploaded file data to packing slip format."""
        processed_data = {}
        
        try:
            # Normalize column names to lowercase for easier matching
            df_lower = df.copy()
            df_lower.columns = [str(col).lower() for col in df.columns]
            
            # Group by device/IP if there's a column for it, otherwise treat as single device
            device_key = None
            for col in df_lower.columns:
                if any(x in col for x in ["device", "ip", "system name", "name"]):
                    device_key = col
                    break
            
            if device_key and df_lower[device_key].nunique() > 1:
                # Multiple devices
                for device_id, device_group in df_lower.groupby(device_key, sort=False):
                    processed_data[str(device_id)] = device_group.reset_index(drop=True)
            else:
                # Single device or no grouping needed
                processed_data["Device_0"] = df_lower.reset_index(drop=True)
            
            return processed_data
            
        except Exception as e:
            logging.error(f"Error processing file: {e}")
            raise

    def run_tds(self):
        """Run TDS diagnostics for a specific device."""
        ip = self.tds_ip_entry.get().strip()
        platform = (self.tds_platform_var.get() or "rls").strip().lower()
        username = self.tds_username_entry.get().strip()
        password = self.tds_password_entry.get()
        file_name = self.tds_filename_entry.get().strip()
        
        if not ip:
            messagebox.showerror("Input Error", "Please enter a device IP address.")
            return
        if platform not in ("6500", "rls"):
            messagebox.showerror("Input Error", "Platform must be either 6500 or rls.")
            return
        if not username:
            messagebox.showerror("Input Error", "Please enter a username.")
            return
        if not password:
            messagebox.showerror("Input Error", "Please enter a password.")
            return
        if not file_name:
            messagebox.showerror("Input Error", "Please enter a file name.")
            return

        tds_script_path = os.path.join(os.path.dirname(__file__), "..", "scripts", "TDS", "TDS_v6.2.py")
        tds_script_path = os.path.normpath(tds_script_path)
        if not os.path.isfile(tds_script_path):
            messagebox.showerror("TDS Error", f"TDS script not found:\n{tds_script_path}")
            return

        self.tds_status_label.config(text="Status: Running...")
        self.tds_run_button.config(state=tk.DISABLED)
        self.output_screen.insert(tk.END, f"Starting TDS diagnostics at {ip} (platform={platform})...\n")
        self.output_screen.see(tk.END)

        def tds_worker():
            try:
                command = [
                    sys.executable,
                    tds_script_path,
                    "--non-interactive",
                    "--host",
                    ip,
                    "--platform",
                    platform,
                    "--username",
                    username,
                    "--file-name",
                    file_name,
                ]
                run_env = os.environ.copy()
                run_env["TDS_PASSWORD"] = password

                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    cwd=os.path.dirname(tds_script_path),
                    env=run_env,
                    timeout=1800,
                )

                combined_output = ""
                if result.stdout:
                    combined_output += result.stdout
                if result.stderr:
                    if combined_output:
                        combined_output += "\n"
                    combined_output += result.stderr

                def on_complete():
                    self.tds_run_button.config(state=tk.NORMAL)
                    self.tds_status_label.config(text="Status: Ready")
                    if combined_output.strip():
                        self.output_screen.insert(tk.END, combined_output + "\n")
                        self.output_screen.see(tk.END)
                    if result.returncode == 0:
                        messagebox.showinfo("TDS Complete", "TDS diagnostics completed successfully.")
                    else:
                        messagebox.showerror("TDS Error", f"TDS script exited with code {result.returncode}.")

                self.root.after(0, on_complete)
            except subprocess.TimeoutExpired:
                def on_timeout():
                    self.tds_run_button.config(state=tk.NORMAL)
                    self.tds_status_label.config(text="Status: Timeout")
                    messagebox.showerror("TDS Timeout", "TDS diagnostics timed out after 30 minutes.")

                self.root.after(0, on_timeout)
            except Exception as exc:
                def on_error():
                    self.tds_run_button.config(state=tk.NORMAL)
                    self.tds_status_label.config(text="Status: Error")
                    messagebox.showerror("TDS Error", f"Failed to run TDS script:\n{exc}")

                self.root.after(0, on_error)

        threading.Thread(target=tds_worker, daemon=True).start()

    def get_user_inputs(self, default_filename):
        """Prompt user for project information in a popup"""
        root = tk.Toplevel()  # Create a new popup window
        root.title("User Inputs")

        # Dictionary to store input values
        user_inputs = {
            "Customer": tk.StringVar(),
            "Project": tk.StringVar(),
            "Purchase Order": tk.StringVar(),
            "Sales Order": tk.StringVar(),
            "Filename": tk.StringVar(value=default_filename),
        }

        # Create input fields
        row = 0
        for label, var in user_inputs.items():
            tk.Label(root, text=label + ":").grid(row=row, column=0, padx=10, pady=5, sticky="w")
            tk.Entry(root, textvariable=var, width=40).grid(row=row, column=1, padx=10, pady=5)
            row += 1

        # Handle window closing event to prevent errors
        def on_close():
            root.destroy()

        root.protocol("WM_DELETE_WINDOW", on_close)

        # Button to submit inputs
        def submit():
            root.destroy()  # Close the popup safely

        tk.Button(root, text="Submit", command=submit).grid(row=row, column=0, columnspan=2, pady=10)

        root.grab_set()  # Make the popup modal
        root.wait_window(root)  # Ensure the window waits before proceeding

        # Extract values
        return {key: var.get().strip() for key, var in user_inputs.items()}

    def collect_run_context(self):
        default_filename = ""
        append_mode = bool(self.inventory_report_path and os.path.isfile(self.inventory_report_path))

        user_inputs = self.get_user_inputs(default_filename)
        if not user_inputs:
            messagebox.showerror("Input Error", "User input window was closed without entering details.")
            return None

        required_fields = ["Customer", "Project", "Purchase Order", "Sales Order"]
        if not append_mode:
            required_fields.append("Filename")

        for key in required_fields:
            value = user_inputs.get(key, "")
            if not value.strip():
                messagebox.showerror("Input Error", f"{key} is required.")
                return None

        customer = user_inputs["Customer"]
        project = user_inputs["Project"]
        customer_po = user_inputs["Purchase Order"]
        sales_order = user_inputs["Sales Order"]
        if append_mode:
            output_file = os.path.normpath(self.inventory_report_path)
        else:
            filename = user_inputs["Filename"]
            filename = "".join(c for c in filename if c.isalnum() or c in (" ", "_", "-")).strip()
            if not filename:
                messagebox.showerror("Input Error", "Invalid filename entered.")
                return None

            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
            final_filename = f"{filename}_{customer}_{project}_Inventory_{timestamp}"

            save_folder = filedialog.askdirectory(title="Select Save Location")
            if not save_folder:
                save_folder = os.getcwd()

            output_file = os.path.normpath(os.path.join(save_folder, f"{final_filename}.xlsx"))
            counter = 1
            while os.path.exists(output_file):
                output_file = os.path.join(save_folder, f"{final_filename}_{counter}.xlsx")
                counter += 1

        pod_1 = self.pod_var_1.get()
        pod_2 = self.pod_var_2.get()
        start_ip_1 = self.start_ip_entry_1.get()
        end_ip_1 = self.end_ip_entry_1.get()
        start_ip_2 = self.start_ip_entry_2.get()
        end_ip_2 = self.end_ip_entry_2.get()

        if not start_ip_1 or not end_ip_1:
            messagebox.showwarning("Input Error", "Please enter at least one IP range (IP Selection 1).")
            return None

        try:
            start_ip_1, end_ip_1 = int(start_ip_1), int(end_ip_1)
            start_ip_2 = int(start_ip_2) if start_ip_2 else None
            end_ip_2 = int(end_ip_2) if end_ip_2 else None
        except ValueError:
            messagebox.showerror("Input Error", "IP values must be numbers.")
            return None

        ip_list = {f"10.9.{pod_1}.{i}" for i in range(start_ip_1, end_ip_1 + 1)}
        if start_ip_2 is not None and end_ip_2 is not None and pod_2 != pod_1:
            ip_list.update(f"10.9.{pod_2}.{i}" for i in range(start_ip_2, end_ip_2 + 1))

        return {
            "customer": customer,
            "project": project,
            "customer_po": customer_po,
            "sales_order": sales_order,
            "output_file": output_file,
            "ip_list": list(ip_list),
            "append_mode": append_mode,
        }

    def start_run_worker(self):
        self.run_thread = threading.Thread(target=self.run_inventory_worker, args=(self.run_context,), daemon=True)
        self.run_thread.start()
        self.root.after(100, self.poll_run_queue)

    def start_export_worker(self, processed_data, packing_slip=False):
        target = self.run_packing_slip_worker if packing_slip else self.run_export_worker
        self.export_thread = threading.Thread(target=target, args=(self.run_context, processed_data), daemon=True)
        self.export_thread.start()
        self.root.after(100, self.poll_run_queue)

    def run_inventory_worker(self, context):
        queue = self.run_queue

        try:
            reachable_ips = []
            for ip in context["ip_list"]:
                if self.stop_threads:
                    queue.put(("aborted", None))
                    return
                if script_interface.is_reachable(ip):
                    reachable_ips.append(ip)

            if not reachable_ips:
                queue.put(("log", "No reachable IPs found."))
                queue.put(("inventory_complete", False))
                return

            device_identifier = script_interface.DeviceIdentifier()
            script_selector = script_interface.ScriptSelector()
            self.task_queue = Queue()

            for ip in reachable_ips:
                if self.stop_threads:
                    queue.put(("aborted", None))
                    return

                while self.is_paused and not self.stop_threads:
                    time.sleep(0.1)

                if self.stop_threads:
                    queue.put(("aborted", None))
                    return

                device_type, device_name = device_identifier.identify_device(ip, queue, None, self.should_stop)
                script_instance = script_selector.select_script(device_type, ip, stop_callback=self.should_stop)

                if script_instance:
                    self.task_queue.put((ip, script_instance))
                else:
                    queue.put(("log", f"No script selected for {ip}"))

            self.process_task_queue(queue)
            queue.put(("inventory_complete", True))
        except Exception as exc:
            logging.exception("Background inventory run failed")
            queue.put(("error", str(exc)))

    def run_export_worker(self, context, _processed_data):
        try:
            processed_data = self.build_report_workbook(
                self.outputs,
                context["output_file"],
                customer=context["customer"],
                project=context["project"],
                customer_po=context["customer_po"],
                sales_order=context["sales_order"],
                append_mode=context.get("append_mode", False),
            )
            self.run_queue.put(("export_complete", {"processed_data": processed_data, "output_file": context["output_file"]}))
        except Exception as exc:
            logging.exception("Background export failed")
            self.run_queue.put(("export_error", str(exc)))

    def run_packing_slip_worker(self, context, processed_data):
        try:
            save_folder = context.get("packing_slip_folder") or os.getcwd()
            save_path = self.build_packing_slip_workbook(
                processed_data,
                context["ip_list"],
                context["customer"],
                context["project"],
                context["customer_po"],
                context["sales_order"],
                save_folder,
            )
            self.run_queue.put(("packing_complete", save_path))
        except Exception as exc:
            logging.exception("Background packing slip export failed")
            self.run_queue.put(("packing_error", str(exc)))

    def should_stop(self):
        return self.stop_threads

    def poll_run_queue(self):
        should_reschedule = True

        while not self.run_queue.empty():
            try:
                item = self.run_queue.get_nowait()
            except Empty:
                break

            if isinstance(item, tuple) and len(item) == 2:
                event_type, payload = item
            else:
                event_type, payload = "log", item

            if event_type == "log":
                self.output_screen.insert(tk.END, payload + '\n')
                self.output_screen.see(tk.END)
            elif event_type == "error":
                self.finish_run()
                messagebox.showerror("Run Error", payload)
                should_reschedule = False
                break
            elif event_type == "aborted":
                self.finish_run()
                self.output_screen.insert(tk.END, "Run aborted.\n")
                self.output_screen.see(tk.END)
                should_reschedule = False
                break
            elif event_type == "inventory_complete":
                if payload:
                    self.update_status("Exporting...")
                    self.start_export_worker(None)
                else:
                    self.finish_run()
                should_reschedule = False
                break
            elif event_type == "export_complete":
                processed_data = payload["processed_data"]
                output_file = payload["output_file"]
                self.output_screen.insert(tk.END, f"Report saved successfully as:\n{output_file}\n")
                self.output_screen.see(tk.END)
                wants_packing_slips = messagebox.askyesno(
                    "Success",
                    f"Report saved successfully as:\n{output_file}\n\nDo you need packing slips?"
                )
                if wants_packing_slips:
                    save_folder = filedialog.askdirectory(title="Select Packing Slip Save Location")
                    if not save_folder:
                        save_folder = os.getcwd()
                    self.run_context["packing_slip_folder"] = save_folder
                    self.update_status("Packing Slips...")
                    self.start_export_worker(processed_data, packing_slip=True)
                else:
                    self.finish_run(success_message=True)
                should_reschedule = False
                break
            elif event_type == "export_error":
                self.finish_run()
                messagebox.showerror("Export Error", f"Failed to save Excel file:\n{payload}")
                should_reschedule = False
                break
            elif event_type == "packing_complete":
                self.finish_run(success_message=True)
                messagebox.showinfo("Success", f"Packing slips saved to:\n{payload}")
                should_reschedule = False
                break
            elif event_type == "packing_error":
                self.finish_run()
                messagebox.showerror("Packing Slip Error", f"Error:\n{payload}")
                should_reschedule = False
                break
            else:
                self.output_screen.insert(tk.END, str(payload) + '\n')
                self.output_screen.see(tk.END)

        if should_reschedule and ((self.run_thread and self.run_thread.is_alive()) or (self.export_thread and self.export_thread.is_alive())):
            self.root.after(100, self.poll_run_queue)
        elif should_reschedule and ((self.run_thread and not self.run_thread.is_alive()) or (self.export_thread and not self.export_thread.is_alive())):
            self.finish_run()

    def finish_run(self, success_message: bool = False):
        self.set_run_controls(False)
        self.update_status("Ready")
        sys.stdout = self._stdout_original

        self.run_context = None
        self.run_thread = None
        self.export_thread = None
        if success_message:
            self.stop_threads = True
            messagebox.showinfo("System Ready", "The system is ready.")

    def run_script(self):
        if (self.run_thread and self.run_thread.is_alive()) or (self.export_thread and self.export_thread.is_alive()):
            messagebox.showwarning("Run In Progress", "Please wait for the current run to finish.")
            return

        self.outputs.clear()
        self.stop_threads = False
        self.is_paused = False

        context = self.collect_run_context()
        if not context:
            self.update_status("Ready")
            return

        self.run_context = context
        self.run_queue = Queue()
        self.set_run_controls(True)
        self.update_status("Running...")
        self.start_run_worker()


    def process_task_queue(self, queue):
        while not self.task_queue.empty():
            item = self.task_queue.get()
            
            # Unpack original format: (ip, script_instance)
            ip, script_instance = item
            self.current_script_instance = script_instance

            try:
                if self.stop_threads:
                    queue.put(("aborted", None))
                    return

                while self.is_paused and not self.stop_threads:
                    time.sleep(0.1)

                if self.stop_threads:
                    queue.put(("aborted", None))
                    return

                # 1. Run normal inventory (your existing logic)
                commands = script_instance.get_commands() or []
                if commands:
                    outputs_list, error = script_instance.execute_commands(commands)
                    if error == "Aborted":
                        queue.put(("aborted", None))
                        return
                    if error:
                        queue.put(("log", f"Error in normal inventory for {ip}: {error}"))
                    elif outputs_list and hasattr(script_instance, "process_outputs"):
                        script_instance.process_outputs(outputs_list, ip, self.outputs)
                        queue.put(("log", f"Normal inventory completed for {ip}"))
                    else:
                        queue.put(("log", f"No output from normal inventory for {ip}"))

                queue.put(("log", f"Overall processing finished for {ip}"))

            except Exception as e:
                queue.put(("log", f"Error processing {ip}: {e}"))

    def update_gui_from_queue(self, queue):
        while not queue.empty():
            try:
                message = queue.get_nowait()
                self.output_screen.insert(tk.END, message + '\n')
                self.output_screen.see(tk.END)
            except Empty:
                break
        
    def pause_program(self):
        with self.lock:
            self.is_paused = not self.is_paused
            self.update_status("Paused" if self.is_paused else "Resumed")
    
    def abort_program(self):
        with self.lock:
            self.stop_threads = True
            # Forcefully close any active connection in the current script
            if self.current_script_instance and hasattr(self.current_script_instance, 'abort_connection'):
                try:
                    self.current_script_instance.abort_connection()
                except Exception as e:
                    logging.debug(f"Error calling abort_connection: {e}")
            self.update_status("Aborted")
        messagebox.showinfo("Aborted", "The program has been aborted.")
        
# Redirect Console Output to GUI Output Screen
class ConsoleRedirector:
    def __init__(self, widget):
        self.widget = widget

    def write(self, message):
        self.widget.insert(tk.END, message)
        self.widget.see(tk.END)  # Auto-scroll to the latest message

    def flush(self):
        pass  # Required for compatibility with logging
    
def main():
    logging.info("Starting LAMIS Inventory System")
    root = tk.Tk()
    # Reuse the already-created instances
    app = InventoryGUI(
        root,
        update_available=False,
        command_tracker=command_tracker,
        db_cache=db_cache
    )
    root.mainloop()

if __name__ == "__main__":
    main()
