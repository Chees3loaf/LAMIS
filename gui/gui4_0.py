from datetime import datetime
import importlib
import ipaddress
import os
import logging
import re
import shutil
import sqlite3
import sys
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from queue import Empty, Queue
from tkinter import filedialog
from typing import Dict, Optional, List, Any, Callable, Tuple
import time
from pathlib import Path
import openpyxl
from openpyxl.utils import get_column_letter
from openpyxl.styles import Font, PatternFill
import pandas as pd
import script_interface
import csv
from utils.helpers import (
    extract_ip_sort_key,
    friendly_error,
    get_data_dir,
    get_database_path,
    get_project_root,
    sanitize_filename_component,
    scrub_password_widget,
)
import config
from gui.workbook_builder import WorkbookBuilder
from gui.inventory_frame import InventoryFrame
from gui.diagnostics_frame import DiagnosticsFrame
from gui.packing_slip_frame import PackingSlipFrame
from gui.raw_frame import RawFrame
from gui.provision_frame import ProvisionFrame

command_tracker = script_interface.CommandTracker()
db_cache = script_interface.get_cache()
DATA_DIR = get_data_dir()

class InventoryGUI:
    _manual_script_modules = {
        "Nokia SAR": "scripts.Nokia_SAR",
        "Nokia IXR": "scripts.Nokia_IXR",
        "Nokia 1830": "scripts.Nokia_1830",
        "Nokia PSI": "scripts.Nokia_PSI",
        "Ciena 6500": "scripts.Ciena_6500",
        "Ciena RLS": "scripts.Ciena_RLS",
        "Ciena SAOS": "scripts.Ciena_SAOS_Inv",
        "Ciena SAOS 10": "scripts.Ciena_SAOS10_Inv",
    }

    # F025: explicit allowlist of importable script modules. Any value not in
    # this frozen set is rejected before reaching importlib, so even if
    # ``_manual_script_modules`` were ever mutated by attacker-controlled data
    # we still cannot import an arbitrary module.
    _ALLOWED_SCRIPT_MODULES = frozenset(_manual_script_modules.values())

    _lan_connection_types = {
        "Nokia 1830": "ssh",
        "Nokia PSI": "ssh",
        "Ciena 6500": "ssh",
        "Ciena RLS": "ssh",
        "Ciena SAOS": "ssh",
        "Ciena SAOS 10": "ssh",
    }

    _allowed_lan_scripts = {"Nokia 1830", "Nokia PSI", "Ciena 6500", "Ciena RLS", "Ciena SAOS", "Ciena SAOS 10"}
    _allowed_serial_scripts = {"Nokia SAR", "Nokia IXR"}

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
        self.run_future = None
        self.run_context = None
        self.export_future = None
        self._worker_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="atlas-worker")
        self._stdout_original = sys.stdout
        self.db_file = str(get_database_path())
        self.current_script_instance = None
        self.current_mode = tk.StringVar(value="inventory")
        self.output_screen = None
        self.raw_frame = None  # initialized in setup_gui
        self.failed_ips: Dict[str, str] = {}
        # Devices whose default credentials all failed are parked here so the
        # main run keeps going. After the regular task queue drains, the
        # worker prompts the user for each parked device on the main thread
        # via the run_queue ("creds_needed" event).
        self.pause_queue: List[Tuple[str, Any]] = []
        self._creds_response_queue: Queue = Queue()

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
        self.psi_template_path = str(DATA_DIR / "Nokia_PSI_Report_Template.xlsx")
        self.rls_template_path = str(DATA_DIR / "Ciena_RLS_Report_Template.xlsx")
        self.packing_slip_template = str(DATA_DIR / "ATLAS_Packing_Slip.xlsx")
        self.psi_packing_slip_template = str(DATA_DIR / "Nokia_PSI_Packing_Slip.xlsx")
        self.rls_packing_slip_template = str(DATA_DIR / "Ciena_RLS_Packing_Slip.xlsx")
        self.lock = threading.Lock()
        # Per-IP device family for export-time template routing.
        # Values: "rls" (Ciena RLS), "psi" (Nokia PSI), "default" (everything else).
        self.device_family_by_ip: Dict[str, str] = {}

        # Tracks script instances that are actively executing so abort_program
        # can stop all of them immediately, regardless of concurrency.
        self._active_scripts: Dict[str, Any] = {}
        self._active_scripts_lock = threading.Lock()

        self.workbook_builder = WorkbookBuilder(self.db_cache, self.template_path, self.packing_slip_template)

        # Setup GUI Components
        self.setup_gui()

        # Initialize ScrolledText for Output at the bottom
        self.output_screen = scrolledtext.ScrolledText(self.root, height=8, width=120)
        self.output_screen.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.output_screen.insert(tk.END, "Automatied Toolkit for Lightriver Asset & Systems (ATLAS)\n")
        self.output_screen.insert(tk.END, "Select mode above to begin\n")

    def setup_gui(self):
        self.root.title("Automatied Toolkit for Lightriver Asset & Systems (ATLAS)")
        self.root.geometry('900x750')
        
        # Top frame: Mode selector
        mode_frame = ttk.LabelFrame(self.root, text="Select Mode")
        mode_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Radiobutton(mode_frame, text="Inventory", variable=self.current_mode, value="inventory", command=self.switch_mode).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="Diagnostics", variable=self.current_mode, value="tds", command=self.switch_mode).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="Packing Slip Generator", variable=self.current_mode, value="packing_slip", command=self.switch_mode).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="Raw File Processing", variable=self.current_mode, value="raw", command=self.switch_mode).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="Provisioning", variable=self.current_mode, value="provision", command=self.switch_mode).pack(side=tk.LEFT, padx=10)
        
        # Container frame for all mode frames
        self.content_frame = ttk.Frame(self.root)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create frames for each mode
        self.inventory_frame = InventoryFrame(self.content_frame, self)
        self.tds_frame = DiagnosticsFrame(self.content_frame, self)
        self.packing_slip_frame = PackingSlipFrame(self.content_frame, self)
        self.raw_frame = RawFrame(self.content_frame, self)
        self.provision_frame = ProvisionFrame(self.content_frame, self)
        
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
        if self.raw_frame:
            self.raw_frame.pack_forget()
        if self.provision_frame:
            self.provision_frame.pack_forget()
        
        if mode == "inventory":
            self.inventory_frame.pack(fill=tk.BOTH, expand=True)
        elif mode == "tds":
            self.tds_frame.pack(fill=tk.BOTH, expand=True)
        elif mode == "packing_slip":
            self.packing_slip_frame.pack(fill=tk.BOTH, expand=True)
        elif mode == "raw":
            self.raw_frame.pack(fill=tk.BOTH, expand=True)
        elif mode == "provision":
            self.provision_frame.pack(fill=tk.BOTH, expand=True)

    def update_status(self, message: str) -> None:
        self.inventory_frame.update_status(message)

    def set_run_controls(self, running: bool) -> None:
        self.inventory_frame.set_run_controls(running)

    # Delegate workbook operations to the dedicated WorkbookBuilder.
    def autosize_sheet_columns(self, sheet: Any, min_width: int = 10, max_width: int = 60) -> None:
        self.workbook_builder.autosize_sheet_columns(sheet, min_width, max_width)

    def combine_and_format_data(self, ip_data: Dict[str, pd.DataFrame]) -> pd.DataFrame:
        return self.workbook_builder.combine_and_format_data(ip_data)

    def build_report_workbook(self, outputs: Dict[str, Any], output_file: str, customer: str = "", project: str = "", customer_po: str = "", sales_order: str = "", append_mode: bool = False) -> Dict[str, Any]:
        return self.workbook_builder.build_report_workbook(outputs, output_file, customer=customer, project=project, customer_po=customer_po, sales_order=sales_order, append_mode=append_mode)

    def build_psi_report_workbook(self, outputs: Dict[str, Any], output_file: str, customer: str = "", project: str = "", customer_po: str = "", sales_order: str = "", append_mode: bool = False, template_override: Optional[str] = None) -> Dict[str, Any]:
        return self.workbook_builder.build_psi_report_workbook(
            outputs,
            output_file,
            customer=customer,
            project=project,
            customer_po=customer_po,
            sales_order=sales_order,
            append_mode=append_mode,
            psi_template_path=template_override or self.psi_template_path,
        )

    def build_unified_report_workbook(self, family_buckets: Dict[str, Dict[str, Any]], output_file: str, customer: str = "", project: str = "", customer_po: str = "", sales_order: str = "", append_mode: bool = False) -> Dict[str, Any]:
        return self.workbook_builder.build_unified_report_workbook(
            family_buckets,
            output_file,
            customer=customer,
            project=project,
            customer_po=customer_po,
            sales_order=sales_order,
            append_mode=append_mode,
            rls_template_path=self.rls_template_path,
            psi_template_path=self.psi_template_path,
        )

    @staticmethod
    def _family_for_script(script_instance: Any) -> str:
        """Return the export-template family for a script instance.

        Used to route per-IP outputs to the correct workbook template at
        export time. Module name is the most reliable signal because it
        is fixed at import time and does not depend on user-visible labels.
        """
        try:
            mod = type(script_instance).__module__
        except Exception:
            return "default"
        if mod.endswith("Ciena_RLS"):
            return "rls"
        if mod.endswith("Nokia_PSI"):
            return "psi"
        return "default"

    def copy_sheet(self, source_sheet: Any, target_wb: Any, new_sheet_name: str) -> Any:
        return self.workbook_builder.copy_sheet(source_sheet, target_wb, new_sheet_name)

    def build_packing_slip_workbook(self, processed_data: Dict[str, Any], ip_list: List[str], customer: str, project: str, customer_po: str, sales_order: str, save_folder: str) -> str:
        return self.workbook_builder.build_packing_slip_workbook(processed_data, ip_list, customer, project, customer_po, sales_order, save_folder)

    def build_unified_packing_slip_workbook(self, processed_data: Dict[str, Any], ip_list: List[str], customer: str, project: str, customer_po: str, sales_order: str, save_folder: str, family_for_ip: Optional[Dict[str, str]] = None) -> str:
        """Per-device-family packing slip workbook (RLS / PSI / default templates merged)."""
        return self.workbook_builder.build_unified_packing_slip_workbook(
            processed_data, ip_list, customer, project, customer_po, sales_order, save_folder,
            family_for_ip=family_for_ip,
            rls_packing_slip_template=self.rls_packing_slip_template,
            psi_packing_slip_template=self.psi_packing_slip_template,
        )

    def get_user_inputs(self, default_filename, prefill: Optional[Dict[str, str]] = None):
        """Prompt user for project information in a popup.

        Args:
            default_filename: Default value for the Filename field.
            prefill: Optional dict with keys "customer", "project", "po", "so".
                When provided (e.g. from an uploaded inventory report), the
                corresponding fields are pre-populated so the user only has
                to confirm rather than retype.
        """
        prefill = prefill or {}
        root = tk.Toplevel()  # Create a new popup window
        root.title("User Inputs")

        # Dictionary to store input values
        user_inputs = {
            "Customer": tk.StringVar(value=prefill.get("customer", "")),
            "Project": tk.StringVar(value=prefill.get("project", "")),
            "Purchase Order": tk.StringVar(value=prefill.get("po", "")),
            "Sales Order": tk.StringVar(value=prefill.get("so", "")),
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

    def collect_run_context(self) -> Optional[Dict[str, Any]]:
        default_filename = ""
        connection_mode = self.inventory_frame.connection_type.get()
        append_mode = bool(
            self.inventory_frame.inventory_report_path
            and os.path.isfile(self.inventory_frame.inventory_report_path)
        )

        user_inputs = self.get_user_inputs(
            default_filename,
            prefill=getattr(self.inventory_frame, "uploaded_metadata", {}) or {},
        )
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
            output_file = os.path.normpath(self.inventory_frame.inventory_report_path)
        else:
            filename = user_inputs["Filename"]
            # Sanitize filename: only alphanumeric, underscore, and hyphen (no spaces for better compatibility)
            filename = "".join(c for c in filename if c.isalnum() or c in ("_", "-")).strip()
            if not filename:
                messagebox.showerror("Input Error", "Invalid filename entered.")
                return None

            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
            # F018: sanitize customer/project before composing the on-disk filename;
            # they originate from imported XLSX values and could contain `..\` or other
            # path-traversal sequences.
            safe_customer = sanitize_filename_component(customer, fallback="Customer")
            safe_project = sanitize_filename_component(project, fallback="Project")
            final_filename = f"{filename}_{safe_customer}_{safe_project}_Inventory_{timestamp}"

            save_folder = filedialog.askdirectory(title="Select Save Location")
            if not save_folder:
                messagebox.showinfo("Export Cancelled", "No save folder selected.")
                return None

            # Save folder is the source of truth for where the report is written.
            self.save_location = os.path.realpath(os.path.normpath(save_folder))

            output_file = os.path.normpath(os.path.join(self.save_location, f"{final_filename}.xlsx"))
            counter = 1
            while os.path.exists(output_file):
                output_file = os.path.join(self.save_location, f"{final_filename}_{counter}.xlsx")
                counter += 1

        if connection_mode in ("LAN", "Serial"):
            manual_script = self.inventory_frame.manual_script_var.get().strip()
            if not manual_script or manual_script not in self._manual_script_modules:
                messagebox.showerror("Input Error", "Please select a valid script.")
                return None

            if connection_mode == "LAN" and manual_script not in self._allowed_lan_scripts:
                messagebox.showerror("Input Error", "LAN supports only Nokia 1830, Nokia PSI, Ciena 6500, and Ciena RLS.")
                return None
            if connection_mode == "Serial" and manual_script not in self._allowed_serial_scripts:
                messagebox.showerror("Input Error", "Serial supports only Nokia SAR and Nokia IXR.")
                return None

            context = {
                "customer": customer,
                "project": project,
                "customer_po": customer_po,
                "sales_order": sales_order,
                "output_file": output_file,
                "append_mode": append_mode,
                "connection_mode": connection_mode,
                "manual_script": manual_script,
            }

            if connection_mode == "LAN":
                ip_address = self.inventory_frame.lan_ip.strip()
                username = self.inventory_frame.lan_username_entry.get().strip()
                password = self.inventory_frame.lan_password_entry.get().strip()
                if not ip_address:
                    messagebox.showerror("Input Error", "LAN IP is required.")
                    return None
                try:
                    ipaddress.ip_address(ip_address)
                except ValueError:
                    messagebox.showerror("Input Error", "LAN IP must be a valid IPv4 or IPv6 address.")
                    return None
                if not username or not password:
                    messagebox.showerror("Input Error", "LAN username and password are required.")
                    return None
                context.update({
                    "target_id": ip_address,
                    "ip_address": ip_address,
                    "username": username,
                    "password": password,
                })
                # Clear password from Entry widget to prevent lingering in memory
                scrub_password_widget(self.inventory_frame.lan_password_entry)
                # Overwrite local password variable to prevent plaintext exposure via memory inspection
                del password
            else:
                serial_port = self.inventory_frame.serial_port_var.get().strip()
                baud_raw = self.inventory_frame.serial_baud_var.get().strip()
                username = self.inventory_frame.serial_username_entry.get().strip()
                password = self.inventory_frame.serial_password_entry.get().strip()
                if not serial_port:
                    messagebox.showerror("Input Error", "Serial port is required (example: COM3).")
                    return None
                if not baud_raw:
                    messagebox.showerror("Input Error", "Baud rate is required.")
                    return None
                try:
                    baud_rate = int(baud_raw)
                except ValueError:
                    messagebox.showerror("Input Error", "Baud rate must be a number.")
                    return None
                if not username or not password:
                    messagebox.showerror("Input Error", "Serial username and password are required.")
                    return None

                context.update({
                    "target_id": serial_port,
                    "serial_port": serial_port,
                    "baud_rate": baud_rate,
                    "username": username,
                    "password": password,
                })
                # Clear password from Entry widget to prevent lingering in memory
                scrub_password_widget(self.inventory_frame.serial_password_entry)
                del password

            return context

        pod_1 = self.inventory_frame.pod_var_1.get()
        pod_2 = self.inventory_frame.pod_var_2.get()
        start_ip_1 = self.inventory_frame.start_ip_entry_1.get()
        end_ip_1 = self.inventory_frame.end_ip_entry_1.get()
        start_ip_2 = self.inventory_frame.start_ip_entry_2.get()
        end_ip_2 = self.inventory_frame.end_ip_entry_2.get()

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

        # Validate IP ranges (start <= end)
        if start_ip_1 > end_ip_1:
            messagebox.showerror("Input Error", "IP Range 1: Start IP must be less than or equal to End IP.")
            return None
        if start_ip_2 is not None and end_ip_2 is not None and start_ip_2 > end_ip_2:
            messagebox.showerror("Input Error", "IP Range 2: Start IP must be less than or equal to End IP.")
            return None

        ip_list = {f"{config.POD_NETWORK_PREFIX}.{pod_1}.{i}" for i in range(start_ip_1, end_ip_1 + 1)}
        if start_ip_2 is not None and end_ip_2 is not None:
            ip_count_before_merge = len(ip_list)
            ip_list.update(f"{config.POD_NETWORK_PREFIX}.{pod_2}.{i}" for i in range(start_ip_2, end_ip_2 + 1))
            # Warn about duplicates only when both ranges are in the same pod
            if pod_2 == pod_1:
                overlap_count = ip_count_before_merge + (end_ip_2 - start_ip_2 + 1) - len(ip_list)
                if overlap_count > 0:
                    messagebox.showwarning("Duplicate IPs Detected", f"IP ranges overlap by {overlap_count} addresses. Duplicates will be removed.")
                    logging.warning(f"Duplicate IPs detected and removed: {overlap_count} addresses")

        return {
            "customer": customer,
            "project": project,
            "customer_po": customer_po,
            "sales_order": sales_order,
            "output_file": output_file,
            "ip_list": list(ip_list),
            "append_mode": append_mode,
            "connection_mode": "Network",
        }

    def _build_manual_script_instance(self, context: Dict[str, Any]):
        script_name = context["manual_script"]
        module_name = self._manual_script_modules.get(script_name)
        if not module_name:
            raise ValueError(f"Unsupported script selection: {script_name}")
        # F025: defense-in-depth — refuse to import anything outside the allowlist.
        if module_name not in self._ALLOWED_SCRIPT_MODULES:
            raise ValueError(
                f"Refusing to import non-allowlisted module: {module_name!r}"
            )

        module = importlib.import_module(module_name)
        script_class = module.Script
        mode = context["connection_mode"]

        kwargs = {
            "db_cache": self.db_cache,
            "command_tracker": self.command_tracker,
            "stop_callback": self.should_stop,
        }

        if mode == "LAN":
            if script_name not in self._allowed_lan_scripts:
                raise ValueError(f"{script_name} is not supported in LAN mode")
            kwargs.update({
                "connection_type": self._lan_connection_types.get(script_name, "ssh"),
                "ip_address": context["ip_address"],
                "username": context["username"],
                "password": context["password"],
            })
        elif mode == "Serial":
            if script_name not in self._allowed_serial_scripts:
                raise ValueError(f"{script_name} is not supported in Serial mode")
            kwargs.update({
                "connection_type": "serial",
                "serial_port": context["serial_port"],
                "baud_rate": context["baud_rate"],
                "username": context["username"],
                "password": context["password"],
            })
        else:
            raise ValueError(f"Unsupported connection mode: {mode}")

        return script_class(**kwargs)

    def start_run_worker(self):
        self.run_future = self._worker_pool.submit(self.run_inventory_worker, self.run_context)
        self.root.after(100, self.poll_run_queue)

    def start_export_worker(self, processed_data):
        self.export_future = self._worker_pool.submit(self.run_export_worker, self.run_context, processed_data)
        self.root.after(100, self.poll_run_queue)

    def run_inventory_worker(self, context: Dict[str, Any]) -> None:
        queue = self.run_queue

        # Reset the command tracker so re-running the same device in the same
        # app session doesn't skip commands marked "already executed".
        script_interface.get_tracker().reset()



        try:
            if context.get("connection_mode") in ("LAN", "Serial"):
                queue.put(("progress", (0, 1, "Preparing 0/1")))
                manual_script = self._build_manual_script_instance(context)
                self.task_queue = Queue()
                self.device_family_by_ip[context["target_id"]] = self._family_for_script(manual_script)
                self.task_queue.put((context["target_id"], manual_script))
                self.process_task_queue(queue)
                queue.put(("inventory_complete", True))
                return

            self.failed_ips = {}
            self.pause_queue = []
            # Drain stale credential responses left over from a prior run.
            while not self._creds_response_queue.empty():
                try:
                    self._creds_response_queue.get_nowait()
                except Empty:
                    break
            total_ips = len(context["ip_list"])
            reachable_ips = []
            reachable_lock = threading.Lock()

            def _probe(ip):
                return ip, script_interface.is_reachable(ip)

            with ThreadPoolExecutor(max_workers=min(20, total_ips or 1)) as ping_pool:
                futures = {ping_pool.submit(_probe, ip): ip for ip in context["ip_list"]}
                for idx, future in enumerate(as_completed(futures), start=1):
                    if self.stop_threads:
                        ping_pool.shutdown(wait=False, cancel_futures=True)
                        queue.put(("aborted", None))
                        return
                    ip, alive = future.result()
                    if alive:
                        with reachable_lock:
                            reachable_ips.append(ip)
                    else:
                        self.failed_ips[ip] = "Unreachable"
                    queue.put(("progress", (idx, total_ips, f"Pinging {idx}/{total_ips}")))

            if not reachable_ips:
                queue.put(("log", "No reachable IPs found."))
                queue.put(("inventory_complete", False))
                return

            total_reachable = len(reachable_ips)
            completed_count = 0
            completed_lock = threading.Lock()

            # Combined identify + execute pipeline: each of up to 5 concurrent
            # workers handles one device end-to-end, reusing the SSH connection
            # when possible so we avoid a second authentication round-trip.
            with ThreadPoolExecutor(
                max_workers=min(5, total_reachable or 1),
                thread_name_prefix="atlas-scan",
            ) as scan_pool:
                scan_futures = {
                    scan_pool.submit(self._process_single_device, ip, queue): ip
                    for ip in reachable_ips
                }
                for future in as_completed(scan_futures):
                    if self.stop_threads:
                        scan_pool.shutdown(wait=False, cancel_futures=True)
                        queue.put(("aborted", None))
                        return

                    while self.is_paused and not self.stop_threads:
                        time.sleep(0.1)

                    ip, status, script_instance, fam = future.result()

                    with completed_lock:
                        completed_count += 1
                        count = completed_count

                    queue.put(("progress", (count, total_reachable, f"Scanning {count}/{total_reachable}")))

                    if status == "ABORTED":
                        scan_pool.shutdown(wait=False, cancel_futures=True)
                        queue.put(("aborted", None))
                        return
                    elif status == "CREDS_REQUIRED":
                        self.pause_queue.append((ip, script_instance))
                    elif status:
                        self.failed_ips[ip] = status
                        queue.put(("log", f"[{ip}] Error: {status}"))

            if self.pause_queue and not self.stop_threads:
                self._drain_pause_queue(queue)

            if self.failed_ips:
                lines = ["\n--- FAILED IPs ---"]
                for ip, reason in self.failed_ips.items():
                    lines.append(f"  {ip}: {reason}")
                queue.put(("log", "\n".join(lines)))

            queue.put(("inventory_complete", True))
        except Exception as exc:
            logging.exception("Background inventory run failed")
            queue.put(("error", friendly_error(exc)))

    def run_export_worker(self, context: Dict[str, Any], _processed_data: Optional[Dict[str, Any]]) -> None:
        try:
            with self.lock:
                outputs_copy = dict(self.outputs)
                family_map = dict(self.device_family_by_ip)

            logging.debug(f"[EXPORT] outputs keys: {list(outputs_copy.keys())}")
            logging.debug(f"[EXPORT] family_map: {family_map}")

            # Partition outputs by family. IPs with no recorded family
            # (e.g., legacy in-memory data from a prior run) fall through
            # to "default" so we never silently drop them.
            buckets: Dict[str, Dict[str, Any]] = {"rls": {}, "psi": {}, "default": {}}
            for ip, data in outputs_copy.items():
                fam = family_map.get(ip, "default")
                logging.debug(f"[EXPORT] IP={ip!r} → family={fam!r}")
                buckets.setdefault(fam, {})[ip] = data

            non_empty = {fam: ips for fam, ips in buckets.items() if ips}
            output_file = context["output_file"]

            if not non_empty:
                self.run_queue.put(("export_complete", {"processed_data": {}, "output_file": output_file}))
                return

            common_kwargs = dict(
                customer=context["customer"],
                project=context["project"],
                customer_po=context["customer_po"],
                sales_order=context["sales_order"],
                append_mode=context.get("append_mode", False),
            )

            # Single-family scans bypass the unified builder so behavior
            # exactly matches the prior single-template path.
            if len(non_empty) == 1:
                fam = next(iter(non_empty))
                ips = non_empty[fam]
                if fam == "rls":
                    processed_data = self.build_psi_report_workbook(
                        ips, output_file, template_override=self.rls_template_path, **common_kwargs
                    )
                elif fam == "psi":
                    processed_data = self.build_psi_report_workbook(ips, output_file, **common_kwargs)
                else:
                    processed_data = self.build_report_workbook(ips, output_file, **common_kwargs)
            else:
                processed_data = self.build_unified_report_workbook(non_empty, output_file, **common_kwargs)

            self.run_queue.put((
                "export_complete",
                {"processed_data": processed_data, "output_file": output_file},
            ))
        except Exception as exc:
            logging.exception("Background export failed")
            self.run_queue.put(("export_error", friendly_error(exc)))

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
            elif event_type == "progress":
                current, total, label = payload
                self.inventory_frame.update_progress(current, total, label)
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
                output_file = payload["output_file"]
                self.output_screen.insert(tk.END, f"Report saved successfully as:\n{output_file}\n")
                self.output_screen.see(tk.END)
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
            elif event_type == "creds_needed":
                # Worker has parked an IP and is blocked waiting for the user
                # to type credentials. Prompt on the main (Tk) thread, then
                # push the answer (or None) back to the worker's response
                # queue so the worker can retry that single device.
                ip = payload
                try:
                    from utils.credentials import prompt_for_credentials_gui
                    self.output_screen.insert(
                        tk.END,
                        f"\n[{ip}] Default credentials failed — please enter credentials.\n",
                    )
                    self.output_screen.see(tk.END)
                    answer = prompt_for_credentials_gui(parent_window=self.root)
                except Exception as prompt_err:
                    logging.exception(f"Credential prompt failed for {ip}")
                    self.output_screen.insert(
                        tk.END,
                        f"[{ip}] Credential prompt failed: {friendly_error(prompt_err)}\n",
                    )
                    answer = None
                # Always push *something* so the worker doesn't hang.
                self._creds_response_queue.put(answer if answer else (None, None))
            else:
                self.output_screen.insert(tk.END, str(payload) + '\n')
                self.output_screen.see(tk.END)

        if should_reschedule and ((self.run_future and not self.run_future.done()) or (self.export_future and not self.export_future.done())):
            self.root.after(100, self.poll_run_queue)
        elif should_reschedule and ((self.run_future and self.run_future.done()) or (self.export_future and self.export_future.done())):
            self.finish_run()

    def finish_run(self, success_message: bool = False):
        self.set_run_controls(False)
        self.update_status("Ready")
        sys.stdout = self._stdout_original
        self.inventory_frame.reset_progress()

        self.run_context = None
        self.run_future = None
        self.export_future = None
        if success_message:
            self.stop_threads = True
            messagebox.showinfo("System Ready", "The system is ready.")

    def run_script(self):
        if (self.run_future and not self.run_future.done()) or (self.export_future and not self.export_future.done()):
            messagebox.showwarning("Run In Progress", "Please wait for the current run to finish.")
            return

        with self.lock:
            self.outputs.clear()
            self.device_family_by_ip.clear()
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


    def process_task_queue(self, queue: Queue) -> None:
        total_tasks = self.task_queue.qsize()
        completed = 0
        while not self.task_queue.empty():
            item = self.task_queue.get()
            
            # Unpack original format: (ip, script_instance)
            ip, script_instance = item
            self.current_script_instance = script_instance
            completed += 1

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
                    if error == script_interface.NEEDS_CREDENTIALS_SENTINEL:
                        # Credentials failed — park for user prompt after the
                        # rest of the run completes.
                        self.pause_queue.append((ip, script_instance))
                        queue.put((
                            "log",
                            f"[{ip}] Credentials failed — parking for "
                            f"manual credential entry after the rest of the run.",
                        ))
                    elif error:
                        logging.warning(f"[TASK] Script execution error for {ip}: {error}")
                        queue.put(("log", f"Error in normal inventory for {ip}: {error}"))
                        if any(kw in error.lower() for kw in ("auth", "login", "credential", "password", "invalid")):
                            # Defensive fallback: a script returned an auth-related
                            # error string instead of NEEDS_CREDENTIALS_SENTINEL.
                            # Park for retry rather than recording as a hard failure.
                            self.pause_queue.append((ip, script_instance))
                            queue.put((
                                "log",
                                f"[{ip}] Auth error detected — parking for manual credential entry.",
                            ))
                        else:
                            self.failed_ips[ip] = error
                    elif outputs_list and hasattr(script_instance, "process_outputs"):
                        with self.lock:
                            script_instance.process_outputs(outputs_list, ip, self.outputs)
                        queue.put(("log", f"Normal inventory completed for {ip}"))
                    else:
                        queue.put(("log", f"No output from normal inventory for {ip}"))

                queue.put(("log", f"Overall processing finished for {ip}"))
                queue.put(("progress", (completed, total_tasks, f"Collecting {completed}/{total_tasks}")))

            except Exception as e:
                logging.exception(f"[TASK] Unhandled error processing {ip}")
                queue.put(("log", f"Error processing {ip}: {friendly_error(e)}"))

        # Main queue drained — now process anything that needed manual creds.
        if self.pause_queue and not self.stop_threads:
            self._drain_pause_queue(queue)

    def _process_single_device(
        self,
        ip: str,
        queue: Queue,
    ) -> Tuple[str, Optional[str], Any, Optional[str]]:
        """Identify and collect inventory for a single device in one pass.

        Called from the concurrent scan pool in ``run_inventory_worker``.
        Creates its own ``DeviceIdentifier`` and ``ScriptSelector`` instances
        so multiple devices can run completely in parallel without sharing state.

        Returns:
            (ip, status, script_instance, family)
            - status is ``None`` on success, ``"CREDS_REQUIRED"``, ``"ABORTED"``,
              or an error string.
            - script_instance is the Script object (``None`` if identification failed).
            - family is the export-template routing key (``None`` if unavailable).
        """
        device_identifier = script_interface.DeviceIdentifier()
        script_selector = script_interface.ScriptSelector()
        script_instance = None
        fam = None

        # ── Phase A: Identify ─────────────────────────────────────────────
        try:
            device_type, device_name = device_identifier.identify_device(
                ip, queue, None, self.should_stop
            )
        except script_interface.CredentialPromptRequired:
            queue.put((
                "log",
                f"[{ip}] Default credentials exhausted — parked for manual credential entry.",
            ))
            return ip, "CREDS_REQUIRED", None, None
        except Exception as exc:
            logging.exception(f"[PIPELINE] Identification error for {ip}")
            return ip, f"Identification error: {friendly_error(exc)}", None, None

        if self.stop_threads:
            return ip, "ABORTED", None, None

        if not device_type:
            return ip, "Identification failed", None, None

        # ── Phase B: Select script and optionally inject kept SSH client ───
        # Nokia 1830 now uses SSH (paramiko auth_none + two-stage shell login).
        conn_type = 'ssh'
        script_instance = script_selector.select_script(
            device_type, ip, connection_type=conn_type, stop_callback=self.should_stop
        )
        if not script_instance:
            reason = f"Unknown device type: {device_type}"
            return ip, reason, None, None

        fam = self._family_for_script(script_instance)
        logging.debug(f"[FAMILY] (pipeline) ip={ip} mod={type(script_instance).__module__} → fam={fam!r}")
        with self.lock:
            self.device_family_by_ip[ip] = fam

        # Hand off the SSH client kept alive during identification so the
        # script can skip the second authentication round-trip.
        kept_client = device_identifier.take_identified_client()
        if kept_client is not None and hasattr(script_instance, 'set_existing_ssh_client'):
            script_instance.set_existing_ssh_client(kept_client)

        # ── Phase C: Execute ───────────────────────────────────────────────
        with self._active_scripts_lock:
            self._active_scripts[ip] = script_instance
        try:
            if self.stop_threads:
                return ip, "ABORTED", script_instance, fam

            while self.is_paused and not self.stop_threads:
                time.sleep(0.1)

            if self.stop_threads:
                return ip, "ABORTED", script_instance, fam

            commands = script_instance.get_commands() or []
            if not commands:
                queue.put(("log", f"No commands for {ip}"))
                return ip, None, script_instance, fam

            outputs_list, error = script_instance.execute_commands(commands)

            if error == "Aborted":
                return ip, "ABORTED", script_instance, fam

            if error == script_interface.NEEDS_CREDENTIALS_SENTINEL:
                queue.put((
                    "log",
                    f"[{ip}] Credentials failed during execution — parking for manual entry.",
                ))
                return ip, "CREDS_REQUIRED", script_instance, fam

            if error:
                if any(kw in error.lower() for kw in ("auth", "login", "credential", "password", "invalid")):
                    queue.put(("log", f"[{ip}] Auth error — parking for manual credential entry."))
                    return ip, "CREDS_REQUIRED", script_instance, fam
                return ip, error, script_instance, fam

            if outputs_list and hasattr(script_instance, "process_outputs"):
                with self.lock:
                    script_instance.process_outputs(outputs_list, ip, self.outputs)
                queue.put(("log", f"Inventory completed for {ip}"))
            else:
                queue.put(("log", f"No output from {ip}"))

            return ip, None, script_instance, fam

        except Exception as exc:
            logging.exception(f"[PIPELINE] Unhandled error processing {ip}")
            return ip, friendly_error(exc), script_instance, fam
        finally:
            with self._active_scripts_lock:
                self._active_scripts.pop(ip, None)

    def _drain_pause_queue(self, queue: Queue) -> None:
        """Prompt user for credentials per parked IP and retry collection.

        Runs on the worker thread. For each parked (ip, script_instance):
          1. Post ("creds_needed", ip) on the run queue. The main thread sees
             this in poll_run_queue, prompts the user with a Tk dialog, and
             pushes the answer (or None) to ``self._creds_response_queue``.
          2. Block on the response queue (with stop/pause checks).
          3. If user provided creds, swap them onto the script_instance and
             re-run execute_commands. Otherwise mark the IP as skipped.
        """
        parked = list(self.pause_queue)
        self.pause_queue.clear()
        total = len(parked)
        # Need our own identifier/selector since the worker's locals are out
        # of scope here. They're cheap to construct.
        device_identifier = script_interface.DeviceIdentifier()
        script_selector = script_interface.ScriptSelector()
        queue.put((
            "log",
            f"\n--- Processing {total} device(s) that need manual credentials ---",
        ))
        for idx, (ip, script_instance) in enumerate(parked, start=1):
            if self.stop_threads:
                queue.put(("aborted", None))
                return
            while self.is_paused and not self.stop_threads:
                time.sleep(0.1)
            if self.stop_threads:
                queue.put(("aborted", None))
                return

            queue.put((
                "progress",
                (idx, total, f"Manual credentials {idx}/{total}"),
            ))
            queue.put(("log", f"[{ip}] Requesting credentials from user..."))

            # Drain any stale response just in case.
            while not self._creds_response_queue.empty():
                try:
                    self._creds_response_queue.get_nowait()
                except Empty:
                    break

            queue.put(("creds_needed", ip))

            new_creds: Optional[Tuple[Optional[str], Optional[str]]] = None
            while True:
                if self.stop_threads:
                    queue.put(("aborted", None))
                    return
                try:
                    new_creds = self._creds_response_queue.get(timeout=0.25)
                    break
                except Empty:
                    continue

            if not new_creds or not new_creds[0]:
                self.failed_ips[ip] = (
                    "Login failed: user declined to provide credentials"
                )
                queue.put((
                    "log",
                    f"[{ip}] Skipped — no credentials provided by user.",
                ))
                continue

            new_user, new_pass = new_creds

            # Identify-time park: no script_instance was ever built. Re-run
            # identification with the user-provided creds, build the script,
            # then execute it.
            if script_instance is None:
                queue.put(("log", f"[{ip}] Re-identifying with user-provided credentials..."))
                try:
                    device_type, device_name = device_identifier.identify_device(
                        ip,
                        queue,
                        None,
                        self.should_stop,
                        explicit_credentials=(new_user, new_pass),
                    )
                except script_interface.CredentialPromptRequired:
                    self.failed_ips[ip] = "Login failed: user-provided credentials rejected at identification"
                    queue.put(("log", f"[{ip}] User-provided credentials rejected during identification."))
                    continue
                except Exception as e:
                    logging.exception(f"[PAUSE] Re-identify error for {ip}")
                    self.failed_ips[ip] = f"Identification failed: {friendly_error(e)}"
                    queue.put(("log", f"[{ip}] Re-identify error: {friendly_error(e)}"))
                    continue

                if not device_type:
                    self.failed_ips[ip] = "Identification failed even with user-provided credentials"
                    queue.put(("log", f"[{ip}] Could not identify device with user-provided credentials."))
                    continue

                conn_type = 'ssh'
                script_instance = script_selector.select_script(
                    device_type, ip, connection_type=conn_type, stop_callback=self.should_stop
                )
                if not script_instance:
                    self.failed_ips[ip] = f"Unknown device type: {device_type}"
                    queue.put(("log", f"[{ip}] No script for device type {device_type!r}"))
                    continue

            # Record the export-template family before running. The
            # bulk-identify path (run_inventory_worker) does this inline,
            # but parked IPs land here without it being set, which would
            # leave them routed to the default workbook builder.
            fam = self._family_for_script(script_instance)
            logging.info(f"[FAMILY] (pause-queue) ip={ip} → fam={fam!r}")
            self.device_family_by_ip[ip] = fam

            # Push the user-provided creds onto whichever attribute the script
            # uses. SAR/IXR take them as method args; Smartoptics_DCP and
            # Nokia_1830 hold them as instance state.
            if hasattr(script_instance, "username"):
                script_instance.username = new_user
            if hasattr(script_instance, "password"):
                script_instance.password = new_pass

            queue.put(("log", f"[{ip}] Retrying with user-provided credentials..."))
            try:
                commands = script_instance.get_commands() or []
                outputs_list, error = script_instance.execute_commands(commands)
                if error == "Aborted":
                    queue.put(("aborted", None))
                    return
                if error == script_interface.NEEDS_CREDENTIALS_SENTINEL:
                    # User-provided creds also failed default-set → record
                    # and move on. We do not re-prompt the same IP twice.
                    self.failed_ips[ip] = "Login failed: user-provided credentials rejected"
                    queue.put((
                        "log",
                        f"[{ip}] User-provided credentials also failed. Skipping.",
                    ))
                elif error:
                    logging.warning(f"[PAUSE] Retry error for {ip}: {error}")
                    queue.put(("log", f"[{ip}] Retry error: {error}"))
                    self.failed_ips[ip] = f"Login failed: {error}"
                elif outputs_list and hasattr(script_instance, "process_outputs"):
                    with self.lock:
                        script_instance.process_outputs(outputs_list, ip, self.outputs)
                    queue.put(("log", f"[{ip}] Inventory completed via manual credentials"))
                    self.failed_ips.pop(ip, None)
                else:
                    queue.put(("log", f"[{ip}] No output after manual credential retry"))
            except Exception as e:
                logging.exception(f"[PAUSE] Unhandled error processing {ip}")
                queue.put(("log", f"[{ip}] Retry error: {friendly_error(e)}"))

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
            # Stop any script that is actively executing (concurrent pipeline).
            with self._active_scripts_lock:
                for ip, script_inst in list(self._active_scripts.items()):
                    if hasattr(script_inst, 'abort_connection'):
                        try:
                            script_inst.abort_connection()
                        except Exception as e:
                            logging.debug(f"Error calling abort_connection for {ip}: {e}")
            # Also stop the legacy single-instance reference (LAN/Serial modes).
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
    logging.info("Starting ATLAS")
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
