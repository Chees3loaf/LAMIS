from datetime import datetime
import os
import logging
import re
import shutil
import sqlite3
import sys
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor
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
from utils.helpers import extract_ip_sort_key, get_database_path
import config
from gui.workbook_builder import WorkbookBuilder
from gui.inventory_frame import InventoryFrame
from gui.tds_frame import TDSFrame
from gui.packing_slip_frame import PackingSlipFrame

command_tracker = script_interface.CommandTracker()
db_cache = script_interface.get_cache()
DATA_DIR = get_database_path().parent

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
        self.run_future = None
        self.run_context = None
        self.export_future = None
        self._worker_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="lamis-worker")
        self._stdout_original = sys.stdout
        self.db_file = str(DATA_DIR / "network_inventory.db")
        self.current_script_instance = None
        self.current_mode = tk.StringVar(value="inventory")
        self.output_screen = None

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

        self.workbook_builder = WorkbookBuilder(self.db_cache, self.template_path, self.packing_slip_template)

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
        self.inventory_frame = InventoryFrame(self.content_frame, self)
        self.tds_frame = TDSFrame(self.content_frame, self)
        self.packing_slip_frame = PackingSlipFrame(self.content_frame, self)
        
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

    def copy_sheet(self, source_sheet: Any, target_wb: Any, new_sheet_name: str) -> Any:
        return self.workbook_builder.copy_sheet(source_sheet, target_wb, new_sheet_name)

    def build_packing_slip_workbook(self, processed_data: Dict[str, Any], ip_list: List[str], customer: str, project: str, customer_po: str, sales_order: str, save_folder: str) -> str:
        return self.workbook_builder.build_packing_slip_workbook(processed_data, ip_list, customer, project, customer_po, sales_order, save_folder)

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

    def collect_run_context(self) -> Optional[Dict[str, Any]]:
        default_filename = ""
        append_mode = bool(
            self.inventory_frame.inventory_report_path
            and os.path.isfile(self.inventory_frame.inventory_report_path)
        )

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
            output_file = os.path.normpath(self.inventory_frame.inventory_report_path)
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
        }

    def start_run_worker(self):
        self.run_future = self._worker_pool.submit(self.run_inventory_worker, self.run_context)
        self.root.after(100, self.poll_run_queue)

    def start_export_worker(self, processed_data):
        self.export_future = self._worker_pool.submit(self.run_export_worker, self.run_context, processed_data)
        self.root.after(100, self.poll_run_queue)

    def run_inventory_worker(self, context: Dict[str, Any]) -> None:
        queue = self.run_queue

        try:
            total_ips = len(context["ip_list"])
            reachable_ips = []
            for idx, ip in enumerate(context["ip_list"], start=1):
                if self.stop_threads:
                    queue.put(("aborted", None))
                    return
                if script_interface.is_reachable(ip):
                    reachable_ips.append(ip)
                queue.put(("progress", (idx, total_ips, f"Pinging {idx}/{total_ips}")))

            if not reachable_ips:
                queue.put(("log", "No reachable IPs found."))
                queue.put(("inventory_complete", False))
                return

            device_identifier = script_interface.DeviceIdentifier()
            script_selector = script_interface.ScriptSelector()
            self.task_queue = Queue()
            total_reachable = len(reachable_ips)

            for idx, ip in enumerate(reachable_ips, start=1):
                if self.stop_threads:
                    queue.put(("aborted", None))
                    return

                while self.is_paused and not self.stop_threads:
                    time.sleep(0.1)

                if self.stop_threads:
                    queue.put(("aborted", None))
                    return

                queue.put(("progress", (idx, total_reachable, f"Identifying {idx}/{total_reachable}")))
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

    def run_export_worker(self, context: Dict[str, Any], _processed_data: Optional[Dict[str, Any]]) -> None:
        try:
            with self.lock:
                outputs_copy = dict(self.outputs)
            processed_data = self.build_report_workbook(
                outputs_copy,
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
                    if error:
                        logging.warning(f"[TASK] Script execution error for {ip}: {error}")
                        queue.put(("log", f"Error in normal inventory for {ip}: {error}"))
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
