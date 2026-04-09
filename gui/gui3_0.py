from datetime import datetime
import os
import logging
import re
import shutil
import sqlite3
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from queue import Empty, Queue
from tkinter import filedialog
from typing import Dict
import time
from pathlib import Path
import openpyxl
from openpyxl.utils import get_column_letter
from openpyxl.styles import Font
import pandas as pd
import script_interface

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
        self.db_file = str(DATA_DIR / "network_inventory.db")

        if os.path.isfile(self.db_file):
            if self.db_cache.db_path != self.db_file:
                logging.warning(f"[DB] Fixing db_cache path from {self.db_cache.db_path} to {self.db_file}")
                self.db_cache.db_path = self.db_file
                # clear any stale cached results tied to the old DB
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

        # Initialize ScrolledText for Output
        self.output_screen = scrolledtext.ScrolledText(self.root, height=15, width=120)
        self.output_screen.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.output_screen.insert(tk.END, "Lightriver Automated Multivendor Inventory System Started\n")
        self.output_screen.insert(tk.END, "Please select pod(s) and enter the IP of your device(s) above\n")

    def setup_gui(self):
        self.root.title("Lightriver Automated Multivendor Inventory System")
        self.root.geometry('850x650')
        
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Connection Type at the top
        connection_frame = ttk.LabelFrame(main_frame, text="Connection Type")
        connection_frame.pack(fill=tk.X, pady=5)
        self.connection_type = tk.StringVar(value="Network")
        tk.Radiobutton(connection_frame, text="Network", variable=self.connection_type, value="Network").pack(side=tk.LEFT, padx=10)

        # Middle section with Pod and IP Selections
        middle_frame = ttk.Frame(main_frame)
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
        
        # ====================== CONTROL FRAME ======================
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=10)

        # Left side: TDS Checkbox
        self.tds_var = tk.BooleanVar(value=False)
        self.tds_checkbox = ttk.Checkbutton(
            control_frame,
            text="Run Diagnostics",
            variable=self.tds_var
        )
        self.tds_checkbox.pack(side=tk.LEFT, padx=20)

        # Right side: Action buttons
        tk.Button(control_frame, text="Run", command=self.run_script).pack(side=tk.RIGHT, padx=5)
        tk.Button(control_frame, text="Pause", command=self.pause_program).pack(side=tk.RIGHT, padx=5)
        tk.Button(control_frame, text="Abort", command=self.abort_program).pack(side=tk.RIGHT, padx=5)

        # Status label on the far right
        self.status_label = tk.Label(control_frame, text="Status: Ready", anchor="w")
        self.status_label.pack(side=tk.RIGHT, padx=10)
        
    def update_ip_labels(self, pod_var, start_ip_label, end_ip_label):
        # Update IP labels when the pod selection changes
        pod_number = pod_var.get()
        start_ip_label.config(text=f"Start IP: 10.9.{pod_number}.")
        end_ip_label.config(text=f"End IP: 10.9.{pod_number}.")

    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update_idletasks()
        
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
        # Writes processed data to an Excel file using a provided template.
        # Preserves the DataFrame and prompts the user for packing slips.

        # ----- re-entrancy guard -----
        if getattr(self, "_export_running", False):
            logging.warning("[EXCEL] Export already running; skipping duplicate call.")
            return
        self._export_running = True

        logging.info("Starting Excel export process...")
        try:
            # --- Helpers ---------------------------------------------------------
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

            # --- Open template ---------------------------------------------------
            if not os.path.exists(self.template_path):
                raise FileNotFoundError(f"Template file not found at {self.template_path}")

            # if you imported `from openpyxl import load_workbook`, use `load_workbook(...)` instead
            import openpyxl  # Make sure this import exists somewhere
            wb = openpyxl.load_workbook(self.template_path)
            sheet = wb.active

            db_exists = os.path.isfile(self.db_cache.db_path)
            logging.info(f"[EXCEL] Using DB cache path: {self.db_cache.db_path} (exists={db_exists})")
            logging.info(f"Starting Excel export for {len(outputs)} devices.")

            processed_data = {}

            # --- Build each sheet ------------------------------------------------
            for ip, data_dict in outputs.items():
                try:
                    logging.info(f"Processing data for IP {ip}.")
                    combined_df = self.combine_and_format_data(data_dict)
                    if combined_df.empty:
                        logging.warning(f"No data to write for IP {ip}")
                        continue

                    # Header fields (safe + fallbacks)
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
                    new_sheet = wb.copy_worksheet(sheet)
                    new_sheet.title = system_name

                    # Header/meta cells
                    new_sheet["C5"] = customer
                    new_sheet["C6"] = project
                    new_sheet["C7"] = customer_po
                    new_sheet["D7"] = sales_order
                    new_sheet["F5"] = source_val
                    new_sheet["F6"] = system_name
                    new_sheet["F7"] = system_type

                    # Only write rows that look like equipment (have Part or Model)
                    has_part = combined_df.get("Part Number")
                    has_model = combined_df.get("Model Number")

                    mask_part = nonempty_col(has_part)
                    mask_model = nonempty_col(has_model)

                    if mask_part is not None and mask_model is not None:
                        write_df = combined_df[mask_part | mask_model]
                    elif mask_part is not None:
                        write_df = combined_df[mask_part]
                    elif mask_model is not None:
                        write_df = combined_df[mask_model]
                    else:
                        write_df = combined_df.iloc[0:0]

                    START_ROW = 15
                    for i, row in write_df.reset_index(drop=True).iterrows():
                        row_num = START_ROW + i

                        # Clean values
                        part_number = clean_str(row.get("Part Number", "")) or clean_str(row.get("Model Number", ""))
                        info_type = clean_str(row.get("Information Type", "")).lower()
                        name_value = clean_str(row.get("Name", ""))

                        if "mda card" in info_type:
                            match = re.search(r"\d+", name_value)
                            mda_number = match.group() if match else "Unknown"
                            name_value = f"MDA {mda_number}"

                        type_value = clean_str(row.get("Type", ""))
                        serial_val = clean_str(row.get("Serial Number", ""))

                        # Skip fully empty rows so first real row is at 15
                        if not any([name_value, type_value, part_number, serial_val]):
                            continue

                        # Description lookup (only if DB exists)
                        description = ""
                        if part_number and db_exists:
                            description = self.db_cache.lookup_part(part_number[:10])
                            if not description or description == "Not Found":
                                # optional LIKE fallback
                                try:
                                    import sqlite3
                                    with sqlite3.connect(self.db_cache.db_path) as tmpconn:
                                        tcur = tmpconn.cursor()
                                        tcur.execute(
                                            "SELECT description FROM parts WHERE part_number LIKE ?",
                                            (part_number[:10] + "%",),
                                        )
                                        res = tcur.fetchone()
                                        if res:
                                            description = res[0]
                                except Exception as e:
                                    logging.debug(f"[EXCEL] Fallback DB lookup failed: {e}")

                        # Write to sheet
                        new_sheet[f"B{row_num}"] = name_value
                        new_sheet[f"C{row_num}"] = type_value
                        new_sheet[f"D{row_num}"] = part_number
                        new_sheet[f"E{row_num}"] = serial_val
                        new_sheet[f"F{row_num}"] = description

                    processed_data[ip] = write_df

                except Exception as e:
                    logging.error(f"Failed to process data for IP {ip}. Error: {e}")

            # Remove the original template sheet if we created any copies
            if len(wb.sheetnames) > 1:
                wb.remove(sheet)

            # Save (with retry if file is locked)
            save_dir = os.path.dirname(output_file)
            os.makedirs(save_dir, exist_ok=True)

            while True:
                try:
                    wb.save(output_file)
                    logging.info(f"Data successfully saved to {output_file}")
                    break
                except PermissionError:
                    from tkinter import messagebox
                    logging.warning(f"File is locked: {output_file}")
                    if not messagebox.askretrycancel("File Locked", f"Close '{output_file}' and retry."):
                        return
                    import time
                    time.sleep(3)

            # Prompt for packing slips using in-memory data
            from tkinter import messagebox
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

        except Exception as e:
            logging.error(f"Failed to save data to Excel: {e}")
            from tkinter import messagebox
            messagebox.showerror("Export Error", f"Failed to save Excel file:\n{e}")

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
        """
        Generates a single packing slip workbook with one sheet per device.
        """
        try:
            packing_template_path = self.packing_slip_template
            logging.info(f"Loading packing slip template: {packing_template_path}")

            if not os.path.exists(packing_template_path):
                raise FileNotFoundError(f"Packing slip template not found at: {packing_template_path}")

            # Temporary copy of template
            temp_packing_slip = os.path.join(os.getcwd(), "PackingSlip_Temp.xlsx")
            shutil.copy(packing_template_path, temp_packing_slip)

            wb_final = openpyxl.load_workbook(temp_packing_slip)

            # Template sheet
            if "Packing Slip" not in wb_final.sheetnames:
                raise ValueError(f"'Packing Slip' template sheet not found. Available: {wb_final.sheetnames}")

            template_sheet = wb_final["Packing Slip"]

            # Summary sheet
            summary_sheet = None
            for name in wb_final.sheetnames:
                if "summary" in name.lower():
                    summary_sheet = wb_final[name]
                    break

            if not summary_sheet:
                raise ValueError(f"No summary sheet found. Available: {wb_final.sheetnames}")

            # Ask for save folder
            save_folder = filedialog.askdirectory(title="Select Packing Slip Save Location")
            if not save_folder:
                save_folder = os.getcwd()

            # === SAFE FILENAME CREATION ===
            timestamp = datetime.now().strftime('%Y-%m-%d')
            safe_customer = re.sub(r'[^a-zA-Z0-9_]', '_', (customer or "Unknown").strip())
            safe_project = re.sub(r'[^a-zA-Z0-9_]', '_', (project or "Unknown").strip())

            filename = f"PackingSlip_{safe_customer}_{safe_project}_{timestamp}.xlsx"
            save_path = os.path.join(save_folder, filename)

            logging.info(f"Packing slips will be saved as: {save_path}")

            # Summary sheet info
            summary_sheet["B5"] = "Customer"
            summary_sheet["B7"] = customer or ""
            summary_sheet["D5"] = "Project"
            summary_sheet["D7"] = project or ""
            summary_sheet["F5"] = "IP Addresses"
            summary_sheet["F7"] = ", ".join(ip_list)

            # === Create one sheet per device ===
            logging.info(f"Generating packing slips for {len(processed_data)} device(s)")

            for ip, device_data in processed_data.items():
                if device_data.empty:
                    logging.warning(f"No data for {ip} - skipping")
                    continue

                logging.info(f"Columns for {ip}: {list(device_data.columns)}")   # ← Helpful debug

                try:
                    # Get device name
                    device_name = "Unknown_Device"
                    for col in device_data.columns:
                        if any(x in col.lower() for x in ["system name", "name"]):
                            device_name = str(device_data.iloc[0].get(col, "Unknown_Device"))
                            break

                    device_name_clean = re.sub(r'[^a-zA-Z0-9_]', '_', device_name.strip())[:31]

                    new_sheet = wb_final.copy_worksheet(template_sheet)
                    new_sheet.title = device_name_clean

                    # Copy merged cells
                    for merged in template_sheet.merged_cells.ranges:
                        new_sheet.merge_cells(str(merged))

                    # Header
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

                    # === Write data rows - SAFE VERSION ===
                    start_row = 15   # ← Confirm this matches your template

                    for idx, row_dict in enumerate(device_data.to_dict('records')):
                        row_num = start_row + idx

                        part_number = str(row_dict.get("Part Number", "")).strip()
                        serial_number = str(row_dict.get("Serial Number", "")).strip()
                        description = str(row_dict.get("Description", "")).strip()

                        # Fallback for part number
                        if not part_number:
                            part_number = str(row_dict.get("Model Number", "")).strip()

                        # Clean NaN values
                        if part_number.lower() in ("nan", ""): 
                            part_number = ""
                        if serial_number.lower() in ("nan", ""): 
                            serial_number = ""
                        if description.lower() in ("nan", ""): 
                            description = ""

                        # Write row only if there's useful data
                        if part_number or serial_number or description:
                            new_sheet[f"B{row_num}"] = sales_order or ""
                            new_sheet[f"C{row_num}"] = customer_po or ""
                            new_sheet[f"D{row_num}"] = part_number
                            new_sheet[f"E{row_num}"] = serial_number
                            new_sheet[f"F{row_num}"] = description
                            

                    logging.debug(f"Written {len(device_data)} line items for device '{device_name}' with SO/PO")
                
                except Exception as e:
                    logging.error(f"Error creating sheet for {ip}: {e}")

            # Move summary to front
            if summary_sheet.title in wb_final.sheetnames:
                idx = wb_final.sheetnames.index(summary_sheet.title)
                wb_final._sheets.insert(0, wb_final._sheets.pop(idx))

            # Remove template sheet
            if "Packing Slip" in wb_final.sheetnames:
                del wb_final["Packing Slip"]

            # Save
            wb_final.save(save_path)
            logging.info(f"Packing slips saved successfully: {save_path}")
            messagebox.showinfo("Success", f"Packing slips saved to:\n{save_path}")

        except Exception as e:
            logging.error(f"Failed to generate packing slips: {e}")
            messagebox.showerror("Packing Slip Error", f"Error:\n{str(e)}")

        finally:
            # Cleanup temp file
            if 'temp_packing_slip' in locals() and os.path.exists(temp_packing_slip):
                try:
                    os.remove(temp_packing_slip)
                except:
                    pass
    
    def get_user_inputs(self, default_filename):
        
        #Prompt user for project information in a popup
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
            root.quit()  # Ensure the event loop quits properly
            root.destroy()

        root.protocol("WM_DELETE_WINDOW", on_close)

        # Button to submit inputs
        def submit():
            root.quit()  # Quit the popup loop
            root.destroy()  # Close the popup safely

        tk.Button(root, text="Submit", command=submit).grid(row=row, column=0, columnspan=2, pady=10)

        root.grab_set()  # Make the popup modal
        root.wait_window(root)  # Ensure the window waits before proceeding

        # Extract values
        return {key: var.get().strip() for key, var in user_inputs.items()}

    def run_script(self):
        self.outputs.clear()
        self.update_status("Running...")
        
        # Generate default filename with timestamp
        default_filename = ""
        queue = Queue()

        # Get user inputs from a single input popup
        user_inputs = self.get_user_inputs(default_filename)
        
        if not user_inputs:  # Ensure the window wasn't closed
            messagebox.showerror("Input Error", "User input window was closed without entering details.")
            return

        # Ensure all fields are provided
        for key, value in user_inputs.items():
            if not value.strip():  # Ensures no empty fields
                messagebox.showerror("Input Error", f"{key} is required.")
                return

        # Assign user inputs
        customer = user_inputs["Customer"]
        project = user_inputs["Project"]
        customer_po = user_inputs["Purchase Order"]
        sales_order = user_inputs["Sales Order"]
        filename = user_inputs["Filename"]

        # Sanitize user-provided filename
        filename = "".join(c for c in filename if c.isalnum() or c in (" ", "_", "-")).strip()
        if not filename:
            messagebox.showerror("Input Error", "Invalid filename entered.")
            return

        # Append metadata to filename
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
        final_filename = f"{filename}_{customer}_{project}_Inventory_{timestamp}"

        # Ask user for save folder
        save_folder = filedialog.askdirectory(title="Select Save Location")

        # If user cancels, use current directory
        if not save_folder:
            save_folder = os.getcwd()

        # Ensure filename is unique
        base_path = os.path.normpath(os.path.join(save_folder, f"{final_filename}.xlsx"))
        counter = 1
        self.output_file = base_path

        while os.path.exists(self.output_file):
            self.output_file = os.path.join(save_folder, f"{final_filename}_{counter}.xlsx")
            counter += 1
        

        
        # Get user input from the GUI
        pod_1 = self.pod_var_1.get()
        pod_2 = self.pod_var_2.get()

        start_ip_1 = self.start_ip_entry_1.get()
        end_ip_1 = self.end_ip_entry_1.get()
        start_ip_2 = self.start_ip_entry_2.get()
        end_ip_2 = self.end_ip_entry_2.get()

        # Validate inputs - Ensure at least one set is filled
        if not start_ip_1 or not end_ip_1:
            messagebox.showwarning("Input Error", "Please enter at least one IP range (IP Selection 1).")
            return

        try:
            start_ip_1, end_ip_1 = int(start_ip_1), int(end_ip_1)
            start_ip_2 = int(start_ip_2) if start_ip_2 else None
            end_ip_2 = int(end_ip_2) if end_ip_2 else None
        except ValueError:
            messagebox.showerror("Input Error", "IP values must be numbers.")
            return

        # Generate the list of IPs, ensuring uniqueness
        ip_list = {f"10.9.{pod_1}.{i}" for i in range(start_ip_1, end_ip_1 + 1)}

        if start_ip_2 is not None and end_ip_2 is not None and pod_2 != pod_1:
            ip_list.update(f"10.9.{pod_2}.{i}" for i in range(start_ip_2, end_ip_2 + 1))

        # Convert set back to list
        ip_list = list(ip_list)

        # Filter out unreachable IPs
        reachable_ips = [ip for ip in ip_list if script_interface.is_reachable(ip)]

        if not reachable_ips:
            queue.put("No reachable IPs found.")
            self.update_gui_from_queue(queue)
            return

        device_identifier = script_interface.DeviceIdentifier()
        script_selector = script_interface.ScriptSelector()

        # Identify the device and run the appropriate script
        for ip in reachable_ips:
            device_type, device_name = device_identifier.identify_device(ip, queue, self.output_screen)
            script_instance = script_selector.select_script(device_type, ip)

            if script_instance:
                self.task_queue.put((ip, script_instance))

        self.process_task_queue(queue)
        self.update_gui_from_queue(queue)

        # **Trigger export automatically after processing**
        self.root.after(100, lambda: self.output_to_excel(
            outputs=self.outputs,
            output_file=self.output_file,
            customer=customer,
            project=project,
            customer_po=customer_po,
            sales_order=sales_order
        ))
        # Redirect console output to the GUI output screen
        sys.stdout = ConsoleRedirector(self.output_screen)
        
        # Show success message
        self.output_screen.insert(tk.END, f"Report saved successfully as:\n{self.output_file}\n")
        self.output_screen.see(tk.END)  # Auto-scroll to the latest log
        self.stop_threads = True
        self.update_status("Ready")
        messagebox.showinfo("System Ready", "The system is ready.")


    def process_task_queue(self, queue):
        import scripts.Ciena_TDS
        while not self.task_queue.empty():
            item = self.task_queue.get()
            
            # Unpack original format: (ip, script_instance)
            ip, script_instance = item

            try:
                # 1. Run normal inventory (your existing logic)
                commands = script_instance.get_commands() or []
                if commands:
                    outputs_list, error = script_instance.execute_commands(commands)
                    if error:
                        queue.put(f"Error in normal inventory for {ip}: {error}")
                    elif outputs_list and hasattr(script_instance, "process_outputs"):
                        script_instance.process_outputs(outputs_list, ip, self.outputs)
                        queue.put(f"Normal inventory completed for {ip}")
                    else:
                        queue.put(f"No output from normal inventory for {ip}")

                # 2. Run Full TDS if checkbox is checked AND it's a Ciena 6500/CPL
                device_type = getattr(script_instance, 'device_type', None) or "Unknown"  # fallback
                if self.tds_var.get() and any(k in str(device_type).upper() for k in ["6500", "CPL", "CIENA"]):
                    queue.put(f"Running diagnostic on {ip}...\n")
                    try:
                        from scripts.Ciena_TDS import CienaTDS
                        
                        tds_script = CienaTDS(
                            ip_address=ip,
                            username=getattr(script_instance, 'username', 'admin'),
                            password=getattr(script_instance, 'password', 'admin'),
                            connection_type=getattr(script_instance, 'connection_type', 'telnet'),
                            db_cache=self.db_cache,
                            command_tracker=self.command_tracker
                        )
                        
                        tds_script.process_outputs([], ip, self.outputs)
                        queue.put(f"Full TDS diagnostic completed for {ip}\n")
                    except Exception as tds_err:
                        queue.put(f"TDS diagnostic failed for {ip}: {tds_err}\n")

                queue.put(f"Overall processing finished for {ip}")

            except Exception as e:
                queue.put(f"Error processing {ip}: {e}")

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
