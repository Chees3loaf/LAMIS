from datetime import datetime
import os
import logging
import re
import shutil
import sqlite3
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from queue import Queue
from tkinter import filedialog
from typing import Dict
import time
import openpyxl
from openpyxl.utils import get_column_letter
from openpyxl.styles import Font
import pandas as pd
import script_interface

command_tracker = script_interface.CommandTracker()
db_cache = script_interface.DatabaseCache(os.path.join(os.path.dirname(__file__), "..", "data", "network_inventory.db"))
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
        self.db_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'network_inventory.db')
        self.template_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'Device_Report_Template.xlsx')
        self.packing_slip_template = os.path.join(os.path.dirname(__file__), '..', 'data', 'LAMIS_Packing_Slip.xlsx')
        self.lock = threading.Lock()

        # 🔹 Setup GUI Components
        self.setup_gui()

        # 🔹 Initialize ScrolledText for Output
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

        pod_options = [f"{100 + i}" for i in range(1, 15)] + ['118']

        # Pod Selection 1 (Left)
        pod_frame_1 = ttk.LabelFrame(left_middle_frame, text="Pod Selection 1")
        pod_frame_1.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(pod_frame_1, text="Pod:").pack(side=tk.LEFT, padx=5)
        self.pod_var_1 = tk.StringVar()
        self.pod_combobox_1 = ttk.Combobox(pod_frame_1, textvariable=self.pod_var_1, values=pod_options)
        self.pod_combobox_1.pack(side=tk.LEFT, padx=5)
        self.pod_combobox_1.set('101')
        
        # IP Selection 1 (Below Pod Selection 1)
        ip_frame_1 = ttk.LabelFrame(left_middle_frame, text="IP Selection 1")
        ip_frame_1.pack(fill=tk.X, padx=10, pady=5)
        ip_container_1 = ttk.Frame(ip_frame_1)
        ip_container_1.pack()
        self.start_ip_label_1 = tk.Label(ip_container_1, text=f"Start IP: 172.21.{self.pod_var_1.get()}.")
        self.start_ip_label_1.pack(side=tk.LEFT)
        self.start_ip_entry_1 = tk.Entry(ip_container_1, width=3, justify='center')
        self.start_ip_entry_1.pack(side=tk.LEFT)
        self.end_ip_label_1 = tk.Label(ip_container_1, text=f"End IP: 172.21.{self.pod_var_1.get()}.")
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
        self.pod_combobox_2.set('101')
        
        # IP Selection 2 (Below Pod Selection 2)
        ip_frame_2 = ttk.LabelFrame(right_middle_frame, text="IP Selection 2")
        ip_frame_2.pack(fill=tk.X, padx=10, pady=5)
        ip_container_2 = ttk.Frame(ip_frame_2)
        ip_container_2.pack()
        self.start_ip_label_2 = tk.Label(ip_container_2, text=f"Start IP: 172.21.{self.pod_var_2.get()}.")
        self.start_ip_label_2.pack(side=tk.LEFT)
        self.start_ip_entry_2 = tk.Entry(ip_container_2, width=3, justify='center')
        self.start_ip_entry_2.pack(side=tk.LEFT)
        self.end_ip_label_2 = tk.Label(ip_container_2, text=f"End IP: 172.21.{self.pod_var_2.get()}.")
        self.end_ip_label_2.pack(side=tk.LEFT)
        self.end_ip_entry_2 = tk.Entry(ip_container_2, width=3, justify='center')
        self.end_ip_entry_2.pack(side=tk.LEFT)
        self.pod_var_2.trace_add("write", lambda *args: self.update_ip_labels(self.pod_var_2, self.start_ip_label_2, self.end_ip_label_2))
        
        # Control Buttons below the Pod and IP Selections
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=10)
        tk.Button(control_frame, text="Run", command=self.run_script).pack(side=tk.RIGHT, padx=5)
        tk.Button(control_frame, text="Pause", command=self.pause_program).pack(side=tk.RIGHT, padx=5)
        tk.Button(control_frame, text="Abort", command=self.abort_program).pack(side=tk.RIGHT, padx=5)
        self.status_label = tk.Label(control_frame, text="Status: Ready", anchor="w")
        self.status_label.pack(side=tk.RIGHT, padx=10)
        
    def update_ip_labels(self, pod_var, start_ip_label, end_ip_label):
        # Update IP labels when the pod selection changes
        pod_number = pod_var.get()
        start_ip_label.config(text=f"Start IP: 172.21.{pod_number}.")
        end_ip_label.config(text=f"End IP: 172.21.{pod_number}.")

    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update_idletasks()
        
    def combine_and_format_data(self, ip_data: Dict[str, Dict]) -> pd.DataFrame:
        # Combines all data for an IP into a single DataFrame
        all_data = []
        logging.info(f"Starting combination of {len(ip_data)} data entries.")
        
        for key, data in ip_data.items():
            df = data['DataFrame']
            all_data.append(df)
            logging.info(f"Processed DataFrame under key '{key}' with {len(df)} rows.")

        if all_data:
            combined_df = pd.concat(all_data, ignore_index=True)
            logging.info(f"Combined DataFrame created with {len(combined_df)} rows from {len(all_data)} DataFrames.")
        else:
            combined_df = pd.DataFrame()
            logging.warning("No data to combine. Returning empty DataFrame.")
        
        return combined_df

        
    def output_to_excel(self, outputs, db_file, output_file, customer="", project="", customer_po="", sales_order=""):
        
        # Writes processed data to an Excel file using a provided template.
        # Preserves the DataFrame and prompts the user for packing slips.
        
        conn = None
        try:
            if not os.path.exists(self.template_path):
                raise FileNotFoundError(f"Template file not found at {self.template_path}")

            wb = openpyxl.load_workbook(self.template_path)
            sheet = wb.active

            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()

            logging.info(f"Starting Excel export for {len(outputs)} devices.")
            
            processed_data = {}  #  Dictionary to store processed DataFrame

            for ip, data_dict in outputs.items():
                try:
                    logging.info(f"Processing data for IP {ip}.")
                    combined_df = self.combine_and_format_data(data_dict)

                    if combined_df.empty:
                        logging.warning(f"No data to write for IP {ip}")
                        continue

                    system_name = combined_df.iloc[0].get('System Name', '').strip() or f"System_{ip.replace('.', '_')}"
                    system_name = system_name.replace(":", "_").replace("/", "_")[:31]
                    
                    system_type = combined_df.iloc[0].get('System Type', '').strip()
                    system_type = system_type.replace(":", "_").replace("/", "_")[:31]

                    logging.info(f"Creating sheet for system '{system_name}' with {len(combined_df)} rows.")

                    new_sheet = wb.copy_worksheet(sheet)
                    new_sheet.title = system_name

                    # Populate User Imputed Data 
                    new_sheet["C5"] = customer
                    new_sheet["C6"] = project
                    new_sheet["C7"] = customer_po
                    new_sheet["D7"] = sales_order
                    new_sheet["F5"] = combined_df.iloc[0].get("Source", "")
                    new_sheet["F6"] = system_name
                    new_sheet["F7"] = system_type

                    start_row = 15
                    for idx, row in combined_df.iterrows():
                        row_num = start_row + idx
                        part_number = row.get("Part Number", row.get("Model Number", ""))

                        description = ""
                        if part_number:
                            cursor.execute("SELECT description FROM parts WHERE part_number = ?", (part_number,))
                            result = cursor.fetchone()
                            if result:
                                description = result[0]

                        # ✅ Convert "Information Type" to string safely
                        info_type = str(row.get("Information Type", "")).lower() if row.get("Information Type") is not None else ""

                        # ✅ If it's an MDA row, format the Name field properly
                        name_value = row.get("Name", "")
                        if "mda card" in info_type:
                            match = re.search(r"\d+", str(name_value))  # Extracts the number safely
                            mda_number = match.group() if match else "Unknown"
                            name_value = f"MDA {mda_number}"  # ✅ Format name as "MDA 1", "MDA 5", etc.

                        # ✅ Insert Data into Excel
                        new_sheet[f"B{row_num}"] = name_value
                        new_sheet[f"C{row_num}"] = row.get("Type", "")
                        new_sheet[f"D{row_num}"] = part_number
                        new_sheet[f"E{row_num}"] = row.get("Serial Number", "")
                        new_sheet[f"F{row_num}"] = description
    
                    #  Store DataFrame for use in packing slip generation
                    processed_data[ip] = combined_df

                except Exception as e:
                    logging.error(f"Failed to process data for IP {ip}. Error: {e}")

            if len(wb.sheetnames) > 1:
                wb.remove(sheet)

            # Ensure file isn't locked
            while True:
                try:
                    wb.save(output_file)
                    logging.info(f"Data successfully saved to {output_file}")
                    break
                except PermissionError:
                    logging.warning(f"File is locked: {output_file}")
                    if not messagebox.askretrycancel("File Locked", f"Close '{output_file}' and retry."):
                        return
                    time.sleep(3)

            # Show success message and prompt user for packing slips
            user_wants_packing_slips = messagebox.askyesno(
                "Success",
                f"Report saved successfully as:\n{output_file}\n\nDo you need packing slips?"
            )

            #  Pass in-memory DataFrame instead of reading from Excel again
            if user_wants_packing_slips:
                logging.info("User requested packing slips. Generating now...")
                self.generate_packing_slips(processed_data, output_file, list(outputs.keys()), customer, project, customer_po, sales_order)
            else:
                logging.info("User skipped packing slip generation.")

        except Exception as e:
            logging.error(f"Failed to save data to Excel: {e}")
            messagebox.showerror("Export Error", f"Failed to save Excel file:\n{e}")

        finally:
            if conn:
                conn.close()

    def copy_sheet(self, source_sheet, target_wb, new_sheet_name):
    
        # Copies an entire sheet from one workbook to another while preserving formatting.
        
        new_sheet = target_wb.create_sheet(title=new_sheet_name)

        for row in source_sheet.iter_rows():
            for cell in row:
                new_sheet[cell.coordinate].value = cell.value  # ✅ Copy cell values

                # ✅ Copy formatting
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
        Generates a single packing slip workbook.
        Each device gets its own sheet based on the packing slip template.
        """

        try:
            # ✅ **Load the template**
            packing_template_path = self.packing_slip_template
            logging.debug(f"Loading template: {packing_template_path}")

            # ✅ **Copy template to prevent modification of the original**
            temp_packing_slip = os.path.join(os.getcwd(), "PackingSlip_Temp.xlsx")
            shutil.copy(packing_template_path, temp_packing_slip)

            # ✅ **Load the copied workbook**
            wb_final = openpyxl.load_workbook(temp_packing_slip)

            # ✅ **Find the packing slip template sheet**
            template_sheet = wb_final["Packing Slip"]  # Ensure this sheet exists
            if not template_sheet:
                logging.error("Packing Slip template not found in workbook.")
                messagebox.showerror("Packing Slip Error", "Packing Slip template sheet not found.")
                return

            # ✅ **Find the summary sheet**
            summary_sheet_name = next((s for s in wb_final.sheetnames if "summary" in s.lower()), None)
            if summary_sheet_name:
                summary_sheet = wb_final[summary_sheet_name]
                logging.debug(f"Using summary sheet: {summary_sheet_name}")
            else:
                error_msg = f"Error: No summary sheet found. Available sheets: {wb_final.sheetnames}"
                logging.error(error_msg)
                messagebox.showerror("Packing Slip Error", error_msg)
                return

            # ✅ **Prompt user for save location**
            save_folder = filedialog.askdirectory(title="Select Packing Slip Save Location")
            if not save_folder:
                logging.warning("No folder selected, using current directory.")
                save_folder = os.getcwd()

            # ✅ **Format the filename**
            filename = f"PackingSlip_{customer}_{project}_{datetime.now().strftime('%Y-%m-%d')}.xlsx"
            save_path = os.path.join(save_folder, filename)
            logging.debug(f"Packing slip will be saved to: {save_path}")

            # ✅ **Write customer details on the summary page**
            summary_sheet["B5"], summary_sheet["B7"] = "Customer", customer
            summary_sheet["D5"], summary_sheet["D7"] = "Project", project
            summary_sheet["F5"], summary_sheet["F7"] = "IP Addresses", ", ".join(ip_list)

            logging.debug("Customer details written to summary sheet.")

            # ✅ **Extract Device Column from processed_data**
            device_column = None
            for col in processed_data[next(iter(processed_data))].columns:
                if "system name" in col.lower() or "device id" in col.lower():
                    device_column = col
                    break

            if not device_column:
                error_msg = "Packing slip failed: No 'Device ID' column found in processed data."
                logging.error(error_msg)
                messagebox.showerror("Packing Slip Error", error_msg)
                return

            summary_sheet["H5"], summary_sheet["H7"] = "Device ID", device_column
            logging.debug(f"Device identifier column found: {device_column}")

            # ✅ **Generate Packing Slips for Each Device**
            logging.debug(f"Found {len(processed_data)} devices for packing slips.")

            for ip, device_data in processed_data.items():
                try:
                    device_name = device_data.iloc[0].get(device_column, f"Unknown_{ip}")
                    logging.debug(f"Creating packing slip for device: {device_name}")

                    # ✅ **Duplicate the existing packing slip sheet to retain formatting**
                    new_sheet = wb_final.copy_worksheet(template_sheet)
                    new_sheet.title = f"{device_name.replace(' ', '_')}"
                    logging.debug(f"Copied template to create: {new_sheet.title}")

                    # ✅ **Ensure merged cells are copied**
                    for merged_range in template_sheet.merged_cells.ranges:
                        new_sheet.merge_cells(str(merged_range))
                    logging.debug(f"Merged cells copied for {new_sheet.title}")

                    # ✅ **Assign device-specific values**
                    new_sheet["B5"], new_sheet["C5"] = "Customer", customer
                    new_sheet["B6"], new_sheet["C6"] = "Project", project
                    new_sheet["B7"], new_sheet["C7"] = "Device ID", device_name
                    new_sheet["B14"], new_sheet["B15"] = "Sales Order", sales_order
                    new_sheet["C14"], new_sheet["C15"] = "Customer PO", customer_po

                    # ✅ **Write each entry to its own row in the packing slip**
                    start_row = 15  # Data starts from this row

                    # 🔹 **Validate Column Names Before Writing Data**
                    try:
                        part_number_col = device_data.columns.get_loc("Part Number")
                        serial_number_col = device_data.columns.get_loc("Serial Number")
                        description_col = device_data.columns.get_loc("Description")
                    except KeyError as e:
                        logging.error(f"Column missing in DataFrame: {e}")
                        messagebox.showerror("Packing Slip Error", f"Missing expected column: {e}")
                        continue

                    for idx, row in enumerate(device_data.itertuples(index=False), start=0):
                        try:
                            part_number = row[part_number_col]
                            serial_number = row[serial_number_col]
                            description = row[description_col]
                        except IndexError:
                            logging.warning(f"Missing data in row {idx}. Skipping row.")
                            continue

                        row_num = start_row + idx  # Ensure each entry gets a new row

                        # ✅ **Write to correct columns**
                        new_sheet[f"D{row_num}"] = part_number
                        new_sheet[f"E{row_num}"] = serial_number
                        new_sheet[f"F{row_num}"] = description

                    logging.debug(f"Packing slip for {device_name} added to workbook with {len(device_data)} items.")

                except Exception as e:
                    logging.error(f"Failed to create packing slip for {device_name}: {e}")

            # ✅ **Ensure Summary Sheet is First**
            sheets = wb_final.sheetnames
            if summary_sheet_name in sheets:
                summary_index = sheets.index(summary_sheet_name)
                wb_final._sheets.insert(0, wb_final._sheets.pop(summary_index))
                logging.debug("Summary sheet moved to first sheet.")

            # ✅ **Remove the template sheet after copying**
            if "Packing Slip" in wb_final.sheetnames:
                del wb_final["Packing Slip"]
                logging.debug("Removed the original Packing Slip template sheet from the final workbook.")

            # ✅ **Save Workbook**
            wb_final.save(save_path)
            logging.info(f"Packing slips saved to {save_path}")
            messagebox.showinfo("Packing Slips", f"Packing slips saved successfully as:\n{save_path}")

        except Exception as e:
            logging.error(f"Failed to generate packing slips: {e}")
            messagebox.showerror("Packing Slip Error", f"An error occurred while generating packing slips: {e}")

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

        queue = Queue()

        # Generate default filename with timestamp
        default_filename = f"LAMIS_Output_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"

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

        # Validate filename (remove invalid characters)
        filename = "".join(c for c in filename if c.isalnum() or c in (" ", "_", "-")).strip()
        if not filename:
            messagebox.showerror("Input Error", "Invalid filename entered.")
            return

        # Ask user for save folder
        save_folder = filedialog.askdirectory(title="Select Save Location")

        # If user cancels, use current directory
        if not save_folder:
            save_folder = os.getcwd()

        # Ensure filename is unique
        base_path = os.path.normpath(os.path.join(save_folder, f"{filename}.xlsx"))
        counter = 1
        self.output_file = base_path

        while os.path.exists(self.output_file):
            self.output_file = os.path.join(save_folder, f"{filename}_{counter}.xlsx")
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
        ip_list = {f"172.21.{pod_1}.{i}" for i in range(start_ip_1, end_ip_1 + 1)}

        if start_ip_2 is not None and end_ip_2 is not None and pod_2 != pod_1:
            ip_list.update(f"172.21.{pod_2}.{i}" for i in range(start_ip_2, end_ip_2 + 1))

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
            script_class = script_selector.select_script(device_type)

            if script_class:
                self.task_queue.put((ip, script_class))

        self.process_task_queue(queue)
        self.update_gui_from_queue(queue)

        # **Trigger export automatically after processing**
        self.root.after(100, lambda: self.output_to_excel(
            outputs=self.outputs,
            db_file=self.db_file,
            output_file=self.output_file,
            customer=customer,
            project=project,
            customer_po=customer_po,
            sales_order=sales_order
        ))

        # Open Excel file after saving
        try:
            if os.name == "nt":  # Windows
                os.startfile(self.output_file)
            elif os.name == "posix":  # macOS/Linux
                subprocess.run(["open", self.output_file], check=True)
        except Exception as e:
            logging.error(f"Failed to open Excel file: {e}")

        # Show success message
        self.output_screen.insert(tk.END, f"Report saved successfully as:\n{self.output_file}\n")
        self.output_screen.see(tk.END)  # Auto-scroll to the latest log


    def process_task_queue(self, queue):
        # Processes the task queue and executes commands on each device
        while not self.task_queue.empty():
            ip, script_class = self.task_queue.get()
            try:
                # Initialize the script for the device
                script_instance = script_class(connection_type='ssh', ip_address=ip, username='admin', password='admin')


                # Get commands to execute
                commands = script_instance.get_commands() or []
                if not commands:
                    queue.put(f"No commands available for {ip}, skipping execution.")
                    continue

                # Execute the commands
                outputs, error = script_instance.execute_commands(commands)
                if error:
                    queue.put(f"Error executing commands on {ip}: {error}")
                    continue  # Skip further processing if an error occurred

                # Process and store the outputs
                if outputs:
                    if hasattr(script_instance, "process_outputs"):
                        script_instance.process_outputs(outputs, ip, self.outputs)
                    else:
                        queue.put(f"process_outputs() missing in script for {ip}. Skipping output processing.")
                    queue.put(f"Processing completed for {ip}")
                else:
                    queue.put(f"No output received from {ip}")

            except Exception as e:
                queue.put(f"Error processing {ip}: {e}")

        self.update_gui_from_queue(queue)  # Ensure GUI updates with results

    def update_gui_from_queue(self, queue):
        while not queue.empty():
            try:
                message = queue.get_nowait()
                self.output_screen.insert(tk.END, message + '\n')
                self.output_screen.see(tk.END)
            except queue.Empty:
                break  # Prevents crashing when the queue is unexpectedly empty
    
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
    app = InventoryGUI(root, update_available=False, command_tracker=script_interface.CommandTracker(), db_cache=script_interface.DatabaseCache("network_inventory.db"))
    root.mainloop()

if __name__ == "__main__":
    main()
