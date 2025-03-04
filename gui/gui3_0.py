from datetime import datetime
import os
import logging
import sqlite3
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from queue import Queue
from tkinter import simpledialog, filedialog
from typing import Dict

import openpyxl
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
        self.lock = threading.Lock()
        self.setup_gui()

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
        
        # Output Screen at the Bottom
        output_frame = ttk.LabelFrame(main_frame, text="Output Screen")
        output_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.output_screen = scrolledtext.ScrolledText(output_frame, height=15, width=120)
        self.output_screen.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def update_ip_labels(self, pod_var, start_ip_label, end_ip_label):
        """Update IP labels when the pod selection changes."""
        pod_number = pod_var.get()
        start_ip_label.config(text=f"Start IP: 172.21.{pod_number}.")
        end_ip_label.config(text=f"End IP: 172.21.{pod_number}.")

    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update_idletasks()
        
    def combine_and_format_data(self, ip_data: Dict[str, Dict]) -> pd.DataFrame:
        """Combines all data for an IP into a single DataFrame."""
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

        
    def output_to_excel(self, outputs: Dict[str, Dict[str, Dict]], db_file: str, output_file: str) -> None:
        """
        Writes processed data to an Excel file using a provided template.
        Each IP gets its own sheet. Ensures files do not overwrite existing data.
        """
        conn = None
        try:
            # Ensure template file exists
            if not os.path.exists(self.template_path):
                raise FileNotFoundError(f"Template file not found at {self.template_path}")

            # Load the template workbook
            wb = openpyxl.load_workbook(self.template_path)
            sheet = wb.active  # First sheet is the template

            # Open the SQLite database
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()

            logging.info(f"Starting Excel export for {len(outputs)} devices.")
            sheet_created = False  # Track if any new sheet is created
            
            for ip, data_dict in outputs.items():
                try:
                    logging.info(f"Processing data for IP {ip}.")
                    
                    # Combine data into one DataFrame per IP
                    combined_df = self.combine_and_format_data(data_dict)
                    
                    if combined_df.empty:
                        logging.warning(f"No data to write for IP {ip}")
                        continue

                    # Sanitize system name for sheet title
                    system_name = combined_df.iloc[0].get('System Name', '').strip() or f"System_{ip.replace('.', '_')}"
                    system_name = system_name.replace(':', '_').replace('/', '_')[:31]  # Excel sheet name limit

                    logging.info(f"Creating sheet for system '{system_name}' with {len(combined_df)} rows.")

                    # Create and reference the new sheet
                    new_sheet = wb.copy_worksheet(sheet)
                    new_sheet.title = system_name
                    sheet_created = True  # Mark that a new sheet was created

                    # Populate metadata
                    new_sheet['F6'] = combined_df.iloc[0].get('System Name', '')
                    new_sheet['F7'] = combined_df.iloc[0].get('System Type', '')
                    new_sheet['F5'] = combined_df.iloc[0].get('Source', '')

                    # Populate equipment details (starting at row 15)
                    start_row = 15
                    for idx, row in combined_df.iterrows():
                        row_num = start_row + idx
                        part_number = row.get('Part Number' or row.get('Model Number', ''), '')

                        # Fetch description from SQLite database using part number
                        description = ''
                        if part_number:
                            cursor.execute("SELECT description FROM parts WHERE part_number = ?", (part_number,))
                            result = cursor.fetchone()
                            if result:
                                description = result[0]

                        # Write data into the Excel sheet
                        new_sheet[f'B{row_num}'] = row.get('Name', '')
                        new_sheet[f'C{row_num}'] = row.get('Type', '')
                        new_sheet[f'D{row_num}'] = part_number
                        new_sheet[f'E{row_num}'] = row.get('Serial Number', '')
                        new_sheet[f'F{row_num}'] = description

                except Exception as e:
                    logging.error(f"Failed to process data for IP {ip}. Error: {e}")

            # Ensure at least one sheet is present before removing the template
            if sheet_created:
                wb.remove(sheet)
            else:
                logging.error("No sheets were created. Cannot remove the template sheet.")
                messagebox.showerror("Export Error", "No data available to export. The Excel file was not saved.")
                return

            # Save the workbook
            wb.save(output_file)
            logging.info(f"Data successfully saved to {output_file}")

            # Open the file automatically
            try:
                if os.name == "nt":  # Windows
                    os.startfile(output_file)
                elif os.name == "posix":  # macOS/Linux
                    subprocess.run(["open", output_file], check=True)
            except Exception as e:
                logging.error(f"Failed to open Excel file: {e}")

            # Show success message
            messagebox.showinfo("Success", f"Report saved successfully as:\n{output_file}")

        except Exception as e:
            logging.error(f"Failed to save data to Excel: {e}")
            messagebox.showerror("Export Error", f"Failed to save Excel file:\n{e}")
        finally:
            if conn:
                conn.close()

    
    def run_script(self):
        self.outputs.clear()
        self.update_status("Running...")

        queue = Queue()

        # Generate default filename with timestamp
        default_filename = f"LAMIS_Output_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"

        # Ask user for filename
        filename = simpledialog.askstring(
            "Filename Input",
            "Enter filename for the Excel report:",
            initialvalue=default_filename
        )

        # If user cancels, use default filename
        if not filename:
            logging.warning("No filename entered, using default.")
            filename = default_filename

        # Ask user for save folder
        save_folder = filedialog.askdirectory(title="Select Save Location")

        # If user cancels, use current directory
        if not save_folder:
            logging.warning("No folder selected, using current directory.")
            save_folder = os.getcwd()

        # Ensure filename is unique by appending numbers if needed
        base_path = os.path.join(save_folder, f"{filename}.xlsx")
        counter = 1
        self.output_file = base_path

        while os.path.exists(self.output_file):
            self.output_file = os.path.join(save_folder, f"{filename}_{counter}.xlsx")
            counter += 1

        # Ask user for Customer, Project, Customer Order, and Sales Order
        customer = simpledialog.askstring("Customer Name", "Enter the Customer Name:")
        project = simpledialog.askstring("Project Name", "Enter the Project Name:")
        customer_po = simpledialog.askstring("Customer PO", "Enter the Customer PO:")
        sales_order = simpledialog.askstring("Sales Order", "Enter the Sales Order:")

        # Ensure at least some input is provided; default to empty strings if user cancels
        customer = customer if customer else ""
        project = project if project else ""
        customer_po = customer_po if customer_po else ""
        sales_order = sales_order if sales_order else ""

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

        # **Open Excel file after saving**
        try:
            if os.name == "nt":  # Windows
                os.startfile(self.output_file)
            elif os.name == "posix":  # macOS/Linux
                subprocess.run(["open", self.output_file], check=True)
        except Exception as e:
            logging.error(f"Failed to open Excel file: {e}")

        # **Show success message**
        messagebox.showinfo("Success", f"Report saved successfully as:\n{self.output_file}")


    def process_task_queue(self, queue):
        """Processes the task queue and executes commands on each device."""
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
    

def main():
    logging.info("Starting LAMIS Inventory System")
    root = tk.Tk()
    app = InventoryGUI(root, update_available=False, command_tracker=script_interface.CommandTracker(), db_cache=script_interface.DatabaseCache("network_inventory.db"))
    root.mainloop()

if __name__ == "__main__":
    main()
