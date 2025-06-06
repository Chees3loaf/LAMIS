import os
import sqlite3
import logging
import re
import time
from tkinter import messagebox
import pandas as pd
import paramiko
import subprocess
from openpyxl import load_workbook
from typing import Callable, Dict, List, Optional, Tuple
import serial
from script_interface import BaseScript, CommandTracker
import telnetlib

# Ensure logging is configured
logging.basicConfig(level=logging.DEBUG)

db_path = os.path.join(os.path.dirname(__file__), "data", "network_inventory.db")

class Script:
    def __init__(self, db_name='network_inventory.db', connection_type='serial', command_tracker=None, **kwargs):
        self.db_name = db_name
        self.connection_type = connection_type
        self.command_tracker = command_tracker or CommandTracker()  # Initialize with a tracker or use a provided one
        if connection_type == 'serial':
            self.serial_port = kwargs.get('serial_port')
            self.baud_rate = kwargs.get('baud_rate')
            self.timeout = kwargs.get('timeout', 5)  # Increase timeout to 5 seconds
        elif connection_type == 'telnet':
            self.ip_address = kwargs.get('ip_address')
            self.username = kwargs.get('username')
            self.password = kwargs.get('password')

    def get_commands(self) -> List[str]:
        return [
            'show general name',
            'show shelf inventory *',
            'show interface inventory *',
            'show card inventory *',
        ]

    def execute_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        """
        Executes a list of commands using the specified connection type.
        Tracks commands to ensure they are only executed once per device.
        """
        outputs = []

        for command in commands:
            if self.command_tracker.has_executed(self.ip_address, command, self.connection_type):
                logging.info(f"Skipping previously executed command: {command}")
                continue  # Skip commands already executed for this device

            if self.connection_type == 'serial':
                output, error = self.execute_serial_commands(command)
            elif self.connection_type == 'telnet':
                output, error = self.execute_telnet_command(command)
            else:
                error = f"Invalid connection type: {self.connection_type}"
                output = None

            if error:
                logging.error(f"Error executing command '{command}': {error}")
                outputs.append(None)
            else:
                outputs.append(output)
                # Pass self.connection_type to mark_as_executed
                self.command_tracker.mark_as_executed(self.ip_address, command, self.connection_type)

        return outputs, None if all(outputs) else "Some commands failed"


    def telnet_login(self, tn: telnetlib.Telnet) -> bool:
        """
        Handles the Telnet login sequence and verifies credentials.
        """
        try:
            # Send initial login command
            logging.debug("Starting Telnet login sequence.")
            tn.read_until(b"login: ", timeout=5)
            tn.write(b"cli\n")
            logging.debug("Sent 'cli' for initial login prompt.")

            # Provide credentials
            tn.read_until(b"Username: ", timeout=5)
            tn.write(self.username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(self.password.encode('ascii') + b"\n")
            time.sleep(1)  # Allow time for login response

            # Check login response
            login_response = tn.read_very_eager().decode('ascii')
            if "Login incorrect" in login_response or "invalid" in login_response.lower():
                logging.error("Telnet login failed: Invalid credentials.")
                return False

            logging.info("Telnet login successful.")
            return True
        except Exception as e:
            logging.error(f"Telnet login sequence failed: {e}")
            return False


    def execute_telnet_command(self, command: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Executes a single command via Telnet using the specific login sequence.
        """
        try:
            logging.info(f"Connecting to {self.ip_address} via Telnet...")
            tn = telnetlib.Telnet(self.ip_address, timeout=10)  # Telnet connection with 10s timeout

            # Verify login before executing any commands
            if not self.telnet_login(tn):
                tn.close()
                return None, "Telnet login failed."

            # Execute the command
            logging.info(f"Successfully logged in via Telnet. Executing command: {command}")
            tn.write(command.encode('ascii') + b"\n")
            time.sleep(2)  # Wait for output to stabilize

            # Read and capture the command output
            output = self.capture_full_output_telnet(tn)
            if not output:
                logging.warning(f"No output received for command: {command}")

            tn.write(b"exit\n")  # Exit Telnet session
            tn.close()
            return output, None

        except Exception as e:
            logging.error(f"Telnet connection failed: {e}")
            return None, str(e)


    def capture_full_output_telnet(self, tn: telnetlib.Telnet) -> str:
        """
        Reads the full output from a Telnet session after a command is sent.
        """
        output = ""
        try:
            while True:
                chunk = tn.read_very_eager().decode('ascii')  # Read available output
                if chunk:
                    output += chunk
                else:
                    break  # Exit when no more data is available
            return output.strip()
        except Exception as e:
            logging.error(f"Error capturing Telnet output: {e}")
            return ""

    def execute_serial_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        try:
            with serial.Serial(self.serial_port, self.baud_rate, timeout=self.timeout) as ser:
                logging.info(f"Connected to serial port {self.serial_port}")

                outputs = []
                for command in commands:
                    output = self.capture_full_output_serial(ser, command)
                    if output is None:
                        error_message = f"Failed to execute command: {command}"
                        logging.error(error_message)
                        return outputs, error_message
                    outputs.append(output)

                return outputs, None

        except Exception as e:
            logging.error(f"Serial connection failed: {e}")
            return [], str(e)

    def capture_full_output_serial(self, ser, command: str) -> str:
        try:
            logging.info(f"Executing command: {command}")
            ser.write((command + '\n').encode())

            output = ""
            while True:
                time.sleep(1)
                chunk = ser.read(ser.in_waiting or 1).decode('utf-8')
                logging.debug(f"Read chunk: {chunk}")  # Debugging output
                if chunk:
                    output += chunk
                if "Press any key to continue" in chunk:
                    ser.write(b' ')
                    output = output.replace("Press any key to continue (Q to quit)", "")
                    time.sleep(2)
                if ser.in_waiting == 0:
                    break

            logging.debug(f"Output: {output}")

            return output

        except Exception as e:
            logging.error(f"Exception in executing command: {e}")
            return None
    
    def get_part_description(self, part_number: str) -> str:
        """
        Fetches the description of a part from the database based on part number.
        """
        conn = None
        try:
            # Use the globally defined db_path
            global db_path
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Execute query
            cursor.execute('SELECT description FROM parts WHERE part_number = ?', (part_number,))
            result = cursor.fetchone()

            # Debug log
            logging.debug(f"Query result for part_number '{part_number}': {result}")

            return result[0] if result else "Unknown"

        except sqlite3.Error as e:
            logging.error(f"Database error for part_number '{part_number}': {e}")
            return f"Database Error: {e}"

        finally:
            if conn:
                conn.close()
                
    def extract_system_name(
            self,
            output: str,
            cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
            ip: Optional[str] = None
        ) -> pd.DataFrame:
        
        system_data = []

        try:
            logging.debug(f"Raw output: {output}")
            output = output.strip()

            # Regex pattern to extract the system name
            system_name_pattern = re.compile(r"System Name\W ([A-Z0-9_]+)", re.MULTILINE | re.DOTALL)

            # Search for the system name
            match = system_name_pattern.search(output)
            if match:
                system_name = match.group(1).strip()
                logging.debug(f"Extracted System Name: {system_name}")

                # Append the extracted data
                system_data.append({
                    'System Name': system_name,
                    'Source': ip or 'Unknown'
                })
            else:
                logging.warning("No system name found in output.")
                system_data.append({
                    'System Name': 'Unknown',
                    'Source': ip or 'Unknown'
                })

        except Exception as e:
            logging.error(f"Error in extract_system_name: {e}")
            system_data.append({
                'System Name': "Error",
                'Source': ip or 'Unknown'
            })

        # Convert to DataFrame
        df = pd.DataFrame(system_data)
        if df.empty:
            logging.warning("No system name data found or parsing failed. Returning empty DataFrame.")
        else:
            logging.info(f"DataFrame for System Name is populated:\n{df}")

        logging.debug("\n" + df.to_string())

        if cache_callback:
            cache_callback(df, 'system_name')

        print(df.to_string(index=False))

        return df
                      
    def extract_shelf_inventory(
            self,
            output: str,
            cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
            ip: Optional[str] = None
        ) -> pd.DataFrame:
        
        shelf_data = []

        try:
            logging.debug(f"Raw output: {output}")
            output = output.strip()

            # Regex pattern to extract details
            shelf_pattern = re.compile(r"^\s*\d+\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)", re.MULTILINE | re.DOTALL)

            # Process each match from the regex
            matches = re.finditer(shelf_pattern, output)
            for match in matches:
                try:
                    shelf_type = match.group(1).strip()  # Group 1: Type
                    part_number = match.group(2).strip()  # Group 2: Part Number
                    serial_number = match.group(3).strip()  # Group 3: Serial Number

                    # Get description for the part number
                    description = self.get_part_description(part_number[:10])  # Limit to 10 characters
                    logging.debug(f"Matched Shelf - Type: {shelf_type}, Part: {part_number}, Serial: {serial_number}")

                    # Append the parsed data
                    shelf_data.append({
                        'System Name': '',
                        'System Type': shelf_type,
                        'Type': shelf_type.title(),
                        'Part Number': part_number,
                        'Serial Number': serial_number,
                        'Description': description,
                        'Name': f"Shelf {shelf_type}",
                        'Source': ip or 'Unknown'
                    })

                except Exception as match_error:
                    logging.error(f"Error processing shelf inventory match: {match_error}")
                    continue

            if not shelf_data:
                logging.warning("No shelf inventory data found in output.")
            else:
                logging.debug(f"Data successfully extracted: {shelf_data}")

        except Exception as e:
            logging.error(f"Error in extract_shelf_inventory: {e}")
            shelf_data.append({
                'System Name': '',
                'System Type': '',
                'Type': 'Error',
                'Part Number': "Error",
                'Serial Number': "Error",
                'Description': "Error",
                'Name': 'Error',
                'Source': ip or 'Unknown'
            })

        # Convert to DataFrame
        df = pd.DataFrame(shelf_data)
        if df.empty:
            logging.warning("No shelf inventory data found or parsing failed. Returning empty DataFrame.")
        else:
            logging.info(f"DataFrame for Shelf Inventory is populated:\n{df}")

        logging.debug("\n" + df.to_string())

        if cache_callback:
            cache_callback(df, 'shelf_inventory')

        print(df.to_string(index=False))

        return df
        
    def extract_card_inventory(
            self,
            output: str,
            cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
            ip: Optional[str] = None
        ) -> pd.DataFrame:
       
        card_data = []

        try:
            # Clean up the raw output
            logging.debug(f"Raw output: {output}")
            output = output.replace("Press any key to continue (Q to quit)", "").strip()

            # Regex to capture Location, Mnemonic, Part Number, and Serial Number
            card_pattern = re.compile(
                r"^\s*(\d+\/\d+)\s+[^\s]+\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)", re.MULTILINE
            )

            # Process each match from the regex
            matches = re.finditer(card_pattern, output)
            for match in matches:
                try:
                    slot = match.group(1).strip()
                    type = match.group(2).strip()
                    part_number = match.group(3).strip()
                    serial_number = match.group(4).strip()

                    # Get description from the database for the part number
                    description = self.get_part_description(part_number[:10])  # Limit part number to 10 characters
                    logging.debug(f"Matched Card - Location: {slot}, Type: {type}, Part: {part_number}, Serial: {serial_number}")

                    # Append parsed data
                    card_data.append({
                        'System Name': '',
                        'System Type': '',
                        'Type': type.title(),
                        'Part Number': part_number,
                        'Serial Number': serial_number,
                        'Description': description,
                        'Name': slot,
                        'Source': ip or 'Unknown'
                    })

                except Exception as match_error:
                    logging.error(f"Error processing card match: {match_error}")
                    continue

            # Handle case where no data was parsed
            if not card_data:
                logging.warning("No card data found in output.")
            else:
                logging.debug(f"Data successfully extracted: {card_data}")

        except Exception as e:
            logging.error(f"Error in Card Inventory: {e}")
            card_data.append({
                'System Name': '',
                'System Type': '',
                'Type': 'Error',
                'Part Number': "Error",
                'Serial Number': "Error",
                'Description': "Error",
                'Name': 'Error',
                'Source': ip or 'Unknown'
            })

        # Convert to DataFrame
        df = pd.DataFrame(card_data)
        if df.empty:
            logging.warning("No card data found or parsing failed. Returning empty DataFrame.")
        else:
            logging.info(f"DataFrame for cards is populated:\n{df}")

        logging.debug("\n" + df.to_string())

        # Cache the DataFrame if callback is provided
        if cache_callback:
            cache_callback(df, 'card data')

        # Print the DataFrame for review
        print(df.to_string(index=False))

        return df
    
    def extract_interface_inventory(
            self,
            output: str,
            cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
            ip: Optional[str] = None
        ) -> pd.DataFrame:
        
        interface_data = []

        try:
            logging.debug(f"Raw output: {output}")
            output = output.strip()

            # Updated regex to match only valid data rows
            interface_pattern = re.compile(
                r"^\s*(\d+\/\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", re.MULTILINE
            )

            # Process each match from the regex
            matches = re.finditer(interface_pattern, output)
            for match in matches:
                try:
                    location = match.group(1).strip()
                    module_type = match.group(2).strip()
                    part_number = match.group(3).strip()
                    serial_number = match.group(4).strip()

                    # Get description for the part number
                    description = self.get_part_description(part_number[:10])  # Limit to 10 characters
                    logging.debug(f"Matched Interface - Location: {location}, Module Type: {module_type}, Part: {part_number}, Serial: {serial_number}")

                    # Append the parsed data
                    interface_data.append({
                        'System Name': '',
                        'System Type': '',
                        'Type': module_type.title(),
                        'Part Number': part_number,
                        'Serial Number': serial_number,
                        'Description': description,
                        'Name': f"Port {location}",
                        'Source': ip or 'Unknown'
                    })

                except Exception as match_error:
                    logging.error(f"Error processing interface inventory match: {match_error}")
                    continue

            if not interface_data:
                logging.warning("No interface inventory data found in output.")
            else:
                logging.debug(f"Data successfully extracted: {interface_data}")

        except Exception as e:
            logging.error(f"Error in extract_interface_inventory: {e}")
            interface_data.append({
                'System Name': '',
                'System Type': '',
                'Type': 'Error',
                'Part Number': "Error",
                'Serial Number': "Error",
                'Description': "Error",
                'Name': 'Error',
                'Source': ip or 'Unknown'
            })

        # Convert to DataFrame
        df = pd.DataFrame(interface_data)
        if df.empty:
            logging.warning("No interface inventory data found or parsing failed. Returning empty DataFrame.")
        else:
            logging.info(f"DataFrame for Interface Inventory is populated:\n{df}")

        logging.debug("\n" + df.to_string())

        if cache_callback:
            cache_callback(df, 'interface_inventory')

        print(df.to_string(index=False))

        return df    

    def process_outputs(self, outputs_from_device: List[str], ip_address: str, outputs: Dict[str, Dict[str, Dict]]) -> None:
        """
        Processes outputs from a device and caches parsed data.

        :param outputs_from_device: List of command outputs from the device.
        :param ip_address: IP address or identifier of the device.
        :param outputs: Shared data structure for storing results.
        """
        if not outputs_from_device:
            logging.warning(f"No outputs received from device at {ip_address}. Skipping processing.")
            return

        # Define the processing functions and corresponding data keys
        processing_functions = [
            lambda output, callback: self.extract_system_name(output, callback, ip_address),
            lambda output, callback: self.extract_shelf_inventory(output, callback, ip_address),
            lambda output, callback: self.extract_card_inventory(output, callback, ip_address),
            lambda output, callback: self.extract_interface_inventory(output, callback, ip_address),
        ]

        # Example system info; replace with actual data as necessary
        system_info = {'System Name': 'Example System', 'System Type': 'Type A'}

        # Ensure outputs_from_device aligns with processing functions
        if len(outputs_from_device) != len(processing_functions):
            logging.warning(
                f"Mismatch between outputs and processing functions for device {ip_address}. "
                f"Expected {len(processing_functions)} outputs, but received {len(outputs_from_device)}."
            )

        # Process each command output with the corresponding function
        for idx, (command_output, processing_function) in enumerate(zip(outputs_from_device, processing_functions)):
            if not command_output:
                logging.warning(f"Command output {idx} for {ip_address} is empty or None. Skipping this step.")
                continue

            try:
                processing_function(
                    command_output,
                    lambda df, key: self.cache_data_frame(outputs, ip_address, key, df, system_info)
                )
            except Exception as e:
                logging.error(
                    f"Error processing output {idx} for device {ip_address}: {e}",
                    exc_info=True
                )
                continue

        logging.info(f"All outputs processed successfully for device {ip_address}.")
            
    def is_valid_output(self, output: str, command: str) -> bool:
        """
        Validate the output of a command to ensure it matches the expected structure or patterns.

        Args:
            output (str): The raw output from the device.
            command (str): The command that was executed.

        Returns:
            bool: True if the output is valid, False otherwise.
        """
        try:
            if not output or not output.strip():
                logging.warning(f"Empty or missing output for command: {command}")
                return False

            # Validation for 'show general name'
            if command.startswith("show general name"):
                system_name_pattern = re.compile(r"System Name\W+([A-Z0-9_]+)", re.MULTILINE | re.DOTALL)
                if system_name_pattern.search(output):
                    logging.debug(f"Output for 'show general name' validated successfully.")
                    return True
                else:
                    logging.warning(f"Output for 'show general name' missing expected pattern.")
                    return False

            # Validation for 'show shelf inventory *'
            elif command.startswith("show shelf inventory"):
                shelf_inventory_pattern = re.compile(r"^\s*\d+\s+\S+\s+\S+\s+\S+", re.MULTILINE)
                if shelf_inventory_pattern.search(output):
                    logging.debug(f"Output for 'show shelf inventory' validated successfully.")
                    return True
                else:
                    logging.warning(f"Output for 'show shelf inventory' missing expected data.")
                    return False

            # Validation for 'show card inventory *'
            elif command.startswith("show card inventory"):
                card_inventory_pattern = re.compile(r"^\s*(\d+/\d+)\s+\S+\s+\S+\s+\S+", re.MULTILINE)
                if card_inventory_pattern.search(output):
                    logging.debug(f"Output for 'show card inventory' validated successfully.")
                    return True
                else:
                    logging.warning(f"Output for 'show card inventory' missing expected data.")
                    return False

            # Validation for 'show interface inventory *'
            elif command.startswith("show interface inventory"):
                interface_inventory_pattern = re.compile(r"^\s*(\d+/\S+)\s+\S+\s+\S+\s+\S+", re.MULTILINE)
                if interface_inventory_pattern.search(output):
                    logging.debug(f"Output for 'show interface inventory' validated successfully.")
                    return True
                else:
                    logging.warning(f"Output for 'show interface inventory' missing expected data.")
                    return False

            # General validation for unknown commands
            if len(output.strip()) > 10:  # Arbitrary threshold for meaningful data
                logging.debug(f"Output for unknown command '{command}' contains sufficient data.")
                return True
            else:
                logging.warning(f"Output for unknown command '{command}' is too short or meaningless.")
                return False

        except Exception as e:
            logging.error(f"Error validating output for command '{command}': {e}", exc_info=True)
            return False

    def cache_data_frame(self, outputs: Dict[str, Dict[str, Dict]], ip: str, key: str, df: pd.DataFrame, system_info: Dict[str, str]) -> bool:
        try:
            if ip not in outputs:
                outputs[ip] = {}
            outputs[ip][key] = {'DataFrame': df, 'System Info': system_info}
            logging.info(f"DataFrame for {ip} under key {key} cached successfully.")
            return True
        except Exception as e:
            logging.error(f"Failed to cache data for {ip} under key {key}. Error: {e}")
            return False
        
    def print_cached_data(self, outputs: Dict[str, Dict[str, Dict]]) -> None:
        try:
            if not outputs:
                logging.warning("No data has been cached to display.")
                print("No cached data to display.")
                return

            print("\n--- All Cached DataFrames ---")
            for ip, ip_data in outputs.items():
                print(f"\nIP Address: {ip}")
                for key, data in ip_data.items():
                    print(f"  Key: {key}")
                    print("  DataFrame:")
                    print(data['DataFrame'])
                    print("  System Info:")
                    for info_key, info_value in data['System Info'].items():
                        print(f"    {info_key}: {info_value}")

            logging.info("All cached data has been displayed successfully.")
        except Exception as e:
            logging.error(f"Failed to print cached data. Error: {e}")
            print(f"Error while printing cached data: {e}")

    def combine_and_format_data(self, ip_data: Dict[str, Dict]) -> pd.DataFrame:
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
                      
    def output_to_excel(
        self,
        outputs: Dict[str, Dict[str, Dict]],
        template_file: str,
        output_file: str,
        db_file: str,
        customer: str = '',
        project: str = '',
        sales_order: str = '',
        customer_po: str = ''
    ) -> None:
        """
        Writes processed data to an Excel file using a provided template, with metadata from GUI inputs.
        """
        conn = None
        try:
            # Resolve template path
            template_path = os.path.abspath(template_file)
            if not os.path.exists(template_path):
                raise FileNotFoundError(f"Template file not found at {template_path}")

            # Load the template workbook
            wb = load_workbook(template_path)
            sheet = wb.active  # Assuming the first sheet is the template

            # Open the SQLite database
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()

            logging.info(f"Starting Excel output for {len(outputs)} devices.")
            for ip, data_dict in outputs.items():
                try:
                    logging.info(f"Processing data for IP {ip}.")
                    combined_df = self.combine_and_format_data(data_dict)  # Prepare combined data for each IP
                    if combined_df.empty:
                        logging.warning(f"No data to write for IP {ip}")
                        continue

                    # Sanitize and validate system name for sheet title
                    system_name = combined_df.iloc[0].get('System Name', '').strip()
                    if not system_name:
                        system_name = f"System_{ip.replace('.', '_')}"

                    # Replace invalid characters and truncate to 31 characters (Excel constraints)
                    system_name = system_name.replace(':', '_').replace('/', '_')[:31]

                    logging.info(f"Creating sheet for system '{system_name}' with {len(combined_df)} rows.")

                    # Create and reference the new sheet
                    new_sheet = wb.copy_worksheet(sheet)
                    new_sheet.title = system_name

                    # Populate metadata (user-defined fields and static fields)
                    new_sheet['F6'] = combined_df.iloc[0].get('System Name', '')
                    new_sheet['F7'] = combined_df.iloc[0].get('System Type', '')
                    new_sheet['C5'] = customer
                    new_sheet['F5'] = combined_df.iloc[0].get('Source', '')
                    new_sheet['C6'] = project
                    new_sheet['D7'] = sales_order
                    new_sheet['C7'] = customer_po

                    # Populate equipment details (row by row, starting at row 15)
                    start_row = 15
                    for idx, row in combined_df.iterrows():
                        row_num = start_row + idx
                        part_number = row.get('Part Number', row.get('Model Number', ''))

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

            # Remove the original template sheet
            wb.remove(sheet)

            # Save the workbook
            wb.save(output_file)
            logging.info(f"Data successfully saved to {output_file}")

            # Open the file (platform-specific handling)
            if os.name == 'nt':  # Windows
                subprocess.run(["start", output_file], check=True, shell=True)
            else:  # macOS/Linux
                subprocess.run(["open", output_file], check=True, shell=True)

        except Exception as e:
            logging.error(f"Failed to save data to Excel: {e}")
            messagebox.showerror("Export Error", f"Failed to save Excel file:\n{e}")
        finally:
            # Close the SQLite connection
            if conn:
                conn.close()