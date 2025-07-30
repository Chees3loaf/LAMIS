import os
import sqlite3
import logging
import re
import time
from tkinter import messagebox
import pandas as pd
import subprocess
from openpyxl import load_workbook
from typing import Callable, Dict, List, Optional, Tuple
from script_interface import BaseScript, CommandTracker, DatabaseCache
import telnetlib


# Ensure logging is configured
logging.basicConfig(level=logging.DEBUG)

db_path = os.path.join(os.path.dirname(__file__), "data", "network_inventory.db")

class Script:
    def __init__(self, db_name='network_inventory.db', connection_type='telnet', command_tracker=None, **kwargs):
        db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", db_name))
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"Database file missing at: {db_path}")
        self.db_cache = DatabaseCache(db_path)
        self.connection_type = connection_type
        self.command_tracker = command_tracker or CommandTracker()
        self.telnet = None
        self.ip_address = kwargs.get('ip_address')
        self.username = kwargs.get('username', 'admin')
        self.password = kwargs.get('password', 'admin')
        self.timeout = kwargs.get('timeout', 5)

        if not self.ip_address:
            raise ValueError("Missing required 'ip_address' for network-based connection.")

    def get_commands(self) -> List[str]:
        return [
            'show general name',
            'show shelf inventory *',
            'show card inventory *',
            'show interface inventory *',
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
            if self.connection_type == 'telnet':
                output, error = self.execute_telnet_command(command)
            elif self.connection_type == 'ssh':
                logging.warning("SSH not supported. Switching to Telnet fallback.")
                self.connection_type = 'telnet'
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
        self.close_telnet()
        return outputs, None if all(outputs) else "Some commands failed"


    def telnet_login(self, retries: int = 2) -> bool:
        if self.telnet:
            return True

        for attempt in range(1, retries + 1):
            try:
                logging.info(f"Connecting to {self.ip_address} via Telnet (Attempt {attempt})...")
                self.telnet = telnetlib.Telnet(self.ip_address, timeout=self.timeout)

                self.telnet.read_until(b"login: ", timeout=5)
                self.telnet.write(b"cli\n")
                self.telnet.read_until(b"Username: ", timeout=5)
                self.telnet.write(self.username.encode('ascii') + b"\n")
                self.telnet.read_until(b"Password: ", timeout=5)
                self.telnet.write(self.password.encode('ascii') + b"\n")
                time.sleep(1)

                login_response = self.telnet.read_very_eager().decode('ascii')
                if "Login incorrect" in login_response or "invalid" in login_response.lower():
                    logging.error("Telnet login failed: Invalid credentials.")
                    self.telnet.close()
                    self.telnet = None
                    continue

                logging.info("Telnet login successful.")
                return True
            except Exception as e:
                logging.error(f"Telnet login attempt {attempt} failed: {e}")
                self.telnet = None

        return False


    def execute_telnet_command(self, command: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            if not self.telnet_login():
                return None, "Telnet login failed."

            logging.info(f"Successfully logged in via Telnet. Executing command: {command}")
            self.telnet.write(command.encode('ascii') + b"\n")
            time.sleep(3.5)
            output = self.capture_full_output_telnet()
            return output, None

        except Exception as e:
            logging.error(f"Telnet connection failed: {e}")
            return None, str(e)


    def capture_full_output_telnet(self) -> str:
        try:
            output = self.telnet.read_until(b"#", timeout=10).decode('ascii')
            return output.strip()
        except Exception as e:
            logging.error(f"Error capturing Telnet output: {e}")
            return ""
    
    def close_telnet(self):
        """
        Gracefully closes the Telnet session if it's open.
        """
        if self.telnet:
            try:
                self.telnet.write(b"exit\n")
                self.telnet.close()
                logging.info("Telnet session closed successfully.")
            except Exception as e:
                logging.warning(f"Failed to close Telnet session gracefully: {e}")
            finally:
                self.telnet = None

    def get_part_description(self, part_number: str) -> str:
        return self.db_cache.lookup_part(part_number)

                
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
            system_name_pattern = re.compile(r"Name:\s+([A-Za-z0-9_-]+)", re.MULTILINE | re.DOTALL)

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
                    description = self.db_cache.lookup_part(part_number)
                    logging.debug(f"Matched Shelf - Type: {shelf_type}, Part: {part_number}, Serial: {serial_number}")

                    # Append the parsed data
                    shelf_data.append({
                        'System Name': '',
                        'System Type': shelf_type,
                        'Type': shelf_type.title(),
                        'Part Number': part_number[:10], # Limit to 10 characters
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
            logging.debug(f"Cleaned output: {output}")
            # Regex to capture Location, Mnemonic, Part Number, and Serial Number
            card_pattern = re.compile(
                r"^\s*(\d+\/\d+)\s+[^\s]+\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)", re.MULTILINE
            )

            # Process each match from the regex
            matches = re.finditer(card_pattern, output)
            for match in matches:
                try:
                    slot = match.group(1).strip()
                    card_type = match.group(2).strip()
                    part_number = match.group(3).strip()
                    serial_number = match.group(4).strip()

                    # Get description from the database for the part number
                    description = self.db_cache.lookup_part(part_number)
                    logging.debug(f"Matched Card - Location: {slot}, Type: {type}, Part: {part_number}, Serial: {serial_number}")

                    # Append parsed data
                    card_data.append({
                        'System Name': '',
                        'System Type': '',
                        'Type': card_type.title(),
                        'Part Number': part_number[:10], # Limit to 10 characters
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
                    description = self.db_cache.lookup_part(part_number)
                    logging.debug(f"Matched Interface - Location: {location}, Module Type: {module_type}, Part: {part_number}, Serial: {serial_number}")

                    # Append the parsed data
                    interface_data.append({
                        'System Name': '',
                        'System Type': '',
                        'Type': module_type.title(),
                        'Part Number': part_number[:10], # Limit to 10 characters
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
                system_name_pattern = re.compile(r"Name:\s+([A-Za-z0-9_-]+)", re.MULTILINE | re.DOTALL)
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
                card_inventory_pattern = re.compile(r"^\s*(\d+\/\d+)\s+[^\s]+\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)", re.MULTILINE)
                if card_inventory_pattern.search(output):
                    logging.debug(f"Output for 'show card inventory' validated successfully.")
                    return True
                else:
                    logging.warning(f"Output for 'show card inventory' missing expected data.")
                    return False

            # Validation for 'show interface inventory *'
            elif command.startswith("show interface inventory"):
                interface_inventory_pattern = re.compile(r"^\s*(\d+\/\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", re.MULTILINE)
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
            if isinstance(df, pd.DataFrame):
                logging.info(f"Processed DataFrame under key '{key}' with {len(df)} rows.")

        if all_data:
            combined_df = pd.concat(all_data, ignore_index=True)
            logging.info(f"Combined DataFrame created with {len(combined_df)} rows from {len(all_data)} DataFrames.")
        else:
            combined_df = pd.DataFrame()
            logging.warning("No data to combine. Returning empty DataFrame.")
    
        return combined_df
                      
    '''def output_to_excel(
        self,
        outputs: Dict[str, Dict[str, Dict]],
        template_file: str,
        output_file: str,
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

            logging.info(f"Starting Excel output for {len(outputs)} devices.")
            for ip, data_dict in outputs.items():
                try:
                    logging.info(f"Processing data for IP {ip}.")
                    combined_df = self.combine_and_format_data(data_dict)  # Prepare combined data for each IP
                    if combined_df.empty:
                        logging.warning(f"No data to write for IP {ip}")
                        continue

                    # Sanitize and validate system name for sheet title
                    raw_name = combined_df.iloc[0].get('System Name', '')
                    system_name = str(raw_name).strip() if isinstance(raw_name, str) else f"System_{ip.replace('.', '_')}"
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
                        description = self.db_cache.lookup_part(part_number[:10])  # Limit part number to 10 characters

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
            logging.debug("SQLite connection closed.")'''



'''if __name__ == "__main__":
    def main():
        # Set target IP and Telnet credentials
        ip = '172.21.101.171'
        username = 'admin'  # <-- Replace this
        password = 'admin'  # <-- Replace this

        # Create Script instance
        script = Script(
            connection_type='telnet',
            ip_address=ip,
            username=username,
            password=password
        )

        # Get and run commands
        commands = script.get_commands()
        raw_outputs, error = script.execute_commands(commands)

        if error:
            print(f"Execution error: {error}")
            return

        # Initialize cache
        outputs = {}

        # Parse outputs
        script.process_outputs(raw_outputs, ip_address=ip, outputs=outputs)

        # Print DataFrames
        script.print_cached_data(outputs)

    main()'''