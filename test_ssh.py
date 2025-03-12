import os
import sqlite3
import logging
import re
import time
import pandas as pd
from typing import Callable, Dict, List, Optional, Tuple
from pexpect import spawn
import pexpect
from script_interface import BaseScript, CommandTracker

# Ensure logging is configured
logging.basicConfig(level=logging.DEBUG)

db_path = os.path.join(os.path.dirname(__file__), "data", "network_inventory.db")

class Script:
    def __init__(self, db_name='network_inventory.db', command_tracker=None, **kwargs):
        self.db_name = db_name
        self.command_tracker = command_tracker or CommandTracker()
        # 🔹 Hardcoded IP for standalone testing
        self.ip_address = "172.21.101.161"  # This replaces kwargs.get('ip_address')
        self.username = kwargs.get('username', 'admin')
        self.password = kwargs.get('password', 'admin')

    def get_commands(self) -> List[str]:
        return [
            'show general name',
            'show shelf inventory *',
            'show card inventory *',
            'show interface inventory *',
        ]


    def execute_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        """
        Executes a list of commands using SSH by manually sending 'ssh cli@172.21.101.161'.
        Then enters the username 'admin' and password 'admin' interactively.
        Captures the full output of all executed commands with extensive logging.
        """
        outputs = []
        full_output = ""
        start_time_total = time.time()  # Track total execution time

        try:
            logging.info(f"Starting SSH session to {self.ip_address} using pexpect...")

            # ✅ Step 1: Spawn an SSH session using pexpect
            ssh_session = spawn(f"ssh cli@{self.ip_address}", timeout=10)
            ssh_session.logfile = None  # Set to `sys.stdout.buffer` for debugging output in real-time

            # ✅ Step 2: Wait for 'Username:' prompt and send "admin"
            logging.info("Waiting for 'Username:' prompt...")
            ssh_session.expect("Username:")
            logging.info("Username prompt detected. Sending 'admin'.")
            ssh_session.sendline("admin")

            # ✅ Step 3: Wait for 'Password:' prompt and send "admin"
            logging.info("Waiting for 'Password:' prompt...")
            ssh_session.expect("Password:")
            logging.info("Password prompt detected. Sending 'admin'.")
            ssh_session.sendline("admin")

            # ✅ Step 4: Wait for CLI prompt to confirm login
            logging.info("Waiting for CLI prompt 'MUNR_1830#'...")
            ssh_session.expect("MUNR_1830#")
            logging.info("CLI prompt detected. Ready to execute commands.")

            # ✅ Step 5: Execute commands
            for command in commands:
                logging.info(f"Executing SSH command: {command}")
                ssh_session.sendline(command)
                ssh_session.expect("MUNR_1830#")  # Wait for next prompt
                output = ssh_session.before.decode("utf-8").strip()
                logging.debug(f"Output received for command '{command}':\n{output}")
                full_output += f"\nCommand: {command}\n{output}\n"
                outputs.append(output)

            ssh_session.sendline("exit")  # Close SSH session
            ssh_session.expect(pexpect.EOF)
            logging.info(f"SSH session closed for {self.ip_address}.")
            total_time = time.time() - start_time_total
            logging.info(f"All commands executed in {total_time:.2f} seconds.")

        except Exception as e:
            logging.error(f"Unexpected error: {e}", exc_info=True)
            return [], str(e)

        return outputs, full_output if all(outputs) else "Some commands failed"




    
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
                      
# ✅ Standalone execution for validation
if __name__ == "__main__":
    """
    Allows direct execution of this script from CMD for validation.
    """
    script = Script()
    commands = script.get_commands()
    results, full_output = script.execute_commands(commands)

    print("\n--- SSH SESSION OUTPUT ---\n")
    print(full_output)

    # ✅ Process outputs and extract structured data
    parsed_data = {}

    if results:
        parsed_data['system_name'] = script.extract_system_name(results[0])
        parsed_data['shelf_inventory'] = script.extract_shelf_inventory(results[1])
        parsed_data['card_inventory'] = script.extract_card_inventory(results[2])
        parsed_data['interface_inventory'] = script.extract_interface_inventory(results[3])

        # ✅ Combine all parsed data into a single DataFrame
        final_df = script.combine_and_format_data(parsed_data)

        print("\n--- Extracted System Info ---\n")
        print(final_df.to_string(index=False))  # ✅ Print final DataFrame
