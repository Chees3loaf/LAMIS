import datetime
import os
import sqlite3
import logging
import re
import time
from tkinter import filedialog, messagebox
import pandas as pd
import paramiko
import subprocess
from openpyxl import load_workbook
from typing import Callable, Dict, List, Optional, Tuple
import serial
from script_interface import BaseScript

# Ensure logging is configured
logging.basicConfig(level=logging.DEBUG)

db_path = os.path.join(os.path.dirname(__file__),"..", "data", "network_inventory.db")

class Script(BaseScript):
    def __init__(self, db_name='network_inventory.db', connection_type='serial', **kwargs):
        self.db_name = db_name
        self.connection_type = connection_type
        self.device_name = None
        self.device_type = None
        if connection_type == 'serial':
            self.serial_port = kwargs.get('serial_port')
            self.baud_rate = kwargs.get('baud_rate')
            self.timeout = kwargs.get('timeout', 5)  # Increase timeout to 5 seconds
        elif connection_type == 'ssh':
            self.ip_address = kwargs.get('ip_address')
            self.username = kwargs.get('username')
            self.password = kwargs.get('password')

    def get_commands(self) -> List[str]:
        return [
            'show chassis detail  | match "(Name.+)|(Type.+)|(Part.+)|(Serial.+)" pre-lines 1 expression',
            'show card a detail | match expression "(Slot)|(^A)|(Part number)|(Serial number)"',
            'show card b detail | match expression "(Slot)|(^B)|(Part number)|(Serial number)"',
            'show mda detail | match "(Slot)|(up)|(Serial.+)|(Part.+)" post-lines 1 expression',
            'show port detail | match "(Optical Compliance.+)|(Serial.+)|(Model.+)|(Part.+)|(Interface +: [0-9/]+)" expression'
        ]

    def execute_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        if self.connection_type == 'serial':
            return self.execute_serial_commands(commands)
        elif self.connection_type == 'ssh':
            return self.execute_ssh_commands(self.ip_address, self.username, self.password, commands)
        else:
            raise ValueError("Invalid connection type")
    
    def execute_ssh_commands(self, ip_address: str, username: str, password: str, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.info(f"Connecting to {ip_address}")
            ssh_client.connect(ip_address,
                               username=username,
                               password=password, 
                               look_for_keys=False,
                               allow_agent=False,
                               timeout=10
                               )
            logging.info(f"Connected to {ip_address}")

            shell = ssh_client.invoke_shell()
            time.sleep(1)  # Give the shell some time to initialize

            outputs = []
            for command in commands:
                output = self.capture_full_output_ssh(shell, command)
                if output is None:
                    error_message = f"Failed to execute command: {command}"
                    logging.error(error_message)
                    shell.close()
                    ssh_client.close()
                    return outputs, error_message
                outputs.append(output)

            shell.close()
            ssh_client.close()
            return outputs, None

        except Exception as e:
            logging.error(f"SSH connection failed: {e}")
            return [], str(e)

    def capture_full_output_ssh(self, shell, command: str) -> str:
        try:
            logging.info(f"Executing command: {command}")
            shell.send(command + '\n')

            output = ""
            while True:
                if shell.recv_ready():
                    chunk = shell.recv(65535).decode('utf-8')
                    output += chunk
                    if "Press any key to continue" in chunk:
                        shell.send(' ')
                        output = output.replace("Press any key to continue (Q to quit)", "")
                        time.sleep(2)
                    if shell.recv_stderr_ready():
                        error_chunk = shell.recv_stderr(65535).decode('utf-8')
                        if error_chunk:
                            logging.error(f"Error output: {error_chunk}")
                            break
                else:
                    time.sleep(1)
                    if not shell.recv_ready() and not shell.recv_stderr_ready():
                        break

            logging.debug(f"Output: {output}")

            return output

        except Exception as e:
            logging.error(f"Exception in executing command: {e}")
            return None

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


    def extract_hardware_data(self, output: str, cache_callback: Callable[[pd.DataFrame, str], None], ip: str) -> None:
        data = []
        system_info = {}

        try:
            # Extract system info using separate regexes
            name_match = re.search(r"^\s*Name\s*:\s*(.+)", output, re.MULTILINE)
            type_match = re.search(r"^\s*Type\s*:\s*(.+)", output, re.MULTILINE)

            if name_match and type_match:
                system_info['System Name'] = name_match.group(1).strip()
                system_info['System Type'] = type_match.group(1).strip()
            else:
                logging.warning("No system information found in the output.")

            # Regex pattern to capture hierarchical part data
            hardware_pattern = re.compile(
                r"^\s+Part number\s*:\s*(?P<PartNumber>[^\r\n]+)\s*"
                r"(?:CLEI code\s*:\s*[^\r\n]+\s*)?"  # CLEI code (optional)
                r"Serial number\s*:\s*(?P<SerialNumber>[^\r\n]+)",
                re.MULTILINE
            )

            # Find all matches
            all_matches = list(re.finditer(hardware_pattern, output))

            for match in all_matches:
                try:
                    part_number = match.group("PartNumber").strip()[:10] if match.group("PartNumber") else "Unknown"
                    serial_number = match.group("SerialNumber").strip() if match.group("SerialNumber") else "Unknown"

                    # Identify type dynamically
                    if part_number == "3HE11278AA":
                        part_type = "Chassis"
                        name = "Chassis"
                    elif part_number == "3HE11279AA":
                        part_type = "Chassis Fan"
                        name = "Chassis Fan"
                    else:
                        part_type = "Unknown"
                        name = "Unknown"

                    # Get description from the database
                    description = self.get_part_description(part_number)

                    # Append structured data
                    data.append({
                        'System Name': system_info.get('System Name'),
                        'System Type': system_info.get('System Type'),
                        'Type': part_type,
                        'Part Number': part_number,
                        'Serial Number': serial_number,
                        'Description': description,
                        'Name': name,
                        'Source': ip
                    })

                except Exception as match_error:
                    logging.error(f"Error processing hardware match: {match_error}")
                    continue

            if not data:
                logging.warning("No hardware data found in output.")
            else:
                logging.debug(f"Extracted hardware data: {data}")

        except Exception as e:
            logging.error(f"Error in extract_hardware_data: {e}")
            data = [{
                'System Name': "Error",
                'System Type': "Error",
                'Type': "Error",
                'Part Number': "Error",
                'Serial Number': "Error",
                'Description': "Error",
                'Name': "Error",
                'Source': ip
            }]

        # Convert to DataFrame
        df = pd.DataFrame(data)
        if df.empty:
            logging.warning("No data to cache. DataFrame is empty.")
        else:
            logging.info(f"DataFrame populated successfully:\n{df}")

        # Cache the DataFrame using the callback
        cache_callback(df, 'hardware_data')


    def extract_card_details(self, device_output, slot_names, card_label, cache_callback, ip):
        """
        Extracts card details (Type, Part Number, Serial Number) for both Card A and Card B using a flexible regex.
        """
        card_data = []

        try:
            # More flexible regex to match both Card A and B with irregular output structure
            card_detail_pattern = re.compile(
                r"^[ ]*(?P<Slot>[A-Z])\s+(?P<Type>[^\s]+).*?"          # Match Slot A/B and Type
                r"Part number\s*:\s*(?P<PartNumber>[^\n]+).*?"         # Match Part Number
                r"Serial number\s*:\s*(?P<SerialNumber>[^\n]+)",       # Match the correct Serial Number
                re.MULTILINE | re.DOTALL
            )

            matches = re.finditer(card_detail_pattern, device_output)

            for match in matches:
                slot = match.group("Slot").strip()
                if slot not in slot_names:
                    continue  # Skip if the slot does not match A or B

                try:
                    part_type = match.group("Type").strip() if match.group("Type") else "Unknown"
                    part_number = match.group("PartNumber").strip()[:10] if match.group("PartNumber") else "Unknown"
                    serial_number = match.group("SerialNumber").strip() if match.group("SerialNumber") else "Unknown"
                    description = self.get_part_description(part_number)
                except Exception as e:
                    logging.error(f"Error retrieving part description for Part Number: {part_number}")
                    description = "Unknown Description"

                # Create structured data entry for the card
                card_info = {
                    'System Name': '',
                    'System Type': '',
                    'Type': part_type,
                    'Part Number': part_number,
                    'Serial Number': serial_number,
                    'Description': description,
                    'Information Type': 'Control Card',
                    'Name': f"Slot {slot}",
                    'Source': ip
                }
                card_data.append(card_info)
                logging.debug(f"Extracted info for {slot}: {card_info}")

            if not card_data:
                logging.warning(f"No {card_label} data found in output.")
            else:
                logging.debug(f"Data successfully extracted for {card_label}: {card_data}")

        except Exception as e:
            logging.error(f"Error in extract_{card_label.lower()}_details: {e}")
            card_data.append({
                'System Name': '',
                'System Type': '',
                'Type': "Error",
                'Part Number': "Error",
                'Serial Number': "Error",
                'Description': "Error",
                'Information Type': '',
                'Name': f"{card_label} Error",
                'Source': ip,
            })

        # Create DataFrame for extracted card data
        expected_columns = ['System Name', 'System Type', 'Type', 'Part Number', 'Serial Number',
                            'Description', 'Information Type', 'Name', 'Source']
        df = pd.DataFrame(card_data, columns=expected_columns)

        if df.empty:
            logging.warning(f"No {card_label} data found or parsing failed. Returning empty DataFrame.")
        else:
            logging.info(f"DataFrame for {card_label} is populated:\n{df}")

        logging.debug(df)

        # Cache the DataFrame using the provided callback
        cache_callback(df, f"{card_label}_data")
        return df


    def extract_mda_details(self, output, cache_callback=None, ip=None):
        """
        Extracts MDA details using regex to capture relevant fields.
        """
        mda_data = []

        try:
            output = output.replace("Press any key to continue (Q to quit)", "").strip()

            # Combined regex to capture MDA, Type, Part Number, and Serial Number
            mda_block_pattern = re.compile(
                r"^\s*\d*\s+(?P<MDA>\d+)\s+(?P<Type>[\w\(\)\-]+).*?"
                r"Part number\s*:\s*(?P<PartNumber>[^\r\n]+).*?"
                r"Serial number\s*:\s*(?P<SerialNumber>[^\r\n]+)",
                re.DOTALL | re.MULTILINE
            )

            logging.debug(f"Raw MDA output:\n{output}")

            match_found = False  # Flag to check if at least one match was found

            for match in mda_block_pattern.finditer(output):
                match_found = True
                part_number = match.group("PartNumber").strip()[:10] if match.group("PartNumber") else "Unknown"
                serial_number = match.group("SerialNumber").strip() if match.group("SerialNumber") else "Unknown"
                mda_type = match.group("Type").strip() if match.group("Type") else "Unknown"

                # Get part description
                description = self.get_part_description(part_number)

                entry = {
                    'System Name': '',
                    'System Type': '',
                    'Type': mda_type,
                    'Part Number': part_number,
                    'Serial Number': serial_number,
                    'Description': description,  # ✅ Fixed function call
                    'Information Type': "MDA Card",
                    'Name': match.group("MDA"),
                    'Source': ip or 'Unknown'
                }

                logging.debug(f"Extracted MDA entry: {entry}")
                mda_data.append(entry)

            # If no matches were found, log an error
            if not match_found:
                logging.error("No MDA details found in the provided output.")
                return None  # Prevent further processing if no matches were found

        except Exception as e:
            logging.error(f"Error extracting MDA details: {e}")
            mda_data.append({
                'System Name': 'Error',
                'System Type': 'Error',
                'Type': 'Error',
                'Part Number': 'Error',
                'Serial Number': 'Error',
                'Description': 'Error',
                'Information Type': 'Error',
                'Name': 'Error',
                'Source': 'Error'
            })

        # Convert to DataFrame
        df = pd.DataFrame(mda_data)
        if df.empty:
            logging.warning("No MDA data found or parsing failed. Returning empty DataFrame.")
        else:
            logging.info(f"DataFrame for MDA is populated:\n{df}")

        logging.debug("\n" + df.to_string())

        if cache_callback:
            cache_callback(df, 'mda_data')

        return df


    def extract_port_detail(self, output: str, cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None, ip: Optional[str] = None) -> pd.DataFrame:
        port_data = []

        try:
            logging.debug(f"Raw output:\n{output}")
            output = output.replace("Press any key to continue (Q to quit)", "").strip()

            # ✅ Validate output before processing
            if not self.is_valid_output(output, "port detail"):
                logging.warning("Invalid output detected for port detail command.")
                raise ValueError("Invalid port detail output")

            lines = output.split("\n")

            # ✅ Define regex patterns
            interface_pattern = re.compile(r'Interface\s+:\s+([\d\S]+)', re.MULTILINE)
            serial_pattern = re.compile(r'Serial Number\s+:\s*(.+)', re.MULTILINE)
            model_pattern = re.compile(r'Model Number\s+:\s*([^\s]+)', re.MULTILINE)
            part_pattern = re.compile(r'Part Number\s+:\s*([^\s]+)', re.MULTILINE)
            optical_compliance_pattern = re.compile(r'Optical Compliance\s+:\s*(.+)', re.MULTILINE)

            # ✅ Initialize current port entry
            current_interface = None
            current_serial_number = None
            current_model_number = None
            current_part_number = None
            current_optical_compliance = None

            # ✅ Iterate through each line to extract port details
            for i, line in enumerate(lines):
                logging.debug(f"Processing line: {line.strip()}")

                if "Optical Compliance" in line:
                    # 🔹 **Look back for related data** (Previous 5 lines max)
                    for j in range(max(0, i - 5), i):
                        if not current_interface:
                            interface_match = interface_pattern.search(lines[j])
                            if interface_match:
                                current_interface = interface_match.group(1).strip()

                        if not current_serial_number:
                            serial_match = serial_pattern.search(lines[j])
                            if serial_match:
                                current_serial_number = serial_match.group(1).strip()

                        if not current_part_number:
                            part_match = part_pattern.search(lines[j])
                            if part_match:
                                current_part_number = part_match.group(1).strip()

                        if not current_model_number:
                            model_match = model_pattern.search(lines[j])
                            if model_match:
                                current_model_number = model_match.group(1).strip()[:10]

                    # ✅ **Ensure missing values are assigned properly**
                    if not current_interface:
                        logging.warning(f"Missing Interface in entry. Assigning placeholder.")
                        current_interface = f"Unknown Interface"

                    if not current_serial_number:
                        logging.warning(f"Missing Serial Number in entry. Assigning placeholder.")
                        current_serial_number = f"Unknown Serial"

                    if not current_model_number or current_model_number.lower() == "none":
                        logging.warning(f"Model Number missing, using Part Number instead: {current_part_number}")
                        current_model_number = current_part_number if current_part_number else "Unknown"

                    # ✅ **Extract Optical Compliance**
                    optical_compliance_match = optical_compliance_pattern.search(line)
                    current_optical_compliance = (
                        optical_compliance_match.group(1).strip() if optical_compliance_match else "N/A"
                    )

                    # ✅ **Special case for known model numbers**
                    if current_model_number == "3HE12546AA":
                        current_optical_compliance = "SFP - C37.94"

                    # ✅ **Final Validation: Entry must have valid values**
                    if (
                        current_interface != "Unknown Interface"
                        and current_serial_number != "Unknown Serial"
                        and current_model_number != "Unknown"
                        and current_optical_compliance != "N/A"
                    ):
                        try:
                            # ✅ **Retrieve part description**
                            description = self.get_part_description(current_model_number)
                        except Exception as desc_error:
                            logging.error(f"Error retrieving part description: {desc_error}")
                            description = "Unknown"

                        # ✅ **Create port info dictionary**
                        port_info = {
                            "System Name": '',
                            "System Type": '',
                            "Type": current_optical_compliance,
                            "Part Number": current_model_number,
                            "Serial Number": current_serial_number,
                            "Description": description,
                            "Information Type": "Plugable Optical Transceiver",
                            "Name": current_interface,
                            "Source": ip or "Unknown"
                        }
                        port_data.append(port_info)
                        logging.debug(f"Extracted port data: {port_info}")
                    else:
                        logging.warning(
                            f"Skipping entry due to missing data:\n"
                            f"Interface: {current_interface}, Serial: {current_serial_number}, "
                            f"Model: {current_model_number}, Optical Compliance: {current_optical_compliance}"
                        )

                    # ✅ **Reset values for next entry**
                    current_interface = None
                    current_serial_number = None
                    current_model_number = None
                    current_part_number = None
                    current_optical_compliance = None

            # ✅ **Final validation**
            if not port_data:
                logging.warning("No port data found in output.")
            else:
                logging.debug(f"Data successfully extracted: {port_data}")

        except Exception as e:
            logging.error(f"Error in extract_port_detail: {e}")
            port_data.append({
                "System Name": '',
                "System Type": '',
                "Type": "Error",
                "Part Number": "Error",
                "Serial Number": "Error",
                "Description": "Error",
                "Information Type": "Error",
                "Name": "Error",
                "Source": ip or "Unknown"
            })

        # ✅ **Create DataFrame and remove empty rows**
        df = pd.DataFrame(port_data).dropna(how='all')
        if df.empty:
            logging.warning("No port data found or parsing failed. Returning empty DataFrame.")
        else:
            logging.info(f"DataFrame for port details is populated:\n{df}")

        logging.debug("\n" + df.to_string())

        if cache_callback:
            cache_callback(df, 'port_data')

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
        
        # Set device_name and device_type properly
        self.device_name = self.device_name or "Unknown"
        self.device_type = self.device_type or "Unknown"

        system_info = {'System Name': self.device_name, 'System Type': self.device_type}

        processing_functions = [
            lambda output, callback: self.extract_hardware_data(output, callback, ip_address),
            lambda output, callback: self.extract_card_details(output, ['A'], 'Card A', callback, ip_address),
            lambda output, callback: self.extract_card_details(output, ['B'], 'Card B', callback, ip_address),
            lambda output, callback: self.extract_mda_details(output, callback, ip_address),
            lambda output, callback: self.extract_port_detail(output, callback, ip_address),
        ]

        # Ensure outputs_from_device aligns with processing functions
        min_outputs = min(len(outputs_from_device), len(processing_functions))

        if len(outputs_from_device) != len(processing_functions):
            logging.warning(
                f"Mismatch between outputs and processing functions for device {ip_address}. "
                f"Processing only {min_outputs} outputs."
            )

        system_info = {'System Name': self.device_name or 'Unknown', 'System Type': self.device_type or 'Unknown'}

        for idx, (command_output, processing_function) in enumerate(zip(outputs_from_device[:min_outputs], processing_functions[:min_outputs])):
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
                continue  # Ensures other functions still execute

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

            # Validation for known commands
            if command.startswith("show chassis"):
                # Look for expected fields in chassis details
                required_keywords = ["Name", "Type", "Part", "Serial"]
                if all(keyword in output for keyword in required_keywords):
                    logging.debug(f"Output for 'show chassis' validated successfully.")
                    return True
                else:
                    logging.warning(f"Output for 'show chassis' missing expected keywords: {required_keywords}")
                    return False

            elif command.startswith("show card"):
                # Validate card information, expect slots and serial numbers
                if re.search(r"Slot\s*:\s*\w+", output) and "Serial number" in output:
                    logging.debug(f"Output for 'show card' validated successfully.")
                    return True
                else:
                    logging.warning(f"Output for 'show card' missing required patterns or keywords.")
                    return False

            elif command.startswith("show mda"):
                # Validate MDA details, expect slots and part numbers
                if re.search(r"Slot\s*:\s*\w+", output) and "Part number" in output:
                    logging.debug(f"Output for 'show mda' validated successfully.")
                    return True
                else:
                    logging.warning(f"Output for 'show mda' missing required patterns or keywords.")
                    return False

            elif command.startswith("show port"):
                # Validate port details, expect interfaces and compliance details
                required_keywords = ["Interface", "Optical Compliance", "Serial"]
                if all(keyword in output for keyword in required_keywords):
                    logging.debug(f"Output for 'show port' validated successfully.")
                    return True
                else:
                    logging.warning(f"Output for 'show port' missing expected keywords: {required_keywords}")
                    return False

            # General validation for unknown commands
            if len(output.strip()) > 10:  # Arbitrary threshold for meaningful data
                logging.debug(f"Output for unknown command '{command}' contains sufficient data.")
                return True
            else:
                logging.warning(f"Output for unknown command '{command}' is too short or meaningless.")
                return False

        except Exception as e:
            logging.error(f"Error validating output for command '{command}': {e}")
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
            