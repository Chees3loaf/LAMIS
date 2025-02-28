import os
import sqlite3
import logging
import re
import time
import pandas as pd
import paramiko
import subprocess
from openpyxl import load_workbook
from typing import Callable, Dict, List, Optional, Tuple

import serial
from scripts.script_interface import BaseScript

# Ensure logging is configured
logging.basicConfig(level=logging.DEBUG)

class Script(BaseScript):
    def __init__(self, db_name='network_inventory.db', connection_type='serial', **kwargs):
        self.db_name = db_name
        self.connection_type = connection_type
        if connection_type == 'serial':
            self.serial_port = kwargs.get('serial_port')
            self.baud_rate = kwargs.get('baud_rate')
            self.timeout = kwargs.get('timeout', 5)  # Increase timeout to 5 seconds
        elif connection_type == 'ssh':
            self.ip_address = kwargs.get('ip_address')
            self.username = kwargs.get('username')
            self.password = kwargs.get('password')

    def get_commands(self) -> List[str]:
        # Add the commands specific to your device here
        return [
            
            
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
            ssh_client.connect(ip_address, username=username, password=password)
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

    def get_part_description(self, part_number: str, part_type: str) -> str:
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute('''
        SELECT description FROM parts WHERE part_number = ? AND type = ?
        ''', (part_number))

        result = cursor.fetchone()
        conn.close()

        if result:
            return result[0]
        else:
            return "Unknown"
        
    def chassis():
        data=[]
        system_inro = {'System Name': "Unknown", 'System Type': "Unknown"}
        
        try:
            chassis_pattern = re.compile(
                r"Part Number\S*\W*([0-9]+)"
                r"Serial Number\s*\W.([A-Z0-9]+)",  
                re.DOTALL
            )        
                
            psu_pattern = re.compile(
                r"Part Number\S*\W*([0-9]+\S+)"
                r"Serial Number\s*\W.([A-Z0-9]+)",
                re.DOTALL
            )
        
                
        except Exception as e:
            logging.error(f"Error in extract_hardware_data: {e}")
            data.append({
                'System Name': "Error",
                'System Type': "Error",
                'Type': '',
                'Part Number': "Error",
                'Serial Number': "Error",
                'Description': "Error",
                'Information Type': 'Error',
                'Name': '',
                'Source': ip
                
            })
    
    
    #def xcvr():
        
        
        

    def is_valid_output(self, output: str, command: str) -> bool:
        if not output.strip():
            return False
        
        error_indicators = ["error", "failed", "unreachable", "not found"]
        if any(indicator in output.lower() for indicator in error_indicators):
            return False
        
        # Add device-specific command validation here in the following format
        # "chassis": ["Name", "Type", "Part", "Serial"],
        required_keywords = {
        
        }
        
        for key, keywords in required_keywords.items():
            if key in command and not all(keyword in output for keyword in keywords):
                return False
        
        return True

    def process_outputs(self, outputs_from_device: List[str], ip_address: str, outputs: Dict[str, Dict[str, Dict]]) -> None:
        # Add device-specific processing functions here in the following format
        # lambda output, callback: self.extract_example_data(output, callback, ip_address),
        processing_functions = [
            
        ]

        system_info = {'System Name': 'Example System', 'System Type': 'Type A'}

        for command_output, processing_function in zip(outputs_from_device, processing_functions):
            processing_function(command_output, lambda df, key: self.cache_data_frame(outputs, ip_address, key, df, system_info))

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

    def output_to_excel(self, outputs: Dict[str, Dict[str, Dict]], template_file: str, output_file: str) -> None:
        try:
            # Load the template workbook
            template_path = os.path.join(os.path.dirname(__file__), '..', 'Data', 'Device_Report_Template.xlsx')
            wb = load_workbook(template_path)
            sheet = wb.active  # Assuming data goes to the first sheet; adjust if necessary

            for ip, data_dict in outputs.items():
                combined_df = self.combine_and_format_data(data_dict)
                if not combined_df.empty:
                    # Extract system name for the sheet title
                    system_name = combined_df.iloc[0]['System Name'].replace(':', '_').replace('/', '_')

                    # Create a new sheet for each device using the template sheet as a base
                    new_sheet = wb.copy_worksheet(sheet)
                    new_sheet.title = system_name
                    
                    # Example of writing data to specific cells in the template
                    for idx, row in combined_df.iterrows():
                        # Adjust these cell mappings based on your actual template layout
                        new_sheet[f'C{idx + 7}'] = row['System Name']
                        new_sheet[f'F{idx + 7}'] = row['System Type']
                        new_sheet[f'B{idx + 15}'] = row['Name']
                        new_sheet[f'D{idx + 15}'] = row['Part Number']
                        new_sheet[f'E{idx + 15}'] = row['Serial Number']
                        new_sheet[f'F{idx + 5}'] = row['Source']
                        new_sheet[f'C{idx + 15}'] = row['Type']
                        new_sheet[f'F{idx + 15}'] = row['Description']
                        
            # Remove the original template sheet if desired
            wb.remove(sheet)
                    
            # Save the workbook with the new data
            wb.save(output_file)
            logging.info(f"Data successfully saved to {output_file}")

            subprocess.run(["start", output_file], check=True, shell=True)
        except Exception as e:
            logging.error(f"Failed to save data to Excel: {e}")

    def combine_and_format_data(self, ip_data: Dict[str, Dict]) -> pd.DataFrame:
        all_data = []
        for key, data in ip_data.items():
            df = data['DataFrame']
            all_data.append(df)
        
        if all_data:
            combined_df = pd.concat(all_data, ignore_index=True)
            logging.info(f"Combined DataFrame created with {len(combined_df)} rows.")
        else:
            combined_df = pd.DataFrame()
            logging.warning("No data to combine.")
        
        return combined_df
    
    # Example placeholder for a device-specific data extraction function
    def extract_example_data(self, output: str, cache_callback: Callable[[pd.DataFrame, str], None], ip: str) -> None:
        # Replace with actual data extraction logic
        data = []
        # Process the output and append to data
        df = pd.DataFrame(data)
        cache_callback(df, 'example_data')
