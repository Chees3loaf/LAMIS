import os
import subprocess
import logging
import sqlite3
import time
from typing import Dict
import paramiko
import re
import telnetlib
from paramiko.ssh_exception import AuthenticationException

# Configure logging with a debug flag
debug_mode = False  # Toggle this for verbose logging
logging.basicConfig(level=logging.DEBUG if debug_mode else logging.INFO)

def is_reachable(ip):
    # Ping an IP address to check if it is reachable
    try:
        result = subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        logging.error(f"Ping check failed for {ip}: {e}")
        return False

class BaseScript:
    def execute_commands(self, commands):
        
        # Executes a list of commands and returns their output.
        
        raise NotImplementedError("Subclasses must implement this method")

    def process_outputs(self, outputs_from_device, ip_address, outputs):
        
        # Processes outputs from a device and caches parsed data.
        
        raise NotImplementedError("Subclasses must implement this method")


class CommandTracker:
    def __init__(self):
        self.executed_commands = {}

    def has_executed(self, ip, command, connection_type):
        key = (ip, connection_type)
        return command in self.executed_commands.get(key, set())

    def mark_as_executed(self, ip, command, connection_type):
        key = (ip, connection_type)
        if key not in self.executed_commands:
            self.executed_commands[key] = set()
        self.executed_commands[key].add(command)
        logging.debug(f"Command '{command}' marked as executed for IP: {ip}, Connection Type: {connection_type}")

    def reset(self):
        self.executed_commands.clear()
        logging.debug("CommandTracker has been reset.")


class DatabaseCache:
    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(db_path)
        self.cache: Dict[str, str] = {}

    def lookup_part(self, part_number: str) -> str:
        key = part_number[:10]
        if key in self.cache:
            return self.cache[key]

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT description FROM parts WHERE part_number LIKE ?", (key + "%",))
                result = cursor.fetchone()
                if result:
                    self.cache[key] = result[0]
                    return result[0]
                else:
                    self.cache[key] = "Not Found"
                    return "Not Found"
        except Exception as e:
            logging.error(f"Database error for part_number '{key}': {e}")
            self.cache[key] = f"Database Error: {e}"
            return f"Database Error: {e}"



class DeviceIdentifier:
    def identify_device(self, ip, queue, output_screen):
        username, password = 'admin', 'admin'
        logging.debug(f"Attempting to identify device at {ip} with SSH.")
        queue.put(f"Attempting to identify device at {ip} with SSH...\n")

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=10)

            queue.put(f"Connected to {ip} via SSH\n")
            session = ssh_client.invoke_shell()

            for command in ["show chassis | match (Type) pre-lines 1 expression"]:
                queue.put(f"Executing command: {command}\n")
                session.send(command + '\n')
                time.sleep(2)

                output = ""
                while session.recv_ready():
                    output += session.recv(1024).decode('utf-8')

                if output:
                    queue.put(f"SSH response from {ip}:\n{output}\n")
                    device_type, device_name = self.parse_device_info(output, queue)
                    if device_type:
                        ssh_client.close()
                        return device_type, device_name

            ssh_client.close()

        except AuthenticationException as ae:
            logging.warning(f"SSH auth failed for {ip}: {ae}")
            queue.put(f"SSH authentication failed for {ip}. Trying Telnet...\n")
        except Exception as e:
            logging.warning(f"SSH failed for {ip}: {e}")
            queue.put(f"SSH connection failed for {ip}: {e}. Trying Telnet...\n")

        # Fallback to Telnet
        return self.identify_device_telnet(ip, queue)

    def identify_device_telnet(self, ip, queue):
        username, password = 'admin', 'admin'
        try:
            queue.put(f"Attempting Telnet connection to {ip}...\n")
            tn = telnetlib.Telnet(ip, timeout=10)

            tn.read_until(b"login: ", timeout=5)
            tn.write(b"cli\n")
            tn.read_until(b"Username: ", timeout=5)
            tn.write(username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(password.encode('ascii') + b"\n")
            time.sleep(1)
            login_output = tn.read_very_eager().decode('ascii')

            if "Login incorrect" in login_output or "invalid" in login_output.lower():
                queue.put("Telnet login failed: Invalid credentials.\n")
                return None, None
            
            tn.write(b"show general system-identification\n")
            time.sleep(3)
            output1 = tn.read_until(b"#", timeout=5).decode('ascii')
            tn.write(b"show general name\n")
            time.sleep(3)
            output2 = tn.read_until(b"#", timeout=5).decode('ascii')
            output = output1 + "\n" + output2
            tn.write(b"exit\n")
            tn.close()

            queue.put(f"Telnet response from {ip}:\n{output}\n")
            return self.parse_device_info(output, queue)

        except Exception as e:
            queue.put(f"Telnet failed for {ip}: {e}\n")
            logging.error(f"Telnet failed for {ip}: {e}")
            return None, None

    @staticmethod
    def parse_device_info(output, queue):
        queue.put(f"Parsing device output:\n{output}\n")
        logging.debug(f"Raw device output before parsing: {output}")
        try:
            type_match = re.search(r"Type\s+:\s+(.+)", output)
            name_match = re.search(r"Name\s+:\s+(.+)", output)
            product_match = re.search(r"Product\s+:\s+(\d+)", output)
            product_name_match = re.search(r"Name:\s+(.+)", output)

            device_type = type_match.group(1).strip() if type_match else (product_match.group(1).strip() if product_match else None)
            device_name = name_match.group(1).strip() if name_match else (product_name_match.group(1).strip() if product_name_match else None)

            queue.put(f"Parsed Device Info:\n - Type: {device_type}\n - Name: {device_name}\n")

            return device_type, device_name
        except Exception as e:
            queue.put(f"Error parsing device info: {e}\n")
            logging.error(f"Error parsing device info: {e}")
            return None, None


class ScriptSelector:
    def select_script(self, device_type, ip_address, connection_type='ssh'):
        
        # Select a script class based on device type and connection type.
        
        from scripts.Nokia_SAR import Script as Sar
        from scripts.Nokia_IXR import Script as Ixr
        from Nokia_1830 import Script as Pss
        
        DEVICE_SCRIPT_MAPPING = {
            '7705 sar-8 v2': Sar,
            '7250 ixr-r6': Ixr,
            '7250 ixr-r6d': Ixr,
            '1830': Pss,
        }
        
        normalized_device_type = device_type.strip().lower() if device_type else 'unknown'
        script_class = DEVICE_SCRIPT_MAPPING.get(normalized_device_type)
        
        if script_class:
            logging.debug(f"Script class for device type '{device_type}': {script_class.__name__}")
            return script_class
        else:
            logging.error(f"No script found for device type: '{device_type}'")
            return None
