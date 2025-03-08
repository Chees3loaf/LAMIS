import subprocess
import logging
import sqlite3
import time
import paramiko
import re

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
    def __init__(self, db_path):
        self.db_path = db_path
        self.cache = {}

    def get_part_description(self, part_number):
        if part_number in self.cache:
            logging.debug(f"Cache hit for part number: {part_number}")
            return self.cache[part_number]

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT description FROM parts WHERE part_number = ?", (part_number,))
            result = cursor.fetchone()
            description = result[0] if result else "Unknown"
            self.cache[part_number] = description
            logging.debug(f"Fetched and cached description for part number: {part_number}")
            return description
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return f"Database Error: {e}"
        finally:
            conn.close()


class DeviceIdentifier:    
    def identify_device(self, ip, queue, output_screen):
        
        # Identifies the device type and name based on command output.
        
        username, password = 'admin', 'admin'
        logging.debug(f"Attempting to identify device at {ip} with SSH.")
        queue.put(f"Attempting to identify device at {ip} with SSH...\n")

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=10)
            
            queue.put(f"Connected to {ip} via SSH\n")
            logging.info(f"Connected to {ip}")

            session = ssh_client.invoke_shell()
            command = "show chassis | match (Type) pre-lines 1 expression"
            logging.debug(f"Executing SSH command on {ip}: {command}")
            queue.put(f"Executing command: {command}\n")
            
            session.send(command + '\n')
            time.sleep(2)  # Allow time for response
            
            output = ""
            while session.recv_ready():
                output += session.recv(1024).decode('utf-8')

            ssh_client.close()

            # Debugging Output
            logging.debug(f"Raw SSH output from {ip}: {output}")
            queue.put(f"Received response from {ip}:\n{output}\n")

            if output:
                return self.parse_device_info(output, queue)

        except Exception as e:
            logging.warning(f"SSH connection failed for {ip}: {e}")
            queue.put(f"SSH connection failed for {ip}: {e}\n")

        return None, None


    @staticmethod
    def parse_device_info(output, queue):
        logging.debug(f"Raw device output before parsing: {output}")  # Log full raw output
        queue.put(f"Parsing device output:\n{output}\n")

        try:
            type_match = re.search(r"Type\s+:\s+(.+)", output)
            name_match = re.search(r"Name\s+:\s+(.+)", output)

            device_type = type_match.group(1).strip() if type_match else None
            device_name = name_match.group(1).strip() if name_match else None

            logging.debug(f"Parsed device info - Type: {device_type}, Name: {device_name}")
            queue.put(f"Parsed Device Info:\n - Type: {device_type}\n - Name: {device_name}\n")

            if not device_type:
                logging.warning(f"Device type not found in output: {output}")
                queue.put("Warning: Device type not found in output.\n")

            return device_type, device_name

        except Exception as e:
            logging.error(f"Error parsing device info: {e}")
            queue.put(f"Error parsing device info: {e}\n")
            return None, None


class ScriptSelector:
    def select_script(self, device_type, connection_type='ssh'):
        
        # Select a script class based on device type and connection type.
        
        from scripts.Nokia_SAR import Script as Sar
        from scripts.Nokia_IXR import Script as Ixr
        from scripts.Nokia_1830 import Script as Pss
        
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
