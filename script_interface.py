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
debug_mode = True  # Toggle this for verbose logging
logging.basicConfig(level=logging.DEBUG if debug_mode else logging.INFO)

DEFAULT_PASSWORD = "admin"
DEFAULT_USERNAME = "admin"

# At the bottom or top-level
def get_inventory_db_path() -> str:
    try:
        # Always go up to the project root from the current file
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base_dir, "data", "network_inventory.db")
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Database file missing at: {path}")
        logging.debug(f"[DB PATH] Resolved database path: {path}")
        return path
    except Exception as e:
        logging.error(f"[DB PATH] Failed to resolve DB path: {e}")
        raise

def is_reachable(ip):
    try:
        logging.debug(f"[PING] Checking reachability for {ip}")
        result = subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True)
        reachable = result.returncode == 0
        logging.info(f"[PING] {ip} is {'reachable' if reachable else 'not reachable'}")
        return reachable
    except Exception as e:
        logging.error(f"[PING] Ping check failed for {ip}: {e}")
        return False

class BaseScript:
    def execute_commands(self, commands):
        raise NotImplementedError("Subclasses must implement this method")

    def process_outputs(self, outputs_from_device, ip_address, outputs):
        raise NotImplementedError("Subclasses must implement this method")

class CommandTracker:
    def __init__(self):
        self.executed_commands = {}
        logging.debug("[TRACKER] Initialized command tracker")

    def has_executed(self, ip, command, connection_type):
        key = (ip, connection_type)
        result = command in self.executed_commands.get(key, set())
        logging.debug(f"[TRACKER] Check if executed '{command}' on {ip}/{connection_type}: {result}")
        return result

    def mark_as_executed(self, ip, command, connection_type):
        key = (ip, connection_type)
        if key not in self.executed_commands:
            self.executed_commands[key] = set()
        self.executed_commands[key].add(command)
        logging.debug(f"[TRACKER] Marked '{command}' as executed on {ip}/{connection_type}")

    def reset(self):
        self.executed_commands.clear()
        logging.debug("[TRACKER] Reset executed commands")

class DatabaseCache:
    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(db_path)
        self.cache: Dict[str, str] = {}
        logging.debug(f"[CACHE] Initialized cache with DB path: {self.db_path}")

    def lookup_part(self, part_number: str) -> str:
        key = part_number[:10]
        if key in self.cache:
            logging.debug(f"[CACHE] Cache hit for part: {key}")
            return self.cache[key]

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                logging.debug(f"[CACHE] Looking up part in DB: {key}")
                cursor.execute("SELECT description FROM parts WHERE part_number LIKE ?", (key + "%",))
                result = cursor.fetchone()
                if result:
                    self.cache[key] = result[0]
                    return result[0]
                else:
                    self.cache[key] = "Not Found"
                    return "Not Found"
        except Exception as e:
            logging.error(f"[CACHE] DB error on '{key}': {e}")
            self.cache[key] = f"DB Error: {e}"
            return f"DB Error: {e}"

class DeviceIdentifier:
    def identify_device(self, ip, queue, output_screen):
        username, password = 'admin', 'admin'
        logging.info(f"[IDENTIFY] Trying to identify {ip} via SSH")

        try:
            transport = paramiko.Transport((ip, 22))
            transport.start_client(timeout=5)

            banner_holder = {}
            def handler(title, instructions, prompt_list):
                banner_holder['banner'] = transport.get_banner()
                return [''] * len(prompt_list)

            try:
                transport.auth_interactive('dummyuser', handler)
            except AuthenticationException:
                pass

            banner = banner_holder.get('banner')
            decoded = banner.decode('utf-8', errors='ignore') if banner else ''
            logging.debug(f"[IDENTIFY] Banner from {ip}:\n{decoded}")
            queue.put(f"[DEBUG] SSH Auth Banner from {ip}:\n{decoded}\n")

            if any(kw in decoded.lower() for kw in ["6500", "ciena 6500 optical"]):
                logging.info(f"[IDENTIFY] Ciena 6500 banner matched on {ip}")
                queue.put(f"[IDENTIFY] Device identified from banner: Ciena 6500 OPTICAL at {ip}\n")
                transport.close()
                return self.parse_device_info("Type : 6500\nName : Ciena 6500 OPTICAL", queue)

            transport.close()
        except Exception as e:
            logging.warning(f"[IDENTIFY] SSH banner scan failed for {ip}: {e}")
            queue.put(f"[WARNING] SSH banner scan failed for {ip}: {e}. Proceeding with login...\n")

        # SSH fallback
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=10)

            logging.info(f"[IDENTIFY] Connected to {ip} via SSH")
            queue.put(f"Connected to {ip} via SSH\n")
            session = ssh_client.invoke_shell()

            for command in ["show chassis | match (Type) pre-lines 1 expression"]:
                queue.put(f"Executing command: {command}\n")
                session.send(command + '\n')
                time.sleep(2)

                output = ""
                while session.recv_ready():
                    output += session.recv(1024).decode('utf-8')

                logging.debug(f"[IDENTIFY] SSH output from {ip}:\n{output}")
                queue.put(f"SSH response from {ip}:\n{output}\n")
                device_type, device_name = self.parse_device_info(output, queue)
                if device_type:
                    ssh_client.close()
                    return device_type, device_name

            ssh_client.close()

        except AuthenticationException as ae:
            logging.warning(f"[IDENTIFY] SSH auth failed for {ip}: {ae}")
            queue.put(f"SSH authentication failed for {ip}. Trying Telnet...\n")
        except Exception as e:
            logging.warning(f"[IDENTIFY] SSH error for {ip}: {e}")
            queue.put(f"SSH connection failed for {ip}: {e}. Trying Telnet...\n")

        return self.identify_device_telnet(ip, queue)

    def identify_device_telnet(self, ip, queue):
        username, password = 'admin', 'admin'
        logging.info(f"[IDENTIFY] Attempting Telnet to {ip}")
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
            logging.debug(f"[TELNET] Login output from {ip}:\n{login_output}")

            if "Login incorrect" in login_output or "invalid" in login_output.lower():
                queue.put("Telnet login failed: Invalid credentials.\n")
                return None, None

            tn.write(b"show general system-identification\n")
            time.sleep(3)
            output1 = tn.read_until(b"#", timeout=5).decode('ascii')
            tn.write(b"show general name\n")
            time.sleep(3)
            output2 = tn.read_until(b"#", timeout=5).decode('ascii')
            tn.write(b"exit\n")
            tn.close()

            full_output = output1 + "\n" + output2
            logging.debug(f"[TELNET] Response from {ip}:\n{full_output}")
            queue.put(f"Telnet response from {ip}:\n{full_output}\n")
            return self.parse_device_info(full_output, queue)

        except Exception as e:
            logging.error(f"[TELNET] Failed for {ip}: {e}")
            queue.put(f"Telnet failed for {ip}: {e}\n")
            return None, None

    @staticmethod
    def parse_device_info(output, queue):
        logging.debug(f"[PARSE] Raw output:\n{output}")
        queue.put(f"Parsing device output:\n{output}\n")
        try:
            type_match = re.search(r"Type\s+:\s+(.+)", output)
            name_match = re.search(r"Name\s+:\s+(.+)", output)
            product_match = re.search(r"Product\s+:\s+(\d+)", output)
            product_name_match = re.search(r"Name:\s+(.+)", output)

            device_type = type_match.group(1).strip() if type_match else (product_match.group(1).strip() if product_match else None)
            device_name = name_match.group(1).strip() if name_match else (product_name_match.group(1).strip() if product_name_match else None)

            queue.put(f"Parsed Device Info:\n - Type: {device_type}\n - Name: {device_name}\n")
            logging.info(f"[PARSE] Parsed Type: {device_type}, Name: {device_name}")
            return device_type, device_name

        except Exception as e:
            logging.error(f"[PARSE] Error parsing device info: {e}")
            queue.put(f"Error parsing device info: {e}\n")
            return None, None


class ScriptSelector:   
    def select_script(self, device_type, ip_address, connection_type='ssh'):
        logging.debug(f"[SCRIPT SELECTOR] Selecting script for IP: {ip_address}, Device Type: {device_type}, Connection: {connection_type}")
        try:
            from scripts.Nokia_SAR import Script as Sar
            from scripts.Nokia_IXR import Script as Ixr
            from scripts.Nokia_1830 import Script as Pss
            from scripts.Ciena_6500 import Script as C65

            DEVICE_SCRIPT_MAPPING = {
                '7705 sar-8 v2': Sar,
                '7250 ixr-r6': Ixr,
                '7250 ixr-r6d': Ixr,
                '1830': Pss,
                '6500': C65,
                'ciena 6500 optical': C65,
            }

            normalized_type = (device_type or '').strip().lower()
            script_class = DEVICE_SCRIPT_MAPPING.get(normalized_type)

            if script_class:
                logging.info(f"[SCRIPT SELECTOR] Matched '{normalized_type}' to script: {script_class.__name__}")
                return script_class(
                    connection_type=connection_type,
                    ip_address=ip_address,
                    username=DEFAULT_USERNAME,      # ✅ required
                    password=DEFAULT_PASSWORD,      # ✅ required
                    db_path=get_inventory_db_path(),
                    command_tracker=CommandTracker()
                )
            else:
                logging.warning(f"[SCRIPT SELECTOR] No matching script found for normalized device type: '{normalized_type}'")
                return None

        except Exception as e:
            logging.error(f"[SCRIPT SELECTOR] Failed to select script for device '{device_type}' at IP {ip_address}: {e}")
            return None