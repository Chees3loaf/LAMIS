"""
Device identification, script selection, and shared infrastructure for LAMIS.

Provides:
  - ``is_reachable`` — ICMP ping check
  - ``BaseScript`` — ABC that all device scripts must implement
  - ``CommandTracker`` — deduplication of per-device commands
  - ``DatabaseCache`` — write-through cache for part-number lookups
  - ``DeviceIdentifier`` — SSH/Telnet banner probing to determine device type
  - ``ScriptSelector`` — maps device type strings to script classes
"""
import os
import subprocess
import logging
import sqlite3
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple, List, Any, Callable
from queue import Queue
import paramiko
import re
from utils.telnet import Telnet
from paramiko.ssh_exception import AuthenticationException
import config
from utils.helpers import get_database_path

DEFAULT_PASSWORD = config.DEFAULT_PASSWORD
DEFAULT_USERNAME = config.DEFAULT_USERNAME

# At the bottom or top-level
def get_inventory_db_path() -> str:
    """
    Get the inventory database path.
    
    Deprecated: Use utils.helpers.get_database_path() instead.
    Kept for backward compatibility.
    """
    return str(get_database_path())

def is_reachable(ip: str) -> bool:
    """Return True if the host at *ip* responds to a single ping."""
    try:
        logging.debug(f"[PING] Checking reachability for {ip}")
        result = subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True)
        reachable = result.returncode == 0
        logging.debug(f"[PING] {ip} is {'reachable' if reachable else 'not reachable'}")
        return reachable
    except Exception as e:
        logging.warning(f"[PING] Ping check failed for {ip}: {e}")
        return False

class BaseScript(ABC):
    """Abstract base class that all device scripts must implement."""

    @abstractmethod
    def get_commands(self) -> List[str]:
        """Return the list of commands to execute on this device type."""

    @abstractmethod
    def execute_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        """Execute commands on the device. Returns (outputs, error_or_None)."""

    @abstractmethod
    def process_outputs(self, outputs_from_device: List[str], ip_address: str, outputs: Dict[str, Any]) -> None:
        """Parse raw device output and populate the outputs dict."""

    @abstractmethod
    def abort_connection(self) -> None:
        """Forcefully close any open connection to interrupt blocking I/O."""

    def should_stop(self) -> bool:
        """Return True if a stop has been requested via the stop_callback."""
        return bool(getattr(self, 'stop_callback', None) and self.stop_callback())

class CommandTracker:
    """Track which CLI commands have already been run on a given device.

    Prevents duplicate command execution when a script is re-entered or
    retried on the same IP/connection pair within a single scan session.
    """
    def __init__(self) -> None:
        self.executed_commands: Dict[Tuple[str, str], set] = {}
        logging.debug("[TRACKER] Initialized command tracker")

    def has_executed(self, ip: str, command: str, connection_type: str) -> bool:
        """Return True if *command* has already been run on *ip* over *connection_type*."""
        key = (ip, connection_type)
        result = command in self.executed_commands.get(key, set())
        logging.debug(f"[TRACKER] Check if executed '{command}' on {ip}/{connection_type}: {result}")
        return result

    def mark_as_executed(self, ip: str, command: str, connection_type: str) -> None:
        """Record that *command* has been executed on *ip* over *connection_type*."""
        key = (ip, connection_type)
        if key not in self.executed_commands:
            self.executed_commands[key] = set()
        self.executed_commands[key].add(command)
        logging.debug(f"[TRACKER] Marked '{command}' as executed on {ip}/{connection_type}")

    def reset(self) -> None:
        """Clear all execution history (call between scan sessions)."""
        self.executed_commands.clear()
        logging.debug("[TRACKER] Reset executed commands")

class DatabaseCache:
    """In-memory write-through cache for part number → description lookups.

    Wraps a SQLite parts database so repeated lookups for the same part
    number don't hit disk on every call.
    """
    def __init__(self, db_path: str) -> None:
        self.db_path = os.path.abspath(db_path)
        self.cache: Dict[str, str] = {}
        logging.debug(f"[CACHE] Initialized cache with DB path: {self.db_path}")

    def lookup_part(self, part_number: str) -> str:
        """Return the description for *part_number* (first 10 chars used as key).

        Returns "Invalid part number" if part_number is empty/whitespace,
        "Not Found" when the part is absent from the database,
        or a "DB Error: ..." string if the database cannot be read.
        """
        # Validate part number is not empty or whitespace
        if not part_number or not part_number.strip():
            return "Invalid part number"
        
        key = part_number[:10]
        
        # Check cache first
        if key in self.cache:
            return self.cache[key]
        
        # Lookup in database and cache result
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT description FROM parts WHERE part_number LIKE ?", (key + "%",))
                result = cursor.fetchone()
                description = result[0] if result else "Not Found"
        except Exception as e:
            logging.exception(f"[CACHE] DB error on '{key}'")
            description = f"DB Error: {e}"
        
        # Always cache the result before returning
        self.cache[key] = description
        return description
        
_CACHE = None
def get_cache():
    """Return the process-wide singleton DatabaseCache, creating it on first call."""
    global _CACHE
    if _CACHE is None:
        _CACHE = DatabaseCache(get_inventory_db_path())
    return _CACHE

_TRACKER = None
def get_tracker():
    """Return the process-wide singleton CommandTracker, creating it on first call."""
    global _TRACKER
    if _TRACKER is None:
        _TRACKER = CommandTracker()
    return _TRACKER

class DeviceIdentifier:
    """Identify a network device's type and name by probing it via SSH then Telnet."""

    def identify_device(self, ip: str, queue: Queue, output_screen: Optional[Any], stop_callback: Optional[Callable[[], bool]] = None) -> Tuple[Optional[str], Optional[str]]:
        """Attempt to identify the device at *ip*.

        Tries SSH banner inspection first, then SSH login, then Telnet.
        Progress messages are placed on *queue* for the GUI to display.

        Returns:
            (device_type, device_name) — both None if identification fails.
        """
        username, password = config.DEFAULT_USERNAME, config.DEFAULT_PASSWORD
        logging.info(f"[IDENTIFY] Trying to identify {ip} via SSH")

        def should_stop():
            return bool(stop_callback and stop_callback())

        def sleep_with_abort(seconds: float, interval: float = 0.1) -> bool:
            end_time = time.time() + seconds
            while time.time() < end_time:
                if should_stop():
                    return True
                time.sleep(min(interval, end_time - time.time()))
            return should_stop()

        if should_stop():
            queue.put(f"[ABORT] Identification cancelled for {ip}.\n")
            return None, None

        try:
            transport = paramiko.Transport((ip, 22))
            transport.start_client(timeout=config.SSH_CONNECT_TIMEOUT)

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
                logging.debug(f"[IDENTIFY] Ciena 6500 banner matched on {ip}")
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
            ssh_client.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=config.SSH_CONNECT_TIMEOUT)

            logging.debug(f"[IDENTIFY] Connected to {ip} via SSH")
            queue.put(f"Connected to {ip} via SSH\n")
            session = ssh_client.invoke_shell()

            for command in ["show chassis | match (Type) pre-lines 1 expression"]:
                if should_stop():
                    ssh_client.close()
                    queue.put(f"[ABORT] SSH identification cancelled for {ip}.\n")
                    return None, None
                queue.put(f"Executing command: {command}\n")
                session.send(command + '\n')
                if sleep_with_abort(2):
                    ssh_client.close()
                    queue.put(f"[ABORT] SSH identification cancelled for {ip}.\n")
                    return None, None

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

        return self.identify_device_telnet(ip, queue, stop_callback=stop_callback)

    def identify_device_telnet(self, ip: str, queue: Queue, stop_callback: Optional[Callable[[], bool]] = None) -> Tuple[Optional[str], Optional[str]]:
        """Attempt device identification via Telnet when SSH is unavailable.

        Returns:
            (device_type, device_name) — both None if identification fails.
        """
        username, password = config.DEFAULT_USERNAME, config.DEFAULT_PASSWORD
        logging.info(f"[IDENTIFY] Attempting Telnet to {ip}")

        def should_stop():
            return bool(stop_callback and stop_callback())

        def sleep_with_abort(seconds: float, interval: float = 0.1) -> bool:
            end_time = time.time() + seconds
            while time.time() < end_time:
                if should_stop():
                    return True
                time.sleep(min(interval, end_time - time.time()))
            return should_stop()

        tn = None
        try:
            queue.put(f"Attempting Telnet connection to {ip}...\n")
            tn = Telnet(ip, timeout=config.TELNET_CONNECT_TIMEOUT)

            tn.read_until(b"login: ", timeout=config.TELNET_READ_TIMEOUT)
            tn.write(b"cli\n")
            tn.read_until(b"Username: ", timeout=config.TELNET_READ_TIMEOUT)
            tn.write(username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=config.TELNET_READ_TIMEOUT)
            tn.write(password.encode('ascii') + b"\n")
            if sleep_with_abort(1):
                queue.put(f"[ABORT] Telnet identification cancelled for {ip}.\n")
                return None, None

            login_output = tn.read_very_eager().decode('ascii')
            logging.debug(f"[TELNET] Login output from {ip}:\n{login_output}")

            if "Login incorrect" in login_output or "invalid" in login_output.lower():
                queue.put("Telnet login failed: Invalid credentials.\n")
                return None, None

            if should_stop():
                queue.put(f"[ABORT] Telnet identification cancelled for {ip}.\n")
                return None, None

            tn.write(b"show general system-identification\n")
            if sleep_with_abort(3):
                queue.put(f"[ABORT] Telnet identification cancelled for {ip}.\n")
                return None, None
            output1 = tn.read_until(b"#", timeout=config.TELNET_READ_TIMEOUT).decode('ascii')
            tn.write(b"show general name\n")
            if sleep_with_abort(3):
                queue.put(f"[ABORT] Telnet identification cancelled for {ip}.\n")
                return None, None
            output2 = tn.read_until(b"#", timeout=config.TELNET_READ_TIMEOUT).decode('ascii')
            tn.write(b"exit\n")

            full_output = output1 + "\n" + output2
            logging.debug(f"[TELNET] Response from {ip}:\n{full_output}")
            queue.put(f"Telnet response from {ip}:\n{full_output}\n")
            return self.parse_device_info(full_output, queue)

        except Exception as e:
            logging.error(f"[TELNET] Failed for {ip}: {e}")
            queue.put(f"Telnet failed for {ip}: {e}\n")
            return None, None
        finally:
            if tn is not None:
                try:
                    tn.close()
                except Exception as e:
                    logging.debug(f"[TELNET] Error closing connection for {ip}: {e}")

    @staticmethod
    def parse_device_info(output: str, queue: Queue) -> Tuple[Optional[str], Optional[str]]:
        """Parse raw CLI output and extract device type and name.

        Searches for Nokia-style ``Type : ...`` / ``Name : ...`` fields and
        Ciena-style ``Product : ...`` / ``Name: ...`` fields.

        Returns:
            (device_type, device_name) — either or both may be None.
        """
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
            logging.debug(f"[PARSE] Parsed Type: {device_type}, Name: {device_name}")
            return device_type, device_name

        except Exception as e:
            logging.exception(f"[PARSE] Error parsing device info for {ip}")
            queue.put(f"Error parsing device info: {e}\n")
            return None, None


class ScriptSelector:
    """Map an identified device type to the appropriate BaseScript subclass and instantiate it."""

    # Map of normalized device types to script classes
    _device_type_to_script = {
        '7705 sar-8 v2': 'scripts.Nokia_SAR',
        '7250 ixr-r6': 'scripts.Nokia_IXR',
        '7250 ixr-r6d': 'scripts.Nokia_IXR',
        '1830': 'scripts.Nokia_1830',
        '6500': 'scripts.Ciena_6500',
        'ciena 6500 optical': 'scripts.Ciena_6500',
    }

    def _is_device_supported(self, normalized_type: str) -> bool:
        """Return True if the device type is supported by an available script."""
        return normalized_type in self._device_type_to_script

    def select_script(self, device_type: Optional[str], ip_address: str, connection_type: str = 'ssh', stop_callback: Optional[Callable[[], bool]] = None) -> Optional[BaseScript]:
        """Return an instantiated script for *device_type* at *ip_address*, or None if unknown."""
        logging.debug(f"[SCRIPT SELECTOR] Selecting script for IP: {ip_address}, Device Type: {device_type}, Connection: {connection_type}")

        normalized_type = (device_type or '').strip().lower()
        if not normalized_type:
            logging.debug(f"[SCRIPT SELECTOR] No device type detected for IP {ip_address}; skipping script selection.")
            return None

        # Validate device type is supported
        if not self._is_device_supported(normalized_type):
            logging.debug(f"[SCRIPT SELECTOR] Device type '{normalized_type}' not supported for IP {ip_address}")
            return None

        try:
            script_module = self._device_type_to_script[normalized_type]
            # Dynamically import the module
            parts = script_module.rsplit('.', 1)
            module = __import__(script_module, fromlist=[parts[-1]])
            script_class = module.Script

            logging.info(f"[SCRIPT SELECTOR] Matched '{normalized_type}' to script: {script_class.__name__}")
            return script_class(
                connection_type=connection_type,
                ip_address=ip_address,
                username=DEFAULT_USERNAME,
                password=DEFAULT_PASSWORD,
                db_cache=get_cache(),
                command_tracker=get_tracker(),
                stop_callback=stop_callback,
            )

        except ImportError as e:
            logging.exception(f"[SCRIPT SELECTOR] Missing optional dependency for device '{device_type}' at IP {ip_address}")
            return None
        except Exception as e:
            logging.exception(f"[SCRIPT SELECTOR] Failed to select script for device '{device_type}' at IP {ip_address}")
            return None