import os
import sys
import sqlite3
import logging
import re
import ipaddress
import time
from tkinter import messagebox
import pandas as pd
import subprocess
from openpyxl import load_workbook
from typing import Callable, Dict, List, Optional, Tuple

# Allow running this file directly from the scripts/ directory
# (`python Nokia_1830.py`) by ensuring the project root is on sys.path.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from script_interface import BaseScript, CommandTracker, DatabaseCache, get_inventory_db_path, get_tracker, get_cache, NEEDS_CREDENTIALS_SENTINEL
from utils.helpers import ensure_host_key_known, friendly_error, get_known_hosts_path
from utils.telnet import Telnet

try:
    from wexpect import spawn, EOF, TIMEOUT  # type: ignore[import-not-found]
except ImportError:
    from pexpect import spawn, EOF, TIMEOUT  # type: ignore[import-not-found]


# Ensure logging is configured

class Script(BaseScript):
    def __init__(self, *,                       # <- make these keyword-only to avoid mixups
                 connection_type='telnet',
                 command_tracker=None,
                 ip_address,
                 username='admin',
                 password='admin',
                 timeout=5,
                 db_path=None,
                 db_cache=None,
                 stop_callback=None):
        # --- DB wiring ---
        if db_cache is not None:
            self.db_cache = db_cache
            self.db_path = db_cache.db_path
        else:
            if db_path is None:
                db_path = get_inventory_db_path()   # final fallback
            db_path = os.path.abspath(db_path)
            if not os.path.exists(db_path):
                raise FileNotFoundError(f"Database file missing at: {db_path}")
            self.db_cache = DatabaseCache(db_path)
            self.db_path = db_path

        # --- misc wiring ---
        self.connection_type = connection_type
        self.command_tracker = command_tracker or get_tracker()
        self.telnet = None
        self.child = None
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = 22
        self.stop_callback = stop_callback

        if not self.ip_address:
            raise ValueError("Missing required 'ip_address' for network-based connection.")

    def abort_connection(self):
        """Forcefully close the SSH/Telnet connection to interrupt blocking I/O."""
        if self.child:
            try:
                self.child.close(force=True)
                logging.debug("SSH spawn process forcefully closed for abort.")
            except Exception as e:
                logging.debug(f"Error force-closing spawn: {e}")
            finally:
                self.child = None
        if self.telnet:
            try:
                self.telnet.close()
                logging.info("Telnet connection forcefully closed for abort.")
            except Exception as e:
                logging.debug(f"Error force-closing telnet: {e}")
            finally:
                self.telnet = None

    def should_stop(self) -> bool:
        return bool(self.stop_callback and self.stop_callback())

    def sleep_with_abort(self, seconds: float, interval: float = 0.1) -> bool:
        end_time = time.time() + seconds
        while time.time() < end_time:
            if self.should_stop():
                return True
            time.sleep(min(interval, end_time - time.time()))
        return self.should_stop()

    def expect_with_abort(self, child, patterns, timeout=30, step=1):
        elapsed = 0
        while elapsed < timeout:
            if self.should_stop():
                return None
            try:
                return child.expect(patterns, timeout=min(step, timeout - elapsed))
            except TIMEOUT:
                elapsed += min(step, timeout - elapsed)
        raise TIMEOUT("Timeout waiting for device response")

    def get_commands(self) -> List[str]:
        return [
            'show general name',
            'show shelf inventory *',
            'show card inventory *',
            'show interface inventory *',
        ]

    def execute_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        if self.connection_type == 'ssh':
            outputs, error = self.execute_ssh_commands(commands)
            if error and error not in ("Aborted", NEEDS_CREDENTIALS_SENTINEL):
                logging.warning(f"SSH failed for {self.ip_address}: {error}. Falling back to Telnet.")
                return self._execute_telnet_commands(commands)
            return outputs, error
        return self._execute_telnet_commands(commands)

    def _execute_telnet_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        outputs = []
        try:
            # Open ONE persistent session — the probe proved a single session
            # handles all 5 inventory commands cleanly. Per-command sessions
            # were a workaround for an unrelated bug (CRLF vs LF, SPACE flush).
            if not self.telnet_login():
                return outputs, "Aborted" if self.should_stop() else NEEDS_CREDENTIALS_SENTINEL

            total = len(commands)
            logging.info(f"Collecting inventory from {self.ip_address} ({total} commands)")
            for idx, command in enumerate(commands, start=1):
                if self.should_stop():
                    return outputs, "Aborted"
                if self.command_tracker.has_executed(self.ip_address, command, 'telnet'):
                    logging.debug(f"Skipping previously executed command: {command}")
                    continue
                logging.info(f"[{self.ip_address}] ({idx}/{total}) Executing: {command}")
                output, error = self.execute_telnet_command(command)
                if error:
                    logging.error(f"Error executing command '{command}': {error}")
                    outputs.append(None)
                else:
                    outputs.append(output)
                    self.command_tracker.mark_as_executed(self.ip_address, command, 'telnet')
            logging.info(f"Inventory collection complete for {self.ip_address}")
            return outputs, None if all(outputs) else "Some commands failed"
        finally:
            self.close_telnet()

    def execute_ssh_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        try:
            # Validate IP address format to prevent injection attacks
            try:
                ipaddress.ip_address(self.ip_address)
            except ValueError:
                return [], f"Invalid IP address format: {self.ip_address}"
            
            # Validate username to prevent injection (alphanumeric, dash, underscore, dot only)
            if not re.match(r'^[a-zA-Z0-9._-]+$', self.username):
                return [], f"Invalid username format: {self.username}"
            
            _kh = str(get_known_hosts_path())
            if not ensure_host_key_known(str(self.ip_address), port=self.port):
                return [], (
                    f"SSH host key verification failed or rejected for "
                    f"{self.ip_address}:{self.port}"
                )
            ssh_args = [
                "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={_kh}",
                "-o", "HostKeyAlgorithms=+ssh-rsa",
                "-o", "PubkeyAcceptedKeyTypes=+ssh-rsa",
                "-p", str(self.port),
                "-l", self.username,
                str(self.ip_address),
            ]
            logging.debug(f"Spawning SSH process to {self.ip_address}:{self.port}")
            self.child = spawn("ssh", args=ssh_args, encoding='utf-8', timeout=30)
            output_log = []

            idx = self.expect_with_abort(
                self.child,
                [r"[Ll]ogin:", r"[Uu]sername:", r"[Pp]assword:", EOF, TIMEOUT],
                timeout=30,
            )
            if idx is None:
                self.child.close(force=True); self.child = None; return [], "Aborted"
            if idx in (3, 4):
                self.child.close(force=True); self.child = None; return [], "SSH connection failed"

            if idx == 0:  # login: — Nokia CLI step
                self.child.sendline("cli")
                r = self.expect_with_abort(self.child, [r"[Uu]sername:", EOF, TIMEOUT], timeout=15)
                if r is None:
                    self.child.close(force=True); self.child = None; return [], "Aborted"
                if r != 0:
                    self.child.close(force=True); self.child = None; return [], "SSH login sequence failed"
                self.child.sendline(self.username)
            elif idx == 1:  # username:
                self.child.sendline(self.username)
            # idx == 2 means already at password:

            if idx != 2:
                r = self.expect_with_abort(self.child, [r"[Pp]assword:", EOF, TIMEOUT], timeout=15)
                if r is None:
                    self.child.close(force=True); self.child = None; return [], "Aborted"
                if r != 0:
                    self.child.close(force=True); self.child = None; return [], "SSH did not present password prompt"
            self.child.sendline(self.password)

            # Some 1830 builds insert a Y/n acknowledgement banner (license/EULA
            # or session-warning) between successful auth and the shell prompt.
            # Auto-answer "y" up to a few times before insisting on a real prompt.
            for _ in range(3):
                idx = self.expect_with_abort(
                    self.child,
                    [r"[#>]",
                     r"(?i)\(\s*y\s*/\s*n\s*\)|\[\s*y\s*/\s*n\s*\]|continue\?|accept\?|press\s+y",
                     "incorrect", "invalid", EOF, TIMEOUT],
                    timeout=30,
                )
                if idx is None:
                    self.child.close(force=True); self.child = None; return [], "Aborted"
                if idx == 0:
                    break  # at shell prompt
                if idx == 1:
                    logging.debug("[1830] Acknowledging post-login Y/n prompt")
                    self.child.sendline("y")
                    continue
                if idx in (2, 3):
                    self.child.close(force=True); self.child = None; return [], NEEDS_CREDENTIALS_SENTINEL
                if idx in (4, 5):
                    self.child.close(force=True); self.child = None; return [], "SSH session closed unexpectedly"
            else:
                # Loop exhausted without seeing a prompt char.
                self.child.close(force=True); self.child = None; return [], "Login banner did not yield shell prompt"

            prompt = self.child.after.strip()
            logging.debug(f"Detected SSH prompt: '{prompt}'")

            for cmd in commands:
                if self.should_stop():
                    self.child.close(force=True); self.child = None; return output_log, "Aborted"
                logging.debug(f"Sending SSH command: {cmd}")
                self.child.sendline(cmd)
                if self.expect_with_abort(self.child, cmd, timeout=15) is None:
                    self.child.close(force=True); self.child = None; return output_log, "Aborted"
                full_output = ""
                while True:
                    index = self.expect_with_abort(self.child, [prompt, EOF, TIMEOUT], timeout=30)
                    if index is None:
                        self.child.close(force=True); self.child = None; return output_log, "Aborted"
                    full_output += self.child.before
                    if index == 0:
                        full_output += self.child.after
                        break
                    elif index in (1, 2):
                        logging.warning(f"SSH session ended waiting for prompt (cmd: {cmd})")
                        break
                output_log.append(full_output.strip())
                self.command_tracker.mark_as_executed(self.ip_address, cmd, 'ssh')

            self.child.sendline("exit")
            try:
                self.expect_with_abort(self.child, [prompt, EOF, TIMEOUT], timeout=10)
            except Exception:
                pass
            self.child.close(force=True)
            self.child = None
            return output_log, None

        except Exception as e:
            logging.exception("SSH execution exception")
            if self.child:
                try:
                    self.child.close(force=True)
                except Exception:
                    pass
                self.child = None
            return [], str(e)

    def telnet_login(self, retries: int = 2) -> bool:
        if self.telnet:
            return True

        for attempt in range(1, retries + 1):
            temp_telnet = None
            try:
                if self.should_stop():
                    return False
                if attempt == 1:
                    logging.info(f"Connecting to {self.ip_address}")
                else:
                    logging.info(f"Connecting to {self.ip_address} (attempt {attempt})")
                temp_telnet = Telnet(self.ip_address, timeout=self.timeout,
                                     bypass_policy=True,
                                     purpose="nokia-1830-inventory")

                # Three-stage 1830 login — bare \n line endings (\r\n is
                # treated as literal text by this CLI).
                temp_telnet.read_until(b"login: ", timeout=5)
                temp_telnet.write(b"cli\n")
                temp_telnet.read_until(b"Username: ", timeout=5)
                temp_telnet.write(self.username.encode('ascii') + b"\n")
                temp_telnet.read_until(b"Password: ", timeout=5)
                temp_telnet.write(self.password.encode('ascii') + b"\n")
                if self.sleep_with_abort(1):
                    try: temp_telnet.close()
                    except Exception: pass
                    return False

                login_response = temp_telnet.read_very_eager().decode('ascii', errors='ignore')
                if "Login incorrect" in login_response or "invalid" in login_response.lower():
                    logging.error("Telnet login failed: Invalid credentials.")
                    try: temp_telnet.close()
                    except Exception: pass
                    continue

                # Some 1830 builds present a "Do you acknowledge? (Y/N)?" banner
                # between authentication and the CLI prompt. Auto-accept it.
                if re.search(r"(?i)\(\s*y\s*/\s*n\s*\)|acknowledge", login_response):
                    logging.debug("Acknowledging post-login Y/N banner")
                    temp_telnet.write(b"y\n")
                    if self.sleep_with_abort(0.5):
                        try: temp_telnet.close()
                        except Exception: pass
                        return False
                    try:
                        temp_telnet.read_very_eager()
                    except Exception:
                        pass

                logging.info(f"Connected to {self.ip_address}")
                self.telnet = temp_telnet
                return True
            except Exception as e:
                logging.error(f"Telnet login attempt {attempt} failed: {e}")
                if temp_telnet is not None:
                    try:
                        temp_telnet.close()
                    except Exception as close_err:
                        logging.debug(f"Error closing Telnet after failed login: {close_err}")

        return False


    def execute_telnet_command(self, command: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            if not self.telnet_login():
                return None, "Aborted" if self.should_stop() else "Telnet login failed."

            self.telnet.write(command.encode('ascii') + b"\n")
            output = self.capture_full_output_telnet()
            if self.should_stop():
                return None, "Aborted"

            logging.debug(f"Captured {len(output)} bytes for '{command}'")
            return output, None

        except Exception as e:
            logging.error(f"Telnet command failed: {e}")
            return None, str(e)


    def capture_full_output_telnet(self, settle: float = 2.0,
                                   read_timeout: float = 10.0,
                                   max_pager_pages: int = 50) -> str:
        """Capture command output using the proven probe pattern.

        Sleeps `settle` seconds after the command was sent (lets the device
        start producing output), then reads until the '#' prompt with a
        bounded timeout, drains any tail bytes, and handles real pager
        prompts ("Press any key", "--More--", "(More)") if they appear.
        """
        if self.sleep_with_abort(settle):
            return ""
        try:
            blob = self.telnet.read_until(b"#", timeout=read_timeout)
        except Exception as e:
            logging.error(f"Telnet read failed while capturing output: {e}")
            blob = b""
        try:
            tail = self.telnet.read_very_eager()
        except Exception:
            tail = b""
        data = bytearray(blob)
        data.extend(tail)
        logging.debug(f"[1830-CAP] read_until={len(blob)}B tail={len(tail)}B")

        pager_hits = 0
        while (b"Press any key to continue" in data
               or b"--More--" in data
               or b"(More)" in data) and pager_hits < max_pager_pages:
            if self.should_stop():
                break
            pager_hits += 1
            logging.debug(f"[1830-CAP] pager #{pager_hits} — sending SPACE")
            try:
                self.telnet.write(b" ")
            except Exception as e:
                logging.debug(f"[1830-CAP] pager write failed: {e}")
                break
            if self.sleep_with_abort(0.5):
                break
            try:
                more_blob = self.telnet.read_until(b"#", timeout=8)
                more_tail = self.telnet.read_very_eager()
            except Exception as e:
                logging.debug(f"[1830-CAP] pager read failed: {e}")
                break
            data.extend(more_blob)
            data.extend(more_tail)
            if not more_blob and not more_tail:
                break

        text = bytes(data).decode('ascii', errors='replace')
        # Strip pager artifacts from the captured text
        text = re.sub(r"Press any key to continue.*?\(Q to quit\)", "", text,
                      flags=re.IGNORECASE)
        text = text.replace("--More--", "").replace("(More)", "")
        return text.strip()
    
    def close_telnet(self):
        """
        Gracefully closes the Telnet session if it's open.
        """
        if self.telnet:
            try:
                try:
                    self.telnet.write(b"exit\n")
                except Exception:
                    pass  # socket may already be closed; that's fine
                self.telnet.close()
                logging.debug("Telnet session closed.")
            except Exception as e:
                logging.debug(f"Telnet close raised (already dead?): {e}")
            finally:
                self.telnet = None

    def close_telnet_force(self):
        """
        Force-closes the Telnet session immediately to interrupt blocking I/O.
        """
        if self.telnet:
            try:
                self.telnet.close()
                logging.info("Telnet session force-closed.")
            except Exception as e:
                logging.debug(f"Error force-closing telnet: {e}")
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

            # Single-line match — don't let \s+ cross newlines into the
            # trailing CLI prompt. Part Number / Serial / CLEI may all be
            # blank on the 1830 if the shelf is unprovisioned, so they're
            # optional captures.
            shelf_pattern = re.compile(
                r"^\s*(\d+)\s+(\S+)(?:\s+(\S+))?(?:\s+(\S+))?(?:\s+(\S+))?\s*$",
                re.MULTILINE,
            )

            # Process each match from the regex
            matches = re.finditer(shelf_pattern, output)
            for match in matches:
                try:
                    shelf_type = (match.group(2) or "").strip()
                    part_number = (match.group(3) or "").strip()
                    serial_number = (match.group(4) or "").strip()
                    # Filter out anything that looks like a prompt fragment
                    if shelf_type.endswith("#") or part_number.endswith("#"):
                        continue

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
                    logging.debug(f"Processing data for IP {ip}.")
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
            # SECURITY: Do not use shell=True; shell is not needed for these platform-specific commands
            if os.name == 'nt':  # Windows
                subprocess.run(["start", "", output_file], check=True)
            else:  # macOS/Linux
                subprocess.run(["open", output_file], check=True)

        except Exception as e:
            logging.error(f"Failed to save data to Excel: {e}")
            messagebox.showerror("Export Error", f"Failed to save Excel file:\n{friendly_error(e)}")
        finally:
            # Close the SQLite connection
            if conn:
                conn.close()
            logging.debug("SQLite connection closed.")'''



'''if __name__ == "__main__":
    def main():
        # Set target IP and Telnet credentials
        ip = '10.9.101.120'
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