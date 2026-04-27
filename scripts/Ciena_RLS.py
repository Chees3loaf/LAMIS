import os
import logging
import re
import time
from tkinter import messagebox
import pandas as pd
from openpyxl import load_workbook
from typing import Callable, Dict, List, Optional, Tuple
from script_interface import BaseScript, CommandTracker, DatabaseCache, get_inventory_db_path, get_tracker, get_cache
from utils.telnet import Telnet

try:
    from wexpect import spawn, EOF, TIMEOUT
except ImportError:
    from redexpect import spawn, EOF, TIMEOUT


class Script(BaseScript):
    def __init__(self, *,
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
                db_path = get_inventory_db_path()
            db_path = os.path.abspath(db_path)
            if not os.path.exists(db_path):
                raise FileNotFoundError(f"Database file missing at: {db_path}")
            self.db_cache = DatabaseCache(db_path)
            self.db_path = db_path

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

    # ------------------------------------------------------------------
    # Abort / stop helpers
    # ------------------------------------------------------------------

    def abort_connection(self):
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

    # ------------------------------------------------------------------
    # Command list
    # ------------------------------------------------------------------

    def get_commands(self) -> List[str]:
        return [
            'show shelf',                                        # shelf name + type info
            'show slots * inventory',                            # shelf / slot hardware summary
            'show slots * inventory circuit-pack',               # card inventory
            'show slots * inventory slots *',                    # module / pluggable inventory
            'show software',                                     # software release info
            'show slots *',                                      # slot programming state
            'show aps',                                          # APS line protection switch
            'show components component power-supply state',      # power supply status
            'show lldp interfaces',                              # LLDP port topology
        ]

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def execute_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        if self.connection_type == 'ssh':
            return self.execute_ssh_commands(commands)

        outputs = []
        for command in commands:
            if self.should_stop():
                self.close_telnet()
                return outputs, "Aborted"
            if self.command_tracker.has_executed(self.ip_address, command, self.connection_type):
                logging.debug(f"Skipping previously executed command: {command}")
                continue
            if self.connection_type == 'telnet':
                output, error = self.execute_telnet_command(command)
            else:
                error = f"Invalid connection type: {self.connection_type}"
                output = None

            if error:
                logging.error(f"Error executing command '{command}': {error}")
                outputs.append(None)
            else:
                outputs.append(output)
                self.command_tracker.mark_as_executed(self.ip_address, command, self.connection_type)

        self.close_telnet()
        return outputs, None if all(outputs) else "Some commands failed"

    def execute_ssh_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        try:
            ssh_cmd = (
                f"ssh -o StrictHostKeyChecking=no "
                f"-o HostKeyAlgorithms=+ssh-rsa "
                f"-o PubkeyAcceptedKeyTypes=+ssh-rsa "
                f"-p {self.port} {self.ip_address}"
            )
            logging.debug(f"Spawning SSH process to {self.ip_address}:{self.port}")
            self.child = spawn(ssh_cmd, encoding='utf-8', timeout=30)

            output_log = []

            idx = self.expect_with_abort(
                self.child,
                ["[Ll]ogin:", "Are you sure you want to continue connecting", EOF, TIMEOUT],
                timeout=30,
            )
            if idx is None:
                self.child.close(force=True)
                self.child = None
                return [], "Aborted"
            if idx == 1:
                self.child.sendline("yes")
                idx = self.expect_with_abort(self.child, ["[Ll]ogin:", EOF, TIMEOUT], timeout=30)
                if idx is None:
                    self.child.close(force=True)
                    self.child = None
                    return [], "Aborted"

            self.child.sendline(self.username)
            if self.expect_with_abort(self.child, "[Pp]assword:", timeout=30) is None:
                self.child.close(force=True)
                self.child = None
                return [], "Aborted"
            self.child.sendline(self.password)

            idx = self.expect_with_abort(self.child, [r"[#]", EOF, TIMEOUT], timeout=30)
            if idx is None:
                self.child.close(force=True)
                self.child = None
                return [], "Aborted"
            if idx in [1, 2]:
                logging.error("SSH authentication failed")
                return [], "Authentication failed"

            prompt = self.child.after.strip()
            logging.debug(f"Detected SSH prompt: '{prompt}'")

            for cmd in commands:
                if self.should_stop():
                    self.child.close(force=True)
                    self.child = None
                    return output_log, "Aborted"
                logging.debug(f"Sending SSH command: {cmd}")
                self.child.sendline(cmd)
                if self.expect_with_abort(self.child, cmd, timeout=30) is None:
                    self.child.close(force=True)
                    self.child = None
                    return output_log, "Aborted"
                full_output = ""
                while True:
                    index = self.expect_with_abort(self.child, [prompt, EOF, TIMEOUT], timeout=30)
                    if index is None:
                        self.child.close(force=True)
                        self.child = None
                        return output_log, "Aborted"
                    chunk = self.child.before
                    full_output += chunk
                    if index == 0:
                        full_output += self.child.after
                        break
                    elif index == 1:
                        logging.warning("EOF while waiting for SSH prompt")
                        break
                    elif index == 2:
                        logging.error("Timeout waiting for SSH prompt")
                        break
                output_log.append(full_output.strip())
                self.command_tracker.mark_as_executed(self.ip_address, cmd, self.connection_type)

            self.child.sendline("exit")
            try:
                self.expect_with_abort(self.child, [prompt, EOF, TIMEOUT], timeout=10)
            except TIMEOUT:
                logging.warning("Timeout after SSH 'exit', force closing")
            self.child.close(force=True)
            self.child = None
            return output_log, None

        except Exception as e:
            logging.exception("SSH execution exception")
            self.child = None
            return [], str(e)

    # ------------------------------------------------------------------
    # Telnet helpers
    # ------------------------------------------------------------------

    def telnet_login(self, retries: int = 2) -> bool:
        if self.telnet:
            return True

        for attempt in range(1, retries + 1):
            temp_telnet = None
            try:
                if self.should_stop():
                    return False
                logging.info(f"Connecting to {self.ip_address} via Telnet (Attempt {attempt})...")
                temp_telnet = Telnet(self.ip_address, timeout=self.timeout)

                temp_telnet.read_until(b"login: ", timeout=5)
                temp_telnet.write(b"cli\n")
                temp_telnet.read_until(b"Username: ", timeout=5)
                temp_telnet.write(self.username.encode('ascii') + b"\n")
                temp_telnet.read_until(b"Password: ", timeout=5)
                temp_telnet.write(self.password.encode('ascii') + b"\n")
                if self.sleep_with_abort(1):
                    try:
                        temp_telnet.close()
                    except Exception:
                        pass
                    return False

                login_response = temp_telnet.read_very_eager().decode('ascii')
                if "Login incorrect" in login_response or "invalid" in login_response.lower():
                    logging.error("Telnet login failed: Invalid credentials.")
                    try:
                        temp_telnet.close()
                    except Exception:
                        pass
                    continue

                logging.info("Telnet login successful.")
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

            logging.debug(f"Executing command: {command}")
            self.telnet.write(command.encode('ascii') + b"\n")
            if self.sleep_with_abort(3.5):
                return None, "Aborted"
            output = self.capture_full_output_telnet()
            if self.should_stop():
                return None, "Aborted"
            return output, None
        except Exception as e:
            logging.error(f"Telnet command failed: {e}")
            return None, str(e)

    def capture_full_output_telnet(self) -> str:
        try:
            while not self.should_stop():
                output = self.telnet.read_until(b"#", timeout=1).decode('ascii')
                if output:
                    return output.strip()
            return ""
        except Exception as e:
            logging.error(f"Error capturing Telnet output: {e}")
            return ""

    def close_telnet(self):
        if self.telnet:
            try:
                self.telnet.write(b"exit\n")
                self.telnet.close()
                logging.info("Telnet session closed.")
            except Exception as e:
                logging.warning(f"Failed to close Telnet gracefully: {e}")
            finally:
                self.telnet = None

    def close_telnet_force(self):
        if self.telnet:
            try:
                self.telnet.close()
                logging.info("Telnet session force-closed.")
            except Exception as e:
                logging.debug(f"Error force-closing telnet: {e}")
            finally:
                self.telnet = None

    # ------------------------------------------------------------------
    # DB helper
    # ------------------------------------------------------------------

    def get_part_description(self, part_number: str) -> str:
        return self.db_cache.lookup_part(part_number)

    # ------------------------------------------------------------------
    # Output parsers
    # ------------------------------------------------------------------

    def extract_shelf_detail(
        self,
        output: str,
        cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
        ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse 'show shelf' — extract system name, PEC, shelf type, and serial number."""
        system_data = []
        try:
            output = output.strip()
            name_match = re.search(r"name\s*[:\s]+(\S+)", output, re.IGNORECASE)
            pec_match = re.search(r"pec\s*[:\s]+(\S+)", output, re.IGNORECASE)
            ctype_match = re.search(r"c-type\s*[:\s]+(\S+)", output, re.IGNORECASE)
            serial_match = re.search(r"serial-number\s*[:\s]+(\S+)", output, re.IGNORECASE)
            shelf_type_match = re.search(r"shelf-type\s*[:\s]+(\S+)", output, re.IGNORECASE)

            system_name = name_match.group(1).strip() if name_match else 'Unknown'
            pec = pec_match.group(1).strip() if pec_match else ''
            system_type = ctype_match.group(1).strip() if ctype_match else 'Unknown'
            serial_number = serial_match.group(1).strip() if serial_match else ''
            shelf_type = shelf_type_match.group(1).strip() if shelf_type_match else system_type

            system_data.append({
                'System Name': system_name,
                'System Type': system_type,
                'Type': 'Shelf',
                'Part Number': pec,
                'Serial Number': serial_number,
                'Description': shelf_type,
                'Name': system_name,
                'Source': ip or 'Unknown',
            })
            logging.info(f"Extracted shelf detail — Name: {system_name}, Type: {system_type}")
        except Exception as e:
            logging.error(f"Error in extract_shelf_detail: {e}")
            system_data.append({
                'System Name': 'Error', 'System Type': 'Error', 'Type': 'Error',
                'Part Number': 'Error', 'Serial Number': 'Error',
                'Description': 'Error', 'Name': 'Error', 'Source': ip or 'Unknown',
            })

        df = pd.DataFrame(system_data)
        if cache_callback:
            cache_callback(df, 'shelf_detail')
        print(df.to_string(index=False))
        return df

    def extract_shelf_inventory(
        self,
        output: str,
        cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
        ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse 'show slots * inventory' — slot-level hardware summary.
        Expected columns: slot  pec  serial-number  manufacturing-date  hardware-release
        """
        shelf_data = []
        try:
            output = output.strip()
            # Match: slot identifier, pec, serial-number from key: value style blocks
            # Block starts with "slot X:" or "slot X/Y:"
            slot_blocks = re.split(r'(?=\bslot\s+\S+\s*[:/])', output, flags=re.IGNORECASE)
            for block in slot_blocks:
                if not block.strip():
                    continue
                slot_match = re.match(r'slot\s+(\S+)', block, re.IGNORECASE)
                if not slot_match:
                    continue
                slot_id = slot_match.group(1).rstrip(':').strip()
                pec_match = re.search(r'pec\s*[:\s]+(\S+)', block, re.IGNORECASE)
                serial_match = re.search(r'serial-number\s*[:\s]+(\S+)', block, re.IGNORECASE)
                hw_match = re.search(r'hardware-release\s*[:\s]+(\S+)', block, re.IGNORECASE)
                mfg_match = re.search(r'manufacturing-date\s*[:\s]+(\S+)', block, re.IGNORECASE)

                pec = pec_match.group(1).strip() if pec_match else ''
                serial_number = serial_match.group(1).strip() if serial_match else ''
                hw_release = hw_match.group(1).strip() if hw_match else ''
                mfg_date = mfg_match.group(1).strip() if mfg_match else ''

                if not pec and not serial_number:
                    continue

                description = self.db_cache.lookup_part(pec) if pec else ''
                shelf_data.append({
                    'System Name': '',
                    'System Type': hw_release,
                    'Type': 'Slot',
                    'Part Number': pec[:10] if pec else '',
                    'Serial Number': serial_number,
                    'Description': description or mfg_date,
                    'Name': f"Slot {slot_id}",
                    'Source': ip or 'Unknown',
                })

            # Fallback: try tabular format  SLOT  PEC  SERIAL
            if not shelf_data:
                pattern = re.compile(
                    r"^\s*(\d+(?:/\S*)?)\s+(\S+)\s+(\S+)(?:\s+(\S+))?",
                    re.MULTILINE,
                )
                for match in pattern.finditer(output):
                    try:
                        slot_id = match.group(1).strip()
                        pec = match.group(2).strip()
                        serial_number = match.group(3).strip()
                        hw_release = match.group(4).strip() if match.group(4) else ''
                        if pec.upper() in ('SLOT', 'PEC', 'SERIAL', 'NAME'):
                            continue
                        description = self.db_cache.lookup_part(pec)
                        shelf_data.append({
                            'System Name': '',
                            'System Type': hw_release,
                            'Type': 'Slot',
                            'Part Number': pec[:10],
                            'Serial Number': serial_number,
                            'Description': description,
                            'Name': f"Slot {slot_id}",
                            'Source': ip or 'Unknown',
                        })
                    except Exception as me:
                        logging.error(f"Error processing shelf inventory row: {me}")

            if not shelf_data:
                logging.warning("No shelf inventory data found.")
        except Exception as e:
            logging.error(f"Error in extract_shelf_inventory: {e}")

        df = pd.DataFrame(shelf_data)
        if cache_callback:
            cache_callback(df, 'shelf_inventory')
        print(df.to_string(index=False))
        return df

    def extract_card_inventory(
        self,
        output: str,
        cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
        ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse 'show slots * inventory circuit-pack' — circuit pack PEC, serial number,
        hardware release, manufacturing date, power draw and temperature.
        """
        card_data = []
        try:
            output = output.replace("Press any key to continue (Q to quit)", "").strip()
            # Split into per-slot blocks
            slot_blocks = re.split(r'(?=\bslot\s+\S+\s*[:/])', output, flags=re.IGNORECASE)
            for block in slot_blocks:
                if not block.strip():
                    continue
                slot_match = re.match(r'slot\s+(\S+)', block, re.IGNORECASE)
                if not slot_match:
                    continue
                slot_id = slot_match.group(1).rstrip(':').strip()
                pec_match = re.search(r'pec\s*[:\s]+(\S+)', block, re.IGNORECASE)
                serial_match = re.search(r'serial-number\s*[:\s]+(\S+)', block, re.IGNORECASE)
                hw_match = re.search(r'hardware-release\s*[:\s]+(\S+)', block, re.IGNORECASE)
                mfg_match = re.search(r'manufacturing-date\s*[:\s]+(\S+)', block, re.IGNORECASE)
                power_match = re.search(r'power\s*[:\s]+(\S+)', block, re.IGNORECASE)
                temp_match = re.search(r'current-temperature\s*[:\s]+(\S+)', block, re.IGNORECASE)

                pec = pec_match.group(1).strip() if pec_match else ''
                serial_number = serial_match.group(1).strip() if serial_match else ''
                hw_release = hw_match.group(1).strip() if hw_match else ''
                mfg_date = mfg_match.group(1).strip() if mfg_match else ''
                power = power_match.group(1).strip() if power_match else ''
                temperature = temp_match.group(1).strip() if temp_match else ''

                if not pec and not serial_number:
                    continue

                description = self.db_cache.lookup_part(pec) if pec else ''
                extras = " | ".join(filter(None, [
                    f"HW: {hw_release}" if hw_release else '',
                    f"Mfg: {mfg_date}" if mfg_date else '',
                    f"Pwr: {power}W" if power else '',
                    f"Temp: {temperature}C" if temperature else '',
                ]))
                card_data.append({
                    'System Name': '',
                    'System Type': '',
                    'Type': 'Circuit Pack',
                    'Part Number': pec[:10] if pec else '',
                    'Serial Number': serial_number,
                    'Description': description or extras,
                    'Name': f"Slot {slot_id}",
                    'Source': ip or 'Unknown',
                })

            # Fallback: tabular  SLOT  PEC  HW-REL  SERIAL
            if not card_data:
                pattern = re.compile(
                    r"^\s*(\d+(?:/\S*)?)\s+(\S+)\s+(\S+)\s+(\S+)",
                    re.MULTILINE,
                )
                for match in pattern.finditer(output):
                    try:
                        slot_id = match.group(1).strip()
                        pec = match.group(2).strip()
                        hw_release = match.group(3).strip()
                        serial_number = match.group(4).strip()
                        if pec.upper() in ('SLOT', 'PEC', 'HW', 'SERIAL', 'NAME'):
                            continue
                        description = self.db_cache.lookup_part(pec)
                        card_data.append({
                            'System Name': '',
                            'System Type': '',
                            'Type': 'Circuit Pack',
                            'Part Number': pec[:10],
                            'Serial Number': serial_number,
                            'Description': description,
                            'Name': f"Slot {slot_id}",
                            'Source': ip or 'Unknown',
                        })
                    except Exception as me:
                        logging.error(f"Error processing card inventory row: {me}")

            if not card_data:
                logging.warning("No card inventory data found.")
        except Exception as e:
            logging.error(f"Error in extract_card_inventory: {e}")

        df = pd.DataFrame(card_data)
        if cache_callback:
            cache_callback(df, 'card_inventory')
        print(df.to_string(index=False))
        return df

    def extract_module_inventory(
        self,
        output: str,
        cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
        ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse 'show slots * inventory slots *' — pluggable / sub-slot / OSC inventory."""
        module_data = []
        try:
            output = output.strip()
            # Split into per-slot blocks (may be nested slot X/Y)
            slot_blocks = re.split(r'(?=\bslot\s+\S+\s*[:/])', output, flags=re.IGNORECASE)
            for block in slot_blocks:
                if not block.strip():
                    continue
                slot_match = re.match(r'slot\s+(\S+)', block, re.IGNORECASE)
                if not slot_match:
                    continue
                slot_id = slot_match.group(1).rstrip(':').strip()
                pec_match = re.search(r'pec\s*[:\s]+(\S+)', block, re.IGNORECASE)
                serial_match = re.search(r'serial-number\s*[:\s]+(\S+)', block, re.IGNORECASE)
                hw_match = re.search(r'hardware-release\s*[:\s]+(\S+)', block, re.IGNORECASE)
                type_match = re.search(r'c-type\s*[:\s]+(\S+)', block, re.IGNORECASE)

                pec = pec_match.group(1).strip() if pec_match else ''
                serial_number = serial_match.group(1).strip() if serial_match else ''
                hw_release = hw_match.group(1).strip() if hw_match else ''
                module_type = type_match.group(1).strip() if type_match else 'Module'

                if not pec and not serial_number:
                    continue

                description = self.db_cache.lookup_part(pec) if pec else ''
                module_data.append({
                    'System Name': '',
                    'System Type': '',
                    'Type': module_type.title(),
                    'Part Number': pec[:10] if pec else '',
                    'Serial Number': serial_number,
                    'Description': description,
                    'Name': f"Module {slot_id}",
                    'Source': ip or 'Unknown',
                })

            # Fallback: tabular  SLOT  PEC  SERIAL
            if not module_data:
                pattern = re.compile(
                    r"^\s*(\d+/\S+)\s+(\S+)\s+(\S+)\s*$",
                    re.MULTILINE,
                )
                for match in pattern.finditer(output):
                    try:
                        slot_id = match.group(1).strip()
                        pec = match.group(2).strip()
                        serial_number = match.group(3).strip()
                        description = self.db_cache.lookup_part(pec)
                        module_data.append({
                            'System Name': '',
                            'System Type': '',
                            'Type': 'Module',
                            'Part Number': pec[:10],
                            'Serial Number': serial_number,
                            'Description': description,
                            'Name': f"Module {slot_id}",
                            'Source': ip or 'Unknown',
                        })
                    except Exception as me:
                        logging.error(f"Error processing module inventory row: {me}")

            if not module_data:
                logging.warning("No module inventory data found.")
        except Exception as e:
            logging.error(f"Error in extract_module_inventory: {e}")

        df = pd.DataFrame(module_data)
        if cache_callback:
            cache_callback(df, 'module_inventory')
        print(df.to_string(index=False))
        return df

    def extract_software_info(
        self,
        output: str,
        cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
        ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse 'show software' — active, committed, and running release versions."""
        sw_data = []
        try:
            output = output.strip()
            active_match = re.search(r"active-version\s*[:\s]+(\S+)", output, re.IGNORECASE)
            committed_match = re.search(r"committed-version\s*[:\s]+(\S+)", output, re.IGNORECASE)
            running_match = re.search(r"running-version\s*[:\s]+(\S+)", output, re.IGNORECASE)
            state_match = re.search(r"upgrade-operational-state\s*[:\s]+(\S+)", output, re.IGNORECASE)

            active = active_match.group(1).strip() if active_match else 'Unknown'
            committed = committed_match.group(1).strip() if committed_match else 'Unknown'
            running = running_match.group(1).strip() if running_match else active
            op_state = state_match.group(1).strip() if state_match else 'Unknown'

            sw_data.append({
                'System Name': '',
                'System Type': '',
                'Type': 'Software',
                'Part Number': active,
                'Serial Number': '',
                'Description': f"Running: {running} | Committed: {committed} | State: {op_state}",
                'Name': 'SW Release',
                'Source': ip or 'Unknown',
            })
            logging.info(f"Software release: active={active}, committed={committed}")
        except Exception as e:
            logging.error(f"Error in extract_software_info: {e}")

        df = pd.DataFrame(sw_data)
        if cache_callback:
            cache_callback(df, 'software_info')
        print(df.to_string(index=False))
        return df

    def extract_slot_info(
        self,
        output: str,
        cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
        ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse 'show slots *' — slot occupancy, provisioning, and form-factor state."""
        slot_data = []
        try:
            output = output.strip()
            # Split into per-slot blocks
            slot_blocks = re.split(r'(?=\bslot\s+\S+\s*[:/])', output, flags=re.IGNORECASE)
            for block in slot_blocks:
                if not block.strip():
                    continue
                slot_match = re.match(r'slot\s+(\S+)', block, re.IGNORECASE)
                if not slot_match:
                    continue
                slot_id = slot_match.group(1).rstrip(':').strip()

                present_match = re.search(r'card-present\s*[:\s]+(\S+)', block, re.IGNORECASE)
                occupied_match = re.search(r'slot-occupied\s*[:\s]+(\S+)', block, re.IGNORECASE)
                provisioned_match = re.search(r'card-provisioned\s*[:\s]+(\S+)', block, re.IGNORECASE)
                auto_prov_match = re.search(r'auto-provisioning\s*[:\s]+(\S+)', block, re.IGNORECASE)
                form_factor_match = re.search(r'form-factor\s*[:\s]+(\S+)', block, re.IGNORECASE)
                parent_match = re.search(r'parent\s*[:\s]+(\S+)', block, re.IGNORECASE)

                card_present = present_match.group(1).strip() if present_match else 'Unknown'
                slot_occupied = occupied_match.group(1).strip() if occupied_match else 'Unknown'
                card_provisioned = provisioned_match.group(1).strip() if provisioned_match else 'Unknown'
                auto_prov = auto_prov_match.group(1).strip() if auto_prov_match else ''
                form_factor = form_factor_match.group(1).strip() if form_factor_match else ''
                parent = parent_match.group(1).strip() if parent_match else ''

                extras = " | ".join(filter(None, [
                    f"Auto-Prov: {auto_prov}" if auto_prov else '',
                    f"Form: {form_factor}" if form_factor else '',
                    f"Parent: {parent}" if parent else '',
                ]))

                slot_data.append({
                    'System Name': '',
                    'System Type': '',
                    'Type': 'Slot',
                    'Part Number': card_provisioned,
                    'Present Type': card_present,
                    'Serial Number': '',
                    'Description': (
                        f"Present: {card_present} | Occupied: {slot_occupied}"
                        + (f" | {extras}" if extras else '')
                    ),
                    'Name': f"Slot {slot_id}",
                    'Source': ip or 'Unknown',
                })

            # Fallback: tabular format
            if not slot_data:
                for raw_line in output.splitlines():
                    line = raw_line.strip()
                    if not line or not re.match(r"^\d+(?:/\S*)?\s+", line):
                        continue
                    tokens = line.split()
                    if len(tokens) < 3:
                        continue
                    try:
                        slot_id = tokens[0].strip()
                        card_present = tokens[1].strip()
                        slot_occupied = tokens[2].strip()
                        card_provisioned = tokens[3].strip() if len(tokens) > 3 else ''
                        slot_data.append({
                            'System Name': '',
                            'System Type': '',
                            'Type': 'Slot',
                            'Part Number': card_provisioned,
                            'Present Type': card_present,
                            'Serial Number': '',
                            'Description': f"Present: {card_present} | Occupied: {slot_occupied}",
                            'Name': f"Slot {slot_id}",
                            'Source': ip or 'Unknown',
                        })
                    except Exception as me:
                        logging.error(f"Error processing slot row: {me}")

            if not slot_data:
                logging.warning("No slot data found.")
        except Exception as e:
            logging.error(f"Error in extract_slot_info: {e}")

        df = pd.DataFrame(slot_data)
        if cache_callback:
            cache_callback(df, 'slot_info')
        print(df.to_string(index=False))
        return df

    def extract_redundancy_info(
        self,
        output: str,
        cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
        ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse 'show aps' — APS line protection switch state."""
        redun_data = []
        try:
            output = output.strip()
            # Each APS group may have: group-id, working-entity, protection-entity, switch-state
            group_blocks = re.split(r'(?=\baps\s+\S+\s*[:/])', output, flags=re.IGNORECASE)
            if len(group_blocks) <= 1:
                group_blocks = [output]

            for block in group_blocks:
                if not block.strip():
                    continue
                group_match = re.search(r'aps\s+(\S+)', block, re.IGNORECASE)
                group_id = group_match.group(1).rstrip(':').strip() if group_match else 'APS'

                switch_match = re.search(r'switch-state\s*[:\s]+(\S+)', block, re.IGNORECASE)
                working_match = re.search(r'working-entity\s*[:\s]+(\S+)', block, re.IGNORECASE)
                protect_match = re.search(r'protection-entity\s*[:\s]+(\S+)', block, re.IGNORECASE)
                active_match = re.search(r'active-entity\s*[:\s]+(\S+)', block, re.IGNORECASE)

                switch_state = switch_match.group(1).strip() if switch_match else 'Unknown'
                working = working_match.group(1).strip() if working_match else 'Unknown'
                protection = protect_match.group(1).strip() if protect_match else 'Unknown'
                active = active_match.group(1).strip() if active_match else 'Unknown'

                redun_data.append({
                    'System Name': '',
                    'System Type': '',
                    'Type': 'APS',
                    'Part Number': '',
                    'Serial Number': '',
                    'Description': (
                        f"Switch: {switch_state} | Working: {working} | "
                        f"Protection: {protection} | Active: {active}"
                    ),
                    'Name': f"APS {group_id}",
                    'Source': ip or 'Unknown',
                })

            if not redun_data:
                # Minimal single-row fallback
                redun_data.append({
                    'System Name': '',
                    'System Type': '',
                    'Type': 'APS',
                    'Part Number': '',
                    'Serial Number': '',
                    'Description': output[:120].replace('\n', ' '),
                    'Name': 'APS',
                    'Source': ip or 'Unknown',
                })
        except Exception as e:
            logging.error(f"Error in extract_redundancy_info: {e}")

        df = pd.DataFrame(redun_data)
        if cache_callback:
            cache_callback(df, 'redundancy_info')
        print(df.to_string(index=False))
        return df

    def extract_power_info(
        self,
        output: str,
        cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
        ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse 'show components component power-supply state' — PSU enabled/capacity/current/voltage."""
        pf_data = []
        try:
            output = output.strip()
            # Split by component / power-supply blocks
            psu_blocks = re.split(
                r'(?=\bcomponent\s+\S+\s*[:/]|\bpower-supply\s+\S+\s*[:/])',
                output,
                flags=re.IGNORECASE,
            )
            if len(psu_blocks) <= 1:
                psu_blocks = [output]

            for block in psu_blocks:
                if not block.strip():
                    continue
                comp_match = re.search(r'(?:component|power-supply)\s+(\S+)', block, re.IGNORECASE)
                comp_id = comp_match.group(1).rstrip(':').strip() if comp_match else 'PSU'

                enabled_match = re.search(r'enabled\s*[:\s]+(true|false|\S+)', block, re.IGNORECASE)
                capacity_match = re.search(r'capacity\s*[:\s]+(\S+)', block, re.IGNORECASE)
                in_curr_match = re.search(r'input-current\s*[:\s]+(\S+)', block, re.IGNORECASE)
                in_volt_match = re.search(r'input-voltage\s*[:\s]+(\S+)', block, re.IGNORECASE)
                out_curr_match = re.search(r'output-current\s*[:\s]+(\S+)', block, re.IGNORECASE)
                out_volt_match = re.search(r'output-voltage\s*[:\s]+(\S+)', block, re.IGNORECASE)
                out_pwr_match = re.search(r'output-power\s*[:\s]+(\S+)', block, re.IGNORECASE)

                enabled = enabled_match.group(1).strip() if enabled_match else 'Unknown'
                capacity = capacity_match.group(1).strip() if capacity_match else ''
                in_curr = in_curr_match.group(1).strip() if in_curr_match else ''
                in_volt = in_volt_match.group(1).strip() if in_volt_match else ''
                out_curr = out_curr_match.group(1).strip() if out_curr_match else ''
                out_volt = out_volt_match.group(1).strip() if out_volt_match else ''
                out_pwr = out_pwr_match.group(1).strip() if out_pwr_match else ''

                if enabled == 'Unknown' and not capacity and not in_volt:
                    continue

                pf_data.append({
                    'System Name': '',
                    'System Type': '',
                    'Type': 'Power Supply',
                    'Part Number': '',
                    'Serial Number': '',
                    'Description': " | ".join(filter(None, [
                        f"Enabled: {enabled}",
                        f"Cap: {capacity}W" if capacity else '',
                        f"In: {in_volt}V/{in_curr}A" if in_volt or in_curr else '',
                        f"Out: {out_volt}V/{out_curr}A/{out_pwr}W" if out_volt or out_pwr else '',
                    ])),
                    'Name': f"PSU {comp_id}",
                    'Source': ip or 'Unknown',
                })

            if not pf_data:
                logging.warning("No power supply data found.")
        except Exception as e:
            logging.error(f"Error in extract_power_info: {e}")

        df = pd.DataFrame(pf_data)
        if cache_callback:
            cache_callback(df, 'power_info')
        print(df.to_string(index=False))
        return df

    def extract_topology(
        self,
        output: str,
        cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
        ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse 'show lldp interfaces' — LLDP neighbor / port connectivity."""
        topo_data = []
        try:
            output = output.strip()
            # Split into per-interface blocks
            iface_blocks = re.split(
                r'(?=\binterface\s+\S+\s*[:/]|\bport\s+\S+\s*[:/])',
                output,
                flags=re.IGNORECASE,
            )
            for block in iface_blocks:
                if not block.strip():
                    continue
                iface_match = re.search(r'(?:interface|port)\s+(\S+)', block, re.IGNORECASE)
                if not iface_match:
                    continue
                interface = iface_match.group(1).rstrip(':').strip()

                nbr_id_match = re.search(r'neighbor-id\s*[:\s]+(\S+)', block, re.IGNORECASE)
                sys_name_match = re.search(r'system-name\s*[:\s]+(\S+)', block, re.IGNORECASE)
                port_id_match = re.search(r'port-id\s*[:\s]+(\S+)', block, re.IGNORECASE)
                port_desc_match = re.search(r'port-description\s*[:\s]+(.+)', block, re.IGNORECASE)

                neighbor = nbr_id_match.group(1).strip() if nbr_id_match else ''
                sys_name = sys_name_match.group(1).strip() if sys_name_match else ''
                port_id = port_id_match.group(1).strip() if port_id_match else ''
                port_desc = port_desc_match.group(1).strip() if port_desc_match else ''

                connected_to = sys_name or neighbor or 'Unknown'
                from_port = port_id or port_desc or ''

                topo_data.append({
                    'System Name': '',
                    'System Type': '',
                    'Type': 'LLDP',
                    'Part Number': '',
                    'Serial Number': '',
                    'Description': f"Connected To: {connected_to} | Port: {from_port}",
                    'Name': f"If {interface}",
                    'Source': ip or 'Unknown',
                })

            # Fallback: tabular  INTERFACE  NEIGHBOR  PORT-ID
            if not topo_data:
                for raw_line in output.strip().splitlines():
                    line = raw_line.strip()
                    if not line or not re.match(r"^\S+/\S+", line):
                        continue
                    tokens = line.split()
                    if len(tokens) < 2:
                        continue
                    try:
                        interface = tokens[0].strip()
                        connected_to = tokens[1].strip()
                        from_port = tokens[2].strip() if len(tokens) >= 3 else ''
                        topo_data.append({
                            'System Name': '',
                            'System Type': '',
                            'Type': 'LLDP',
                            'Part Number': '',
                            'Serial Number': '',
                            'Description': f"Connected To: {connected_to} | Port: {from_port}",
                            'Name': f"If {interface}",
                            'Source': ip or 'Unknown',
                        })
                    except Exception as me:
                        logging.error(f"Error processing topology row: {me}")

            if not topo_data:
                logging.warning("No topology data found.")
        except Exception as e:
            logging.error(f"Error in extract_topology: {e}")

        df = pd.DataFrame(topo_data)
        if cache_callback:
            cache_callback(df, 'topology')
        print(df.to_string(index=False))
        return df

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def process_outputs(
        self,
        outputs_from_device: List[str],
        ip_address: str,
        outputs: Dict[str, Dict[str, Dict]],
    ) -> None:
        if not outputs_from_device:
            logging.warning(f"No outputs received from {ip_address}. Skipping.")
            return

        processing_functions = [
            lambda out, cb: self.extract_shelf_detail(out, cb, ip_address),
            lambda out, cb: self.extract_shelf_inventory(out, cb, ip_address),
            lambda out, cb: self.extract_card_inventory(out, cb, ip_address),
            lambda out, cb: self.extract_module_inventory(out, cb, ip_address),
            lambda out, cb: self.extract_software_info(out, cb, ip_address),
            lambda out, cb: self.extract_slot_info(out, cb, ip_address),
            lambda out, cb: self.extract_redundancy_info(out, cb, ip_address),
            lambda out, cb: self.extract_power_info(out, cb, ip_address),
            lambda out, cb: self.extract_topology(out, cb, ip_address),
        ]

        system_info = {'System Name': '', 'System Type': ''}

        if len(outputs_from_device) != len(processing_functions):
            logging.warning(
                f"Output/function count mismatch for {ip_address}: "
                f"expected {len(processing_functions)}, got {len(outputs_from_device)}."
            )

        for idx, (command_output, fn) in enumerate(zip(outputs_from_device, processing_functions)):
            if not command_output:
                logging.warning(f"Command output {idx} for {ip_address} is empty. Skipping.")
                continue
            try:
                fn(
                    command_output,
                    lambda df, key: self.cache_data_frame(outputs, ip_address, key, df, system_info),
                )
            except Exception as e:
                logging.error(f"Error processing output {idx} for {ip_address}: {e}", exc_info=True)

        logging.info(f"All outputs processed for {ip_address}.")

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def is_valid_output(self, output: str, command: str) -> bool:
        try:
            if not output or not output.strip():
                logging.warning(f"Empty output for command: {command}")
                return False

            if command.startswith("show shelf"):
                return bool(re.search(r"name\s*[:\s]+\S+", output, re.IGNORECASE))

            if "inventory circuit-pack" in command:
                return bool(re.search(r"pec\s*[:\s]+\S+", output, re.IGNORECASE))

            if "inventory slots" in command:
                return bool(re.search(r"pec\s*[:\s]+\S+|serial-number\s*[:\s]+\S+", output, re.IGNORECASE))

            if command.startswith("show slots") and "inventory" in command:
                return bool(re.search(r"slot\s+\S+", output, re.IGNORECASE))

            if command.startswith("show software"):
                return bool(re.search(r"active-version\s*[:\s]+\S+", output, re.IGNORECASE))

            if command.startswith("show slots"):
                return bool(re.search(r"slot\s+\S+", output, re.IGNORECASE))

            if command.startswith("show aps"):
                return bool(re.search(r"switch-state|aps\s+\S+", output, re.IGNORECASE))

            if command.startswith("show components"):
                return bool(re.search(r"enabled\s*[:\s]+\S+|capacity\s*[:\s]+\S+", output, re.IGNORECASE))

            if command.startswith("show lldp"):
                return bool(re.search(r"interface\s+\S+|neighbor-id", output, re.IGNORECASE))

            return len(output.strip()) > 10

        except Exception as e:
            logging.error(f"Error validating output for '{command}': {e}", exc_info=True)
            return False

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def cache_data_frame(
        self,
        outputs: Dict[str, Dict[str, Dict]],
        ip: str,
        key: str,
        df: pd.DataFrame,
        system_info: Dict[str, str],
    ) -> bool:
        try:
            if ip not in outputs:
                outputs[ip] = {}
            outputs[ip][key] = {'DataFrame': df, 'System Info': system_info}
            logging.info(f"Cached DataFrame for {ip} / {key}.")
            return True
        except Exception as e:
            logging.error(f"Failed to cache data for {ip} / {key}: {e}")
            return False

    def combine_and_format_data(self, ip_data: Dict[str, Dict]) -> pd.DataFrame:
        all_data = []
        for key, data in ip_data.items():
            df = data['DataFrame']
            if isinstance(df, pd.DataFrame) and not df.empty:
                all_data.append(df)
                logging.info(f"Combining key '{key}' with {len(df)} rows.")

        if all_data:
            combined_df = pd.concat(all_data, ignore_index=True)
            logging.info(f"Combined DataFrame: {len(combined_df)} rows from {len(all_data)} sources.")
        else:
            combined_df = pd.DataFrame()
            logging.warning("No data to combine.")

        return combined_df

    def print_cached_data(self, outputs: Dict[str, Dict[str, Dict]]) -> None:
        try:
            if not outputs:
                print("No cached data to display.")
                return
            print("\n--- All Cached DataFrames ---")
            for ip, ip_data in outputs.items():
                print(f"\nIP Address: {ip}")
                for key, data in ip_data.items():
                    print(f"  Key: {key}")
                    print(data['DataFrame'].to_string())
        except Exception as e:
            logging.error(f"Failed to print cached data: {e}")
