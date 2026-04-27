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
            'show shelf 1',              # shelf name + type info
            'show shelf inventory *',    # shelf hardware
            'show card inventory *',     # card inventory
            'show module inventory *',   # module / transceiver inventory
            'show software dynamic',     # software release info
            'show slot *',               # slot programming state
            'show redundancy 1 detail',  # redundancy / clock switch
            'show pf *',                 # power feed status
            'show interface topology *', # port connectivity
        ]

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def execute_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        if self.connection_type == 'ssh':
            outputs, error = self.execute_ssh_commands(commands)
            if error and error != "Aborted":
                logging.warning(f"SSH failed for {self.ip_address}: {error}. Falling back to Telnet.")
                return self._execute_telnet_commands(commands)
            return outputs, error
        return self._execute_telnet_commands(commands)

    def _execute_telnet_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        outputs = []
        for command in commands:
            if self.should_stop():
                self.close_telnet()
                return outputs, "Aborted"
            if self.command_tracker.has_executed(self.ip_address, command, 'telnet'):
                logging.debug(f"Skipping previously executed command: {command}")
                continue
            output, error = self.execute_telnet_command(command)
            if error:
                logging.error(f"Error executing command '{command}': {error}")
                outputs.append(None)
            else:
                outputs.append(output)
                self.command_tracker.mark_as_executed(self.ip_address, command, 'telnet')
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
                ["Are you sure you want to continue connecting",
                 r"[Ll]ogin:", r"[Uu]sername:", r"[Pp]assword:", EOF, TIMEOUT],
                timeout=30,
            )
            if idx is None:
                self.child.close(force=True); self.child = None; return [], "Aborted"
            if idx in (4, 5):
                self.child.close(force=True); self.child = None; return [], "SSH connection failed"
            if idx == 0:  # host key warning
                self.child.sendline("yes")
                idx = self.expect_with_abort(
                    self.child,
                    [r"[Ll]ogin:", r"[Uu]sername:", r"[Pp]assword:", EOF, TIMEOUT],
                    timeout=30,
                )
                if idx is None:
                    self.child.close(force=True); self.child = None; return [], "Aborted"
                if idx in (3, 4):
                    self.child.close(force=True); self.child = None; return [], "SSH connection failed"
                idx += 1  # re-align: 0->1(login), 1->2(username), 2->3(password)

            if idx == 1:  # login: — Nokia CLI step
                self.child.sendline("cli")
                r = self.expect_with_abort(self.child, [r"[Uu]sername:", EOF, TIMEOUT], timeout=15)
                if r is None:
                    self.child.close(force=True); self.child = None; return [], "Aborted"
                if r != 0:
                    self.child.close(force=True); self.child = None; return [], "SSH login sequence failed"
                self.child.sendline(self.username)
            elif idx == 2:  # username:
                self.child.sendline(self.username)
            # idx == 3 means already at password:

            if idx != 3:
                r = self.expect_with_abort(self.child, [r"[Pp]assword:", EOF, TIMEOUT], timeout=15)
                if r is None:
                    self.child.close(force=True); self.child = None; return [], "Aborted"
                if r != 0:
                    self.child.close(force=True); self.child = None; return [], "SSH did not present password prompt"
            self.child.sendline(self.password)

            idx = self.expect_with_abort(
                self.child, [r"[#>]", "incorrect", "invalid", EOF, TIMEOUT], timeout=30
            )
            if idx is None:
                self.child.close(force=True); self.child = None; return [], "Aborted"
            if idx in (1, 2):
                self.child.close(force=True); self.child = None; return [], "Authentication failed"
            if idx in (3, 4):
                self.child.close(force=True); self.child = None; return [], "SSH session closed unexpectedly"

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
        """Parse 'show shelf 1' — extract system name and type."""
        system_data = []
        try:
            output = output.strip()
            name_match = re.search(r"Name\s*:\s*(.+)", output)
            type_match = re.search(r"Programmed Type\s*:\s*(.+)", output)

            system_name = name_match.group(1).strip() if name_match else "Unknown"
            system_type = type_match.group(1).strip() if type_match else "Unknown"

            system_data.append({
                'System Name': system_name,
                'System Type': system_type,
                'Type': 'Shelf',
                'Part Number': '',
                'Serial Number': '',
                'Description': system_type,
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
        """Parse 'show shelf inventory *'
        Expected columns: shelf_num  shelf_type  part_number  serial_number  [clei]
        """
        shelf_data = []
        try:
            output = output.strip()
            # Match: leading number, shelf type, part number, serial number
            pattern = re.compile(
                r"^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?",
                re.MULTILINE,
            )
            for match in pattern.finditer(output):
                try:
                    shelf_num = match.group(1).strip()
                    shelf_type = match.group(2).strip()
                    part_number = match.group(3).strip()
                    serial_number = match.group(4).strip()
                    clei = match.group(5).strip() if match.group(5) else ''

                    description = self.db_cache.lookup_part(part_number)
                    shelf_data.append({
                        'System Name': '',
                        'System Type': shelf_type,
                        'Type': 'Shelf',
                        'Part Number': part_number[:10],
                        'Serial Number': serial_number,
                        'Description': description,
                        'Name': f"Shelf {shelf_num}",
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
        """Parse 'show card inventory *'
        Expected columns: location  card_type  mnemonic  part_number  serial_number  clei  licensed  pmax  ir
        """
        card_data = []
        try:
            output = output.replace("Press any key to continue (Q to quit)", "").strip()
            # Match slot (e.g. 1/1 or 1/42), card_type, mnemonic, part_number, serial_number
            pattern = re.compile(
                r"^\s*(\d+/\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)",
                re.MULTILINE,
            )
            for match in pattern.finditer(output):
                try:
                    location = match.group(1).strip()
                    card_type = match.group(2).strip()
                    mnemonic = match.group(3).strip()
                    part_number = match.group(4).strip()
                    serial_number = match.group(5).strip()

                    # Skip header rows
                    if part_number.upper() in ('PART', 'NUMBER', 'TYPE'):
                        continue

                    description = self.db_cache.lookup_part(part_number)
                    card_data.append({
                        'System Name': '',
                        'System Type': '',
                        'Type': mnemonic.title(),
                        'Part Number': part_number[:10],
                        'Serial Number': serial_number,
                        'Description': description,
                        'Name': location,
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
        """Parse 'show module inventory *'
        Expected columns: location  module_type  part_number  serial_number
        """
        module_data = []
        try:
            output = output.strip()
            pattern = re.compile(
                r"^\s*(\d+/\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$",
                re.MULTILINE,
            )
            for match in pattern.finditer(output):
                try:
                    location = match.group(1).strip()
                    module_type = match.group(2).strip()
                    part_number = match.group(3).strip()
                    serial_number = match.group(4).strip()

                    description = self.db_cache.lookup_part(part_number)
                    module_data.append({
                        'System Name': '',
                        'System Type': '',
                        'Type': module_type.title(),
                        'Part Number': part_number[:10],
                        'Serial Number': serial_number,
                        'Description': description,
                        'Name': f"Module {location}",
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
        """Parse 'show software dynamic' — release and RPMS counts."""
        sw_data = []
        try:
            output = output.strip()
            release_match = re.search(r"Release\s*:\s*(\S+)", output)
            total_match = re.search(r"Total RPMS in load\s*[:\s]+(\d+)", output)
            loaded_match = re.search(r"RPMS Loaded\s*[:\s]+(\d+)", output)

            release = release_match.group(1).strip() if release_match else 'Unknown'
            total_rpms = total_match.group(1).strip() if total_match else 'Unknown'
            rpms_loaded = loaded_match.group(1).strip() if loaded_match else 'Unknown'

            sw_data.append({
                'System Name': '',
                'System Type': '',
                'Type': 'Software',
                'Part Number': release,
                'Serial Number': '',
                'Description': f"RPMS Loaded: {rpms_loaded} / {total_rpms}",
                'Name': 'SW Release',
                'Source': ip or 'Unknown',
            })
            logging.info(f"Software release: {release}, RPMS: {rpms_loaded}/{total_rpms}")
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
        """Parse 'show slot *' — slot programming and operational state."""
        slot_data = []
        try:
            state_values = {"up", "down", "empty"}
            for raw_line in output.strip().splitlines():
                line = raw_line.strip()
                if not line or not re.match(r"^\d+/\d+\s+", line):
                    continue

                tokens = line.split()
                if len(tokens) < 5:
                    continue

                admin_index = None
                for idx in range(3, len(tokens) - 1):
                    if tokens[idx].lower() in state_values and tokens[idx + 1].lower() in state_values:
                        admin_index = idx
                        break

                if admin_index is None or admin_index < 2:
                    continue

                try:
                    slot = tokens[0].strip()
                    prog_type = tokens[1].strip()
                    pres_type = " ".join(tokens[2:admin_index]).strip()
                    admin_state = tokens[admin_index].strip()
                    oper_state = tokens[admin_index + 1].strip()
                    qualifier = " ".join(tokens[admin_index + 2:]).strip()

                    slot_data.append({
                        'System Name': '',
                        'System Type': '',
                        'Type': 'Slot',
                        'Part Number': prog_type,
                        'Present Type': pres_type,
                        'Serial Number': '',
                        'Description': f"Admin: {admin_state} | Oper: {oper_state}{' | ' + qualifier if qualifier else ''}",
                        'Name': f"Slot {slot}",
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
        """Parse 'show redundancy 1 detail' — clock switch and EC selection."""
        redun_data = []
        try:
            output = output.strip()
            clock_match = re.search(r"Clock Switch\s*[:\s]+(\S+)", output)
            ec_match = re.search(r"EC Selection\s*[:\s]+(\S+)", output)

            clock_switch = clock_match.group(1).strip() if clock_match else 'Unknown'
            ec_selection = ec_match.group(1).strip() if ec_match else 'Unknown'

            redun_data.append({
                'System Name': '',
                'System Type': '',
                'Type': 'Redundancy',
                'Part Number': '',
                'Serial Number': '',
                'Description': f"Clock Switch: {clock_switch} | EC Selection: {ec_selection}",
                'Name': 'Redundancy',
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
        """Parse 'show pf *' — power feed admin/oper state."""
        pf_data = []
        try:
            output = output.strip()
            # Match: slot  Admin State  Oper State  (Up/Down)
            pattern = re.compile(
                r"^\s*(\d+/\d+)\s+\S+\s+(Up|Down)\s+(Up|Down)",
                re.MULTILINE | re.IGNORECASE,
            )
            for match in pattern.finditer(output):
                try:
                    slot = match.group(1).strip()
                    admin_state = match.group(2).strip()
                    oper_state = match.group(3).strip()

                    pf_data.append({
                        'System Name': '',
                        'System Type': '',
                        'Type': 'Power Feed',
                        'Part Number': '',
                        'Serial Number': '',
                        'Description': f"Admin: {admin_state} | Oper: {oper_state}",
                        'Name': f"PF {slot}",
                        'Source': ip or 'Unknown',
                    })
                except Exception as me:
                    logging.error(f"Error processing power feed row: {me}")

            if not pf_data:
                logging.warning("No power feed data found.")
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
        """Parse 'show interface topology *' — port connectivity."""
        topo_data = []
        try:
            for raw_line in output.strip().splitlines():
                line = raw_line.strip()
                if not line or not re.match(r"^\d+/\S+", line):
                    continue

                tokens = line.split()
                if len(tokens) < 2:
                    continue

                try:
                    interface = tokens[0].strip()
                    interface_type = tokens[1].strip()

                    if len(tokens) == 2:
                        connected_to = ''
                        type_from = ''
                    elif interface_type == '-' and len(tokens) >= 5 and tokens[2] == 'Ext':
                        connected_to = ' '.join(tokens[2:4]).strip()
                        type_from = ' '.join(tokens[4:]).strip()
                    else:
                        connected_to = tokens[2].strip() if len(tokens) >= 3 else ''
                        type_from = ' '.join(tokens[3:]).strip() if len(tokens) >= 4 else ''

                    topo_data.append({
                        'System Name': '',
                        'System Type': '',
                        'Type': interface_type,
                        'Part Number': '',
                        'Serial Number': '',
                        'Description': f"Connected To: {connected_to} | From: {type_from}",
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

            if command.startswith("show shelf 1"):
                return bool(re.search(r"Name\s*:", output))

            if command.startswith("show shelf inventory"):
                return bool(re.search(r"^\s*\d+\s+\S+\s+\S+\s+\S+", output, re.MULTILINE))

            if command.startswith("show card inventory"):
                return bool(re.search(r"^\s*\d+/\d+\s+\S+\s+\S+\s+\S+\s+\S+", output, re.MULTILINE))

            if command.startswith("show module inventory"):
                return bool(re.search(r"^\s*\d+/\S+\s+\S+\s+\S+\s+\S+", output, re.MULTILINE))

            if command.startswith("show software dynamic"):
                return bool(re.search(r"Release\s+\S+", output))

            if command.startswith("show slot"):
                return bool(re.search(r"^\s*\d+/\d+\s+\S+", output, re.MULTILINE))

            if command.startswith("show redundancy"):
                return bool(re.search(r"Clock Switch", output))

            if command.startswith("show pf"):
                return bool(re.search(r"(Up|Down)", output, re.IGNORECASE))

            if command.startswith("show interface topology"):
                return bool(re.search(r"^\s*\d+/\S+\s+\S+\s+\S+", output, re.MULTILINE))

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
