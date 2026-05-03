import os
import logging
import re
import ipaddress
import time
from tkinter import messagebox
import pandas as pd
import paramiko
from openpyxl import load_workbook
from typing import Callable, Dict, List, Optional, Tuple
from script_interface import BaseScript, CommandTracker, DatabaseCache, get_inventory_db_path, get_tracker, get_cache, NEEDS_CREDENTIALS_SENTINEL
from utils.helpers import ensure_host_key_known, get_known_hosts_path
from utils.telnet import Telnet

try:
    from wexpect import spawn, EOF, TIMEOUT  # type: ignore[import-not-found]
except ImportError:
    from pexpect import spawn, EOF, TIMEOUT  # type: ignore[import-not-found]


class Script(BaseScript):
    def __init__(self, *,
                 connection_type='telnet',
                 command_tracker=None,
                 ip_address,
                 username='su',
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

    def _resolve_tid(self, output: str = "") -> str:
        """Return the device TID, preferring the prompt captured at SSH login.

        Falls back to scanning *output* for an embedded ``hostname#`` prompt
        line, which is useful for offline parsing of pre-captured logs.
        """
        cached = getattr(self, "system_tid", "")
        if cached:
            return cached
        if output:
            return self._extract_hostname(output)
        return ""

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
            'show slots * inventory circuit-pack',               # card inventory
            'show slots * inventory slots *',                    # module / pluggable inventory
            'show software',                                     # software release info
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
        """Run *commands* over an interactive paramiko SSH shell.

        Replaces the previous wexpect/pexpect approach which silently hung
        on Windows when spawning ssh.exe. Paramiko is already proven to
        work for this exact host (it's used during identification), and
        every meaningful step here logs at INFO so the operator can see
        progress in the console / log file.
        """
        try:
            try:
                ipaddress.ip_address(self.ip_address)
            except ValueError:
                return [], f"Invalid IP address format: {self.ip_address}"

            if not re.match(r'^[a-zA-Z0-9._-]+$', self.username):
                return [], f"Invalid username format: {self.username}"

            kh_path = str(get_known_hosts_path())
            logging.info(
                f"[RLS] Pre-verifying host key for {self.ip_address}:{self.port}"
            )
            if not ensure_host_key_known(str(self.ip_address), port=self.port):
                return [], (
                    f"SSH host key verification failed or rejected for "
                    f"{self.ip_address}:{self.port}"
                )

            client = paramiko.SSHClient()
            try:
                client.load_host_keys(kh_path)
            except (FileNotFoundError, IOError):
                pass
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

            logging.info(
                f"[RLS] Connecting paramiko SSH to "
                f"{self.username}@{self.ip_address}:{self.port}"
            )
            try:
                client.connect(
                    self.ip_address,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=15,
                    banner_timeout=15,
                    auth_timeout=15,
                    look_for_keys=False,
                    allow_agent=False,
                )
            except paramiko.AuthenticationException as ae:
                logging.error(f"[RLS] SSH auth failed for {self.ip_address}: {ae}")
                client.close()
                return [], NEEDS_CREDENTIALS_SENTINEL
            except Exception as ce:
                logging.exception(f"[RLS] SSH connect failed for {self.ip_address}")
                client.close()
                return [], f"SSH connect error: {ce}"

            logging.info(f"[RLS] SSH session established for {self.ip_address}")
            session = client.invoke_shell(width=200, height=10000)
            session.settimeout(30)

            # Drain login banner, then detect the actual prompt suffix so we
            # know when each command's output has finished. RLS prompts look
            # like `lrt2.bb.net.apple.com#`.
            #
            # The RLS is slow to settle after auth — it dumps a multi-line
            # banner, sometimes pauses, then prints the prompt. Wait a beat
            # for it to flush, then keep nudging with newlines (up to a few
            # times) until we actually see a `hostname#` prompt.
            time.sleep(2.0)
            login_banner = self._drain_paramiko_shell(session, idle_seconds=1.5, max_wait=8.0)
            logging.debug(f"[RLS] Login banner ({len(login_banner)} chars):\n{login_banner}")

            prompt_match = re.search(r"([A-Za-z0-9._\-]+#)\s*$", login_banner)
            for nudge in range(1, 6):
                if prompt_match:
                    break
                if self.should_stop():
                    return [], "Aborted"
                logging.info(
                    f"[RLS] No prompt yet for {self.ip_address}; "
                    f"sending newline nudge #{nudge}"
                )
                session.send("\n")
                time.sleep(1.0)
                login_banner += self._drain_paramiko_shell(
                    session, idle_seconds=1.0, max_wait=4.0
                )
                prompt_match = re.search(r"([A-Za-z0-9._\-]+#)\s*$", login_banner)
            if not prompt_match:
                logging.error(
                    f"[RLS] Could not detect shell prompt for {self.ip_address} "
                    f"after 5 nudges. Last 200 chars: {login_banner[-200:]!r}"
                )
                try: session.close()
                except Exception: pass
                client.close()
                return [], "Could not detect shell prompt"
            prompt = prompt_match.group(1)
            logging.info(f"[RLS] Detected prompt {prompt!r} for {self.ip_address}")
            tid_match = re.match(r'([A-Za-z0-9][\w.\-]*)[#>]', prompt)
            if tid_match:
                self.system_tid = tid_match.group(1)
                logging.info(f"[RLS] Captured TID {self.system_tid!r} for {self.ip_address}")

            output_log: List[str] = []
            try:
                for cmd in commands:
                    if self.should_stop():
                        return output_log, "Aborted"
                    logging.info(f"[RLS] {self.ip_address} >> {cmd}")
                    session.send(cmd + "\n")
                    cmd_out = self._read_until_prompt(session, prompt, timeout=60)
                    if cmd_out is None:
                        logging.warning(f"[RLS] Timeout waiting for prompt after '{cmd}'")
                        output_log.append("")
                        continue
                    logging.debug(f"[RLS] '{cmd}' returned {len(cmd_out)} bytes")
                    output_log.append(cmd_out.strip())
                    self.command_tracker.mark_as_executed(
                        self.ip_address, cmd, self.connection_type
                    )
            finally:
                try:
                    session.send("exit\n")
                    time.sleep(0.5)
                except Exception:
                    pass
                try: session.close()
                except Exception: pass
                try: client.close()
                except Exception: pass

            logging.info(
                f"[RLS] Completed {len(output_log)}/{len(commands)} commands for {self.ip_address}"
            )
            return output_log, None

        except Exception as e:
            logging.exception("SSH execution exception")
            return [], str(e)

    @staticmethod
    def _drain_paramiko_shell(session, idle_seconds: float = 1.0, max_wait: float = 5.0) -> str:
        """Read everything available from a paramiko shell until idle."""
        deadline = time.time() + max_wait
        last_read = time.time()
        buf = bytearray()
        while time.time() < deadline:
            if session.recv_ready():
                chunk = session.recv(65535)
                if chunk:
                    buf.extend(chunk)
                    last_read = time.time()
            else:
                if time.time() - last_read >= idle_seconds and buf:
                    break
                time.sleep(0.1)
        return buf.decode("utf-8", errors="replace")

    def _read_until_prompt(self, session, prompt: str, timeout: float = 60.0) -> Optional[str]:
        """Read from session until *prompt* appears at the end of the buffer.

        Crucially, the prompt must be the LAST non-whitespace content in the
        buffer — not just present somewhere inside it. Otherwise we'd match
        the command echo line (`lrt2.bb.net.apple.com# show aps\\n`), which
        starts with the prompt verbatim, and return before any real output
        arrives. We also enforce a small idle window after the prompt match
        so multi-page output (with `--More--`-style flushes that pause
        briefly) doesn't get truncated.
        """
        deadline = time.time() + timeout
        buf = bytearray()
        prompt_b = prompt.encode("utf-8")
        while time.time() < deadline:
            if self.should_stop():
                return None
            if session.recv_ready():
                chunk = session.recv(65535)
                if chunk:
                    buf.extend(chunk)
            else:
                # Strip CR + trailing whitespace, then check whether the
                # prompt is the last thing in the buffer. Require at least
                # one newline before it so we don't match the echoed
                # command line.
                stripped = bytes(buf).replace(b"\r", b"").rstrip()
                if stripped.endswith(prompt_b) and b"\n" in stripped:
                    # Idle settle: wait briefly to make sure the device
                    # isn't about to print more (handles re-prompting after
                    # paged output).
                    time.sleep(0.4)
                    if not session.recv_ready():
                        return buf.decode("utf-8", errors="replace")
                    # More data arrived — keep reading.
                    continue
                time.sleep(0.1)
        logging.warning(
            f"[RLS] _read_until_prompt timed out after {timeout:.0f}s "
            f"(buffer={len(buf)} bytes, tail={bytes(buf[-120:])!r})"
        )
        return None

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

    @staticmethod
    def _strip_rls_noise(output: str) -> str:
        """Drop CLI prompt lines (``hostname# ...``) and pager prompts."""
        cleaned = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                cleaned.append(line)
                continue
            if re.match(r'^\S+[#>]\s*(?:\S.*)?$', stripped):
                continue
            if "press any key to continue" in stripped.lower():
                continue
            cleaned.append(line)
        return "\n".join(cleaned)

    @staticmethod
    def _extract_hostname(output: str) -> str:
        """Pick the device hostname out of a CLI-prompt line if present."""
        m = re.search(r'^([A-Za-z0-9][\w.\-]*)[#>]\s', output, re.MULTILINE)
        return m.group(1) if m else ""

    @classmethod
    def _walk_rls_yaml(cls, output: str) -> List[Tuple[Tuple[str, ...], Dict[str, str]]]:
        """Walk YAML-style indented RLS output and yield ``(path, fields)`` per ``- name : N`` block.

        ``path`` is a tuple of slot names from outermost to innermost
        (e.g. ``('1',)`` for a top-level slot, ``('1', '50')`` for a
        nested sub-slot). ``fields`` is a dict of ``key: value`` pairs
        appearing at any indent strictly greater than the slot marker
        and before the next sibling/parent slot, attributed to the
        deepest still-open slot. First-occurrence wins so duplicates
        from nested blocks (e.g. ``admin-state`` inside ``oscs:``)
        don't clobber the slot's own value.
        """
        cleaned = cls._strip_rls_noise(output)
        stack: List[Tuple[int, str, Dict[str, str]]] = []
        results: List[Tuple[Tuple[str, ...], Dict[str, str]]] = []

        name_re = re.compile(r'^-\s*name\s*:\s*(\S+)\s*$')
        kv_re = re.compile(r'^([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*)$')

        for raw in cleaned.splitlines():
            line = raw.rstrip()
            stripped = line.lstrip()
            if not stripped:
                continue
            indent = len(line) - len(stripped)

            m_name = name_re.match(stripped)
            if m_name:
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                fields: Dict[str, str] = {}
                stack.append((indent, m_name.group(1), fields))
                path = tuple(s[1] for s in stack)
                results.append((path, fields))
                continue

            m_kv = kv_re.match(stripped)
            if m_kv and stack:
                key = m_kv.group(1).lower()
                value = m_kv.group(2).strip()
                for entry in reversed(stack):
                    if entry[0] < indent:
                        if key not in entry[2]:
                            entry[2][key] = value
                        break

        return results

    def extract_shelf_detail(
        self,
        output: str,
        cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
        ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse ``show shelf`` — system name, PEC, shelf type, serial number.

        Top-level fields live under a single ``shelf:`` block. Hostname
        is recovered from any embedded CLI prompt so ``System Name``
        matches what the operator sees on the device.
        """
        system_data = []
        try:
            hostname = self._resolve_tid(output)
            cleaned = self._strip_rls_noise(output)

            def grab(key: str) -> str:
                m = re.search(
                    rf'^\s*{re.escape(key)}\s*:\s*(.+?)\s*$',
                    cleaned,
                    re.IGNORECASE | re.MULTILINE,
                )
                return m.group(1).strip() if m else ""

            shelf_number = grab("name")
            pec = grab("pec")
            ctype = grab("c-type")
            shelf_type = grab("shelf-type") or ctype
            serial_number = grab("serial-number")
            ui_name = grab("ui-name")
            product = grab("product")

            if hostname:
                system_name = hostname
            elif ui_name:
                system_name = ui_name
            elif shelf_number:
                system_name = f"Shelf {shelf_number}"
            else:
                system_name = "Unknown"
            system_type = ui_name or shelf_type or product or "Unknown"
            slot_label = ui_name or shelf_type or (f"Shelf {shelf_number}" if shelf_number else system_name)

            system_data.append({
                'System Name': system_name,
                'System Type': system_type,
                'Type': 'Shelf',
                'Part Number': pec,
                'Serial Number': serial_number,
                'Description': ctype or shelf_type or product,
                'Name': slot_label,
                'Source': ip or 'Unknown',
            })
            logging.info(
                f"Extracted shelf detail — Name: {system_name}, "
                f"Type: {system_type}, PEC: {pec}, Serial: {serial_number}"
            )
        except Exception as e:
            logging.error(f"Error in extract_shelf_detail: {e}", exc_info=True)
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

    def extract_card_inventory(
        self,
        output: str,
        cache_callback: Optional[Callable[[pd.DataFrame, str], None]] = None,
        ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """Parse ``show slots * inventory circuit-pack`` — circuit-pack PEC,
        serial number, hardware release, manufacturing date and power.

        Only top-level slots (path length 1) are emitted; sub-slot
        pluggables come from ``extract_module_inventory`` to avoid duplicates.
        """
        card_data = []
        try:
            for path, fields in self._walk_rls_yaml(output):
                if len(path) != 1:
                    continue
                slot_id = path[0]
                pec = fields.get("pec", "")
                serial_number = fields.get("serial-number", "")
                hw_release = fields.get("hardware-release", "")
                mfg_date = fields.get("manufacturing-date", "")
                ctype = fields.get("c-type", "")
                power = fields.get("value", "")
                temperature = fields.get("current-temperature", "")
                admin_state = fields.get("admin-state", "")

                if not pec and not serial_number:
                    continue

                description = self.db_cache.lookup_part(pec) if pec else ""
                if not description:
                    description = " | ".join(filter(None, [
                        ctype,
                        f"HW {hw_release}" if hw_release else "",
                        f"Mfg {mfg_date}" if mfg_date else "",
                        f"{power}W" if power else "",
                        f"{temperature}C" if temperature else "",
                        admin_state,
                    ])) or ctype

                card_data.append({
                    'System Name': '',
                    'System Type': hw_release,
                    'Type': ctype or 'Circuit Pack',
                    'Part Number': pec,
                    'Serial Number': serial_number,
                    'Description': description,
                    'Name': f"Slot {slot_id}",
                    'Source': ip or 'Unknown',
                })

            if not card_data:
                logging.warning("No card inventory data found.")
        except Exception as e:
            logging.error(f"Error in extract_card_inventory: {e}", exc_info=True)

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
        """Parse ``show slots * inventory slots *`` — pluggable / sub-slot inventory.

        Only sub-slot rows (path length >= 2) are emitted; the parent
        slot's bare ``- name : N`` marker carries no fields here.
        """
        module_data = []
        try:
            for path, fields in self._walk_rls_yaml(output):
                if len(path) < 2:
                    continue
                slot_id = "/".join(path)
                pec = fields.get("pec", "")
                serial_number = fields.get("serial-number", "")
                hw_release = fields.get("hardware-release", "")
                ctype = fields.get("c-type", "")
                admin_state = fields.get("admin-state", "")

                if not pec and not serial_number:
                    continue

                description = self.db_cache.lookup_part(pec) if pec else ""
                if not description:
                    description = " | ".join(filter(None, [ctype, hw_release, admin_state])) or ctype

                module_data.append({
                    'System Name': '',
                    'System Type': hw_release,
                    'Type': ctype or 'Module',
                    'Part Number': pec,
                    'Serial Number': serial_number,
                    'Description': description,
                    'Name': f"Slot {slot_id}",
                    'Source': ip or 'Unknown',
                })

            if not module_data:
                logging.warning("No module inventory data found.")
        except Exception as e:
            logging.error(f"Error in extract_module_inventory: {e}", exc_info=True)

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
            lambda out, cb: self.extract_card_inventory(out, cb, ip_address),
            lambda out, cb: self.extract_module_inventory(out, cb, ip_address),
            lambda out, cb: self.extract_software_info(out, cb, ip_address),
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

            if command.startswith("show software"):
                return bool(re.search(r"active-version\s*[:\s]+\S+", output, re.IGNORECASE))

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
