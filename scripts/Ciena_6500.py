import os
import logging
import re

import sqlite3
import time
import pandas as pd
from wexpect import spawn, EOF, TIMEOUT
from typing import Any, Callable, Dict, List, Optional, Tuple

import wexpect

db_path = os.path.join(os.path.dirname(__file__), "..", "data", "network_inventory.db")

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

class Script:
    def __init__(self, connection_type='ssh', **kwargs):
        logging.debug("Initializing Script class")
        self.connection_type = connection_type

        if connection_type == 'ssh':
            self.ip_address = kwargs.get('ip_address')
            self.username = kwargs.get('username', 'ADMIN')
            self.password = kwargs.get('password', 'ADMIN')
            self.port = kwargs.get('port', 20002)
            logging.info(f"Configured SSH connection: {self.ip_address}:{self.port} as {self.username}")

    def get_commands(self) -> List[str]:
        logging.debug("Fetching device commands to execute")
        return [
            'equipment inventory-fan show',
            'equipment inventory-io show',
            'equipment inventory show']

    def execute_commands(self, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        logging.info(f"Executing commands over {self.connection_type}")
        if self.connection_type == 'ssh':
            return self.execute_ssh_commands(self.ip_address, self.username, self.password, commands)
        raise ValueError("Unsupported connection type")

    def execute_ssh_commands(self, ip_address: str, username: str, password: str, commands: List[str]) -> Tuple[List[str], Optional[str]]:
        try:
            ssh_cmd = (
                f"ssh -o StrictHostKeyChecking=no "
                f"-o HostKeyAlgorithms=+ssh-rsa "
                f"-o PubkeyAcceptedKeyTypes=+ssh-rsa "
                f"-p {self.port} {ip_address}"
            )
            logging.info(f"Spawning SSH process to {ip_address}:{self.port}")
            child = spawn(ssh_cmd, encoding='utf-8', timeout=30)

            output_log = []

            idx = child.expect(["[Ll]ogin:", "Are you sure you want to continue connecting", EOF, TIMEOUT])
            logging.debug(f"Initial expect matched index: {idx}")
            if idx == 1:
                child.sendline("yes")
                idx = child.expect(["[Ll]ogin:", EOF, TIMEOUT])
                logging.debug(f"Expect after sending yes: {idx}")

            logging.debug("Sending login credentials")
            child.sendline(username)
            child.expect("[Pp]assword:")
            child.sendline(password)

            idx = child.expect([r"[#]", EOF, TIMEOUT])
            if idx in [1, 2]:
                logging.error("Authentication failed")
                return [], "Authentication failed"

            # Capture prompt
            prompt = child.after.strip()
            logging.debug(f"Detected prompt: '{prompt}'")

            for cmd in commands:
                logging.info(f"Sending command: {cmd}")
                child.sendline(cmd)
                child.expect(cmd)  # Echoed command
                full_output = ""

                while True:
                    index = child.expect([prompt, EOF, TIMEOUT], timeout=30)
                    chunk = child.before
                    full_output += chunk

                    if index == 0:
                        full_output += child.after
                        break
                    elif index == 1:
                        logging.warning("EOF while waiting for prompt")
                        break
                    elif index == 2:
                        logging.error("Timeout waiting for prompt")
                        break

                output_log.append(full_output.strip())

            child.sendline("exit")
            try:
                child.expect([prompt, EOF, TIMEOUT], timeout=10)
            except TIMEOUT:
                logging.warning("Timeout after 'exit', force closing")

            return output_log, None

        except Exception as e:
            logging.exception("SSH execution exception")
            return [], str(e)
            

    def get_part_description(self, part_number: str) -> str:
        try:
            logging.debug(f"Looking up part number: {part_number}")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT description FROM parts WHERE part_number = ?", (part_number,))
            result = cursor.fetchone()
            if result:
                logging.debug(f"Found description: {result[0]}")
            else:
                logging.debug("No description found")
            return result[0] if result else "Unknown"
        except Exception as e:
            logging.error(f"Database error: {e}")
            return "Error"
        finally:
            conn.close()

    def format_inventory_df(self, df: pd.DataFrame, ip: Optional[str] = None, system_info: Optional[Dict[str, str]] = None) -> List[Dict[str, str]]:
        logging.debug("Starting inventory DataFrame formatting")

        formatted = []
        source_ip = ip or "Unknown"
        system_name = system_info.get("System Name", "") if system_info else ""
        system_type = system_info.get("System Type", "") if system_info else ""

        logging.debug(f"System Info - Name: {system_name}, Type: {system_type}, Source IP: {source_ip}")
        logging.debug(f"Input DataFrame shape: {df.shape}")
        logging.debug(f"Input DataFrame columns: {df.columns.tolist()}")

        skipped = 0

        for idx, row in df.iterrows():
            slot = str(row.get("aid", "")).strip()
            card_type = str(row.get("ctype", "")).strip()
            part_number = str(row.get("pec", "")).strip()
            serial_number = str(row.get("ser", "")).strip()

            if not slot or slot.upper().startswith(("FILLER", "EMPTY", "SPARE")):
                logging.debug(f"Skipping row {idx} - Non-operational slot: '{slot}'")
                skipped += 1
                continue

            description = self.get_part_description(part_number)

            formatted_entry = {
                'System Name': system_name,
                'System Type': system_type,
                'Type': card_type.title(),
                'Part Number': part_number,
                'Serial Number': serial_number,
                'Description': description,
                'Name': slot,
                'Source': source_ip
            }

            logging.debug(f"Row {idx} formatted: {formatted_entry}")
            formatted.append(formatted_entry)

        logging.info(f"Formatted {len(formatted)} inventory items (Skipped: {skipped}) from IP {source_ip}")
        return formatted

    def process_outputs(self, raw_outputs: List[str], ip_address: str, outputs: Dict[str, Dict[str, Any]]):
        logging.info(f"Processing outputs from {ip_address}")
        system_info = {'System Name': 'Ciena 6500', 'System Type': 'Optical'}
        combined_output = "\n".join(raw_outputs)

        # ✅ Dump output to file for debugging
        debug_path = f"debug_raw_output_{ip_address.replace('.', '_')}.txt"
        with open(debug_path, 'w', encoding='utf-8') as f:
            f.write(combined_output)
        logging.debug(f"Saved raw command output to {debug_path}")

        self.extract_data_to_df(
            combined_output,
            lambda df, key: self.cache_data_frame(outputs, ip_address, key, df, system_info),
            ip=ip_address
        )

    def extract_data_to_df(self, output: str, cache_callback, ip: str) -> None:
        logging.debug("Extracting equipment data from raw output")
        records = self.extract_equipment_data(output)

        if not records:
            logging.warning(f"No equipment records extracted for IP {ip}")
            return

        df = pd.DataFrame(records)

        expected_cols = {"aid", "ctype", "pec", "ser"}
        if not expected_cols.issubset(df.columns):
            logging.warning(f"Missing expected columns in parsed data for {ip}: {df.columns.tolist()}")
            return

        df = df[["aid", "ctype", "pec", "ser"]].dropna(how='all')
        df = df[~df["aid"].str.startswith("EMPTY", na=False)].drop_duplicates()
        cache_callback(df, "equipment_inventory")

    def cache_data_frame(self, outputs: Dict[str, Dict[str, Dict]], ip: str, key: str, df: pd.DataFrame, system_info: Dict[str, str]) -> None:
        logging.info(f"Caching data for IP: {ip}, Key: {key}, Rows: {len(df)}")
        if ip not in outputs:
            outputs[ip] = {}
        outputs[ip][key] = {'DataFrame': df, 'System Info': system_info}

    @staticmethod
    def extract_equipment_data(output: str) -> List[Dict[str, Optional[str]]]:
        logging.debug("Parsing raw output into structured entries")

        cleaned_output = re.sub(r'--\s*More\s*--', '', output)
        lines = cleaned_output.splitlines()

        logging.debug(f"Cleaned Output ({len(lines)} lines):\n" + "\n".join(lines))

        records = []
        current = {}
        line_count = 0
        matched_count = 0

        for line in lines:
            line_count += 1
            match = re.match(r'(?P<key>aid|ctype|pec|ser)\s*\|\s*"(?P<value>[^"]*)"', line.strip(), re.IGNORECASE)
            if match:
                key = match.group("key").lower()
                value = match.group("value").strip()
                if key == "aid" and current.get("aid"):
                    records.append(current)
                    current = {}
                current[key] = value
                matched_count += 1
            else:
                logging.debug(f"No match on line {line_count}: {line.strip()}")

        if current.get("aid"):
            records.append(current)

        logging.info(f"Parsed {len(records)} equipment entries (matched {matched_count} fields in {line_count} lines)")
        return records

    def print_cached_data(self, outputs: Dict[str, Dict[str, Dict]]) -> None:
        for ip, sections in outputs.items():
            df = sections["equipment_inventory"]["DataFrame"]
            system_info = sections["equipment_inventory"]["System Info"]
            formatted = self.format_inventory_df(df, ip=ip, system_info=system_info)
            print("\n--- FORMATTED INVENTORY ---")
            for row in formatted:
                print(row)


# This script is designed to run as part of a larger system for network inventory management.
# It is not intended to be executed directly, but can be tested by uncommenting the main below.
# If you want to run this script directly, ensure the database path is correct and the database is set up properly.

if __name__ == "__main__":
    def main():
        ip = '172.21.113.10'
        logging.info(f"Running main routine for {ip}")
        script = Script(
            connection_type='ssh',
            ip_address=ip,
            username='ADMIN',
            password='ADMIN',
            port=20002
        )
        commands = script.get_commands()
        raw_outputs, error = script.execute_commands(commands)
        if error:
            logging.error(f"[ERROR] {error}")
            return
        outputs = {}
        script.process_outputs(raw_outputs, ip_address=ip, outputs=outputs)
        script.print_cached_data(outputs)

    main()
