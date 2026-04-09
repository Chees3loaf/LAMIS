import os
import re
import time
import logging
import pandas as pd
import telnetlib
import paramiko
from typing import List, Dict
from script_interface import BaseScript, get_cache, get_tracker

logging.basicConfig(level=logging.INFO)

class CienaTDS(BaseScript):
    def __init__(self, *, ip_address: str, username: str = "admin", password: str = "admin",
                 connection_type: str = "telnet", port: int = 23, timeout: int = 120,
                 db_cache=None, command_tracker=None):
        
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.connection_type = connection_type.lower()
        self.port = port
        self.timeout = timeout

        self.db_cache = db_cache or get_cache()
        self.command_tracker = command_tracker or get_tracker()

        self.telnet = None
        self.ssh = None
        self.chan = None
        self.is_cpl = False
        self.tid = "UNKNOWN_TID"

    def get_commands(self) -> List[str]:
        """Complete set of TL1 commands based on original TDS_v5.1"""
        return [
            'RTRV-SHELF::ALL:QSHELF;',
            'RTRV-NETYPE:::QTYPE;',
            'RTRV-CLLI:::QCLLI;',
            'RTRV-SYS::ALL:QSYS;',
            'RTRV-EQPT::ALL:QEQUIP;',
            'RTRV-AUTOEQUIP::ALL:QAUTO;',
            'RTRV-EQPTMODE::ALL:QMODE;',
            'RTRV-INVENTORY::ALL:QINV;',
            'RTRV-INVENTORY-FAN::ALL:QFAN;',
            'RTRV-INVENTORY-IO::ALL:QIO;',
            'RTRV-OTS::ALL:QOTS;',
            'RTRV-AMP::ALL:AMPALL;',
            'RTRV-RAMAN::ALL:QRAMAN;',
            'RTRV-VOA::ALL:QVOA;',
            'RTRV-OPTMON::ALL:QOPT;',
            'RTRV-OSRP::ALL:QOSRP;',
            'RTRV-SNC::ALL:SNCEE;',
            'RTRV-SNCG::ALL:QSNCG;',
            'RTRV-DTL::ALL:QDTLA;',
            'RTRV-ALM-ALL:::QALM1;',
            'RTRV-SECU-USER::ALL:QSECU;',
            'RTRV-IP:::QIP;',
            'RTRV-SNMP:::QSNMP;',
            'RTRV-TELEMETRY::ALL:QTELE;',
            'RTRV-OTDRCFG::ALL:QOCFG;',
            'RTRV-OTDR-EVENTS::ALL:QTEVE:::TRACETAG=BSLN,TRACETYPE=LONG;',
        ]

    # ====================== CONNECTION ======================
    def login(self) -> bool:
        if self.connection_type == "ssh":
            return self._login_ssh()
        return self._login_telnet()

    def _login_telnet(self) -> bool:
        try:
            self.telnet = telnetlib.Telnet(self.ip_address, self.port, self.timeout)
            self.telnet.read_until(b"parameter/keyword", self.timeout)
            cmd = f'ACT-USER::"{self.username}":LOG::"{self.password}":;\n'
            self.telnet.write(cmd.encode())
            resp = self.telnet.read_until(b";", self.timeout).decode(errors='ignore')
            if "LOG DENY" in resp or "M  DENY" in resp:
                logging.error("Telnet login denied")
                return False
            self.telnet.write(b'INH-MSG-ALL::ALL:Q0;\n')
            self.telnet.read_until(b";", self.timeout)
            logging.info("Telnet login successful")
            return True
        except Exception as e:
            logging.error(f"Telnet login failed: {e}")
            return False

    def _login_ssh(self) -> bool:
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(self.ip_address, self.port, self.username, self.password, timeout=15)
            self.chan = self.ssh.invoke_shell()
            time.sleep(1.5)
            logging.info("SSH login successful")
            return True
        except Exception as e:
            logging.error(f"SSH login failed: {e}")
            return False

    def send_tl1(self, command: str) -> str:
        try:
            if self.connection_type == "telnet" and self.telnet:
                self.telnet.write((command + "\n").encode())
                return self.telnet.read_until(b";", self.timeout).decode(errors='ignore')
            elif self.connection_type == "ssh" and self.chan:
                self.chan.send(command + "\n")
                time.sleep(2)
                resp = ""
                while self.chan.recv_ready():
                    resp += self.chan.recv(8192).decode(errors='ignore')
                return resp
            return ""
        except Exception as e:
            logging.error(f"TL1 command failed: {e}")
            return ""

    # ====================== HELPERS ======================
    def parse_shelf_and_tid(self, output: str):
        for line in output.splitlines():
            if re.search(r'\d{2}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line):
                self.tid = line.strip().split()[0].strip('"')
            if "Common Photonic" in line or "CPL" in line.upper():
                self.is_cpl = True

    def _extract_shelf(self, aid: str) -> str:
        try:
            if '-' in aid:
                parts = aid.split('-')
                if len(parts) > 1:
                    return f"SHELF-{parts[1]}"
            return "SHELF-0"
        except:
            return "Unknown"

    def _extract_ots_members(self, rest: str) -> str:
        try:
            members = []
            for pattern in ['OSC=', 'LIM=', 'LINEOUT=', 'SMD=', 'DSCM=']:
                if pattern in rest:
                    idx = rest.find(pattern)
                    end = rest.find(',', idx)
                    if end == -1:
                        end = len(rest)
                    member = rest[idx:end].strip()
                    members.append(member)
            return '+'.join(members) if members else 'NONE'
        except:
            return 'NONE'

    def _fish(self, line: str, start: str, end: str = ',') -> str:
        try:
            if start:
                idx = line.find(start)
                if idx == -1:
                    return ''
                idx += len(start)
            else:
                idx = 0

            if end:
                end_idx = line.find(end, idx)
                if end_idx == -1:
                    end_idx = len(line)
                value = line[idx:end_idx]
            else:
                value = line[idx:]

            return value.strip().strip('"').strip()
        except:
            return ''

    # ====================== PARSERS ======================
    def parse_equipment(self, output: str) -> pd.DataFrame:
        data = []
        lines = output.splitlines()
        for line in lines:
            if '::' not in line or line.startswith('   "') or 'RTRV-EQPT' in line:
                continue
            try:
                parts = line.split('::', 1)
                aid = parts[0].strip(' "')
                rest = parts[1]
                pec = self._fish(rest, 'PEC=', ',')
                ctype = self._fish(rest, 'CTYPE=\\"', '\\"').replace(',', ';')
                provpec = self._fish(rest, 'PROVPEC=', ',')
                ser = self._fish(rest, 'SER=', ',')
                clei = self._fish(rest, 'CLEI=', ',')
                row = {
                    'System Name': self.tid,
                    'System Type': 'Ciena 6500' if not self.is_cpl else 'Ciena CPL',
                    'Name': aid,
                    'Type': 'Equipment',
                    'Part Number': pec[:10] if pec else '',
                    'Serial Number': ser,
                    'Description': ctype,
                    'Provisioned PEC': provpec,
                    'CLEI': clei,
                    'Source': self.ip_address,
                    'Information Type': 'Equipment'
                }
                data.append(row)
            except:
                continue
        return pd.DataFrame(data)

    def parse_inventory(self, output: str) -> pd.DataFrame:
        data = []
        for line in output.splitlines():
            if '::' not in line or line.startswith('   "'):
                continue
            try:
                parts = line.split('::', 1)
                aid = parts[0].strip(' "')
                rest = parts[1]
                pec = self._fish(rest, 'PEC=', ',')
                ser = self._fish(rest, 'SER=', ',')
                clei = self._fish(rest, 'CLEI=', ',')
                row = {
                    'System Name': self.tid,
                    'System Type': 'Ciena 6500' if not self.is_cpl else 'Ciena CPL',
                    'Name': aid,
                    'Type': 'Inventory Item',
                    'Part Number': pec[:10] if pec else '',
                    'Serial Number': ser,
                    'CLEI': clei,
                    'Source': self.ip_address,
                    'Information Type': 'Inventory'
                }
                data.append(row)
            except:
                continue
        return pd.DataFrame(data)

    def parse_ots(self, output: str) -> pd.DataFrame:
        data = []
        lines = output.splitlines()
        for line in lines:
            if '::' not in line or line.startswith('   "') or 'RTRV-OTS' in line:
                continue
            try:
                parts = line.split('::', 1)
                aid = parts[0].strip(' "')
                rest = parts[1]
                shelf = self._extract_shelf(aid)
                cfgtype = self._fish(rest, 'CFGTYPE=', ',')
                subtype = self._fish(rest, 'SUBTYPE=', ',')
                osid = self._fish(rest, 'OSID=\\"', '\\"')
                txpath = self._fish(rest, 'TXPATH=', ',')
                rxpath = self._fish(rest, 'RXPATH=', ',')
                members = self._extract_ots_members(rest)
                row = {
                    'System Name': self.tid,
                    'System Type': 'Ciena 6500' if not self.is_cpl else 'Ciena CPL',
                    'Name': aid,
                    'Type': 'OTS',
                    'Shelf': shelf,
                    'OSID': osid,
                    'TX Path': txpath,
                    'RX Path': rxpath,
                    'OTS Members': members,
                    'Source': self.ip_address,
                    'Information Type': 'OTS'
                }
                data.append(row)
            except:
                continue
        return pd.DataFrame(data)

    def parse_amp(self, output: str) -> pd.DataFrame:
        data = []
        lines = output.splitlines()
        for line in lines:
            if '::' not in line or line.startswith('   "'):
                continue
            try:
                parts = line.split('::', 1)
                aid = parts[0].strip(' "')
                rest = parts[1]
                shelf = self._extract_shelf(aid)
                amp_type = self._fish(rest, 'AMPTYPE=', ',') or 'Unknown'
                gain = self._fish(rest, 'GAIN=', ',')
                targetpower = self._fish(rest, 'TARGPOW=', ',')
                row = {
                    'System Name': self.tid,
                    'System Type': 'Ciena 6500' if not self.is_cpl else 'Ciena CPL',
                    'Name': aid,
                    'Type': 'Amplifier',
                    'Shelf': shelf,
                    'AMP Type': amp_type,
                    'Gain (dB)': gain,
                    'Target Power (dBm)': targetpower,
                    'Source': self.ip_address,
                    'Information Type': 'Amplifier'
                }
                data.append(row)
            except:
                continue
        return pd.DataFrame(data)

    def parse_osrp(self, output: str) -> pd.DataFrame:
        data = []
        lines = output.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('   "'):
                continue
            try:
                if 'OSRPNODENAME=' in line:
                    nodename = self._fish(line, 'OSRPNODENAME=\\"', '\\"')
                    nodeid = self._fish(line, 'OSRPNODEID=', ',')
                    row = {'Type': 'OSRP Node', 'Name': nodename, 'Node ID': nodeid, 'Source': self.ip_address}
                    data.append(row)
                elif 'OSRPLINK' in line:
                    aid = self._fish(line, '', ':') if ':' in line else ''
                    label = self._fish(line, 'LABEL=\\"', '\\"')
                    row = {'Type': 'OSRP Link', 'Name': aid, 'Label': label, 'Source': self.ip_address}
                    data.append(row)
            except:
                continue
        return pd.DataFrame(data)

    def parse_alarms(self, output: str) -> pd.DataFrame:
        data = []
        for line in output.splitlines():
            if '::' not in line or line.startswith('   "'):
                continue
            try:
                parts = line.split('::', 1)
                aid = parts[0].strip(' "')
                rest = parts[1]
                condition = self._fish(rest, '', ',')
                severity = self._fish(rest, '', ',') if ',' in rest else ''
                row = {
                    'System Name': self.tid,
                    'Type': 'Alarm',
                    'Name': aid,
                    'Condition': condition,
                    'Severity': severity,
                    'Source': self.ip_address,
                    'Information Type': 'Alarm'
                }
                data.append(row)
            except:
                continue
        return pd.DataFrame(data)

    def parse_issues(self, output: str) -> pd.DataFrame:
        data = []
        for line in output.splitlines():
            if not line or line.startswith('Script Version'):
                continue
            try:
                if any(k in line for k in ['FAIL', 'Issue', 'Provisioning']):
                    parts = line.split(',', 1)
                    category = parts[0].strip()
                    desc = parts[1].strip() if len(parts) > 1 else line
                    row = {
                        'System Name': self.tid,
                        'Type': 'Issue',
                        'Name': category,
                        'Description': desc,
                        'Source': self.ip_address,
                        'Information Type': 'Issue'
                    }
                    data.append(row)
            except:
                continue
        return pd.DataFrame(data)

    def parse_raman(self, output: str) -> pd.DataFrame:
        data = []
        for line in output.splitlines():
            if '::' not in line or line.startswith('   "'):
                continue
            try:
                parts = line.split('::', 1)
                aid = parts[0].strip(' "')
                rest = parts[1]
                shelf = self._extract_shelf(aid)
                pump1 = self._fish(rest, 'PUMP1POWER=', ',')
                targetpow = self._fish(rest, 'TARGPOW=', ',')
                row = {
                    'System Name': self.tid,
                    'Type': 'Raman Amplifier',
                    'Name': aid,
                    'Shelf': shelf,
                    'Pump 1 Power': pump1,
                    'Target Power': targetpow,
                    'Source': self.ip_address,
                    'Information Type': 'Raman'
                }
                data.append(row)
            except:
                continue
        return pd.DataFrame(data)

    def parse_telemetry(self, output: str) -> pd.DataFrame:
        data = []
        for line in output.splitlines():
            if '::' not in line or line.startswith('   "'):
                continue
            try:
                parts = line.split('::', 1)
                aid = parts[0].strip(' "')
                rest = parts[1]
                fibertype = self._fish(rest, 'FIBERTYPE=', ',')
                spanloss = self._fish(rest, 'SPANLOSS=', ',')
                row = {
                    'System Name': self.tid,
                    'Type': 'Telemetry',
                    'Name': aid,
                    'Fiber Type': fibertype,
                    'Span Loss': spanloss,
                    'Source': self.ip_address,
                    'Information Type': 'Telemetry'
                }
                data.append(row)
            except:
                continue
        return pd.DataFrame(data)

    def parse_otdr(self, output: str) -> pd.DataFrame:
        data = []
        for line in output.splitlines():
            if '::' not in line or line.startswith('   "'):
                continue
            try:
                parts = line.split('::', 1)
                aid = parts[0].strip(' "')
                rest = parts[1]
                tracetag = self._fish(rest, 'TRACETAG=', ',')
                row = {
                    'System Name': self.tid,
                    'Type': 'OTDR',
                    'Name': aid,
                    'Trace Tag': tracetag,
                    'Source': self.ip_address,
                    'Information Type': 'OTDR'
                }
                data.append(row)
            except:
                continue
        return pd.DataFrame(data)

    # ====================== MAIN PROCESSING ======================
    def process_outputs(self, outputs_from_device: List[str], ip_address: str, outputs: Dict):
        if not self.login():
            logging.error(f"Failed to login to {ip_address} for TDS")
            return

        logging.info(f"Starting full TDS diagnostic for {ip_address}")

        for cmd in self.get_commands():
            resp = self.send_tl1(cmd)
            if not resp:
                continue

            if any(x in cmd for x in ["RTRV-SHELF", "RTRV-NETYPE", "RTRV-CLLI"]):
                self.parse_shelf_and_tid(resp)

            elif "RTRV-EQPT" in cmd:
                df = self.parse_equipment(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_equipment", df, {'System Name': self.tid})

            elif "RTRV-INVENTORY" in cmd:
                df = self.parse_inventory(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_inventory", df, {'System Name': self.tid})

            elif "RTRV-OTS" in cmd:
                df = self.parse_ots(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_ots", df, {'System Name': self.tid})

            elif "RTRV-AMP" in cmd:
                df = self.parse_amp(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_amp", df, {'System Name': self.tid})

            elif "RTRV-OSRP" in cmd:
                df = self.parse_osrp(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_osrp", df, {'System Name': self.tid})

            elif any(x in cmd for x in ["RTRV-ALM", "RTRV-COND"]):
                df = self.parse_alarms(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_alarms", df, {'System Name': self.tid})

            elif any(x in cmd for x in ["RTRV-SECU", "RTRV-RADIUS"]):
                df = self.parse_security(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_security", df, {'System Name': self.tid})

            elif any(x in cmd for x in ["RTRV-IP", "RTRV-OSPF", "RTRV-IISIS"]):
                df = self.parse_dcn(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_dcn", df, {'System Name': self.tid})

            elif "RTRV-SNMP" in cmd:
                df = self.parse_snmp(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_snmp", df, {'System Name': self.tid})

            elif "RTRV-RAMAN" in cmd:
                df = self.parse_raman(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_raman", df, {'System Name': self.tid})

            elif "RTRV-TELEMETRY" in cmd:
                df = self.parse_telemetry(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_telemetry", df, {'System Name': self.tid})

            elif "RTRV-OTDR" in cmd:
                df = self.parse_otdr(resp)
                if not df.empty:
                    self.cache_data_frame(outputs, ip_address, "tds_otdr", df, {'System Name': self.tid})

        self.close()
        logging.info(f"TDS diagnostic completed for {ip_address}")

    def close(self):
        if self.telnet:
            try:
                self.telnet.close()
            except:
                pass
        if self.ssh:
            try:
                self.ssh.close()
            except:
                pass