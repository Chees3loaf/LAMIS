"""RLS session driver extracted from TDS_v6.2.py.

Provides RLSSession — a self-contained class that connects to a Ciena RLS/SAOS 10
node via SSH, collects diagnostics, and produces the same CSV/XLSX artifacts as
TDS_v6.2.py in standalone mode.

No module-level side effects: no argparse, no open(), no sys.exit().
Safe to import and call directly from RLS_Network_Audit.py.
"""
from __future__ import annotations

import csv
import glob
import os
import re
import socket
import time
from datetime import datetime
from time import strftime
from typing import Optional

import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', '..'))

_paramiko = None


def _ensure_paramiko():
    global _paramiko
    if _paramiko is not None:
        return True
    try:
        import paramiko as _p
        _paramiko = _p
        return True
    except Exception as err:
        print('[tds_rls] Paramiko import failed: %s' % err)
        return False


# ---------------------------------------------------------------------------
# Pure module-level helpers (no global state)
# ---------------------------------------------------------------------------

def _recv_text(channel, nbytes: int) -> str:
    try:
        data = channel.recv(nbytes)
    except socket.timeout:
        return ''
    if isinstance(data, (bytes, bytearray)):
        return data.decode('utf-8', errors='ignore')
    return data


def _sanitize_rls_output(output: str) -> str:
    if not output:
        return ''
    output = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', output)
    output = output.replace('\r', '')
    output = output.replace('\x08 \x08', '')
    output = output.replace('--More--', '')
    return output


def _rls_prompt_seen(text: str, shell_prompt: str = '') -> bool:
    if not text:
        return False
    trimmed = text.rstrip()
    if not trimmed:
        return False
    last_line = trimmed.splitlines()[-1].strip()
    if shell_prompt and last_line.endswith(shell_prompt):
        return True
    return last_line.endswith('#') or last_line.endswith('>') or last_line.endswith('$')


def _rls_meaningful_lines(output: str, command: str = '', shell_prompt: str = '') -> list:
    lines = []
    for line in (output or '').splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if command and stripped == command.strip():
            continue
        if _rls_prompt_seen(stripped, shell_prompt):
            continue
        lines.append(stripped)
    return lines


def _classify_rls_output(output: str, command: str = '', shell_prompt: str = '') -> tuple:
    text = _sanitize_rls_output(output)
    upper_text = text.upper()
    if 'CLI SYNTAX ERROR' in upper_text or 'UNKNOWN KEYWORD' in upper_text:
        return 'WARN', 'syntax error'
    if 'COMMAND ERROR' in upper_text or 'TRACEBACK' in upper_text or 'PERMISSION DENIED' in upper_text or 'INCOMPLETE COMMAND' in upper_text:
        return 'WARN', 'command failure'
    meaningful = _rls_meaningful_lines(text, command, shell_prompt)
    if not meaningful:
        return 'WARN', 'echo only / incomplete capture'
    return 'OK', 'response captured'


def _extract_rls_slot_details(show_slots_output: str) -> list:
    slot_details = []
    seen_slots = set()
    current_slot = None
    current_form = ''

    def _append_current():
        if current_slot and current_form in ('access-panel', 'ctm', 'fan', 'power') and current_slot not in seen_slots:
            slot_details.append((current_slot, current_form))
            seen_slots.add(current_slot)

    for raw_line in (show_slots_output or '').splitlines():
        stripped = raw_line.strip()
        indent = len(raw_line) - len(raw_line.lstrip(' '))
        if indent == 2 and stripped.startswith('- name'):
            _append_current()
            match = re.search(r':\s*([0-9]+)\s*$', stripped)
            current_slot = match.group(1) if match else None
            current_form = ''
        elif current_slot and indent == 4 and stripped.startswith('form-factor'):
            current_form = stripped.split(':', 1)[1].strip().lower()
    _append_current()
    return sorted(slot_details, key=lambda item: int(item[0]))


def _extract_rls_lldp_interfaces(lldp_output: str) -> tuple:
    interfaces = []
    neighbor_map = {}
    current_iface = None
    for raw_line in (lldp_output or '').splitlines():
        stripped = raw_line.strip()
        if raw_line.startswith('      - name'):
            match = re.search(r':\s*([A-Za-z0-9_.-]+)\s*$', stripped)
            if match:
                current_iface = match.group(1)
                if current_iface not in interfaces:
                    interfaces.append(current_iface)
                if current_iface not in neighbor_map:
                    neighbor_map[current_iface] = False
        elif stripped.startswith('neighbors:') and current_iface:
            neighbor_map[current_iface] = True
    return interfaces, neighbor_map


def _read_rls_file(path: str) -> str:
    try:
        with open(path, 'r', errors='ignore') as f:
            return f.read()
    except Exception:
        return ''


def _rls_artifact_path(base_path: str) -> str:
    csv_path = base_path + '.csv'
    txt_path = base_path + '.txt'
    if os.path.exists(csv_path):
        return csv_path
    if os.path.exists(txt_path):
        return txt_path
    return csv_path


def _read_rls_artifact(base_path: str) -> str:
    path = _rls_artifact_path(base_path)
    if path.lower().endswith('.csv'):
        try:
            with open(path, 'r', newline='', errors='ignore') as f:
                rows = list(csv.reader(f))
            if rows and rows[0][:3] == ['command', 'line_number', 'output']:
                return '\n'.join([row[2] if len(row) > 2 else '' for row in rows[1:]])
        except Exception:
            pass
    return _read_rls_file(path)


def _read_rls_summary_counts(base_path: str) -> tuple:
    path = _rls_artifact_path(base_path)
    if path.lower().endswith('.csv'):
        total_ok = 0
        total_warn = 0
        try:
            with open(path, 'r', newline='', errors='ignore') as f:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) >= 6 and row[0] == 'TOTALS' and row[2] == 'OK_COUNT':
                        total_ok = _safe_int(row[5])
                    elif len(row) >= 6 and row[0] == 'TOTALS' and row[2] == 'WARN_COUNT':
                        total_warn = _safe_int(row[5])
        except Exception:
            pass
        return total_ok, total_warn
    text = _read_rls_file(path)
    ok_match = re.search(r'(?m)^OK =\s*(\d+)\s*$', text)
    warn_match = re.search(r'(?m)^WARN =\s*(\d+)\s*$', text)
    return _safe_int(ok_match.group(1) if ok_match else 0), _safe_int(warn_match.group(1) if warn_match else 0)


def _extract_rls_summary_commands(base_path: str) -> list:
    commands = []
    path = _rls_artifact_path(base_path)
    if not path.lower().endswith('.csv'):
        return commands
    try:
        with open(path, 'r', newline='', errors='ignore') as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if len(row) < 6:
                    continue
                group_name = (row[0] or '').strip()
                status = (row[1] or '').strip()
                command = (row[2] or '').strip()
                note = (row[4] or '').strip()
                if not command:
                    continue
                if group_name in ('TOTALS', 'DISCOVERED_INTERFACES', 'DISCOVERED_HARDWARE'):
                    continue
                commands.append((group_name, status, command, note))
    except Exception:
        pass
    return commands


def _extract_rls_device_command_log_entries(command_log_text: str, target_user: str = '',
                                             max_entries: int = 5000, session_gap_minutes: int = 45) -> list:
    entries = []
    target_user_norm = (target_user or '').strip().lower()

    def _parse_timestamp(value):
        if not value:
            return None
        cleaned = value.strip().replace(' ', 'T').replace('Z', '+00:00').replace(',', '.')
        if re.search(r'[+-]\d{4}$', cleaned):
            cleaned = cleaned[:-5] + cleaned[-5:-2] + ':' + cleaned[-2:]
        try:
            return datetime.fromisoformat(cleaned)
        except Exception:
            return None

    def _looks_like_session_start(text):
        text = (text or '').lower()
        return bool(re.search(r'\b(login|logged\s+in|authentication\s+ok|session\s+(started|opened)|connected)\b', text))

    def _matches_target_user(entry):
        if not target_user_norm:
            return True
        entry_user_norm = (entry[1] or '').strip().lower()
        if entry_user_norm and entry_user_norm == target_user_norm:
            return True
        raw = (entry[3] or '').lower()
        return bool(re.search(r'(?i)\b(?:user|username|login-user|principal)\s*[:=]\s*' + re.escape(target_user_norm) + r'\b', raw))

    for raw_line in (command_log_text or '').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower() == 'show command-log':
            continue
        if set(line) <= set('-=_.'):
            continue

        timestamp = ''
        user = ''
        command = ''

        ts_match = re.search(r'\b\d{4}-\d{2}-\d{2}[t\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:z|[+-]\d{2}:?\d{2})?\b', line, re.IGNORECASE)
        if ts_match:
            timestamp = ts_match.group(0)

        user_match = re.search(r'(?i)\b(?:user|username|login-user|principal)\s*[:=]\s*([^,;\s]+)', line)
        if user_match:
            user = user_match.group(1).strip()

        cmd_match = re.search(r'(?i)\b(?:command|cmd|cli|input)\s*[:=]\s*(.+)$', line)
        if cmd_match:
            command = cmd_match.group(1).strip()
        else:
            segments = re.split(r'\s{2,}|\s+-\s+', line)
            if segments:
                candidate = segments[-1].strip()
                if candidate and len(candidate) <= len(line):
                    command = candidate

        if not command:
            command = line

        if re.match(r'(?i)^\s*(start-date-time|end-date-time)\s*[:=]', command):
            continue
        if re.search(r'(?i)\b(start-date-time|end-date-time)\b\s*[:=]', line):
            continue

        entries.append((timestamp, user, command, line))
        if len(entries) >= max_entries:
            break

    if not entries:
        return entries

    first_dt = _parse_timestamp(entries[0][0])
    last_dt = _parse_timestamp(entries[-1][0])
    is_descending = bool(first_dt and last_dt and first_dt >= last_dt)

    newest_to_oldest = entries if is_descending else list(reversed(entries))
    anchor_index = 0
    for idx, item in enumerate(newest_to_oldest):
        if item[0] and _parse_timestamp(item[0]) is not None:
            anchor_index = idx
            break

    selected_newest_to_oldest = []
    last_ts = None

    for idx in range(anchor_index, len(newest_to_oldest)):
        item = newest_to_oldest[idx]
        explicit_user = (item[1] or '').strip().lower()
        item_ts = _parse_timestamp(item[0])

        if target_user_norm and explicit_user and explicit_user != target_user_norm:
            break

        if last_ts is not None and item_ts is not None:
            gap = last_ts - item_ts
            if gap.total_seconds() > session_gap_minutes * 60:
                break

        selected_newest_to_oldest.append(item)

        if idx > anchor_index and (_looks_like_session_start(item[2]) or _looks_like_session_start(item[3])) and _matches_target_user(item):
            break

        if item_ts is not None:
            last_ts = item_ts

    if not selected_newest_to_oldest:
        selected_newest_to_oldest = []
        last_ts = None
        for idx in range(anchor_index, len(newest_to_oldest)):
            item = newest_to_oldest[idx]
            item_ts = _parse_timestamp(item[0])
            if last_ts is not None and item_ts is not None:
                gap = last_ts - item_ts
                if gap.total_seconds() > session_gap_minutes * 60:
                    break
            selected_newest_to_oldest.append(item)
            if item_ts is not None:
                last_ts = item_ts

    if is_descending:
        return selected_newest_to_oldest
    return list(reversed(selected_newest_to_oldest))


def _extract_rls_field(text: str, field_name: str) -> str:
    if not text:
        return ''
    match = re.search(r'(?im)^\s*' + re.escape(field_name) + r'\s*:\s*(.*?)\s*$', text)
    if match:
        return match.group(1).strip()
    return ''


def _normalize_rls_tid_label(value: str) -> str:
    value = str(value or '').strip()
    value = re.sub(r'(_RLS)+$', '', value, flags=re.IGNORECASE)
    value = re.sub(r'[>#;$]+\s*$', '', value).strip()
    if not value:
        return ''
    if re.match(r'^[A-Za-z0-9][A-Za-z0-9_.-]*$', value):
        return value.upper()
    return value


def _extract_tid_from_prompt(prompt_text: str) -> str:
    prompt_text = _normalize_rls_tid_label(prompt_text)
    if not prompt_text:
        return ''
    candidate = prompt_text.split()[-1]
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', candidate):
        return ''
    if re.match(r'^[A-Z0-9][A-Z0-9_.-]{2,}$', candidate):
        return candidate
    return ''


def _looks_like_component_label(value: str) -> bool:
    value = _normalize_rls_tid_label(value)
    if not value:
        return False
    blocked_prefixes = (
        'SLOT-', 'SHELF-', 'OSC-', 'OTS-', 'OSID-', 'TX-', 'RX-', 'FE-',
        'ETTP-', 'OTUTTP-', 'ODUTTP-', 'CHMON-', 'NMCMON-', 'OPTMON-', 'SDMON-'
    )
    if value.startswith(blocked_prefixes):
        return True
    if re.match(r'^(SLOT|SHELF|OSC|OTS|OSID|TX|RX|FE|ETTP|OTUTTP|ODUTTP|CHMON|NMCMON|OPTMON|SDMON)[-_]?[A-Z0-9]+$', value):
        return True
    return False


def _is_probable_rls_tid(value: str) -> bool:
    value = _normalize_rls_tid_label(value)
    if not value:
        return False
    if value in ('UNKNOWN', 'NONE', 'N/A', 'AUTO'):
        return False
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value):
        return False
    if _looks_like_component_label(value):
        return False
    return bool(re.match(r'^[A-Z0-9][A-Z0-9_.-]{2,}$', value))


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except Exception:
        return default


def _extract_rls_alarm_highlights(text: str, max_items: int = 5) -> list:
    if not text:
        return []
    highlights = []
    seen = set()
    blocks = re.split(r'(?m)^\s*-\s*history-id\s*:\s*\d+\s*$', text)
    for block in blocks[1:]:
        severity = _extract_rls_field(block, 'severity')
        cause = _extract_rls_field(block, 'cause') or _extract_rls_field(block, 'name')
        resource = _extract_rls_field(block, 'resource')
        info = _extract_rls_field(block, 'additional-info')
        if not severity and not cause:
            continue
        if (cause or '').lower() in ('slot empty', 'circuit pack unknown'):
            continue
        signature = (severity, cause, resource, info)
        if signature in seen:
            continue
        seen.add(signature)
        parts = [severity.upper() if severity else 'INFO', cause or 'unspecified']
        if resource:
            parts.append(resource)
        if info:
            parts.append(info)
        highlights.append(' | '.join(parts))
        if len(highlights) >= max_items:
            break
    return highlights


def _extract_rls_neighbor_details(artifact_prefix: str, interfaces: list) -> list:
    """artifact_prefix is the full path prefix, e.g. /workdir/192.168.1.1"""
    details = []
    for iface in interfaces:
        safe_iface = re.sub(r'[^A-Za-z0-9]+', '_', iface).strip('_')
        text = _read_rls_artifact(artifact_prefix + '_RLS_lldp_' + safe_iface + '_neighbors')
        if not text:
            continue
        system_name = _extract_rls_field(text, 'system-name') or 'unknown'
        mgmt_addr = _extract_rls_field(text, 'management-address') or 'n/a'
        port_id = _extract_rls_field(text, 'port-description') or _extract_rls_field(text, 'port-id') or 'n/a'
        details.append((iface, system_name, mgmt_addr, port_id))
    return details


def _extract_rls_interface_context(text: str, iface: str, radius: int = 20) -> str:
    if not text:
        return ''
    iface = str(iface or '').strip().lower()
    if not iface:
        return text
    lines = text.splitlines()
    windows = []
    seen = set()
    tokens = [iface, iface.replace('-', '/'), iface.replace('-', ' ')]
    for idx, line in enumerate(lines):
        lowered = line.lower()
        if any(token and token in lowered for token in tokens):
            start = max(0, idx - radius)
            end = min(len(lines), idx + radius + 1)
            key = (start, end)
            if key not in seen:
                seen.add(key)
                windows.append('\n'.join(lines[start:end]))
    return '\n\n'.join(windows) if windows else text


def _extract_rls_named_metric_value(text: str, metric_patterns: list,
                                     min_value: float = -80.0, max_value: float = 40.0) -> str:
    if not text:
        return ''
    for metric in metric_patterns:
        patterns = [
            r'(?im)^\s*' + metric + r'\s*[:=]\s*(-?\d+(?:\.\d+)?)\s*(?:dBm|dbm|dB|db)?\s*$',
            r'(?ims)' + metric + r'.{0,120}?\b(?:current|value|measured|actual|untimed|average)?\b.{0,40}?(-?\d+(?:\.\d+)?)\s*(?:dBm|dbm|dB|db)?',
            r'(?ims)' + metric + r'.{0,80}?(-?\d+(?:\.\d+)?)\s*(?:dBm|dbm|dB|db)?',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                value = match.group(1).strip()
                numeric = _safe_float(value, 9999.0)
                if min_value <= numeric <= max_value:
                    return value
    return ''


def _format_rls_metric_value(value: str, unit: str) -> str:
    value = str(value or '').strip()
    if not value:
        return ''
    numeric_match = re.search(r'-?\d+(?:\.\d+)?', value)
    if not numeric_match:
        return ''
    numeric = numeric_match.group(0)
    number = _safe_float(numeric, 9999.0)
    if unit.lower() == 'dbm':
        if not (-80.0 <= number <= 40.0):
            return ''
        formatted = ('%.2f' % number).rstrip('0').rstrip('.')
        return formatted + ' dBm'
    if unit.lower() == 'db':
        if not (0.0 <= abs(number) <= 80.0):
            return ''
        formatted = ('%.2f' % abs(number)).rstrip('0').rstrip('.')
        return formatted + ' dB'
    formatted = ('%.2f' % number).rstrip('0').rstrip('.')
    return formatted + ' ' + unit


def _extract_rls_osc_power_metrics(pm_current_text: str, pm_history_text: str, iface: str = '') -> tuple:
    search_text = '\n'.join([pm_current_text or '', pm_history_text or ''])
    if not search_text.strip():
        return '', '', ''

    candidate_texts = []
    scoped_text = _extract_rls_interface_context(search_text, iface)
    if scoped_text:
        candidate_texts.append(scoped_text)
    if 'osc' in str(iface or '').lower():
        osc_text = _extract_rls_interface_context(search_text, 'osc')
        if osc_text and osc_text not in candidate_texts:
            candidate_texts.append(osc_text)
    if search_text not in candidate_texts:
        candidate_texts.append(search_text)

    tx_labels = [
        r'untimed[\s-]*tx[\s-]*power(?:[\s-]*value)?',
        r'current(?:[\s-]*15[\s-]*minutes)?[\s-]*tx[\s-]*power(?:[\s-]*value)?',
        r'tx[\s-]*actual[\s-]*power', r'actual[\s-]*tx[\s-]*power',
        r'current[\s-]*tx[\s-]*power', r'\btx[\s-]*power\b',
    ]
    rx_labels = [
        r'untimed[\s-]*rx[\s-]*power(?:[\s-]*level)?',
        r'current(?:[\s-]*15[\s-]*minutes)?[\s-]*rx[\s-]*power(?:[\s-]*level)?',
        r'rx[\s-]*actual[\s-]*power', r'actual[\s-]*rx[\s-]*power',
        r'nominal[\s-]*rx[\s-]*power', r'\brx[\s-]*power\b',
    ]
    loss_labels = [
        r'rx[\s-]*cord[\s-]*loss', r'span[\s-]*loss', r'total[\s-]*fiber[\s-]*loss',
    ]

    tx_value = rx_value = loss_value = ''
    for candidate_text in candidate_texts:
        if not tx_value:
            tx_value = _extract_rls_named_metric_value(candidate_text, tx_labels, -80.0, 40.0)
        if not rx_value:
            rx_value = _extract_rls_named_metric_value(candidate_text, rx_labels, -80.0, 40.0)
        if not loss_value:
            loss_value = _extract_rls_named_metric_value(candidate_text, loss_labels, 0.0, 80.0)
        if tx_value and rx_value and loss_value:
            break

    tx_power = _format_rls_metric_value(tx_value, 'dBm')
    rx_power = _format_rls_metric_value(rx_value, 'dBm')
    rx_cord_loss = _format_rls_metric_value(loss_value, 'dB')

    if not rx_cord_loss and tx_power and rx_power:
        tx_match = re.search(r'-?\d+(?:\.\d+)?', tx_power)
        rx_match = re.search(r'-?\d+(?:\.\d+)?', rx_power)
        if tx_match and rx_match:
            tx_number = _safe_float(tx_match.group(0), 0.0)
            rx_number = _safe_float(rx_match.group(0), 0.0)
            if tx_number >= rx_number:
                rx_cord_loss = _format_rls_metric_value(str(tx_number - rx_number), 'dB')

    return tx_power, rx_power, rx_cord_loss


def _write_rls_csv(path: str, headers: list, rows: list) -> None:
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row)
    print('Created CSV: ' + os.path.basename(path))


def _autosize_worksheet_columns(worksheet, rows: list, min_width: int = 8,
                                 max_width: int = 80, padding: int = 2) -> None:
    col_widths = []
    for row in rows:
        for col_idx, value in enumerate(row):
            text = str(value or '')
            line_width = max([len(line) for line in text.splitlines()] or [0])
            if col_idx >= len(col_widths):
                col_widths.extend([0] * (col_idx - len(col_widths) + 1))
            if line_width > col_widths[col_idx]:
                col_widths[col_idx] = line_width
    for col_idx, width in enumerate(col_widths):
        worksheet.set_column(col_idx, col_idx, min(max_width, max(min_width, width + padding)))


def _reserve_workbook_path(preferred_path: str, dbg_write=None) -> str:
    if not os.path.exists(preferred_path):
        return preferred_path
    try:
        os.rename(preferred_path, preferred_path)
        return preferred_path
    except OSError as err:
        root, ext = os.path.splitext(preferred_path)
        stamp = strftime('%Y%m%d_%H%M%S')
        candidate = root + '_' + stamp + ext
        counter = 1
        while os.path.exists(candidate):
            candidate = root + '_' + stamp + '_' + str(counter) + ext
            counter += 1
        if dbg_write:
            try:
                dbg_write('\nWorkbook in use, saving to alternate file: %s (%s)\n' % (candidate, str(err)))
            except Exception:
                pass
        print('Workbook in use; saving to alternate file: ' + os.path.basename(candidate))
        return candidate


def _cleanup_rls_csv_artifacts(csv_paths: list, dbg_write=None) -> None:
    for csv_path in csv_paths:
        try:
            if os.path.exists(csv_path):
                os.remove(csv_path)
        except Exception as err:
            if dbg_write:
                try:
                    dbg_write('\nCould not remove RLS CSV %s: %s\n' % (csv_path, str(err)))
                except Exception:
                    pass


def _consolidate_rls_csv_to_xlsx(artifact_prefix: str, tid_label: str = '',
                                  cleanup_csvs: bool = True, dbg_write=None) -> str:
    try:
        from xlsxwriter.workbook import Workbook
    except Exception as err:
        if dbg_write:
            dbg_write('\nRLS XLSX generation unavailable: %s\n' % str(err))
        return ''

    workbook_label = _normalize_rls_tid_label(tid_label or artifact_prefix) or _normalize_rls_tid_label(artifact_prefix)
    workbook_label = re.sub(r'[\\/:*?"<>|]+', '_', workbook_label)
    workdir = os.path.dirname(artifact_prefix) or os.getcwd()
    output_file = os.path.join(workdir, workbook_label + '_RLS.xlsx')
    output_file = _reserve_workbook_path(output_file, dbg_write)
    workbook = Workbook(output_file)
    header_format = workbook.add_format({'bold': True, 'font_color': 'white'})
    header_format.set_bg_color('black')
    link_format = workbook.add_format({'font_color': 'blue', 'underline': 1})
    header_link_format = workbook.add_format({'bold': True, 'font_color': 'blue', 'underline': 1})
    header_link_format.set_bg_color('black')

    display_tid = workbook_label
    capture_stamp = strftime('%Y-%m-%d @ %H:%M:%S')

    index_sheet = workbook.add_worksheet('Index')
    index_sheet.set_column(0, 0, 24)
    index_sheet.set_column(1, 1, 72)
    index_sheet.merge_range(0, 0, 0, 1, 'Capture Time = ' + capture_stamp, header_format)
    index_sheet.merge_range(2, 0, 2, 1, 'TID IP = ' + os.path.basename(artifact_prefix), header_format)
    index_sheet.merge_range(3, 0, 3, 1, 'TID Name = ' + display_tid, header_format)

    all_csv_paths = glob.glob(artifact_prefix + '_RLS_*.csv')
    priority = {
        artifact_prefix + '_RLS_Issues.csv': 0,
        # Engineering-level verdicts produced by the validation step (when
        # the run was invoked with --validate). Slotted right after Issues
        # so the operator sees PASS/WARN/FAIL/INFO judgements before
        # diving into raw command output.
        artifact_prefix + '_RLS_Validation.csv': 1,
        artifact_prefix + '_RLS_Adjacencies.csv': 2,
        artifact_prefix + '_RLS_Alarms.csv': 3,
        artifact_prefix + '_RLS_Amplifiers.csv': 4,
        artifact_prefix + '_RLS_CHMON.csv': 5,
        artifact_prefix + '_RLS_DCN.csv': 6,
        artifact_prefix + '_RLS_Logging.csv': 7,
        artifact_prefix + '_RLS_PM_Audit.csv': 8,
        artifact_prefix + '_RLS_OSRP_Diagnostics.csv': 9,
        artifact_prefix + '_RLS_DOC.csv': 10,
        artifact_prefix + '_RLS_Equipment.csv': 8,
        artifact_prefix + '_RLS_ETTP.csv': 9,
        artifact_prefix + '_RLS_Inventory.csv': 10,
        artifact_prefix + '_RLS_Licenses.csv': 11,
        artifact_prefix + '_RLS_LOC.csv': 12,
        artifact_prefix + '_RLS_NMCMON.csv': 13,
        artifact_prefix + '_RLS_ODUTTP.csv': 14,
        artifact_prefix + '_RLS_OPTMON.csv': 15,
        artifact_prefix + '_RLS_OSC.csv': 16,
        artifact_prefix + '_RLS_OSPF_Nodes.csv': 17,
        artifact_prefix + '_RLS_OTM4.csv': 18,
        artifact_prefix + '_RLS_OTS.csv': 19,
        artifact_prefix + '_RLS_OTUTTP.csv': 20,
        artifact_prefix + '_RLS_PTP.csv': 22,
        artifact_prefix + '_RLS_Routing_Table.csv': 24,
        artifact_prefix + '_RLS_Rx_Adjacency.csv': 25,
        artifact_prefix + '_RLS_Shelves.csv': 28,
        artifact_prefix + '_RLS_SlotSequence.csv': 29,
        artifact_prefix + '_RLS_SPLI.csv': 30,
        artifact_prefix + '_RLS_Tx_Adjacency.csv': 32,
        artifact_prefix + '_RLS_Software.csv': 33,
        artifact_prefix + '_RLS_LLDP.csv': 35,
        # LLDP neighbor topology snapshot produced by the audit's walk
        # mode (--walk-mode). Placed at the end so the workbook reads
        # device-detail first, network-level info last.
        artifact_prefix + '_RLS_Walk_Neighbors.csv': 36,
    }
    display_names = {
        artifact_prefix + '_RLS_Issues.csv': 'Issues',
        artifact_prefix + '_RLS_Validation.csv': 'Validation',
        artifact_prefix + '_RLS_Adjacencies.csv': 'Adjacencies',
        artifact_prefix + '_RLS_Alarms.csv': 'Alarms',
        artifact_prefix + '_RLS_Amplifiers.csv': 'Amplifiers',
        artifact_prefix + '_RLS_CHMON.csv': 'CHMON',
        artifact_prefix + '_RLS_DCN.csv': 'DCN',
        artifact_prefix + '_RLS_Logging.csv': 'Command Log',
        artifact_prefix + '_RLS_PM_Audit.csv': 'PM_Audit',
        artifact_prefix + '_RLS_OSRP_Diagnostics.csv': 'OSRP_Diagnostics',
        artifact_prefix + '_RLS_DOC.csv': 'DOC',
        artifact_prefix + '_RLS_Equipment.csv': 'Equipment',
        artifact_prefix + '_RLS_ETTP.csv': 'ETTP',
        artifact_prefix + '_RLS_Inventory.csv': 'Inventory',
        artifact_prefix + '_RLS_Licenses.csv': 'Licenses',
        artifact_prefix + '_RLS_LOC.csv': 'LOC',
        artifact_prefix + '_RLS_NMCMON.csv': 'NMCMON',
        artifact_prefix + '_RLS_ODUTTP.csv': 'ODUTTP',
        artifact_prefix + '_RLS_OPTMON.csv': 'OPTMON',
        artifact_prefix + '_RLS_OSC.csv': 'OSC',
        artifact_prefix + '_RLS_OSPF_Nodes.csv': 'OSPF_Nodes',
        artifact_prefix + '_RLS_OTM4.csv': 'OTM4',
        artifact_prefix + '_RLS_OTS.csv': 'OTS',
        artifact_prefix + '_RLS_OTUTTP.csv': 'OTUTTP',
        artifact_prefix + '_RLS_PTP.csv': 'PTP',
        artifact_prefix + '_RLS_Routing_Table.csv': 'Routing_Table',
        artifact_prefix + '_RLS_Rx_Adjacency.csv': 'Rx_Adjacency',
        artifact_prefix + '_RLS_Shelves.csv': 'Shelves',
        artifact_prefix + '_RLS_SlotSequence.csv': 'SlotSequence',
        artifact_prefix + '_RLS_SPLI.csv': 'SPLI',
        artifact_prefix + '_RLS_Tx_Adjacency.csv': 'Tx_Adjacency',
        artifact_prefix + '_RLS_Software.csv': 'Software',
        artifact_prefix + '_RLS_LLDP.csv': 'LLDP',
        artifact_prefix + '_RLS_Walk_Neighbors.csv': 'Walk_Neighbors',
    }
    index_descriptions = {
        'Issues': 'Photonic Issues',
        'Validation': 'Engineering validation verdicts (PASS / WARN / FAIL / INFO)',
        'Adjacencies': 'Adjacency and discovered neighbor summary',
        'Alarms': 'Active and disabled alarm conditions',
        'Amplifiers': 'Amplifier and line-card power summary',
        'CHMON': 'Channel monitoring summary',
        'DCN': 'Management connectivity and discovered neighbors',
        'Command Log': 'Log collection and command context summary',
        'PM_Audit': 'Performance monitoring, baseline, and TCA visibility',
        'OSRP_Diagnostics': 'OSRP SNC and SNCG diagnostic visibility',
        'DOC': 'Shelf and software document summary',
        'Equipment': 'Equipment and equipment mode summary',
        'ETTP': 'Ethernet trail termination point view',
        'Inventory': 'Inventory, fan, and power module summary',
        'Licenses': 'License-related signals and software state',
        'LOC': 'Optical line characteristics and reference power',
        'NMCMON': 'Optical channel performance monitoring',
        'ODUTTP': 'ODU trail termination point summary',
        'OPTMON': 'Optical monitor summary',
        'OSC': 'Optical Service Channel neighbor summary',
        'OSPF_Nodes': 'Visible neighboring nodes',
        'OTM4': 'OTM4 transport card summary',
        'OTS': 'Optical transport section summary',
        'OTUTTP': 'OTN trail termination summary',
        'PTP': 'PTP and timing summary',
        'Routing_Table': 'Discovered routing and adjacency paths',
        'Rx_Adjacency': 'Receive adjacencies',
        'Shelves': 'Shelf identity, release, and alignment summary',
        'SlotSequence': 'Slot and hardware ordering',
        'SPLI': 'SPLI-like provisioning summary',
        'Tx_Adjacency': 'Transmit adjacencies',
        'Software': 'Software versions and upgrade state',
        'LLDP': 'LLDP neighbors and management addresses',
        'Walk_Neighbors': 'Network-walk neighbor topology (interface / system / mgmt-address / port)',
    }
    csv_paths = sorted(all_csv_paths, key=lambda p: (priority.get(p, 100), os.path.basename(p).lower()))

    used_sheet_names = {'Index'}
    row_index = 5
    for csv_path in csv_paths:
        if not os.path.exists(csv_path):
            continue
        if csv_path not in display_names:
            continue
        sheet_name = display_names[csv_path]
        sheet_name = sheet_name[:31]
        candidate = sheet_name
        suffix = 1
        while candidate in used_sheet_names:
            tag = '_' + str(suffix)
            candidate = sheet_name[:31 - len(tag)] + tag
            suffix += 1
        sheet_name = candidate
        used_sheet_names.add(sheet_name)

        index_sheet.write_url(row_index, 0, 'internal:' + sheet_name + '!A1', link_format, sheet_name)
        index_sheet.write(row_index, 1, index_descriptions.get(sheet_name, 'RLS derived data'))
        with open(csv_path, 'r', newline='', errors='ignore') as f_csv:
            reader = csv.reader(f_csv)
            sheet = workbook.add_worksheet(sheet_name)
            rows = list(reader)
            for r, row in enumerate(rows):
                for c, value in enumerate(row):
                    if r == 0 and c == 0:
                        sheet.write_url(0, 0, 'internal:Index!A' + str(row_index + 1), header_link_format, value)
                        try:
                            sheet.write_comment(0, 0, 'Bookmark to Index')
                        except Exception:
                            pass
                    elif r == 0:
                        sheet.write(r, c, value, header_format)
                    else:
                        sheet.write(r, c, value)
            _autosize_worksheet_columns(sheet, rows)
        row_index += 1

    try:
        workbook.close()
    except Exception as err:
        if dbg_write:
            try:
                dbg_write('\nRLS workbook close failed for %s: %s\n' % (output_file, str(err)))
            except Exception:
                pass
        raise

    if cleanup_csvs:
        _cleanup_rls_csv_artifacts(csv_paths, dbg_write)
    return output_file


def _consolidate_rls_csv_to_debug_xlsx(artifact_prefix: str, tid_label: str = '',
                                        dbg_write=None) -> str:
    try:
        from xlsxwriter.workbook import Workbook
    except Exception as err:
        if dbg_write:
            dbg_write('\nRLS Debug XLSX generation unavailable: %s\n' % str(err))
        return ''

    workbook_label = _normalize_rls_tid_label(tid_label or artifact_prefix) or _normalize_rls_tid_label(artifact_prefix)
    workbook_label = re.sub(r'[\\/:*?"<>|]+', '_', workbook_label)
    output_file = _reserve_workbook_path(artifact_prefix + '_Debug.xlsx', dbg_write)

    try:
        workbook = Workbook(output_file)
    except Exception as err:
        output_file = _reserve_workbook_path(artifact_prefix + '_Debug_' + strftime('%Y%m%d_%H%M%S') + '.xlsx', dbg_write)
        try:
            workbook = Workbook(output_file)
        except Exception as err:
            if dbg_write:
                try:
                    dbg_write('\nRLS Debug workbook creation failed for %s: %s\n' % (output_file, str(err)))
                except Exception:
                    pass
            return ''

    header_format = workbook.add_format({'bold': True, 'font_color': 'white'})
    header_format.set_bg_color('black')
    link_format = workbook.add_format({'font_color': 'blue', 'underline': 1})
    header_link_format = workbook.add_format({'bold': True, 'font_color': 'blue', 'underline': 1})
    header_link_format.set_bg_color('black')

    capture_stamp = strftime('%Y-%m-%d @ %H:%M:%S')
    index_sheet = workbook.add_worksheet('Index')
    index_sheet.set_column(0, 0, 24)
    index_sheet.set_column(1, 1, 72)
    index_sheet.merge_range(0, 0, 0, 1, 'Debug Workbook - Capture Time = ' + capture_stamp, header_format)
    index_sheet.merge_range(2, 0, 2, 1, 'TID IP = ' + os.path.basename(artifact_prefix), header_format)
    index_sheet.merge_range(3, 0, 3, 1, 'TID Name = ' + workbook_label, header_format)

    debug_sheets = {
        artifact_prefix + '_RLS_System_Health.csv': ('System_Health', 'CPU, memory, logging, and notifications'),
        artifact_prefix + '_RLS_Report.csv': ('Report', 'Consolidated RLS diagnostic report'),
        artifact_prefix + '_RLS_Detected.csv': ('Detected', 'Detected platform family and artifact list'),
        artifact_prefix + '_RLS_Smoke_Summary.csv': ('Smoke_Summary', 'Command capture completion summary'),
    }
    raw_tabs_map = {
        'alarm_history': ('raw_alarm_history', 'Raw alarm history evidence'),
        'all_slots': ('raw_all_slots', 'Raw slot inventory evidence'),
        'lldp': ('raw_lldp', 'Raw LLDP evidence'),
        'operation_info': ('raw_operation_info', 'Raw software operation evidence'),
    }

    all_csv_paths = glob.glob(artifact_prefix + '_RLS_*.csv')
    used_sheet_names = {'Index'}
    row_index = 5

    for csv_path in sorted(all_csv_paths):
        if not os.path.exists(csv_path):
            continue
        if csv_path in debug_sheets:
            sheet_name, description = debug_sheets[csv_path]
        else:
            base_name = os.path.splitext(os.path.basename(csv_path))[0]
            prefix_base = os.path.basename(artifact_prefix) + '_RLS_'
            if base_name.startswith(prefix_base):
                base_name = base_name[len(prefix_base):]
            if base_name in raw_tabs_map:
                sheet_name, description = raw_tabs_map[base_name]
            else:
                continue

        sheet_name = sheet_name[:31]
        candidate = sheet_name
        suffix = 1
        while candidate in used_sheet_names:
            tag = '_' + str(suffix)
            candidate = sheet_name[:31 - len(tag)] + tag
            suffix += 1
        sheet_name = candidate
        used_sheet_names.add(sheet_name)

        index_sheet.write_url(row_index, 0, 'internal:' + sheet_name + '!A1', link_format, sheet_name)
        index_sheet.write(row_index, 1, description)

        with open(csv_path, 'r', newline='', errors='ignore') as f_csv:
            reader = csv.reader(f_csv)
            sheet = workbook.add_worksheet(sheet_name)
            rows = list(reader)
            for r, row in enumerate(rows):
                for c, value in enumerate(row):
                    if r == 0 and c == 0:
                        sheet.write_url(0, 0, 'internal:Index!A' + str(row_index + 1), header_link_format, value)
                        try:
                            sheet.write_comment(0, 0, 'Bookmark to Index')
                        except Exception:
                            pass
                    elif r == 0:
                        sheet.write(r, c, value, header_format)
                    else:
                        sheet.write(r, c, value)
            _autosize_worksheet_columns(sheet, rows)
        row_index += 1

    try:
        workbook.close()
    except Exception as err:
        if dbg_write:
            try:
                dbg_write('\nRLS Debug workbook close failed for %s: %s\n' % (output_file, str(err)))
            except Exception:
                pass
        raise

    return output_file


# ---------------------------------------------------------------------------
# RLSSession
# ---------------------------------------------------------------------------

class RLSSession:
    """Self-contained RLS/SAOS 10 SSH session.

    Parameters mirror the CLI flags TDS_v6.2.py accepts when platform=rls.
    """

    def __init__(self, host: str, user: str, password: str, *,
                 expected_tid: str = '', run_validations: bool = False,
                 walk_mode: bool = False, walk_hop: int = 0,
                 workdir: Optional[str] = None, timeout: int = 120):
        self.host = host
        self.user = user
        self.password = password
        self.expected_tid = expected_tid
        self.run_validations = run_validations
        self.walk_mode = walk_mode
        self.walk_hop = walk_hop
        self.workdir = workdir or os.getcwd()
        self.timeout = timeout
        self._artifact_prefix = os.path.join(self.workdir, host.replace(':', '^'))
        self._shell_prompt = ''
        self._ssh = None
        self._chan = None
        self._dbg_handle = None

    # ------------------------------------------------------------------
    # Debug logging
    # ------------------------------------------------------------------

    def _dbg_write(self, text: str) -> None:
        try:
            if self._dbg_handle is None:
                dbg_path = os.path.join(self.workdir, 'TDS_Debug.txt')
                self._dbg_handle = open(dbg_path, 'a')
            self._dbg_handle.write(text)
            self._dbg_handle.flush()
        except Exception:
            pass

    def _close_dbg(self) -> None:
        try:
            if self._dbg_handle is not None:
                self._dbg_handle.close()
                self._dbg_handle = None
        except Exception:
            pass

    # ------------------------------------------------------------------
    # SSH connection
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Open SSH shell to self.host. Returns True on success."""
        if not _ensure_paramiko():
            return False
        try:
            from utils.helpers import (
                get_known_hosts_path as _get_kh,
                safe_load_host_keys as _safe_load_host_keys,
                safe_save_host_keys as _safe_save_host_keys,
            )
            _kh = str(_get_kh())
        except Exception:
            _kh = os.path.join(self.workdir, 'known_hosts')
            _safe_load_host_keys = None
            _safe_save_host_keys = None

        try:
            self._ssh = _paramiko.SSHClient()
            if _safe_load_host_keys is not None:
                _safe_load_host_keys(self._ssh, _kh)
            else:
                try:
                    self._ssh.load_host_keys(_kh)
                except Exception:
                    pass
            self._ssh.set_missing_host_key_policy(_paramiko.RejectPolicy())
            self._ssh.connect(self.host, port=22, username=self.user,
                              password=self.password, timeout=self.timeout,
                              look_for_keys=False, allow_agent=False)
            if _safe_save_host_keys is not None:
                _safe_save_host_keys(self._ssh, _kh)
            else:
                try:
                    self._ssh.save_host_keys(_kh)
                except Exception:
                    pass
            self._chan = self._ssh.invoke_shell()
            time.sleep(2)
            banner = ''
            while self._chan.recv_ready():
                banner += _recv_text(self._chan, 32768)
                time.sleep(0.1)
            banner = banner.replace('\r', '')
            lines = [line.strip() for line in banner.splitlines() if line.strip()]
            if lines:
                last_line = lines[-1]
                if last_line.endswith('#') or last_line.endswith('>') or last_line.endswith('$'):
                    self._shell_prompt = last_line
            self._dbg_write('\nRLS SSH banner:\n' + banner + '\n')
            return True
        except Exception as err:
            self._dbg_write('\nRLS SSH Connection Error: %s' % str(err))
            print('RLS SSH Connection Error: %s' % str(err))
            return False

    def disconnect(self) -> None:
        """Close SSH session gracefully."""
        logout_attempted = False
        try:
            if self._chan is not None:
                logout_attempted = True
                for cmd in ('logout', 'exit'):
                    try:
                        self._chan.send(cmd + '\n')
                        time.sleep(0.2)
                    except Exception:
                        pass
                try:
                    if self._chan.recv_ready():
                        _recv_text(self._chan, 32768)
                except Exception:
                    pass
                try:
                    self._chan.close()
                except Exception:
                    pass
                self._chan = None
        finally:
            try:
                if self._ssh is not None:
                    self._ssh.close()
                    self._ssh = None
            except Exception:
                pass
        if logout_attempted:
            print('RLS session logged out.')
            self._dbg_write('\nRLS session logged out.\n')
        self._close_dbg()

    # ------------------------------------------------------------------
    # Channel I/O
    # ------------------------------------------------------------------

    def _prompt_seen(self, text: str) -> bool:
        return _rls_prompt_seen(text, self._shell_prompt)

    def _drain(self, max_wait: float = 1.0) -> str:
        drained = ''
        end_time = time.time() + max_wait
        while time.time() < end_time:
            if self._chan.recv_ready():
                drained += _recv_text(self._chan, 32768)
                end_time = time.time() + 0.2
            else:
                time.sleep(0.05)
        return _sanitize_rls_output(drained)

    def _sync_prompt(self, timeout: float = 3.0) -> str:
        output = self._drain(0.5)
        if self._prompt_seen(output):
            return output
        self._chan.send('\n')
        end_time = time.time() + timeout
        while time.time() < end_time:
            if self._chan.recv_ready():
                output += _recv_text(self._chan, 32768)
                output = _sanitize_rls_output(output)
                if self._prompt_seen(output):
                    break
            else:
                time.sleep(0.1)
        return _sanitize_rls_output(output)

    def cmd(self, command: str, settle_time: float = 0.6, timeout: float = 20) -> str:
        """Send command, return sanitised output."""
        self._sync_prompt(2.0)
        output = ''
        self._chan.send(command + '\n')
        end_time = time.time() + timeout
        idle_loops = 0
        saw_meaningful = False
        while time.time() < end_time:
            if self._chan.recv_ready():
                chunk = _recv_text(self._chan, 32768)
                if chunk:
                    output += chunk
                    if '--More--' in chunk:
                        self._chan.send(' ')
                    if _rls_meaningful_lines(_sanitize_rls_output(output), command, self._shell_prompt):
                        saw_meaningful = True
                    idle_loops = 0
                time.sleep(0.1)
            else:
                idle_loops += 1
                time.sleep(max(settle_time / 3, 0.2))
                cleaned = _sanitize_rls_output(output)
                if saw_meaningful and self._prompt_seen(cleaned) and idle_loops >= 3:
                    break

        cleaned = _sanitize_rls_output(output)
        if not _rls_meaningful_lines(cleaned, command, self._shell_prompt):
            grace_end = time.time() + min(6.0, timeout)
            while time.time() < grace_end:
                if self._chan.recv_ready():
                    chunk = _recv_text(self._chan, 32768)
                    if chunk:
                        output += chunk
                        cleaned = _sanitize_rls_output(output)
                        if _rls_meaningful_lines(cleaned, command, self._shell_prompt) and self._prompt_seen(cleaned):
                            break
                else:
                    time.sleep(0.2)
        return _sanitize_rls_output(output)

    # ------------------------------------------------------------------
    # Smoke test (command collection)
    # ------------------------------------------------------------------

    def _record_command(self, summary_writer, group_name: str, label: str,
                        cmd_str: str, cmd_timeout: float, total_ok: int, total_warn: int):
        """Run one command, write its CSV, update summary. Returns (output, ok, warn)."""
        safe_name = re.sub(r'[^A-Za-z0-9]+', '_', label).strip('_')
        out_path = self._artifact_prefix + '_RLS_' + safe_name + '.csv'
        try:
            output = self.cmd(cmd_str, timeout=cmd_timeout)
        except Exception as err:
            output = 'COMMAND ERROR: %s' % str(err)
        with open(out_path, 'w', newline='') as f_out:
            writer = csv.writer(f_out)
            writer.writerow(['command', 'line_number', 'output'])
            output_lines = output.splitlines()
            if output_lines:
                for idx, line in enumerate(output_lines, 1):
                    writer.writerow([cmd_str, idx, line])
            else:
                writer.writerow([cmd_str, 1, ''])
        print('Created CSV: ' + os.path.basename(out_path))
        status, note = _classify_rls_output(output, cmd_str, self._shell_prompt)
        if status == 'OK':
            total_ok += 1
        else:
            total_warn += 1
        first_line = next((line.strip() for line in output.splitlines() if line.strip()), '')
        summary_writer.writerow([group_name, status, cmd_str, out_path, note, first_line])
        return output, total_ok, total_warn

    def smoke_test(self) -> None:
        """Run all RLS collection commands, write per-command CSVs and summary."""
        command_groups = [
            ('software', [
                ('software_summary', 'show software', 20),
                ('active_version', 'show software active-version', 15),
                ('running_version', 'show software running-version', 15),
                ('committed_version', 'show software committed-version', 15),
                ('upgrade_state', 'show software upgrade-operational-state', 15),
                ('upgrade_target', 'show software upgrade-to-version', 15),
                ('operation_info', 'show software operation-info', 20),
                ('ztp', 'show ztp', 15),
                ('ztp_admin_state', 'show ztp admin-state', 15),
            ]),
            ('platform', [
                ('shelf', 'show shelf', 15),
                ('system', 'show system', 15),
                ('lldp', 'show lldp', 20),
                ('alarm_history', 'show alarm-history', 20),
                ('alarm_counts', 'show alarm-counts', 15),
            ]),
            ('logging_pm', [
                ('logs_remote_config', 'show logs remote-config', 20),
                ('logs_retrieve_status', 'show logs retrieve-log-status', 20),
                ('command_log', 'show command-log', 20),
                ('syslog_history', 'syslog-history level 0', 20),
                ('pm_current', 'show pm current', 20),
                ('pm_history', 'show pm historical', 20),
                ('pm_tca', 'show-pm-tca', 20),
                ('osrp_snc_diagnostics', 'action osrp ALL object snc ALL show-snc-diagnostics', 25),
                ('osrp_sncg_diagnostics', 'action osrp ALL object snc-group ALL show-snc-group-diagnostics', 25),
            ]),
            ('hardware', [
                ('all_slots', 'show slots', 30),
            ]),
        ]

        summary_path = self._artifact_prefix + '_RLS_Smoke_Summary.csv'
        total_ok = 0
        total_warn = 0
        slot_details = []
        lldp_interfaces = []
        lldp_neighbor_map = {}

        with open(summary_path, 'w', newline='') as f_sum:
            summary_writer = csv.writer(f_sum)
            summary_writer.writerow(['Group', 'Status', 'Command', 'Output File', 'Note', 'First Non-Empty Line'])
            print('Created CSV: ' + os.path.basename(summary_path))

            for group_name, commands in command_groups:
                for label, cmd_str, cmd_timeout in commands:
                    output, total_ok, total_warn = self._record_command(
                        summary_writer, group_name.upper(), label, cmd_str, cmd_timeout, total_ok, total_warn)
                    if label == 'all_slots':
                        slot_details = _extract_rls_slot_details(output)
                    elif label == 'lldp':
                        lldp_interfaces, lldp_neighbor_map = _extract_rls_lldp_interfaces(output)

            if not lldp_interfaces:
                lldp_interfaces = ['colan-x', 'colan-a', 'ilan-in1', 'ilan-out1', 'ilan-in2', 'ilan-out2', 'osc-1-50-1']
                lldp_neighbor_map = {'colan-x': True, 'osc-1-50-1': True}

            summary_writer.writerow(['DISCOVERED_INTERFACES', 'INFO', 'selected_interfaces', '', '',
                                     ', '.join(lldp_interfaces[:8])])

            for iface in lldp_interfaces[:8]:
                detail_commands = [
                    ('lldp_' + iface + '_state', 'show lldp interfaces interface ' + iface + ' state', 15),
                ]
                if lldp_neighbor_map.get(iface, False):
                    detail_commands.append(
                        ('lldp_' + iface + '_neighbors', 'show lldp interfaces interface ' + iface + ' neighbors', 15))
                for label, cmd_str, cmd_timeout in detail_commands:
                    self._record_command(summary_writer, 'NETWORK_DETAILS', label, cmd_str, cmd_timeout, total_ok, total_warn)

            if not slot_details:
                slot_details = [
                    ('40', 'access-panel'), ('41', 'ctm'), ('42', 'ctm'),
                    ('51', 'fan'), ('52', 'fan'), ('61', 'power'), ('62', 'power'),
                ]

            summary_writer.writerow(['DISCOVERED_HARDWARE', 'INFO', 'selected_slots', '', '',
                                     ', '.join([slot + ' (' + form + ')' for slot, form in slot_details])])

            for slot, form_factor in slot_details:
                detail_commands = [
                    ('slot_' + slot + '_inventory', 'show slots ' + slot + ' inventory', 20),
                ]
                if form_factor in ('access-panel', 'ctm'):
                    detail_commands.append(('slot_' + slot + '_config_circuit_pack',
                                            'show slots ' + slot + ' config circuit-pack', 20))
                    detail_commands.append(('slot_' + slot + '_oper_state',
                                            'show slots ' + slot + ' inventory circuit-pack operational-state', 20))
                    detail_commands.append(('slot_' + slot + '_software_component',
                                            'show software component ' + slot, 20))
                for label, cmd_str, cmd_timeout in detail_commands:
                    self._record_command(summary_writer, 'HARDWARE_DETAILS', label, cmd_str, cmd_timeout, total_ok, total_warn)

            summary_writer.writerow(['TOTALS', 'OK', 'OK_COUNT', '', '', str(total_ok)])
            summary_writer.writerow(['TOTALS', 'WARN', 'WARN_COUNT', '', '', str(total_warn)])

    # ------------------------------------------------------------------
    # Data parsing / CSV generation
    # ------------------------------------------------------------------

    def parse_data(self) -> str:
        """Parse collected artifacts and write all RLS CSVs/XLSX. Returns '' on success."""
        ap = self._artifact_prefix
        summary_text = _read_rls_artifact(ap + '_RLS_Smoke_Summary')
        if not summary_text:
            msg = ap + '_RLS_Smoke_Summary not found'
            print(msg)
            self._dbg_write('\n' + msg + '\n')
            return msg

        active_version = _extract_rls_field(_read_rls_artifact(ap + '_RLS_active_version'), 'active-version')
        running_version = _extract_rls_field(_read_rls_artifact(ap + '_RLS_running_version'), 'running-version')
        committed_version = _extract_rls_field(_read_rls_artifact(ap + '_RLS_committed_version'), 'committed-version')
        upgrade_state = _extract_rls_field(_read_rls_artifact(ap + '_RLS_upgrade_state'), 'upgrade-operational-state')
        upgrade_target = _extract_rls_field(_read_rls_artifact(ap + '_RLS_upgrade_target'), 'upgrade-to-version')
        ztp_state = _extract_rls_field(_read_rls_artifact(ap + '_RLS_ztp_admin_state'), 'admin-state')

        operation_text = _read_rls_artifact(ap + '_RLS_operation_info')
        operation_in_progress = _extract_rls_field(operation_text, 'operation')
        operation_result = _extract_rls_field(operation_text, 'result')
        op_start = _extract_rls_field(operation_text, 'start-timestamp')
        op_end = _extract_rls_field(operation_text, 'end-timestamp')

        alarm_text = _read_rls_artifact(ap + '_RLS_alarm_counts')
        alarm_history_text = _read_rls_artifact(ap + '_RLS_alarm_history')
        critical = _safe_int(_extract_rls_field(alarm_text, 'critical'))
        major = _safe_int(_extract_rls_field(alarm_text, 'major'))
        minor = _safe_int(_extract_rls_field(alarm_text, 'minor'))
        warning = _safe_int(_extract_rls_field(alarm_text, 'warning'))
        alarm_highlights = _extract_rls_alarm_highlights(alarm_history_text)

        shelf_text = _read_rls_artifact(ap + '_RLS_shelf')
        shelf_product = _extract_rls_field(shelf_text, 'product')
        shelf_type = _extract_rls_field(shelf_text, 'shelf-type')
        serial_number = _extract_rls_field(shelf_text, 'serial-number')
        hardware_release = _extract_rls_field(shelf_text, 'hardware-release')
        current_power = _extract_rls_field(shelf_text, 'value')

        system_text = _read_rls_artifact(ap + '_RLS_system')
        system_admin = _extract_rls_field(system_text, 'admin-state')
        debug_logging = _extract_rls_field(system_text, 'debug-logging')
        publish_notifications = _extract_rls_field(system_text, 'publish-notifications')
        latest_bin_match = re.search(r'latest-bin-number:\s*\n\s*bin-number\s*:\s*(\d+)', system_text, re.IGNORECASE)
        latest_bin = latest_bin_match.group(1) if latest_bin_match else ''
        cpu_idle_match = re.search(r'idle:\s*\n\s*current\s*:\s*([0-9.]+)', system_text, re.IGNORECASE)
        cpu_idle = cpu_idle_match.group(1) if cpu_idle_match else ''
        mem_used_match = re.search(r'percent-of-used-mem:\s*\n\s*current\s*:\s*([0-9.]+)', system_text, re.IGNORECASE)
        mem_used = mem_used_match.group(1) if mem_used_match else ''

        logs_remote_config_text = _read_rls_artifact(ap + '_RLS_logs_remote_config')
        logs_retrieve_status_text = _read_rls_artifact(ap + '_RLS_logs_retrieve_status')
        command_log_text = _read_rls_artifact(ap + '_RLS_command_log')
        syslog_history_text = _read_rls_artifact(ap + '_RLS_syslog_history')
        pm_current_text = _read_rls_artifact(ap + '_RLS_pm_current')
        pm_history_text = _read_rls_artifact(ap + '_RLS_pm_history')
        pm_tca_text = _read_rls_artifact(ap + '_RLS_pm_tca')
        osrp_snc_diag_text = _read_rls_artifact(ap + '_RLS_osrp_snc_diagnostics')
        osrp_sncg_diag_text = _read_rls_artifact(ap + '_RLS_osrp_sncg_diagnostics')

        syslog_server_hosts = []
        for line in logs_remote_config_text.splitlines():
            if re.match(r'(?i)^\s*host\s*:', line):
                host_value = line.split(':', 1)[1].strip()
                if host_value and host_value not in ('""', "''"):
                    syslog_server_hosts.append(host_value)
        provisioned_syslog_servers = len(syslog_server_hosts)
        log_collection_status = _extract_rls_field(logs_retrieve_status_text, 'status') or \
                                 ('visible' if logs_retrieve_status_text.strip() else 'unknown')
        command_log_visible = 'YES' if _rls_meaningful_lines(command_log_text, 'show command-log', self._shell_prompt) else 'NO'
        pm_current_available = 'YES' if _rls_meaningful_lines(pm_current_text, 'show pm current', self._shell_prompt) else 'NO'
        pm_history_available = 'YES' if _rls_meaningful_lines(pm_history_text, 'show pm historical', self._shell_prompt) else 'NO'
        pm_baseline_state = 'VISIBLE' if 'BASELINE' in pm_current_text.upper() else 'NOT-VISIBLE'
        pm_tca_state = 'VISIBLE' if 'TCA' in pm_tca_text.upper() or 'THRESHOLD' in pm_tca_text.upper() else 'NOT-VISIBLE'
        osrp_snc_status = 'VISIBLE' if _rls_meaningful_lines(osrp_snc_diag_text, 'action osrp ALL object snc ALL show-snc-diagnostics', self._shell_prompt) else 'NOT-VISIBLE'
        osrp_sncg_status = 'VISIBLE' if _rls_meaningful_lines(osrp_sncg_diag_text, 'action osrp ALL object snc-group ALL show-snc-group-diagnostics', self._shell_prompt) else 'NOT-VISIBLE'
        auth_event_count = sum(syslog_history_text.upper().count(evt) for evt in ('LOGINACCEPTED', 'LOGINDENIED', 'LOGOUT'))
        alarm_event_count = sum(syslog_history_text.upper().count(evt) for evt in ('ALARMCREATED', 'ALARMDELETED', 'ALARMMODIFIED'))

        login_user = self.user or 'unknown'
        session_commands = _extract_rls_summary_commands(ap + '_RLS_Smoke_Summary')
        device_command_entries = _extract_rls_device_command_log_entries(command_log_text, target_user=login_user)
        session_command_count = len(session_commands)
        device_command_count = len(device_command_entries)
        cpu_health = 'PASS' if _safe_float(cpu_idle, -1.0) >= 80.0 else ('WARN' if 0.0 <= _safe_float(cpu_idle, -1.0) < 40.0 else 'INFO')
        mem_health = 'PASS' if 0.0 <= _safe_float(mem_used, -1.0) <= 70.0 else ('WARN' if _safe_float(mem_used, -1.0) > 85.0 else 'INFO')

        all_slots_text = _read_rls_artifact(ap + '_RLS_all_slots')
        slot_details = _extract_rls_slot_details(all_slots_text)
        lldp_text = _read_rls_artifact(ap + '_RLS_lldp')
        lldp_interfaces, lldp_neighbor_map = _extract_rls_lldp_interfaces(lldp_text)
        neighbor_ifaces = [iface for iface in lldp_interfaces if lldp_neighbor_map.get(iface, False)]
        neighbor_details = _extract_rls_neighbor_details(ap, neighbor_ifaces)

        osc_power_map = {}
        osc_power_details = []
        for iface in [item for item in lldp_interfaces if 'osc' in (item or '').lower()]:
            tx_power, rx_power, rx_cord_loss = _extract_rls_osc_power_metrics(pm_current_text, pm_history_text, iface)
            osc_power_map[iface] = (tx_power, rx_power, rx_cord_loss)
            parts = []
            if tx_power:
                parts.append('Tx=' + tx_power)
            if rx_power:
                parts.append('Rx=' + rx_power)
            if rx_cord_loss:
                parts.append('Loss=' + rx_cord_loss)
            if parts:
                osc_power_details.append(iface + ' [' + ', '.join(parts) + ']')

        total_ok, total_warn = _read_rls_summary_counts(ap + '_RLS_Smoke_Summary')
        expected_tid_clean = _normalize_rls_tid_label(self.expected_tid)
        display_tid = expected_tid_clean or ''
        detected_tid = _normalize_rls_tid_label(
            _extract_tid_from_prompt(self._shell_prompt) or
            _extract_rls_field(system_text, 'system-name') or
            _extract_rls_field(system_text, 'host-name') or
            _extract_rls_field(shelf_text, 'system-name') or
            _extract_rls_field(shelf_text, 'host-name') or
            _extract_rls_field(system_text, 'name') or
            _extract_rls_field(shelf_text, 'name')
        )
        tid_match = 'YES' if not expected_tid_clean or expected_tid_clean == detected_tid else 'NO'
        primary_shelf = 'SHELF-1'
        alarm_summary = 'critical=%d, major=%d, minor=%d, warning=%d' % (critical, major, minor, warning)
        osc_neighbor_ifaces = [iface for iface in neighbor_ifaces if 'osc' in (iface or '').lower()]

        # --- Build inventory rows ---
        inventory_rows = []
        for slot, form_factor in slot_details:
            inv_text = _read_rls_artifact(ap + '_RLS_slot_' + slot + '_inventory')
            sw_text = _read_rls_artifact(ap + '_RLS_slot_' + slot + '_software_component')
            inventory_rows.append([
                slot, form_factor,
                _extract_rls_field(inv_text, 'c-type') or form_factor,
                _extract_rls_field(inv_text, 'operational-state') or _extract_rls_field(inv_text, 'state'),
                _extract_rls_field(inv_text, 'serial-number'),
                _extract_rls_field(inv_text, 'hardware-release'),
                _extract_rls_field(inv_text, 'value'),
                _extract_rls_field(sw_text, 'active-version'),
            ])

        neighbor_detail_map = {iface: (system_name, mgmt_addr, port_id)
                               for iface, system_name, mgmt_addr, port_id in neighbor_details}
        lldp_rows = []
        adjacency_rows = []
        ospf_rows = []
        routing_rows = []
        for iface in lldp_interfaces:
            system_name, mgmt_addr, port_id = neighbor_detail_map.get(iface, ('', '', ''))
            neighbor_present = 'YES' if iface in neighbor_ifaces else 'NO'
            lldp_rows.append([display_tid, primary_shelf, iface, neighbor_present, system_name, mgmt_addr, port_id])
            adjacency_rows.append([display_tid, primary_shelf, iface, neighbor_present,
                                   system_name or 'none', mgmt_addr or 'n/a', port_id or 'n/a'])
            if system_name or mgmt_addr:
                ospf_rows.append([display_tid, system_name or 'unknown', mgmt_addr or 'n/a', iface, port_id or 'n/a'])
                routing_rows.append([display_tid, system_name or 'unknown', mgmt_addr or 'n/a', iface, 'LLDP-discovered'])

        uptime_value = _extract_rls_field(all_slots_text, 'uptime') or ''
        time_of_day = _extract_rls_field(all_slots_text, 'time-of-day') or ''
        equipment_rows = [['SHELF-1', 'shelf', shelf_product or shelf_type or 'Shelf',
                           system_admin or 'unknown', serial_number or '', hardware_release or '',
                           current_power or '', active_version or '']]
        equipment_rows.extend(inventory_rows)

        dcn_rows = [
            ['Management', 'Host', self.host],
            ['Management', 'Expected TID', self.expected_tid],
            ['Management', 'Detected TID', detected_tid or 'unknown'],
            ['Management', 'TID Match', tid_match],
            ['Management', 'CLI Prompt', self._shell_prompt.strip()],
            ['Management', 'Publish Notifications', publish_notifications or 'unknown'],
            ['Management', 'Debug Logging', debug_logging or 'unknown'],
            ['Management', 'ZTP Admin State', ztp_state or 'unknown'],
            ['Neighbors', 'Neighbor Count', str(len(neighbor_ifaces))],
        ]
        for iface, system_name, mgmt_addr, port_id in neighbor_details:
            dcn_rows.append(['Neighbors', iface,
                            (system_name or 'unknown') + ' | ' + (mgmt_addr or 'n/a') + ' | ' + (port_id or 'n/a')])

        doc_rows = [[display_tid, primary_shelf, shelf_product or 'unknown', shelf_type or 'unknown',
                     serial_number or 'unknown', hardware_release or 'unknown',
                     active_version or 'unknown', running_version or 'unknown',
                     committed_version or 'unknown', upgrade_state or 'unknown',
                     upgrade_target or 'unknown', ztp_state or 'unknown']]

        license_hits = [item for item in alarm_highlights if 'LICENSE' in item.upper()]
        license_rows = []
        if license_hits:
            for item in license_hits:
                parts = item.split(' | ')
                severity = parts[0] if parts else 'INFO'
                cause = parts[1] if len(parts) > 1 else item
                resource = ' | '.join(parts[2:]) if len(parts) > 2 else primary_shelf
                license_rows.append([display_tid, severity, cause, resource, 'WARN'])
        else:
            license_rows.append([display_tid, 'INFO', 'No explicit license alarm found in current smoke capture', primary_shelf, 'INFO'])
        license_rows.append([display_tid, 'INFO', 'software-version', active_version or running_version or 'unknown', 'INFO'])

        logging_rows = []
        sequence_id = 1
        for timestamp, user_name, command, raw_line in device_command_entries:
            logging_rows.append([display_tid, sequence_id, 'DEVICE_COMMAND_LOG', timestamp,
                                 user_name or 'unknown', command, 'show command-log', 'INFO', raw_line])
            sequence_id += 1
        for group_name, status, command, note in session_commands:
            logging_rows.append([display_tid, sequence_id, 'TDS_SESSION', '', login_user,
                                 command, group_name, status, note])
            sequence_id += 1
        if not logging_rows:
            logging_rows.append([display_tid, 1, 'INFO', '', login_user, 'No command entries captured',
                                 'show command-log', 'WARN' if command_log_visible != 'YES' else 'INFO',
                                 'Run show command-log manually if the platform restricts command history visibility'])

        pm_audit_rows = [
            [display_tid, 'PM Current', pm_current_available, 'show pm current', pm_baseline_state, 'INFO'],
            [display_tid, 'PM Historical', pm_history_available, 'show pm historical', '', 'INFO'],
            [display_tid, 'PM TCA', pm_tca_state, 'show-pm-tca', '', 'INFO'],
        ]
        osrp_diag_rows = [
            [display_tid, 'SNC Diagnostics', osrp_snc_status,
             'action osrp ALL object snc ALL show-snc-diagnostics', 'read-only audit evidence'],
            [display_tid, 'SNCG Diagnostics', osrp_sncg_status,
             'action osrp ALL object snc-group ALL show-snc-group-diagnostics', 'read-only audit evidence'],
        ]

        def _legacy_optical_tuple(identifier):
            token = re.sub(r'[^0-9A-Za-z]+', '-', str(identifier)).strip('-') or '1'
            return 'OTS-1-' + token, 'OSID-' + token, 'TX-' + token, 'RX-' + token, 'FE-' + token

        slot_sequence_rows = []
        amplifier_rows = []
        chmon_rows = []
        ots_rows = []
        otuttp_detail_rows = []
        optmon_rows = []
        nmcmon_rows = []
        loc_rows = []
        spli_rows = []
        otm4_candidates = []

        for idx, row in enumerate(inventory_rows, 1):
            slot, form_factor, card_type, oper_state, slot_serial, slot_hw, slot_power, slot_sw = row
            ots_aid, osid, tx_path, rx_path, fe_aid = _legacy_optical_tuple(slot)
            slot_label = card_type or form_factor or ('slot-' + str(slot))
            oper_state_clean = (oper_state or '').lower()
            osc_control_state = ('UP' if oper_state_clean in ('active', 'enabled', 'up') else 'STANDBY') \
                if osc_neighbor_ifaces else \
                ('ATTENTION' if oper_state_clean in ('active', 'enabled', 'up') else 'IDLE')

            slot_sequence_rows.append([display_tid, primary_shelf, ots_aid, osid, tx_path, rx_path, fe_aid,
                                       idx, 'YES' if idx == 1 else 'NO', slot_label, idx, idx])
            spli_rows.append([display_tid, primary_shelf, idx, shelf_product or '6500 RLS', fe_aid,
                              display_tid, primary_shelf, self.host,
                              'SSH+LLDP' if osc_neighbor_ifaces else 'SSH',
                              oper_state or 'unknown', len(neighbor_ifaces), osc_control_state])

            if form_factor in ('ctm', 'access-panel') or 'otm' in (card_type or '').lower() or 'amp' in (card_type or '').lower():
                amplifier_rows.append([display_tid, primary_shelf, slot, ots_aid, osid, tx_path, rx_path, fe_aid,
                                       slot_power or '', 'automatic', card_type or form_factor or 'unknown', slot])
                chmon_rows.append([display_tid, primary_shelf, ots_aid, osid, tx_path, rx_path, fe_aid,
                                   'CHMON-' + str(slot), slot_label, '', str(idx), oper_state or 'unknown',
                                   slot_power or '', '', ''])
                ots_rows.append([display_tid, primary_shelf, form_factor or 'RLS', card_type or 'RLS',
                                 ots_aid, osid, tx_path, rx_path, slot, display_tid, 'MONITORED', fe_aid])
                otuttp_detail_rows.append([display_tid, primary_shelf, slot, 'OTUTTP-' + str(slot),
                                           card_type or 'RLS', oper_state or 'unknown',
                                           slot_sw or 'unknown', slot_power or '', 'show slots inventory'])
                optmon_rows.append([display_tid, primary_shelf, ots_aid, osid, tx_path, rx_path, fe_aid,
                                    'OPTMON-' + str(slot), slot_label, 'inventory-monitor', primary_shelf])
                nmcmon_rows.append([display_tid, primary_shelf, ots_aid, osid, tx_path, rx_path, fe_aid,
                                    'NMCMON-' + str(slot), slot_label, '', '', '', slot_power or '', '', ''])
                loc_rows.append([display_tid, slot, ots_aid, osid, tx_path, rx_path, fe_aid,
                                 oper_state or 'unknown', oper_state or 'unknown', form_factor or 'RLS',
                                 '', '', slot_power or '', '', '', card_type or form_factor or 'RLS',
                                 'OSC-VERIFIED' if osc_neighbor_ifaces else (
                                     'IDLE' if oper_state_clean in ('idle', 'down') else 'MONITORED')])
                otm4_candidates.append((slot, slot_label, oper_state or 'unknown',
                                        slot_serial or 'unknown', slot_hw or 'unknown', slot_sw or 'unknown'))

        # Fallbacks for empty row lists
        for rows_list, fallback_fn in [
            (amplifier_rows, lambda f: [display_tid, primary_shelf, '1', f[0], f[1], f[2], f[3], f[4], '', 'automatic', 'unknown', '1']),
            (chmon_rows, lambda f: [display_tid, primary_shelf, f[0], f[1], f[2], f[3], f[4], 'CHMON-1', 'unknown', '', '1', 'unknown', '', '', '']),
            (ots_rows, lambda f: [display_tid, primary_shelf, 'RLS', 'RLS', f[0], f[1], f[2], f[3], '', display_tid, 'MONITORED', f[4]]),
            (otuttp_detail_rows, lambda f: [display_tid, primary_shelf, '1', 'OTUTTP-1', 'RLS', 'IDLE', 'unknown', '', 'inventory-derived']),
            (optmon_rows, lambda f: [display_tid, primary_shelf, f[0], f[1], f[2], f[3], f[4], 'OPTMON-1', 'unknown', 'inventory-monitor', primary_shelf]),
            (nmcmon_rows, lambda f: [display_tid, primary_shelf, f[0], f[1], f[2], f[3], f[4], 'NMCMON-1', 'unknown', '', '', '', '', '', '']),
            (loc_rows, lambda f: [display_tid, '1', f[0], f[1], f[2], f[3], f[4], 'IDLE', 'IDLE', 'RLS', '', '', '', '', '', 'RLS', 'MONITORED']),
        ]:
            if not rows_list:
                fb = _legacy_optical_tuple('1')
                rows_list.append(fallback_fn(fb))

        osc_rows = []
        for row in lldp_rows:
            iface = row[2]
            if 'osc' in (iface or '').lower():
                neighbor_present = row[3]
                system_name = row[4]
                mgmt_addr = row[5]
                port_id = row[6]
                ots_aid, osid, tx_path, rx_path, fe_aid = _legacy_optical_tuple(iface)
                tx_power, rx_power, rx_cord_loss = osc_power_map.get(iface, ('', '', ''))
                osc_rows.append([display_tid, primary_shelf, ots_aid, osid, tx_path, rx_path,
                                 mgmt_addr or fe_aid, len(slot_sequence_rows) or 1, iface,
                                 tx_power, rx_power, rx_cord_loss, system_name or 'none',
                                 port_id or 'n/a', mgmt_addr or 'n/a',
                                 'VERIFIED' if neighbor_present == 'YES' else 'NO_NEIGHBOR'])
        if not osc_rows:
            fb = _legacy_optical_tuple('OSC-1')
            osc_rows.append([display_tid, primary_shelf, fb[0], fb[1], fb[2], fb[3], fb[4],
                             1, 'none-detected', '', '', '', 'none', 'n/a', 'n/a', 'NO_NEIGHBOR'])

        client_ifaces = [iface for iface in lldp_interfaces if 'osc' not in (iface or '').lower()] or ['ETTP-1-1-1']
        ettp_header = (['TL1 Parameter', 'TID = ' + display_tid] +
                       [('ETTP-1-' + re.sub(r'[^0-9A-Za-z]+', '-', iface).strip('-').upper()) for iface in client_ifaces])
        ettp_rows = [
            ['AID', 'Derived From'] + client_ifaces,
            ['State', 'LLDP/Inventory'] + [('UP' if iface in neighbor_ifaces else 'DISCOVERED') for iface in client_ifaces],
            ['Neighbor', 'LLDP'] + [neighbor_detail_map.get(iface, ('', '', ''))[0] or 'none' for iface in client_ifaces],
            ['Management Address', 'LLDP'] + [neighbor_detail_map.get(iface, ('', '', ''))[1] or 'n/a' for iface in client_ifaces],
            ['Port ID', 'LLDP'] + [neighbor_detail_map.get(iface, ('', '', ''))[2] or 'n/a' for iface in client_ifaces],
        ]

        oduttp_candidates = [row[0] for row in inventory_rows[:2]] or ['1']
        oduttp_header = (['TL1 Parameter', 'TID = ' + display_tid] +
                         [('ODUTTP-1-' + str(slot)) for slot in oduttp_candidates])
        oduttp_rows = [
            ['Circuit Pack', 'RLS derived'] + [next((r[2] for r in inventory_rows if r[0] == slot), 'unknown') for slot in oduttp_candidates],
            ['Operational State', 'RLS derived'] + [next((r[3] for r in inventory_rows if r[0] == slot), 'unknown') for slot in oduttp_candidates],
            ['Software Version', 'RLS derived'] + [next((r[7] for r in inventory_rows if r[0] == slot), 'unknown') for slot in oduttp_candidates],
            ['Serial Number', 'RLS derived'] + [next((r[4] for r in inventory_rows if r[0] == slot), 'unknown') for slot in oduttp_candidates],
        ]

        otm4_display = otm4_candidates[:1] or [('1', 'unknown', 'unknown', 'unknown', 'unknown', 'unknown')]
        otm4_header = (['TL1 Parameter', 'TID = ' + display_tid] +
                       [('OTM4-1-' + str(item[0]) + '-1') for item in otm4_display])
        otm4_rows = [
            ['Card Type', 'RLS derived'] + [item[1] for item in otm4_display],
            ['Operational State', 'RLS derived'] + [item[2] for item in otm4_display],
            ['Serial Number', 'RLS derived'] + [item[3] for item in otm4_display],
            ['Hardware Release', 'RLS derived'] + [item[4] for item in otm4_display],
            ['Software Version', 'RLS derived'] + [item[5] for item in otm4_display],
        ]

        ptp_rows = [[display_tid, primary_shelf, time_of_day or 'unknown', uptime_value or 'unknown',
                     latest_bin or 'unknown', operation_result or 'unknown']]

        rx_rows = []
        tx_rows = []
        for tid, shelf, iface, neighbor_present, system_name, mgmt_addr, port_id in adjacency_rows:
            ots_aid, osid, tx_path, rx_path, fe_aid = _legacy_optical_tuple(iface)
            iface_lower = str(iface or '').lower()
            if 'osc' in iface_lower:
                local_service = discovered_service = 'OSC-CONTROL'
                frequency_label = '198.54'
            elif 'colan' in iface_lower:
                local_service = discovered_service = 'CLIENT-LAN'
                frequency_label = ''
            elif 'ilan' in iface_lower:
                local_service = discovered_service = 'INTRA-LAN'
                frequency_label = ''
            else:
                local_service = discovered_service = (iface or 'LINK').upper()
                frequency_label = ''
            link_state = 'UP' if neighbor_present == 'YES' else 'NO-LLDP-NEIGHBOR'
            fe_address = mgmt_addr or system_name or ('LOCAL-' + (iface or 'LINK').upper())
            circuit_id = port_id or system_name or ('LOCAL-' + (iface or 'LINK').upper())
            rx_rows.append([tid, shelf, ots_aid, osid, tx_path, rx_path, fe_aid,
                            iface, local_service, discovered_service, link_state, fe_address])
            tx_rows.append([tid, shelf, ots_aid, osid, tx_path, rx_path, fe_aid,
                            iface, circuit_id, local_service, discovered_service, frequency_label])

        otuttp_aids = [row[2] for row in otuttp_detail_rows]
        otuttp_header2 = (['TL1 Parameter', 'TID = ' + display_tid] +
                          [('OTUTTP-1-' + str(slot)) for slot in otuttp_aids])
        otuttp_rows2 = [
            ['Circuit Pack', 'RLS derived'] + [row[4] for row in otuttp_detail_rows],
            ['Operational State', 'RLS derived'] + [row[5] for row in otuttp_detail_rows],
            ['Software Version', 'RLS derived'] + [row[6] for row in otuttp_detail_rows],
            ['Power W', 'RLS derived'] + [row[7] for row in otuttp_detail_rows],
        ]

        issue_rows = []
        if total_warn == 0:
            issue_rows.append(['INFO', 'Collection', 'Smoke collection completed with WARN = 0'])
        else:
            issue_rows.append(['WARN', 'Collection', 'Smoke collection reported WARN = %d' % total_warn])
        if not [v for v in (active_version, running_version, committed_version) if v] or \
                len(set(v for v in (active_version, running_version, committed_version) if v)) != 1:
            issue_rows.append(['WARN', 'Software', 'Software versions are not fully aligned'])
        if ztp_state and ztp_state.upper() != 'DISABLED':
            issue_rows.append(['WARN', 'Provisioning', 'ZTP admin-state is ' + ztp_state])
        if tid_match != 'YES':
            issue_rows.append(['WARN', 'TID', 'Expected TID does not match detected shelf name: ' +
                               self.expected_tid + ' vs ' + (detected_tid or 'unknown')])
        if critical or major or minor or warning:
            issue_rows.append(['WARN', 'Alarms', 'Active alarms present: ' + alarm_summary])
        if not osc_neighbor_ifaces:
            issue_rows.append(['WARN', 'Optical Control', 'No live OSC neighbor was verified; check optical control continuity'])
        if slot_details and not osc_neighbor_ifaces:
            issue_rows.append(['WARN', 'SPLI', 'SPLI-style sequencing is present but OSC control evidence was not verified'])
        for item in alarm_highlights:
            issue_rows.append(['INFO', 'Alarm Highlight', item])

        # --- Write all CSVs ---
        _write_rls_csv(ap + '_RLS_Software.csv', ['TID', 'Property', 'Value'], [
            [display_tid, 'active-version', active_version],
            [display_tid, 'running-version', running_version],
            [display_tid, 'committed-version', committed_version],
            [display_tid, 'upgrade-operational-state', upgrade_state],
            [display_tid, 'upgrade-to-version', upgrade_target],
            [display_tid, 'operation-in-progress', operation_in_progress],
            [display_tid, 'last-operation-result', operation_result],
            [display_tid, 'last-operation-start', op_start],
            [display_tid, 'last-operation-end', op_end],
            [display_tid, 'ztp-admin-state', ztp_state],
        ])
        _write_rls_csv(ap + '_RLS_DOC.csv',
                       ['TID', 'Shelf', 'Product', 'Shelf Type', 'Serial Number', 'Hardware Release',
                        'Active Version', 'Running Version', 'Committed Version', 'Upgrade State',
                        'Upgrade Target', 'ZTP State'], doc_rows)
        _write_rls_csv(ap + '_RLS_System_Health.csv', ['TID', 'Metric', 'Value'], [
            [display_tid, 'admin-state', system_admin],
            [display_tid, 'debug-logging', debug_logging],
            [display_tid, 'publish-notifications', publish_notifications],
            [display_tid, 'latest-bin-number', latest_bin],
            [display_tid, 'current-cpu-idle-percent', cpu_idle],
            [display_tid, 'current-used-memory-percent', mem_used],
            [display_tid, 'cpu-idle-assessment', cpu_health],
            [display_tid, 'memory-usage-assessment', mem_health],
            [display_tid, 'remote-syslog-servers', str(provisioned_syslog_servers)],
            [display_tid, 'retrieve-log-status', log_collection_status],
            [display_tid, 'pm-current-visible', pm_current_available],
            [display_tid, 'pm-tca-visible', pm_tca_state],
        ])
        _write_rls_csv(ap + '_RLS_Alarms.csv',
                       ['TID', 'Severity', 'Cause or Metric', 'Resource / Value'],
                       [[display_tid, 'COUNT', 'critical', critical],
                        [display_tid, 'COUNT', 'major', major],
                        [display_tid, 'COUNT', 'minor', minor],
                        [display_tid, 'COUNT', 'warning', warning]] +
                       [[display_tid, item.split(' | ')[0],
                         item.split(' | ')[1] if ' | ' in item else item,
                         ' | '.join(item.split(' | ')[2:]) if item.count(' | ') >= 2 else '']
                        for item in alarm_highlights])
        _write_rls_csv(ap + '_RLS_Shelves.csv',
                       ['Host', 'Expected TID', 'Detected TID', 'TID Match', 'Product', 'Shelf Type',
                        'Serial Number', 'Hardware Release', 'Current Power W', 'Active Version',
                        'Running Version', 'Committed Version', 'Upgrade State', 'Upgrade Target',
                        'ZTP State', 'Critical', 'Major', 'Minor', 'Warning'],
                       [[self.host, self.expected_tid, detected_tid or 'unknown', tid_match,
                         shelf_product, shelf_type, serial_number, hardware_release, current_power,
                         active_version, running_version, committed_version, upgrade_state,
                         upgrade_target, ztp_state, critical, major, minor, warning]])
        _write_rls_csv(ap + '_RLS_Equipment.csv',
                       ['Component', 'Form Factor', 'Card Type', 'Operational State',
                        'Serial Number', 'Hardware Release', 'Power W', 'Software Version'],
                       equipment_rows)
        _write_rls_csv(ap + '_RLS_Inventory.csv',
                       ['Slot', 'Form Factor', 'Card Type', 'Operational State',
                        'Serial Number', 'Hardware Release', 'Power W', 'Software Version'],
                       inventory_rows)
        _write_rls_csv(ap + '_RLS_Amplifiers.csv',
                       ['TID', 'SHELF', 'SLOT', 'OTS', 'OSID', 'TX Path ID', 'RX Path ID',
                        'Reliable Far End AID', 'Amplifier Gain Range', 'Amplifier Gain Regime',
                        'Amplifier Type', 'AID'], amplifier_rows)
        _write_rls_csv(ap + '_RLS_CHMON.csv',
                       ['TID', 'SHELF ID', 'OTS', 'OSID', 'TX Path ID', 'RX Path ID',
                        'Reliable Far End AID', 'AID', 'Circuit Pack', 'Wavelength', 'Channel ID',
                        'OCH Status', 'Untimed OPT-OCH (dBm)', 'Baseline OPT-OCH (dBm)',
                        'Beaseline Reset (M-D:H-M)'], chmon_rows)
        _write_rls_csv(ap + '_RLS_Licenses.csv',
                       ['TID', 'Severity', 'Cause', 'Resource', 'Assessment'], license_rows)
        _write_rls_csv(ap + '_RLS_LOC.csv',
                       ['TID', 'Circuit Pack', 'OTS AID', 'OSID', 'Tx Path ID', 'Rx path ID', 'FEAID',
                        'PState', 'SState', 'Reference Tx/Rx Type', 'Reference Signal Bandwidth 3dB (GHz)',
                        'Reference Signal Bandwidth 10dB (GHz)', 'Reference Signal Power (dBm)',
                        'Auto Maximum Control Power Output (dBm)', 'Reference Bandwidth', 'Type',
                        'Tx Power Reduction Control'], loc_rows)
        _write_rls_csv(ap + '_RLS_NMCMON.csv',
                       ['TID', 'SHELF ID', 'OTS', 'OSID', 'TX Path ID', 'RX Path ID',
                        'Reliable Far End AID', 'AID', 'Circuit Pack', 'Frequency (THz)',
                        'Channel Width (GHz)', 'Wavelength (nm)', 'Untimed OPT-OCH (dBm)',
                        'Baseline OPT-OCH (dBm)', 'Beaseline Reset (M-D:H-M)'], nmcmon_rows)
        _write_rls_csv(ap + '_RLS_OSC.csv',
                       ['TID', 'SHELF', 'OTS', 'OSID', 'TX Path ID', 'RX Path ID',
                        'Reliable Far End AID', 'Slot Sequencing', 'AID', 'Tx Power', 'Rx Power',
                        'Rx Cord Loss', 'Neighbor System', 'Neighbor Port', 'Neighbor Mgmt',
                        'OSC Link State'], osc_rows)
        _write_rls_csv(ap + '_RLS_OTS.csv',
                       ['TID', 'Shelf', 'Configuration', 'Subtype', 'AID', 'OSID', 'TX Path ID',
                        'RX Path ID', 'OTS Members', 'DOC Site', 'Slot Sequence Mode',
                        'AMP Mate OTS'], ots_rows)
        _write_rls_csv(ap + '_RLS_OTUTTP.csv', otuttp_header2, otuttp_rows2)
        _write_rls_csv(ap + '_RLS_ODUTTP.csv', oduttp_header, oduttp_rows)
        _write_rls_csv(ap + '_RLS_OTM4.csv', otm4_header, otm4_rows)
        _write_rls_csv(ap + '_RLS_ETTP.csv', ettp_header, ettp_rows)
        _write_rls_csv(ap + '_RLS_OPTMON.csv',
                       ['TID', 'SHELF', 'OTS', 'OSID', 'TX Path ID', 'RX Path ID',
                        'Reliable Far End AID', 'AID', 'Circuit Pack', 'Port Label',
                        'Monitor Type', 'Location'], optmon_rows)
        _write_rls_csv(ap + '_RLS_PTP.csv',
                       ['TID', 'Shelf', 'Time Of Day', 'Uptime', 'Latest Bin Number',
                        'Last Operation Result'], ptp_rows)
        _write_rls_csv(ap + '_RLS_SlotSequence.csv',
                       ['TID', 'Shelf', 'OTS', 'OSID', 'TX Path ID', 'RX Path ID',
                        'Reliable Far End AID', 'Sequence ID', 'Anchor', 'Label',
                        'Add Sequence', 'Drop Sequence'], slot_sequence_rows)
        _write_rls_csv(ap + '_RLS_Adjacencies.csv',
                       ['TID', 'SHELF', 'OTS', 'OSID', 'TX Path ID', 'RX Path ID', 'AID',
                        'Type', 'Provisioned FE AID', 'Discovered FE AID',
                        'Provisioned FE Form', 'Discovered FE Form'],
                       [[tid, shelf,
                         _legacy_optical_tuple(iface)[0], _legacy_optical_tuple(iface)[1],
                         _legacy_optical_tuple(iface)[2], _legacy_optical_tuple(iface)[3],
                         iface, 'LLDP', port_id or 'n/a', system_name or 'none',
                         iface.split('-')[0].upper() if iface else 'unknown', system_name or 'unknown']
                        for tid, shelf, iface, neighbor_present, system_name, mgmt_addr, port_id in adjacency_rows])
        _write_rls_csv(ap + '_RLS_Rx_Adjacency.csv',
                       ['TID', 'Shelf ID', 'OTS', 'OSID', 'TX Path ID', 'RX Path ID',
                        'Reliable Far End AID', 'AID', 'Wavelength', 'Discovered Wavelength',
                        'PState', 'Discovered FE Address'], rx_rows)
        _write_rls_csv(ap + '_RLS_Tx_Adjacency.csv',
                       ['TID', 'Shelf ID', 'OTS', 'OSID', 'TX Path ID', 'RX Path ID',
                        'Reliable Far End AID', 'AID', 'Circuit ID', 'Wavelength',
                        'Discovered Wavelength', 'Frequency (THz)'], tx_rows)
        _write_rls_csv(ap + '_RLS_LLDP.csv',
                       ['Local TID', 'Shelf', 'Interface', 'Neighbor Present',
                        'Neighbor System Name', 'Management Address', 'Neighbor Port'], lldp_rows)
        _write_rls_csv(ap + '_RLS_DCN.csv', ['Section', 'Parameter', 'Value'], dcn_rows)
        _write_rls_csv(ap + '_RLS_Logging.csv',
                       ['TID', 'Sequence', 'Source', 'Timestamp', 'User', 'Command',
                        'Collected Via', 'Status', 'Detail'], logging_rows)
        _write_rls_csv(ap + '_RLS_PM_Audit.csv',
                       ['TID', 'PM Area', 'Status', 'Source', 'Additional Detail', 'Assessment'],
                       pm_audit_rows)
        _write_rls_csv(ap + '_RLS_OSRP_Diagnostics.csv',
                       ['TID', 'Diagnostic Area', 'Visibility', 'Source', 'Notes'], osrp_diag_rows)
        _write_rls_csv(ap + '_RLS_OSPF_Nodes.csv',
                       ['Local TID', 'Remote TID', 'Remote IP', 'Discovered Via Interface', 'Remote Port'],
                       ospf_rows or [[display_tid, 'none', 'n/a', 'n/a', 'n/a']])
        _write_rls_csv(ap + '_RLS_Routing_Table.csv',
                       ['TID', 'Destination System', 'Management Address', 'Outgoing Interface', 'Source'],
                       routing_rows or [[display_tid, 'none', 'n/a', 'n/a', 'n/a']])
        _write_rls_csv(ap + '_RLS_SPLI.csv',
                       ['TID', 'Shelf', 'TIDIndex', 'Platform', 'FEAID Prefix', 'Node/TID',
                        'Shelf/Bay', 'IP Address', 'SPLI Comms Type', 'Status', 'Matches',
                        'SPLI Comms State'], spli_rows)
        _write_rls_csv(ap + '_RLS_Issues.csv', ['Severity', 'Category', 'Summary'], issue_rows)

        # Report CSV
        report_path = ap + '_RLS_Report.csv'
        report_rows = [['Section', 'Status', 'Detail']]
        current_section = 'GENERAL'
        report_lines = [
            '6500 RLS Diagnostic Report', 'Host = ' + self.host,
            'Expected TID = ' + self.expected_tid, 'Detected TID = ' + (detected_tid or 'unknown'),
        ]
        if self._shell_prompt:
            report_lines.append('CLI Prompt = ' + self._shell_prompt.strip())
        report_lines += ['', '[COLLECTION_STATUS]',
            '\t' + ('PASS' if tid_match == 'YES' else 'WARN') + ':\tExpected TID ' +
            ('matches' if tid_match == 'YES' else 'does not match') + ' detected shelf name',
            '\t' + ('PASS' if total_warn == 0 else 'WARN') + ':\tSmoke collection completed' +
            (' cleanly' if total_warn == 0 else ' with warnings') +
            ' (OK = %d, WARN = %d)' % (total_ok, total_warn), '']
        for line in report_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith('[') and stripped.endswith(']'):
                current_section = stripped[1:-1]
                continue
            match = re.match(r'^(PASS|WARN|INFO):\s*(.*)$', stripped)
            if match:
                report_rows.append([current_section, match.group(1), match.group(2)])
            else:
                report_rows.append([current_section, 'INFO', stripped])
        with open(report_path, 'w', newline='') as f_out:
            csv.writer(f_out).writerows(report_rows)
        print('Created CSV: ' + os.path.basename(report_path))

        # Detected metadata CSV
        variant_note = ap + '_RLS_Detected.csv'
        with open(variant_note, 'w', newline='') as f_out:
            writer = csv.writer(f_out)
            writer.writerow(['Key', 'Value'])
            writer.writerow(['Detected platform family', '6500 RLS'])
            writer.writerow(['Expected TID', self.expected_tid])
            writer.writerow(['Detected TID', detected_tid or 'unknown'])
            writer.writerow(['TID Match', tid_match])
        print('Created CSV: ' + os.path.basename(variant_note))

        # XLSX consolidation
        xlsx_path = _consolidate_rls_csv_to_xlsx(ap, display_tid, cleanup_csvs=False,
                                                  dbg_write=self._dbg_write)
        debug_xlsx_path = _consolidate_rls_csv_to_debug_xlsx(ap, display_tid, dbg_write=self._dbg_write)
        # In walk mode the per-host CSVs are consumed by the network audit
        # to build a span-wide workbook, so suppress the cleanup here.
        # ``RLS_Network_Audit.run_audit`` does its own cleanup after the
        # network workbook has been written.
        if not self.walk_mode:
            _cleanup_rls_csv_artifacts(glob.glob(ap + '_RLS_*.csv'), self._dbg_write)

        if xlsx_path:
            print('6500 RLS workbook generated: ' + xlsx_path)
        else:
            print('6500 RLS CSV artifacts created; workbook generation unavailable in this environment.')
        if debug_xlsx_path:
            print('6500 RLS Debug workbook generated: ' + debug_xlsx_path)

        # Optional validation pass
        if self.run_validations:
            try:
                import rls_validations
                host_data = {
                    'expected_tid': expected_tid_clean,
                    'detected_tid': detected_tid,
                    'active_version': active_version,
                    'running_version': running_version,
                    'committed_version': committed_version,
                    'cpu_idle': cpu_idle,
                    'mem_used': mem_used,
                    'critical': critical,
                    'major': major,
                    'minor': minor,
                    'warning': warning,
                    'osc_neighbor_ifaces': osc_neighbor_ifaces,
                    'osc_power_map': osc_power_map,
                    'total_ok': total_ok,
                    'total_warn': total_warn,
                }
                verdicts = rls_validations.run_validations(host_data)
                validation_csv = ap + '_RLS_Validation.csv'
                rls_validations.write_csv(verdicts, validation_csv)
                counts = rls_validations.summarize(verdicts)
                print('Validations: PASS=%d WARN=%d FAIL=%d INFO=%d -> %s' % (
                    counts.get('PASS', 0), counts.get('WARN', 0),
                    counts.get('FAIL', 0), counts.get('INFO', 0), validation_csv))
            except Exception as _verr:
                print('Validation step failed: %s' % str(_verr))
                self._dbg_write('\nValidation step failed: %s\n' % str(_verr))

        # Walk neighbors CSV (for RLS_Network_Audit BFS)
        if self.walk_mode:
            try:
                walk_csv = ap + '_RLS_Walk_Neighbors.csv'
                with open(walk_csv, 'w', newline='') as _f:
                    _w = csv.writer(_f)
                    _w.writerow(['Interface', 'Neighbor System Name', 'Management Address', 'Neighbor Port'])
                    for iface, system_name, mgmt_addr, port_id in neighbor_details:
                        _w.writerow([iface, system_name or '', mgmt_addr or '', port_id or ''])
                print('Walk neighbors written: ' + walk_csv)
            except Exception as _werr:
                print('Walk neighbor export failed: %s' % str(_werr))

        return ''

    # ------------------------------------------------------------------
    # Top-level entry point
    # ------------------------------------------------------------------

    def run(self) -> int:
        """Connect, collect, parse. Returns 0 on success, non-zero on failure."""
        try:
            if not self.connect():
                return 1
            self.smoke_test()
            self.disconnect()
            self.parse_data()
            return 0
        except Exception as err:
            print('RLSSession.run error: %s' % err)
            self._dbg_write('\nRLSSession.run error: %s\n' % err)
            try:
                self.disconnect()
            except Exception:
                pass
            return 1
