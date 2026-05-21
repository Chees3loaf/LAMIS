"""RLS Network Audit orchestrator.

Drives a breadth-first walk across an RLS network. For each host it spawns
``TDS_v6.2.py`` as a subprocess (matching how the GUI launches TDS today),
passes ``--validate --walk-mode``, then reads two artifacts the subprocess
leaves behind:

    <HOST>_RLS_Validation.csv      — per-host engineering verdicts
    <HOST>_RLS_Walk_Neighbors.csv  — interface, system-name, mgmt-address,
                                     port-id for each LLDP neighbor

Newly-discovered management addresses are queued for a future hop, deduped
against a visited set and bounded by ``--max-hops``. The orchestrator emits
``Walk_Summary.csv`` at the end with one row per visited host.

Why a separate orchestrator instead of a loop inside TDS_v6.2.py?
TDS_v6.2.py wires nearly every piece of state to module-level globals
(HOST, WindowsHostName, RLS_SHELL_PROMPT, F_DBG ...). Re-entering the
collection path for a second host inside the same process would require a
deep refactor of a 17K-line file. Spawning one subprocess per host gives
each run a clean global namespace at the cost of subprocess startup time —
acceptable for a sequential walk.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import os
import re
import subprocess
import sys
from collections import deque


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TDS_SCRIPT = os.path.join(SCRIPT_DIR, 'TDS_v6.2.py')


def _tds_command_prefix():
    """Return the argv prefix needed to invoke the TDS entry point.

    Frozen builds self-spawn ATLAS.exe with ``--tds-mode``; main.py's
    dispatch strips the flag and runpy-executes the bundled TDS source.
    Dev runs use the Python interpreter against TDS_v6.2.py directly.
    """
    if getattr(sys, 'frozen', False):
        return [sys.executable, '--tds-mode']
    return [sys.executable, TDS_SCRIPT]


def _windows_safe(host: str) -> str:
    """Mirror TDS_v6.2.py's ``WindowsHostName = HOST.replace(':', '^')``."""
    return host.replace(':', '^')


def _normalize_host(host: str) -> str:
    """Lowercase + strip — used for the visited set."""
    return (host or '').strip().lower()


def _is_valid_host(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.match(r'^[A-Za-z0-9][A-Za-z0-9.\-]*$', value) and '&' not in value)


def _read_seedfile(path: str):
    out = []
    if not path:
        return out
    with open(path, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            # Allow either "HOST" or "HOST TID" per line; only the host is
            # forwarded to TDS — TID derivation happens on-device.
            host = line.split()[0]
            if _is_valid_host(host):
                out.append(host)
    return out


def _read_neighbors_csv(path: str):
    """Return list of management addresses from a Walk_Neighbors CSV."""
    addrs = []
    if not os.path.isfile(path):
        return addrs
    with open(path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            mgmt = (row.get('Management Address') or '').strip()
            if mgmt and mgmt.lower() not in ('n/a', 'none', 'unknown', ''):
                addrs.append(mgmt)
    return addrs


def _read_validation_summary(path: str):
    counts = {'PASS': 0, 'WARN': 0, 'FAIL': 0, 'INFO': 0}
    if not os.path.isfile(path):
        return counts
    with open(path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            status = (row.get('Status') or '').strip().upper()
            if status in counts:
                counts[status] += 1
    return counts


def _run_tds_for_host(host: str, username: str, file_name: str, hop: int,
                      workdir: str, timeout_s: int, log) -> int:
    """Run RLS collection for a single host. Returns 0 on success, non-zero on failure.

    Tries a direct in-process call via tds_rls.RLSSession first (avoids
    subprocess overhead and the one-login-per-hop cost).  Falls back to
    spawning TDS_v6.2.py as a subprocess when the import fails (e.g. inside
    a frozen build that ships TDS.exe separately).

    Password is taken from the ``TDS_PASSWORD`` env var.
    """
    password = os.getenv('TDS_PASSWORD', '')
    log('  $ TDS for %s (hop=%d)' % (host, hop))

    try:
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
        from tds_rls import RLSSession
        session = RLSSession(
            host, username, password,
            expected_tid=file_name,
            run_validations=True,
            walk_mode=True,
            walk_hop=hop,
            workdir=workdir,
            timeout=timeout_s,
        )
        return session.run()
    except ImportError:
        pass
    except Exception as err:
        log('  ! direct RLSSession failed (%s), falling back to subprocess' % err)

    # Subprocess fallback
    cmd = _tds_command_prefix() + [
        '--non-interactive',
        '--host', host,
        '--platform', 'rls',
        '--username', username,
        '--file-name', file_name,
        '--validate',
        '--walk-mode',
        '--hop', str(hop),
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            cwd=workdir, timeout=timeout_s,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
    except subprocess.TimeoutExpired:
        log('  ! TIMEOUT on %s after %ds' % (host, timeout_s))
        return -1
    if proc.stdout:
        for line in proc.stdout.splitlines():
            log('    %s' % line)
    if proc.stderr:
        for line in proc.stderr.splitlines():
            log('    [stderr] %s' % line)
    return proc.returncode


def _read_csv_rows(path: str):
    """Return ``(header_row, data_rows)`` for *path*, or ``(None, [])``.

    Quiet on missing/unreadable files — the audit is best-effort, and a
    single missing per-host CSV must not abort the network rollup.
    """
    try:
        with open(path, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            rows = list(reader)
    except OSError:
        return None, []
    if not rows:
        return None, []
    return rows[0], rows[1:]


# Category sheets aggregated into the network workbook, in display order.
# Each tuple is (csv_suffix, sheet_name, description_for_index).
_NETWORK_AGGREGATED_CATEGORIES = (
    ('_RLS_Validation.csv',    'Validation',     'Engineering verdicts (PASS / WARN / FAIL / INFO) across the span'),
    ('_RLS_Issues.csv',        'Issues',         'Photonic issues across every visited host'),
    ('_RLS_Alarms.csv',        'Alarms',         'Active / disabled alarms across every visited host'),
    ('_RLS_Shelves.csv',       'Shelves',        'Shelf identity, release, and alignment summary per host'),
    ('_RLS_Software.csv',      'Software',       'Software versions and upgrade state per host'),
    ('_RLS_Inventory.csv',     'Inventory',      'Inventory, fan, and power-module rows per host'),
    ('_RLS_Equipment.csv',     'Equipment',      'Equipment and equipment-mode rows per host'),
    ('_RLS_Adjacencies.csv',   'Adjacencies',    'Adjacency and discovered-neighbor rows per host'),
    ('_RLS_OSC.csv',           'OSC',            'Optical Service Channel neighbor rows per host'),
    ('_RLS_OTS.csv',           'OTS',            'Optical transport section rows per host'),
    ('_RLS_OPTMON.csv',        'OPTMON',         'Optical monitor rows per host'),
    ('_RLS_Amplifiers.csv',    'Amplifiers',     'Amplifier and line-card power rows per host'),
    ('_RLS_LLDP.csv',          'LLDP',           'LLDP neighbor / mgmt-address rows per host'),
    ('_RLS_Walk_Neighbors.csv', 'Walk_Neighbors', 'Network-walk topology (Host / Interface / Neighbor System / Mgmt-Address / Port)'),
)


def _aggregate_category(workdir: str, visited_hosts, csv_suffix: str):
    """For each visited host, read ``<workdir>/<host>_<suffix>`` and
    concatenate the rows with a leading ``Host`` column.

    Returns ``(header, rows)`` where ``header`` is the unified column
    list (``Host`` + per-CSV header) and ``rows`` is the merged data.
    A host with no CSV at this path contributes nothing.
    """
    unified_header = None
    merged = []
    for host in visited_hosts:
        wh = _windows_safe(host)
        path = os.path.join(workdir, wh + csv_suffix)
        header, data = _read_csv_rows(path)
        if header is None:
            continue
        if unified_header is None:
            unified_header = ['Host'] + list(header)
        for row in data:
            # Pad/truncate row to unified header width minus one (Host).
            target = len(unified_header) - 1
            if len(row) < target:
                row = list(row) + [''] * (target - len(row))
            elif len(row) > target:
                row = list(row[:target])
            merged.append([host] + list(row))
    return unified_header, merged


def _autosize_columns(sheet, rows) -> None:
    if not rows:
        return
    widths = [10] * max(len(r) for r in rows)
    for row in rows:
        for i, v in enumerate(row):
            s = '' if v is None else str(v)
            if len(s) > widths[i]:
                widths[i] = min(len(s), 60)
    for i, w in enumerate(widths):
        sheet.set_column(i, i, max(10, w + 2))


def compose_network_workbook(workdir: str, visited_hosts, summary_path: str,
                              seed_label: str = '', log=print) -> str:
    """Stitch every per-host ``<HOST>_RLS_<category>.csv`` produced by the
    walk into one network-wide ``.xlsx``.

    Sheets:
      * ``Index`` — capture time, seed, visited-host list with hyperlinks
        to each per-host workbook (if it exists).
      * ``Walk_Summary`` — the orchestrator's own per-hop summary.
      * One sheet per category in ``_NETWORK_AGGREGATED_CATEGORIES``,
        with rows from every host concatenated and a leading ``Host``
        column.

    Returns the path to the generated workbook, or empty string on
    failure (xlsxwriter missing, write error). Never raises.
    """
    try:
        from xlsxwriter.workbook import Workbook
    except Exception as err:
        log('[NETWORK] xlsxwriter unavailable, skipping network workbook: %s' % err)
        return ''

    if not visited_hosts:
        log('[NETWORK] no visited hosts, skipping network workbook')
        return ''

    label = re.sub(r'[\\/:*?"<>|]+', '_', (seed_label or visited_hosts[0]).strip()) or 'RLS_Network'
    output_file = os.path.join(workdir, label + '_RLS_Network.xlsx')
    try:
        workbook = Workbook(output_file)
    except Exception as err:
        log('[NETWORK] could not open workbook %s: %s' % (output_file, err))
        return ''

    header_fmt = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': 'black'})
    link_fmt = workbook.add_format({'font_color': 'blue', 'underline': 1})

    # --- Index sheet
    from time import strftime
    idx = workbook.add_worksheet('Index')
    idx.set_column(0, 0, 28)
    idx.set_column(1, 1, 72)
    idx.merge_range(0, 0, 0, 1, 'Capture Time = ' + strftime('%Y-%m-%d @ %H:%M:%S'), header_fmt)
    idx.merge_range(1, 0, 1, 1, 'Seed = ' + (seed_label or visited_hosts[0]), header_fmt)
    idx.merge_range(2, 0, 2, 1, 'Visited hosts = %d' % len(visited_hosts), header_fmt)

    # --- Walk_Summary sheet (existing CSV the orchestrator just wrote)
    used = {'Index'}
    row_idx = 4
    sum_header, sum_rows = _read_csv_rows(summary_path)
    if sum_header is not None:
        sheet = workbook.add_worksheet('Walk_Summary')
        used.add('Walk_Summary')
        for c, v in enumerate(sum_header):
            sheet.write(0, c, v, header_fmt)
        for r, row in enumerate(sum_rows, start=1):
            for c, v in enumerate(row):
                sheet.write(r, c, v)
        _autosize_columns(sheet, [sum_header] + sum_rows)
        idx.write_url(row_idx, 0, 'internal:Walk_Summary!A1', link_fmt, 'Walk_Summary')
        idx.write(row_idx, 1, 'Per-hop BFS summary (visited host, status, validation counts, neighbors)')
        row_idx += 1

    # --- One sheet per aggregated category
    for csv_suffix, sheet_name, description in _NETWORK_AGGREGATED_CATEGORIES:
        unified, merged = _aggregate_category(workdir, visited_hosts, csv_suffix)
        if not unified or not merged:
            continue
        if sheet_name in used:
            continue
        used.add(sheet_name)
        sheet = workbook.add_worksheet(sheet_name)
        for c, v in enumerate(unified):
            sheet.write(0, c, v, header_fmt)
        for r, row in enumerate(merged, start=1):
            for c, v in enumerate(row):
                sheet.write(r, c, v)
        _autosize_columns(sheet, [unified] + merged)
        idx.write_url(row_idx, 0, 'internal:' + sheet_name + '!A1', link_fmt, sheet_name)
        idx.write(row_idx, 1, description)
        row_idx += 1

    try:
        workbook.close()
    except Exception as err:
        log('[NETWORK] workbook close failed: %s' % err)
        return ''

    log('[NETWORK] wrote %s' % output_file)
    return output_file


def run_audit(seeds, username: str, max_hops: int,
              workdir: str, file_name_seed: str = '',
              per_host_timeout: int = 600, log=print,
              compose_workbook: bool = True) -> str:
    """Run the BFS audit and (by default) stitch a network-wide workbook.

    Returns the path to the network workbook when ``compose_workbook`` is
    True and the composer succeeded, otherwise the path to
    ``Walk_Summary.csv``.

    Caller must have set ``TDS_PASSWORD`` in the environment before invoking.
    """
    visited = set()
    visited_order = []  # parallel to ``visited`` but preserves traversal order
    queued_set = set()
    pending = deque()
    for seed in seeds:
        seed_norm = _normalize_host(seed)
        if seed_norm and seed_norm not in visited:
            pending.append((seed, 0))
            queued_set.add(seed_norm)

    summary_path = os.path.join(workdir, 'Walk_Summary.csv')
    with open(summary_path, 'w', newline='', encoding='utf-8') as f_sum:
        writer = csv.writer(f_sum)
        writer.writerow([
            'Hop', 'Host', 'Subprocess_Status',
            'Pass', 'Warn', 'Fail', 'Info',
            'Neighbors_Discovered', 'Neighbors_Queued', 'Notes',
        ])

        while pending:
            host, hop = pending.popleft()
            host_key = _normalize_host(host)
            if host_key in visited:
                continue
            visited.add(host_key)
            visited_order.append(host)

            log('--- HOP %d : %s ---' % (hop, host))
            tid_for_seed = file_name_seed if hop == 0 else ''
            rc = _run_tds_for_host(host, username, tid_for_seed,
                                   hop, workdir, per_host_timeout, log)
            status = 'OK' if rc == 0 else ('TIMEOUT' if rc == -1 else 'EXIT_%d' % rc)

            wh = _windows_safe(host)
            validation_csv = os.path.join(workdir, wh + '_RLS_Validation.csv')
            neighbors_csv = os.path.join(workdir, wh + '_RLS_Walk_Neighbors.csv')

            counts = _read_validation_summary(validation_csv)
            discovered = _read_neighbors_csv(neighbors_csv)

            queued = 0
            notes = []
            if hop < max_hops:
                for addr in discovered:
                    addr_key = _normalize_host(addr)
                    if not addr_key or addr_key in visited or addr_key in queued_set:
                        continue
                    if not _is_valid_host(addr):
                        notes.append('skip-invalid:%s' % addr)
                        continue
                    pending.append((addr, hop + 1))
                    queued_set.add(addr_key)
                    queued += 1
            elif discovered:
                notes.append('max-hops-reached')

            if not os.path.isfile(validation_csv):
                notes.append('no-validation-csv')

            writer.writerow([
                hop, host, status,
                counts.get('PASS', 0), counts.get('WARN', 0),
                counts.get('FAIL', 0), counts.get('INFO', 0),
                len(discovered), queued, ';'.join(notes),
            ])
            f_sum.flush()
            log('  -> %s | PASS=%d WARN=%d FAIL=%d | found=%d queued=%d' % (
                status, counts.get('PASS', 0), counts.get('WARN', 0),
                counts.get('FAIL', 0), len(discovered), queued))

    log('Walk complete. Visited %d host(s). Summary: %s' % (
        len(visited), summary_path))

    # Stitch the network-wide workbook from the per-host CSVs that walk
    # mode left behind, then sweep them so the workdir is left clean.
    if compose_workbook and visited_order:
        seed_label = seeds[0] if seeds else ''
        network_xlsx = compose_network_workbook(
            workdir, visited_order, summary_path,
            seed_label=seed_label, log=log,
        )
        if network_xlsx:
            _cleanup_walk_csvs(workdir, visited_order, log=log)
            return network_xlsx

    return summary_path


def _cleanup_walk_csvs(workdir: str, visited_hosts, log=print) -> None:
    """Remove the per-host ``<HOST>_RLS_*.csv`` files that walk mode left
    in *workdir* after the network workbook has been written. The per-
    host workbooks (``<HOST>_RLS.xlsx``) are left in place — operators
    can still drill into them for deep per-device detail.
    """
    removed = 0
    for host in visited_hosts:
        wh = _windows_safe(host)
        pattern = os.path.join(workdir, wh + '_RLS_*.csv')
        import glob as _glob
        for path in _glob.glob(pattern):
            try:
                os.remove(path)
                removed += 1
            except OSError:
                pass
    if removed:
        log('[NETWORK] cleaned up %d per-host CSV file(s)' % removed)


def _parse_args():
    p = argparse.ArgumentParser(
        description='RLS Network Audit — BFS walk via LLDP discovery, '
                    'engineering validations per host')
    p.add_argument('--seed', dest='seed', action='append', default=[],
                   help='Seed host (repeatable). At least one --seed or --seedfile required.')
    p.add_argument('--seedfile', dest='seedfile', default='',
                   help='Path to a newline-separated seed host file.')
    p.add_argument('--username', required=True)
    p.add_argument('--read-password-stdin', dest='read_password_stdin',
                   action='store_true',
                   help='Read password from stdin (one line). Otherwise uses TDS_PASSWORD env.')
    p.add_argument('--max-hops', type=int, default=3)
    p.add_argument('--per-host-timeout', type=int, default=600,
                   help='Per-host subprocess timeout in seconds (default 600).')
    p.add_argument('--workdir', default='',
                   help='Where artifacts are written (default: cwd).')
    p.add_argument('--seed-tid', dest='seed_tid', default='',
                   help='Optional --file-name passed to TDS for the seed host(s).')
    return p.parse_args()


def main():
    args = _parse_args()

    seeds = list(args.seed or [])
    seeds.extend(_read_seedfile(args.seedfile))
    seeds = [s for s in seeds if s]
    if not seeds:
        print('ERROR: provide --seed or --seedfile')
        sys.exit(2)
    bad = [s for s in seeds if not _is_valid_host(s)]
    if bad:
        print('ERROR: invalid seed host(s): %s' % ', '.join(bad))
        sys.exit(2)

    if args.read_password_stdin:
        password = sys.stdin.readline().rstrip('\n')
    else:
        password = os.getenv('TDS_PASSWORD', '')
    if not password:
        print('ERROR: password not provided (use --read-password-stdin or TDS_PASSWORD env)')
        sys.exit(2)

    workdir = args.workdir or os.getcwd()
    os.makedirs(workdir, exist_ok=True)

    # Forward password to each subprocess via env so we don't pipe stdin per spawn.
    os.environ['TDS_PASSWORD'] = password

    run_audit(
        seeds=seeds,
        username=args.username,
        max_hops=int(args.max_hops),
        workdir=workdir,
        file_name_seed=args.seed_tid,
        per_host_timeout=int(args.per_host_timeout),
        log=print,
    )


if __name__ == '__main__':
    main()
