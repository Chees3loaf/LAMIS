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
    """Spawn TDS_v6.2.py for a single host. Returns subprocess exit code.

    Password is read from the ``TDS_PASSWORD`` env var by the child — set
    by ``main()`` before the walk starts.
    """
    cmd = [
        sys.executable, TDS_SCRIPT,
        '--non-interactive',
        '--host', host,
        '--platform', 'rls',
        '--username', username,
        '--file-name', file_name,
        '--validate',
        '--walk-mode',
        '--hop', str(hop),
    ]
    log('  $ TDS for %s (hop=%d)' % (host, hop))
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


def run_audit(seeds, username: str, max_hops: int,
              workdir: str, file_name_seed: str = '',
              per_host_timeout: int = 600, log=print) -> str:
    """Run the BFS audit. Returns the path to Walk_Summary.csv.

    Caller must have set ``TDS_PASSWORD`` in the environment before invoking.
    """
    visited = set()
    pending = deque()
    for seed in seeds:
        seed_norm = _normalize_host(seed)
        if seed_norm and seed_norm not in visited:
            pending.append((seed, 0))

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
                    if not addr_key or addr_key in visited:
                        continue
                    if any(_normalize_host(p[0]) == addr_key for p in pending):
                        continue
                    if not _is_valid_host(addr):
                        notes.append('skip-invalid:%s' % addr)
                        continue
                    pending.append((addr, hop + 1))
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
    return summary_path


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
