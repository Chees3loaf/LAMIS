"""Engineering validations for Ciena RLS shelves.

Consumes the per-command artifacts that ``TDS_v6.2.py`` already writes for an
RLS host (no extra device queries) and produces a flat list of ``Verdict``
records. Each verdict is one PASS/WARN/FAIL/INFO judgement against a named
engineering threshold or compliance rule.

Validations included today (data the smoke test already collects):
    - Software version alignment + approved-version compliance
    - System health (CPU idle, memory used)
    - Active alarm counts
    - Expected vs detected TID
    - LLDP neighbor presence on OSC interfaces
    - OSC Tx / Rx power floors

Validations not yet covered (require extending ``RLS_SMOKE_TEST`` to capture
the underlying data):
    - Span loss bidirectional delta
    - Amp gain / tilt deltas vs provisioned
    - ORL state and floor
    - CCMD Rx power floor and measured-vs-expected delta
    - Frequency in-band check

For each missing-data check this module emits a single INFO verdict naming
the command that would need to be added, so the operator can see the
diagnostic gap rather than getting a silent pass.
"""
from __future__ import annotations

from collections import namedtuple


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

# Software compliance. Populate these tuples with the versions blessed for
# production. Leave empty to skip the compliance check (alignment-only).
APPROVED_SW_VERSIONS: tuple = ()
PREVIOUS_APPROVED_SW_VERSIONS: tuple = ()

# System health (mirrors the inline classification PARSE_COLLECTED_DATA_RLS
# already does for cpu_idle / mem_used, lifted here so all verdicts live in
# one place).
CPU_IDLE_PASS_PCT = 80.0
CPU_IDLE_FAIL_PCT = 40.0
MEM_USED_PASS_PCT = 70.0
MEM_USED_FAIL_PCT = 85.0

# Optical power floors (dBm).
OSC_RX_FAIL_DBM = -30.0
OSC_TX_FAIL_DBM = -10.0
CCMD_RX_FAIL_DBM = -8.0

# Optical deltas (dB).
SPAN_LOSS_UNIDIR_FAIL_DB = 1.5
SPAN_LOSS_BIDIR_FAIL_DB = 2.0
AMP_GAIN_DELTA_FAIL_DB = 0.5
AMP_TILT_DELTA_FAIL_DB = 0.5
MEASURED_VS_EXPECTED_FAIL_DB = 1.0

# ORL.
ORL_FAIL_DB = 30.0
ORL_FAULT_STATES = frozenset({
    'outputOORL', 'reflectOORL', 'reflectOORH', 'hssf', 'shutoff',
})


# ---------------------------------------------------------------------------
# Verdict record
# ---------------------------------------------------------------------------

Verdict = namedtuple(
    'Verdict',
    ['category', 'item', 'value', 'threshold', 'status', 'detail'],
)


def _v(category: str, item: str, value, threshold, status: str, detail: str = '') -> Verdict:
    return Verdict(
        category=category,
        item=item,
        value='' if value is None else str(value),
        threshold='' if threshold is None else str(threshold),
        status=status,
        detail=detail,
    )


def _to_float(value, default=None):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Individual validators. Each returns a list of Verdict.
#
# Inputs are simple dicts/strings extracted by PARSE_COLLECTED_DATA_RLS so
# this module stays decoupled from TDS internals.
# ---------------------------------------------------------------------------

def validate_tid_match(expected_tid: str, detected_tid: str) -> list:
    expected = (expected_tid or '').strip().upper()
    detected = (detected_tid or '').strip().upper()
    if not expected:
        return [_v('TID', 'expected_tid', '', '', 'INFO',
                   'No expected TID provided; skipped match check')]
    if expected == detected:
        return [_v('TID', 'tid_match', detected, expected, 'PASS',
                   'Detected TID matches expected')]
    return [_v('TID', 'tid_match', detected or 'unknown', expected, 'FAIL',
               'Detected TID does not match expected')]


def validate_software(active: str, running: str, committed: str) -> list:
    verdicts = []
    versions = [v for v in (active, running, committed) if v]
    if not versions:
        return [_v('Software', 'version_alignment', '', '', 'INFO',
                   'No software versions reported')]

    if len(set(versions)) == 1:
        verdicts.append(_v('Software', 'version_alignment', versions[0],
                           'active==running==committed', 'PASS',
                           'Software versions aligned'))
    else:
        verdicts.append(_v('Software', 'version_alignment',
                           'active=%s, running=%s, committed=%s' % (
                               active or '?', running or '?', committed or '?'),
                           'active==running==committed', 'FAIL',
                           'Software versions are not aligned'))

    if APPROVED_SW_VERSIONS:
        active_v = (active or '').strip()
        if active_v in APPROVED_SW_VERSIONS:
            verdicts.append(_v('Software', 'approved_version', active_v,
                               'in APPROVED_SW_VERSIONS', 'PASS', ''))
        elif active_v in PREVIOUS_APPROVED_SW_VERSIONS:
            verdicts.append(_v('Software', 'approved_version', active_v,
                               'in APPROVED_SW_VERSIONS', 'WARN',
                               'Active version is previously-approved'))
        else:
            verdicts.append(_v('Software', 'approved_version', active_v or 'unknown',
                               'in APPROVED_SW_VERSIONS', 'FAIL',
                               'Active version is not on the approved list'))
    else:
        verdicts.append(_v('Software', 'approved_version', active or '',
                           'APPROVED_SW_VERSIONS empty', 'INFO',
                           'Compliance list not configured; skipped'))
    return verdicts


def validate_system_health(cpu_idle, mem_used) -> list:
    verdicts = []
    cpu = _to_float(cpu_idle)
    if cpu is None:
        verdicts.append(_v('System', 'cpu_idle_pct', cpu_idle, CPU_IDLE_PASS_PCT,
                           'INFO', 'CPU idle not reported'))
    elif cpu >= CPU_IDLE_PASS_PCT:
        verdicts.append(_v('System', 'cpu_idle_pct', cpu, '>=%.0f' % CPU_IDLE_PASS_PCT,
                           'PASS', ''))
    elif cpu < CPU_IDLE_FAIL_PCT:
        verdicts.append(_v('System', 'cpu_idle_pct', cpu, '>=%.0f' % CPU_IDLE_FAIL_PCT,
                           'FAIL', 'CPU idle below floor'))
    else:
        verdicts.append(_v('System', 'cpu_idle_pct', cpu, '>=%.0f' % CPU_IDLE_PASS_PCT,
                           'WARN', 'CPU idle below pass threshold'))

    mem = _to_float(mem_used)
    if mem is None:
        verdicts.append(_v('System', 'mem_used_pct', mem_used, MEM_USED_PASS_PCT,
                           'INFO', 'Memory utilisation not reported'))
    elif mem <= MEM_USED_PASS_PCT:
        verdicts.append(_v('System', 'mem_used_pct', mem, '<=%.0f' % MEM_USED_PASS_PCT,
                           'PASS', ''))
    elif mem > MEM_USED_FAIL_PCT:
        verdicts.append(_v('System', 'mem_used_pct', mem, '<=%.0f' % MEM_USED_FAIL_PCT,
                           'FAIL', 'Memory utilisation above ceiling'))
    else:
        verdicts.append(_v('System', 'mem_used_pct', mem, '<=%.0f' % MEM_USED_PASS_PCT,
                           'WARN', 'Memory utilisation above pass threshold'))
    return verdicts


def validate_alarms(critical: int, major: int, minor: int, warning: int) -> list:
    summary = 'critical=%d major=%d minor=%d warning=%d' % (
        critical, major, minor, warning)
    if critical > 0:
        return [_v('Alarms', 'active_alarm_counts', summary, 'critical==0',
                   'FAIL', 'Critical alarms present')]
    if major > 0 or minor > 0 or warning > 0:
        return [_v('Alarms', 'active_alarm_counts', summary,
                   'critical/major/minor/warning all 0', 'WARN',
                   'Non-critical alarms present')]
    return [_v('Alarms', 'active_alarm_counts', summary,
               'all severities 0', 'PASS', 'No active alarms')]


def validate_lldp_osc_neighbor(osc_neighbor_ifaces) -> list:
    osc_neighbor_ifaces = list(osc_neighbor_ifaces or [])
    if osc_neighbor_ifaces:
        return [_v('LLDP', 'osc_neighbor_present', ', '.join(osc_neighbor_ifaces),
                   '>=1 OSC neighbor', 'PASS', 'OSC peer visible via LLDP')]
    return [_v('LLDP', 'osc_neighbor_present', 'none',
               '>=1 OSC neighbor', 'WARN',
               'No live OSC neighbor visible from current LLDP capture')]


def validate_osc_power(osc_power_map) -> list:
    """osc_power_map: dict[iface] -> (tx_str, rx_str, rx_cord_loss_str)."""
    verdicts = []
    if not osc_power_map:
        return [_v('Optical', 'osc_power', '', '', 'INFO',
                   'No OSC interfaces or PM data captured')]
    for iface, triple in osc_power_map.items():
        tx, rx, _loss = triple
        tx_v = _to_float(tx)
        rx_v = _to_float(rx)
        if tx_v is None:
            verdicts.append(_v('Optical', 'osc_tx_dbm:%s' % iface, tx,
                               '>=%.1f' % OSC_TX_FAIL_DBM, 'INFO',
                               'No Tx reading'))
        elif tx_v >= OSC_TX_FAIL_DBM:
            verdicts.append(_v('Optical', 'osc_tx_dbm:%s' % iface, tx_v,
                               '>=%.1f' % OSC_TX_FAIL_DBM, 'PASS', ''))
        else:
            verdicts.append(_v('Optical', 'osc_tx_dbm:%s' % iface, tx_v,
                               '>=%.1f' % OSC_TX_FAIL_DBM, 'FAIL',
                               'OSC Tx below floor'))

        if rx_v is None:
            verdicts.append(_v('Optical', 'osc_rx_dbm:%s' % iface, rx,
                               '>=%.1f' % OSC_RX_FAIL_DBM, 'INFO',
                               'No Rx reading'))
        elif rx_v >= OSC_RX_FAIL_DBM:
            verdicts.append(_v('Optical', 'osc_rx_dbm:%s' % iface, rx_v,
                               '>=%.1f' % OSC_RX_FAIL_DBM, 'PASS', ''))
        else:
            verdicts.append(_v('Optical', 'osc_rx_dbm:%s' % iface, rx_v,
                               '>=%.1f' % OSC_RX_FAIL_DBM, 'FAIL',
                               'OSC Rx below floor'))
    return verdicts


def validate_collection_health(total_ok: int, total_warn: int) -> list:
    if total_warn == 0:
        return [_v('Collection', 'smoke_status', 'OK=%d WARN=%d' % (total_ok, total_warn),
                   'WARN==0', 'PASS', 'All commands returned data')]
    return [_v('Collection', 'smoke_status', 'OK=%d WARN=%d' % (total_ok, total_warn),
               'WARN==0', 'WARN', 'Some commands returned no data or errors')]


# ---------------------------------------------------------------------------
# Gap markers — call these where validation requires data the smoke test
# doesn't currently capture, so the operator sees what's missing.
# ---------------------------------------------------------------------------

def _gap(category: str, item: str, missing_command: str) -> Verdict:
    return _v(category, item, '', '', 'INFO',
              'Not validated; add `%s` to RLS_SMOKE_TEST to enable' % missing_command)


def gaps_optical_engineering() -> list:
    return [
        _gap('Optical', 'span_loss_bidir_delta', 'show optical-control links'),
        _gap('Optical', 'amp_gain_delta', 'show amplifiers'),
        _gap('Optical', 'amp_tilt_delta', 'show amplifiers'),
        _gap('Optical', 'orl_state', 'show optical-control orl'),
        _gap('Optical', 'ccmd_rx_dbm', 'show optical-control circuits'),
        _gap('Optical', 'measured_vs_expected_db', 'show optical-control circuits'),
        _gap('Optical', 'frequency_in_band', 'show optical-control circuits'),
    ]


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def run_validations(host_data: dict) -> list:
    """Run every validator that has its required input present in host_data.

    Expected host_data keys (all optional — missing keys produce INFO verdicts):
        expected_tid, detected_tid
        active_version, running_version, committed_version
        cpu_idle, mem_used
        critical, major, minor, warning
        osc_neighbor_ifaces (list)
        osc_power_map (dict[iface] -> (tx, rx, rx_cord_loss))
        total_ok, total_warn
    """
    verdicts = []
    verdicts.extend(validate_tid_match(
        host_data.get('expected_tid', ''),
        host_data.get('detected_tid', ''),
    ))
    verdicts.extend(validate_software(
        host_data.get('active_version', ''),
        host_data.get('running_version', ''),
        host_data.get('committed_version', ''),
    ))
    verdicts.extend(validate_system_health(
        host_data.get('cpu_idle'),
        host_data.get('mem_used'),
    ))
    verdicts.extend(validate_alarms(
        int(host_data.get('critical', 0) or 0),
        int(host_data.get('major', 0) or 0),
        int(host_data.get('minor', 0) or 0),
        int(host_data.get('warning', 0) or 0),
    ))
    verdicts.extend(validate_lldp_osc_neighbor(
        host_data.get('osc_neighbor_ifaces') or [],
    ))
    verdicts.extend(validate_osc_power(
        host_data.get('osc_power_map') or {},
    ))
    verdicts.extend(validate_collection_health(
        int(host_data.get('total_ok', 0) or 0),
        int(host_data.get('total_warn', 0) or 0),
    ))
    verdicts.extend(gaps_optical_engineering())
    return verdicts


def summarize(verdicts) -> dict:
    """Aggregate counts per status — handy for the walk roll-up."""
    out = {'PASS': 0, 'WARN': 0, 'FAIL': 0, 'INFO': 0}
    for v in verdicts:
        out[v.status] = out.get(v.status, 0) + 1
    return out


def write_csv(verdicts, path: str) -> None:
    import csv as _csv
    with open(path, 'w', newline='') as f:
        w = _csv.writer(f)
        w.writerow(['Category', 'Item', 'Value', 'Threshold', 'Status', 'Detail'])
        for v in verdicts:
            w.writerow([v.category, v.item, v.value, v.threshold, v.status, v.detail])
