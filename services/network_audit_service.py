"""UI-independent Ciena RLS and Nokia PSI network-audit execution."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
from typing import Callable


ProgressCallback = Callable[[str], None]


@dataclass(frozen=True)
class NetworkAuditRequest:
    network_type: str
    seed: str
    username: str
    password: str
    output_path: Path
    capture_alarms: bool = False
    capture_alarm_history: bool = False
    debug: bool = False


def is_valid_audit_host(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]*", value) and "&" not in value)


def validate_network_audit_request(request: NetworkAuditRequest) -> None:
    if request.network_type not in {"rls", "psi"}:
        raise ValueError("Network type must be Ciena RLS or Nokia PSI.")
    if not is_valid_audit_host(request.seed):
        raise ValueError(f"Seed IP or hostname is invalid: {request.seed!r}")
    if not request.username.strip():
        raise ValueError("Username is required.")
    if not request.password:
        raise ValueError("Password is required.")
    if request.output_path.suffix.lower() != ".xlsx":
        raise ValueError("Network Audit output must be an .xlsx workbook.")


def run_network_audit(
    request: NetworkAuditRequest,
    *,
    progress: ProgressCallback | None = None,
) -> Path:
    validate_network_audit_request(request)
    emit = progress or (lambda _message: None)
    request.output_path.parent.mkdir(parents=True, exist_ok=True)
    label = "Nokia PSI" if request.network_type == "psi" else "Ciena RLS"
    emit(f"Starting {label} Network Audit from {request.seed}…")
    if request.network_type == "psi":
        from scripts.Network.Nokia_PSI_Audit import run_audit
        run_audit(
            seed_host=request.seed,
            username=request.username,
            password=request.password,
            output_path=str(request.output_path),
            debug=request.debug,
            log_callback=emit,
        )
    else:
        from scripts.Network.RLS_Audit import run_audit
        run_audit(
            seed_host=request.seed,
            username=request.username,
            password=request.password,
            output_path=str(request.output_path),
            capture_alarms=request.capture_alarms,
            capture_alarm_history=request.capture_alarm_history,
            debug=request.debug,
            log_callback=emit,
        )
    emit(f"Saved Network Audit report: {request.output_path}")
    return request.output_path
