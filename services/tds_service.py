"""UI-independent launcher for ATLAS TDS diagnostics."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable

import config
from utils.credentials import get_default_credential_for_vendor
from utils.helpers import ensure_host_key_known


CredentialCallback = Callable[[str], tuple[str, str] | None]
HostKeyVerifier = Callable[[str], bool]

_AUTH_FAILURE_RE = re.compile(
    r"(?i)\b(authentication failed|permission denied|login (?:failed|incorrect)|"
    r"invalid (?:credentials|username|password|login)|access denied|bad (?:username|password))\b"
)


@dataclass(frozen=True)
class TdsRequest:
    host: str
    platform: str
    file_name: str


@dataclass(frozen=True)
class TdsOutcome:
    host: str
    output: str


def is_valid_tds_host(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]*", value))


def validate_tds_request(request: TdsRequest) -> None:
    if not is_valid_tds_host(request.host):
        raise ValueError(f"Invalid TDS IP address or hostname: {request.host!r}")
    if request.platform not in {"rls", "6500"}:
        raise ValueError("TDS platform must be RLS or 6500.")
    if not request.file_name.strip():
        raise ValueError("TDS file name is required.")
    if Path(request.file_name).name != request.file_name or request.file_name in {".", ".."}:
        raise ValueError("TDS file name must be a file name, not a directory path.")


def _command_prefix() -> tuple[list[str], str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--tds-mode"], os.path.dirname(sys.executable)
    script = Path(__file__).resolve().parents[1] / "scripts" / "TDS" / "TDS_v6.2.py"
    if not script.is_file():
        raise FileNotFoundError(f"TDS script not found: {script}")
    return [sys.executable, str(script)], str(script.parent)


def run_tds(
    request: TdsRequest,
    *,
    request_credentials: CredentialCallback | None = None,
    verify_host_key: HostKeyVerifier | None = None,
    subprocess_runner=subprocess.run,
) -> TdsOutcome:
    validate_tds_request(request)
    verifier = verify_host_key or ensure_host_key_known
    if not verifier(request.host):
        raise RuntimeError(
            f"SSH host-key verification failed for {request.host}."
        )
    prefix, cwd = _command_prefix()

    def invoke(username: str, password: str):
        command = prefix + [
            "--non-interactive", "--host", request.host,
            "--platform", request.platform, "--username", username,
            "--file-name", request.file_name, "--read-password-stdin",
        ]
        if request.platform == "rls":
            command.extend(["--validate", "--walk-mode"])
        return subprocess_runner(
            command, input=password, capture_output=True, text=True, cwd=cwd,
            timeout=config.TDS_TIMEOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    credentials = get_default_credential_for_vendor("ciena")
    result = invoke(*credentials) if credentials else None
    combined = "" if result is None else "\n".join(
        part for part in (result.stdout or "", result.stderr or "") if part
    )
    needs_credentials = result is None or (
        result.returncode != 0 and bool(_AUTH_FAILURE_RE.search(combined))
    )
    if needs_credentials:
        answer = request_credentials(request.host) if request_credentials else None
        if not answer:
            raise RuntimeError("No working credentials were provided; TDS did not run.")
        result = invoke(*answer)
        combined = "\n".join(
            part for part in (result.stdout or "", result.stderr or "") if part
        )
    if result.returncode != 0:
        detail = combined.strip() or f"TDS exited with code {result.returncode}."
        raise RuntimeError(detail)
    return TdsOutcome(request.host, combined.strip())
