"""Headless LAN/Serial inventory collection for the PySide6 migration."""
from __future__ import annotations

from dataclasses import dataclass
import importlib
import ipaddress
import logging
from pathlib import Path
import threading
from typing import Any, Callable

import script_interface
from services.raw_processing_service import create_raw_workbook_builder
from utils.credentials import load_credentials_from_config
from utils.helpers import clear_known_host_entry, get_data_dir


ProgressCallback = Callable[[str], None]

SCRIPT_MODULES = {
    "Nokia SAR": "scripts.Nokia_SAR",
    "Nokia IXR": "scripts.Nokia_IXR",
    "Nokia PSS": "scripts.Nokia_1830",
    "Nokia PSI": "scripts.Nokia_PSI",
    "Ciena 6500": "scripts.Ciena_6500",
    "Ciena RLS": "scripts.Ciena_RLS",
    "Ciena Waveserver 5": "scripts.Ciena_Waveserver5",
}
LAN_SCRIPTS = ("Nokia PSS", "Nokia PSI", "Ciena 6500", "Ciena RLS")
SERIAL_SCRIPTS = ("Nokia SAR", "Nokia IXR", "Nokia PSI", "Ciena RLS", "Ciena Waveserver 5")
LAN_CONNECTION_TYPES = {"Nokia PSI": "telnet"}


@dataclass(frozen=True)
class DirectInventoryRequest:
    mode: str
    script_name: str
    target: str
    output_path: Path
    customer: str
    project: str
    purchase_order: str
    sales_order: str
    baud_rate: int = 9600
    append_mode: bool = False


@dataclass(frozen=True)
class DirectInventoryOutcome:
    output_path: Path
    target: str
    family: str


class InventoryRunControl:
    def __init__(self) -> None:
        self.cancelled = threading.Event()
        self.paused = threading.Event()
        self._active_script: Any | None = None
        self._lock = threading.Lock()

    def should_stop(self) -> bool:
        return self.cancelled.is_set()

    def set_script(self, script: Any | None) -> None:
        with self._lock:
            self._active_script = script

    def cancel(self) -> None:
        self.cancelled.set()
        with self._lock:
            script = self._active_script
        if script is not None and hasattr(script, "abort_connection"):
            script.abort_connection()

    def wait_if_paused(self) -> None:
        while self.paused.is_set() and not self.cancelled.wait(0.1):
            pass


def validate_direct_request(request: DirectInventoryRequest) -> None:
    if request.mode not in {"LAN", "Serial"}:
        raise ValueError("Connection mode must be LAN or Serial.")
    allowed = LAN_SCRIPTS if request.mode == "LAN" else SERIAL_SCRIPTS
    if request.script_name not in allowed:
        raise ValueError(f"{request.script_name} is not supported in {request.mode} mode.")
    if request.mode == "LAN":
        try:
            ipaddress.ip_address(request.target)
        except ValueError as exc:
            raise ValueError("LAN target must be a valid IP address.") from exc
    elif not request.target.strip():
        raise ValueError("Serial port is required.")
    if request.baud_rate <= 0:
        raise ValueError("Baud rate must be positive.")
    if request.output_path.suffix.lower() != ".xlsx":
        raise ValueError("Inventory output must be an .xlsx workbook.")
    for label, value in (
        ("Customer", request.customer), ("Project", request.project),
        ("Purchase order", request.purchase_order), ("Sales order", request.sales_order),
    ):
        if not value.strip():
            raise ValueError(f"{label} is required.")
    if request.append_mode and not request.output_path.is_file():
        raise ValueError("The append-mode inventory workbook no longer exists.")


def _family(script: Any) -> str:
    module = type(script).__module__
    if module.endswith("Ciena_RLS"):
        return "rls"
    if module.endswith("Nokia_PSI"):
        return "psi"
    return "default"


def _build_script(request: DirectInventoryRequest, control: InventoryRunControl):
    module_name = SCRIPT_MODULES[request.script_name]
    module = importlib.import_module(module_name)
    username, password = load_credentials_from_config()
    kwargs = {
        "db_cache": script_interface.get_cache(),
        "command_tracker": script_interface.get_tracker(),
        "stop_callback": control.should_stop,
        "username": username or "",
        "password": password or "",
    }
    if request.mode == "LAN":
        connection_type = LAN_CONNECTION_TYPES.get(request.script_name, "ssh")
        if connection_type == "telnet":
            from utils.telnet_policy import add_telnet_allowlist
            add_telnet_allowlist(request.target, f"auto: {request.script_name} LAN inventory (operator-selected)")
        kwargs.update(connection_type=connection_type, ip_address=request.target)
    else:
        kwargs.update(connection_type="serial", serial_port=request.target, baud_rate=request.baud_rate)
    return module.Script(**kwargs)


def run_direct_inventory(
    request: DirectInventoryRequest,
    *,
    progress: ProgressCallback | None = None,
    control: InventoryRunControl | None = None,
    builder=None,
) -> DirectInventoryOutcome:
    validate_direct_request(request)
    emit = progress or (lambda _message: None)
    run_control = control or InventoryRunControl()
    tracker = script_interface.get_tracker()
    tracker.reset()
    request.output_path.parent.mkdir(parents=True, exist_ok=True)

    emit(f"Preparing {request.mode} inventory for {request.target}…")
    script = _build_script(request, run_control)
    run_control.set_script(script)
    try:
        run_control.wait_if_paused()
        if run_control.should_stop():
            raise RuntimeError("Inventory run aborted.")
        commands = script.get_commands() or []
        emit(f"Connecting and running {len(commands)} inventory command(s)…")
        outputs_list, error = script.execute_commands(commands)
        if run_control.should_stop() or error == "Aborted":
            raise RuntimeError("Inventory run aborted.")
        if error == script_interface.NEEDS_CREDENTIALS_SENTINEL:
            raise RuntimeError("Default credentials were rejected by the device.")
        if error:
            raise RuntimeError(str(error))
        outputs: dict[str, Any] = {}
        if outputs_list and hasattr(script, "process_outputs"):
            script.process_outputs(outputs_list, request.target, outputs)
        if not outputs:
            raise RuntimeError("No inventory data was collected; no report was saved.")

        family = _family(script)
        emit(f"Collection complete. Building {family} inventory workbook…")
        workbook_builder = builder or create_raw_workbook_builder()
        kwargs = dict(
            customer=request.customer.strip(), project=request.project.strip(),
            customer_po=request.purchase_order.strip(), sales_order=request.sales_order.strip(),
            append_mode=request.append_mode,
        )
        data_dir = get_data_dir()
        if family == "rls":
            workbook_builder.build_psi_report_workbook(
                outputs, str(request.output_path),
                psi_template_path=str(data_dir / "Ciena_RLS_Report_Template.xlsx"), **kwargs,
            )
        elif family == "psi":
            workbook_builder.build_psi_report_workbook(
                outputs, str(request.output_path),
                psi_template_path=str(data_dir / "Nokia_PSI_Report_Template.xlsx"), **kwargs,
            )
        else:
            workbook_builder.build_report_workbook(outputs, str(request.output_path), **kwargs)
        emit(f"Saved inventory report: {request.output_path}")
        return DirectInventoryOutcome(request.output_path, request.target, family)
    finally:
        run_control.set_script(None)
        if request.mode == "LAN":
            try:
                clear_known_host_entry(request.target)
            except Exception:
                logging.exception("Failed to clear known_hosts after LAN inventory")
