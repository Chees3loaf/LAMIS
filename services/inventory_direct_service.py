"""Headless LAN/Serial inventory collection for the PySide6 migration."""
from __future__ import annotations

from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib
import ipaddress
import logging
from pathlib import Path
from queue import Queue
import threading
from typing import Any, Callable, Sequence

import config
import script_interface
from services.raw_processing_service import create_raw_workbook_builder
from utils.credentials import load_credentials_from_config
from utils.helpers import clear_known_host_entry, get_data_dir


ProgressCallback = Callable[[str], None]
NumericProgressCallback = Callable[[int, int, str], None]
CredentialCallback = Callable[[str], tuple[str, str] | None]

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


@dataclass(frozen=True)
class NetworkInventoryRequest:
    targets: tuple[str, ...]
    output_path: Path
    customer: str
    project: str
    purchase_order: str
    sales_order: str
    append_mode: bool = False


@dataclass(frozen=True)
class NetworkInventoryOutcome:
    output_path: Path
    requested: int
    collected: int
    failed: dict[str, str]


class InventoryRunControl:
    def __init__(self) -> None:
        self.cancelled = threading.Event()
        self.paused = threading.Event()
        self._active_scripts: dict[str, Any] = {}
        self._lock = threading.Lock()

    def should_stop(self) -> bool:
        return self.cancelled.is_set()

    def set_script(self, script: Any | None, key: str = "direct") -> None:
        with self._lock:
            if script is None:
                self._active_scripts.pop(key, None)
            else:
                self._active_scripts[key] = script

    def cancel(self) -> None:
        self.cancelled.set()
        with self._lock:
            scripts = list(self._active_scripts.values())
        for script in scripts:
            if hasattr(script, "abort_connection"):
                try:
                    script.abort_connection()
                except Exception:
                    logging.exception("Could not abort an active inventory connection")

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


def expand_network_range(
    selection: str,
    start_host: str,
    end_host: str,
    start_third: str = "",
    end_third: str = "",
) -> list[str]:
    """Expand one Pod/Lab selector using the legacy addressing rules."""
    def octet(value: str, label: str) -> int:
        text = value.strip()
        if not text.isdigit() or not 0 <= int(text) <= 255:
            raise ValueError(f"{label} must be a number from 0 to 255.")
        return int(text)

    first_host = octet(start_host, "Start host octet")
    last_host = octet(end_host, "End host octet")
    if selection == config.LAB_LABEL:
        first_third = octet(start_third, "Start third octet")
        last_third = octet(end_third, "End third octet")
        start = ipaddress.IPv4Address(f"{config.LAB_NETWORK_PREFIX}.{first_third}.{first_host}")
        end = ipaddress.IPv4Address(f"{config.LAB_NETWORK_PREFIX}.{last_third}.{last_host}")
    else:
        try:
            pod = int(selection.removeprefix("Pod ").strip())
        except ValueError as exc:
            raise ValueError("Choose a valid Pod or Lab range.") from exc
        if not 1 <= pod <= config.POD_COUNT:
            raise ValueError("Choose a valid Pod or Lab range.")
        third = config.POD_THIRD_OCTET_BASE + pod
        start = ipaddress.IPv4Address(f"{config.POD_NETWORK_PREFIX}.{third}.{first_host}")
        end = ipaddress.IPv4Address(f"{config.POD_NETWORK_PREFIX}.{third}.{last_host}")
    if int(start) > int(end):
        raise ValueError("Start IP must be less than or equal to End IP.")
    return [str(ipaddress.IPv4Address(value)) for value in range(int(start), int(end) + 1)]


def combine_network_ranges(*ranges: Sequence[str]) -> tuple[str, ...]:
    targets = tuple(dict.fromkeys(ip for values in ranges for ip in values))
    if not targets:
        raise ValueError("Enter at least one IP range.")
    if len(targets) > config.MAX_SCAN_ADDRESSES:
        raise ValueError(
            f"The selection covers {len(targets)} addresses "
            f"(limit {config.MAX_SCAN_ADDRESSES})."
        )
    return targets


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
    request_credentials: CredentialCallback | None = None,
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
            credentials = request_credentials(request.target) if request_credentials else None
            if not credentials:
                raise RuntimeError("Default credentials were rejected by the device.")
            if hasattr(script, "username"):
                script.username = credentials[0]
            if hasattr(script, "password"):
                script.password = credentials[1]
            emit("Retrying with operator-provided credentials…")
            outputs_list, error = script.execute_commands(commands)
            if error == script_interface.NEEDS_CREDENTIALS_SENTINEL:
                raise RuntimeError("Operator-provided credentials were rejected by the device.")
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


def _collect_network_device(
    ip: str,
    outputs: dict[str, Any],
    families: dict[str, str],
    data_lock: threading.Lock,
    control: InventoryRunControl,
    emit: ProgressCallback,
    request_credentials: CredentialCallback | None,
) -> tuple[str, str | None]:
    """Identify and collect one host, returning ``(ip, error)``."""
    identifier = script_interface.DeviceIdentifier()
    selector = script_interface.ScriptSelector()
    device_queue: Queue = Queue()
    script = None
    credentials = None
    try:
        control.wait_if_paused()
        if control.should_stop():
            return ip, "ABORTED"
        emit(f"[{ip}] Identifying device type…")
        try:
            device_type, _device_name = identifier.identify_device(
                ip, device_queue, None, control.should_stop
            )
        except script_interface.CredentialPromptRequired:
            if request_credentials is None:
                return ip, "Default credentials rejected"
            emit(f"[{ip}] Default credentials rejected; requesting credentials…")
            credentials = request_credentials(ip)
            if not credentials:
                return ip, "Credentials were not provided"
            device_type, _device_name = identifier.identify_device(
                ip, device_queue, None, control.should_stop,
                explicit_credentials=credentials,
            )
        if control.should_stop():
            return ip, "ABORTED"
        if not device_type:
            return ip, "Identification failed"
        emit(f"[{ip}] Identified as {device_type}.")
        identified_credentials = identifier.take_identified_credentials()
        script = selector.select_script(
            device_type, ip, connection_type="ssh",
            stop_callback=control.should_stop,
            credentials=identified_credentials or credentials,
        )
        if script is None:
            return ip, f"Unknown device type: {device_type}"
        control.set_script(script, ip)
        kept_client = identifier.take_identified_client()
        if kept_client is not None and hasattr(script, "set_existing_ssh_client"):
            script.set_existing_ssh_client(kept_client)
        commands = script.get_commands() or []
        emit(f"[{ip}] Running {len(commands)} inventory command(s)…")
        raw, error = script.execute_commands(commands)
        if error == script_interface.NEEDS_CREDENTIALS_SENTINEL:
            if request_credentials is None:
                return ip, "Default credentials rejected"
            credentials = request_credentials(ip)
            if not credentials:
                return ip, "Credentials were not provided"
            if hasattr(script, "username"):
                script.username = credentials[0]
            if hasattr(script, "password"):
                script.password = credentials[1]
            raw, error = script.execute_commands(commands)
        if control.should_stop() or error == "Aborted":
            return ip, "ABORTED"
        if error:
            return ip, str(error)
        local_outputs: dict[str, Any] = {}
        if raw and hasattr(script, "process_outputs"):
            script.process_outputs(raw, ip, local_outputs)
        if not local_outputs:
            return ip, "No inventory data returned"
        with data_lock:
            outputs.update(local_outputs)
            families[ip] = _family(script)
        emit(f"[{ip}] Scan complete.")
        return ip, None
    except script_interface.CredentialPromptRequired:
        return ip, "User-provided credentials were rejected"
    except Exception as exc:
        logging.exception("Network inventory failed for %s", ip)
        return ip, str(exc)
    finally:
        if script is not None:
            control.set_script(None, ip)


def _export_network_inventory(
    request: NetworkInventoryRequest,
    outputs: dict[str, Any],
    families: dict[str, str],
    builder,
) -> None:
    buckets: dict[str, dict[str, Any]] = {"rls": {}, "psi": {}, "default": {}}
    for ip, data in outputs.items():
        buckets.setdefault(families.get(ip, "default"), {})[ip] = data
    populated = {family: values for family, values in buckets.items() if values}
    kwargs = dict(
        customer=request.customer.strip(), project=request.project.strip(),
        customer_po=request.purchase_order.strip(), sales_order=request.sales_order.strip(),
        append_mode=request.append_mode,
    )
    data_dir = get_data_dir()
    if len(populated) > 1:
        builder.build_unified_report_workbook(
            populated, str(request.output_path),
            rls_template_path=str(data_dir / "Ciena_RLS_Report_Template.xlsx"),
            psi_template_path=str(data_dir / "Nokia_PSI_Report_Template.xlsx"),
            **kwargs,
        )
    else:
        family, values = next(iter(populated.items()))
        if family in {"rls", "psi"}:
            template = "Ciena_RLS_Report_Template.xlsx" if family == "rls" else "Nokia_PSI_Report_Template.xlsx"
            builder.build_psi_report_workbook(
                values, str(request.output_path),
                psi_template_path=str(data_dir / template), **kwargs,
            )
        else:
            builder.build_report_workbook(values, str(request.output_path), **kwargs)


def run_network_inventory(
    request: NetworkInventoryRequest,
    *,
    progress: ProgressCallback | None = None,
    numeric_progress: NumericProgressCallback | None = None,
    request_credentials: CredentialCallback | None = None,
    control: InventoryRunControl | None = None,
    builder=None,
) -> NetworkInventoryOutcome:
    """Probe, identify, collect, and export a bounded Pod/Lab target set."""
    targets = combine_network_ranges(request.targets)
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

    emit = progress or (lambda _message: None)
    advance = numeric_progress or (lambda _current, _total, _label: None)
    run_control = control or InventoryRunControl()
    script_interface.get_tracker().reset()
    failed: dict[str, str] = {}
    reachable: list[str] = []
    emit(f"Phase 1/3 · Probing SSH/Telnet on {len(targets)} address(es)…")
    with ThreadPoolExecutor(max_workers=min(20, len(targets)), thread_name_prefix="atlas-probe") as pool:
        futures = {pool.submit(script_interface.probe_host, ip): ip for ip in targets}
        for index, future in enumerate(as_completed(futures), 1):
            if run_control.should_stop():
                pool.shutdown(wait=False, cancel_futures=True)
                raise RuntimeError("Inventory run aborted.")
            ip = futures[future]
            try:
                ok, reason = future.result()
            except Exception as exc:
                ok, reason = False, str(exc)
            if ok:
                reachable.append(ip)
            else:
                failed[ip] = reason or script_interface.PROBE_UNREACHABLE
            advance(index, len(targets), f"Probing {index}/{len(targets)}")
    emit(f"Probe complete — {len(reachable)} reachable, {len(targets) - len(reachable)} unavailable.")
    if not reachable:
        raise RuntimeError("No reachable devices were found; no report was saved.")

    outputs: dict[str, Any] = {}
    families: dict[str, str] = {}
    data_lock = threading.Lock()
    emit(f"Phase 2/3 · Scanning {len(reachable)} reachable device(s), up to 5 concurrently…")
    with ThreadPoolExecutor(max_workers=min(5, len(reachable)), thread_name_prefix="atlas-scan") as pool:
        futures = {
            pool.submit(
                _collect_network_device, ip, outputs, families, data_lock,
                run_control, emit, request_credentials,
            ): ip for ip in reachable
        }
        for index, future in enumerate(as_completed(futures), 1):
            if run_control.should_stop():
                pool.shutdown(wait=False, cancel_futures=True)
                raise RuntimeError("Inventory run aborted.")
            ip, error = future.result()
            if error == "ABORTED":
                raise RuntimeError("Inventory run aborted.")
            if error:
                failed[ip] = error
                emit(f"[{ip}] Failed: {error}")
            advance(index, len(reachable), f"Scanning {index}/{len(reachable)}")
    if not outputs:
        raise RuntimeError("No inventory data was collected; no report was saved.")

    if failed:
        emit("--- FAILED IPs ---")
        for ip, reason in failed.items():
            emit(f"{ip}: {reason}")
    emit(f"Phase 3/3 · Building report for {len(outputs)} device(s)…")
    request.output_path.parent.mkdir(parents=True, exist_ok=True)
    _export_network_inventory(request, outputs, families, builder or create_raw_workbook_builder())
    emit(f"Saved inventory report: {request.output_path}")
    return NetworkInventoryOutcome(request.output_path, len(targets), len(outputs), failed)
