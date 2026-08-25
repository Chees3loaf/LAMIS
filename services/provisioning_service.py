"""GUI-independent live device provisioning orchestration."""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path
from typing import Callable, Iterable

import openpyxl


DEVICE_TYPES = (
    "Auto (from hostname)", "Nokia 7705 SAR", "Nokia 7250 IXR",
    "Nokia 1830 OLS", "Ciena SAOS 6.21.5", "Ciena SAOS 10",
)
DEVICE_TYPE_MAP = {
    "Auto (from hostname)": None, "Nokia 7705 SAR": "7705",
    "Nokia 7250 IXR": "7250", "Nokia 1830 OLS": "ols",
    "Ciena SAOS 6.21.5": "saos", "Ciena SAOS 10": "saos10",
}


@dataclass(frozen=True)
class ProvisioningDevice:
    ip: str
    hostname: str = ""
    prefix: str = ""
    gateway: str = ""
    static_route: str = ""

    @property
    def label(self) -> str:
        return f"{self.hostname}  ({self.ip})"


@dataclass
class ProvisioningRequest:
    device: ProvisioningDevice
    device_type_label: str = DEVICE_TYPES[0]
    connection_type: str = "ssh"
    connect_ip: str = ""
    serial_port: str = ""
    baud_rate: int = 115200
    username: str = ""
    password: str = ""
    prefix_len: int = 22
    gateway: str = ""
    static_route_dest: str = "10.0.0.0/8"
    configure_card: bool = False
    sync_redundancy: bool = False
    saos_vlan_id: str = "4000"
    saos_iface_name: str = "mgmt"
    saos_vlan_name: str = "mgmt"
    saos_mgmt_port: str = ""
    saos_protocols: set[str] = field(default_factory=lambda: {"SSH", "SNMP", "NTP", "Syslog", "RADIUS", "TACACS"})
    update_existing: bool = False
    saos10_src_iface: str = ""
    ols_shelf_type: str = "auto"
    ols_set_loopback: bool = False


def read_provisioning_devices(path: str | Path) -> list[ProvisioningDevice]:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Device workbook does not exist: {source}")
    if source.suffix.lower() != ".xlsx":
        raise ValueError("Device list must be an .xlsx workbook.")
    workbook = openpyxl.load_workbook(source, read_only=True, data_only=True)
    try:
        rows = list(workbook.active.iter_rows(values_only=True))
    finally:
        workbook.close()
    header_index = next((i for i, row in enumerate(rows) if any(value is not None for value in row)), None)
    if header_index is None:
        raise ValueError("Device workbook is empty.")
    aliases = {
        "ip": {"ip", "management ip", "mgmt ip", "mgmt_ip", "management_ip"},
        "hostname": {"hostname", "host name", "host_name", "name"},
        "prefix": {"subnet", "prefix", "prefix len", "prefix_len", "prefix length"},
        "gateway": {"gateway", "gw", "next-hop", "next hop", "nexthop"},
        "static_route": {"static route", "static route dest", "static_route", "static_route_dest"},
    }
    headers = [str(value).strip().lower() if value is not None else "" for value in rows[header_index]]
    columns = {name: next((i for i, header in enumerate(headers) if header in names), None) for name, names in aliases.items()}
    if columns["ip"] is None or columns["hostname"] is None:
        raise ValueError("Device workbook requires IP and Hostname columns.")

    def value(row: Iterable[object], name: str) -> str:
        cells = list(row)
        index = columns[name]
        return "" if index is None or index >= len(cells) or cells[index] is None else str(cells[index]).strip()

    devices = [ProvisioningDevice(value(row, "ip"), value(row, "hostname"), value(row, "prefix"), value(row, "gateway"), value(row, "static_route")) for row in rows[header_index + 1:] if value(row, "ip") and value(row, "hostname")]
    if not devices:
        raise ValueError("No devices were found beneath the IP and Hostname headers.")
    return devices


def validate_provisioning_request(request: ProvisioningRequest) -> None:
    try:
        IPv4Address(request.device.ip)
    except ValueError as exc:
        raise ValueError(f"Target IP is not a valid IPv4 address: {request.device.ip!r}") from exc
    if request.device_type_label not in DEVICE_TYPE_MAP:
        raise ValueError(f"Unsupported device type: {request.device_type_label}")
    device_type = DEVICE_TYPE_MAP[request.device_type_label]
    if not request.device.hostname and device_type is None:
        raise ValueError("Enter a hostname or select a specific device type; Auto cannot infer a type without a hostname.")
    if not request.device.hostname and device_type in {"7705", "7250"}:
        raise ValueError("Nokia 7705/7250 provisioning requires a hostname.")
    if request.connection_type not in {"ssh", "serial"}:
        raise ValueError("Connection type must be LAN (SSH) or Serial.")
    if request.connection_type == "ssh":
        try:
            IPv4Address(request.connect_ip or request.device.ip)
        except ValueError as exc:
            raise ValueError("SSH connection IP must be a valid IPv4 address.") from exc
    elif not request.serial_port.strip():
        raise ValueError("Select a serial port before provisioning.")
    if not request.gateway.strip():
        raise ValueError("Gateway is required.")
    try:
        IPv4Address(request.gateway)
    except ValueError as exc:
        raise ValueError(f"Gateway is not a valid IPv4 address: {request.gateway!r}") from exc
    if not 0 <= request.prefix_len <= 32:
        raise ValueError("Subnet prefix must be between 0 and 32.")
    if request.baud_rate <= 0:
        raise ValueError("Baud rate must be greater than zero.")


def run_live_provisioning(request: ProvisioningRequest, *, progress: Callable[[str], None] = lambda _message: None, should_stop: Callable[[], bool] = lambda: False) -> bool:
    validate_provisioning_request(request)
    device = request.device
    device_type = DEVICE_TYPE_MAP[request.device_type_label]
    common = dict(
        connection_type=request.connection_type,
        serial_port=request.serial_port if request.connection_type == "serial" else None,
        baud_rate=request.baud_rate,
        timeout=15,
        ip_address=(request.connect_ip or device.ip) if request.connection_type == "ssh" else None,
        username=request.username,
        password=request.password,
        hostname=device.hostname,
        target_ip=device.ip,
        gateway=request.gateway,
        stop_callback=should_stop,
        output_callback=progress,
    )
    progress(f"Provisioning {device.hostname or device.ip} ({request.device_type_label})")
    if device_type == "saos":
        from scripts.Network.Ciena_SAOS import Script
        runner = Script(**common, vlan_id=request.saos_vlan_id or "4000", iface_name=request.saos_iface_name or "mgmt", vlan_name=request.saos_vlan_name or "mgmt", mgmt_port=request.saos_mgmt_port, static_route_dest=request.static_route_dest or "0.0.0.0/0", protocols=request.saos_protocols, update_existing=request.update_existing)
    elif device_type == "saos10":
        from scripts.Network.Ciena_SAOS10 import Script
        runner = Script(**common, prefix_len=request.prefix_len, static_route_dest=request.static_route_dest or "0.0.0.0/0", global_src_iface=request.saos10_src_iface, update_existing=request.update_existing)
    elif device_type == "ols":
        from scripts.Network.Nokia_OLS import Script
        runner = Script(**common, prefix_len=request.prefix_len, shelf_type=request.ols_shelf_type, set_loopback=request.ols_set_loopback)
    else:
        from scripts.Network.Nokia_Provision import Script
        # This script logs its own command stream; suppress duplicate callback lines.
        common["output_callback"] = lambda _message: None
        common["timeout"] = 10
        runner = Script(**common, prefix_len=request.prefix_len, static_route_dest=request.static_route_dest or "10.0.0.0/8", device_type=device_type, configure_card=request.configure_card, sync_redundancy=request.sync_redundancy)
    success = bool(runner.run())
    if not success and not should_stop():
        raise RuntimeError(f"Provisioning did not complete for {device.hostname or device.ip}; review the device output for the rejected command or connection failure.")
    return success
