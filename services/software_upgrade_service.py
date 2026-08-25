"""GUI-independent orchestration for supported ATLAS software upgrades."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import threading
import time
from typing import Callable


FAMILIES = ("Ciena RLS", "Ciena Waveserver 5", "Nokia G42", "Nokia PSI", "Nokia PSS")
NETWORKS = {
    "Ciena RLS CTM41": ("10.0.0.2", "10.0.0.1", "255.255.255.0"),
    "Ciena RLS CTM42": ("10.0.0.6", "10.0.0.5", "255.255.255.0"),
    "Ciena Waveserver 5": ("10.9.49.101", "10.9.49.36", "255.255.252.0"),
    "Nokia G42": ("169.254.0.101", "169.254.0.1", "255.255.255.0"),
    "Nokia PSI": ("172.16.0.101", "172.16.0.1", "255.255.255.0"),
    "Nokia PSS": ("172.16.0.101", "172.16.0.1", "255.255.255.0"),
}


@dataclass
class SoftwareUpgradeRequest:
    family: str
    software_path: str
    nic: str
    ctm: str = "CTM41"
    username: str = ""
    password: str = ""
    inner_username: str = ""
    inner_password: str = ""
    serial_port: str = ""


@dataclass(frozen=True)
class SoftwareUpgradeOutcome:
    family: str
    artifact: str
    completion_note: str


def list_upgrade_nics() -> list[str]:
    from gui.software_upgrade_frame import _list_nics
    return _list_nics()


def _resolve(request: SoftwareUpgradeRequest):
    if request.family not in FAMILIES: raise ValueError(f"Unsupported software-upgrade family: {request.family}")
    if not request.nic.strip(): raise ValueError("Select the wired network interface connected to the device.")
    selected = Path(request.software_path)
    if not selected.exists(): raise ValueError(f"Software path does not exist: {selected}")
    network_key = f"Ciena RLS {request.ctm}" if request.family == "Ciena RLS" else request.family
    if network_key not in NETWORKS: raise ValueError(f"Unsupported RLS CTM selection: {request.ctm}")
    pc_ip, device_ip, mask = NETWORKS[network_key]
    if request.family in {"Nokia PSI", "Nokia PSS"}:
        cc = selected if selected.name.casefold() == "cc" else selected / "CC"
        if not cc.is_dir(): raise ValueError("Select the software folder containing an unzipped CC directory.")
        releases = sorted(item for item in cc.iterdir() if item.is_dir())
        if not releases: raise ValueError("CC contains no unzipped software release folder. Extract the release into CC first.")
        artifact = releases[0].name; root = cc.parent
    else:
        if selected.is_dir():
            candidates = [item for item in selected.iterdir() if item.is_file()]
            if request.family == "Nokia G42": candidates = [item for item in candidates if item.suffix.casefold() == ".manifest"]
            if request.family == "Ciena Waveserver 5": candidates = [item for item in candidates if item.name.casefold().endswith(".tar.gz")]
            if not candidates: raise ValueError("The selected folder contains no compatible software artifact for this device family.")
            source = sorted(candidates)[0]
        else: source = selected
        artifact = source.name; root = source.parent
    if request.family == "Ciena Waveserver 5" and not request.serial_port.strip(): raise ValueError("Select the serial console port for the Waveserver 5 upgrade.")
    return root, artifact, pc_ip, device_ip, mask


def validate_software_upgrade(request: SoftwareUpgradeRequest) -> None:
    _resolve(request)


def run_software_upgrade(request: SoftwareUpgradeRequest, *, progress: Callable[[str], None] = lambda _message: None, should_stop: Callable[[], bool] = lambda: False) -> SoftwareUpgradeOutcome:
    root, artifact, pc_ip, device_ip, mask = _resolve(request)
    from gui.software_upgrade_frame import _UpgradeHTTPServer, _run_netsh, _set_static_ipv4
    server = None; server_thread = None; static_owned = False
    try:
        progress(f"Setting {request.nic} to {pc_ip}/{mask}…")
        ok, detail = _set_static_ipv4(request.nic, pc_ip, mask)
        if not ok: raise RuntimeError(f"Could not apply the required temporary static IP: {detail}")
        static_owned = True; progress(f"Temporary static IP applied: {detail}")
        if should_stop(): raise RuntimeError("Upgrade stopped before device execution; DHCP restoration is in progress.")
        def transfer(filename: str, sent: int, total: int, done: bool = False):
            percent = (sent / total * 100.0) if total else 0.0
            progress(f"HTTP {'complete' if done else 'transfer'}: {filename} — {sent}/{total} bytes ({percent:.1f}%)")
        server = _UpgradeHTTPServer(("0.0.0.0", 8000), directory=str(root), on_progress=transfer, on_log=progress)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True); server_thread.start()
        progress(f"HTTP server started at http://{pc_ip}:8000/ (root: {root})")
        time.sleep(0.2)
        callback = progress; stop = should_stop
        if request.family == "Ciena RLS":
            from scripts.Network.Ciena_RLS_Upgrade import RLSUpgradeScript
            runner = RLSUpgradeScript(ip_address=device_ip, username=request.username or "su", password=request.password, server_url=f"http://{pc_ip}:8000/{artifact}", output_callback=callback, stop_callback=stop)
            note = "RLS upgrade reported complete."
        elif request.family == "Nokia G42":
            from scripts.Network.Nokia_G42_Upgrade import NokiaG42UpgradeScript
            runner = NokiaG42UpgradeScript(ip_address=device_ip, username=request.username or "admin", password=request.password, server_url=f"http://{pc_ip}:8000/{artifact}", manifest_name=artifact, output_callback=callback, stop_callback=stop)
            note = "Activation in progress. Safe to disconnect."
        elif request.family in {"Nokia PSI", "Nokia PSS"}:
            if request.family == "Nokia PSI":
                from scripts.Network.Nokia_PSI_Upgrade import NokiaPSIUpgradeScript as Script
            else:
                from scripts.Network.Nokia_PSS_Upgrade import NokiaPSSUpgradeScript as Script
            runner = Script(ip_address=device_ip, username=request.username or "cli", password=request.password, inner_username=request.inner_username or "admin", inner_password=request.inner_password, software_filename=artifact, output_callback=callback, stop_callback=stop)
            note = "Activation in progress. Manual commit required. Safe to disconnect."
        else:
            from scripts.Network.Ciena_Waveserver5_Upgrade import Waveserver5UpgradeScript
            runner = Waveserver5UpgradeScript(serial_port=request.serial_port, software_filename=artifact, server_url=f"http://{pc_ip}:8000/{artifact}", device_ip=device_ip, device_ip_cidr="10.9.49.36/22", gateway_ip=pc_ip, hostname="WS5_1", output_callback=callback, stop_callback=stop)
            note = "Activation complete or in progress. Manual commit required. Safe to disconnect."
        if not runner.run(): raise RuntimeError("The device upgrade did not complete; review the device output for the failed phase.")
        if request.family == "Nokia G42" and getattr(runner, "standby_sync_warning", False): note = "Control cards are not synchronized. Perform the upgrade again on the second XMM4."
        return SoftwareUpgradeOutcome(request.family, artifact, note)
    finally:
        if server is not None:
            progress("Stopping the local HTTP server…"); server.shutdown(); server.server_close()
            if server_thread is not None: server_thread.join(timeout=3)
        if static_owned:
            progress(f"Restoring DHCP and DNS on {request.nic}…")
            ok, detail = _run_netsh(["interface", "ipv4", "set", "address", f"name={request.nic}", "source=dhcp"])
            _run_netsh(["interface", "ipv4", "set", "dnsservers", f"name={request.nic}", "source=dhcp"])
            if not ok: progress(f"WARNING: DHCP restoration failed: {detail}")
            else: progress("DHCP and DNS restoration complete.")
