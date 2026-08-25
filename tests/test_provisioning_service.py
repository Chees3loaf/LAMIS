from pathlib import Path
import sys
import types

import openpyxl
import pytest

from services.provisioning_service import ProvisioningDevice, ProvisioningRequest, read_provisioning_devices, run_live_provisioning, validate_provisioning_request


def test_reads_device_workbook(tmp_path: Path):
    path = tmp_path / "devices.xlsx"
    workbook = openpyxl.Workbook(); sheet = workbook.active
    sheet.append(["Management IP", "Host Name", "Prefix", "GW"])
    sheet.append(["10.1.2.3", "TEST-1", 24, "10.1.2.1"]); workbook.save(path)
    assert read_provisioning_devices(path) == [ProvisioningDevice("10.1.2.3", "TEST-1", "24", "10.1.2.1", "")]


@pytest.mark.parametrize("change, message", [
    ({"device": ProvisioningDevice("bad", "TEST")}, "valid IPv4"),
    ({"device": ProvisioningDevice("10.1.2.3", ""), "device_type_label": "Auto (from hostname)"}, "hostname"),
    ({"connection_type": "serial", "serial_port": ""}, "serial port"),
    ({"gateway": ""}, "Gateway"),
])
def test_validation_is_actionable(change, message):
    values = dict(device=ProvisioningDevice("10.1.2.3", "TEST"), device_type_label="Ciena SAOS 10", connect_ip="10.1.2.3", gateway="10.1.2.1")
    values.update(change)
    with pytest.raises(ValueError, match=message): validate_provisioning_request(ProvisioningRequest(**values))


@pytest.mark.parametrize("label,module_name,expected", [
    ("Nokia 7705 SAR", "scripts.Network.Nokia_Provision", {"device_type": "7705", "prefix_len": 22}),
    ("Ciena SAOS 6.21.5", "scripts.Network.Ciena_SAOS", {"vlan_id": "4000", "protocols": {"SSH"}}),
    ("Ciena SAOS 10", "scripts.Network.Ciena_SAOS10", {"global_src_iface": "loopback"}),
    ("Nokia 1830 OLS", "scripts.Network.Nokia_OLS", {"shelf_type": "psi", "set_loopback": True}),
])
def test_dispatches_device_script(monkeypatch, label, module_name, expected):
    captured = {}
    class Script:
        def __init__(self, **kwargs): captured.update(kwargs)
        def run(self): return True
    monkeypatch.setitem(sys.modules, module_name, types.SimpleNamespace(Script=Script))
    request = ProvisioningRequest(device=ProvisioningDevice("10.1.2.3", "TEST"), device_type_label=label, connect_ip="10.1.2.3", gateway="10.1.2.1", saos_protocols={"SSH"}, saos10_src_iface="loopback", ols_shelf_type="psi", ols_set_loopback=True)
    assert run_live_provisioning(request)
    for key, value in expected.items(): assert captured[key] == value


def test_false_script_result_becomes_descriptive_failure(monkeypatch):
    class Script:
        def __init__(self, **_kwargs): pass
        def run(self): return False
    monkeypatch.setitem(sys.modules, "scripts.Network.Ciena_SAOS10", types.SimpleNamespace(Script=Script))
    request = ProvisioningRequest(device=ProvisioningDevice("10.1.2.3", "TEST"), device_type_label="Ciena SAOS 10", connect_ip="10.1.2.3", gateway="10.1.2.1")
    with pytest.raises(RuntimeError, match="did not complete"): run_live_provisioning(request)
