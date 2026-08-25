from pathlib import Path
import sys
import types

import pytest

from services import software_upgrade_service as service
from services.software_upgrade_service import SoftwareUpgradeRequest, run_software_upgrade, validate_software_upgrade


class Server:
    def __init__(self, *args, **kwargs): self.closed = False
    def serve_forever(self): pass
    def shutdown(self): pass
    def server_close(self): self.closed = True


@pytest.fixture
def lifecycle(monkeypatch):
    calls = []
    import gui.software_upgrade_frame as legacy
    monkeypatch.setattr(legacy, "_set_static_ipv4", lambda nic, ip, mask: (calls.append(("static", nic, ip, mask)) or (True, "OK")))
    monkeypatch.setattr(legacy, "_run_netsh", lambda args: (calls.append(("netsh", args)) or (True, "OK")))
    monkeypatch.setattr(legacy, "_UpgradeHTTPServer", Server)
    monkeypatch.setattr(service.time, "sleep", lambda _n: None)
    return calls


def _script_module(monkeypatch, name, class_name, result=True, **attributes):
    captured = {}
    class Script:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            for key, value in attributes.items(): setattr(self, key, value)
        def run(self): return result
    monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(**{class_name: Script}))
    return captured


@pytest.mark.parametrize("family,module,class_name,filename", [
    ("Ciena RLS", "scripts.Network.Ciena_RLS_Upgrade", "RLSUpgradeScript", "load.bin"),
    ("Nokia G42", "scripts.Network.Nokia_G42_Upgrade", "NokiaG42UpgradeScript", "load.manifest"),
    ("Ciena Waveserver 5", "scripts.Network.Ciena_Waveserver5_Upgrade", "Waveserver5UpgradeScript", "load.tar.gz"),
])
def test_file_upgrade_dispatch_and_cleanup(tmp_path, monkeypatch, lifecycle, family, module, class_name, filename):
    path = tmp_path / filename; path.write_bytes(b"x")
    captured = _script_module(monkeypatch, module, class_name)
    request = SoftwareUpgradeRequest(family, str(path), "Ethernet", serial_port="COM4")
    outcome = run_software_upgrade(request)
    assert outcome.family == family and captured["stop_callback"]
    assert lifecycle[0][0] == "static" and sum(call[0] == "netsh" for call in lifecycle) == 2


@pytest.mark.parametrize("family,module,class_name", [
    ("Nokia PSI", "scripts.Network.Nokia_PSI_Upgrade", "NokiaPSIUpgradeScript"),
    ("Nokia PSS", "scripts.Network.Nokia_PSS_Upgrade", "NokiaPSSUpgradeScript"),
])
def test_cc_upgrade_dispatch(tmp_path, monkeypatch, lifecycle, family, module, class_name):
    release = tmp_path / "CC" / "1830OLS-25.3-3"; release.mkdir(parents=True)
    captured = _script_module(monkeypatch, module, class_name)
    run_software_upgrade(SoftwareUpgradeRequest(family, str(tmp_path), "Ethernet", inner_username="admin"))
    assert captured["software_filename"] == release.name and captured["inner_username"] == "admin"


def test_failure_still_restores_network(tmp_path, monkeypatch, lifecycle):
    path = tmp_path / "load.manifest"; path.write_bytes(b"x")
    _script_module(monkeypatch, "scripts.Network.Nokia_G42_Upgrade", "NokiaG42UpgradeScript", False)
    with pytest.raises(RuntimeError, match="did not complete"):
        run_software_upgrade(SoftwareUpgradeRequest("Nokia G42", str(path), "Ethernet"))
    assert sum(call[0] == "netsh" for call in lifecycle) == 2


def test_validation_explains_unzipped_cc_requirement(tmp_path):
    (tmp_path / "CC").mkdir()
    with pytest.raises(ValueError, match="unzipped software release"):
        validate_software_upgrade(SoftwareUpgradeRequest("Nokia PSI", str(tmp_path), "Ethernet"))
