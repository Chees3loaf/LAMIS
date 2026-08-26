from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_provisioning_workflows_have_independent_navigation_entries() -> None:
    source = (ROOT / "gui_qt" / "main_window.py").read_text(encoding="utf-8")
    assert '"live-provisioning": LiveProvisioningWorkspace()' in source
    assert '"route-builder": RlsRouteWorkspace()' in source
    assert '"Live Provisioning", "live-provisioning"' in source
    assert '"Ciena Route Builder", "route-builder"' in source
    assert '"provisioning": ProvisioningPage()' not in source


def test_each_provisioning_workspace_has_its_own_heading() -> None:
    source = (ROOT / "gui_qt" / "provisioning_page.py").read_text(encoding="utf-8")
    assert '"Live Provisioning"' in source
    assert '"Ciena Route Builder"' in source
    assert 'layout.setSpacing(12)' in source
