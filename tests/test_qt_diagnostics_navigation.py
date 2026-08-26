from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_diagnostic_workflows_have_independent_navigation_entries() -> None:
    source = (ROOT / "gui_qt" / "main_window.py").read_text(encoding="utf-8")
    assert '"tds-diagnostics": TdsDiagnosticsWorkspace()' in source
    assert '"network-audit": NetworkAuditWorkspace()' in source
    assert '"TDS Diagnostics", "tds-diagnostics"' in source
    assert '"Network Audit", "network-audit"' in source
    assert '"diagnostics": DiagnosticsPage()' not in source


def test_diagnostics_no_longer_use_a_nested_tab_widget() -> None:
    source = (ROOT / "gui_qt" / "diagnostics_page.py").read_text(encoding="utf-8")
    assert "QTabWidget" not in source
    assert '"TDS Diagnostics"' in source
    assert '"Network Audit"' in source


def test_overview_cards_use_the_split_workflow_targets() -> None:
    source = (ROOT / "gui_qt" / "pages.py").read_text(encoding="utf-8")
    assert '"TDS Diagnostics"' in source and '"tds-diagnostics"' in source
    assert '"Network Audit"' in source and '"network-audit"' in source
    assert '"Live Provisioning"' in source and '"live-provisioning"' in source
    assert '"Ciena Route Builder"' in source and '"route-builder"' in source
