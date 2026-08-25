from pathlib import Path

from services import rls_route_service
from services.rls_route_service import evaluate_route, load_route_draft, publish_route_bundle, review_route, save_route_draft
from utils.rls_config.route_project import RouteProject, ShelfInstance, Site


def _draft() -> RouteProject:
    return RouteProject(
        project_id="project-1", route_code="A-Z", title="A to Z",
        revision="1", sites=(Site("site-a", "A", "Alpha"),),
        shelves=(ShelfInstance("shelf-1", "add_drop_a", "RLS R4.0", "RLS", "site-a", "A-RLS-1", "192.0.2.1", "A/B -48 VDC"),),
    )


def test_review_preserves_order_and_reports_blockers():
    result = review_route(_draft())
    assert result.shelves[0].order == 1
    assert result.shelves[0].site == "A"
    assert result.shelves[0].tid == "A-RLS-1"
    assert not result.ready
    assert result.blockers


def test_draft_round_trip(tmp_path: Path):
    path = save_route_draft(_draft(), tmp_path / "route.json")
    loaded = load_route_draft(path)
    assert loaded.to_dict() == _draft().to_dict()


def test_evaluation_remains_fail_closed_for_unreviewed_shelf():
    result = evaluate_route(_draft())
    assert not result.ready
    assert result.config_count == 0


def test_publish_delegates_to_atomic_exporter(monkeypatch, tmp_path: Path):
    expected = {"project": tmp_path / "bundle" / "project.json"}
    calls = []
    monkeypatch.setattr(rls_route_service, "export_route_bundle", lambda project, output: calls.append((project, output)) or expected)
    assert publish_route_bundle(_draft(), tmp_path) == expected
    assert calls == [(_draft(), tmp_path)]


def test_publish_requires_output_folder():
    try:
        publish_route_bundle(_draft(), "")
    except ValueError as exc:
        assert "output folder" in str(exc)
    else:
        raise AssertionError("blank output folder was accepted")
