from pathlib import Path

from services import rls_route_service
from services.rls_route_service import evaluate_route, load_route_draft, move_route_shelf, new_route_project, publish_route_bundle, remove_route_shelf, review_route, save_route_draft, update_route_details, upsert_route_shelf
from utils.rls_config.route_project import OpticalPath, RouteLink, RouteProject, ShelfInstance, Site


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


def test_new_project_and_metadata_update():
    project = new_route_project()
    assert project.revision == "1" and not project.shelves
    updated = update_route_details(project, route_code=" A-Z ", title=" Route ", revision=" A ", ospf_area="0.0.0.0", notes="note")
    assert (updated.route_code, updated.title, updated.revision) == ("A-Z", "Route", "A")


def test_add_and_edit_shelf_preserves_audited_payload():
    project = upsert_route_shelf(new_route_project(), site_code="A", site_name="Alpha", profile_id="add_drop_a", tid="A-RLS-1", primary_oam_ip="192.0.2.1")
    original = project.shelves[0]
    reviewed = ShelfInstance(**{**original.__dict__, "profile_payload": {"provider": "audited"}, "review_state": "confirmed", "source_evidence": {"source": "operator"}})
    project = RouteProject(**{**project.__dict__, "shelves": (reviewed,)})
    edited = upsert_route_shelf(project, shelf_id=reviewed.shelf_id, site_code="A", site_name="Alpha", profile_id="add_drop_a", tid="A-RLS-RENAMED", primary_oam_ip="192.0.2.2")
    assert edited.shelves[0].profile_payload == {"provider": "audited"}
    assert edited.shelves[0].source_evidence == {"source": "operator"}
    assert edited.shelves[0].review_state == "confirmed"


def test_remove_shelf_removes_attached_links():
    first = upsert_route_shelf(new_route_project(), site_code="A", site_name="Alpha", profile_id="add_drop_a", tid="A", primary_oam_ip="192.0.2.1")
    project = upsert_route_shelf(first, site_code="Z", site_name="Zulu", profile_id="add_drop_z", tid="Z", primary_oam_ip="192.0.2.2")
    a, z = project.shelves
    link = RouteLink("link-1", 1, a.shelf_id, z.shelf_id, paths=(OpticalPath("path-1", "route", "A-Z", 1.0, 1.0, "NDSF", "C", 1, 2),))
    project = RouteProject(**{**project.__dict__, "links": (link,)})
    result = remove_route_shelf(project, a.shelf_id)
    assert result.shelves == (z,) and not result.links


def test_reorder_is_blocked_when_reviewed_links_exist():
    project = upsert_route_shelf(new_route_project(), site_code="A", site_name="Alpha", profile_id="add_drop_a", tid="A", primary_oam_ip="192.0.2.1")
    project = upsert_route_shelf(project, site_code="Z", site_name="Zulu", profile_id="add_drop_z", tid="Z", primary_oam_ip="192.0.2.2")
    a, z = project.shelves
    link = RouteLink("link-1", 1, a.shelf_id, z.shelf_id)
    project = RouteProject(**{**project.__dict__, "links": (link,)})
    try: move_route_shelf(project, z.shelf_id, -1)
    except ValueError as exc: assert "links exist" in str(exc)
    else: raise AssertionError("linked route was reordered")
