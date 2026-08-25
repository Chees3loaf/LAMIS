"""Thin GUI-independent boundary around the audited RLS route core."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from utils.rls_config.route_bundle import export_route_bundle
from utils.rls_config.route_config import RouteConfigBuild, evaluate_route_configs
from utils.rls_config.route_project import PROFILE_LABELS, RouteProject, load_route_project_draft, save_route_project_draft


@dataclass(frozen=True)
class RouteShelfSummary:
    order: int
    shelf_id: str
    site: str
    tid: str
    role: str
    oam_ip: str
    review_state: str


@dataclass(frozen=True)
class RouteReview:
    shelves: tuple[RouteShelfSummary, ...]
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    ready: bool
    blockers: tuple[str, ...]


def load_route_draft(path: str | Path) -> RouteProject:
    return load_route_project_draft(Path(path))


def save_route_draft(project: RouteProject, path: str | Path) -> Path:
    return save_route_project_draft(project, Path(path))


def review_route(project: RouteProject) -> RouteReview:
    sites = {site.site_key: site for site in project.sites}
    shelves = tuple(
        RouteShelfSummary(
            order=order,
            shelf_id=shelf.shelf_id,
            site=(sites[shelf.site_key].code if shelf.site_key in sites else shelf.site_key),
            tid=shelf.tid,
            role=PROFILE_LABELS.get(shelf.profile_id, shelf.profile_id),
            oam_ip=shelf.primary_oam_ip,
            review_state=shelf.review_state,
        )
        for order, shelf in enumerate(project.shelves, 1)
    )
    issues = project.validate()
    errors = tuple(f"{issue.field}: {issue.message}" for issue in issues if issue.severity == "error")
    warnings = tuple(f"{issue.field}: {issue.message}" for issue in issues if issue.severity != "error")
    readiness = project.deployment_readiness()
    return RouteReview(shelves, errors, warnings, readiness.ready, tuple(readiness.blocking_reasons))


def evaluate_route(project: RouteProject) -> RouteConfigBuild:
    return evaluate_route_configs(project)


def publish_route_bundle(project: RouteProject, output_directory: str | Path) -> Mapping[str, Path]:
    destination = Path(output_directory)
    if not str(output_directory).strip():
        raise ValueError("Choose an output folder for the route bundle.")
    return export_route_bundle(project, destination)
