"""Thin GUI-independent boundary around the audited RLS route core."""
from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping
from uuid import uuid4

from utils.rls_config.route_bundle import export_route_bundle
from utils.rls_config.route_config import RouteConfigBuild, evaluate_route_configs
from utils.rls_config.route_project import PROFILE_LABELS, PROFILE_REGISTRY, RouteProject, ShelfInstance, Site, load_route_project_draft, save_route_project_draft


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


def new_route_project() -> RouteProject:
    return RouteProject(project_id=uuid4().hex, route_code="", title="", revision="1")


def route_profile_choices() -> tuple[tuple[str, str], ...]:
    return tuple(PROFILE_LABELS.items())


def update_route_details(project: RouteProject, *, route_code: str, title: str, revision: str, ospf_area: str = "", notes: str = "") -> RouteProject:
    if not isinstance(project, RouteProject):
        raise TypeError("project must be a RouteProject")
    return replace(project, route_code=route_code.strip(), title=title.strip(), revision=revision.strip(), ospf_area=ospf_area.strip(), notes=notes)


def upsert_route_shelf(
    project: RouteProject, *, shelf_id: str = "", site_code: str,
    site_name: str, profile_id: str, tid: str, primary_oam_ip: str,
    software_release: str = "RLS R4.0", shelf_variant: str = "RLS",
    power_label: str = "A/B -48 VDC", raman_label: str = "", notes: str = "",
) -> RouteProject:
    if profile_id not in PROFILE_REGISTRY:
        raise ValueError(f"Unsupported RLS route role: {profile_id}")
    code = site_code.strip(); name = site_name.strip()
    if not code or not name:
        raise ValueError("Site code and site name are required.")
    if not tid.strip():
        raise ValueError("Shelf TID is required.")
    existing_index = next((i for i, shelf in enumerate(project.shelves) if shelf.shelf_id == shelf_id), None)
    existing = project.shelves[existing_index] if existing_index is not None else None
    matching_site = next((site for site in project.sites if site.code.casefold() == code.casefold()), None)
    if matching_site is not None and matching_site.name.casefold() != name.casefold():
        raise ValueError(f"Site code {code!r} already uses site name {matching_site.name!r}.")
    site = matching_site or Site(site_key=f"site-{uuid4().hex}", code=code, name=name)
    shelf = ShelfInstance(
        shelf_id=existing.shelf_id if existing else uuid4().hex,
        profile_id=profile_id, software_release=software_release.strip(),
        shelf_variant=shelf_variant.strip(), site_key=site.site_key,
        tid=tid.strip(), primary_oam_ip=primary_oam_ip.strip(),
        power_label=power_label.strip(), raman_label=raman_label.strip(), notes=notes,
        profile_payload=existing.profile_payload if existing else {},
        review_state=existing.review_state if existing else "manual",
        source_evidence=existing.source_evidence if existing else {},
    )
    shelves = list(project.shelves)
    if existing_index is None: shelves.append(shelf)
    else: shelves[existing_index] = shelf
    sites = list(project.sites)
    if matching_site is None: sites.append(site)
    used = {item.site_key for item in shelves}
    sites = [item for item in sites if item.site_key in used]
    return replace(project, sites=tuple(sites), shelves=tuple(shelves))


def remove_route_shelf(project: RouteProject, shelf_id: str) -> RouteProject:
    shelves = tuple(shelf for shelf in project.shelves if shelf.shelf_id != shelf_id)
    if len(shelves) == len(project.shelves):
        raise ValueError("The selected shelf no longer exists in the project.")
    used = {shelf.site_key for shelf in shelves}
    sites = tuple(site for site in project.sites if site.site_key in used)
    links = tuple(link for link in project.links if link.from_shelf_id != shelf_id and link.to_shelf_id != shelf_id)
    return replace(project, shelves=shelves, sites=sites, links=links)


def move_route_shelf(project: RouteProject, shelf_id: str, offset: int) -> RouteProject:
    shelves = list(project.shelves)
    index = next((i for i, shelf in enumerate(shelves) if shelf.shelf_id == shelf_id), None)
    if index is None: raise ValueError("The selected shelf no longer exists in the project.")
    target = index + offset
    if target < 0 or target >= len(shelves): return project
    if project.links:
        raise ValueError("Shelf order cannot change while route links exist. Remove or rebuild the reviewed topology in the diagram workflow first.")
    shelves[index], shelves[target] = shelves[target], shelves[index]
    return replace(project, shelves=tuple(shelves))
