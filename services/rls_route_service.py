"""Thin GUI-independent boundary around the audited RLS route core."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path
from typing import Mapping
from uuid import uuid4

from utils.rls_config.route_bundle import export_route_bundle
from utils.rls_config.route_config import RouteConfigBuild, evaluate_route_configs
from utils.rls_config.route_project import PROFILE_LABELS, PROFILE_REGISTRY, RouteProject, ShelfInstance, Site, load_route_project_draft, save_route_project_draft
from utils.rls_config.common import DEFAULT_R40_TARGET_BUILD_SCHEMA, ManagementInterface, ROUTING_OSPF_OSC_ONLY
from utils.rls_config.r4_0_generator import R40_PROVIDER_CATALOG, R40ExactConfigGenerator, R40ExactRequest, R40LinePath, decode_r40_exact_payload, encode_r40_exact_payload


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


def publish_route_bundle(project: RouteProject, output_directory: str | Path, *, diagram=None) -> Mapping[str, Path]:
    destination = Path(output_directory)
    if not str(output_directory).strip():
        raise ValueError("Choose an output folder for the route bundle.")
    return export_route_bundle(project, destination, diagram=diagram)


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


def exact_provider_choices(profile_id: str) -> tuple[tuple[str, str], ...]:
    return tuple(
        (provider.provider_id, provider.display_name)
        for provider in R40_PROVIDER_CATALOG.values()
        if profile_id in provider.role_profiles
    )


def exact_payload_template(project: RouteProject, shelf_id: str, provider_id: str) -> str:
    shelf = next((item for item in project.shelves if item.shelf_id == shelf_id), None)
    if shelf is None: raise ValueError("Select a shelf before creating an exact-provider template.")
    provider = R40_PROVIDER_CATALOG.get(provider_id)
    if provider is None or shelf.profile_id not in provider.role_profiles:
        raise ValueError("The selected exact provider is not compatible with this shelf role.")
    site = project.site_by_key(shelf.site_key)
    line = lambda number: R40LinePath(
        link_name=provider.line_link_names[number - 1], neighbor_node="REVIEW-PEER",
        neighbor_line_mux_pfg=provider.line_pfg_names[number - 1][0],
        neighbor_line_demux_pfg=provider.line_pfg_names[number - 1][1],
        fiber_type="NDSF", expected_loss_db=1.0,
    )
    colan_enabled = provider.colan_policy != "prohibited"
    request = R40ExactRequest(
        provider_id=provider.provider_id, profile=shelf.profile_id,
        software_release="RLS R4.0", target_software_build=DEFAULT_R40_TARGET_BUILD_SCHEMA,
        chassis_family=provider.chassis_family, chassis_pec=provider.chassis_pec,
        hardware_profile=provider.hardware_profile, shelf_name=shelf.tid,
        site_name=site.name if site else "", member_name=shelf.tid,
        hostname=shelf.tid, frame_identification_code="", loopback_ip=shelf.primary_oam_ip,
        ospf_area=project.ospf_area, line_1=line(1),
        line_2=line(2) if len(provider.line_outputs) > 1 else None,
        line_1_route_side="A", shelf_label=shelf.notes,
        management=ManagementInterface(enabled=colan_enabled, routing_mode=(ManagementInterface().routing_mode if colan_enabled else ROUTING_OSPF_OSC_ONLY)),
    )
    return json.dumps(encode_r40_exact_payload(request), indent=2, ensure_ascii=False)


def validate_exact_payload(project: RouteProject, shelf_id: str, payload_text: str):
    shelf = next((item for item in project.shelves if item.shelf_id == shelf_id), None)
    if shelf is None: raise ValueError("Select a shelf before validating an exact-provider payload.")
    try: raw = json.loads(payload_text)
    except json.JSONDecodeError as exc: raise ValueError(f"Exact-provider JSON is invalid at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    request = decode_r40_exact_payload(raw)
    if request.profile != shelf.profile_id:
        raise ValueError(f"Payload role {request.profile!r} does not match shelf role {shelf.profile_id!r}.")
    generator = R40ExactConfigGenerator()
    issues = generator.validate(request)
    errors = tuple(issue for issue in issues if issue.severity == "error")
    if errors:
        raise ValueError("Exact-provider validation failed:\n" + "\n".join(f"- [{issue.code}] {issue.field}: {issue.message}" for issue in errors))
    artifact = generator.generate(request)
    return encode_r40_exact_payload(request), artifact


def apply_exact_payload(project: RouteProject, shelf_id: str, payload_text: str):
    payload, artifact = validate_exact_payload(project, shelf_id, payload_text)
    shelves = list(project.shelves)
    index = next(i for i, shelf in enumerate(shelves) if shelf.shelf_id == shelf_id)
    shelves[index] = replace(shelves[index], profile_payload=payload, review_state="confirmed")
    updated = replace(project, shelves=tuple(shelves))
    return updated, artifact


def transcribe_route_diagram(path: str | Path, *, raman_callout_enabled: bool = False):
    """Run the controlled external-vision transcription without GUI access."""
    import config as atlas_config
    from utils.ai.provider import OpenAIProvider
    from utils.rls_config.diagram_import import DiagramImportConventions, RAMAN_CALLOUT_CONVENTION_DISABLED, RAMAN_CALLOUT_CONVENTION_SMALL_RED_SLOT_PORT, import_route_diagram
    provider = OpenAIProvider(
        chat_model=atlas_config.RLS_DIAGRAM_MODEL,
        image_detail=atlas_config.RLS_DIAGRAM_IMAGE_DETAIL,
        reasoning_effort=atlas_config.RLS_DIAGRAM_REASONING_EFFORT,
        max_completion_tokens=atlas_config.RLS_DIAGRAM_MAX_COMPLETION_TOKENS,
    )
    conventions = DiagramImportConventions(
        raman_callout_convention=(RAMAN_CALLOUT_CONVENTION_SMALL_RED_SLOT_PORT if raman_callout_enabled else RAMAN_CALLOUT_CONVENTION_DISABLED)
    )
    return import_route_diagram(Path(path), provider, conventions=conventions)


def apply_diagram_transcription(result):
    """Convert one accepted transcription using the established audited adapters."""
    from services.rls_route_core import WORKBOOK_DIAGRAM_MARKER_KEY, _diagram_editor_rows, _diagram_route_links, _diagram_source_record, build_route_project, diagram_import_mutation_blockers
    from utils.rls_config.diagram_assets import workbook_diagram_from_source
    blockers = diagram_import_mutation_blockers(result)
    if blockers:
        raise ValueError("Diagram transcription is incomplete; route unchanged:\n" + "\n".join(f"- [{item.code}] {item.field}: {item.message}" for item in blockers[:12]))
    rows = _diagram_editor_rows(result)
    if not rows: raise ValueError("Diagram transcription contains no active shelves; route unchanged.")
    links = _diagram_route_links(result, rows)
    diagram_source = _diagram_source_record(result)
    diagram = workbook_diagram_from_source(result.source)
    diagram_source[WORKBOOK_DIAGRAM_MARKER_KEY] = diagram.marker_dict(required_in_mop=True)
    project = build_route_project(
        route_code=result.route_code or "", title=result.title or "",
        revision=result.revision or "1", rows=rows, ospf_area=result.ospf_area or "",
        links=links, diagram_source=diagram_source, require_valid=False,
    )
    return project, diagram


def reattach_route_diagram(project: RouteProject, path: str | Path):
    from utils.rls_config.diagram_assets import validate_workbook_diagram_for_project, workbook_diagram_from_source
    from utils.rls_config.diagram_import import load_diagram_source
    diagram = workbook_diagram_from_source(load_diagram_source(Path(path)))
    return validate_workbook_diagram_for_project(project, diagram)
