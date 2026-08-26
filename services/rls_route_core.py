"""Toolkit-independent Ciena RLS route planning and validation core.

This frame intentionally separates route documentation from deployable CLI.
Add/Drop, ILA, and ROADM shelf records can be arranged into a route and
exported to the controlled FBN workbook template. A route role remains
planning-only until the operator explicitly selects and validates one of the
narrow exact providers registered for its release and installed hardware.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
import ipaddress
import logging
import math
import os
from pathlib import Path
from queue import Empty, Queue
import re
import tempfile
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence
from uuid import uuid4


from utils.helpers import friendly_error, get_desktop_dir
from utils.rls_config.common import (
    DEFAULT_R40_TARGET_BUILD_SCHEMA,
    FIBER_TYPES,
    SUPPORTED_SOFTWARE_RELEASE,
)
from utils.rls_config.route_project import (
    DeploymentReadiness,
    OpticalPath,
    OpticalPathSegment,
    PATH_SOURCE_DISCREPANCIES_KEY,
    PATH_SOURCE_DISCREPANCY_PENDING,
    PATH_SOURCE_DISCREPANCY_SUPERSEDED,
    PathEndpointReview,
    PROFILE_REGISTRY,
    R40_PENDING_SRA_PEER_REVIEW,
    RouteCustomerPolicy,
    RouteLink,
    RouteProject,
    ShelfInstance,
    Site,
    _r40_payload_readiness,
    _r40_sra_evidence_mismatches,
    _r40_sra_line_output,
    _r40_sra_peer_shelf_ids,
    _r40_provider_sra_slots,
    _r40_provider_route_band_mismatches,
    _r40_route_topology_issues,
    _structured_sra_state,
    load_route_project_draft,
    route_link_propagation_views,
    route_project_fingerprint,
    save_route_project_draft,
)
from utils.rls_config.route_config import RouteConfigBuild, evaluate_route_configs

try:
    from utils.rls_config.diagram_import import (
        DIAGRAM_EVIDENCE_SCHEMA_ID,
        DIAGRAM_EVIDENCE_SCHEMA_VERSION,
        MIN_FIELD_CONFIDENCE,
        RAMAN_CALLOUT_CONVENTION_DISABLED,
        RAMAN_CALLOUT_CONVENTION_SMALL_RED_SLOT_PORT,
        SOURCE_EVIDENCE_DISCREPANCY_CODE,
        DiagramImportConventions,
        DiagramImportError,
        DiagramImportResult,
        import_route_diagram,
        load_diagram_source,
        tid_site_code_review_suggestion,
    )
except ImportError as _diagram_import_error:  # pragma: no cover - packaging guard
    DiagramImportConventions = None  # type: ignore[assignment,misc]
    DiagramImportError = RuntimeError  # type: ignore[assignment,misc]
    DiagramImportResult = Any  # type: ignore[assignment,misc]
    import_route_diagram = None  # type: ignore[assignment]
    load_diagram_source = None  # type: ignore[assignment]
    DIAGRAM_EVIDENCE_SCHEMA_ID = "atlas.ciena.rls.diagram-import-evidence"
    DIAGRAM_EVIDENCE_SCHEMA_VERSION = "1.8"
    MIN_FIELD_CONFIDENCE = 0.85
    RAMAN_CALLOUT_CONVENTION_DISABLED = "disabled"
    RAMAN_CALLOUT_CONVENTION_SMALL_RED_SLOT_PORT = (
        "small-red-slot-port-v1"
    )
    SOURCE_EVIDENCE_DISCREPANCY_CODE = "SOURCE_EVIDENCE_DISCREPANCY"

    def tid_site_code_review_suggestion(_tid: str | None) -> str:
        return ""

    _DIAGRAM_IMPORT_ERROR: Optional[BaseException] = _diagram_import_error
else:
    _DIAGRAM_IMPORT_ERROR = None

try:
    from utils.rls_config.diagram_assets import (
        WORKBOOK_DIAGRAM_MARKER_KEY,
        DiagramAssetError,
        WorkbookDiagram,
        validate_workbook_diagram_for_project,
        workbook_diagram_from_source,
    )
except ImportError as _diagram_asset_import_error:  # pragma: no cover
    WORKBOOK_DIAGRAM_MARKER_KEY = "workbook_diagram"
    DiagramAssetError = RuntimeError  # type: ignore[assignment,misc]
    WorkbookDiagram = Any  # type: ignore[assignment,misc]
    validate_workbook_diagram_for_project = None  # type: ignore[assignment]
    workbook_diagram_from_source = None  # type: ignore[assignment]
    _DIAGRAM_ASSET_IMPORT_ERROR: Optional[BaseException] = (
        _diagram_asset_import_error
    )
else:
    _DIAGRAM_ASSET_IMPORT_ERROR = None

try:
    from utils.rls_config.mop_export import MopExportError, export_mop
except ImportError as _mop_import_error:  # pragma: no cover - packaging guard
    MopExportError = RuntimeError  # type: ignore[assignment,misc]
    export_mop = None  # type: ignore[assignment]
    _MOP_IMPORT_ERROR: Optional[BaseException] = _mop_import_error
else:
    _MOP_IMPORT_ERROR = None

try:
    from utils.rls_config.route_bundle import RouteBundleError, export_route_bundle
except ImportError as _bundle_import_error:  # pragma: no cover - packaging guard
    RouteBundleError = RuntimeError  # type: ignore[assignment,misc]
    export_route_bundle = None  # type: ignore[assignment]
    _BUNDLE_IMPORT_ERROR: Optional[BaseException] = _bundle_import_error
else:
    _BUNDLE_IMPORT_ERROR = None


LOGGER = logging.getLogger(__name__)

PLANNING_CLI_NOTICE = (
    "This Route Builder supports exact RLS 4.0 projects only. Review each "
    "selected shelf before building the deliverable. RLS 4.0 "
    "supports multiple Add/Drop, ILA, and ROADM arrangements; those site roles "
    "are not complete variants. ATLAS requires the operator to choose a "
    "compatible exact audited R4.0 hardware/topology provider and validate all "
    "directional engineering inputs. Unsupported arrangements remain "
    "planning/documentation-only."
)


def _log_route_event(message: str, level: int = logging.INFO) -> None:
    """Record a safe operator action without serializing CLI or payload data."""

    LOGGER.log(level, "[RLS ROUTE] %s", message)

DIAGRAM_PRIVACY_NOTICE = (
    "The selected customer diagram will be decoded locally, then its embedded "
    "or selected images will be sent to the configured external AI vision "
    "provider for transcription. The provider may process customer site names, "
    "TIDs, IP addresses, circuit identifiers, and other visible diagram data. "
    "Only continue if you are authorized to send this file to that provider."
)

R40_UI_RELEASE = SUPPORTED_SOFTWARE_RELEASE
_AUDITED_TERMINAL_ROUTE_PATCH_LOSS_DB = 0.5
R40_UI_PROFILE_IDS = (
    "add_drop_a",
    "add_drop_z",
    "add_drop",
    "ila",
    "roadm_a",
    "roadm_z",
    "roadm",
)
_R40_UI_PROFILE_ID_SET = frozenset(R40_UI_PROFILE_IDS)
UNRESOLVED_PROFILE_LABEL = "Unresolved — select shelf role"
_DIRECTION_EVIDENCE_INVALIDATION_KEY = "line_endpoint_direction_invalidation"
_INVALIDATED_LINE_ENDPOINTS_KEY = "invalidated_line_endpoints"
_PROVIDER_PRESELECTION_INVALIDATION_KEY = "provider_preselection_invalidation"
_TERMINAL_ROUTE_TITLE_RULE_ID = "terminal-site-route-title-v1"
_TERMINAL_ROUTE_TOKEN_RE = re.compile(r"^[A-Z0-9]{2,32}$")

_TABLE_COLUMNS = (
    "order",
    "profile",
    "site",
    "tid",
    "ip",
    "release",
    "raman",
    "power",
    "provider",
    "direction",
    "readiness",
)


@dataclass
class _ShelfEditorRow:
    """Display/edit representation that retains route-model-only metadata."""

    shelf_id: str
    profile_id: str
    site_key: str
    site_code: str
    site_name: str
    tid: str
    primary_oam_ip: str
    software_release: str
    shelf_variant: str
    raman_label: str
    power_label: str
    site_address: str = ""
    network_site_id: str = ""
    notes: str = ""
    profile_payload: Mapping[str, Any] = field(default_factory=dict)
    review_state: str = "manual"
    source_evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _WorkerResult:
    """One worker completion packet consumed exclusively by the Tk thread."""

    kind: str
    generation: int
    fingerprint: str
    value: Any = None
    error: Exception | None = None
    context: Any = None


@dataclass(frozen=True)
class _R40CandidatePairReview:
    """Fail-closed paired-SRA outcome for one candidate route snapshot."""

    pending_peer_ids: tuple[str, ...] = ()
    validated_peer_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class DiagramImportMutationBlocker:
    """One transcription-integrity failure that forbids route replacement."""

    code: str
    field: str
    message: str


@dataclass(frozen=True)
class DiagramReviewIssueAggregate:
    """Privacy-safe counts for provider transcription review issues."""

    issue_count: int
    required_review_count: int
    advisory_count: int
    code_counts: tuple[tuple[str, int], ...]
    required_path_counts: tuple[tuple[str, int], ...]
    missing_leaf_counts: tuple[tuple[str, int], ...]
    missing_path_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class DiagramReviewAccounting:
    """Post-import accounting that preserves source issues without overstating work."""

    raw: DiagramReviewIssueAggregate
    unresolved: DiagramReviewIssueAggregate
    unresolved_issues: tuple[Any, ...]
    defaulted_count: int
    suggestion_pending_count: int
    scope_inherited_count: int
    optional_count: int
    lifecycle_excluded_count: int

    @property
    def source_absence_count(self) -> int:
        return sum(count for _path, count in self.raw.missing_path_counts)

    @property
    def category_counts(self) -> tuple[tuple[str, int], ...]:
        return (
            ("unresolved", self.unresolved.required_review_count),
            ("defaulted", self.defaulted_count),
            ("suggestion_pending", self.suggestion_pending_count),
            ("scope_inherited", self.scope_inherited_count),
            ("optional", self.optional_count),
            ("lifecycle_excluded", self.lifecycle_excluded_count),
        )


@dataclass(frozen=True)
class DiagramFiberTypeScope:
    """One review-only uniform source-fiber observation across active spans."""

    value: str
    source_sha256: str
    observed_span_orders: tuple[int, ...]
    inherited_span_order: int


_SAFE_DIAGNOSTIC_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,95}$")
_SAFE_DIAGNOSTIC_PATH_RE = re.compile(
    r"^(?:route|shelves|spans|evidence)"
    r"(?:\[\d+\])?"
    r"(?:\.[a-z][a-z0-9_]*(?:\[\d+\])?)*$"
)
_INDEXED_PATH_RE = re.compile(r"\[\d+\]")
_DOTTED_INDEX_RE = re.compile(r"\.\d+(?=\.|$)")
_SHELF_MISSING_PATH_RE = re.compile(
    r"^shelves\[(?P<order>\d+)\]\.(?P<field>[a-z][a-z0-9_]*)$"
)
_SPAN_MISSING_PATH_RE = re.compile(
    r"^spans\[(?P<order>\d+)\]\.(?P<field>[a-z][a-z0-9_]*)$"
)
_SOFTWARE_RELEASE_SCOPE_DEFAULT_REASON = (
    "active Route Builder product contract; not diagram evidence"
)
_SITE_CODE_REVIEW_SUGGESTION_REASON = (
    "review-only TID-prefix suggestion; not direct site-code diagram evidence"
)
_SHELF_VARIANT_CHASSIS_SUGGESTION_REASON = (
    "review-only chassis-family fallback; not an exact shelf variant or PEC"
)
_POWER_LABEL_ROLE_DEFAULT_REASON = (
    "ATLAS route-role power standard; not customer-diagram evidence"
)
_POWER_LABEL_ROLE_DEFAULT_KEY = "power_label_role_default"
_ROUTE_REVISION_SCOPE_DEFAULT_REASON = (
    "new ATLAS deliverable revision; not customer-diagram evidence"
)
_ROUTE_FIBER_SCOPE_CONVENTION_ID = "uniform-active-span-fiber-v1"
_ROUTE_FIBER_SCOPE_SUGGESTION_KEY = "route_fiber_type_scope_suggestion"
_ROUTE_NATIVE_FIBER_REVIEW_KEY = "route_native_fiber_review"


def _safe_diagnostic_code(value: object) -> str:
    code = str(value or "").strip()
    return code if _SAFE_DIAGNOSTIC_CODE_RE.fullmatch(code) else "UNKNOWN"


def _safe_diagnostic_path(value: object) -> str:
    """Normalize controlled field paths without logging customer values."""

    raw = str(value or "").strip()
    candidate = _DOTTED_INDEX_RE.sub("[0]", raw)
    if not _SAFE_DIAGNOSTIC_PATH_RE.fullmatch(candidate):
        return "other"
    return _INDEXED_PATH_RE.sub("[]", candidate)


def _count_labels(values: Iterable[str]) -> tuple[tuple[str, int], ...]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _format_count_pairs(
    values: Iterable[tuple[str, int]],
    *,
    limit: int = 12,
) -> str:
    pairs = tuple(values)
    shown = pairs[:limit]
    text = ",".join(f"{label}:{count}" for label, count in shown)
    if len(pairs) > len(shown):
        text += f",other:{sum(count for _label, count in pairs[len(shown):])}"
    return text or "none"


def _review_site_code_suggestion(tid: str) -> str:
    """Return a conservative, unconfirmed site-code suggestion from a TID."""

    return tid_site_code_review_suggestion(tid)


def power_label_for_profile(profile_id: str) -> str:
    """Return the ATLAS route-role power label, or blank for unknown roles."""

    normalized = str(profile_id or "").strip().casefold()
    if normalized == "ila":
        return "DC"
    if normalized in {
        "add_drop",
        "add_drop_a",
        "add_drop_z",
        "roadm",
        "roadm_a",
        "roadm_z",
    }:
        return "AC"
    return ""


def _power_label_role_default_marker(profile_id: str) -> dict[str, str]:
    """Build exact provenance for a power value supplied by ATLAS."""

    return {
        "value": power_label_for_profile(profile_id),
        "profile_id": str(profile_id or "").strip(),
        "reason": _POWER_LABEL_ROLE_DEFAULT_REASON,
    }


def _has_exact_power_label_role_default(
    source_evidence: Mapping[str, Any],
    profile_id: str,
    power_label: str,
) -> bool:
    """Return whether power is still the exact ATLAS-derived role default."""

    expected = power_label_for_profile(profile_id)
    return (
        bool(expected)
        and str(power_label or "").strip() == expected
        and source_evidence.get(_POWER_LABEL_ROLE_DEFAULT_KEY)
        == _power_label_role_default_marker(profile_id)
    )


def aggregate_diagram_review_issues(
    issues: Iterable[Any],
) -> DiagramReviewIssueAggregate:
    """Aggregate importer issues without messages, values, or shelf identity."""

    issue_list = tuple(issues)
    required = tuple(
        issue for issue in issue_list if bool(getattr(issue, "blocking", False))
    )
    missing = tuple(
        issue
        for issue in required
        if _safe_diagnostic_code(getattr(issue, "code", ""))
        == "MISSING_REQUIRED_FIELD"
    )
    missing_paths = tuple(
        _safe_diagnostic_path(getattr(issue, "field", "")) for issue in missing
    )
    missing_leaves = tuple(
        path.rsplit(".", 1)[-1].replace("[]", "")
        if path != "other"
        else "other"
        for path in missing_paths
    )
    return DiagramReviewIssueAggregate(
        issue_count=len(issue_list),
        required_review_count=len(required),
        advisory_count=len(issue_list) - len(required),
        code_counts=_count_labels(
            _safe_diagnostic_code(getattr(issue, "code", ""))
            for issue in issue_list
        ),
        required_path_counts=_count_labels(
            _safe_diagnostic_path(getattr(issue, "field", ""))
            for issue in required
        ),
        missing_leaf_counts=_count_labels(missing_leaves),
        missing_path_counts=_count_labels(missing_paths),
    )


def _exact_review_marker(
    value: object,
    *,
    expected_value: str,
    source_field: str | None,
    reason: str,
) -> bool:
    expected = {
        "value": expected_value,
        "reason": reason,
    }
    if source_field is not None:
        expected["source_field"] = source_field
    return isinstance(value, Mapping) and dict(value) == expected


def _active_rows_by_source_order(
    result: DiagramImportResult,
    rows: Iterable[_ShelfEditorRow],
) -> dict[int, _ShelfEditorRow]:
    """Bind active source orders to rows only when identity/order still agree."""

    active_shelves = tuple(getattr(result, "active_shelves", ()) or ())
    row_list = tuple(rows)
    if len(active_shelves) != len(row_list):
        return {}
    by_order: dict[int, _ShelfEditorRow] = {}
    for shelf, row in zip(active_shelves, row_list):
        order = getattr(shelf, "order", None)
        shelf_tid = str(getattr(shelf, "tid", "") or "").strip()
        if (
            isinstance(order, bool)
            or not isinstance(order, int)
            or order < 1
            or not shelf_tid
            or shelf_tid.casefold() != row.tid.strip().casefold()
            or order in by_order
        ):
            return {}
        by_order[order] = row
    return by_order


def _direct_fiber_evidence_matches(span: object, value: str) -> bool:
    normalized = value.strip().casefold()
    if not normalized:
        return False
    for evidence in tuple(getattr(span, "evidence", ()) or ()):
        if (
            str(getattr(evidence, "field", "") or "") != "fiber_type"
            or str(getattr(evidence, "method", "") or "")
            not in {"vision", "ocr", "native_text"}
        ):
            continue
        confidence = getattr(evidence, "confidence", None)
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or confidence < MIN_FIELD_CONFIDENCE
        ):
            continue
        evidence_value = str(
            getattr(evidence, "normalized_value", "") or ""
        ).strip()
        if evidence_value.casefold() == normalized:
            return True
    return False


def diagram_fiber_type_scope(
    result: DiagramImportResult,
) -> DiagramFiberTypeScope | None:
    """Derive one pending route-scope suggestion from unanimous direct facts."""

    active_spans = tuple(getattr(result, "active_spans", ()) or ())
    if len(active_spans) < 3:
        return None
    observed: list[tuple[int, str]] = []
    missing_orders: list[int] = []
    for span in active_spans:
        order = getattr(span, "order", None)
        if (
            isinstance(order, bool)
            or not isinstance(order, int)
            or order < 1
        ):
            return None
        value = str(getattr(span, "fiber_type", "") or "").strip()
        if not value:
            missing_orders.append(order)
            continue
        if not _direct_fiber_evidence_matches(span, value):
            return None
        observed.append((order, value))
    if len(missing_orders) != 1 or len(observed) < 2:
        return None
    normalized_values = {value.casefold() for _order, value in observed}
    if len(normalized_values) != 1:
        return None
    source = getattr(result, "source", None)
    source_sha256 = str(getattr(source, "sha256", "") or "").strip()
    if not source_sha256:
        return None
    return DiagramFiberTypeScope(
        value=observed[0][1],
        source_sha256=source_sha256,
        observed_span_orders=tuple(order for order, _value in observed),
        inherited_span_order=missing_orders[0],
    )


def _fiber_type_scope_marker(
    scope: DiagramFiberTypeScope,
) -> dict[str, object]:
    return {
        "convention_id": _ROUTE_FIBER_SCOPE_CONVENTION_ID,
        "source_sha256": scope.source_sha256,
        "value": scope.value,
        "observed_span_orders": list(scope.observed_span_orders),
        "inherited_span_orders": [scope.inherited_span_order],
        "scope": "active_route_spans",
        "status": "pending_operator_review",
        "deployable_cli": False,
    }


def _observed_route_fiber_types(
    diagram_source: Mapping[str, object],
    links: Iterable[RouteLink],
) -> tuple[str, ...]:
    """Return distinct direct source labels without consulting reviewed tokens."""

    scope_marker = diagram_source.get(_ROUTE_FIBER_SCOPE_SUGGESTION_KEY)
    if isinstance(scope_marker, Mapping):
        value = str(scope_marker.get("value", "") or "").strip()
        if value:
            return (value,)
    values: dict[str, str] = {}
    for link in links:
        for path in link.paths:
            raw_fields = path.source_evidence.get("fields", ())
            if not isinstance(raw_fields, (list, tuple)):
                continue
            for evidence in raw_fields:
                if not isinstance(evidence, Mapping):
                    continue
                if (
                    evidence.get("field") != "fiber_type"
                    or evidence.get("method")
                    not in {"vision", "ocr", "native_text"}
                ):
                    continue
                raw_confidence = evidence.get("confidence")
                if (
                    isinstance(raw_confidence, bool)
                    or not isinstance(raw_confidence, (int, float))
                    or raw_confidence < MIN_FIELD_CONFIDENCE
                ):
                    continue
                value = str(
                    evidence.get("normalized_value", "") or ""
                ).strip()
                if value:
                    values.setdefault(value.casefold(), value)
    return tuple(values[key] for key in sorted(values))


def _path_has_exact_fiber_type_scope_marker(
    path: OpticalPath,
    scope: DiagramFiberTypeScope,
) -> bool:
    marker = path.source_evidence.get(_ROUTE_FIBER_SCOPE_SUGGESTION_KEY)
    if not isinstance(marker, Mapping):
        return False
    observed_orders = marker.get("observed_span_orders")
    inherited_orders = marker.get("inherited_span_orders")
    return (
        marker.get("convention_id") == _ROUTE_FIBER_SCOPE_CONVENTION_ID
        and marker.get("source_sha256") == scope.source_sha256
        and marker.get("value") == scope.value
        and isinstance(observed_orders, (list, tuple))
        and tuple(observed_orders) == scope.observed_span_orders
        and isinstance(inherited_orders, (list, tuple))
        and tuple(inherited_orders) == (scope.inherited_span_order,)
        and marker.get("scope") == "active_route_spans"
        and marker.get("status") == "pending_operator_review"
        and marker.get("deployable_cli") is False
    )


def account_diagram_review_issues(
    result: DiagramImportResult,
    rows: Iterable[_ShelfEditorRow],
    *,
    revision_default: object = None,
    links: Iterable[RouteLink] = (),
) -> DiagramReviewAccounting:
    """Classify source blockers against the exact post-import workflow state.

    Only a missing-field issue may be reclassified. Invalid, unsupported,
    low-confidence, or evidence-mismatch issues always remain unresolved.
    Locally generated defaults and suggestions require exact provenance
    markers; a merely nonblank editor value is never enough.
    """

    issues = tuple(getattr(result, "issues", ()) or ())
    raw = aggregate_diagram_review_issues(issues)
    all_shelves = tuple(getattr(result, "shelves", ()) or ())
    active_shelves = tuple(getattr(result, "active_shelves", ()) or ())
    shelves_by_order = {
        getattr(shelf, "order"): shelf
        for shelf in all_shelves
        if isinstance(getattr(shelf, "order", None), int)
        and not isinstance(getattr(shelf, "order", None), bool)
    }
    active_orders = {
        getattr(shelf, "order")
        for shelf in active_shelves
        if isinstance(getattr(shelf, "order", None), int)
        and not isinstance(getattr(shelf, "order", None), bool)
    }
    active_span_orders = {
        getattr(span, "order")
        for span in tuple(getattr(result, "active_spans", ()) or ())
        if isinstance(getattr(span, "order", None), int)
        and not isinstance(getattr(span, "order", None), bool)
    }
    rows_by_order = _active_rows_by_source_order(result, rows)
    paths_by_order: dict[int, OpticalPath] = {}
    duplicate_link_orders: set[int] = set()
    for link in tuple(links):
        order = getattr(link, "order", None)
        if (
            isinstance(order, bool)
            or not isinstance(order, int)
            or order < 1
            or len(link.paths) != 1
        ):
            continue
        if order in paths_by_order:
            duplicate_link_orders.add(order)
            paths_by_order.pop(order, None)
            continue
        if order not in duplicate_link_orders:
            paths_by_order[order] = link.paths[0]
    fiber_scope = diagram_fiber_type_scope(result)

    unresolved: list[Any] = []
    category_counts = {
        "defaulted": 0,
        "suggestion_pending": 0,
        "scope_inherited": 0,
        "optional": 0,
        "lifecycle_excluded": 0,
    }

    for issue in issues:
        if not bool(getattr(issue, "blocking", False)):
            continue
        if (
            _safe_diagnostic_code(getattr(issue, "code", ""))
            != "MISSING_REQUIRED_FIELD"
        ):
            unresolved.append(issue)
            continue

        issue_path = str(getattr(issue, "field", "") or "").strip()
        shelf_match = _SHELF_MISSING_PATH_RE.fullmatch(issue_path)
        span_match = _SPAN_MISSING_PATH_RE.fullmatch(issue_path)

        if shelf_match is not None:
            order = int(shelf_match.group("order"))
            field_name = shelf_match.group("field")
            shelf = shelves_by_order.get(order)
            row = rows_by_order.get(order)

            if shelf is not None and order not in active_orders:
                category_counts["lifecycle_excluded"] += 1
                continue
            if shelf is None:
                unresolved.append(issue)
                continue
            if field_name == "raman_label":
                category_counts["optional"] += 1
                continue
            if row is None or row.review_state != "pending":
                unresolved.append(issue)
                continue

            evidence = row.source_evidence
            if not isinstance(evidence, Mapping):
                unresolved.append(issue)
                continue
            if field_name == "software_release" and (
                not str(getattr(shelf, "software_release", "") or "").strip()
                and row.software_release == R40_UI_RELEASE
                and _exact_review_marker(
                    evidence.get("software_release_scope_default"),
                    expected_value=R40_UI_RELEASE,
                    source_field=None,
                    reason=_SOFTWARE_RELEASE_SCOPE_DEFAULT_REASON,
                )
            ):
                category_counts["defaulted"] += 1
                continue
            if field_name == "power_label" and (
                not str(getattr(shelf, "power_label", "") or "").strip()
                and _has_exact_power_label_role_default(
                    evidence,
                    row.profile_id,
                    row.power_label,
                )
            ):
                category_counts["defaulted"] += 1
                continue
            if field_name == "site_code":
                suggested = row.site_code.strip()
                if (
                    not str(getattr(shelf, "site_code", "") or "").strip()
                    and suggested
                    and suggested == _review_site_code_suggestion(row.tid)
                    and _exact_review_marker(
                        evidence.get("site_code_review_suggestion"),
                        expected_value=suggested,
                        source_field="tid",
                        reason=_SITE_CODE_REVIEW_SUGGESTION_REASON,
                    )
                ):
                    category_counts["suggestion_pending"] += 1
                    continue
            if field_name == "shelf_variant":
                suggested = row.shelf_variant.strip()
                chassis = str(evidence.get("chassis", "") or "").strip()
                if (
                    not str(getattr(shelf, "shelf_variant", "") or "").strip()
                    and not str(evidence.get("shelf_variant", "") or "").strip()
                    and suggested
                    and suggested == chassis
                    and suggested
                    == str(getattr(shelf, "chassis", "") or "").strip()
                    and _exact_review_marker(
                        evidence.get("shelf_variant_chassis_suggestion"),
                        expected_value=suggested,
                        source_field="chassis",
                        reason=_SHELF_VARIANT_CHASSIS_SUGGESTION_REASON,
                    )
                ):
                    category_counts["suggestion_pending"] += 1
                    continue

            unresolved.append(issue)
            continue

        if span_match is not None:
            span_order = int(span_match.group("order"))
            if (
                fiber_scope is not None
                and span_order == fiber_scope.inherited_span_order
                and span_match.group("field") == "fiber_type"
            ):
                path = paths_by_order.get(span_order)
                if (
                    path is not None
                    and not path.fiber_type.strip()
                    and _path_has_exact_fiber_type_scope_marker(
                        path,
                        fiber_scope,
                    )
                ):
                    category_counts["scope_inherited"] += 1
                    continue
            if (
                span_order in active_span_orders
                and span_match.group("field")
                in {"circuit_id", "fiber_start", "fiber_end"}
            ):
                category_counts["optional"] += 1
                continue

        if (
            issue_path == "route.revision"
            and not str(getattr(result, "revision", "") or "").strip()
            and _exact_review_marker(
                revision_default,
                expected_value="1",
                source_field=None,
                reason=_ROUTE_REVISION_SCOPE_DEFAULT_REASON,
            )
        ):
            category_counts["defaulted"] += 1
            continue

        unresolved.append(issue)

    unresolved_issues = tuple(unresolved)
    return DiagramReviewAccounting(
        raw=raw,
        unresolved=aggregate_diagram_review_issues(unresolved_issues),
        unresolved_issues=unresolved_issues,
        defaulted_count=category_counts["defaulted"],
        suggestion_pending_count=category_counts["suggestion_pending"],
        scope_inherited_count=category_counts["scope_inherited"],
        optional_count=category_counts["optional"],
        lifecycle_excluded_count=category_counts["lifecycle_excluded"],
    )


def _run_background_job(
    result_queue: Queue[_WorkerResult],
    *,
    kind: str,
    generation: int,
    fingerprint: str,
    work: Callable[[], Any],
    context: Any = None,
) -> None:
    """Run non-Tk work and publish a passive result packet.

    This function is the executor boundary. It intentionally has no widget,
    dialog, variable, or other Tk access.
    """

    try:
        value = work()
    except Exception as exc:
        LOGGER.exception("[RLS ROUTE] Background %s task failed", kind)
        result = _WorkerResult(
            kind=kind,
            generation=generation,
            fingerprint=fingerprint,
            error=exc,
            context=context,
        )
    else:
        result = _WorkerResult(
            kind=kind,
            generation=generation,
            fingerprint=fingerprint,
            value=value,
            context=context,
        )
    result_queue.put(result)


def _default_diagram_provider() -> Any:
    """Resolve the configured provider lazily inside the import worker."""

    import config as atlas_config
    from utils.ai.provider import OpenAIProvider

    return OpenAIProvider(
        chat_model=atlas_config.RLS_DIAGRAM_MODEL,
        image_detail=atlas_config.RLS_DIAGRAM_IMAGE_DETAIL,
        reasoning_effort=atlas_config.RLS_DIAGRAM_REASONING_EFFORT,
        max_completion_tokens=(
            atlas_config.RLS_DIAGRAM_MAX_COMPLETION_TOKENS
        ),
    )


def _import_diagram_worker(
    source: Path,
    provider_factory: Callable[[], Any],
    conventions: Any,
) -> DiagramImportResult:
    if import_route_diagram is None:
        raise DiagramImportError("Route diagram importer is unavailable.")
    return import_route_diagram(
        source,
        provider_factory(),
        conventions=conventions,
    )


def _open_preview_file(path: Path) -> None:
    """Open a generated preview using the platform shell."""

    startfile = getattr(os, "startfile", None)
    if not callable(startfile):
        raise OSError("Opening the preview is supported only on Windows.")
    startfile(str(path))


def _diagram_route_optical_band_status(
    result: DiagramImportResult,
) -> str:
    """Classify the passive route-band observation without authorizing CLI."""

    value = str(getattr(result, "optical_band", "") or "").strip()
    if not value:
        return "not_observed"
    if any(
        bool(getattr(issue, "blocking", False))
        and str(getattr(issue, "field", "") or "") == "route.optical_band"
        for issue in tuple(getattr(result, "issues", ()) or ())
    ):
        return "unverified"
    return "direct_supported"


def _display_optical_band_for_review(value: object) -> str:
    """Render one closed route-band token for operator-facing context."""

    return {
        "c": "C",
        "l": "L",
        "c+l": "C+L",
        "integrated_c+l": "Integrated C+L",
    }.get(str(value or "").strip().casefold(), "unknown")


def _diagram_source_record(result: DiagramImportResult) -> dict[str, Any]:
    """Build JSON-safe project provenance without retaining paths or pixels."""

    source = result.source
    record = {
        "schema_id": DIAGRAM_EVIDENCE_SCHEMA_ID,
        "schema_version": DIAGRAM_EVIDENCE_SCHEMA_VERSION,
        "file_name": source.file_name,
        "source_type": source.source_type,
        "source_sha256": source.sha256,
        "size_bytes": source.size_bytes,
        "external_vision_processing_confirmed": True,
        "images": [
            {
                "index": image.index,
                "source_label": image.source_label,
                "source_part": image.source_part,
                "source_sha256": image.source_sha256,
                "normalized_sha256": image.normalized_sha256,
                "original_width": image.original_width,
                "original_height": image.original_height,
                "width": image.width,
                "height": image.height,
                "format": image.format,
                "view_kind": image.view_kind,
                "source_image_index": image.source_image_index,
                "canonical_width": image.canonical_width,
                "canonical_height": image.canonical_height,
                "crop_box": (
                    list(image.crop_box)
                    if image.crop_box is not None
                    else None
                ),
            }
            for image in source.images
        ],
        "route_evidence": [
            evidence.to_dict() for evidence in result.route_evidence
        ],
        "route_header": {
            "route_code": result.route_code,
            "title": result.title,
            "revision": result.revision,
            "ospf_area": result.ospf_area,
            "optical_band": getattr(result, "optical_band", None),
            "optical_band_status": _diagram_route_optical_band_status(result),
        },
        "active_span_count": len(result.active_spans),
        "active_spans": [
            {
                "order": span.order,
                "from_tid": span.from_tid,
                "to_tid": span.to_tid,
                "expected_loss_db": getattr(
                    span, "expected_loss_db", None
                ),
                "distance_km": getattr(span, "distance_km", None),
                "circuit_id": getattr(span, "circuit_id", None),
                "fiber_start": getattr(span, "fiber_start", None),
                "fiber_end": getattr(span, "fiber_end", None),
                "fiber_type": getattr(span, "fiber_type", None),
                "segment_count": len(
                    tuple(getattr(span, "segments", ()) or ())
                ),
                "segments": [
                    {
                        "order": getattr(segment, "order", None),
                        "from_tid": getattr(segment, "from_tid", None),
                        "to_tid": getattr(segment, "to_tid", None),
                        "expected_loss_db": getattr(
                            segment, "expected_loss_db", None
                        ),
                        "distance_km": getattr(
                            segment, "distance_km", None
                        ),
                        "circuit_id": getattr(
                            segment, "circuit_id", None
                        ),
                        "fiber_start": getattr(
                            segment, "fiber_start", None
                        ),
                        "fiber_end": getattr(segment, "fiber_end", None),
                        "fiber_type": getattr(segment, "fiber_type", None),
                        "evidence": [
                            evidence.to_dict()
                            for evidence in getattr(
                                segment, "evidence", ()
                            )
                        ],
                    }
                    for segment in tuple(
                        getattr(span, "segments", ()) or ()
                    )
                ],
                "evidence": [
                    evidence.to_dict()
                    for evidence in getattr(span, "evidence", ())
                ],
            }
            for span in result.active_spans
        ],
        "planned_removals": [
            {
                "order": shelf.order,
                "tid": shelf.tid,
                "site_code": shelf.site_code,
                "profile_id": getattr(shelf, "profile_id", ""),
                "notes": getattr(shelf, "notes", None),
            }
            for shelf in result.shelves
            if not getattr(
                shelf,
                "active_for_route",
                shelf in result.active_shelves,
            )
        ],
        "issues": [
            {
                "severity": issue.severity,
                "code": issue.code,
                "field": issue.field,
                "message": issue.message,
                "blocking": issue.blocking,
            }
            for issue in result.issues
        ],
    }
    route_title_derivation = getattr(
        result,
        "route_title_derivation",
        {},
    )
    if isinstance(route_title_derivation, Mapping) and route_title_derivation:
        record["route_title_derivation"] = dict(route_title_derivation)
    raman_provenance = getattr(result, "raman_callout_provenance", {})
    if isinstance(raman_provenance, Mapping):
        record.update(dict(raman_provenance))
    fiber_scope = diagram_fiber_type_scope(result)
    if fiber_scope is not None:
        record[_ROUTE_FIBER_SCOPE_SUGGESTION_KEY] = (
            _fiber_type_scope_marker(fiber_scope)
        )
    return record


def _validated_diagram_attachment(
    project: RouteProject,
    diagram: WorkbookDiagram | None,
) -> WorkbookDiagram | None:
    """Validate the session-only diagram against saved route provenance."""

    if validate_workbook_diagram_for_project is None:
        marker = project.diagram_source.get(WORKBOOK_DIAGRAM_MARKER_KEY)
        if marker is not None or diagram is not None:
            raise DiagramAssetError(
                "Diagram attachment validation support is unavailable."
            )
        return None
    return validate_workbook_diagram_for_project(project, diagram)


def _diagram_route_links(
    result: DiagramImportResult,
    rows: Iterable[_ShelfEditorRow],
) -> list[RouteLink]:
    """Convert reviewed route adjacency transcription into first-class links."""

    row_list = list(rows)
    if len(row_list) < 2:
        return []
    by_tid = {row.tid.casefold(): row for row in row_list if row.tid}
    if len(by_tid) != len(row_list):
        raise DiagramImportError(
            "Imported active shelves require unique non-empty TIDs before "
            "their optical links can be retained."
        )
    fiber_scope = diagram_fiber_type_scope(result)
    links: list[RouteLink] = []
    for order, span in enumerate(result.active_spans, start=1):
        from_tid = str(span.from_tid or "").strip()
        to_tid = str(span.to_tid or "").strip()
        from_row = by_tid.get(from_tid.casefold())
        to_row = by_tid.get(to_tid.casefold())
        if from_row is None or to_row is None:
            raise DiagramImportError(
                "Imported span endpoints do not resolve to active shelf IDs."
            )
        source_evidence: dict[str, object] = {
            "schema_id": DIAGRAM_EVIDENCE_SCHEMA_ID,
            "schema_version": DIAGRAM_EVIDENCE_SCHEMA_VERSION,
            "source_sha256": str(
                getattr(getattr(result, "source", None), "sha256", "") or ""
            ),
            "fields": [
                evidence.to_dict()
                for evidence in getattr(span, "evidence", ())
            ],
        }
        discrepancy_prefix = f"spans[{span.order}]."
        source_discrepancies = [
            {
                "field": str(getattr(issue, "field", ""))[
                    len(discrepancy_prefix) :
                ],
                "source_field": str(getattr(issue, "field", "")),
                "issue_code": SOURCE_EVIDENCE_DISCREPANCY_CODE,
                "status": PATH_SOURCE_DISCREPANCY_PENDING,
                "deployable_cli": False,
            }
            for issue in tuple(getattr(result, "issues", ()) or ())
            if str(getattr(issue, "code", "") or "")
            == SOURCE_EVIDENCE_DISCREPANCY_CODE
            and str(getattr(issue, "field", "") or "").startswith(
                discrepancy_prefix
            )
        ]
        if source_discrepancies:
            source_evidence[PATH_SOURCE_DISCREPANCIES_KEY] = (
                source_discrepancies
            )
        if (
            fiber_scope is not None
            and span.order == fiber_scope.inherited_span_order
        ):
            source_evidence[_ROUTE_FIBER_SCOPE_SUGGESTION_KEY] = (
                _fiber_type_scope_marker(fiber_scope)
            )
        links.append(
            RouteLink(
                link_id=f"diagram-link-{order:03}",
                order=order,
                from_shelf_id=from_row.shelf_id,
                to_shelf_id=to_row.shelf_id,
                paths=(
                    OpticalPath(
                        path_id=f"diagram-path-{order:03}-1",
                        path_role="route",
                        link_name=str(
                            getattr(span, "circuit_id", None) or ""
                        ),
                        expected_loss_db=getattr(
                            span, "expected_loss_db", None
                        ),
                        distance_km=getattr(span, "distance_km", None),
                        fiber_type=str(
                            getattr(span, "fiber_type", None) or ""
                        ),
                        circuit_id=str(
                            getattr(span, "circuit_id", None) or ""
                        ),
                        fiber_start=getattr(span, "fiber_start", None),
                        fiber_end=getattr(span, "fiber_end", None),
                        review_state="pending",
                        source_evidence=source_evidence,
                        segments=tuple(
                            OpticalPathSegment(
                                order=getattr(segment, "order", 0),
                                from_tid=str(
                                    getattr(segment, "from_tid", None) or ""
                                ),
                                to_tid=str(
                                    getattr(segment, "to_tid", None) or ""
                                ),
                                expected_loss_db=getattr(
                                    segment, "expected_loss_db", None
                                ),
                                distance_km=getattr(
                                    segment, "distance_km", None
                                ),
                                fiber_type=str(
                                    getattr(segment, "fiber_type", None) or ""
                                ),
                                circuit_id=str(
                                    getattr(segment, "circuit_id", None) or ""
                                ),
                                fiber_start=getattr(
                                    segment, "fiber_start", None
                                ),
                                fiber_end=getattr(
                                    segment, "fiber_end", None
                                ),
                                source_evidence={
                                    "schema_id": (
                                        DIAGRAM_EVIDENCE_SCHEMA_ID
                                    ),
                                    "schema_version": (
                                        DIAGRAM_EVIDENCE_SCHEMA_VERSION
                                    ),
                                    "source_sha256": str(
                                        getattr(
                                            getattr(result, "source", None),
                                            "sha256",
                                            "",
                                        )
                                        or ""
                                    ),
                                    "fields": [
                                        evidence.to_dict()
                                        for evidence in getattr(
                                            segment, "evidence", ()
                                        )
                                    ],
                                },
                            )
                            for segment in tuple(
                                getattr(span, "segments", ()) or ()
                            )
                        ),
                    ),
                ),
            )
        )
    return links


def _diagram_editor_rows(
    result: DiagramImportResult,
) -> list[_ShelfEditorRow]:
    """Convert importer mappings while keeping provider data and evidence apart."""

    rows: list[_ShelfEditorRow] = []
    for raw in result.gui_rows():
        profile_payload = raw.get("profile_payload", {})
        source_evidence = raw.get("source_evidence", {})
        observed_release = str(raw.get("software_release", "")).strip()
        observed_raman_label = str(raw.get("raman_label", "")).strip()
        observed_power_label = str(raw.get("power_label", "")).strip()
        suggested_raman_label = str(
            raw.get("raman_label_suggestion", "")
        ).strip()
        displayed_shelf_variant = str(raw.get("shelf_variant", "")).strip()
        tid = str(raw.get("tid", "")).strip()
        observed_site_code = str(raw.get("site_code", "")).strip()
        suggested_site_code = (
            _review_site_code_suggestion(tid)
            if not observed_site_code
            else ""
        )
        site_code = observed_site_code or suggested_site_code
        if not isinstance(profile_payload, Mapping):
            raise DiagramImportError(
                "Imported shelf profile_payload must be a JSON object."
            )
        if not isinstance(source_evidence, Mapping):
            raise DiagramImportError(
                "Imported shelf source_evidence must be a JSON object."
            )
        # Compatibility with importer drafts created before the dedicated
        # source_evidence field. Exact provider envelopes are never moved.
        if (
            not source_evidence
            and profile_payload.get("schema_id") == DIAGRAM_EVIDENCE_SCHEMA_ID
        ):
            source_evidence = profile_payload
            profile_payload = {}
        if not source_evidence:
            source_evidence = {
                "schema_id": DIAGRAM_EVIDENCE_SCHEMA_ID,
                "schema_version": DIAGRAM_EVIDENCE_SCHEMA_VERSION,
                "source_sha256": result.source.sha256,
                "fields": [],
            }
        source_evidence = dict(source_evidence)
        if not observed_release:
            # The vision importer remains facts-only. A missing release is
            # supplied here by the Route Builder's fixed product scope and is
            # recorded separately from customer-diagram evidence.
            source_evidence["software_release_scope_default"] = {
                "value": R40_UI_RELEASE,
                "reason": _SOFTWARE_RELEASE_SCOPE_DEFAULT_REASON,
            }
        if suggested_site_code:
            source_evidence["site_code_review_suggestion"] = {
                "value": suggested_site_code,
                "source_field": "tid",
                "reason": _SITE_CODE_REVIEW_SUGGESTION_REASON,
            }
        default_power_label = power_label_for_profile(
            str(raw.get("profile_id", ""))
        )
        if not observed_power_label and default_power_label:
            source_evidence[_POWER_LABEL_ROLE_DEFAULT_KEY] = (
                _power_label_role_default_marker(
                    str(raw.get("profile_id", ""))
                )
            )
        elif observed_power_label:
            source_evidence.pop(_POWER_LABEL_ROLE_DEFAULT_KEY, None)
        source_variant = str(
            source_evidence.get("shelf_variant", "") or ""
        ).strip()
        source_chassis = str(
            source_evidence.get("chassis", "") or ""
        ).strip()
        if (
            not source_variant
            and displayed_shelf_variant
            and displayed_shelf_variant == source_chassis
        ):
            source_evidence["shelf_variant_chassis_suggestion"] = {
                "value": displayed_shelf_variant,
                "source_field": "chassis",
                "reason": _SHELF_VARIANT_CHASSIS_SUGGESTION_REASON,
            }
        rows.append(
            _ShelfEditorRow(
                shelf_id=str(raw.get("shelf_id", "")),
                profile_id=str(raw.get("profile_id", "")),
                site_key=(
                    f"site-{site_code.casefold()}"
                    if suggested_site_code
                    else str(raw.get("site_key", ""))
                ),
                site_code=site_code,
                site_name=str(raw.get("site_name", "")),
                tid=tid,
                primary_oam_ip=str(raw.get("primary_oam_ip", "")),
                software_release=observed_release or R40_UI_RELEASE,
                shelf_variant=displayed_shelf_variant,
                raman_label=observed_raman_label or suggested_raman_label,
                power_label=observed_power_label or default_power_label,
                site_address=str(raw.get("site_address", "")),
                network_site_id=str(raw.get("network_site_id", "")),
                notes=str(raw.get("notes", "")),
                profile_payload=dict(profile_payload),
                review_state="pending",
                source_evidence=source_evidence,
            )
        )
    return rows


def diagram_issue_summary(
    issues: Iterable[Any],
    *,
    limit: int = 8,
) -> str:
    """Format privacy-safe aggregated transcription diagnostics for review."""

    if limit < 1:
        raise ValueError("Diagram issue summary limit must be positive.")
    aggregate = aggregate_diagram_review_issues(issues)
    if not aggregate.required_review_count:
        return "No field-level blockers were reported."
    lines = [
        "- Transcription issue types: "
        + _format_count_pairs(aggregate.code_counts, limit=limit),
        "- Affected field paths: "
        + _format_count_pairs(aggregate.required_path_counts, limit=limit),
    ]
    if aggregate.missing_leaf_counts:
        lines.extend(
            (
                "- Absent diagram fields: "
                + _format_count_pairs(
                    aggregate.missing_leaf_counts,
                    limit=limit,
                ),
                "- Absent field paths: "
                + _format_count_pairs(
                    aggregate.missing_path_counts,
                    limit=limit,
                ),
            )
        )
    return "\n".join(lines)


_CRITICAL_BBOX_EVIDENCE_FIELDS = {
    "route": {"route_code", "title", "ospf_area"},
    "shelves": {
        "tid",
        "primary_oam_ip",
        "site_code",
        "site_name",
        "profile_family",
        "chassis",
        "lifecycle",
    },
    "spans": {"from_tid", "to_tid"},
}
_DISCARDED_EVIDENCE_FIELD_RE = re.compile(
    r"\bEvidence for ['\"](?P<field>[a-z][a-z0-9_.]*)['\"] was discarded\b"
)


def _nonblank_import_value(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _discarded_critical_bbox(issue: object) -> bool:
    """Return whether an invalid bbox removed route-identity evidence.

    ``INVALID_EVIDENCE_BBOX`` predates the GUI mutation gate and stores the
    evidence-list location in ``field``.  Its controlled message includes the
    logical evidence field. Unknown future forms fail closed unless they are
    explicitly configuration-only evidence.
    """

    if getattr(issue, "code", "") != "INVALID_EVIDENCE_BBOX":
        return False
    issue_path = str(getattr(issue, "field", ""))
    if ".config_evidence[" in issue_path:
        return False
    if issue_path.startswith("route.evidence["):
        scope = "route"
    elif issue_path.startswith("shelves[") and ".evidence[" in issue_path:
        scope = "shelves"
    elif issue_path.startswith("spans[") and ".evidence[" in issue_path:
        scope = "spans"
    else:
        return True

    match = _DISCARDED_EVIDENCE_FIELD_RE.search(
        str(getattr(issue, "message", ""))
    )
    if match is None:
        return True
    return match.group("field") in _CRITICAL_BBOX_EVIDENCE_FIELDS[scope]


def diagram_import_mutation_blockers(
    result: DiagramImportResult,
) -> tuple[DiagramImportMutationBlocker, ...]:
    """Return structural transcription failures that forbid GUI replacement.

    This deliberately does not use the importer's general ``blocking_issues``
    collection. Missing shelf role, OAM IP, chassis, release, variant, power,
    RAMAN, or generator-specific values are review/readiness problems; an
    otherwise coherent route must still be allowed into pending human review.
    Missing source site fields may also enter review when the observed TID has
    a conservative prefix that the editor can mark explicitly as a suggestion.
    """

    blockers: list[DiagramImportMutationBlocker] = []

    for field_name, label in (
        ("route_code", "Route code"),
        ("title", "Route title"),
        ("ospf_area", "OSPF area"),
    ):
        if not _nonblank_import_value(getattr(result, field_name, None)):
            blockers.append(
                DiagramImportMutationBlocker(
                    "MISSING_ROUTE_IDENTITY",
                    f"route.{field_name}",
                    f"{label} is absent from the transcription.",
                )
            )

    if _nonblank_import_value(getattr(result, "title", None)) and any(
        bool(getattr(issue, "blocking", False))
        and str(getattr(issue, "field", "") or "") == "route.title"
        for issue in tuple(getattr(result, "issues", ()) or ())
    ):
        blockers.append(
            DiagramImportMutationBlocker(
                "UNSUPPORTED_ROUTE_TITLE",
                "route.title",
                (
                    "The transcribed route title is not backed by an exact "
                    "source observation or the controlled terminal-site "
                    "derivation."
                ),
            )
        )

    orientation_issues = tuple(
        issue
        for issue in tuple(getattr(result, "issues", ()) or ())
        if bool(getattr(issue, "blocking", False))
        and str(getattr(issue, "code", "") or "")
        in {
            "ROUTE_ORIENTATION_AMBIGUOUS",
            "ROUTE_ORIENTATION_MISMATCH",
            "ROUTE_ORIENTATION_UNRESOLVED",
        }
    )
    if orientation_issues:
        blockers.append(
            DiagramImportMutationBlocker(
                "MISSING_ROUTE_ORIENTATION",
                "shelves",
                (
                    "The diagram does not establish one directly corroborated "
                    "terminal A/Z order."
                ),
            )
        )

    shelves = tuple(getattr(result, "shelves", ()) or ())
    active_shelves = tuple(getattr(result, "active_shelves", ()) or ())
    if len(active_shelves) < 2:
        blockers.append(
            DiagramImportMutationBlocker(
                "INSUFFICIENT_ACTIVE_SHELVES",
                "shelves",
                "A route transcription requires at least two active shelves.",
            )
        )

    shelf_orders = [getattr(shelf, "order", None) for shelf in shelves]
    if shelf_orders != list(range(1, len(shelves) + 1)):
        blockers.append(
            DiagramImportMutationBlocker(
                "NONCONTIGUOUS_SHELF_ORDER",
                "shelves",
                "Shelf records are not in exact contiguous source order.",
            )
        )
    active_orders = [getattr(shelf, "order", None) for shelf in active_shelves]
    if active_orders != sorted(
        order for order in active_orders if isinstance(order, int)
    ) or len(set(active_orders)) != len(active_orders):
        blockers.append(
            DiagramImportMutationBlocker(
                "NONCONTIGUOUS_ACTIVE_SHELF_ORDER",
                "shelves",
                "Active shelves do not preserve one unambiguous route order.",
            )
        )

    for index, shelf in enumerate(active_shelves, start=1):
        order = getattr(shelf, "order", index)
        prefix = f"shelves[{order}]"
        # TID is the customer-observed endpoint key used to prove that spans
        # follow shelf order. OAM IP and chassis are required before an exact
        # configuration can validate, but neither establishes route topology;
        # keep those fields blank for explicit operator review instead of
        # rejecting an otherwise coherent transcription.
        if not _nonblank_import_value(getattr(shelf, "tid", None)):
            blockers.append(
                DiagramImportMutationBlocker(
                    "MISSING_SHELF_IDENTITY",
                    f"{prefix}.tid",
                    f"Active shelf {order} has no TID.",
                )
            )
        has_source_site = (
            _nonblank_import_value(getattr(shelf, "site_code", None))
            or _nonblank_import_value(getattr(shelf, "site_name", None))
        )
        suggested_site_code = _review_site_code_suggestion(
            str(getattr(shelf, "tid", "") or "")
        )
        if not has_source_site and not suggested_site_code:
            blockers.append(
                DiagramImportMutationBlocker(
                    "MISSING_SHELF_IDENTITY",
                    f"{prefix}.site",
                    (
                        f"Active shelf {order} has no site identifier or name, "
                        "and its TID cannot support a conservative site-code "
                        "review suggestion."
                    ),
                )
            )
    spans = tuple(getattr(result, "spans", ()) or ())
    active_spans = tuple(getattr(result, "active_spans", ()) or ())
    span_orders = [getattr(span, "order", None) for span in spans]
    if span_orders != list(range(1, len(spans) + 1)):
        blockers.append(
            DiagramImportMutationBlocker(
                "NONCONTIGUOUS_SPAN_ORDER",
                "spans",
                "Span records are not in exact contiguous source order.",
            )
        )

    expected_span_count = max(0, len(active_shelves) - 1)
    if len(active_spans) != expected_span_count:
        blockers.append(
            DiagramImportMutationBlocker(
                "ACTIVE_SPAN_COUNT",
                "spans",
                (
                    f"Expected {expected_span_count} active spans for "
                    f"{len(active_shelves)} active shelves; found "
                    f"{len(active_spans)}."
                ),
            )
        )

    expected_pairs = [
        (getattr(left, "tid", None), getattr(right, "tid", None))
        for left, right in zip(active_shelves, active_shelves[1:])
    ]
    actual_pairs = [
        (getattr(span, "from_tid", None), getattr(span, "to_tid", None))
        for span in active_spans
    ]
    if actual_pairs != expected_pairs:
        blockers.append(
            DiagramImportMutationBlocker(
                "SPAN_ROUTE_DISCONTINUITY",
                "spans",
                "Active span endpoints do not exactly follow active shelf order.",
            )
        )

    if any(
        _discarded_critical_bbox(issue)
        for issue in tuple(getattr(result, "issues", ()) or ())
    ):
        blockers.append(
            DiagramImportMutationBlocker(
                "CRITICAL_EVIDENCE_BBOX_DISCARDED",
                "evidence",
                (
                    "A malformed evidence rectangle discarded route identity "
                    "or topology evidence."
                ),
            )
        )

    return tuple(blockers)


def _descriptor_value(profile_id: str, attribute: str, default: str = "") -> str:
    descriptor = PROFILE_REGISTRY.get(profile_id)
    value = getattr(descriptor, attribute, default) if descriptor is not None else default
    return str(value or default)


def profile_display_name(profile_id: str) -> str:
    """Return the operator-facing name for a registered route shelf profile."""

    if not str(profile_id or "").strip():
        return UNRESOLVED_PROFILE_LABEL
    return _descriptor_value(profile_id, "display_name", profile_id)


def profile_is_planning_only(profile_id: str) -> bool:
    descriptor = PROFILE_REGISTRY.get(profile_id)
    return bool(
        True if descriptor is None else getattr(descriptor, "planning_only", True)
    )


def _r40_payload_version_state(
    profile_payload: Optional[Mapping[str, Any]],
) -> str:
    """Return ``current``, ``retired``, or ``absent`` for an exact payload."""

    if (
        not isinstance(profile_payload, Mapping)
        or profile_payload.get("schema_id")
        != "ciena.rls.r4-0-exact-request"
    ):
        return "absent"
    from utils.rls_config.r4_0_generator import (
        R40_SUPPORTED_PAYLOAD_SCHEMA_VERSIONS,
    )

    return (
        "current"
        if profile_payload.get("schema_version")
        in R40_SUPPORTED_PAYLOAD_SCHEMA_VERSIONS
        else "retired"
    )


def profile_readiness_label(
    profile_id: str,
    *,
    review_state: str = "manual",
    advisory_label: str = "",
    profile_payload: Optional[Mapping[str, Any]] = None,
) -> str:
    """Short, unambiguous readiness label used in the shelf table."""

    if review_state == "pending":
        return "Pending review — CLI blocked"
    payload_state = _r40_payload_version_state(profile_payload)
    has_exact_payload = payload_state == "current"
    if payload_state == "retired":
        return "Exact review outdated — re-review required"
    if review_state in {"confirmed", "corrected"} and not has_exact_payload:
        return "Confirmed - CLI Pending"
    if has_exact_payload:
        if advisory_label and advisory_label != "R4.0 review only — CLI gated":
            return advisory_label
        return "Exact R4.0 provider — validation pending"
    if profile_is_planning_only(profile_id):
        return "R4.0 review only — CLI gated"
    return advisory_label or "Provider available — validation pending"


_R40_SRA_PROVIDER_REASON_CODES = frozenset(
    {
        "R40_SRA_PROVIDER_UNAVAILABLE",
        "R40_SRA_CAPABLE_PROVIDER_UNAVAILABLE",
        "R40_EXACT_PROVIDER_SRA_CONFLICT",
    }
)


def _r40_sole_candidate_provider_id(
    provider_resolution: Mapping[str, object],
) -> str:
    """Return the sole non-conflicting review provider, otherwise blank.

    This is a review-visibility predicate only.  It does not establish the
    installed packout, construct a request, or authorize generated CLI.
    """

    if (
        str(provider_resolution.get("status", "") or "").strip()
        not in {"exact_match", "unique_candidate"}
    ):
        return ""
    if (
        str(
            provider_resolution.get(
                "raman_callout_review_status",
                "not_applicable",
            )
            or ""
        )
        .strip()
        .casefold()
        in {"pending", "invalid"}
    ):
        return ""
    provider_id = str(
        provider_resolution.get("provider_id", "") or ""
    ).strip()
    raw_ids = provider_resolution.get("review_provider_ids", ())
    if not provider_id or not isinstance(raw_ids, (list, tuple)):
        return ""
    review_ids = tuple(
        dict.fromkeys(
            str(item).strip()
            for item in raw_ids
            if isinstance(item, str) and item.strip()
        )
    )
    if review_ids != (provider_id,):
        return ""
    raw_codes = provider_resolution.get("reason_codes", ())
    reason_codes = (
        {
            str(item).strip().upper()
            for item in raw_codes
            if isinstance(item, str) and item.strip()
        }
        if isinstance(raw_codes, (list, tuple))
        else set()
    )
    if reason_codes.intersection(_R40_SRA_PROVIDER_REASON_CODES):
        return ""
    return provider_id


def _r40_direction_mapping_text(
    profile: Any,
    line_1_route_side: object,
) -> str:
    """Render fixed hardware records without inventing a return degree."""

    side = str(line_1_route_side or "").strip().upper()
    if side not in {"A", "Z"}:
        return ""
    line_outputs = getattr(profile, "line_outputs", ())
    if not isinstance(line_outputs, (list, tuple)) or len(line_outputs) not in {
        1,
        2,
    }:
        return ""
    semantics = str(getattr(profile, "line_semantics", "") or "")
    record = (
        "D"
        if semantics == "bidirectional_degree"
        else "P"
        if semantics == "unidirectional_amplifier_path"
        else ""
    )
    if not record:
        return ""
    if len(line_outputs) == 1:
        suffix = " (both flows)" if record == "D" else ""
        return f"{record}1→{side}{suffix}"
    opposite = "Z" if side == "A" else "A"
    return f"{record}1→{side} / {record}2→{opposite}"


def _r40_shelf_glance_labels(
    project: RouteProject,
    shelf: ShelfInstance,
) -> tuple[str, str]:
    """Return synchronized provider and fixed-direction table summaries."""

    from utils.rls_config.r4_0_generator import (
        R40ExactConfigGenerator,
        R40_PROVIDER_CATALOG,
        decode_r40_exact_payload,
    )

    raman_status = _raman_callout_review_status(shelf.source_evidence)
    if raman_status == "pending":
        return ("SRA review pending", "Blocked — SRA review pending")
    if raman_status == "invalid":
        return ("Invalid SRA evidence", "Invalid direction evidence")

    payload = shelf.profile_payload
    if payload:
        payload_state = _r40_payload_version_state(payload)
        if payload_state == "retired":
            return (
                "Stale provider review — re-review",
                "Stale direction review — re-review",
            )
        if payload_state != "current":
            return (
                "Invalid provider review — re-review",
                "Invalid direction review — re-review",
            )
        try:
            request = decode_r40_exact_payload(payload)
        except (TypeError, ValueError):
            return (
                "Invalid provider review — re-review",
                "Invalid direction review — re-review",
            )
        profile = R40_PROVIDER_CATALOG.get(request.provider_id)
        if (
            profile is None
            or request.profile != shelf.profile_id
            or shelf.profile_id not in profile.role_profiles
            or request.software_release != shelf.software_release
            or request.shelf_name != shelf.tid
            or request.loopback_ip != shelf.primary_oam_ip
            or _r40_provider_route_band_mismatches(profile, shelf, project)
        ):
            return (
                "Invalid provider review — re-review",
                "Invalid direction review — re-review",
            )
        if raman_status == "accepted" and not profile.supports_raman:
            return ("SRA provider required", "Blocked — SRA provider required")
        if _r40_sra_evidence_mismatches(profile, shelf):
            return (
                "SRA evidence mismatch — re-review",
                "Blocked — SRA evidence mismatch",
            )
        try:
            validation_issues = R40ExactConfigGenerator().validate(request)
        except (TypeError, ValueError):
            return (
                "Invalid provider review — re-review",
                "Invalid direction review — re-review",
            )
        if any(issue.severity == "error" for issue in validation_issues):
            return (
                "Invalid provider review — re-review",
                "Invalid direction review — re-review",
            )
        mapping = _r40_direction_mapping_text(
            profile,
            request.line_1_route_side,
        )
        if isinstance(project, RouteProject):
            topology_issues = _r40_route_topology_issues(
                request,
                shelf,
                project,
            )
            if topology_issues and all(
                issue.code == R40_PENDING_SRA_PEER_REVIEW
                for issue in topology_issues
            ):
                return (
                    f"Staged — {profile.display_name} (SRA peer pending)",
                    (
                        f"Staged — {mapping} (SRA peer pending)"
                        if mapping
                        else "Invalid direction review — re-review"
                    ),
                )
            if topology_issues:
                return (
                    "Topology mismatch — re-review",
                    "Blocked — topology mismatch",
                )
        return (
            f"Applied — {profile.display_name}",
            (
                f"Applied — {mapping}"
                if mapping
                else "Invalid direction review — re-review"
            ),
        )

    try:
        provider_resolution, direction_resolution = (
            _r4_0_provider_prepopulation(project, shelf)
        )
    except (TypeError, ValueError):
        return ("Invalid provider evidence", "Invalid direction evidence")
    provider_id = str(
        provider_resolution.get("provider_id", "") or ""
    ).strip()
    raw_review_ids = provider_resolution.get("review_provider_ids", ())
    review_ids = (
        tuple(
            dict.fromkeys(
                candidate_id
                for candidate_id in raw_review_ids
                if (
                    isinstance(candidate_id, str)
                    and candidate_id in R40_PROVIDER_CATALOG
                    and shelf.profile_id
                    in R40_PROVIDER_CATALOG[candidate_id].role_profiles
                    and not _r40_provider_route_band_mismatches(
                        R40_PROVIDER_CATALOG[candidate_id],
                        shelf,
                        project,
                    )
                    and not (
                        raman_status == "accepted"
                        and not R40_PROVIDER_CATALOG[
                            candidate_id
                        ].supports_raman
                    )
                )
            )
        )
        if isinstance(raw_review_ids, (list, tuple))
        else ()
    )
    checked_provider_resolution = {
        **provider_resolution,
        "review_provider_ids": list(review_ids),
    }
    sole_provider_id = _r40_sole_candidate_provider_id(
        checked_provider_resolution
    )
    profile = R40_PROVIDER_CATALOG.get(sole_provider_id)
    resolution_status = str(
        provider_resolution.get("status", "") or ""
    ).strip()
    if profile is not None:
        provider_prefix = (
            "Suggested"
            if provider_resolution.get("preselect_allowed") is True
            else "Candidate"
        )
        provider_label = f"{provider_prefix} — {profile.display_name}"
    elif resolution_status == "conflict":
        provider_label = "Provider conflict — review required"
    elif review_ids:
        provider_label = f"Select provider ({len(review_ids)} compatible)"
    elif raman_status == "accepted":
        provider_label = "SRA provider required"
    else:
        provider_label = "No compatible provider"

    if raman_status == "accepted" and profile is None:
        return (provider_label, "Blocked — SRA provider required")
    if profile is None:
        if resolution_status == "conflict":
            return (provider_label, "Blocked — provider conflict")
        if review_ids:
            return (provider_label, "Blocked — select provider")
        return (provider_label, "Blocked — no compatible provider")

    direction_status = str(
        direction_resolution.get("status", "") or ""
    ).strip()
    if direction_status in {"exact_match", "controlled_fallback"}:
        mapping = _r40_direction_mapping_text(
            profile,
            direction_resolution.get("line_1_route_side", ""),
        )
        if not mapping:
            return (provider_label, "Invalid direction evidence")
        prefix = "Direct" if direction_status == "exact_match" else "Derived"
        return (provider_label, f"{prefix} — {mapping}")
    if direction_status == "conflict":
        return (provider_label, "Blocked — direction conflict")
    if direction_status == "ambiguous":
        return (provider_label, "Blocked — direction ambiguous")
    return (provider_label, "Blocked — direction review required")


def r40_provider_glance_label(
    project: RouteProject,
    shelf: ShelfInstance,
) -> str:
    """Return the fail-closed exact-provider summary for the shelf table."""

    return _r40_shelf_glance_labels(project, shelf)[0]


def r40_direction_glance_label(
    project: RouteProject,
    shelf: ShelfInstance,
) -> str:
    """Return the fail-closed fixed-record-to-route-side summary."""

    return _r40_shelf_glance_labels(project, shelf)[1]


def provider_identity_changed(
    current: _ShelfEditorRow,
    replacement: _ShelfEditorRow,
) -> bool:
    """Return whether an edit invalidates a provider-specific request payload."""

    provider_fields = (
        "profile_id",
        "site_key",
        "site_code",
        "site_name",
        "tid",
        "primary_oam_ip",
        "software_release",
        "shelf_variant",
    )
    return any(
        str(getattr(current, field_name)).strip()
        != str(getattr(replacement, field_name)).strip()
        for field_name in provider_fields
    )


def _review_raman_callout_evidence(
    source_evidence: Mapping[str, Any],
    raman_label: str,
) -> tuple[dict[str, Any], bool]:
    """Record explicit operator disposition of imported SRA callouts.

    A display label is never interpreted as RAMAN hardware on its own. This
    transition applies only when the source evidence already contains
    structured, source-bound shelf-endpoint callouts.
    """

    reviewed = dict(source_evidence)
    raw_callouts = reviewed.get("raman_callouts")
    if not isinstance(raw_callouts, (list, tuple)) or not raw_callouts:
        return (reviewed, False)
    old_review = reviewed.get("raman_callout_review", "pending")
    if isinstance(old_review, Mapping):
        old_status = str(old_review.get("status", "pending"))
    else:
        old_status = str(old_review)
    new_status = "accepted" if raman_label.strip() else "rejected"
    reviewed["raman_callout_review"] = new_status
    reviewed["raman_callout_review_record"] = {
        "status": new_status,
        "display_text": raman_label.strip(),
        "action": "operator_update_selected",
        "deployable_cli": False,
    }
    compatibility_changed = (
        old_status == "accepted"
    ) != (new_status == "accepted")
    return (reviewed, compatibility_changed)


def _has_accepted_structured_sra(
    source_evidence: Mapping[str, Any],
) -> bool:
    raw_callouts = source_evidence.get("raman_callouts")
    if not isinstance(raw_callouts, (list, tuple)) or not raw_callouts:
        return False
    raw_review = source_evidence.get("raman_callout_review", "pending")
    if isinstance(raw_review, Mapping):
        status = raw_review.get("status")
    else:
        status = raw_review
    return status == "accepted"


def _raman_callout_review_status(
    source_evidence: Mapping[str, Any],
) -> str:
    """Return the fail-closed operator-review state for structured callouts."""

    raw_callouts = source_evidence.get("raman_callouts")
    if raw_callouts is None:
        return "not_applicable"
    if not isinstance(raw_callouts, (list, tuple)):
        return "invalid"
    if not raw_callouts:
        return "not_applicable"
    raw_review = source_evidence.get("raman_callout_review", "pending")
    if isinstance(raw_review, Mapping):
        raw_status = raw_review.get("status", "pending")
    else:
        raw_status = raw_review
    status = str(raw_status or "").strip().casefold()
    return status if status in {"accepted", "rejected", "pending"} else "invalid"


def _source_scoped_no_sra_observation(
    project: RouteProject,
    shelf: ShelfInstance,
) -> bool:
    """Return a review-only SRA absence fact from the enabled source convention.

    This narrows the provider dropdown only. It does not prove installed
    inventory or authorize CLI. Any unassigned source callout keeps the
    absence unknown for every shelf because its intended endpoint is unresolved.
    """

    evidence = shelf.source_evidence
    convention = evidence.get("raman_callout_convention")
    source_sha256 = evidence.get("source_sha256")
    if (
        not isinstance(convention, Mapping)
        or convention.get("id")
        != RAMAN_CALLOUT_CONVENTION_SMALL_RED_SLOT_PORT
        or convention.get("scope") != "source"
        or convention.get("deployable_cli") is not False
        or not isinstance(source_sha256, str)
        or not source_sha256
        or convention.get("source_sha256") != source_sha256
    ):
        return False
    raw_callouts = evidence.get("raman_callouts")
    if not isinstance(raw_callouts, (list, tuple)) or raw_callouts:
        return False
    raw_review = evidence.get("raman_callout_review", "not_applicable")
    if isinstance(raw_review, Mapping):
        raw_review = raw_review.get("status", "not_applicable")
    if str(raw_review or "").strip().casefold() not in {
        "not_applicable",
        "rejected",
    }:
        return False
    suggestion = evidence.get("raman_callout_suggestion")
    if isinstance(suggestion, Mapping) and suggestion.get("raman_present") is True:
        return False
    if shelf.raman_label.strip().casefold() not in {
        "",
        "no",
        "none",
        "not applicable",
    }:
        return False
    diagram_source = getattr(project, "diagram_source", {})
    if not isinstance(diagram_source, Mapping):
        return False
    for key in ("unassigned_raman_callouts", "unknown_callouts"):
        unresolved = diagram_source.get(key, ())
        if not isinstance(unresolved, (list, tuple)) or unresolved:
            return False
    return True


def _r4_0_candidate_sra_state(
    project: RouteProject,
    shelf: ShelfInstance,
) -> str:
    """Return present/absent/unknown for non-executable provider filtering."""

    evidence = shelf.source_evidence
    if _has_accepted_structured_sra(evidence):
        return "present"
    if _source_scoped_no_sra_observation(project, shelf):
        return "absent"
    raman_label = shelf.raman_label.strip()
    if (
        raman_label.casefold() in {"no", "none", "not applicable"}
        and _direct_diagram_fact(evidence, "raman_label", raman_label)
    ):
        return "absent"
    return "unknown"


def _next_pending_shelf_id(
    rows: Sequence[_ShelfEditorRow],
    current_index: int,
) -> str:
    """Return the next pending shelf after the current row, with one wrap."""

    if not rows or current_index < 0 or current_index >= len(rows):
        return ""
    for offset in range(1, len(rows) + 1):
        row = rows[(current_index + offset) % len(rows)]
        if row.review_state == "pending":
            return row.shelf_id
    return ""


def _next_exact_config_review_shelf_id(
    rows: Sequence[_ShelfEditorRow],
    current_index: int,
) -> str:
    """Return the next shelf that can enter an available exact-provider review."""

    if not rows or current_index < 0 or current_index >= len(rows):
        return ""
    from utils.rls_config.r4_0_generator import provider_profiles_for_role

    for offset in range(1, len(rows) + 1):
        row = rows[(current_index + offset) % len(rows)]
        if (
            _r40_payload_version_state(row.profile_payload) == "current"
        ):
            continue
        providers = provider_profiles_for_role(row.profile_id)
        if _has_accepted_structured_sra(row.source_evidence):
            providers = tuple(
                provider for provider in providers if provider.supports_raman
            )
        if providers:
            return row.shelf_id
    return ""


def _exact_config_review_progress(
    rows: Sequence[_ShelfEditorRow],
) -> tuple[int, int]:
    """Return completed and total exact-provider review counts."""

    return (
        sum(
            _r40_payload_version_state(row.profile_payload) == "current"
            for row in rows
        ),
        len(rows),
    )


def imported_values_changed(
    current: _ShelfEditorRow,
    replacement: _ShelfEditorRow,
) -> bool:
    """Return whether an operator corrected any visible imported field."""

    visible_fields = (
        "profile_id",
        "site_code",
        "site_name",
        "tid",
        "primary_oam_ip",
        "software_release",
        "shelf_variant",
        "raman_label",
        "power_label",
    )
    return any(
        str(getattr(current, field_name)).strip()
        != str(getattr(replacement, field_name)).strip()
        for field_name in visible_fields
    )


def profile_choices() -> tuple[tuple[str, str], ...]:
    """Return only RLS R4.0 route roles exposed to operators."""

    return tuple(
        (profile_id, profile_display_name(profile_id))
        for profile_id in R40_UI_PROFILE_IDS
        if profile_id in PROFILE_REGISTRY
    )


def _site_key_for(code: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "-", code.strip().casefold()).strip("-")
    return f"site-{token or uuid4().hex[:8]}"


def _filename_stem(value: str, fallback: str = "Ciena_RLS_Route") -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._")
    return stem or fallback


def _release_is_exact(value: str, major: int, minor: int) -> bool:
    return value.strip() == f"RLS R{major}.{minor}"


def _r40_only_rows_error(rows: Iterable[object]) -> str:
    """Explain why rows cannot enter the RLS R4.0-only operator workflow."""

    row_list = tuple(rows)

    def pending_unresolved_diagram_role(row: object) -> bool:
        evidence = getattr(row, "source_evidence", {})
        return (
            not str(getattr(row, "profile_id", "") or "").strip()
            and getattr(row, "review_state", "") == "pending"
            and isinstance(evidence, Mapping)
            and evidence.get("schema_id") == DIAGRAM_EVIDENCE_SCHEMA_ID
        )

    unsupported_profiles = sorted(
        {
            str(getattr(row, "profile_id", "") or "")
            for row in row_list
            if getattr(row, "profile_id", None) not in _R40_UI_PROFILE_ID_SET
            and not pending_unresolved_diagram_role(row)
        }
    )
    unsupported_releases = sorted(
        {
            str(getattr(row, "software_release", "") or "")
            for row in row_list
            if not _release_is_exact(
                str(getattr(row, "software_release", "") or ""),
                4,
                0,
            )
        }
    )
    details: list[str] = []
    if unsupported_profiles:
        details.append(
            "unsupported shelf role(s): "
            + ", ".join(value or "<blank>" for value in unsupported_profiles)
        )
    if unsupported_releases:
        details.append(
            "non-R4.0 release value(s): "
            + ", ".join(value or "<blank>" for value in unsupported_releases)
        )
    if not details:
        return ""
    return (
        "The Ciena RLS Route Builder accepts exact RLS R4.0 Add/Drop, ILA, "
        "and ROADM projects only; " + "; ".join(details) + "."
    )


def _reconcile_route_links(
    rows: Iterable[_ShelfEditorRow],
    existing_links: Iterable[RouteLink],
    *,
    populate_missing: bool,
) -> list[RouteLink]:
    """Retain physical span facts only when their shelf pair still exists."""

    row_list = list(rows)
    link_list = list(existing_links)
    if not populate_missing or len(row_list) < 2:
        return []
    available: dict[frozenset[str], list[RouteLink]] = {}
    for link in link_list:
        key = frozenset((link.from_shelf_id, link.to_shelf_id))
        available.setdefault(key, []).append(link)

    reconciled: list[RouteLink] = []
    for order, (left, right) in enumerate(
        zip(row_list, row_list[1:]),
        start=1,
    ):
        key = frozenset((left.shelf_id, right.shelf_id))
        candidates = available.get(key, [])
        prior = candidates.pop(0) if candidates else None
        if prior is None:
            paths = (
                OpticalPath(
                    path_id=f"manual-path-{uuid4().hex}",
                    path_role="route",
                    review_state="manual",
                ),
            )
            link_id = f"manual-link-{uuid4().hex}"
        else:
            paths = prior.paths
            link_id = prior.link_id
        reconciled.append(
            RouteLink(
                link_id=link_id,
                order=order,
                from_shelf_id=left.shelf_id,
                to_shelf_id=right.shelf_id,
                paths=paths,
            )
        )
    return reconciled


def _route_profile_family(profile_id: str) -> str:
    """Return the role family whose A/Z suffix is route-order-derived."""

    normalized = str(profile_id or "").strip().casefold()
    if normalized in {"add_drop", "add_drop_a", "add_drop_z"}:
        return "add_drop"
    if normalized in {"roadm", "roadm_a", "roadm_z"}:
        return "roadm"
    return normalized


def _route_row_site_identity(row: _ShelfEditorRow) -> str:
    """Return one stable site identity for endpoint-side derivation."""

    return (
        str(row.site_key or "").strip().casefold()
        or str(row.site_code or "").strip().casefold()
        or str(row.site_name or "").strip().casefold()
        or f"shelf:{row.shelf_id}"
    )


def _reconcile_route_endpoint_profiles(
    rows: Iterable[_ShelfEditorRow],
) -> tuple[list[_ShelfEditorRow], int]:
    """Recompute A/Z role suffixes from the current ordered terminal sites.

    Add/Drop and ROADM side suffixes are derived route facts, not immutable
    hardware attributes. Reordering therefore updates every affected endpoint
    role. ILA roles and unresolved roles remain unchanged.
    """

    row_list = list(rows)
    ordered_sites: list[str] = []
    for row in row_list:
        identity = _route_row_site_identity(row)
        if identity not in ordered_sites:
            ordered_sites.append(identity)
    a_site = ordered_sites[0] if len(ordered_sites) >= 2 else ""
    z_site = ordered_sites[-1] if len(ordered_sites) >= 2 else ""

    reconciled: list[_ShelfEditorRow] = []
    changed = 0
    for row in row_list:
        family = _route_profile_family(row.profile_id)
        if family not in {"add_drop", "roadm"}:
            reconciled.append(row)
            continue
        identity = _route_row_site_identity(row)
        if a_site and identity == a_site:
            side = "A"
        elif z_site and identity == z_site:
            side = "Z"
        else:
            side = ""
        expected_profile = (
            f"{family}_{side.casefold()}" if side else family
        )
        if expected_profile == row.profile_id:
            reconciled.append(row)
            continue
        evidence = dict(row.source_evidence)
        if (
            _has_exact_power_label_role_default(
                evidence,
                row.profile_id,
                row.power_label,
            )
            and row.power_label == power_label_for_profile(expected_profile)
        ):
            # A/Z suffixes are route-order derivations, while Add/Drop and
            # ROADM use the same ATLAS power standard on either side. Keep
            # that controlled-default provenance bound to the newly derived
            # profile instead of turning an untouched AC value into an
            # apparent operator override.
            evidence[_POWER_LABEL_ROLE_DEFAULT_KEY] = (
                _power_label_role_default_marker(expected_profile)
            )
        evidence["route_endpoint_derivation"] = {
            "endpoint_side": side,
            "profile_family": family,
            "reason": "current ordered first/last distinct route site",
            "deployable_cli": False,
        }
        reconciled.append(
            replace(
                row,
                profile_id=expected_profile,
                profile_payload={},
                source_evidence=evidence,
            )
        )
        changed += 1
    return reconciled, changed


def _invalidate_route_direction_evidence(
    rows: Iterable[_ShelfEditorRow],
    *,
    reason: str,
) -> tuple[list[_ShelfEditorRow], int]:
    """Retain but disable source-relative endpoint adjacency after reordering."""

    result: list[_ShelfEditorRow] = []
    invalidated = 0
    for row in rows:
        evidence = dict(row.source_evidence)
        line_endpoints = evidence.pop("line_endpoints", None)
        if isinstance(line_endpoints, (list, tuple)) and line_endpoints:
            evidence[_INVALIDATED_LINE_ENDPOINTS_KEY] = list(line_endpoints)
            evidence[_DIRECTION_EVIDENCE_INVALIDATION_KEY] = {
                "reason": reason,
                "endpoint_count": len(line_endpoints),
                "deployable_cli": False,
            }
            row = replace(row, source_evidence=evidence)
            invalidated += 1
        result.append(row)
    return result, invalidated


def _current_terminal_route_title(
    rows: Sequence[_ShelfEditorRow],
    *,
    prior_marker: Mapping[str, object],
    source_sha256: str,
) -> tuple[str, Mapping[str, object]] | None:
    """Derive the display title from the current ordered terminal TIDs."""

    if len(rows) < 2:
        return None
    endpoint_rows = (rows[0], rows[-1])
    endpoint_tids = tuple(row.tid.strip() for row in endpoint_rows)
    endpoint_codes = tuple(
        (
            _review_site_code_suggestion(row.tid)
            or row.site_code.strip()
        ).upper()
        for row in endpoint_rows
    )
    if (
        not all(endpoint_tids)
        or not all(endpoint_codes)
        or endpoint_codes[0] == endpoint_codes[1]
        or any(
            _TERMINAL_ROUTE_TOKEN_RE.fullmatch(code) is None
            for code in endpoint_codes
        )
    ):
        return None

    display_codes = endpoint_codes
    removed_prefix: str | None = None
    if all(code.startswith("US") for code in endpoint_codes):
        stripped = tuple(code[2:] for code in endpoint_codes)
        if all(
            _TERMINAL_ROUTE_TOKEN_RE.fullmatch(code) is not None
            for code in stripped
        ):
            display_codes = stripped
            removed_prefix = "US"
    title = "-".join(display_codes)
    marker: Mapping[str, object] = {
        "rule_id": _TERMINAL_ROUTE_TITLE_RULE_ID,
        "status": "operator_order_derivation",
        "value": title,
        "provider_title": prior_marker.get("provider_title"),
        "observed_header_pair": prior_marker.get("observed_header_pair"),
        "current_endpoint_pair": "-".join(endpoint_codes),
        "endpoint_tids": endpoint_tids,
        "endpoint_codes": endpoint_codes,
        "display_codes": display_codes,
        "removed_shared_prefix": removed_prefix,
        "source_sha256": source_sha256,
        "deployable_cli": False,
    }
    return title, marker


def _clear_provider_payloads(
    rows: Iterable[_ShelfEditorRow],
) -> tuple[list[_ShelfEditorRow], int]:
    """Clear every route-bound provider request after a topology change."""

    cleared = 0
    result: list[_ShelfEditorRow] = []
    for row in rows:
        if row.profile_payload:
            cleared += 1
            row = replace(row, profile_payload={})
        result.append(row)
    return result, cleared


def _r40_sra_pair_binding_signature(request: object) -> tuple[object, ...]:
    """Return only the request fields that bind a reviewed SRA peer."""

    from utils.rls_config.r4_0_generator import R40_PROVIDER_CATALOG

    provider_id = str(getattr(request, "provider_id", "") or "")
    profile = R40_PROVIDER_CATALOG.get(provider_id)
    line_1_side = str(
        getattr(request, "line_1_route_side", "") or ""
    ).strip().upper()
    line_signatures: list[tuple[object, ...]] = []
    for direction in range(len(getattr(profile, "line_outputs", ()))):
        if _r40_sra_line_output(profile, direction) is None:
            continue
        line = getattr(
            request,
            "line_1" if direction == 0 else "line_2",
            None,
        )
        line_signatures.append(
            (
                direction,
                getattr(line, "link_name", None),
                getattr(line, "neighbor_node", None),
                getattr(line, "neighbor_line_mux_pfg", None),
                getattr(line, "neighbor_line_demux_pfg", None),
                getattr(line, "fiber_type", None),
                getattr(line, "expected_loss_db", None),
            )
        )
    return (provider_id, line_1_side, tuple(line_signatures))


def _restage_changed_r40_sra_peers(
    rows: Sequence[_ShelfEditorRow],
    project: RouteProject,
    shelf_id: str,
    previous_request: object | None,
    replacement_request: object,
) -> tuple[list[_ShelfEditorRow], tuple[str, ...]]:
    """Clear paired endpoint payloads after an SRA-bound review change.

    This is intentionally narrow: build, rack, COLAN, and other non-topology
    edits do not discard a reciprocal peer review. Provider, direction, or
    SRA-facing endpoint/path changes do, because the old pair can no longer be
    treated as one validated snapshot.
    """

    result = list(rows)
    if (
        previous_request is None
        or _r40_sra_pair_binding_signature(previous_request)
        == _r40_sra_pair_binding_signature(replacement_request)
    ):
        return (result, ())
    shelf = next(
        (item for item in project.shelves if item.shelf_id == shelf_id),
        None,
    )
    if shelf is None:
        return (result, ())
    peer_ids = tuple(
        dict.fromkeys(
            (
                *_r40_sra_peer_shelf_ids(
                    previous_request,
                    shelf,
                    project,
                ),
                *_r40_sra_peer_shelf_ids(
                    replacement_request,
                    shelf,
                    project,
                ),
            )
        )
    )
    cleared: list[str] = []
    for index, row in enumerate(result):
        if (
            row.shelf_id in peer_ids
            and row.shelf_id != shelf_id
            and row.profile_payload
        ):
            result[index] = replace(row, profile_payload={})
            cleared.append(row.shelf_id)
    return (result, tuple(cleared))


def _validate_r40_candidate_pair_review(
    project: RouteProject,
    shelf_id: str,
) -> _R40CandidatePairReview:
    """Validate a proposed exact payload and any facing SRA peer in full.

    The first locally valid endpoint may return a pending peer only when the
    named pending condition is its sole readiness finding. A completed pair is
    accepted only after both payloads pass the complete generator, identity,
    band, SRA-evidence, and reciprocal-topology contract against this same
    immutable candidate project.
    """

    from utils.rls_config.r4_0_generator import decode_r40_exact_payload

    shelf = next(
        (item for item in project.shelves if item.shelf_id == shelf_id),
        None,
    )
    if shelf is None:
        raise ValueError(
            "The reviewed shelf is absent from the candidate route snapshot."
        )
    current_codes, current_reasons = _r40_payload_readiness(
        shelf.profile_payload,
        shelf,
        project.site_by_key(shelf.site_key),
        project.ospf_area,
        project,
    )
    if current_codes:
        if tuple(current_codes) == (R40_PENDING_SRA_PEER_REVIEW,):
            request = decode_r40_exact_payload(shelf.profile_payload)
            topology_issues = _r40_route_topology_issues(
                request,
                shelf,
                project,
            )
            pending_peer_ids = tuple(
                dict.fromkeys(
                    issue.peer_shelf_id
                    for issue in topology_issues
                    if (
                        issue.code == R40_PENDING_SRA_PEER_REVIEW
                        and issue.peer_shelf_id
                    )
                )
            )
            if (
                pending_peer_ids
                and all(
                    issue.code == R40_PENDING_SRA_PEER_REVIEW
                    for issue in topology_issues
                )
            ):
                return _R40CandidatePairReview(
                    pending_peer_ids=pending_peer_ids
                )
        raise ValueError(
            "The reviewed configuration failed the complete current-snapshot "
            "readiness contract "
            f"({', '.join(current_codes)}):\n• "
            + "\n• ".join(current_reasons)
        )

    request = decode_r40_exact_payload(shelf.profile_payload)
    peer_ids = _r40_sra_peer_shelf_ids(request, shelf, project)
    peer_failures: list[str] = []
    for peer_id in peer_ids:
        peer_shelf = next(
            (
                item
                for item in project.shelves
                if item.shelf_id == peer_id
            ),
            None,
        )
        if peer_shelf is None:
            peer_failures.append(
                f"Paired SRA peer {peer_id!r} is absent from the candidate "
                "route snapshot."
            )
            continue
        peer_codes, peer_reasons = _r40_payload_readiness(
            peer_shelf.profile_payload,
            peer_shelf,
            project.site_by_key(peer_shelf.site_key),
            project.ospf_area,
            project,
        )
        if peer_codes:
            peer_failures.append(
                f"{peer_shelf.tid} ({', '.join(peer_codes)}): "
                + "; ".join(peer_reasons)
            )
    if peer_failures:
        raise ValueError(
            "The paired SRA endpoints did not pass their complete reciprocal "
            "readiness contracts against the same route snapshot:\n• "
            + "\n• ".join(peer_failures)
        )
    return _R40CandidatePairReview(validated_peer_ids=peer_ids)


_BUNDLE_EXACT_REVIEW_CODES = frozenset(
    {
        "EXACT_PROVIDER_REVIEW_REQUIRED",
        "PLANNING_ONLY_PROVIDER_NOT_IMPLEMENTED",
        "INVALID_R40_EXACT_PROFILE_PAYLOAD",
        "UNSUPPORTED_PROVIDER_RELEASE",
        "R40_EXACT_GENERATOR_VALIDATION_FAILED",
        "R40_EXACT_GENERATOR_REJECTED",
        "R40_EXACT_GENERATOR_ERROR",
        "R40_EXACT_PAYLOAD_IDENTITY_MISMATCH",
        "R40_EXACT_ROUTE_TOPOLOGY_MISMATCH",
    }
)
_BUNDLE_PAIRED_SRA_REVIEW_CODES = frozenset(
    {R40_PENDING_SRA_PEER_REVIEW}
)
_BUNDLE_RAMAN_REVIEW_CODES = frozenset(
    {
        "PENDING_RAMAN_CALLOUT_REVIEW",
        "INVALID_RAMAN_CALLOUT_EVIDENCE",
    }
)
_BUNDLE_SRA_PROVIDER_CODES = frozenset(
    {
        "R40_SRA_CAPABLE_PROVIDER_UNAVAILABLE",
        "R40_EXACT_PROVIDER_SRA_CONFLICT",
    }
)
_BUNDLE_NATIVE_FIBER_CODES = frozenset(
    {
        "MISSING_ROUTE_NATIVE_FIBER_REVIEW",
        "INVALID_ROUTE_NATIVE_FIBER_REVIEW",
        "UNSUPPORTED_ROUTE_NATIVE_FIBER",
        "ROUTE_NATIVE_FIBER_PATH_MISMATCH",
        "ROUTE_NATIVE_FIBER_ENDPOINT_MISMATCH",
        "ROUTE_NATIVE_FIBER_MISMATCH",
    }
)
_BUNDLE_PROPAGATION_CODES = frozenset(
    {
        "PROPAGATION_PATH_INCOMPLETE",
        "UNREVIEWED_OPTICAL_PATH",
    }
)


def _bundle_preflight_actions(
    project: RouteProject,
    readiness: DeploymentReadiness,
) -> tuple[tuple[str, str, int], ...]:
    """Return concise, deduplicated operator actions for a blocked bundle."""

    statuses = tuple(readiness.shelf_statuses)

    def shelf_count(codes: frozenset[str]) -> int:
        return sum(
            bool(set(status.reason_codes) & codes)
            for status in statuses
        )

    pending_shelves = shelf_count(frozenset({"PENDING_SHELF_REVIEW"}))
    raman_shelves = shelf_count(_BUNDLE_RAMAN_REVIEW_CODES)
    sra_provider_shelves = shelf_count(_BUNDLE_SRA_PROVIDER_CODES)
    paired_sra_shelves = shelf_count(_BUNDLE_PAIRED_SRA_REVIEW_CODES)
    exact_review_shelves = shelf_count(_BUNDLE_EXACT_REVIEW_CODES)
    unreviewed_paths = 0
    for link in project.links:
        propagation_views = route_link_propagation_views(link)
        if not propagation_views:
            unreviewed_paths += 1
            continue
        missing = sum(
            view.egress_review is None for view in propagation_views
        )
        unreviewed_paths += missing
        if (
            not missing
            and any(
                path.review_state not in {"confirmed", "corrected"}
                for path in link.paths
            )
        ):
            unreviewed_paths += 1
    native_fiber_blocked = any(
        set(status.reason_codes) & _BUNDLE_NATIVE_FIBER_CODES
        for status in statuses
    )
    known_codes = {
        "PENDING_SHELF_REVIEW",
        *_BUNDLE_PROPAGATION_CODES,
        *_BUNDLE_RAMAN_REVIEW_CODES,
        *_BUNDLE_SRA_PROVIDER_CODES,
        *_BUNDLE_PAIRED_SRA_REVIEW_CODES,
        *_BUNDLE_EXACT_REVIEW_CODES,
        *_BUNDLE_NATIVE_FIBER_CODES,
    }
    other_shelves = sum(
        not status.ready
        and bool(set(status.reason_codes) - known_codes)
        for status in statuses
    )
    candidates = (
        (
            "REVIEW_SHELF_FACTS",
            "Review imported shelf facts",
            pending_shelves,
        ),
        (
            "REVIEW_RAMAN_EVIDENCE",
            "Resolve RAMAN/SRA evidence",
            raman_shelves,
        ),
        (
            "SRA_PROVIDER_COVERAGE",
            "Add a vendor-audited SRA-capable R4.0 provider",
            sra_provider_shelves,
        ),
        (
            "REVIEW_PAIRED_SRA_PEER",
            "Review the facing paired SRA endpoint",
            paired_sra_shelves,
        ),
        (
            "REVIEW_EXACT_CONFIGS",
            "Complete or correct exact R4.0 configuration reviews",
            exact_review_shelves,
        ),
        (
            "REVIEW_OPTICAL_PATHS",
            (
                "Complete A→Z and Z→A egress reviews through the adjacent "
                "shelf configuration reviews"
            ),
            unreviewed_paths,
        ),
        (
            "CONFIRM_NATIVE_FIBER",
            "Confirm one route-native CLI fiber token",
            1 if native_fiber_blocked else 0,
        ),
        (
            "RESOLVE_OTHER_BLOCKERS",
            "Resolve other route validation blockers",
            other_shelves,
        ),
    )
    return tuple(item for item in candidates if item[2])


def _bundle_preflight_message(
    actions: Iterable[tuple[str, str, int]],
) -> str:
    action_list = tuple(actions)
    lines = [
        "The final route bundle is not ready. Resolve these items first:",
        "",
    ]
    if action_list:
        lines.extend(
            f"• {label}: {count}" for _code, label, count in action_list
        )
    else:
        lines.append("• Resolve the remaining deployment-readiness blockers.")
    lines.extend(
        [
            "",
            "No destination folder was selected, no background export was "
            "started, and no bundle artifacts were created.",
        ]
    )
    return "\n".join(lines)


def _r4_0_review_facts(
    project: RouteProject,
    shelf_id: str,
) -> dict[str, object]:
    """Map route identity and adjacent span evidence into the R4.0 catalog."""

    shelf_index = next(
        (
            index
            for index, shelf in enumerate(project.shelves)
            if shelf.shelf_id == shelf_id
        ),
        None,
    )
    if shelf_index is None:
        raise ValueError("The selected shelf is no longer in the route.")
    shelf = project.shelves[shelf_index]
    site = project.site_by_key(shelf.site_key)
    descriptor = PROFILE_REGISTRY.get(shelf.profile_id)
    evidence_chassis = shelf.source_evidence.get("chassis", "")
    facts: dict[str, object] = {
        "route_id": project.route_code,
        "tid": shelf.tid,
        "site_name": site.name if site is not None else "",
        "primary_oam_ip": shelf.primary_oam_ip,
        "ospf_area": project.ospf_area,
        "chassis": (
            evidence_chassis
            if isinstance(evidence_chassis, str) and evidence_chassis.strip()
            else shelf.shelf_variant
        ),
        "site_code": site.code if site is not None else "",
        "shelf_variant": shelf.shelf_variant,
        "lifecycle": "active",
        "power_label": shelf.power_label,
        "raman_label": shelf.raman_label,
        "notes": shelf.notes,
    }
    for side, neighbor_index in (
        ("a", shelf_index - 1),
        ("z", shelf_index + 1),
    ):
        neighbor = (
            project.shelves[neighbor_index]
            if 0 <= neighbor_index < len(project.shelves)
            else None
        )
        neighbor_id = neighbor.shelf_id if neighbor is not None else ""
        matching_links = (
            tuple(
                link
                for link in project.links
                if {
                    link.from_shelf_id,
                    link.to_shelf_id,
                }
                == {shelf_id, neighbor_id}
            )
            if neighbor_id
            else ()
        )
        # Ordered shelf topology is the authority for A/Z adjacency. A path is
        # used only when exactly one first-class link represents that adjacent
        # pair; a missing or ambiguous link must not borrow another degree's
        # optical facts.
        link = matching_links[0] if len(matching_links) == 1 else None
        propagation_views = (
            route_link_propagation_views(link)
            if link is not None
            else ()
        )
        outbound_direction = "Z_TO_A" if side == "a" else "A_TO_Z"
        outbound_view = next(
            (
                view
                for view in propagation_views
                if view.direction == outbound_direction
                and view.egress_shelf_id == shelf_id
            ),
            None,
        )
        inbound_direction = (
            "A_TO_Z" if outbound_direction == "Z_TO_A" else "Z_TO_A"
        )
        inbound_view = next(
            (
                view
                for view in propagation_views
                if view.direction == inbound_direction
                and view.ingress_shelf_id == shelf_id
            ),
            None,
        )
        path = (
            outbound_view.shared_span
            if outbound_view is not None
            else None
        )
        endpoint_review = (
            outbound_view.egress_review
            if outbound_view is not None
            else None
        )
        inbound_peer_review = (
            inbound_view.egress_review
            if inbound_view is not None
            else None
        )
        neighbor_profile = (
            PROFILE_REGISTRY.get(neighbor.profile_id)
            if neighbor is not None
            else None
        )
        source_fiber_labels: dict[str, str] = {}
        if path is not None:
            raw_fields = path.source_evidence.get("fields", ())
            if isinstance(raw_fields, (list, tuple)):
                for raw_evidence in raw_fields:
                    if (
                        not isinstance(raw_evidence, Mapping)
                        or raw_evidence.get("field") != "fiber_type"
                        or raw_evidence.get("method")
                        not in {"vision", "ocr", "native_text"}
                    ):
                        continue
                    raw_confidence = raw_evidence.get("confidence")
                    if (
                        isinstance(raw_confidence, bool)
                        or not isinstance(raw_confidence, (int, float))
                        or raw_confidence < MIN_FIELD_CONFIDENCE
                    ):
                        continue
                    label = str(
                        raw_evidence.get("normalized_value", "") or ""
                    ).strip()
                    if label:
                        source_fiber_labels.setdefault(label.casefold(), label)
        source_fiber_label = (
            next(iter(source_fiber_labels.values()))
            if len(source_fiber_labels) == 1
            else ""
        )
        facts.update(
            {
                f"{side}_neighbor_tid": neighbor.tid if neighbor else "",
                f"{side}_neighbor_role": (
                    neighbor_profile.family if neighbor_profile else ""
                ),
                f"{side}_span_fiber_type": (
                    endpoint_review.fiber_type
                    if endpoint_review is not None
                    else path.fiber_type
                    if path is not None
                    else ""
                ),
                f"{side}_span_distance_km": (
                    path.distance_km if path is not None else None
                ),
                f"{side}_span_loss_db": (
                    endpoint_review.expected_loss_db
                    if endpoint_review is not None
                    else path.expected_loss_db
                    if path is not None
                    else None
                ),
                f"{side}_span_circuit_id": (
                    path.circuit_id if path is not None else ""
                ),
                f"{side}_span_link_name": (
                    endpoint_review.link_name
                    if endpoint_review is not None
                    else path.link_name
                    if path is not None
                    else ""
                ),
                f"{side}_span_fiber_start": (
                    path.fiber_start if path is not None else None
                ),
                f"{side}_span_fiber_end": (
                    path.fiber_end if path is not None else None
                ),
                f"{side}_span_source_fiber_label": source_fiber_label,
                f"{side}_span_present": path is not None,
                f"{side}_outbound_flow": (
                    "Z→A" if side == "a" else "A→Z"
                ),
                f"{side}_inbound_flow": (
                    "A→Z" if side == "a" else "Z→A"
                ),
                f"{side}_propagation_reviewed": (
                    endpoint_review is not None
                ),
                f"{side}_inbound_peer_reviewed": (
                    inbound_peer_review is not None
                ),
                f"{side}_inbound_peer_link_name": (
                    inbound_peer_review.link_name
                    if inbound_peer_review is not None
                    else ""
                ),
                f"{side}_inbound_peer_loss_db": (
                    inbound_peer_review.expected_loss_db
                    if inbound_peer_review is not None
                    else None
                ),
                f"{side}_inbound_peer_fiber_type": (
                    inbound_peer_review.fiber_type
                    if inbound_peer_review is not None
                    else ""
                ),
            }
        )
    # The descriptor lookup above is also a deliberate profile-registration
    # assertion for headless review callers.
    if descriptor is None:
        raise ValueError("The selected shelf profile is not registered.")
    return facts


def _r4_0_assumption_facts(
    project: RouteProject,
    shelf_id: str,
) -> dict[str, object]:
    """Return only fields accepted by the deterministic assumptions catalog."""

    from utils.rls_config.r4_0_review import R40_DIAGRAM_FACT_FIELDS

    return {
        field_name: value
        for field_name, value in _r4_0_review_facts(
            project,
            shelf_id,
        ).items()
        if field_name in R40_DIAGRAM_FACT_FIELDS
    }


def _route_header_optical_band(project: RouteProject) -> str:
    """Return the passive route-header band observation, when retained."""

    route_header = project.diagram_source.get("route_header", {})
    if not isinstance(route_header, Mapping):
        return ""
    if route_header.get("optical_band_status") != "direct_supported":
        return ""
    value = route_header.get("optical_band")
    return str(value or "").strip() if isinstance(value, str) else ""


def _represented_route_degree_count(
    project: RouteProject,
    shelf: ShelfInstance,
) -> int:
    """Count modeled adjacent physical spans, not traffic directions."""

    shelf_index = next(
        (
            index
            for index, candidate in enumerate(project.shelves)
            if candidate.shelf_id == shelf.shelf_id
        ),
        None,
    )
    if shelf_index is None:
        return 0
    count = 0
    for neighbor_index in (shelf_index - 1, shelf_index + 1):
        if not 0 <= neighbor_index < len(project.shelves):
            continue
        neighbor_id = project.shelves[neighbor_index].shelf_id
        matching = tuple(
            link
            for link in project.links
            if {link.from_shelf_id, link.to_shelf_id}
            == {shelf.shelf_id, neighbor_id}
            and bool(link.paths)
        )
        if len(matching) == 1:
            count += 1
    return count


def _direct_diagram_fact(
    source_evidence: Mapping[str, object],
    field_name: str,
    value: object,
    *,
    allow_inferred: bool = False,
) -> bool:
    """Return whether one retained shelf fact has matching strong evidence."""

    raw_fields = source_evidence.get("fields", ())
    if not isinstance(raw_fields, (list, tuple)):
        return False
    allowed_methods = {"vision", "ocr", "native_text"}
    if allow_inferred:
        allowed_methods.add("inferred")
    normalized = str(value or "").strip().casefold()
    if not normalized:
        return False
    for raw in raw_fields:
        if not isinstance(raw, Mapping):
            continue
        observed_field = str(raw.get("field", "") or "").strip()
        if (
            observed_field != field_name
            and not observed_field.endswith(f".{field_name}")
        ):
            continue
        if raw.get("method") not in allowed_methods:
            continue
        confidence = raw.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or float(confidence) < MIN_FIELD_CONFIDENCE
        ):
            continue
        observed = str(
            raw.get("normalized_value", raw.get("raw_text", "")) or ""
        ).strip().casefold()
        if observed == normalized:
            return True
    return False


def _topology_checked_line_endpoints(
    project: RouteProject,
    shelf: ShelfInstance,
) -> tuple[object, tuple[dict[str, object], ...]]:
    """Correct a lone terminal endpoint's impossible route-side assertion.

    Endpoint slot/port values remain direct diagram observations, but their
    ``preceding``/``following`` labels are provider-inferred topology. When
    exactly one imported endpoint exists and exactly one adjacent modeled span
    proves that a terminal can face only the opposite route side, normalize
    that inferred label before resolving the provider's fixed direction.
    """

    raw_endpoints = shelf.source_evidence.get("line_endpoints", ())
    if not isinstance(raw_endpoints, (list, tuple)) or len(raw_endpoints) != 1:
        return raw_endpoints, ()
    shelf_index = next(
        (
            index
            for index, candidate in enumerate(project.shelves)
            if candidate.shelf_id == shelf.shelf_id
        ),
        None,
    )
    if shelf_index is None or len(project.shelves) < 2:
        return raw_endpoints, ()

    possible: list[str] = []
    for adjacency, neighbor_index in (
        ("preceding", shelf_index - 1),
        ("following", shelf_index + 1),
    ):
        if not 0 <= neighbor_index < len(project.shelves):
            continue
        neighbor_id = project.shelves[neighbor_index].shelf_id
        matching = tuple(
            link
            for link in project.links
            if {
                link.from_shelf_id,
                link.to_shelf_id,
            }
            == {shelf.shelf_id, neighbor_id}
            and bool(link.paths)
        )
        if len(matching) == 1:
            possible.append(adjacency)
    if len(possible) != 1:
        return raw_endpoints, ()

    raw_endpoint = raw_endpoints[0]
    if not isinstance(raw_endpoint, Mapping):
        return raw_endpoints, ()
    observed = str(raw_endpoint.get("adjacency", "") or "").strip()
    normalized = possible[0]
    if observed not in {"preceding", "following"} or observed == normalized:
        return raw_endpoints, ()

    raw_evidence = raw_endpoint.get("evidence", ())
    if not isinstance(raw_evidence, (list, tuple)):
        return raw_endpoints, ()
    corrected_evidence: list[object] = []
    adjacency_supported = False
    for item in raw_evidence:
        if not isinstance(item, Mapping) or not str(
            item.get("field", "") or ""
        ).endswith(".adjacency"):
            corrected_evidence.append(item)
            continue
        confidence = item.get("confidence")
        if (
            item.get("method") != "inferred"
            or isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or float(confidence) < MIN_FIELD_CONFIDENCE
            or str(item.get("normalized_value", "") or "").strip()
            != observed
        ):
            corrected_evidence.append(item)
            continue
        corrected_evidence.append(
            {
                **dict(item),
                "normalized_value": normalized,
                "method": "inferred",
            }
        )
        adjacency_supported = True
    if not adjacency_supported:
        return raw_endpoints, ()

    corrected_endpoint = {
        **dict(raw_endpoint),
        "adjacency": normalized,
    }
    corrected_endpoint["evidence"] = corrected_evidence
    adjustment = {
        "rule_id": "terminal-endpoint-adjacency-from-ordered-span-v1",
        "original_adjacency": observed,
        "normalized_adjacency": normalized,
        "status": "derived_pending_review",
        "deployable_cli": False,
    }
    return (corrected_endpoint,), (adjustment,)


def _r4_0_provider_prepopulation(
    project: RouteProject,
    shelf: ShelfInstance,
) -> tuple[dict[str, object], dict[str, object]]:
    """Resolve one advisory provider and its fixed route-direction mapping."""

    from utils.rls_config.r4_0_generator import (
        R40DirectModuleFact,
        R40ProviderCandidateFacts,
        R40_PROVIDER_CATALOG,
        resolve_r40_provider_candidate,
    )
    from utils.rls_config.r4_0_prepopulation import (
        resolve_r40_fixed_direction,
        resolve_r40_fixed_direction_fallback,
    )

    evidence = shelf.source_evidence
    raman_callout_review_status = _raman_callout_review_status(evidence)
    sra_state = _r4_0_candidate_sra_state(project, shelf)
    structured_sra_state, structured_sra_slots = _structured_sra_state(shelf)

    def provider_matches_sra_scope(profile: object) -> bool:
        if sra_state == "present":
            return bool(getattr(profile, "supports_raman", False)) and (
                structured_sra_state == "accepted"
                and set(structured_sra_slots)
                == set(_r40_provider_sra_slots(profile))
            )
        if sra_state == "absent":
            return not bool(getattr(profile, "supports_raman", False))
        return True

    invalidation = evidence.get(_PROVIDER_PRESELECTION_INVALIDATION_KEY)
    if not isinstance(invalidation, Mapping):
        # Projects saved by an earlier Route Builder may contain a corrected
        # visible shelf variant without the newer explicit invalidation
        # marker.  Do not let directly transcribed stale hardware silently
        # reselect a provider in that migration case.
        reviewed_variant = shelf.shelf_variant.strip().casefold()
        direct_shelf_variants = tuple(
            value.strip().casefold()
            for value in (
                str(evidence.get("shelf_variant", "") or ""),
            )
            if value.strip()
            and _direct_diagram_fact(evidence, "shelf_variant", value)
        )
        direct_chassis_variants = tuple(
            value.strip().casefold()
            for value in (
                str(evidence.get("chassis", "") or ""),
            )
            if value.strip()
            and _direct_diagram_fact(evidence, "chassis", value)
        )
        # A specific directly evidenced shelf variant/PEC is stronger than a
        # generic chassis-family label.  Falling back to the latter while a
        # stale PEC remains present could silently preserve the wrong exact
        # provider in an older saved project.
        expected_source_variants = (
            direct_shelf_variants or direct_chassis_variants
        )
        if (
            shelf.review_state == "corrected"
            and reviewed_variant
            and expected_source_variants
            and reviewed_variant not in expected_source_variants
        ):
            invalidation = {
                "reason": (
                    "corrected visible shelf variant differs from retained "
                    "direct diagram hardware"
                ),
                "fields": ("shelf_variant",),
                "deployable_cli": False,
            }
    if isinstance(invalidation, Mapping):
        role_provider_ids = tuple(
            provider_id
            for provider_id, profile in R40_PROVIDER_CATALOG.items()
            if (
                shelf.profile_id in profile.role_profiles
                and provider_matches_sra_scope(profile)
            )
        )
        review_provider_ids = tuple(
            provider_id
            for provider_id in role_provider_ids
            if not _r40_provider_route_band_mismatches(
                R40_PROVIDER_CATALOG[provider_id],
                shelf,
                project,
            )
        )
        route_band = _route_header_optical_band(project)
        raw_shelf_band = str(evidence.get("band", "") or "").strip()
        direct_shelf_band = (
            raw_shelf_band
            if raw_shelf_band
            and _direct_diagram_fact(evidence, "band", raw_shelf_band)
            else ""
        )
        band_scope = direct_shelf_band or route_band
        band_scope_rejected = bool(role_provider_ids) and not review_provider_ids
        return (
            {
                "status": "conflict",
                "provider_id": "",
                "compatible_provider_ids": list(review_provider_ids),
                "review_provider_ids": list(review_provider_ids),
                "reason_codes": [
                    "OPERATOR_PROVIDER_FACT_CORRECTION_REQUIRES_REVIEW",
                    *(
                        (
                            "ROUTE_SCOPE_OPTICAL_BAND_MISMATCH",
                            "NO_AUDITED_ROUTE_SCOPE_PROVIDER",
                        )
                        if band_scope_rejected
                        else ()
                    ),
                ],
                "reasons": [
                    "An operator corrected provider-relevant diagram facts; "
                    "choose and confirm the compatible audited provider "
                    "manually.",
                    *(
                        (
                            "No role-compatible audited provider matches the "
                            "current direct optical-band scope.",
                        )
                        if band_scope_rejected
                        else ()
                    ),
                ],
                "matched_fields": [],
                "missing_fields": [],
                "preselect_allowed": False,
                "band_scope": band_scope,
                "band_scope_source": (
                    "direct_shelf"
                    if direct_shelf_band
                    else "direct_route_header"
                    if route_band
                    else "none"
                ),
                "direct_shelf_band": direct_shelf_band,
                "route_header_band": route_band,
                "represented_route_degree_count": (
                    _represented_route_degree_count(project, shelf)
                ),
                "candidate_provider_degree_count": 0,
                "complete_direct_line_map": False,
                "complete_direct_module_inventory": False,
                "raman_callout_review_status": (
                    raman_callout_review_status
                ),
                "deployable_cli": False,
            },
            {
                "status": "missing_evidence",
                "line_1_route_side": "",
                "reason_codes": ["PROVIDER_NOT_PRESELECTED"],
                "explanation": (
                    "Provider/direction preselection was invalidated by an "
                    "operator hardware correction."
                ),
                "deployable_cli": False,
            },
        )
    chassis = str(evidence.get("chassis", "") or "").strip()
    if chassis and not (
        _direct_diagram_fact(evidence, "chassis", chassis)
        or _direct_diagram_fact(evidence, "shelf_variant", chassis)
    ):
        chassis = ""
    chassis_pec = ""
    for candidate in (
        str(evidence.get("shelf_variant", "") or "").strip(),
        chassis,
    ):
        if (
            re.fullmatch(r"NTK[A-Z0-9]{3,29}", candidate, re.IGNORECASE)
            and (
                _direct_diagram_fact(evidence, "shelf_variant", candidate)
                or _direct_diagram_fact(evidence, "chassis", candidate)
            )
        ):
            chassis_pec = candidate
            break

    def direct_structured(name: str) -> str:
        value = str(evidence.get(name, "") or "").strip()
        return (
            value
            if value and _direct_diagram_fact(evidence, name, value)
            else ""
        )

    direct_modules: list[R40DirectModuleFact] = []
    raw_modules = evidence.get("module_inventory", ())
    if isinstance(raw_modules, (list, tuple)):
        for index, raw_module in enumerate(raw_modules):
            if not isinstance(raw_module, Mapping):
                continue
            pec = str(raw_module.get("pec", "") or "").strip()
            slot = raw_module.get("slot")
            subslot = raw_module.get("subslot")
            if (
                not pec
                or not isinstance(slot, int)
                or isinstance(slot, bool)
                or not _direct_diagram_fact(
                    evidence,
                    f"module_inventory.{index}.pec",
                    pec,
                )
                or not _direct_diagram_fact(
                    evidence,
                    f"module_inventory.{index}.slot",
                    slot,
                )
            ):
                continue
            if subslot is not None and not (
                isinstance(subslot, int)
                and not isinstance(subslot, bool)
                and _direct_diagram_fact(
                    evidence,
                    f"module_inventory.{index}.subslot",
                    subslot,
                )
            ):
                continue
            direct_modules.append(
                R40DirectModuleFact(
                    slot=slot,
                    pec=pec,
                    subslot=subslot,
                )
            )

    facts = R40ProviderCandidateFacts(
        role_profile=shelf.profile_id,
        software_release=R40_UI_RELEASE,
        chassis_family=chassis,
        chassis_pec=chassis_pec,
        # A direct per-shelf band is the strongest provider discriminator. The
        # direct-supported route header is a project-scope compatibility guard;
        # it may narrow the review catalog, but it cannot authorize advisory
        # preselection without a complete direct module inventory or complete
        # local line map plus chassis evidence.
        optical_band=direct_structured("band"),
        topology=direct_structured("topology"),
        add_drop_structure=direct_structured("add_drop_structure"),
        protection_type=direct_structured("protection_type"),
        module_inventory=tuple(direct_modules),
        sra_state=sra_state,
    )
    resolution = resolve_r40_provider_candidate(facts)
    checked_endpoints, topology_adjustments = (
        _topology_checked_line_endpoints(project, shelf)
    )
    route_band = _route_header_optical_band(project)
    shelf_band = facts.optical_band
    band_scope = shelf_band or route_band
    band_scope_source = (
        "direct_shelf"
        if shelf_band
        else "direct_route_header"
        if route_band
        else "none"
    )
    compatible_provider_ids = tuple(resolution.compatible_provider_ids)
    sra_provider_ids = tuple(
        provider_id
        for provider_id in compatible_provider_ids
        if (
            provider_id in R40_PROVIDER_CATALOG
            and provider_matches_sra_scope(
                R40_PROVIDER_CATALOG[provider_id]
            )
        )
    )
    endpoint_provider_ids = tuple(
        provider_id
        for provider_id in sra_provider_ids
        if (
            provider_id in R40_PROVIDER_CATALOG
            and (
                not checked_endpoints
                or "DIRECT_LINE_OUTPUT_PROVIDER_MISMATCH"
                not in resolve_r40_fixed_direction(
                    R40_PROVIDER_CATALOG[provider_id],
                    checked_endpoints,
                ).reason_codes
            )
        )
    )
    review_provider_ids = tuple(
        provider_id
        for provider_id in endpoint_provider_ids
        if (
            provider_id in R40_PROVIDER_CATALOG
            and not _r40_provider_route_band_mismatches(
                R40_PROVIDER_CATALOG[provider_id],
                shelf,
                project,
            )
        )
    )
    sra_scope_rejected = bool(compatible_provider_ids) and not sra_provider_ids
    endpoint_scope_rejected = bool(sra_provider_ids) and not endpoint_provider_ids
    band_scope_rejected = bool(endpoint_provider_ids) and not review_provider_ids
    endpoint_scope_unique = bool(
        checked_endpoints
        and len(review_provider_ids) == 1
        and len(compatible_provider_ids) > 1
    )
    route_scope_unique = bool(
        len(review_provider_ids) == 1
        and resolution.provider_id not in review_provider_ids
        and (band_scope or checked_endpoints)
    )
    provider_id = (
        resolution.provider_id
        if resolution.provider_id in review_provider_ids
        else review_provider_ids[0]
        if route_scope_unique
        else None
    )
    provider_profile = (
        R40_PROVIDER_CATALOG.get(provider_id) if provider_id else None
    )
    direction = (
        resolve_r40_fixed_direction(provider_profile, checked_endpoints)
        if provider_profile is not None
        else None
    )
    direct_line_outputs = {
        (
            endpoint.get("slot"),
            endpoint.get("line_out_port"),
        )
        for endpoint in (
            direction.matched_endpoints if direction is not None else ()
        )
        if isinstance(endpoint.get("slot"), int)
        and not isinstance(endpoint.get("slot"), bool)
        and isinstance(endpoint.get("line_out_port"), int)
        and not isinstance(endpoint.get("line_out_port"), bool)
    }
    complete_line_map = bool(
        provider_profile is not None
        and direct_line_outputs == set(provider_profile.line_outputs)
    )
    direct_module_set = {
        (module.slot, module.subslot, module.pec.strip().upper())
        for module in direct_modules
    }
    expected_module_set = (
        {
            *(
                (slot, None, pec.upper())
                for slot, pec in provider_profile.equipment
            ),
            *(
                (slot, subslot, pec.upper())
                for slot, subslot, pec in provider_profile.osc_modules
            ),
        }
        if provider_profile is not None
        else set()
    )
    complete_module_inventory = bool(
        expected_module_set and direct_module_set == expected_module_set
    )
    represented_degree_count = _represented_route_degree_count(project, shelf)
    provider_degree_count = (
        len(provider_profile.line_outputs)
        if provider_profile is not None
        else 0
    )
    unrepresented_terminal_degree = bool(
        provider_profile is not None
        and provider_profile.line_semantics == "bidirectional_degree"
        and represented_degree_count < provider_degree_count
    )
    matched_fields = set(resolution.matched_fields)
    sufficient_provider_identity = bool(
        complete_module_inventory
        or (
            complete_line_map
            and bool(
                {"chassis_family", "chassis_pec"}.intersection(
                    matched_fields
                )
            )
            and not unrepresented_terminal_degree
        )
    )
    provider_status = (
        "conflict"
        if (
            band_scope_rejected
            or sra_scope_rejected
            or endpoint_scope_rejected
        )
        else "unique_candidate"
        if route_scope_unique
        else resolution.status
    )
    preselect_allowed = (
        provider_status in {"exact_match", "unique_candidate"}
        and provider_profile is not None
        and sufficient_provider_identity
        and raman_callout_review_status not in {"pending", "invalid"}
    )
    provider_reason_codes = [
        code
        for code in resolution.reason_codes
        if not (
            route_scope_unique
            and code == "MULTIPLE_COMPATIBLE_PROVIDERS"
        )
    ]
    provider_reasons = (
        [
            (
                "Exactly one role-compatible provider remains after applying "
                "the reviewed fixed line-output map and direct optical-band "
                "scope."
                if endpoint_scope_unique and band_scope
                else "Exactly one role-compatible provider remains after "
                "applying the reviewed fixed line-output map."
                if endpoint_scope_unique
                else "Exactly one role-compatible provider remains after "
                f"applying the direct {band_scope} optical-band scope."
            )
            + " These review constraints do not replace installed hardware "
            "confirmation."
        ]
        if route_scope_unique
        else list(resolution.reasons)
    )
    if route_scope_unique:
        provider_reason_codes.append(
            (
                "UNIQUE_ENDPOINT_SCOPE_COMPATIBLE_PROVIDER"
                if endpoint_scope_unique
                else "UNIQUE_ROUTE_SCOPE_COMPATIBLE_PROVIDER"
            )
        )
    if band_scope_rejected:
        provider_reason_codes.extend(
            [
                "ROUTE_SCOPE_OPTICAL_BAND_MISMATCH",
                "NO_AUDITED_ROUTE_SCOPE_PROVIDER",
            ]
        )
        provider_reasons.append(
            "No role-compatible audited provider matches the directly "
            f"observed {band_scope or 'unknown'} optical-band scope. A direct "
            "per-shelf band may establish an intentional band-partition "
            "exception; route role and catalog uniqueness cannot."
        )
    if sra_scope_rejected:
        provider_reason_codes.extend(
            [
                "R40_SRA_SLOT_PROVIDER_MISMATCH",
                "NO_AUDITED_SRA_SLOT_PROVIDER",
            ]
        )
        provider_reasons.append(
            "No role-compatible audited provider matches the reviewed SRA "
            "slot and its fixed port-5/port-6 endpoint map."
        )
    if endpoint_scope_rejected:
        provider_reason_codes.extend(
            [
                "DIRECT_LINE_OUTPUT_PROVIDER_MISMATCH",
                "NO_AUDITED_LINE_ENDPOINT_PROVIDER",
            ]
        )
        provider_reasons.append(
            "No role-compatible audited provider matches the reviewed fixed "
            "line-output endpoint map."
        )
    elif provider_profile is not None and not sufficient_provider_identity:
        provider_reason_codes.append(
            "INSUFFICIENT_PROVIDER_IDENTITY_EVIDENCE"
        )
        provider_reasons.append(
            "The compatible catalog candidate is not identified by a complete "
            "direct module inventory or a complete directly observed fixed "
            "line-output map plus chassis evidence."
        )
        if unrepresented_terminal_degree:
            provider_reason_codes.append(
                "PROVIDER_DEGREE_COUNT_NOT_ESTABLISHED"
            )
            provider_reasons.append(
                "The provider contains more physical RLA degrees than the "
                "uploaded route represents. Installed inventory must establish "
                "the additional degree and its independently engineered peer."
            )
    provider_record: dict[str, object] = {
        "status": provider_status,
        "provider_id": provider_id or "",
        "compatible_provider_ids": list(review_provider_ids),
        "review_provider_ids": list(review_provider_ids),
        "reason_codes": provider_reason_codes,
        "reasons": provider_reasons,
        "matched_fields": list(resolution.matched_fields),
        "missing_fields": list(resolution.missing_fields),
        "preselect_allowed": preselect_allowed,
        "band_scope": band_scope,
        "band_scope_source": band_scope_source,
        "direct_shelf_band": shelf_band,
        "route_header_band": route_band,
        "represented_route_degree_count": represented_degree_count,
        "candidate_provider_degree_count": provider_degree_count,
        "complete_direct_line_map": complete_line_map,
        "complete_direct_module_inventory": complete_module_inventory,
        "raman_callout_review_status": raman_callout_review_status,
        "deployable_cli": False,
    }
    direction_record: dict[str, object] = {
        "status": "missing_evidence",
        "line_1_route_side": "",
        "reason_codes": ["PROVIDER_NOT_PRESELECTED"],
        "explanation": (
            "A compatible exact provider must be established before local "
            "ports can be mapped to its fixed directions."
        ),
        "deployable_cli": False,
    }
    if endpoint_scope_rejected:
        direction_record = {
            "status": "conflict",
            "line_1_route_side": "",
            "reason_codes": [
                "DIRECT_LINE_OUTPUT_PROVIDER_MISMATCH",
            ],
            "explanation": (
                "Direct local line-output evidence conflicts with every "
                "route-compatible exact provider's immutable port map."
            ),
            "matched_endpoints": [],
            "deployable_cli": False,
        }
    if provider_id and direction is not None:
        raw_line_endpoints = evidence.get("line_endpoints", ())
        endpoint_evidence_absent = (
            isinstance(raw_line_endpoints, (list, tuple))
            and not raw_line_endpoints
            and not evidence.get(_INVALIDATED_LINE_ENDPOINTS_KEY)
        )
        if (
            _r40_sole_candidate_provider_id(provider_record) == provider_id
            and direction.status == "missing_evidence"
            and endpoint_evidence_absent
        ):
            direction = resolve_r40_fixed_direction_fallback(
                R40_PROVIDER_CATALOG[provider_id],
                shelf.profile_id,
            )
        direction_record = direction.to_dict()
        if topology_adjustments:
            direction_record["reason_codes"] = [
                *list(direction_record.get("reason_codes", ())),
                "TERMINAL_ADJACENCY_NORMALIZED_FROM_ORDERED_SPAN",
            ]
            direction_record["explanation"] = (
                str(direction_record.get("explanation", "") or "").rstrip(
                    "."
                )
                + ". The lone terminal endpoint's inferred route side was "
                "normalized against its only modeled adjacent span; confirm "
                "the fixed direction against the installed port map."
            )
            direction_record["topology_adjustments"] = list(
                topology_adjustments
            )
            direction_record["deployable_cli"] = False
        if (
            direction.status == "conflict"
            and "DIRECT_LINE_OUTPUT_PROVIDER_MISMATCH"
            in direction.reason_codes
        ):
            provider_record["status"] = "conflict"
            provider_record["provider_id"] = ""
            provider_record["compatible_provider_ids"] = []
            provider_record["review_provider_ids"] = []
            provider_record["reason_codes"] = [
                *list(provider_record["reason_codes"]),
                "DIRECT_LINE_OUTPUT_PROVIDER_MISMATCH",
            ]
            provider_record["reasons"] = [
                *list(provider_record["reasons"]),
                (
                    "Direct local line-output evidence conflicts with the "
                    "candidate provider's immutable port map."
                ),
            ]
            provider_record["preselect_allowed"] = False
    return provider_record, direction_record


_PEER_PFG_SOURCE_EXACT_PAYLOAD = "current_exact_peer_payload"
_PEER_PFG_SOURCE_DIRECT_DIRECTION = "direct_peer_direction_evidence"
_PEER_PFG_SOURCE_ROLE_FALLBACK = "audited_peer_role_fallback"
_PEER_PFG_SOURCE_ORDERED_TOPOLOGY = "ordered_topology_single_degree"


def _r4_0_peer_pfg_prepopulation(
    project: RouteProject,
    shelf: ShelfInstance,
    route_side: str,
) -> dict[str, str]:
    """Return fail-closed facing-peer PFG defaults for one represented side.

    Neighbor PFG names are immutable properties of an exact provider, but the
    correct record still depends on the peer's physical route-side mapping.
    A current exact payload is authoritative for that reviewed mapping.
    Otherwise ATLAS requires exactly one route-compatible provider and either
    direct endpoint resolution, the existing audited provider/role fallback,
    or a single-degree endpoint whose sole ordered adjacency proves its only
    possible side. Conflicting, ambiguous, SRA-equipped, and multi-adjacency
    peers intentionally return no suggestion. Reviewed SRA peers are eligible
    only when the surviving exact provider has the same audited SRA slot.
    """

    blank = {
        "neighbor_line_mux_pfg": "",
        "neighbor_line_demux_pfg": "",
        "neighbor_pfg_source": "",
    }
    if route_side not in {"A", "Z"}:
        return blank
    shelf_index = next(
        (
            index
            for index, candidate in enumerate(project.shelves)
            if candidate.shelf_id == shelf.shelf_id
        ),
        None,
    )
    if shelf_index is None:
        return blank
    peer_index = shelf_index - 1 if route_side == "A" else shelf_index + 1
    if not 0 <= peer_index < len(project.shelves):
        return blank
    peer = project.shelves[peer_index]
    matching_links = tuple(
        link
        for link in project.links
        if {link.from_shelf_id, link.to_shelf_id}
        == {shelf.shelf_id, peer.shelf_id}
    )
    if len(matching_links) != 1 or len(matching_links[0].paths) != 1:
        return blank
    peer_raman_status = _raman_callout_review_status(peer.source_evidence)
    if peer_raman_status in {"pending", "invalid"}:
        # Pending or malformed structured callouts are unresolved hardware
        # identity, so they must fail closed.
        return blank

    from utils.rls_config.r4_0_generator import (
        R40_PAYLOAD_SCHEMA_ID,
        R40_PROVIDER_CATALOG,
        decode_r40_exact_payload,
    )
    from utils.rls_config.r4_0_prepopulation import (
        resolve_r40_fixed_direction_fallback,
    )

    peer_facing_side = "Z" if route_side == "A" else "A"
    ordered_neighbor_indices = tuple(
        index
        for index in (peer_index - 1, peer_index + 1)
        if 0 <= index < len(project.shelves)
    )
    sole_neighbor_id = (
        project.shelves[ordered_neighbor_indices[0]].shelf_id
        if len(ordered_neighbor_indices) == 1
        else ""
    )
    sole_links = (
        tuple(
            link
            for link in project.links
            if {
                link.from_shelf_id,
                link.to_shelf_id,
            }
            == {peer.shelf_id, sole_neighbor_id}
        )
        if sole_neighbor_id
        else ()
    )
    sole_side = (
        "A"
        if ordered_neighbor_indices == (peer_index - 1,)
        else "Z"
        if ordered_neighbor_indices == (peer_index + 1,)
        else ""
    )
    one_degree_topology_resolved = bool(
        sole_side == peer_facing_side
        and len(sole_links) == 1
        and len(sole_links[0].paths) == 1
    )

    def provider_matches_peer_sra(profile: object) -> bool:
        state, reviewed_slots = _structured_sra_state(peer)
        supports_sra = bool(getattr(profile, "supports_raman", False))
        if supports_sra:
            return (
                state == "accepted"
                and set(reviewed_slots)
                == set(_r40_provider_sra_slots(profile))
            )
        return state != "accepted"

    def pfg_values(
        profile: object,
        line_1_side: str,
        source: str,
        *,
        line_2_present: bool | None = None,
    ) -> dict[str, str]:
        if line_1_side not in {"A", "Z"}:
            return blank
        record_index = 0 if line_1_side == peer_facing_side else 1
        line_outputs = getattr(profile, "line_outputs", ())
        line_pfg_names = getattr(profile, "line_pfg_names", ())
        if (
            not isinstance(line_outputs, (list, tuple))
            or not isinstance(line_pfg_names, (list, tuple))
            or record_index >= len(line_outputs)
            or record_index >= len(line_pfg_names)
            or (record_index == 1 and line_2_present is False)
            or (
                len(line_outputs) == 1
                and not one_degree_topology_resolved
            )
        ):
            # A one-degree provider has no opposite-side record. Its paired
            # mux/demux carries both traffic directions on the assigned side;
            # reverse traffic must never synthesize a second degree.
            return blank
        raw_names = line_pfg_names[record_index]
        if (
            not isinstance(raw_names, (list, tuple))
            or len(raw_names) != 2
        ):
            return blank
        mux_name = str(raw_names[0] or "").strip()
        demux_name = str(raw_names[1] or "").strip()
        if not mux_name or not demux_name:
            return blank
        return {
            "neighbor_line_mux_pfg": mux_name,
            "neighbor_line_demux_pfg": demux_name,
            "neighbor_pfg_source": source,
        }

    raw_payload = peer.profile_payload
    if (
        isinstance(raw_payload, Mapping)
        and raw_payload.get("schema_id") == R40_PAYLOAD_SCHEMA_ID
    ):
        try:
            peer_request = decode_r40_exact_payload(raw_payload)
        except (TypeError, ValueError):
            return blank
        peer_profile = R40_PROVIDER_CATALOG.get(peer_request.provider_id)
        line_count = (
            len(peer_profile.line_outputs)
            if peer_profile is not None
            else 0
        )
        if (
            peer_profile is None
            or peer.profile_id not in peer_profile.role_profiles
            or peer_request.profile not in peer_profile.role_profiles
            or peer_request.software_release != R40_UI_RELEASE
            or peer_request.chassis_family != peer_profile.chassis_family
            or peer_request.chassis_pec != peer_profile.chassis_pec
            or peer_request.hardware_profile != peer_profile.hardware_profile
            or (line_count == 1 and peer_request.line_2 is not None)
            or (line_count == 2 and peer_request.line_2 is None)
            or not provider_matches_peer_sra(peer_profile)
            or _r40_provider_route_band_mismatches(
                peer_profile,
                peer,
                project,
            )
        ):
            return blank
        return pfg_values(
            peer_profile,
            peer_request.line_1_route_side,
            _PEER_PFG_SOURCE_EXACT_PAYLOAD,
            line_2_present=peer_request.line_2 is not None,
        )

    provider_resolution, direction_resolution = (
        _r4_0_provider_prepopulation(project, peer)
    )
    if provider_resolution.get("status") == "conflict":
        return blank
    raw_provider_ids = provider_resolution.get("review_provider_ids", ())
    provider_ids = (
        tuple(
            str(provider_id).strip()
            for provider_id in raw_provider_ids
            if isinstance(provider_id, str) and provider_id.strip()
        )
        if isinstance(raw_provider_ids, (list, tuple))
        else ()
    )
    if len(provider_ids) != 1:
        return blank
    peer_profile = R40_PROVIDER_CATALOG.get(provider_ids[0])
    if (
        peer_profile is None
        or peer.profile_id not in peer_profile.role_profiles
        or not provider_matches_peer_sra(peer_profile)
        or _r40_provider_route_band_mismatches(
            peer_profile,
            peer,
            project,
        )
    ):
        return blank

    direction_status = str(
        direction_resolution.get("status", "") or ""
    ).strip()
    if direction_status in {"conflict", "ambiguous"}:
        return blank
    line_1_side = str(
        direction_resolution.get("line_1_route_side", "") or ""
    ).strip()
    if direction_status == "exact_match" and line_1_side in {"A", "Z"}:
        source = _PEER_PFG_SOURCE_DIRECT_DIRECTION
    elif (
        direction_status == "controlled_fallback"
        and line_1_side in {"A", "Z"}
    ):
        source = _PEER_PFG_SOURCE_ROLE_FALLBACK
    else:
        source = ""

    if not source and len(peer_profile.line_outputs) == 1:
        # A one-degree endpoint can face only its sole ordered neighbor. This
        # fallback is not valid for an interior shelf, a missing/duplicate
        # modeled link, or any ambiguous/conflicting endpoint observation.
        if (
            direction_status == "missing_evidence"
            and one_degree_topology_resolved
        ):
            line_1_side = sole_side
            source = _PEER_PFG_SOURCE_ORDERED_TOPOLOGY

    if not source and direction_status == "missing_evidence":
        raw_endpoints = peer.source_evidence.get("line_endpoints", ())
        invalidated = peer.source_evidence.get(
            _INVALIDATED_LINE_ENDPOINTS_KEY
        )
        if (
            isinstance(raw_endpoints, (list, tuple))
            and not raw_endpoints
            and not invalidated
        ):
            fallback = resolve_r40_fixed_direction_fallback(
                peer_profile,
                peer.profile_id,
            )
            if fallback.resolved:
                line_1_side = fallback.line_1_route_side
                source = _PEER_PFG_SOURCE_ROLE_FALLBACK

    if not source:
        return blank
    return pfg_values(peer_profile, line_1_side, source)


def _r4_0_editor_seed(
    project: RouteProject,
    shelf_id: str,
) -> dict[str, object]:
    """Seed editable facts without selecting a provider or inventing optics."""

    from utils.rls_config.common import FIBER_TYPES

    shelf = next(
        (item for item in project.shelves if item.shelf_id == shelf_id),
        None,
    )
    if shelf is None:
        raise ValueError("The selected shelf is no longer in the route.")
    site = project.site_by_key(shelf.site_key)
    facts = _r4_0_review_facts(project, shelf_id)
    customer_policy = project.customer_policy
    neighbor_suffix = customer_policy.normalized_neighbor_dns_suffix
    shelf_profile = PROFILE_REGISTRY.get(shelf.profile_id)
    terminal_route_role = bool(
        shelf_profile is not None
        and shelf_profile.family in {"add_drop", "roadm"}
        and shelf_profile.side in {"A", "Z"}
    )
    # The audited legacy workflow uses 0.5/0.5 dB for a terminal's single
    # route-facing degree on either end of the route. A/Z route-policy values
    # apply to two-sided ILA/intermediate shelves instead. This is only a
    # review seed: each exact-provider line field remains operator-editable.
    terminal_patch_loss_db = _AUDITED_TERMINAL_ROUTE_PATCH_LOSS_DB

    def node_identity(tid: object) -> str:
        identity = str(tid or "").strip()
        if (
            identity
            and neighbor_suffix
            and re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?",
                identity,
            )
            is not None
            and len(identity + neighbor_suffix) <= 253
        ):
            return identity + neighbor_suffix
        return identity

    def line(side: str) -> dict[str, object]:
        raw_fiber = facts.get(f"{side}_span_fiber_type", "")
        fiber = (
            str(raw_fiber)
            if isinstance(raw_fiber, str) and raw_fiber in FIBER_TYPES
            else ""
        )
        loss = facts.get(f"{side}_span_loss_db")
        neighbor_node = node_identity(
            facts.get(f"{side}_neighbor_tid", "")
        )
        input_patch_loss = (
            terminal_patch_loss_db
            if terminal_route_role
            else (
                customer_policy.a_input_patch_loss_db
                if side == "a"
                else customer_policy.z_input_patch_loss_db
            )
        )
        output_patch_loss = (
            terminal_patch_loss_db
            if terminal_route_role
            else (
                customer_policy.a_output_patch_loss_db
                if side == "a"
                else customer_policy.z_output_patch_loss_db
            )
        )
        return {
            "link_name": str(facts.get(f"{side}_span_link_name", "") or ""),
            "neighbor_node": neighbor_node,
            "fiber_type": fiber,
            "expected_loss_db": (
                float(loss)
                if isinstance(loss, (int, float)) and not isinstance(loss, bool)
                else None
            ),
            "represented_by_route_span": bool(
                facts.get(f"{side}_span_present", False)
            ),
            "outbound_flow": str(
                facts.get(f"{side}_outbound_flow", "") or ""
            ),
            "inbound_flow": str(
                facts.get(f"{side}_inbound_flow", "") or ""
            ),
            "propagation_reviewed": bool(
                facts.get(f"{side}_propagation_reviewed", False)
            ),
            "inbound_peer_reviewed": bool(
                facts.get(f"{side}_inbound_peer_reviewed", False)
            ),
            "inbound_peer_link_name": str(
                facts.get(f"{side}_inbound_peer_link_name", "") or ""
            ),
            "inbound_peer_loss_db": facts.get(
                f"{side}_inbound_peer_loss_db"
            ),
            "inbound_peer_fiber_type": str(
                facts.get(f"{side}_inbound_peer_fiber_type", "") or ""
            ),
            # Read-only route context carried into the exact editor. These
            # values support review but are not inserted into an R40 request.
            "distance_km": facts.get(f"{side}_span_distance_km"),
            "circuit_id": str(
                facts.get(f"{side}_span_circuit_id", "") or ""
            ),
            "fiber_start": facts.get(f"{side}_span_fiber_start"),
            "fiber_end": facts.get(f"{side}_span_fiber_end"),
            "source_fiber_label": str(
                facts.get(f"{side}_span_source_fiber_label", "") or ""
            ),
            "input_patch_loss_db": input_patch_loss,
            "output_patch_loss_db": output_patch_loss,
        }

    raw_site_id = site.network_site_id.strip() if site is not None else ""
    source_evidence = shelf.source_evidence
    reviewed_hardware = {
        "route_role": shelf.profile_id,
        "chassis": str(source_evidence.get("chassis", "") or "").strip(),
        "shelf_variant": shelf.shelf_variant,
        "shelf_band": str(source_evidence.get("band", "") or "").strip(),
        "topology": str(source_evidence.get("topology", "") or "").strip(),
        "add_drop_structure": str(
            source_evidence.get("add_drop_structure", "") or ""
        ).strip(),
        "protection_type": str(
            source_evidence.get("protection_type", "") or ""
        ).strip(),
        "module_inventory": source_evidence.get("module_inventory", ()),
        "line_endpoints": source_evidence.get("line_endpoints", ()),
        "power_label": shelf.power_label,
        "raman_label": shelf.raman_label,
    }
    provider_resolution, direction_resolution = (
        _r4_0_provider_prepopulation(project, shelf)
    )
    direction_side = str(
        direction_resolution.get("line_1_route_side", "") or ""
    ).strip()
    direction_status = str(
        direction_resolution.get("status", "") or ""
    ).strip()
    direction_prepopulated = bool(
        _r40_sole_candidate_provider_id(provider_resolution)
        and direction_side in {"A", "Z"}
        and direction_status in {"exact_match", "controlled_fallback"}
    )
    lines_by_side = {
        "A": line("a"),
        "Z": line("z"),
    }
    for side, side_seed in lines_by_side.items():
        if side_seed["represented_by_route_span"] is True:
            side_seed.update(
                _r4_0_peer_pfg_prepopulation(
                    project,
                    shelf,
                    side,
                )
            )
        else:
            side_seed.update(
                {
                    "neighbor_line_mux_pfg": "",
                    "neighbor_line_demux_pfg": "",
                    "neighbor_pfg_source": "",
                }
            )
    reviewed_fields = [
        field_name
        for field_name, value in (
            ("shelf_name", shelf.tid),
            ("site_name", site.name if site is not None else ""),
            ("site_id", raw_site_id if raw_site_id.isdigit() else ""),
            ("site_description", project.title),
            ("site_address", site.address if site is not None else ""),
            ("loopback_ip", shelf.primary_oam_ip),
            ("ospf_area", project.ospf_area),
            ("diagram_optical_band", _route_header_optical_band(project)),
        )
        if str(value or "").strip()
    ]
    for field_name, value in reviewed_hardware.items():
        if (
            isinstance(value, (list, tuple)) and bool(value)
        ) or (
            not isinstance(value, (list, tuple))
            and bool(str(value or "").strip())
        ):
            reviewed_fields.append(f"reviewed_hardware.{field_name}")
    for side, side_seed in lines_by_side.items():
        if side_seed["represented_by_route_span"] is not True:
            continue
        for field_name in (
            "link_name",
            "neighbor_node",
            "fiber_type",
            "expected_loss_db",
            "distance_km",
            "circuit_id",
            "fiber_start",
            "fiber_end",
            "source_fiber_label",
            "outbound_flow",
            "inbound_flow",
            "inbound_peer_link_name",
            "inbound_peer_loss_db",
            "inbound_peer_fiber_type",
        ):
            value = side_seed.get(field_name)
            if value is not None and str(value).strip():
                reviewed_fields.append(f"{side}.{field_name}")
    peer_pfg_suggestions = tuple(
        f"{side}:{side_seed['neighbor_pfg_source']}"
        for side, side_seed in lines_by_side.items()
        if (
            side_seed["represented_by_route_span"] is True
            and side_seed.get("neighbor_line_mux_pfg")
            and side_seed.get("neighbor_line_demux_pfg")
            and side_seed.get("neighbor_pfg_source")
        )
    )
    hostname = node_identity(shelf.tid)
    controlled_derivations = [
        "shelf_label_from_site_name",
        "member_name_from_tid",
        "colan_ospf_metric_from_route_customer_policy",
    ]
    controlled_derivations.append(
        (
            "hostname_fqdn_from_tid_and_route_customer_policy"
            if hostname != shelf.tid.strip()
            else "hostname_from_tid"
        )
    )
    if terminal_route_role:
        controlled_derivations.append(
            "terminal_route_degree_patch_losses_from_audited_workflow_default"
        )
    else:
        controlled_derivations.append(
            "directional_patch_losses_from_route_customer_policy"
        )
    if neighbor_suffix:
        controlled_derivations.append(
            "neighbor_fqdn_from_tid_and_route_customer_policy"
        )
    controlled_derivations.extend(
        item.replace(":", "_neighbor_pfg_from_", 1)
        for item in peer_pfg_suggestions
    )
    if direction_prepopulated:
        controlled_derivations.append(
            (
                "fixed_direction_from_direct_endpoint"
                if direction_status == "exact_match"
                else "fixed_direction_from_audited_provider_role_fallback"
            )
        )
    controlled_defaults = [
        "target_build_schema_4.00.00_vendor_baseline_unverified",
        "bay_number_zero",
        "physical_shelf_zero",
        "repair_margin_2_db",
        "high_loss_threshold_3_db",
    ]
    if not raw_site_id.isdigit():
        controlled_defaults.insert(0, "site_id_deferred_when_absent")
    represented_side_count = sum(
        1
        for side_seed in lines_by_side.values()
        if side_seed["represented_by_route_span"] is True
    )
    remote_pfg_manual_field = (
        "prepopulated_remote_pfg_review"
        if represented_side_count
        and len(peer_pfg_suggestions) == represented_side_count
        else "remote_pfg_identities"
    )
    controlled_derivations.append(
        "provider_deployment_controls_included_automatically"
    )
    manual_fields = [
        (
            "prepopulated_provider_and_installed_bom_review"
            if provider_resolution.get("preselect_allowed") is True
            else "exact_provider_and_installed_bom"
        ),
        (
            "prepopulated_fixed_direction_review"
            if direction_prepopulated
            else "fixed_direction_to_route_side"
        ),
        remote_pfg_manual_field,
        "planner_ospcfib",
        "unrepresented_external_degree",
    ]
    policy_exclusions = [
        "customer_managed_ntp_omitted",
        "optional_frame_location_omits_shelf_location_cli_when_blank",
    ]
    if shelf.profile_id == "ila":
        policy_exclusions.append("ila_colan_prohibited")
    else:
        controlled_defaults.append(
            "terminal_colan_deferred_no_commands_by_default"
        )
        policy_exclusions.append(
            "terminal_colan_optional_for_factory_staging"
        )
    return {
        "shelf_name": shelf.tid,
        "shelf_label": site.name if site is not None else "",
        "site_name": site.name if site is not None else "",
        "site_id": int(raw_site_id) if raw_site_id.isdigit() else None,
        "site_description": project.title,
        "site_address": site.address if site is not None else "",
        "member_name": shelf.tid,
        "hostname": hostname,
        # The supplied R4.0.0 upgrade procedures identify Rel. 4.00.00 as the
        # documented baseline. This is editable planning metadata, never an
        # assertion that ATLAS observed the running target shelf.
        "target_software_build": DEFAULT_R40_TARGET_BUILD_SCHEMA,
        # Legacy B4 is a physical rack/location input. A site code or TID is
        # not rack evidence, so leave it blank unless a future diagram schema
        # supplies that fact. Blank means the shelf-location CLI is omitted.
        "frame_identification_code": "",
        "bay_number": 0,
        "physical_shelf": 0,
        "loopback_ip": shelf.primary_oam_ip,
        "ospf_area": project.ospf_area,
        "colan_ospf_metric": customer_policy.colan_ospf_metric,
        "diagram_optical_band": _route_header_optical_band(project),
        "reviewed_hardware": reviewed_hardware,
        "provider_resolution": provider_resolution,
        "direction_resolution": direction_resolution,
        "line_semantics": (
            "unidirectional_amplifier_path"
            if shelf.profile_id == "ila"
            else "bidirectional_degree"
        ),
        "line_1_route_side": (
            direction_side if direction_prepopulated else ""
        ),
        "prepopulation": {
            "route_reviewed_fields": tuple(reviewed_fields),
            "controlled_derivations": tuple(controlled_derivations),
            "controlled_defaults": tuple(controlled_defaults),
            "policy_exclusions": tuple(policy_exclusions),
            "manual_fields": tuple(manual_fields),
            "peer_pfg_suggestions": peer_pfg_suggestions,
        },
        # Route sides remain independent until the operator maps the fixed
        # local outputs. An RLA side is one bidirectional mux/demux degree;
        # missing additional hardware remains blank and is never synthesized
        # from the return propagation on the represented degree.
        "lines_by_side": lines_by_side,
    }


def _apply_r40_reviewed_lines_to_links(
    rows: Iterable[_ShelfEditorRow],
    links: Iterable[RouteLink],
    shelf_id: str,
    request: Any,
) -> list[RouteLink]:
    """Apply local R4.0 line-output facts to bidirectional route spans.

    The request assigns its first fixed local line-output to route side A or
    Z. A two-record provider assigns its second output to the opposite side;
    a one-degree ROADM request has ``line_2=None`` because the first degree's
    paired mux/demux already carries both traffic directions. For the DLE
    provider the two records are opposing amplifier egress paths. The endpoint
    review on the ordered ``from`` shelf is the A→Z propagation; the ``to``
    review is Z→A. An absent provider degree remains unrepresented and is
    never populated by cloning reverse traffic from the same physical span.
    """

    row_list = list(rows)
    shelf_index = next(
        (
            index
            for index, row in enumerate(row_list)
            if row.shelf_id == shelf_id
        ),
        None,
    )
    if shelf_index is None:
        raise ValueError("The reviewed R4.0 shelf is no longer in the route.")
    link_list = _reconcile_route_links(
        row_list,
        links,
        populate_missing=True,
    )
    line_1_side = getattr(request, "line_1_route_side", "")
    if line_1_side not in {"A", "Z"}:
        raise ValueError(
            "R4.0 local line-output 1 must be assigned to route side A or Z."
        )
    line_by_side: dict[str, tuple[Any, int]] = {
        line_1_side: (request.line_1, 1),
    }
    if request.line_2 is not None:
        line_by_side[
            "Z" if line_1_side == "A" else "A"
        ] = (request.line_2, 2)
    line_records: list[tuple[str, Any, int]] = []
    if shelf_index > 0:
        if "A" not in line_by_side:
            raise ValueError(
                "The selected exact R4.0 provider has no reviewed physical "
                "degree/path for this shelf's A-side adjacent span."
            )
        line, record_number = line_by_side["A"]
        line_records.append(
            (
                row_list[shelf_index - 1].shelf_id,
                line,
                record_number,
            )
        )
    if shelf_index < len(row_list) - 1:
        if "Z" not in line_by_side:
            raise ValueError(
                "The selected exact R4.0 provider has no reviewed physical "
                "degree/path for this shelf's Z-side adjacent span."
            )
        line, record_number = line_by_side["Z"]
        line_records.append(
            (
                row_list[shelf_index + 1].shelf_id,
                line,
                record_number,
            )
        )
    for neighbor_id, line, record_number in line_records:
        candidates = [
            index
            for index, link in enumerate(link_list)
            if {link.from_shelf_id, link.to_shelf_id}
            == {shelf_id, neighbor_id}
        ]
        if len(candidates) != 1:
            raise ValueError(
                f"R4.0 local line-output {record_number} must map to exactly "
                "one adjacent route link."
            )
        link_index = candidates[0]
        link = link_list[link_index]
        if len(link.paths) != 1:
            raise ValueError(
                f"R4.0 local line-output {record_number} requires exactly "
                "one reviewed physical optical span on its adjacent route "
                "link."
            )
        prior = link.paths[0]
        shelf_key = shelf_id.casefold()
        prior_endpoint_review = next(
            (
                review
                for review in prior.endpoint_reviews
                if review.shelf_id.casefold() == shelf_key
            ),
            None,
        )
        changed = (
            (
                prior_endpoint_review.expected_loss_db
                if prior_endpoint_review is not None
                else prior.expected_loss_db
            )
            != line.expected_loss_db
            or (
                prior_endpoint_review.fiber_type
                if prior_endpoint_review is not None
                else prior.fiber_type
            )
            != line.fiber_type
            or (
                prior_endpoint_review.link_name
                if prior_endpoint_review is not None
                else prior.link_name
            )
            != line.link_name
        )
        endpoint_reviews = tuple(
            review
            for review in prior.endpoint_reviews
            if review.shelf_id.casefold() != shelf_key
        ) + (
            PathEndpointReview(
                shelf_id=shelf_id,
                link_name=line.link_name,
                expected_loss_db=line.expected_loss_db,
                fiber_type=line.fiber_type,
            ),
        )
        changed = changed or any(
            review.link_name != prior.link_name
            or review.expected_loss_db != prior.expected_loss_db
            or review.fiber_type != prior.fiber_type
            for review in endpoint_reviews
        )
        all_endpoints_reviewed = {
            review.shelf_id.casefold() for review in endpoint_reviews
        } >= {
            link.from_shelf_id.casefold(),
            link.to_shelf_id.casefold(),
        }
        reviewed_losses = {
            review.shelf_id.casefold(): review.expected_loss_db
            for review in endpoint_reviews
            if review.shelf_id.casefold()
            in {
                link.from_shelf_id.casefold(),
                link.to_shelf_id.casefold(),
            }
        }
        common_reviewed_loss = prior.expected_loss_db
        if (
            all_endpoints_reviewed
            and len(reviewed_losses) == 2
            and math.isclose(
                float(reviewed_losses[link.from_shelf_id.casefold()]),
                float(reviewed_losses[link.to_shelf_id.casefold()]),
                rel_tol=0.0,
                abs_tol=1e-9,
            )
        ):
            common_reviewed_loss = reviewed_losses[
                link.from_shelf_id.casefold()
            ]
        reviewed_source_evidence, superseded_discrepancies = (
            _supersede_reviewed_path_source_discrepancies(
                prior.source_evidence,
                all_endpoints_reviewed=all_endpoints_reviewed,
            )
        )
        changed = changed or bool(superseded_discrepancies)
        reviewed_path = OpticalPath(
            path_id=prior.path_id,
            path_role=prior.path_role or "route",
            link_name=prior.link_name,
            expected_loss_db=common_reviewed_loss,
            distance_km=prior.distance_km,
            fiber_type=prior.fiber_type,
            circuit_id=prior.circuit_id,
            fiber_start=prior.fiber_start,
            fiber_end=prior.fiber_end,
            review_state=(
                "pending"
                if not all_endpoints_reviewed
                else "corrected"
                if changed or prior.review_state == "corrected"
                else "confirmed"
            ),
            source_evidence=reviewed_source_evidence,
            endpoint_reviews=endpoint_reviews,
            segments=prior.segments,
        )
        link_list[link_index] = replace(link, paths=(reviewed_path,))
    return link_list


def _supersede_reviewed_path_source_discrepancies(
    source_evidence: Mapping[str, object],
    *,
    all_endpoints_reviewed: bool,
) -> tuple[dict[str, object], int]:
    """Mark a preserved import discrepancy superseded by paired review.

    Source observations are never deleted or rewritten. Only a controlled
    status marker advances, and only after both connected shelves have supplied
    endpoint-local engineering. Other discrepancy fields remain pending until
    a field-specific review workflow exists.
    """

    result = dict(source_evidence)
    raw_markers = source_evidence.get(PATH_SOURCE_DISCREPANCIES_KEY, ())
    if not all_endpoints_reviewed or not isinstance(
        raw_markers,
        (list, tuple),
    ):
        return result, 0

    superseded = 0
    markers: list[object] = []
    for raw_marker in raw_markers:
        if (
            isinstance(raw_marker, Mapping)
            and raw_marker.get("field") == "expected_loss_db"
            and raw_marker.get("status") == PATH_SOURCE_DISCREPANCY_PENDING
        ):
            marker = dict(raw_marker)
            marker["status"] = PATH_SOURCE_DISCREPANCY_SUPERSEDED
            marker["deployable_cli"] = False
            markers.append(marker)
            superseded += 1
        else:
            markers.append(
                dict(raw_marker)
                if isinstance(raw_marker, Mapping)
                else raw_marker
            )
    if superseded:
        result[PATH_SOURCE_DISCREPANCIES_KEY] = markers
    return result, superseded


def build_route_project(
    *,
    route_code: str,
    title: str,
    revision: str,
    rows: Iterable[_ShelfEditorRow],
    project_id: str = "",
    notes: str = "",
    ospf_area: str = "",
    customer_policy: RouteCustomerPolicy | None = None,
    links: Iterable[RouteLink] = (),
    diagram_source: Optional[Mapping[str, Any]] = None,
    require_valid: bool = True,
) -> RouteProject:
    """Build a canonical route project while preserving shelf order.

    Site rows are deduplicated case-insensitively by their visible site code.
    Conflicting names for the same code are rejected because they would make
    the FBN table and IRM counts ambiguous.
    """

    row_list = list(rows)
    if require_valid and not route_code.strip():
        raise ValueError("Route code is required.")
    if require_valid and not title.strip():
        raise ValueError("Project title is required.")
    if require_valid and not revision.strip():
        raise ValueError("Revision is required.")
    if not row_list:
        raise ValueError("Add at least one shelf before saving or exporting.")

    sites: list[Site] = []
    canonical_sites: dict[str, Site] = {}
    used_site_keys: set[str] = set()
    shelves: list[ShelfInstance] = []

    for row_index, row in enumerate(row_list, start=1):
        code = row.site_code.strip()
        name = row.site_name.strip()
        code_key = code.casefold() if code else f"__missing_site_{row_index}"
        if require_valid and (not code or not name):
            raise ValueError(f"Shelf {row.tid or row.shelf_id} needs a site code and name.")

        existing = canonical_sites.get(code_key)
        if (
            existing is not None
            and existing.name.casefold() != name.casefold()
            and not require_valid
        ):
            code_key = f"{code_key}__conflict_{row_index}"
            existing = None
        if existing is None:
            base_site_key = row.site_key.strip() or _site_key_for(
                code or f"review-{row_index}"
            )
            site_key = base_site_key
            suffix = 2
            while site_key.casefold() in used_site_keys:
                site_key = f"{base_site_key}-{suffix}"
                suffix += 1
            existing = Site(
                site_key=site_key,
                code=code,
                name=name,
                address=row.site_address,
                network_site_id=row.network_site_id,
            )
            canonical_sites[code_key] = existing
            used_site_keys.add(site_key.casefold())
            sites.append(existing)
        elif existing.name.casefold() != name.casefold():
            raise ValueError(
                f"Site code {code!r} has conflicting names "
                f"({existing.name!r} and {name!r})."
            )

        shelves.append(
            ShelfInstance(
                shelf_id=row.shelf_id.strip() or uuid4().hex,
                profile_id=row.profile_id,
                software_release=row.software_release.strip(),
                shelf_variant=row.shelf_variant.strip(),
                site_key=existing.site_key,
                tid=row.tid.strip(),
                primary_oam_ip=row.primary_oam_ip.strip(),
                power_label=row.power_label.strip(),
                raman_label=row.raman_label.strip(),
                notes=row.notes,
                profile_payload=dict(row.profile_payload),
                review_state=row.review_state,  # type: ignore[arg-type]
                source_evidence=dict(row.source_evidence),
            )
        )

    project = RouteProject(
        project_id=project_id.strip() or uuid4().hex,
        route_code=route_code.strip(),
        title=title.strip(),
        ospf_area=ospf_area.strip(),
        customer_policy=customer_policy or RouteCustomerPolicy(),
        revision=revision.strip(),
        sites=tuple(sites),
        shelves=tuple(shelves),
        links=tuple(links),
        notes=notes,
        diagram_source=dict(diagram_source or {}),
    )
    if require_valid:
        issues = project.validate()
        errors = [issue for issue in issues if getattr(issue, "is_error", True)]
        if errors:
            formatted = "\n".join(
                f"• {getattr(issue, 'message', str(issue))}" for issue in errors
            )
            raise ValueError(f"Route project validation failed:\n{formatted}")
    return project


# Export private compatibility helpers as well as the public route API.
__all__ = [name for name in globals() if not name.startswith("__")]
