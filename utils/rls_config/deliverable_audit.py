"""Independent audit helpers for an exported RLS route deliverable.

The exporter validates the objects it is about to write.  This module provides
the deliberately separate, read-only side of the contract: it opens the
published files again, verifies their hashes and safety boundary, and compares
the saved route project with a reviewed golden route fixture.

Golden fixtures are data, not route-specific application logic.  A customer
route can therefore be regression-tested without teaching the generator any
special cases for that route.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import tempfile
from typing import Any, Iterable, Mapping, Sequence
import zipfile
from xml.etree import ElementTree

from PIL import Image

from .diagram_assets import (
    WORKBOOK_DIAGRAM_MARKER_KEY,
    WORKBOOK_DIAGRAM_NORMALIZATION,
    WORKBOOK_DIAGRAM_REPRESENTATION,
)
from .r4_0_generator import R40_PAYLOAD_SCHEMA_VERSION
from .route_bundle import _validation_text
from .route_config import (
    RouteConfigBuild,
    RouteConfigError,
    require_complete_route_configs,
)
from .route_project import (
    ROUTE_SCHEMA_VERSION,
    RouteProject,
    RouteProjectFormatError,
)


_SPREADSHEET_NS = (
    "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
)
_OFFICE_REL_NS = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
)
_PACKAGE_REL_NS = (
    "http://schemas.openxmlformats.org/package/2006/relationships"
)
_DRAWING_REL_TYPE = f"{_OFFICE_REL_NS}/drawing"
_IMAGE_REL_TYPE = f"{_OFFICE_REL_NS}/image"
_WORKSHEET_REL_TYPE = f"{_OFFICE_REL_NS}/worksheet"
_DRAWING_NS = (
    "http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing"
)
_DRAWING_MAIN_NS = (
    "http://schemas.openxmlformats.org/drawingml/2006/main"
)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_LEAF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SECRET_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "community",
    "privatekey",
    "private_key",
    "secret",
    "credential",
    "token",
    "apikey",
    "api_key",
    "licensekey",
    "license_key",
)
_SECRET_TEXT_ASSIGNMENT_RE = re.compile(
    r"""
    \b
    (?:
        password
        | passwd
        | community(?:[\s_-]+string)?
        | private[\s_-]*key
        | secret
        | credential
        | api[\s_-]*key
        | license[\s_-]*key
    )
    \b
    \s*[:=]\s*
    (?P<value>\S.*)
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)
_EMPTY_SECRET_TEXT_VALUES = {
    "false",
    "no",
    "none",
    "not configured",
    "not included",
    "not provided",
    "omitted",
    "redacted",
}


@dataclass(frozen=True)
class DeliverableAuditFinding:
    """One deterministic difference or integrity failure."""

    severity: str
    code: str
    field: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "code": self.code,
            "field": self.field,
            "message": self.message,
        }


@dataclass(frozen=True)
class DeliverableAuditReport:
    """Result of a read-only bundle audit."""

    bundle: str
    findings: tuple[DeliverableAuditFinding, ...]
    checked_shelves: int = 0
    checked_spans: int = 0
    checked_hashes: int = 0
    checked_cli_files: int = 0

    @property
    def passed(self) -> bool:
        return not any(
            finding.severity == "error" for finding in self.findings
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "atlas.ciena.rls.deliverable-audit",
            "schema_version": "1.0",
            "bundle": self.bundle,
            "passed": self.passed,
            "checked_shelves": self.checked_shelves,
            "checked_spans": self.checked_spans,
            "checked_hashes": self.checked_hashes,
            "checked_cli_files": self.checked_cli_files,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _first_matching(root: Path, pattern: str) -> Path | None:
    matches = sorted(root.glob(pattern))
    return matches[0] if matches else None


def _provider_id(shelf: Mapping[str, Any]) -> str:
    payload = shelf.get("profile_payload")
    if not isinstance(payload, Mapping):
        return ""
    request = payload.get("request")
    if not isinstance(request, Mapping):
        return ""
    return str(request.get("provider_id", "") or "")


def _project_shelf_rows(project: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw_sites = project.get("sites")
    raw_shelves = project.get("shelves")
    sites = raw_sites if isinstance(raw_sites, Sequence) else ()
    shelves = raw_shelves if isinstance(raw_shelves, Sequence) else ()
    site_by_key = {
        str(site.get("site_key", "")): site
        for site in sites
        if isinstance(site, Mapping)
    }
    rows: list[dict[str, Any]] = []
    for order, raw_shelf in enumerate(shelves, start=1):
        if not isinstance(raw_shelf, Mapping):
            continue
        site = site_by_key.get(str(raw_shelf.get("site_key", "")), {})
        rows.append(
            {
                "order": order,
                "site_code": site.get("code", ""),
                "site_name": site.get("name", ""),
                "tid": raw_shelf.get("tid", ""),
                "primary_oam_ip": raw_shelf.get("primary_oam_ip", ""),
                "profile_id": raw_shelf.get("profile_id", ""),
                "shelf_variant": raw_shelf.get("shelf_variant", ""),
                "power_label": raw_shelf.get("power_label", ""),
                "raman_label": raw_shelf.get("raman_label", ""),
                "provider_id": _provider_id(raw_shelf),
                "review_state": raw_shelf.get("review_state", ""),
            }
        )
    return rows


def _project_request_rows(
    project: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Expose exact saved request values for optional golden comparison."""

    raw_shelves = project.get("shelves")
    shelves = (
        raw_shelves
        if isinstance(raw_shelves, Sequence)
        and not isinstance(raw_shelves, (str, bytes))
        else ()
    )
    rows: list[dict[str, Any]] = []
    for order, raw_shelf in enumerate(shelves, start=1):
        if not isinstance(raw_shelf, Mapping):
            continue
        payload = raw_shelf.get("profile_payload")
        request = (
            payload.get("request")
            if isinstance(payload, Mapping)
            else None
        )
        rows.append(
            {
                "order": order,
                "shelf_id": raw_shelf.get("shelf_id", ""),
                "tid": raw_shelf.get("tid", ""),
                "profile_id": raw_shelf.get("profile_id", ""),
                "schema_id": (
                    payload.get("schema_id", "")
                    if isinstance(payload, Mapping)
                    else ""
                ),
                "schema_version": (
                    payload.get("schema_version", "")
                    if isinstance(payload, Mapping)
                    else ""
                ),
                "request": (
                    dict(request) if isinstance(request, Mapping) else {}
                ),
            }
        )
    return rows


def _project_span_rows(project: Mapping[str, Any]) -> list[dict[str, Any]]:
    shelves = project.get("shelves")
    shelf_by_id = {
        str(shelf.get("shelf_id", "")): str(shelf.get("tid", ""))
        for shelf in (
            shelves if isinstance(shelves, Sequence) else ()
        )
        if isinstance(shelf, Mapping)
    }
    links = project.get("links")
    rows: list[dict[str, Any]] = []
    for raw_link in links if isinstance(links, Sequence) else ():
        if not isinstance(raw_link, Mapping):
            continue
        paths = raw_link.get("paths")
        path = (
            paths[0]
            if isinstance(paths, Sequence)
            and paths
            and isinstance(paths[0], Mapping)
            else {}
        )
        segments = path.get("segments")
        normalized_segments = [
            {
                "order": segment.get("order"),
                "from_tid": segment.get("from_tid", ""),
                "to_tid": segment.get("to_tid", ""),
                "expected_loss_db": segment.get("expected_loss_db"),
                "distance_km": segment.get("distance_km"),
                "circuit_id": segment.get("circuit_id", ""),
                "fiber_start": segment.get("fiber_start"),
                "fiber_end": segment.get("fiber_end"),
                "fiber_type": segment.get("fiber_type", ""),
            }
            for segment in (
                segments if isinstance(segments, Sequence) else ()
            )
            if isinstance(segment, Mapping)
        ]
        rows.append(
            {
                "order": raw_link.get("order"),
                "from_tid": shelf_by_id.get(
                    str(raw_link.get("from_shelf_id", "")), ""
                ),
                "to_tid": shelf_by_id.get(
                    str(raw_link.get("to_shelf_id", "")), ""
                ),
                "expected_loss_db": path.get("expected_loss_db"),
                "distance_km": path.get("distance_km"),
                "circuit_id": path.get("circuit_id", ""),
                "fiber_start": path.get("fiber_start"),
                "fiber_end": path.get("fiber_end"),
                "fiber_type": path.get("fiber_type", ""),
                "review_state": path.get("review_state", ""),
                "segment_count": len(normalized_segments),
                "segments": normalized_segments,
            }
        )
    return rows


def _values_equal(expected: Any, actual: Any) -> bool:
    if (
        isinstance(expected, (int, float))
        and not isinstance(expected, bool)
        and isinstance(actual, (int, float))
        and not isinstance(actual, bool)
    ):
        return abs(float(expected) - float(actual)) <= 1e-6
    return expected == actual


def _compare_mapping(
    expected: Mapping[str, Any],
    actual: Mapping[str, Any],
    *,
    prefix: str,
    code: str,
) -> list[DeliverableAuditFinding]:
    findings: list[DeliverableAuditFinding] = []
    for key, expected_value in expected.items():
        if key not in actual:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    code,
                    f"{prefix}.{key}",
                    f"Expected {expected_value!r}; field is absent.",
                )
            )
            continue
        actual_value = actual[key]
        if isinstance(expected_value, Mapping):
            if not isinstance(actual_value, Mapping):
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        code,
                        f"{prefix}.{key}",
                        (
                            "Expected a structured object; found "
                            f"{actual_value!r}."
                        ),
                    )
                )
            else:
                findings.extend(
                    _compare_mapping(
                        expected_value,
                        actual_value,
                        prefix=f"{prefix}.{key}",
                        code=code,
                    )
                )
            continue
        if (
            isinstance(expected_value, Sequence)
            and not isinstance(expected_value, (str, bytes))
        ):
            if (
                not isinstance(actual_value, Sequence)
                or isinstance(actual_value, (str, bytes))
            ):
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        code,
                        f"{prefix}.{key}",
                        (
                            "Expected an ordered list; found "
                            f"{actual_value!r}."
                        ),
                    )
                )
                continue
            if len(expected_value) != len(actual_value):
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        code,
                        f"{prefix}.{key}",
                        (
                            f"Expected {len(expected_value)} item(s); "
                            f"found {len(actual_value)}."
                        ),
                    )
                )
            for index, expected_item in enumerate(expected_value):
                if index >= len(actual_value):
                    break
                actual_item = actual_value[index]
                if isinstance(expected_item, Mapping):
                    if not isinstance(actual_item, Mapping):
                        findings.append(
                            DeliverableAuditFinding(
                                "error",
                                code,
                                f"{prefix}.{key}[{index + 1}]",
                                (
                                    "Expected a structured object; found "
                                    f"{actual_item!r}."
                                ),
                            )
                        )
                    else:
                        findings.extend(
                            _compare_mapping(
                                expected_item,
                                actual_item,
                                prefix=(
                                    f"{prefix}.{key}[{index + 1}]"
                                ),
                                code=code,
                            )
                        )
                elif not _values_equal(expected_item, actual_item):
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            code,
                            f"{prefix}.{key}[{index + 1}]",
                            (
                                f"Expected {expected_item!r}; "
                                f"found {actual_item!r}."
                            ),
                        )
                    )
            continue
        if not _values_equal(expected_value, actual_value):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    code,
                    f"{prefix}.{key}",
                    f"Expected {expected_value!r}; found {actual_value!r}.",
                )
            )
    return findings


def compare_project_to_golden(
    project: Mapping[str, Any],
    golden: Mapping[str, Any],
) -> tuple[tuple[DeliverableAuditFinding, ...], int, int]:
    """Compare only the reviewed facts declared by a golden route fixture."""

    findings: list[DeliverableAuditFinding] = []
    expected_route = golden.get("route")
    if isinstance(expected_route, Mapping):
        findings.extend(
            _compare_mapping(
                expected_route,
                project,
                prefix="route",
                code="GOLDEN_ROUTE_MISMATCH",
            )
        )

    expected_shelves = golden.get("shelves")
    shelf_rows = _project_shelf_rows(project)
    checked_shelves = (
        len(expected_shelves)
        if isinstance(expected_shelves, Sequence)
        else 0
    )
    if isinstance(expected_shelves, Sequence):
        if len(shelf_rows) != len(expected_shelves):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "GOLDEN_SHELF_COUNT_MISMATCH",
                    "shelves",
                    (
                        f"Expected {len(expected_shelves)} ordered shelves; "
                        f"found {len(shelf_rows)}."
                    ),
                )
            )
        for index, expected in enumerate(expected_shelves):
            if not isinstance(expected, Mapping) or index >= len(shelf_rows):
                continue
            findings.extend(
                _compare_mapping(
                    expected,
                    shelf_rows[index],
                    prefix=f"shelves[{index + 1}]",
                    code="GOLDEN_SHELF_MISMATCH",
                )
            )

    expected_spans = golden.get("spans")
    span_rows = _project_span_rows(project)
    checked_spans = (
        len(expected_spans) if isinstance(expected_spans, Sequence) else 0
    )
    if isinstance(expected_spans, Sequence):
        if len(span_rows) != len(expected_spans):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "GOLDEN_SPAN_COUNT_MISMATCH",
                    "links",
                    (
                        f"Expected {len(expected_spans)} ordered spans; "
                        f"found {len(span_rows)}."
                    ),
                )
            )
        for index, expected in enumerate(expected_spans):
            if not isinstance(expected, Mapping) or index >= len(span_rows):
                continue
            findings.extend(
                _compare_mapping(
                    expected,
                    span_rows[index],
                    prefix=f"spans[{index + 1}]",
                    code="GOLDEN_SPAN_MISMATCH",
                )
            )

    expected_requests = golden.get("configuration_requests")
    request_rows = _project_request_rows(project)
    if (
        isinstance(expected_requests, Sequence)
        and not isinstance(expected_requests, (str, bytes))
    ):
        if len(request_rows) != len(expected_requests):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "GOLDEN_CONFIGURATION_REQUEST_COUNT_MISMATCH",
                    "configuration_requests",
                    (
                        f"Expected {len(expected_requests)} ordered exact "
                        f"request(s); found {len(request_rows)}."
                    ),
                )
            )
        for index, expected in enumerate(expected_requests):
            if (
                not isinstance(expected, Mapping)
                or index >= len(request_rows)
            ):
                continue
            findings.extend(
                _compare_mapping(
                    expected,
                    request_rows[index],
                    prefix=f"configuration_requests[{index + 1}]",
                    code="GOLDEN_CONFIGURATION_REQUEST_MISMATCH",
                )
            )

    return tuple(findings), checked_shelves, checked_spans


def _executable_commit_lines(text: str) -> list[int]:
    lines: list[int] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", "!", "//")):
            continue
        if line.split(maxsplit=1)[0].casefold() == "commit":
            lines.append(number)
    return lines


def _manifest_file_records(
    manifest: Mapping[str, Any],
) -> Iterable[tuple[str, str]]:
    artifacts = manifest.get("artifacts")
    configs_directory: str | None = None
    if isinstance(artifacts, Mapping):
        for record in artifacts.values():
            if (
                isinstance(record, Mapping)
                and isinstance(record.get("filename"), str)
                and isinstance(record.get("sha256"), str)
            ):
                yield str(record["filename"]), str(record["sha256"])
        configs = artifacts.get("configs")
        declared_directory = (
            configs.get("directory")
            if isinstance(configs, Mapping)
            else None
        )
        if _safe_leaf_name(declared_directory):
            configs_directory = str(declared_directory)

    candidates = manifest.get("configuration_candidates")
    if (
        configs_directory is None
        or not isinstance(candidates, Sequence)
        or isinstance(candidates, (str, bytes))
    ):
        return
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        directory = str(candidate.get("directory", "") or "")
        files = candidate.get("files")
        if not isinstance(files, Mapping):
            continue
        for record in files.values():
            if (
                isinstance(record, Mapping)
                and isinstance(record.get("filename"), str)
                and isinstance(record.get("sha256"), str)
            ):
                relative = (
                    Path(configs_directory)
                    / directory
                    / str(record["filename"])
                )
                yield relative.as_posix(), str(record["sha256"])


def _safe_leaf_name(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value in {".", ".."} or value.endswith((".", " ")):
        return False
    if "/" in value or "\\" in value:
        return False
    return bool(_SAFE_LEAF_RE.fullmatch(value))


def _safe_relative_name(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    parts = value.split("/")
    if not parts or any(not _safe_leaf_name(part) for part in parts):
        return None
    return "/".join(parts)


def _discover_bundle_files(
    root: Path,
) -> tuple[
    dict[str, Path],
    dict[str, Path],
    list[DeliverableAuditFinding],
]:
    """Inventory without following links; no bundle file is read beforehand."""

    files: dict[str, Path] = {}
    directories: dict[str, Path] = {}
    findings: list[DeliverableAuditFinding] = []
    try:
        root_lstat = root.lstat()
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        return {}, {}, [
            DeliverableAuditFinding(
                "error",
                "BUNDLE_NOT_FOUND",
                "bundle",
                str(exc),
            )
        ]
    if root.is_symlink() or not stat.S_ISDIR(root_lstat.st_mode):
        return {}, {}, [
            DeliverableAuditFinding(
                "error",
                "BUNDLE_ROOT_UNSAFE",
                "bundle",
                "The bundle root must be a real directory, not a link.",
            )
        ]

    def visit(directory: Path) -> None:
        try:
            entries = sorted(
                os.scandir(directory),
                key=lambda entry: entry.name.casefold(),
            )
        except OSError as exc:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "BUNDLE_ENTRY_UNREADABLE",
                    directory.relative_to(root).as_posix() or ".",
                    str(exc),
                )
            )
            return
        try:
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                try:
                    mode = entry.stat(follow_symlinks=False).st_mode
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(resolved_root)
                except (OSError, ValueError) as exc:
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "BUNDLE_PATH_OUTSIDE_ROOT",
                            relative,
                            (
                                "Bundle entry failed containment validation "
                                f"before read: {exc}"
                            ),
                        )
                    )
                    continue
                if entry.is_symlink():
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "BUNDLE_SYMLINK_FORBIDDEN",
                            relative,
                            "Published bundles must not contain links.",
                        )
                    )
                    continue
                if stat.S_ISDIR(mode):
                    key = relative.casefold()
                    if key in directories:
                        findings.append(
                            DeliverableAuditFinding(
                                "error",
                                "BUNDLE_PATH_COLLISION",
                                relative,
                                "Directory paths are not case-unique.",
                            )
                        )
                        continue
                    directories[key] = path
                    visit(path)
                    continue
                if stat.S_ISREG(mode):
                    key = relative.casefold()
                    if key in files:
                        findings.append(
                            DeliverableAuditFinding(
                                "error",
                                "BUNDLE_PATH_COLLISION",
                                relative,
                                "File paths are not case-unique.",
                            )
                        )
                        continue
                    files[key] = path
                    continue
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "BUNDLE_SPECIAL_FILE_FORBIDDEN",
                        relative,
                        "Only regular files and directories are permitted.",
                    )
                )
        finally:
            for entry in entries:
                del entry

    visit(root)
    return files, directories, findings


def _single_top_level_file(
    files: Mapping[str, Path],
    suffix: str,
    *,
    label: str,
) -> tuple[Path | None, list[DeliverableAuditFinding]]:
    # Do not infer the root from an arbitrary file. Top-level entries have one
    # relative path component in the preflight inventory.
    matches = sorted(
        (
            path
            for key, path in files.items()
            if "/" not in key and path.name.endswith(suffix)
        ),
        key=lambda path: path.name.casefold(),
    )
    if len(matches) == 1:
        return matches[0], []
    code = f"{label.upper()}_NOT_FOUND" if not matches else (
        f"{label.upper()}_AMBIGUOUS"
    )
    message = (
        f"No {label.lower()} was found."
        if not matches
        else (
            f"Expected exactly one {label.lower()}; found "
            f"{len(matches)}."
        )
    )
    return None, [
        DeliverableAuditFinding(
            "error",
            code,
            label.lower(),
            message,
        )
    ]


def _inventory_file(
    files: Mapping[str, Path],
    relative_name: object,
) -> Path | None:
    safe = _safe_relative_name(relative_name)
    return files.get(safe.casefold()) if safe is not None else None


def _audit_manifest_hashes(
    root: Path,
    manifest: Mapping[str, Any],
    files: Mapping[str, Path],
) -> tuple[list[DeliverableAuditFinding], int]:
    findings: list[DeliverableAuditFinding] = []
    checked = 0
    for relative_name, expected_hash in _manifest_file_records(manifest):
        checked += 1
        safe_relative = _safe_relative_name(relative_name)
        if safe_relative is None:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "MANIFEST_PATH_OUTSIDE_BUNDLE",
                    relative_name,
                    (
                        "The manifest artifact path escapes the published "
                        "bundle and was not read."
                    ),
                )
            )
            continue
        target = files.get(safe_relative.casefold())
        if target is None:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "MANIFEST_FILE_MISSING",
                    relative_name,
                    "The manifest-listed artifact is absent.",
                )
            )
            continue
        actual_hash = _sha256(target)
        if actual_hash.casefold() != expected_hash.casefold():
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "MANIFEST_HASH_MISMATCH",
                    relative_name,
                    (
                        f"Expected SHA-256 {expected_hash}; "
                        f"found {actual_hash}."
                    ),
                )
            )
    return findings, checked


def _audit_candidate_cli(
    root: Path,
    files: Mapping[str, Path],
) -> tuple[list[DeliverableAuditFinding], int]:
    findings: list[DeliverableAuditFinding] = []
    cli_files = sorted(
        (
            path
            for relative, path in files.items()
            if relative.startswith("configs/")
            and relative.endswith(".cli")
        ),
        key=lambda path: path.relative_to(root).as_posix().casefold(),
    )
    for path in cli_files:
        commit_lines = _executable_commit_lines(
            path.read_text(encoding="utf-8", errors="replace")
        )
        if commit_lines:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CANDIDATE_CONTAINS_COMMIT",
                    path.relative_to(root).as_posix(),
                    (
                        "A pre-calibration candidate contains executable "
                        f"commit command(s) on line(s) {commit_lines}."
                    ),
                )
            )
    return findings, len(cli_files)


def _formula_records(
    worksheet_roots: Mapping[str, ElementTree.Element],
) -> tuple[list[str], list[str]]:
    formulas: list[str] = []
    caches: list[str] = []
    for part, root in sorted(worksheet_roots.items()):
        for cell in root.iter(f"{{{_SPREADSHEET_NS}}}c"):
            formula = cell.find(f"{{{_SPREADSHEET_NS}}}f")
            if formula is None:
                continue
            reference = str(cell.get("r", "") or "")
            attributes = json.dumps(
                dict(sorted(formula.attrib.items())),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            formulas.append(
                "|".join(
                    (
                        part,
                        reference,
                        attributes,
                        formula.text or "",
                    )
                )
            )
            cached = cell.find(f"{{{_SPREADSHEET_NS}}}v")
            caches.append(
                "|".join(
                    (
                        part,
                        reference,
                        "" if cached is None else (cached.text or ""),
                    )
                )
            )
    return formulas, caches


def _formula_fingerprints(
    worksheet_roots: Mapping[str, ElementTree.Element],
) -> tuple[str, str]:
    """Return exact formula-definition and cached-value fingerprints."""

    formulas, caches = _formula_records(worksheet_roots)
    return (
        hashlib.sha256("\n".join(formulas).encode("utf-8")).hexdigest(),
        hashlib.sha256("\n".join(caches).encode("utf-8")).hexdigest(),
    )


def _relationship_part(source_part: str) -> str:
    directory = posixpath.dirname(source_part)
    name = posixpath.basename(source_part)
    return posixpath.join(directory, "_rels", f"{name}.rels")


@dataclass(frozen=True)
class _PackageRelationship:
    relationship_id: str
    relationship_type: str
    target: str
    target_mode: str
    resolved_part: str


def _relationship_records(
    archive: zipfile.ZipFile,
    source_part: str,
) -> tuple[_PackageRelationship, ...]:
    relationship_part = _relationship_part(source_part)
    if relationship_part not in archive.namelist():
        return ()
    root = ElementTree.fromstring(archive.read(relationship_part))
    result: list[_PackageRelationship] = []
    for relationship in root.findall(
        f"{{{_PACKAGE_REL_NS}}}Relationship"
    ):
        relationship_id = str(relationship.get("Id", "") or "")
        target = str(relationship.get("Target", "") or "")
        relationship_type = str(relationship.get("Type", "") or "")
        target_mode = str(relationship.get("TargetMode", "") or "")
        if not relationship_id or not target:
            continue
        if target_mode.casefold() == "external":
            resolved = ""
        elif target.startswith("/"):
            resolved = target.lstrip("/")
        else:
            resolved = posixpath.normpath(
                posixpath.join(posixpath.dirname(source_part), target)
            )
        result.append(
            _PackageRelationship(
                relationship_id=relationship_id,
                relationship_type=relationship_type,
                target=target,
                target_mode=target_mode,
                resolved_part=resolved,
            )
        )
    return tuple(result)


def _related_parts(
    archive: zipfile.ZipFile,
    source_part: str,
) -> dict[str, str]:
    """Compatibility projection for non-security-sensitive workbook mapping."""

    return {
        record.relationship_id: record.resolved_part
        for record in _relationship_records(archive, source_part)
        if record.target_mode.casefold() != "external"
    }


def _relationship_index(
    records: Sequence[_PackageRelationship],
    *,
    field: str,
) -> tuple[
    dict[str, _PackageRelationship],
    list[DeliverableAuditFinding],
]:
    result: dict[str, _PackageRelationship] = {}
    findings: list[DeliverableAuditFinding] = []
    for record in records:
        if record.relationship_id in result:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_RELATIONSHIP_INVALID",
                    field,
                    (
                        "Relationship IDs must be unique; duplicate "
                        f"{record.relationship_id!r} was found."
                    ),
                )
            )
            continue
        result[record.relationship_id] = record
    return result, findings


def _safe_zip_part(part: str) -> bool:
    if not part or "\\" in part or part.startswith("/"):
        return False
    normalized = posixpath.normpath(part)
    return (
        normalized == part
        and normalized not in {".", ".."}
        and not normalized.startswith("../")
    )


def _is_internal_relationship(
    record: _PackageRelationship,
    expected_type: str,
) -> bool:
    return (
        record.relationship_type == expected_type
        and record.target_mode.casefold() in {"", "internal"}
    )


def _diagram_linked_image_parts(
    archive: zipfile.ZipFile,
    diagram_sheet_part: str,
    diagram_sheet_root: ElementTree.Element,
) -> tuple[tuple[str, ...], list[DeliverableAuditFinding]]:
    findings: list[DeliverableAuditFinding] = []
    sheet_relationships, index_findings = _relationship_index(
        _relationship_records(archive, diagram_sheet_part),
        field="workbook.Diagram.relationships",
    )
    findings.extend(index_findings)
    for record in sheet_relationships.values():
        if record.target_mode.casefold() == "external":
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_RELATIONSHIP_INVALID",
                    (
                        "workbook.Diagram.relationships."
                        f"{record.relationship_id}"
                    ),
                    "Diagram sheet relationships must not be external.",
                )
            )
    drawing_parts: list[str] = []
    for drawing in diagram_sheet_root.iter(
        f"{{{_SPREADSHEET_NS}}}drawing"
    ):
        relationship_id = drawing.get(f"{{{_OFFICE_REL_NS}}}id", "")
        record = sheet_relationships.get(relationship_id)
        if (
            record is None
            or not _is_internal_relationship(record, _DRAWING_REL_TYPE)
            or not _safe_zip_part(record.resolved_part)
            or not record.resolved_part.startswith("xl/drawings/")
            or record.resolved_part not in archive.namelist()
        ):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_RELATIONSHIP_INVALID",
                    "workbook.Diagram.drawing",
                    (
                        "Diagram drawing references must be internal drawing "
                        "relationships to existing package parts."
                    ),
                )
            )
            continue
        drawing_parts.append(record.resolved_part)
    image_parts: list[str] = []
    for drawing_part in drawing_parts:
        drawing_relationships, index_findings = _relationship_index(
            _relationship_records(archive, drawing_part),
            field=f"workbook.{drawing_part}.relationships",
        )
        findings.extend(index_findings)
        for record in drawing_relationships.values():
            if record.target_mode.casefold() == "external":
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "WORKBOOK_DIAGRAM_RELATIONSHIP_INVALID",
                        (
                            f"workbook.{drawing_part}."
                            f"{record.relationship_id}"
                        ),
                        "Diagram drawing relationships must not be external.",
                    )
                )
        try:
            drawing_root = ElementTree.fromstring(archive.read(drawing_part))
        except (KeyError, ElementTree.ParseError) as exc:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_RELATIONSHIP_INVALID",
                    f"workbook.{drawing_part}",
                    str(exc),
                )
            )
            continue
        referenced_ids: set[str] = set()
        for element in drawing_root.iter():
            relationship_id = element.get(
                f"{{{_OFFICE_REL_NS}}}embed", ""
            )
            if not relationship_id:
                continue
            referenced_ids.add(relationship_id)
            record = drawing_relationships.get(relationship_id)
            if (
                record is None
                or not _is_internal_relationship(record, _IMAGE_REL_TYPE)
                or not _safe_zip_part(record.resolved_part)
                or not record.resolved_part.startswith("xl/media/")
                or record.resolved_part not in archive.namelist()
            ):
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "WORKBOOK_DIAGRAM_RELATIONSHIP_INVALID",
                        f"workbook.{drawing_part}.{relationship_id}",
                        (
                            "Diagram image references must be internal image "
                            "relationships to existing xl/media parts."
                        ),
                    )
                )
                continue
            image_parts.append(record.resolved_part)
        for relationship_id, record in drawing_relationships.items():
            if (
                record.relationship_type == _IMAGE_REL_TYPE
                and relationship_id not in referenced_ids
            ):
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "WORKBOOK_DIAGRAM_RELATIONSHIP_INVALID",
                        f"workbook.{drawing_part}.{relationship_id}",
                        "An image relationship is not referenced by the drawing.",
                    )
                )
    return tuple(image_parts), findings


def _audit_diagram_embedding(
    embedding: Mapping[str, Any],
    actual_images: Sequence[Mapping[str, Any]],
) -> list[DeliverableAuditFinding]:
    findings: list[DeliverableAuditFinding] = []
    has_images = bool(actual_images)
    expected_states = {
        "embedded": has_images,
        "sheet": "Diagram",
        "external_relationships": False,
    }
    if has_images:
        expected_states.update(
            {
                "representation": WORKBOOK_DIAGRAM_REPRESENTATION,
                "normalization": WORKBOOK_DIAGRAM_NORMALIZATION,
            }
        )
    for field, expected in expected_states.items():
        actual = embedding.get(field)
        if actual != expected:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_MANIFEST_MISMATCH",
                    f"manifest.diagram_embedding.{field}",
                    f"Expected {expected!r}; found {actual!r}.",
                )
            )

    if not has_images:
        raw_images = embedding.get("images")
        if raw_images not in (None, [], ()):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_MANIFEST_MISMATCH",
                    "manifest.diagram_embedding.images",
                    "Manifest lists Diagram images but none are linked.",
                )
            )
        return findings

    raw_images = embedding.get("images")
    manifest_images = (
        list(raw_images)
        if isinstance(raw_images, Sequence)
        and not isinstance(raw_images, (str, bytes))
        else []
    )
    expected_counts = {
        "image_occurrence_count": len(actual_images),
        "unique_media_count": len(
            {
                str(image.get("normalized_sha256", ""))
                for image in actual_images
            }
        ),
    }
    for field, expected in expected_counts.items():
        actual = embedding.get(field)
        if actual != expected:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_MANIFEST_MISMATCH",
                    f"manifest.diagram_embedding.{field}",
                    f"Expected {expected!r}; found {actual!r}.",
                )
            )
    if len(manifest_images) != len(actual_images):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_DIAGRAM_MANIFEST_MISMATCH",
                "manifest.diagram_embedding.images",
                (
                    f"Expected {len(actual_images)} ordered manifest image "
                    f"record(s); found {len(manifest_images)}."
                ),
            )
        )
    for index, actual_image in enumerate(actual_images):
        if index >= len(manifest_images):
            break
        manifest_image = manifest_images[index]
        if not isinstance(manifest_image, Mapping):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_MANIFEST_MISMATCH",
                    f"manifest.diagram_embedding.images[{index + 1}]",
                    "Image record must be a JSON object.",
                )
            )
            continue
        expected_image = {
            "order": index + 1,
            "normalized_sha256": actual_image.get("normalized_sha256"),
            "width": actual_image.get("width"),
            "height": actual_image.get("height"),
        }
        findings.extend(
            _compare_mapping(
                expected_image,
                manifest_image,
                prefix=(
                    f"manifest.diagram_embedding.images[{index + 1}]"
                ),
                code="WORKBOOK_DIAGRAM_MANIFEST_MISMATCH",
            )
        )
    return findings


def _diagram_drawing_contract(
    actual_xml: bytes,
    template_xml: bytes,
    *,
    embedding: Mapping[str, Any] | None,
    image_records: Sequence[Mapping[str, Any]],
) -> list[DeliverableAuditFinding]:
    """Bind renderer-owned picture anchors to the immutable template drawing."""

    findings: list[DeliverableAuditFinding] = []
    try:
        actual_root = ElementTree.fromstring(actual_xml)
        template_root = ElementTree.fromstring(template_xml)
    except ElementTree.ParseError as exc:
        return [
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_DIAGRAM_DRAWING_INVALID",
                "workbook.Diagram.drawing",
                str(exc),
            )
        ]

    renderer_children: list[
        tuple[int, ElementTree.Element, ElementTree.Element]
    ] = []
    actual_children = list(actual_root)
    for index, child in enumerate(actual_children):
        renderer_properties = [
            element
            for element in child.iter(
                f"{{{_DRAWING_NS}}}cNvPr"
            )
            if re.fullmatch(
                r"ATLAS Route Diagram [1-9][0-9]*",
                str(element.get("name", "") or ""),
            )
        ]
        if renderer_properties:
            if len(renderer_properties) != 1:
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "WORKBOOK_DIAGRAM_ANCHOR_INVALID",
                        "workbook.Diagram.anchors",
                        "A renderer anchor has multiple ATLAS picture names.",
                    )
                )
            renderer_children.append(
                (index, child, renderer_properties[0])
            )

    expected_count = len(image_records)
    if len(renderer_children) != expected_count:
        findings.append(
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_DIAGRAM_ANCHOR_INVALID",
                "workbook.Diagram.anchors",
                (
                    f"Expected {expected_count} ordered ATLAS picture "
                    f"anchor(s); found {len(renderer_children)}."
                ),
            )
        )
    if renderer_children:
        expected_indexes = list(
            range(
                len(actual_children) - len(renderer_children),
                len(actual_children),
            )
        )
        if [item[0] for item in renderer_children] != expected_indexes:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_ANCHOR_INVALID",
                    "workbook.Diagram.anchors",
                    "ATLAS diagram anchors must be a contiguous drawing suffix.",
                )
            )

    all_object_ids = [
        str(element.get("id", "") or "")
        for element in actual_root.iter(f"{{{_DRAWING_NS}}}cNvPr")
    ]
    if (
        any(not value.isdigit() or int(value) < 1 for value in all_object_ids)
        or len(set(all_object_ids)) != len(all_object_ids)
    ):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_DIAGRAM_ANCHOR_INVALID",
                "workbook.Diagram.object_ids",
                "Drawing object IDs must be unique positive integers.",
            )
        )

    source_sha256 = (
        str(embedding.get("source_sha256", "") or "")
        if isinstance(embedding, Mapping)
        else ""
    )
    for order, (_index, anchor, properties) in enumerate(
        renderer_children,
        start=1,
    ):
        expected_name = f"ATLAS Route Diagram {order}"
        if properties.get("name") != expected_name:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_ANCHOR_INVALID",
                    f"workbook.Diagram.anchors[{order}].name",
                    (
                        f"Expected {expected_name!r}; found "
                        f"{properties.get('name')!r}."
                    ),
                )
            )
        description = str(properties.get("descr", "") or "")
        image_digest = (
            str(image_records[order - 1].get("normalized_sha256", "") or "")
            if order <= len(image_records)
            else ""
        )
        if (
            not source_sha256
            or source_sha256 not in description
            or not image_digest
            or image_digest not in description
        ):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_ANCHOR_INVALID",
                    f"workbook.Diagram.anchors[{order}].description",
                    (
                        "Picture description must bind the source and "
                        "normalized image SHA-256 digests."
                    ),
                )
            )
        locks = list(
            anchor.iter(f"{{{_DRAWING_MAIN_NS}}}picLocks")
        )
        if len(locks) != 1 or locks[0].get("noChangeAspect") != "1":
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_ANCHOR_INVALID",
                    f"workbook.Diagram.anchors[{order}].aspect",
                    "Picture aspect ratio must be locked.",
                )
            )
        embeds = [
            str(element.get(f"{{{_OFFICE_REL_NS}}}embed", "") or "")
            for element in anchor.iter(f"{{{_DRAWING_MAIN_NS}}}blip")
        ]
        if len(embeds) != 1 or not embeds[0]:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_ANCHOR_INVALID",
                    f"workbook.Diagram.anchors[{order}].relationship",
                    "Each picture must have one internal image relationship.",
                )
            )
        anchor_extents = [
            element
            for element in list(anchor)
            if element.tag == f"{{{_DRAWING_NS}}}ext"
        ]
        shape_extents = list(
            anchor.iter(f"{{{_DRAWING_MAIN_NS}}}ext")
        )
        if (
            len(anchor_extents) != 1
            or len(shape_extents) != 1
            or anchor_extents[0].get("cx") != shape_extents[0].get("cx")
            or anchor_extents[0].get("cy") != shape_extents[0].get("cy")
        ):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_ANCHOR_INVALID",
                    f"workbook.Diagram.anchors[{order}].extent",
                    "Anchor and picture extents must match exactly.",
                )
            )

    for _index, child, _properties in reversed(renderer_children):
        actual_root.remove(child)
    if ElementTree.tostring(actual_root) != ElementTree.tostring(template_root):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_DIAGRAM_BASE_MISMATCH",
                "workbook.Diagram.drawing",
                (
                    "The non-renderer Diagram drawing content differs from "
                    "the controlled template."
                ),
            )
        )
    return findings


def _audit_workbook_fidelity(
    archive: zipfile.ZipFile,
    *,
    manifest: Mapping[str, Any],
    project: RouteProject,
    diagram_image_parts: Sequence[str],
    diagram_image_records: Sequence[Mapping[str, Any]],
) -> list[DeliverableAuditFinding]:
    """Compare published workbook parts with the template and regeneration."""

    from .mop_export import (
        CALC_CHAIN_PART,
        DEFAULT_TEMPLATE_PATH,
        DIAGRAM_DRAWING_PART,
        DIAGRAM_DRAWING_RELS_PART,
        DIAGRAM_SHEET_PART,
        FBN_PART,
        IRM_PART,
        TEMPLATE_FILENAME,
        TEMPLATE_SHA256,
        WORKBOOK_PART,
        export_mop,
    )

    findings: list[DeliverableAuditFinding] = []
    expected_template_manifest = {
        "filename": TEMPLATE_FILENAME,
        "sha256": TEMPLATE_SHA256,
        "dynamic_sheets": ["FBN", "IRM", "Diagram"],
    }
    raw_template_manifest = manifest.get("template")
    if not isinstance(raw_template_manifest, Mapping):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_TEMPLATE_MANIFEST_INVALID",
                "manifest.template",
                "The controlled workbook template declaration is missing.",
            )
        )
    else:
        findings.extend(
            _compare_mapping(
                expected_template_manifest,
                raw_template_manifest,
                prefix="manifest.template",
                code="WORKBOOK_TEMPLATE_MANIFEST_INVALID",
            )
        )

    try:
        template_bytes = DEFAULT_TEMPLATE_PATH.read_bytes()
    except OSError as exc:
        return findings + [
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_TEMPLATE_UNAVAILABLE",
                "workbook.template",
                str(exc),
            )
        ]
    if hashlib.sha256(template_bytes).hexdigest() != TEMPLATE_SHA256:
        return findings + [
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_TEMPLATE_HASH_MISMATCH",
                "workbook.template",
                "The local controlled template does not match its pinned hash.",
            )
        ]

    renderer_parts = {
        FBN_PART,
        IRM_PART,
        WORKBOOK_PART,
        CALC_CHAIN_PART,
        DIAGRAM_SHEET_PART,
        DIAGRAM_DRAWING_PART,
        DIAGRAM_DRAWING_RELS_PART,
    }
    try:
        with zipfile.ZipFile(BytesIO(template_bytes)) as template:
            template_names = set(template.namelist())
            actual_names = set(archive.namelist())
            for name in sorted(template_names - renderer_parts):
                if name not in actual_names:
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "WORKBOOK_STATIC_PART_MISSING",
                            f"workbook.{name}",
                            "A controlled template part is missing.",
                        )
                    )
                elif archive.read(name) != template.read(name):
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "WORKBOOK_STATIC_PART_MISMATCH",
                            f"workbook.{name}",
                            (
                                "A verbatim controlled template part was "
                                "modified."
                            ),
                        )
                    )

            allowed_extras = set(diagram_image_parts)
            if diagram_image_parts:
                allowed_extras.add(DIAGRAM_DRAWING_RELS_PART)
            for name in sorted(actual_names - template_names - allowed_extras):
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "WORKBOOK_UNEXPECTED_PART",
                        f"workbook.{name}",
                        "The workbook contains an unapproved package part.",
                    )
                )
            for name in sorted(template_names - actual_names):
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "WORKBOOK_TEMPLATE_PART_MISSING",
                        f"workbook.{name}",
                        "The workbook is missing a controlled template part.",
                    )
                )

            if (
                DIAGRAM_DRAWING_PART in actual_names
                and DIAGRAM_DRAWING_PART in template_names
            ):
                embedding = manifest.get("diagram_embedding")
                findings.extend(
                    _diagram_drawing_contract(
                        archive.read(DIAGRAM_DRAWING_PART),
                        template.read(DIAGRAM_DRAWING_PART),
                        embedding=(
                            embedding
                            if isinstance(embedding, Mapping)
                            else None
                        ),
                        image_records=diagram_image_records,
                    )
                )
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        return findings + [
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_TEMPLATE_UNREADABLE",
                "workbook.template",
                str(exc),
            )
        ]

    diagram_source = dict(project.diagram_source)
    diagram_source.pop(WORKBOOK_DIAGRAM_MARKER_KEY, None)
    comparison_project = replace(project, diagram_source=diagram_source)
    try:
        with tempfile.TemporaryDirectory(
            prefix=".atlas-workbook-audit-"
        ) as temporary:
            expected_path = Path(temporary) / "expected.xlsx"
            export_mop(
                comparison_project,
                expected_path,
                purpose="final",
                diagram=None,
            )
            with zipfile.ZipFile(expected_path) as expected_archive:
                for name in (
                    FBN_PART,
                    IRM_PART,
                    WORKBOOK_PART,
                    CALC_CHAIN_PART,
                    DIAGRAM_SHEET_PART,
                ):
                    try:
                        actual_bytes = archive.read(name)
                        expected_bytes = expected_archive.read(name)
                    except KeyError:
                        findings.append(
                            DeliverableAuditFinding(
                                "error",
                                "WORKBOOK_DYNAMIC_PART_MISSING",
                                f"workbook.{name}",
                                "A required renderer-owned part is missing.",
                            )
                        )
                        continue
                    if actual_bytes != expected_bytes:
                        findings.append(
                            DeliverableAuditFinding(
                                "error",
                                "WORKBOOK_REGENERATION_MISMATCH",
                                f"workbook.{name}",
                                (
                                    "The published dynamic workbook part "
                                    "differs from an independent regeneration "
                                    "of the saved route."
                                ),
                            )
                        )
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        findings.append(
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_REGENERATION_FAILED",
                "workbook",
                str(exc),
            )
        )
    return findings


def _audit_workbook(
    workbook: Path,
    golden: Mapping[str, Any],
    manifest: Mapping[str, Any] | None = None,
    project: RouteProject | None = None,
) -> list[DeliverableAuditFinding]:
    expected = golden.get("workbook")
    embedding = (
        manifest.get("diagram_embedding")
        if isinstance(manifest, Mapping)
        else None
    )
    expected_embedding = golden.get("diagram_embedding")
    if (
        not isinstance(expected, Mapping)
        and not isinstance(embedding, Mapping)
        and not isinstance(expected_embedding, Mapping)
    ):
        return []
    if not isinstance(expected, Mapping):
        expected = {}
    findings: list[DeliverableAuditFinding] = []
    contract_version = expected.get("contract_version")
    if contract_version is not None:
        required_contract_fields = {
            "contract_version",
            "template_filename",
            "template_sha256",
            "rack_capacity",
            "formula_count",
            "cached_formula_count",
            "formula_signature_sha256",
            "cache_signature_sha256",
            "selected_sheet_names",
            "diagram_images",
            "required_text",
        }
        missing_contract_fields = sorted(
            required_contract_fields - set(expected)
        )
        if contract_version != "2.0" or missing_contract_fields:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "GOLDEN_WORKBOOK_CONTRACT_INCOMPLETE",
                    "workbook.contract_version",
                    (
                        "Workbook contract must be version 2.0 with every "
                        "required fidelity field; missing: "
                        + (", ".join(missing_contract_fields) or "none")
                    ),
                )
            )
        if (
            expected.get("rack_capacity") != 8
            or manifest is None
            or project is None
        ):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "GOLDEN_WORKBOOK_CONTRACT_INCOMPLETE",
                    "workbook",
                    (
                        "Workbook contract 2.0 requires rack capacity 8, "
                        "a parsed manifest, and a valid route model."
                    ),
                )
            )
        if isinstance(manifest, Mapping):
            template_record = manifest.get("template")
            expected_template = {
                "filename": expected.get("template_filename"),
                "sha256": expected.get("template_sha256"),
            }
            if isinstance(template_record, Mapping):
                findings.extend(
                    _compare_mapping(
                        expected_template,
                        template_record,
                        prefix="workbook.template",
                        code="GOLDEN_WORKBOOK_TEMPLATE_MISMATCH",
                    )
                )
            else:
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "GOLDEN_WORKBOOK_TEMPLATE_MISMATCH",
                        "workbook.template",
                        "The manifest has no controlled-template record.",
                    )
                )
    try:
        with zipfile.ZipFile(workbook) as archive:
            names = [info.filename for info in archive.infolist()]
            folded_names = [name.casefold() for name in names]
            package_issues = False
            if len(set(folded_names)) != len(folded_names):
                package_issues = True
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "WORKBOOK_DUPLICATE_PART",
                        "workbook.package",
                        (
                            "Workbook part names must be unique, including "
                            "case-insensitive collisions."
                        ),
                    )
                )
            unsafe_names = sorted(
                name for name in names if not _safe_zip_part(name)
            )
            if unsafe_names:
                package_issues = True
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "WORKBOOK_UNSAFE_PART",
                        "workbook.package",
                        (
                            "Workbook contains unsafe package part names: "
                            + ", ".join(unsafe_names[:8])
                        ),
                    )
                )
            encrypted_names = sorted(
                info.filename
                for info in archive.infolist()
                if info.flag_bits & 0x1
            )
            if encrypted_names:
                package_issues = True
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "WORKBOOK_ENCRYPTED_PART",
                        "workbook.package",
                        (
                            "Workbook package parts must not be encrypted: "
                            + ", ".join(encrypted_names[:8])
                        ),
                    )
                )
            if package_issues:
                return findings

            formula_count = 0
            cached_formula_count = 0
            worksheet_roots: dict[str, ElementTree.Element] = {}
            for name in archive.namelist():
                if not name.startswith("xl/worksheets/") or not name.endswith(
                    ".xml"
                ):
                    continue
                root = ElementTree.fromstring(archive.read(name))
                worksheet_roots[name] = root
                for cell in root.iter(
                    f"{{{_SPREADSHEET_NS}}}c"
                ):
                    formula = cell.find(f"{{{_SPREADSHEET_NS}}}f")
                    if formula is None:
                        continue
                    formula_count += 1
                    cached = cell.find(f"{{{_SPREADSHEET_NS}}}v")
                    if cached is not None and cached.text is not None:
                        cached_formula_count += 1
            workbook_root = ElementTree.fromstring(
                archive.read("xl/workbook.xml")
            )
            relationships_root = ElementTree.fromstring(
                archive.read("xl/_rels/workbook.xml.rels")
            )
            workbook_relationships: dict[str, _PackageRelationship] = {}
            for relationship in relationships_root.findall(
                f"{{{_PACKAGE_REL_NS}}}Relationship"
            ):
                relationship_id = str(relationship.get("Id", "") or "")
                target = str(relationship.get("Target", "") or "")
                relationship_type = str(
                    relationship.get("Type", "") or ""
                )
                target_mode = str(
                    relationship.get("TargetMode", "") or ""
                )
                if target_mode.casefold() == "external":
                    part = ""
                elif target.startswith("/"):
                    part = target.lstrip("/")
                else:
                    part = posixpath.normpath(
                        posixpath.join("xl", target)
                    )
                if relationship_id in workbook_relationships:
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "WORKBOOK_RELATIONSHIP_INVALID",
                            "workbook.relationships",
                            (
                                "Workbook relationship IDs must be unique; "
                                f"duplicate {relationship_id!r} was found."
                            ),
                        )
                    )
                workbook_relationships[relationship_id] = (
                    _PackageRelationship(
                        relationship_id=relationship_id,
                        relationship_type=relationship_type,
                        target=target,
                        target_mode=target_mode,
                        resolved_part=part,
                    )
                )
            sheet_parts: dict[str, str] = {}
            sheet_relationship_records: dict[
                str, _PackageRelationship | None
            ] = {}
            for sheet in workbook_root.iter(f"{{{_SPREADSHEET_NS}}}sheet"):
                relationship_id = sheet.get(
                    f"{{{_OFFICE_REL_NS}}}id", ""
                )
                relationship = workbook_relationships.get(relationship_id)
                part = (
                    relationship.resolved_part
                    if relationship is not None
                    else ""
                )
                sheet_name = str(sheet.get("name", ""))
                sheet_parts[sheet_name] = part
                sheet_relationship_records[sheet_name] = relationship

            # The controlled template intentionally contains formulas on
            # sheets that the renderer replaces (notably the static FBN
            # layout).  Only the IRM formulas are the executable calculation
            # contract that must survive byte-for-byte.  Fingerprinting every
            # worksheet would therefore make harmless FBN rendering changes
            # look like IRM calculation changes.
            irm_part = sheet_parts.get("IRM", "")
            irm_root = worksheet_roots.get(irm_part)
            formula_signature, cache_signature = _formula_fingerprints(
                {irm_part: irm_root}
                if irm_part and irm_root is not None
                else {}
            )

            selected_sheets: list[str] = []
            for sheet_name, part in sheet_parts.items():
                sheet_root = worksheet_roots.get(part)
                if sheet_root is None:
                    continue
                for view in sheet_root.iter(
                    f"{{{_SPREADSHEET_NS}}}sheetView"
                ):
                    if view.get("tabSelected") in {"1", "true"}:
                        selected_sheets.append(sheet_name)
                        break

            all_text: list[str] = []
            if "xl/sharedStrings.xml" in archive.namelist():
                strings_root = ElementTree.fromstring(
                    archive.read("xl/sharedStrings.xml")
                )
                all_text.extend(
                    text.text or ""
                    for text in strings_root.iter(
                        f"{{{_SPREADSHEET_NS}}}t"
                    )
                )
            for sheet_root in worksheet_roots.values():
                all_text.extend(
                    text.text or ""
                    for text in sheet_root.iter(f"{{{_SPREADSHEET_NS}}}t")
                )
            searchable_text = "\n".join(all_text)

            diagram_image_records: list[dict[str, Any]] = []
            diagram_sheet_part = sheet_parts.get("Diagram", "")
            diagram_sheet_root = worksheet_roots.get(diagram_sheet_part)
            diagram_relationship = sheet_relationship_records.get("Diagram")
            if diagram_sheet_part and (
                diagram_relationship is None
                or not _is_internal_relationship(
                    diagram_relationship,
                    _WORKSHEET_REL_TYPE,
                )
                or not _safe_zip_part(diagram_sheet_part)
                or not diagram_sheet_part.startswith("xl/worksheets/")
                or diagram_sheet_part not in archive.namelist()
            ):
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "WORKBOOK_DIAGRAM_RELATIONSHIP_INVALID",
                        "workbook.Diagram",
                        (
                            "The Diagram sheet must use an internal worksheet "
                            "relationship."
                        ),
                    )
                )
            diagram_image_parts, relationship_findings = (
                _diagram_linked_image_parts(
                    archive,
                    diagram_sheet_part,
                    diagram_sheet_root,
                )
                if diagram_sheet_part and diagram_sheet_root is not None
                else ((), [])
            )
            findings.extend(relationship_findings)
            for order, name in enumerate(diagram_image_parts, start=1):
                try:
                    image_bytes = archive.read(name)
                    with Image.open(BytesIO(image_bytes)) as image:
                        image.load()
                        diagram_image_records.append(
                            {
                                "order": order,
                                "normalized_sha256": hashlib.sha256(
                                    image_bytes
                                ).hexdigest(),
                                "width": int(image.width),
                                "height": int(image.height),
                            }
                        )
                except (OSError, ValueError):
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "WORKBOOK_DIAGRAM_IMAGE_INVALID",
                            f"workbook.diagram_images[{order}]",
                            f"Diagram-linked image {name!r} is unreadable.",
                        )
                    )
            if isinstance(manifest, Mapping) and isinstance(project, RouteProject):
                findings.extend(
                    _audit_workbook_fidelity(
                        archive,
                        manifest=manifest,
                        project=project,
                        diagram_image_parts=diagram_image_parts,
                        diagram_image_records=diagram_image_records,
                    )
                )
    except (
        KeyError,
        OSError,
        zipfile.BadZipFile,
        ElementTree.ParseError,
    ) as exc:
        return [
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_UNREADABLE",
                "workbook",
                str(exc),
            )
        ]

    for key, actual in (
        ("formula_count", formula_count),
        ("cached_formula_count", cached_formula_count),
        ("formula_signature_sha256", formula_signature),
        ("cache_signature_sha256", cache_signature),
    ):
        if key in expected and not _values_equal(expected[key], actual):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_FORMULA_MISMATCH",
                    f"workbook.{key}",
                    f"Expected {expected[key]!r}; found {actual!r}.",
                )
            )

    expected_selected = expected.get("selected_sheet_names")
    if (
        isinstance(expected_selected, Sequence)
        and not isinstance(expected_selected, (str, bytes))
        and list(expected_selected) != selected_sheets
    ):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "WORKBOOK_SELECTION_MISMATCH",
                "workbook.selected_sheet_names",
                (
                    f"Expected {list(expected_selected)!r}; "
                    f"found {selected_sheets!r}."
                ),
            )
        )

    diagram_image_dimensions = [
        (record["width"], record["height"])
        for record in diagram_image_records
    ]
    expected_dimensions = expected.get("diagram_image_dimensions")
    if (
        isinstance(expected_dimensions, Sequence)
        and len(expected_dimensions) == 2
    ):
        target_dimensions = (
            int(expected_dimensions[0]),
            int(expected_dimensions[1]),
        )
        if target_dimensions not in diagram_image_dimensions:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_RESOLUTION_MISMATCH",
                    "workbook.diagram_image_dimensions",
                    (
                        f"Expected an embedded {target_dimensions[0]}x"
                        f"{target_dimensions[1]} Diagram-linked image; found "
                        f"{diagram_image_dimensions!r}."
                    ),
                )
            )

    expected_images = expected.get("diagram_images")
    if (
        isinstance(expected_images, Sequence)
        and not isinstance(expected_images, (str, bytes))
    ):
        if len(expected_images) != len(diagram_image_records):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "WORKBOOK_DIAGRAM_IMAGE_SET_MISMATCH",
                    "workbook.diagram_images",
                    (
                        f"Expected {len(expected_images)} ordered image "
                        f"occurrence(s); found {len(diagram_image_records)}."
                    ),
                )
            )
        for index, expected_image in enumerate(expected_images):
            if (
                not isinstance(expected_image, Mapping)
                or index >= len(diagram_image_records)
            ):
                continue
            findings.extend(
                _compare_mapping(
                    expected_image,
                    diagram_image_records[index],
                    prefix=f"workbook.diagram_images[{index + 1}]",
                    code="WORKBOOK_DIAGRAM_IMAGE_MISMATCH",
                )
            )

    if isinstance(embedding, Mapping):
        findings.extend(
            _audit_diagram_embedding(
                embedding,
                diagram_image_records,
            )
        )
    if isinstance(expected_embedding, Mapping):
        if not isinstance(embedding, Mapping):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "GOLDEN_DIAGRAM_EMBEDDING_MISMATCH",
                    "diagram_embedding",
                    "The bundle manifest has no diagram_embedding object.",
                )
            )
        else:
            findings.extend(
                _compare_mapping(
                    expected_embedding,
                    embedding,
                    prefix="diagram_embedding",
                    code="GOLDEN_DIAGRAM_EMBEDDING_MISMATCH",
                )
            )

    expected_labels = expected.get("required_text")
    if (
        isinstance(expected_labels, Sequence)
        and not isinstance(expected_labels, (str, bytes))
    ):
        for label in expected_labels:
            if isinstance(label, str) and label not in searchable_text:
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "WORKBOOK_REQUIRED_TEXT_MISSING",
                        "workbook.required_text",
                        f"Required workbook text {label!r} was not found.",
                    )
                )
    return findings


def _audit_manifest_contract(
    manifest: Mapping[str, Any],
    *,
    cli_file_count: int,
    discovered_artifacts: Mapping[str, Path | None],
) -> list[DeliverableAuditFinding]:
    """Validate completeness and the non-deployment candidate boundary."""

    findings: list[DeliverableAuditFinding] = []
    if manifest.get("schema") != "atlas.ciena.rls.route-deliverable-bundle":
        findings.append(
            DeliverableAuditFinding(
                "error",
                "MANIFEST_SCHEMA_INVALID",
                "manifest.schema",
                "The route-bundle manifest schema is missing or unsupported.",
            )
        )
    if manifest.get("schema_version") != "2.2":
        findings.append(
            DeliverableAuditFinding(
                "error",
                "MANIFEST_SCHEMA_INVALID",
                "manifest.schema_version",
                "The route-bundle manifest must use schema version 2.2.",
            )
        )
    required_states = {
        "configuration_candidates_complete": True,
        "cli_candidate_files_included": True,
        "candidate_cli_commit_commands_emitted": False,
        "deployment_approved": False,
        "deployable_cli_included": False,
        "secret_material_included": False,
    }
    for field, expected in required_states.items():
        actual = manifest.get(field)
        if actual is not expected:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "MANIFEST_SAFETY_STATE_INVALID",
                    f"manifest.{field}",
                    f"Expected {expected!r}; found {actual!r}.",
                )
            )

    artifacts = manifest.get("artifacts")
    required_top_keys = {"project", "mop", "validation", "configs"}
    if (
        not isinstance(artifacts, Mapping)
        or set(artifacts) != required_top_keys
    ):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "TOP_ARTIFACT_SET_INCOMPLETE",
                "manifest.artifacts",
                (
                    "Top-level artifacts must list project, mop, validation, "
                    "and configs exactly once."
                ),
            )
        )
    top_paths: set[str] = set()
    if isinstance(artifacts, Mapping):
        expected_suffixes = {
            "project": "_route_project.json",
            "mop": "_FBN_MOP.xlsx",
            "validation": "_validation.txt",
        }
        for role, expected_suffix in expected_suffixes.items():
            record = artifacts.get(role)
            field = f"manifest.artifacts.{role}"
            if not isinstance(record, Mapping):
                continue
            filename = record.get("filename")
            digest = record.get("sha256")
            if not _safe_leaf_name(filename):
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "TOP_ARTIFACT_FILENAME_UNSAFE",
                        f"{field}.filename",
                        "Artifact filename must be a nonempty safe leaf name.",
                    )
                )
            else:
                key = str(filename).casefold()
                if key in top_paths:
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "MANIFEST_PATH_COLLISION",
                            f"{field}.filename",
                            "Artifact paths must be unique.",
                        )
                    )
                top_paths.add(key)
                discovered = discovered_artifacts.get(role)
                if (
                    not str(filename).endswith(expected_suffix)
                    or discovered is None
                    or str(filename) != discovered.name
                ):
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "TOP_ARTIFACT_BINDING_INVALID",
                            f"{field}.filename",
                            (
                                f"The {role} artifact must end in "
                                f"{expected_suffix!r} and name the uniquely "
                                "discovered top-level artifact; found "
                                f"{filename!r}."
                            ),
                        )
                    )
            if not isinstance(digest, str) or not _SHA256_RE.fullmatch(
                digest
            ):
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "MANIFEST_HASH_INVALID",
                        f"{field}.sha256",
                        "Artifact hash must be a 64-hex SHA-256 digest.",
                    )
                )
        configs = artifacts.get("configs")
        if not isinstance(configs, Mapping):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CONFIGS_ARTIFACT_INVALID",
                    "manifest.artifacts.configs",
                    "The configs directory record is missing.",
                )
            )
        else:
            configs_directory = configs.get("directory")
            if configs_directory != "configs":
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "CONFIGS_ARTIFACT_INVALID",
                        "manifest.artifacts.configs.directory",
                        (
                            "The configs directory must exactly match the "
                            "exporter contract 'configs'."
                        ),
                    )
                )
            count = configs.get("shelf_artifact_count")
            if (
                isinstance(manifest.get("configuration_candidate_count"), int)
                and count != manifest.get("configuration_candidate_count")
            ):
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "CONFIGS_ARTIFACT_INVALID",
                        "manifest.artifacts.configs.shelf_artifact_count",
                        "Configs artifact count does not match candidates.",
                    )
                )

    candidates = manifest.get("configuration_candidates")
    candidate_records = (
        list(candidates)
        if isinstance(candidates, Sequence)
        and not isinstance(candidates, (str, bytes))
        else []
    )
    required_candidate_file_keys = {
        "cli",
        "annotated",
        "validation",
        "manifest",
    }
    seen_directories: set[str] = set()
    seen_paths = set(top_paths)
    seen_orders: set[int] = set()
    seen_shelf_ids: set[str] = set()
    for index, candidate in enumerate(candidate_records, start=1):
        field = f"manifest.configuration_candidates[{index}]"
        if not isinstance(candidate, Mapping):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CANDIDATE_RECORD_INVALID",
                    field,
                    "Candidate record must be a JSON object.",
                )
            )
            continue
        order = candidate.get("order")
        if (
            isinstance(order, bool)
            or not isinstance(order, int)
            or order < 1
            or order in seen_orders
        ):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CANDIDATE_RECORD_INVALID",
                    f"{field}.order",
                    "Candidate order must be a unique positive integer.",
                )
            )
        else:
            seen_orders.add(order)
        shelf_id = candidate.get("shelf_id")
        if (
            not isinstance(shelf_id, str)
            or not shelf_id.strip()
            or shelf_id.casefold() in seen_shelf_ids
        ):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CANDIDATE_RECORD_INVALID",
                    f"{field}.shelf_id",
                    "Candidate shelf_id must be nonempty and unique.",
                )
            )
        else:
            seen_shelf_ids.add(shelf_id.casefold())
        directory = candidate.get("directory")
        if not _safe_leaf_name(directory):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CANDIDATE_DIRECTORY_UNSAFE",
                    f"{field}.directory",
                    "Candidate directory must be a nonempty safe leaf name.",
                )
            )
            directory_key = ""
        else:
            directory_key = str(directory).casefold()
            if directory_key in seen_directories:
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "CANDIDATE_DIRECTORY_COLLISION",
                        f"{field}.directory",
                        "Candidate directories must be unique.",
                    )
                )
            seen_directories.add(directory_key)
        files = candidate.get("files")
        if (
            not isinstance(files, Mapping)
            or set(files) != required_candidate_file_keys
        ):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CANDIDATE_FILE_SET_INCOMPLETE",
                    f"{field}.files",
                    (
                        "Each shelf candidate must list cli, annotated, "
                        "validation, and manifest artifacts exactly once."
                    ),
                )
            )
        if isinstance(files, Mapping):
            seen_leaf_names: set[str] = set()
            for role, record in files.items():
                record_field = f"{field}.files.{role}"
                if not isinstance(record, Mapping):
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "CANDIDATE_FILE_RECORD_INVALID",
                            record_field,
                            "Candidate file record must be a JSON object.",
                        )
                    )
                    continue
                filename = record.get("filename")
                digest = record.get("sha256")
                if not _safe_leaf_name(filename):
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "CANDIDATE_FILENAME_UNSAFE",
                            f"{record_field}.filename",
                            (
                                "Candidate filename must be a nonempty safe "
                                "leaf name."
                            ),
                        )
                    )
                else:
                    filename_key = str(filename).casefold()
                    if filename_key in seen_leaf_names:
                        findings.append(
                            DeliverableAuditFinding(
                                "error",
                                "CANDIDATE_FILENAME_COLLISION",
                                f"{record_field}.filename",
                                "Candidate filenames must be unique.",
                            )
                        )
                    seen_leaf_names.add(filename_key)
                    path_key = (
                        f"configs/{directory_key}/{filename_key}"
                    )
                    if path_key in seen_paths:
                        findings.append(
                            DeliverableAuditFinding(
                                "error",
                                "MANIFEST_PATH_COLLISION",
                                f"{record_field}.filename",
                                "Manifest artifact paths must be unique.",
                            )
                        )
                    seen_paths.add(path_key)
                if (
                    not isinstance(digest, str)
                    or not _SHA256_RE.fullmatch(digest)
                ):
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "MANIFEST_HASH_INVALID",
                            f"{record_field}.sha256",
                            "Artifact hash must be a 64-hex SHA-256 digest.",
                        )
                    )
        cli_record = (
            files.get("cli") if isinstance(files, Mapping) else None
        )
        cli_name = (
            str(cli_record.get("filename", "") or "")
            if isinstance(cli_record, Mapping)
            else ""
        )
        if not cli_name.endswith("_candidate.cli"):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CANDIDATE_FILENAME_UNSAFE",
                    f"{field}.files.cli.filename",
                    "Raw candidate filename must end in _candidate.cli.",
                )
            )
        if candidate.get("candidate_safety_mode") != "validate_without_commit":
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CANDIDATE_SAFETY_STATE_INVALID",
                    f"{field}.candidate_safety_mode",
                    "Candidate must use validate_without_commit safety mode.",
                )
            )
        if candidate.get("deployment_approved") is not False:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CANDIDATE_SAFETY_STATE_INVALID",
                    f"{field}.deployment_approved",
                    "Candidate deployment approval must remain false.",
                )
            )
        for candidate_field, expected in {
            "commit_commands_emitted": False,
            "commit_command_count": 0,
            "artifact_kind": "pre_calibration_candidate",
        }.items():
            if candidate.get(candidate_field) != expected:
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "CANDIDATE_SAFETY_STATE_INVALID",
                        f"{field}.{candidate_field}",
                        f"Expected {expected!r}.",
                    )
                )
    declared_count = manifest.get("configuration_candidate_count")
    shelf_count = manifest.get("shelf_count")
    count_values = {
        "manifest.configuration_candidate_count": declared_count,
        "manifest.configuration_candidates": len(candidate_records),
        "configs/**/*.cli": cli_file_count,
    }
    if isinstance(shelf_count, int) and not isinstance(shelf_count, bool):
        count_values["manifest.shelf_count"] = shelf_count
    valid_counts = [
        value
        for value in count_values.values()
        if isinstance(value, int) and not isinstance(value, bool)
    ]
    if (
        len(valid_counts) != len(count_values)
        or not valid_counts
        or len(set(valid_counts)) != 1
        or valid_counts[0] < 1
    ):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "CANDIDATE_SET_INCOMPLETE",
                "manifest.configuration_candidates",
                "Candidate/shelf/CLI counts disagree: "
                + ", ".join(
                    f"{field}={value!r}"
                    for field, value in count_values.items()
                ),
            )
        )
    if seen_orders and seen_orders != set(
        range(1, len(candidate_records) + 1)
    ):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "CANDIDATE_ORDER_INVALID",
                "manifest.configuration_candidates",
                "Candidate orders must be contiguous and start at one.",
            )
        )

    summary = manifest.get("configuration_candidate_validation")
    if not isinstance(summary, Mapping):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "CANDIDATE_SAFETY_SUMMARY_MISSING",
                "manifest.configuration_candidate_validation",
                "The route candidate safety summary is absent.",
            )
        )
    else:
        expected_summary = {
            "candidate_generation_ready": True,
            "candidate_safety_mode": "validate_without_commit",
            "deployment_approved": False,
            "on_box_validate_required": True,
            "commit_command_count": 0,
        }
        for field, expected in expected_summary.items():
            actual = summary.get(field)
            if actual != expected:
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "CANDIDATE_SAFETY_SUMMARY_INVALID",
                        (
                            "manifest.configuration_candidate_validation."
                            f"{field}"
                        ),
                        f"Expected {expected!r}; found {actual!r}.",
                    )
                )

    readiness = manifest.get("deployment_readiness")
    if not isinstance(readiness, Mapping):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "DEPLOYMENT_READINESS_MISSING",
                "manifest.deployment_readiness",
                "Deployment readiness state is absent.",
            )
        )
    else:
        for field in (
            "route_cli_ready",
            "deployable_cli_ready",
            "deployment_approved",
        ):
            if readiness.get(field) is not False:
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "DEPLOYMENT_STATE_UNSAFE",
                        f"manifest.deployment_readiness.{field}",
                        "Pre-calibration bundles must fail deployment closed.",
                    )
                )
    if manifest.get("deployment_approval_state") != "not_approved":
        findings.append(
            DeliverableAuditFinding(
                "error",
                "DEPLOYMENT_STATE_UNSAFE",
                "manifest.deployment_approval_state",
                "Pre-calibration bundles must remain not_approved.",
            )
        )
    return findings


def _nonempty_secret_claims(
    value: object,
    *,
    prefix: str,
) -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}"
            normalized = key_text.casefold().replace("-", "_")
            if any(fragment in normalized for fragment in _SECRET_KEY_FRAGMENTS):
                if child not in (None, "", False, [], {}, ()):
                    found.append(path)
            found.extend(_nonempty_secret_claims(child, prefix=path))
    elif (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes))
    ):
        for index, child in enumerate(value, start=1):
            found.extend(
                _nonempty_secret_claims(
                    child,
                    prefix=f"{prefix}[{index}]",
                )
            )
    return found


def _audit_child_manifest(
    child: Mapping[str, Any],
    *,
    field: str,
) -> list[DeliverableAuditFinding]:
    findings: list[DeliverableAuditFinding] = []
    expected = {
        "schema": "atlas.ciena.rls.config-artifact",
        "schema_version": "2.1",
        "generator": "R40ExactConfigGenerator",
        "artifact_kind": "pre_calibration_candidate",
        "candidate_generation_ready": True,
        "candidate_safety_mode": "validate_without_commit",
        "commit_commands_emitted": False,
        "commit_command_count": 0,
        "deployment_approval_state": "not_approved",
        "deployment_approved": False,
        "deployable_cli": False,
        "on_box_validate_required": True,
        "contains_credentials": False,
        "contains_license_secrets": False,
        "ntp_commands_emitted": False,
    }
    for key, expected_value in expected.items():
        actual = child.get(key)
        if actual != expected_value:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CHILD_MANIFEST_SAFETY_INVALID",
                    f"{field}.{key}",
                    f"Expected {expected_value!r}; found {actual!r}.",
                )
            )
    timestamp = child.get("generated_at_utc")
    try:
        parsed = datetime.fromisoformat(str(timestamp))
        if parsed.tzinfo is None:
            raise ValueError("timezone is absent")
    except (TypeError, ValueError):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "CHILD_MANIFEST_TIMESTAMP_INVALID",
                f"{field}.generated_at_utc",
                "Generated timestamp must be a timezone-aware ISO value.",
            )
        )
    for secret_path in _nonempty_secret_claims(child, prefix=field):
        findings.append(
            DeliverableAuditFinding(
                "error",
                "CHILD_MANIFEST_SECRET_CLAIM",
                secret_path,
                "Candidate manifest contains a nonempty secret-bearing claim.",
            )
        )
    return findings


def _read_utf8_bytes(
    path: Path,
    *,
    field: str,
) -> tuple[bytes | None, list[DeliverableAuditFinding]]:
    try:
        data = path.read_bytes()
        data.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        return None, [
            DeliverableAuditFinding(
                "error",
                "CANDIDATE_FILE_UNREADABLE",
                field,
                str(exc),
            )
        ]
    return data, []


def _audit_route_validation_secrets(
    path: Path,
) -> list[DeliverableAuditFinding]:
    """Reject nonempty secret assignments in the route validation artifact."""

    data, findings = _read_utf8_bytes(
        path,
        field=path.name,
    )
    if data is None:
        return findings
    text = data.decode("utf-8")
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        match = _SECRET_TEXT_ASSIGNMENT_RE.search(raw_line.strip())
        if match is None:
            continue
        value = match.group("value").strip().casefold()
        if value in _EMPTY_SECRET_TEXT_VALUES:
            continue
        findings.append(
            DeliverableAuditFinding(
                "error",
                "ROUTE_VALIDATION_SECRET_CLAIM",
                f"{path.name}:{line_number}",
                (
                    "The route validation artifact contains a nonempty "
                    "secret-bearing assignment."
                ),
            )
        )
    return findings


def _audit_regenerated_route_validation(
    path: Path | None,
    *,
    project: RouteProject,
    validation_issues: Sequence[Any],
    readiness: Any,
    build: RouteConfigBuild,
) -> list[DeliverableAuditFinding]:
    """Byte-compare the published route report with deterministic rendering."""

    if path is None:
        return []
    actual, findings = _read_utf8_bytes(
        path,
        field=path.name,
    )
    if actual is None:
        return findings
    expected = _validation_text(
        project,
        tuple(validation_issues),
        readiness,
        build,
    ).encode("utf-8")
    if actual != expected:
        findings.append(
            DeliverableAuditFinding(
                "error",
                "ROUTE_VALIDATION_REGENERATION_MISMATCH",
                path.name,
                (
                    "Published route validation bytes do not match a fresh "
                    "deterministic rendering from the saved route project."
                ),
            )
        )
    return findings


def _expected_candidate_bytes(
    build: RouteConfigBuild,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for shelf_build in build.shelf_builds:
        artifact = shelf_build.artifact
        result.append(
            {
                "order": shelf_build.order,
                "shelf_id": shelf_build.shelf_id,
                "profile_id": shelf_build.profile_id,
                "tid": shelf_build.tid,
                "cli": (str(artifact.cli_text).rstrip() + "\n").encode(
                    "utf-8"
                ),
                "annotated": (
                    str(artifact.annotated_text).rstrip() + "\n"
                ).encode("utf-8"),
                "validation": (
                    str(artifact.validation_report).rstrip() + "\n"
                ).encode("utf-8"),
                "manifest": dict(artifact.manifest),
            }
        )
    return result


def _audit_regenerated_candidates(
    root: Path,
    files: Mapping[str, Path],
    manifest: Mapping[str, Any],
    build: RouteConfigBuild,
) -> list[DeliverableAuditFinding]:
    """Compare saved candidate bytes with a fresh deterministic generation."""

    findings: list[DeliverableAuditFinding] = []
    raw_candidates = manifest.get("configuration_candidates")
    candidates = (
        list(raw_candidates)
        if isinstance(raw_candidates, Sequence)
        and not isinstance(raw_candidates, (str, bytes))
        else []
    )
    expected_candidates = _expected_candidate_bytes(build)
    if len(candidates) != len(expected_candidates):
        return [
            DeliverableAuditFinding(
                "error",
                "CANDIDATE_REGENERATION_COUNT_MISMATCH",
                "manifest.configuration_candidates",
                (
                    f"Regeneration produced {len(expected_candidates)} "
                    f"candidate(s); manifest lists {len(candidates)}."
                ),
            )
        ]
    for index, expected in enumerate(expected_candidates):
        record = candidates[index]
        field = f"manifest.configuration_candidates[{index + 1}]"
        if not isinstance(record, Mapping):
            continue
        for identity_field in (
            "order",
            "shelf_id",
            "profile_id",
            "tid",
        ):
            if record.get(identity_field) != expected[identity_field]:
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "CANDIDATE_IDENTITY_MISMATCH",
                        f"{field}.{identity_field}",
                        (
                            f"Expected {expected[identity_field]!r}; found "
                            f"{record.get(identity_field)!r}."
                        ),
                    )
                )
        directory = record.get("directory")
        file_records = record.get("files")
        if (
            not _safe_leaf_name(directory)
            or not isinstance(file_records, Mapping)
        ):
            continue
        actual_child_manifest: Mapping[str, Any] | None = None
        actual_child_bytes: bytes | None = None
        for role in ("cli", "annotated", "validation", "manifest"):
            file_record = file_records.get(role)
            if not isinstance(file_record, Mapping):
                continue
            filename = file_record.get("filename")
            if not _safe_leaf_name(filename):
                continue
            relative = (
                f"configs/{directory}/{filename}"
            )
            path = files.get(relative.casefold())
            if path is None:
                continue
            actual, read_findings = _read_utf8_bytes(
                path,
                field=relative,
            )
            findings.extend(read_findings)
            if actual is None:
                continue
            if role == "manifest":
                actual_child_bytes = actual
                try:
                    value = json.loads(actual.decode("utf-8"))
                    if not isinstance(value, Mapping):
                        raise ValueError(
                            "candidate manifest root is not an object"
                        )
                    actual_child_manifest = value
                except (json.JSONDecodeError, ValueError) as exc:
                    findings.append(
                        DeliverableAuditFinding(
                            "error",
                            "CHILD_MANIFEST_JSON_INVALID",
                            relative,
                            str(exc),
                        )
                    )
                continue
            expected_bytes = expected[role]
            if actual != expected_bytes:
                findings.append(
                    DeliverableAuditFinding(
                        "error",
                        "CANDIDATE_REGENERATION_MISMATCH",
                        relative,
                        (
                            "Published candidate bytes do not match a fresh "
                            f"generation from saved exact payload ({role})."
                        ),
                    )
                )
        if actual_child_manifest is None or actual_child_bytes is None:
            continue
        expected_manifest = dict(expected["manifest"])
        # The generator timestamp is the only nondeterministic child field.
        # Substitute the published value and then compare canonical bytes so
        # whitespace, ordering, and every other field remain exact.
        expected_manifest["generated_at_utc"] = actual_child_manifest.get(
            "generated_at_utc"
        )
        expected_manifest_bytes = (
            json.dumps(
                expected_manifest,
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        if actual_child_bytes != expected_manifest_bytes:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CANDIDATE_REGENERATION_MISMATCH",
                    f"{field}.files.manifest",
                    (
                        "Published child manifest differs from regenerated "
                        "content after timestamp normalization."
                    ),
                )
            )
    return findings


def _audit_published_child_manifests(
    files: Mapping[str, Path],
    manifest: Mapping[str, Any],
) -> list[DeliverableAuditFinding]:
    findings: list[DeliverableAuditFinding] = []
    raw_candidates = manifest.get("configuration_candidates")
    candidates = (
        raw_candidates
        if isinstance(raw_candidates, Sequence)
        and not isinstance(raw_candidates, (str, bytes))
        else ()
    )
    for index, candidate in enumerate(candidates, start=1):
        if not isinstance(candidate, Mapping):
            continue
        directory = candidate.get("directory")
        file_records = candidate.get("files")
        manifest_record = (
            file_records.get("manifest")
            if isinstance(file_records, Mapping)
            else None
        )
        filename = (
            manifest_record.get("filename")
            if isinstance(manifest_record, Mapping)
            else None
        )
        if not _safe_leaf_name(directory) or not _safe_leaf_name(filename):
            continue
        relative = f"configs/{directory}/{filename}"
        path = files.get(relative.casefold())
        if path is None:
            continue
        try:
            child = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(child, Mapping):
                raise ValueError("candidate manifest root is not an object")
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "CHILD_MANIFEST_JSON_INVALID",
                    relative,
                    str(exc),
                )
            )
            continue
        findings.extend(
            _audit_child_manifest(
                child,
                field=(
                    "manifest.configuration_candidates"
                    f"[{index}].child_manifest"
                ),
            )
        )
    return findings


def _audit_project_and_regenerate(
    raw_project: Mapping[str, Any],
    *,
    root: Path,
    files: Mapping[str, Path],
    manifest: Mapping[str, Any],
    validation_path: Path | None,
) -> tuple[
    RouteProject | None,
    RouteConfigBuild | None,
    list[DeliverableAuditFinding],
]:
    findings: list[DeliverableAuditFinding] = []
    try:
        project = RouteProject.from_dict(raw_project)
    except (RouteProjectFormatError, TypeError, ValueError) as exc:
        return None, None, [
            DeliverableAuditFinding(
                "error",
                "PROJECT_MODEL_INVALID",
                "project",
                str(exc),
            )
        ]
    if raw_project != project.to_dict():
        findings.append(
            DeliverableAuditFinding(
                "error",
                "PROJECT_NONCANONICAL",
                "project",
                (
                    "Saved route JSON is not the current canonical RouteProject "
                    "representation."
                ),
            )
        )
    manifest_project_values = {
        "route_project_schema_version": project.schema_version,
        "project_id": project.project_id,
        "route_code": project.route_code,
        "title": project.title,
        "revision": project.revision,
        "ospf_area": project.ospf_area,
        "shelf_count": len(project.shelves),
        "link_count": len(project.links),
    }
    for key, expected in manifest_project_values.items():
        if manifest.get(key) != expected:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "MANIFEST_PROJECT_MISMATCH",
                    f"manifest.{key}",
                    f"Expected {expected!r}; found {manifest.get(key)!r}.",
                )
            )
    for index, shelf in enumerate(project.shelves, start=1):
        if shelf.profile_payload.get("schema_version") != (
            R40_PAYLOAD_SCHEMA_VERSION
        ):
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "PROJECT_EXACT_PAYLOAD_NOT_CURRENT",
                    f"project.shelves[{index}].profile_payload.schema_version",
                    (
                        "Published exact provider payload must use current "
                        f"schema {R40_PAYLOAD_SCHEMA_VERSION}."
                    ),
                )
            )
    validation_issues = project.validate()
    errors = [issue for issue in validation_issues if issue.is_error]
    for issue in errors:
        findings.append(
            DeliverableAuditFinding(
                "error",
                "PROJECT_VALIDATION_FAILED",
                f"project.{issue.field}",
                f"[{issue.code}] {issue.message}",
            )
        )
    readiness = project.deployment_readiness()
    if not readiness.ready:
        findings.append(
            DeliverableAuditFinding(
                "error",
                "PROJECT_CANDIDATE_READINESS_FAILED",
                "project.deployment_readiness",
                "; ".join(readiness.blocking_reasons),
            )
        )
    if errors or not readiness.ready:
        return project, None, findings
    try:
        build = require_complete_route_configs(project)
    except (RouteConfigError, TypeError, ValueError) as exc:
        findings.append(
            DeliverableAuditFinding(
                "error",
                "PROJECT_REGENERATION_FAILED",
                "project.configuration_candidates",
                str(exc),
            )
        )
        return project, None, findings
    findings.extend(
        _audit_regenerated_candidates(
            root,
            files,
            manifest,
            build,
        )
    )
    findings.extend(
        _audit_regenerated_route_validation(
            validation_path,
            project=project,
            validation_issues=validation_issues,
            readiness=readiness,
            build=build,
        )
    )
    return project, build, findings


def _audit_unlisted_bundle_files(
    root: Path,
    manifest_path: Path,
    manifest: Mapping[str, Any],
    files: Mapping[str, Path],
) -> list[DeliverableAuditFinding]:
    listed = {
        Path(relative).as_posix().casefold()
        for relative, _digest in _manifest_file_records(manifest)
    }
    listed.add(manifest_path.relative_to(root).as_posix().casefold())
    findings: list[DeliverableAuditFinding] = []
    for path in sorted(
        files.values(),
        key=lambda item: item.relative_to(root).as_posix().casefold(),
    ):
        relative = path.relative_to(root).as_posix()
        if relative.casefold() not in listed:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "UNLISTED_BUNDLE_FILE",
                    relative,
                    "Published file is not covered by the route manifest.",
                )
            )
    return findings


def audit_route_deliverable(
    bundle: str | Path,
    golden: Mapping[str, Any],
) -> DeliverableAuditReport:
    """Audit one already-published route bundle directory."""

    root = Path(bundle)
    files, _directories, preflight_findings = _discover_bundle_files(root)
    if preflight_findings:
        return DeliverableAuditReport(
            bundle=str(root),
            findings=tuple(preflight_findings),
        )
    findings: list[DeliverableAuditFinding] = []
    manifest_path, discovery_findings = _single_top_level_file(
        files,
        "_route_manifest.json",
        label="manifest",
    )
    findings.extend(discovery_findings)
    project_path, discovery_findings = _single_top_level_file(
        files,
        "_route_project.json",
        label="project",
    )
    findings.extend(discovery_findings)
    workbook_path, discovery_findings = _single_top_level_file(
        files,
        "_FBN_MOP.xlsx",
        label="workbook",
    )
    findings.extend(discovery_findings)
    validation_path, discovery_findings = _single_top_level_file(
        files,
        "_validation.txt",
        label="validation",
    )
    findings.extend(discovery_findings)
    # ``None`` means the artifact was missing or could not be parsed.  An
    # empty JSON object is still a successfully parsed artifact and must flow
    # through every contract/model check so malformed but self-consistently
    # rehashed bundles cannot bypass the audit via mapping truthiness.
    manifest: Mapping[str, Any] | None = None
    project: Mapping[str, Any] | None = None
    if manifest_path is not None:
        try:
            raw_manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
            if not isinstance(raw_manifest, Mapping):
                raise ValueError("route manifest root is not a JSON object")
            manifest = raw_manifest
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "MANIFEST_JSON_INVALID",
                    "manifest",
                    str(exc),
                )
            )
    if project_path is not None:
        try:
            raw_project = json.loads(
                project_path.read_text(encoding="utf-8")
            )
            if not isinstance(raw_project, Mapping):
                raise ValueError("route project root is not a JSON object")
            project = raw_project
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            findings.append(
                DeliverableAuditFinding(
                    "error",
                    "PROJECT_JSON_INVALID",
                    "project",
                    str(exc),
                )
            )

    checked_shelves = 0
    checked_spans = 0
    if project is not None:
        project_findings, checked_shelves, checked_spans = (
            compare_project_to_golden(project, golden)
        )
        findings.extend(project_findings)

    checked_hashes = 0
    if manifest is not None:
        hash_findings, checked_hashes = _audit_manifest_hashes(
            root,
            manifest,
            files,
        )
        findings.extend(hash_findings)
        if manifest_path is not None:
            findings.extend(
                _audit_unlisted_bundle_files(
                    root,
                    manifest_path,
                    manifest,
                    files,
                )
            )

    cli_findings, checked_cli_files = _audit_candidate_cli(root, files)
    findings.extend(cli_findings)
    if validation_path is not None:
        findings.extend(_audit_route_validation_secrets(validation_path))
    if manifest is not None:
        findings.extend(
            _audit_manifest_contract(
                manifest,
                cli_file_count=checked_cli_files,
                discovered_artifacts={
                    "project": project_path,
                    "mop": workbook_path,
                    "validation": validation_path,
                },
            )
        )
        findings.extend(
            _audit_published_child_manifests(files, manifest)
        )
    project_model: RouteProject | None = None
    if project is not None and manifest is not None:
        project_model, _build, project_audit_findings = (
            _audit_project_and_regenerate(
                project,
                root=root,
                files=files,
                manifest=manifest,
                validation_path=validation_path,
            )
        )
        findings.extend(project_audit_findings)

    if workbook_path is not None:
        findings.extend(
            _audit_workbook(
                workbook_path,
                golden,
                manifest,
                project_model,
            )
        )

    return DeliverableAuditReport(
        bundle=str(root),
        findings=tuple(findings),
        checked_shelves=checked_shelves,
        checked_spans=checked_spans,
        checked_hashes=checked_hashes,
        checked_cli_files=checked_cli_files,
    )


def load_golden_fixture(path: str | Path) -> Mapping[str, Any]:
    """Load and minimally validate a golden route fixture."""

    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("Golden fixture root must be a JSON object.")
    if value.get("schema") != "atlas.ciena.rls.route-golden":
        raise ValueError("Unsupported or missing golden fixture schema.")
    return value
