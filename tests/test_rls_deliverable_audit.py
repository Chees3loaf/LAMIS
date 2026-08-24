"""Independent golden-route and candidate-safety audit contracts."""

from __future__ import annotations

import json
import hashlib
import copy
from io import BytesIO
import os
from pathlib import Path
import zipfile
from xml.etree import ElementTree

import pytest
from PIL import Image

import utils.rls_config.route_bundle as bundle_module
from tests.test_rls_r4_0_route_integration import _two_shelf_exact_project
from utils.rls_config.common import ManagementInterface
from utils.rls_config.deliverable_audit import (
    _audit_workbook,
    _executable_commit_lines,
    _formula_fingerprints,
    audit_route_deliverable,
    compare_project_to_golden,
    load_golden_fixture,
)
from utils.rls_config.r4_0_generator import (
    R40_PROVIDER_CATALOG,
    R40ExactRequest,
    R40LinePath,
    encode_r40_exact_payload,
)
from utils.rls_config.route_config import evaluate_route_configs
from utils.rls_config.route_bundle import export_route_bundle
from utils.rls_config.route_project import (
    OpticalPath,
    OpticalPathSegment,
    PathEndpointReview,
    RouteCustomerPolicy,
    RouteLink,
    RouteProject,
    ShelfInstance,
    Site,
)


FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "rls"
    / "elp1_sat4_golden.json"
)


def _project_from_fixture(golden: dict[str, object]) -> dict[str, object]:
    project = dict(golden["route"])
    expected_requests = list(golden.get("configuration_requests", ()))
    sites: list[dict[str, object]] = []
    shelves: list[dict[str, object]] = []
    shelf_ids: list[str] = []
    for index, row in enumerate(golden["shelves"], start=1):
        row = dict(row)
        site_key = f"site-{index}"
        shelf_id = f"shelf-{index}"
        shelf_ids.append(shelf_id)
        sites.append(
            {
                "site_key": site_key,
                "code": row["site_code"],
                "name": row["site_name"],
            }
        )
        expected_payload = (
            dict(expected_requests[index - 1])
            if index <= len(expected_requests)
            and isinstance(expected_requests[index - 1], dict)
            else {}
        )
        shelves.append(
            {
                "shelf_id": shelf_id,
                "site_key": site_key,
                "tid": row["tid"],
                "primary_oam_ip": row["primary_oam_ip"],
                "profile_id": row["profile_id"],
                "shelf_variant": row["shelf_variant"],
                "power_label": row["power_label"],
                "raman_label": row["raman_label"],
                "review_state": "confirmed",
                "profile_payload": {
                    "schema_id": expected_payload.get(
                        "schema_id", "ciena.rls.r4-0-exact-request"
                    ),
                    "schema_version": expected_payload.get(
                        "schema_version", "1.5"
                    ),
                    "request": expected_payload.get(
                        "request", {"provider_id": row["provider_id"]}
                    ),
                },
            }
        )
    links: list[dict[str, object]] = []
    for index, row in enumerate(golden["spans"], start=1):
        row = dict(row)
        segment_count = int(row.pop("segment_count", 0))
        segments = row.pop("segments", None)
        path = {
            key: value
            for key, value in row.items()
            if key not in {"order", "from_tid", "to_tid"}
        }
        if isinstance(segments, list):
            path["segments"] = [dict(segment) for segment in segments]
        elif segment_count:
            path["segments"] = [
                {
                    "order": part,
                    "from_tid": "",
                    "to_tid": "",
                }
                for part in range(1, segment_count + 1)
            ]
        links.append(
            {
                "order": index,
                "from_shelf_id": shelf_ids[index - 1],
                "to_shelf_id": shelf_ids[index],
                "paths": [path],
            }
        )
    project["sites"] = sites
    project["shelves"] = shelves
    project["links"] = links
    return project


def _exact_project_from_fixture(
    golden: dict[str, object],
) -> RouteProject:
    shelf_rows = [dict(row) for row in golden["shelves"]]
    request_rows = [
        dict(row) for row in golden["configuration_requests"]
    ]
    sites: list[Site] = []
    shelves: list[ShelfInstance] = []
    requests: list[R40ExactRequest] = []
    source_sha256 = str(
        golden["diagram_embedding"]["source_sha256"]
    )
    for index, (shelf_row, request_row) in enumerate(
        zip(shelf_rows, request_rows, strict=True),
        start=1,
    ):
        site_key = f"site-{index}"
        sites.append(
            Site(
                site_key,
                str(shelf_row["site_code"]),
                str(shelf_row["site_name"]),
            )
        )
        raw_request = dict(request_row["request"])
        provider = R40_PROVIDER_CATALOG[str(raw_request["provider_id"])]
        raw_request["management"] = ManagementInterface(
            **dict(raw_request["management"])
        )
        raw_request["line_1"] = R40LinePath(
            **dict(raw_request["line_1"])
        )
        if raw_request["line_2"] is not None:
            raw_request["line_2"] = R40LinePath(
                **dict(raw_request["line_2"])
            )
        request = R40ExactRequest(
            chassis_family=provider.chassis_family,
            chassis_pec=provider.chassis_pec,
            hardware_profile=provider.hardware_profile,
            **raw_request,
        )
        requests.append(request)
        source_evidence: dict[str, object] = {}
        if provider.supports_raman:
            slot = 4 if request.profile == "ila" else 6
            source_evidence = {
                "schema_id": "atlas.ciena.rls.diagram-import-evidence",
                "schema_version": "1.8",
                "source_sha256": source_sha256,
                "raman_callout_convention": {
                    "id": "small-red-slot-port-v1",
                    "source_sha256": source_sha256,
                    "scope": "source",
                    "deployable_cli": False,
                },
                "raman_callouts": [
                    {
                        "raw_text": f"{slot}/{port}",
                        "slot": slot,
                        "port": port,
                        "shelf_tid": request.shelf_name,
                        "context": "shelf_endpoint",
                        "evidence": [
                            {
                                "field": "slot_port",
                                "confidence": 0.99,
                            }
                        ],
                        "deployable_cli": False,
                    }
                    for port in (5, 6)
                ],
                "raman_callout_review": "accepted",
            }
        shelves.append(
            ShelfInstance(
                shelf_id=f"shelf-{index}",
                profile_id=str(shelf_row["profile_id"]),
                software_release="RLS R4.0",
                shelf_variant=str(shelf_row["shelf_variant"]),
                site_key=site_key,
                tid=str(shelf_row["tid"]),
                primary_oam_ip=str(shelf_row["primary_oam_ip"]),
                power_label=str(shelf_row["power_label"]),
                raman_label=str(shelf_row["raman_label"]),
                profile_payload=encode_r40_exact_payload(request),
                review_state="confirmed",
                source_evidence=source_evidence,
            )
        )

    def request_line(request: R40ExactRequest, side: str) -> R40LinePath:
        if request.line_1_route_side == side:
            return request.line_1
        assert request.line_2 is not None
        return request.line_2

    links: list[RouteLink] = []
    for index, raw_span in enumerate(golden["spans"], start=1):
        span = dict(raw_span)
        raw_segments = span.get("segments", ())
        segments = tuple(
            OpticalPathSegment(
                order=int(segment["order"]),
                from_tid=str(segment["from_tid"]),
                to_tid=str(segment["to_tid"]),
                expected_loss_db=float(segment["expected_loss_db"]),
                distance_km=float(segment["distance_km"]),
                fiber_type=str(segment["fiber_type"]),
                circuit_id=str(segment["circuit_id"]),
                fiber_start=int(segment["fiber_start"]),
                fiber_end=int(segment["fiber_end"]),
            )
            for segment in raw_segments
        )
        from_line = request_line(requests[index - 1], "Z")
        to_line = request_line(requests[index], "A")
        links.append(
            RouteLink(
                link_id=f"link-{index}",
                order=index,
                from_shelf_id=f"shelf-{index}",
                to_shelf_id=f"shelf-{index + 1}",
                paths=(
                    OpticalPath(
                        path_id=f"path-{index}",
                        path_role="route",
                        link_name=(
                            str(span.get("circuit_id", ""))
                            or f"SPAN-{index}"
                        ),
                        expected_loss_db=float(
                            span["expected_loss_db"]
                        ),
                        distance_km=float(span["distance_km"]),
                        fiber_type=str(span["fiber_type"]),
                        circuit_id=str(span.get("circuit_id", "")),
                        fiber_start=span.get("fiber_start"),
                        fiber_end=span.get("fiber_end"),
                        review_state="confirmed",
                        source_evidence={
                            "route_native_fiber_review": {
                                "value": "LEAF",
                                "scope": "all_active_route_spans",
                                "action": (
                                    "operator_apply_route_native_fiber"
                                ),
                                "status": "confirmed",
                                "deployable_cli": False,
                            }
                        },
                        endpoint_reviews=(
                            PathEndpointReview(
                                shelf_id=f"shelf-{index}",
                                link_name=from_line.link_name,
                                expected_loss_db=(
                                    from_line.expected_loss_db
                                ),
                                fiber_type=from_line.fiber_type,
                            ),
                            PathEndpointReview(
                                shelf_id=f"shelf-{index + 1}",
                                link_name=to_line.link_name,
                                expected_loss_db=to_line.expected_loss_db,
                                fiber_type=to_line.fiber_type,
                            ),
                        ),
                        segments=segments,
                    ),
                ),
            )
        )

    route = dict(golden["route"])
    return RouteProject(
        project_id="elp1-sat4-golden-acceptance",
        route_code=str(route["route_code"]),
        title=str(route["title"]),
        revision="1",
        ospf_area=str(route["ospf_area"]),
        customer_policy=RouteCustomerPolicy(
            **dict(route["customer_policy"])
        ),
        sites=tuple(sites),
        shelves=tuple(shelves),
        links=tuple(links),
        diagram_source={
            "source_sha256": source_sha256,
            "route_header": {
                "optical_band": "c+l",
                "optical_band_status": "direct_supported",
            },
            "route_title_derivation": {
                "rule_id": "terminal-site-route-title-v1",
                "status": "controlled_derivation",
                "value": "ELP1-SAT4",
                "observed_header_pair": "USELP1-USSAT4",
                "endpoint_codes": ["USELP1", "USSAT4"],
                "display_codes": ["ELP1", "SAT4"],
                "endpoint_tids": [
                    "USELP1-L8R2",
                    "USSAT4-L8R3",
                ],
                "removed_shared_prefix": "US",
                "source_sha256": source_sha256,
                "deployable_cli": False,
            },
        },
    )


def test_elp1_sat4_golden_fixture_covers_every_shelf_and_span() -> None:
    golden = dict(load_golden_fixture(FIXTURE))
    project = _project_from_fixture(golden)

    findings, shelf_count, span_count = compare_project_to_golden(
        project, golden
    )

    assert findings == ()
    assert shelf_count == 16
    assert span_count == 15


def test_elp1_sat4_exact_golden_requests_generate_all_sixteen_candidates() -> None:
    golden = dict(load_golden_fixture(FIXTURE))
    project = _exact_project_from_fixture(golden)

    findings, shelf_count, span_count = compare_project_to_golden(
        project.to_dict(),
        golden,
    )
    validation_errors = [
        issue for issue in project.validate() if issue.is_error
    ]
    build = evaluate_route_configs(project)

    assert findings == ()
    assert shelf_count == 16
    assert span_count == 15
    assert validation_errors == []
    assert project.deployment_readiness().ready is True
    assert build.ready is True
    assert build.config_count == 16


def test_elp1_sat4_full_golden_bundle_passes_independent_audit(
    tmp_path: Path,
) -> None:
    golden = dict(load_golden_fixture(FIXTURE))
    project = _exact_project_from_fixture(golden)
    bundle_golden = copy.deepcopy(golden)
    bundle_golden.pop("diagram_embedding")
    bundle_golden["workbook"]["diagram_images"] = []
    bundle_golden["workbook"].pop("diagram_image_dimensions")
    files = dict(export_route_bundle(project, tmp_path))

    report = audit_route_deliverable(
        files["manifest"].parent,
        bundle_golden,
    )

    assert report.passed
    assert report.findings == ()
    assert report.checked_shelves == 16
    assert report.checked_spans == 15
    assert report.checked_hashes == 67
    assert report.checked_cli_files == 16


def test_golden_fixture_rejects_the_observed_14_88_vision_typo() -> None:
    golden = dict(load_golden_fixture(FIXTURE))
    project = _project_from_fixture(golden)
    project["links"][3]["paths"][0]["expected_loss_db"] = 14.88

    findings, _, _ = compare_project_to_golden(project, golden)

    assert [
        (finding.code, finding.field)
        for finding in findings
        if finding.code == "GOLDEN_SPAN_MISMATCH"
    ] == [("GOLDEN_SPAN_MISMATCH", "spans[4].expected_loss_db")]


def _write_formula_workbook(
    path: Path,
    *,
    irm_formula: str = "SUM(A1:A2)",
    irm_cache: str = "3",
) -> tuple[str, str]:
    spreadsheet_ns = (
        "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    )
    office_rel_ns = (
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    )
    package_rel_ns = (
        "http://schemas.openxmlformats.org/package/2006/relationships"
    )
    workbook = (
        f'<workbook xmlns="{spreadsheet_ns}" xmlns:r="{office_rel_ns}">'
        "<sheets>"
        '<sheet name="FBN" sheetId="1" r:id="rId1"/>'
        '<sheet name="IRM" sheetId="2" r:id="rId2"/>'
        "</sheets></workbook>"
    )
    relationships = (
        f'<Relationships xmlns="{package_rel_ns}">'
        '<Relationship Id="rId1" '
        'Target="worksheets/sheet1.xml" '
        f'Type="{office_rel_ns}/worksheet"/>'
        '<Relationship Id="rId2" '
        'Target="worksheets/sheet2.xml" '
        f'Type="{office_rel_ns}/worksheet"/>'
        "</Relationships>"
    )
    fbn = (
        f'<worksheet xmlns="{spreadsheet_ns}"><sheetData><row r="1">'
        '<c r="A1"><f>STATIC_FBN_FORMULA</f><v>99</v></c>'
        "</row></sheetData></worksheet>"
    )
    irm = (
        f'<worksheet xmlns="{spreadsheet_ns}"><sheetData><row r="1">'
        f'<c r="B1"><f>{irm_formula}</f><v>{irm_cache}</v></c>'
        "</row></sheetData></worksheet>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", relationships)
        archive.writestr("xl/worksheets/sheet1.xml", fbn)
        archive.writestr("xl/worksheets/sheet2.xml", irm)
    return _formula_fingerprints(
        {
            "xl/worksheets/sheet2.xml": ElementTree.fromstring(
                irm.encode("utf-8")
            )
        }
    )


def _export_exact_test_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Path]:
    # Keep the helper signature stable for callers that already use the
    # fixture, but exercise the real controlled-template renderer.  A fake
    # workbook must never be able to make a published-bundle audit pass.
    del monkeypatch
    return dict(
        export_route_bundle(_two_shelf_exact_project(), tmp_path)
    )


def _replace_zip_member(
    path: Path,
    member_name: str,
    transform: object,
) -> None:
    replacement = path.with_suffix(".rewritten.xlsx")
    with zipfile.ZipFile(path) as source, zipfile.ZipFile(
        replacement,
        "w",
    ) as destination:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == member_name:
                data = transform(data)
            destination.writestr(info, data)
    os.replace(replacement, path)


def _rehash_bundle_workbook(files: dict[str, Path]) -> None:
    manifest = json.loads(files["manifest"].read_text(encoding="utf-8"))
    manifest["artifacts"]["mop"]["sha256"] = hashlib.sha256(
        files["mop"].read_bytes()
    ).hexdigest()
    files["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_workbook_audit_fingerprints_only_live_irm_formula_contract(
    tmp_path: Path,
) -> None:
    workbook = tmp_path / "formula-contract.xlsx"
    formula_signature, cache_signature = _write_formula_workbook(workbook)
    golden = {
        "workbook": {
            "formula_count": 2,
            "cached_formula_count": 2,
            "formula_signature_sha256": formula_signature,
            "cache_signature_sha256": cache_signature,
        }
    }

    assert _audit_workbook(workbook, golden) == []

    _write_formula_workbook(workbook, irm_formula="SUM(A1:A3)")
    formula_findings = _audit_workbook(workbook, golden)
    assert {
        finding.field for finding in formula_findings
    } == {"workbook.formula_signature_sha256"}

    _write_formula_workbook(workbook, irm_cache="4")
    cache_findings = _audit_workbook(workbook, golden)
    assert {
        finding.field for finding in cache_findings
    } == {"workbook.cache_signature_sha256"}


@pytest.mark.parametrize(
    ("part_name", "expected_code"),
    (
        (
            "xl/worksheets/sheet2.xml",
            "WORKBOOK_STATIC_PART_MISMATCH",
        ),
        (
            "xl/worksheets/sheet1.xml",
            "WORKBOOK_REGENERATION_MISMATCH",
        ),
        (
            "xl/worksheets/sheet6.xml",
            "WORKBOOK_REGENERATION_MISMATCH",
        ),
    ),
)
def test_self_consistent_workbook_tamper_fails_fidelity_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    part_name: str,
    expected_code: str,
) -> None:
    files = _export_exact_test_bundle(tmp_path, monkeypatch)

    def add_xml_whitespace(data: bytes) -> bytes:
        return data.replace(b"</worksheet>", b" \n</worksheet>", 1)

    _replace_zip_member(files["mop"], part_name, add_xml_whitespace)
    _rehash_bundle_workbook(files)

    report = audit_route_deliverable(
        files["manifest"].parent,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert not report.passed
    assert expected_code in {
        finding.code for finding in report.findings
    }


def test_duplicate_workbook_part_fails_before_content_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _export_exact_test_bundle(tmp_path, monkeypatch)
    with zipfile.ZipFile(files["mop"], "a") as workbook:
        workbook.writestr(
            "xl/worksheets/sheet1.xml",
            workbook.read("xl/worksheets/sheet1.xml"),
        )
    _rehash_bundle_workbook(files)

    report = audit_route_deliverable(
        files["manifest"].parent,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert not report.passed
    assert any(
        finding.code == "WORKBOOK_DUPLICATE_PART"
        for finding in report.findings
    )


def _write_diagram_workbook(
    path: Path,
    *,
    external_image: bool = False,
) -> tuple[bytes, dict[str, object]]:
    spreadsheet_ns = (
        "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    )
    office_rel_ns = (
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    )
    package_rel_ns = (
        "http://schemas.openxmlformats.org/package/2006/relationships"
    )
    drawing_ns = (
        "http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing"
    )
    drawingml_ns = "http://schemas.openxmlformats.org/drawingml/2006/main"
    output = BytesIO()
    image = Image.new("RGB", (31, 17), (20, 40, 60))
    try:
        image.save(output, format="PNG", compress_level=6, optimize=False)
    finally:
        image.close()
    png = output.getvalue()
    digest = hashlib.sha256(png).hexdigest()
    workbook = (
        f'<workbook xmlns="{spreadsheet_ns}" xmlns:r="{office_rel_ns}">'
        "<sheets>"
        '<sheet name="Diagram" sheetId="1" r:id="rId1"/>'
        "</sheets></workbook>"
    )
    workbook_rels = (
        f'<Relationships xmlns="{package_rel_ns}">'
        '<Relationship Id="rId1" Target="worksheets/sheet1.xml" '
        f'Type="{office_rel_ns}/worksheet"/>'
        "</Relationships>"
    )
    sheet = (
        f'<worksheet xmlns="{spreadsheet_ns}" xmlns:r="{office_rel_ns}">'
        '<sheetData/><drawing r:id="rIdDrawing"/></worksheet>'
    )
    sheet_rels = (
        f'<Relationships xmlns="{package_rel_ns}">'
        '<Relationship Id="rIdDrawing" Target="../drawings/drawing1.xml" '
        f'Type="{office_rel_ns}/drawing"/>'
        "</Relationships>"
    )
    drawing = (
        f'<xdr:wsDr xmlns:xdr="{drawing_ns}" xmlns:a="{drawingml_ns}" '
        f'xmlns:r="{office_rel_ns}"><xdr:oneCellAnchor><xdr:pic>'
        '<xdr:blipFill><a:blip r:embed="rIdImage"/></xdr:blipFill>'
        "</xdr:pic></xdr:oneCellAnchor></xdr:wsDr>"
    )
    target_mode = ' TargetMode="External"' if external_image else ""
    drawing_rels = (
        f'<Relationships xmlns="{package_rel_ns}">'
        '<Relationship Id="rIdImage" Target="../media/route.png" '
        f'Type="{office_rel_ns}/image"{target_mode}/>'
        "</Relationships>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        archive.writestr("xl/worksheets/sheet1.xml", sheet)
        archive.writestr(
            "xl/worksheets/_rels/sheet1.xml.rels",
            sheet_rels,
        )
        archive.writestr("xl/drawings/drawing1.xml", drawing)
        archive.writestr(
            "xl/drawings/_rels/drawing1.xml.rels",
            drawing_rels,
        )
        archive.writestr("xl/media/route.png", png)
    embedding: dict[str, object] = {
        "embedded": True,
        "sheet": "Diagram",
        "representation": "normalized_png",
        "normalization": "canonical-rgb-png-v3-full-resolution-max4096",
        "image_occurrence_count": 1,
        "unique_media_count": 1,
        "external_relationships": False,
        "images": [
            {
                "order": 1,
                "source_label": "route.png",
                "source_part": "route.png",
                "normalized_sha256": digest,
                "width": 31,
                "height": 17,
            }
        ],
    }
    return png, embedding


def test_workbook_diagram_audit_binds_relationship_order_and_digest(
    tmp_path: Path,
) -> None:
    workbook = tmp_path / "diagram.xlsx"
    _png, embedding = _write_diagram_workbook(workbook)
    golden = {
        "workbook": {
            "diagram_images": [
                {
                    "order": 1,
                    "normalized_sha256": embedding["images"][0][
                        "normalized_sha256"
                    ],
                    "width": 31,
                    "height": 17,
                }
            ]
        }
    }

    assert _audit_workbook(
        workbook,
        golden,
        {"diagram_embedding": embedding},
    ) == []

    bad_embedding = json.loads(json.dumps(embedding))
    bad_embedding["images"][0]["normalized_sha256"] = "0" * 64
    bad_digest = _audit_workbook(
        workbook,
        golden,
        {"diagram_embedding": bad_embedding},
    )
    assert {
        finding.code for finding in bad_digest
    } >= {"WORKBOOK_DIAGRAM_MANIFEST_MISMATCH"}

    _write_diagram_workbook(workbook, external_image=True)
    bad_relationship = _audit_workbook(
        workbook,
        golden,
        {"diagram_embedding": embedding},
    )
    assert {
        finding.code for finding in bad_relationship
    } >= {"WORKBOOK_DIAGRAM_RELATIONSHIP_INVALID"}


def test_golden_exact_request_contract_compares_nested_engineering_values() -> None:
    project = _two_shelf_exact_project().to_dict()
    first_request = project["shelves"][0]["profile_payload"]["request"]
    expected = {
        "configuration_requests": [
            {
                "tid": "RLS-A",
                "request": {
                    "hostname": first_request["hostname"],
                    "ospf_area": first_request["ospf_area"],
                    "management": {
                        "enabled": True,
                        "ip_address": "192.0.2.1",
                        "ospf_metric": 10,
                    },
                    "line_1": {
                        "neighbor_node": "RLS-Z",
                        "fiber_type": "NDSF",
                        "expected_loss_db": 12.0,
                        "input_patch_loss_db": 0.5,
                        "output_patch_loss_db": 0.5,
                    },
                },
            },
            {
                "tid": "RLS-Z",
                "request": {
                    "line_1": {
                        "neighbor_node": "RLS-A",
                        "expected_loss_db": 13.0,
                    }
                },
            },
        ]
    }

    findings, _, _ = compare_project_to_golden(project, expected)
    assert findings == ()

    expected["configuration_requests"][0]["request"]["line_1"][
        "expected_loss_db"
    ] = 99.0
    findings, _, _ = compare_project_to_golden(project, expected)
    assert any(
        finding.code == "GOLDEN_CONFIGURATION_REQUEST_MISMATCH"
        and finding.field.endswith("request.line_1.expected_loss_db")
        for finding in findings
    )


def test_pre_calibration_candidate_commit_detection_ignores_comments() -> None:
    text = "\n".join(
        (
            "# commit",
            "! commit",
            "// commit",
            "validate",
            "  commit  ",
            "commit confirmed",
        )
    )

    assert _executable_commit_lines(text) == [5, 6]


def test_published_bundle_is_reopened_and_every_declared_hash_is_checked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _export_exact_test_bundle(tmp_path, monkeypatch)
    bundle = files["manifest"].parent
    golden = {
        "schema": "atlas.ciena.rls.route-golden",
        "schema_version": "1.0",
    }

    report = audit_route_deliverable(bundle, golden)

    assert report.passed
    assert report.checked_hashes == 11
    assert report.checked_cli_files == 2

    manifest = json.loads(files["manifest"].read_text(encoding="utf-8"))
    first = manifest["configuration_candidates"][0]
    cli_path = (
        files["configs"]
        / first["directory"]
        / first["files"]["cli"]["filename"]
    )
    cli_path.write_text(
        cli_path.read_text(encoding="utf-8") + "# self-consistent edit\n",
        encoding="utf-8",
    )
    first["files"]["cli"]["sha256"] = hashlib.sha256(
        cli_path.read_bytes()
    ).hexdigest()
    files["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    tampered = audit_route_deliverable(bundle, golden)
    assert not tampered.passed
    assert {
        finding.code for finding in tampered.findings
    } >= {"CANDIDATE_REGENERATION_MISMATCH"}


def test_route_validation_is_regenerated_and_secret_scanned_after_rehash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _export_exact_test_bundle(tmp_path, monkeypatch)
    manifest = json.loads(files["manifest"].read_text(encoding="utf-8"))
    files["validation"].write_text(
        "FALSE VALIDATION REPORT\npassword=exposed-value\n",
        encoding="utf-8",
    )
    manifest["artifacts"]["validation"]["sha256"] = hashlib.sha256(
        files["validation"].read_bytes()
    ).hexdigest()
    files["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    report = audit_route_deliverable(
        files["manifest"].parent,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert not report.passed
    assert {finding.code for finding in report.findings} >= {
        "ROUTE_VALIDATION_REGENERATION_MISMATCH",
        "ROUTE_VALIDATION_SECRET_CLAIM",
    }


def test_manifest_top_artifact_roles_bind_to_discovered_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _export_exact_test_bundle(tmp_path, monkeypatch)
    manifest = json.loads(files["manifest"].read_text(encoding="utf-8"))
    artifacts = manifest["artifacts"]
    project = artifacts["project"]
    mop = artifacts["mop"]
    validation = artifacts["validation"]
    artifacts["project"] = mop
    artifacts["mop"] = validation
    artifacts["validation"] = project
    files["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    report = audit_route_deliverable(
        files["manifest"].parent,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    binding_fields = {
        finding.field
        for finding in report.findings
        if finding.code == "TOP_ARTIFACT_BINDING_INVALID"
    }
    assert binding_fields == {
        "manifest.artifacts.project.filename",
        "manifest.artifacts.mop.filename",
        "manifest.artifacts.validation.filename",
    }


def test_manifest_configs_directory_is_exact_and_drives_hash_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _export_exact_test_bundle(tmp_path, monkeypatch)
    manifest = json.loads(files["manifest"].read_text(encoding="utf-8"))
    manifest["artifacts"]["configs"]["directory"] = "not_configs"
    files["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    report = audit_route_deliverable(
        files["manifest"].parent,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert not report.passed
    assert {finding.code for finding in report.findings} >= {
        "CONFIGS_ARTIFACT_INVALID",
        "MANIFEST_FILE_MISSING",
        "UNLISTED_BUNDLE_FILE",
    }


def test_child_manifest_safety_is_checked_after_self_consistent_rehash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _export_exact_test_bundle(tmp_path, monkeypatch)
    manifest = json.loads(files["manifest"].read_text(encoding="utf-8"))
    candidate = manifest["configuration_candidates"][0]
    child_path = (
        files["configs"]
        / candidate["directory"]
        / candidate["files"]["manifest"]["filename"]
    )
    child = json.loads(child_path.read_text(encoding="utf-8"))
    child["deployment_approved"] = True
    child["contains_credentials"] = True
    child_path.write_text(
        json.dumps(child, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    candidate["files"]["manifest"]["sha256"] = hashlib.sha256(
        child_path.read_bytes()
    ).hexdigest()
    files["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    report = audit_route_deliverable(
        files["manifest"].parent,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert not report.passed
    assert {finding.code for finding in report.findings} >= {
        "CHILD_MANIFEST_SAFETY_INVALID",
        "CHILD_MANIFEST_SECRET_CLAIM",
        "CANDIDATE_REGENERATION_MISMATCH",
    }


def test_manifest_requires_safe_unique_names_and_full_top_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _export_exact_test_bundle(tmp_path, monkeypatch)
    manifest = json.loads(files["manifest"].read_text(encoding="utf-8"))
    del manifest["artifacts"]["validation"]
    manifest["artifacts"]["project"]["sha256"] = "not-a-digest"
    manifest["configuration_candidates"][1]["directory"] = (
        manifest["configuration_candidates"][0]["directory"]
    )
    first_files = manifest["configuration_candidates"][0]["files"]
    first_files["annotated"]["filename"] = first_files["cli"]["filename"]
    files["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    report = audit_route_deliverable(
        files["manifest"].parent,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert {finding.code for finding in report.findings} >= {
        "TOP_ARTIFACT_SET_INCOMPLETE",
        "MANIFEST_HASH_INVALID",
        "CANDIDATE_DIRECTORY_COLLISION",
        "CANDIDATE_FILENAME_COLLISION",
    }


def test_saved_project_must_decode_and_validate_as_current_route_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _export_exact_test_bundle(tmp_path, monkeypatch)
    manifest = json.loads(files["manifest"].read_text(encoding="utf-8"))
    project = json.loads(files["project"].read_text(encoding="utf-8"))
    del project["schema_name"]
    files["project"].write_text(
        json.dumps(project, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest["artifacts"]["project"]["sha256"] = hashlib.sha256(
        files["project"].read_bytes()
    ).hexdigest()
    files["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    report = audit_route_deliverable(
        files["manifest"].parent,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert any(
        finding.code == "PROJECT_MODEL_INVALID"
        for finding in report.findings
    )


def test_empty_rehashed_project_cannot_bypass_model_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _export_exact_test_bundle(tmp_path, monkeypatch)
    manifest = json.loads(files["manifest"].read_text(encoding="utf-8"))
    files["project"].write_text("{}\n", encoding="utf-8")
    manifest["artifacts"]["project"]["sha256"] = hashlib.sha256(
        files["project"].read_bytes()
    ).hexdigest()
    files["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    report = audit_route_deliverable(
        files["manifest"].parent,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert not report.passed
    assert any(
        finding.code == "PROJECT_MODEL_INVALID"
        for finding in report.findings
    )


def test_empty_manifest_cannot_bypass_manifest_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _export_exact_test_bundle(tmp_path, monkeypatch)
    files["manifest"].write_text("{}\n", encoding="utf-8")

    report = audit_route_deliverable(
        files["manifest"].parent,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert not report.passed
    assert {finding.code for finding in report.findings} >= {
        "MANIFEST_SCHEMA_INVALID",
        "MANIFEST_SAFETY_STATE_INVALID",
        "TOP_ARTIFACT_SET_INCOMPLETE",
    }


def test_bundle_symlink_fails_preflight_before_artifact_reads(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = bundle / "route_route_project.json"
    try:
        os.symlink(outside, link)
    except OSError as exc:
        pytest.skip(f"Symlink creation unavailable: {exc}")

    report = audit_route_deliverable(
        bundle,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert not report.passed
    assert {
        finding.code for finding in report.findings
    } & {"BUNDLE_SYMLINK_FORBIDDEN", "BUNDLE_PATH_OUTSIDE_ROOT"}


def test_manifest_artifact_cannot_escape_bundle(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("must not be read", encoding="utf-8")
    project = bundle / "route_route_project.json"
    project.write_text("{}", encoding="utf-8")
    mop = bundle / "route_FBN_MOP.xlsx"
    mop.write_bytes(b"unused")
    manifest = {
        "artifacts": {
            "project": {
                "filename": "../outside.txt",
                "sha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
            }
        }
    }
    (bundle / "route_route_manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    golden = {
        "schema": "atlas.ciena.rls.route-golden",
        "schema_version": "1.0",
    }

    report = audit_route_deliverable(bundle, golden)

    assert not report.passed
    assert any(
        finding.code == "MANIFEST_PATH_OUTSIDE_BUNDLE"
        and finding.field == "../outside.txt"
        for finding in report.findings
    )


def test_malformed_bundle_json_returns_failed_report(
    tmp_path: Path,
) -> None:
    (tmp_path / "route_route_manifest.json").write_text(
        "{not-json",
        encoding="utf-8",
    )
    (tmp_path / "route_route_project.json").write_text(
        "[not-an-object]",
        encoding="utf-8",
    )
    (tmp_path / "route_FBN_MOP.xlsx").write_bytes(b"unused")

    report = audit_route_deliverable(
        tmp_path,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert not report.passed
    assert {finding.code for finding in report.findings} >= {
        "MANIFEST_JSON_INVALID",
        "PROJECT_JSON_INVALID",
    }


def test_manifest_cannot_claim_complete_with_short_candidate_set(
    tmp_path: Path,
) -> None:
    project = tmp_path / "route_route_project.json"
    project.write_text("{}", encoding="utf-8")
    mop = tmp_path / "route_FBN_MOP.xlsx"
    mop.write_bytes(b"unused")
    manifest = {
        "schema": "atlas.ciena.rls.route-deliverable-bundle",
        "schema_version": "2.2",
        "shelf_count": 2,
        "configuration_candidates_complete": True,
        "configuration_candidate_count": 2,
        "configuration_candidates": [],
        "cli_candidate_files_included": True,
        "candidate_cli_commit_commands_emitted": False,
        "deployment_approved": False,
        "deployable_cli_included": False,
        "secret_material_included": False,
        "configuration_candidate_validation": {
            "candidate_generation_ready": True,
            "candidate_safety_mode": "validate_without_commit",
            "deployment_approved": False,
            "on_box_validate_required": True,
            "commit_command_count": 0,
        },
        "deployment_readiness": {
            "route_cli_ready": False,
            "deployable_cli_ready": False,
            "deployment_approved": False,
        },
        "artifacts": {},
    }
    (tmp_path / "route_route_manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    report = audit_route_deliverable(
        tmp_path,
        {
            "schema": "atlas.ciena.rls.route-golden",
            "schema_version": "1.0",
        },
    )

    assert not report.passed
    assert any(
        finding.code == "CANDIDATE_SET_INCOMPLETE"
        for finding in report.findings
    )
