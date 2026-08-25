"""Packing-slip inspection and generation without GUI callbacks."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tempfile
from typing import Callable

import openpyxl
import pandas as pd

from gui.packing_slip_frame import PackingSlipFrame
from services.raw_processing_service import create_raw_workbook_builder
from utils.helpers import get_data_dir, sanitize_filename_component, strip_dataframe_strings, validate_uploaded_file


ProgressCallback = Callable[[str], None]


@dataclass(frozen=True)
class PackingSlipSource:
    path: Path
    customer: str
    project: str
    purchase_order: str
    sales_order: str
    device_count: int
    multisheet: bool


@dataclass(frozen=True)
class PackingSlipRequest:
    source: PackingSlipSource
    output_directory: Path
    customer: str
    project: str
    purchase_order: str = "TBD"
    sales_order: str = "TBD"
    mode: str = "individual"


def _is_device_sheet(ws) -> bool:
    """Recognize Device Report and Packing Slip tabs by structure."""
    title = ws.title.strip().lower()
    if "summary" in title or title in {"bom", "inventory by site"}:
        return False
    b7 = str(ws["B7"].value or "").strip().lower()
    if b7.startswith("customer po") or b7.startswith("device id"):
        return True
    headers = {
        str(ws.cell(14, column).value or "").strip().lower()
        for column in range(1, min(ws.max_column, 12) + 1)
    }
    return "part number" in headers and "serial number" in headers


def _device_sheet_names(workbook) -> list[str]:
    return [ws.title for ws in workbook.worksheets if _is_device_sheet(ws)]


def inspect_packing_slip_source(path: str | Path) -> PackingSlipSource:
    resolved = validate_uploaded_file(
        str(path), allowed_kinds=("xlsx", "xls", "csv")
    )
    source = Path(resolved)
    multisheet = False
    device_count = 0
    if source.suffix.lower() == ".csv":
        frame = pd.read_csv(source)
        device_count = len(frame)
    else:
        workbook = openpyxl.load_workbook(source, read_only=True, data_only=True)
        device_sheets = _device_sheet_names(workbook)
        workbook.close()
        multisheet = bool(device_sheets)
        device_count = len(device_sheets) if multisheet else len(pd.read_excel(source))

    engine = PackingSlipFrame.__new__(PackingSlipFrame)
    engine._last_customer = ""
    engine._last_project = ""
    engine._last_customer_po = ""
    engine._last_sales_order = ""
    engine._refresh_info_display = lambda: None
    if source.suffix.lower() in (".xlsx", ".xls"):
        engine._try_populate_fields_from_file(str(source))
    return PackingSlipSource(
        path=source,
        customer=engine._last_customer,
        project=engine._last_project,
        purchase_order=engine._last_customer_po or "TBD",
        sales_order=engine._last_sales_order or "TBD",
        device_count=device_count,
        multisheet=multisheet,
    )


def run_packing_slip_generation(
    request: PackingSlipRequest,
    *,
    progress: ProgressCallback | None = None,
    builder=None,
) -> Path:
    emit = progress or (lambda _message: None)
    if not request.customer.strip() or not request.project.strip():
        raise ValueError("Customer and Project are required.")
    if request.mode not in {"individual", "consolidated"}:
        raise ValueError(f"Unknown packing-slip mode: {request.mode}")
    request.output_directory.mkdir(parents=True, exist_ok=True)

    engine = PackingSlipFrame.__new__(PackingSlipFrame)
    engine._family_by_ip = {}
    engine._display_ip_for_key = {}
    if request.source.multisheet:
        emit("Reading device sheets…")
        processed = engine._process_multisheet_device_file(str(request.source.path))
    else:
        emit("Reading source rows…")
        if request.source.path.suffix.lower() == ".csv":
            data = pd.read_csv(request.source.path)
        else:
            data = pd.read_excel(request.source.path)
        strip_dataframe_strings(data)
        processed = engine._process_file_for_packing_slip(data)
    if not processed:
        raise RuntimeError("No valid packing-slip data was found in the source.")

    workbook_builder = builder or create_raw_workbook_builder()
    emit(f"Generating packing slips for {len(processed)} device(s)…")
    build_directory = request.output_directory
    temporary = None
    if request.mode == "consolidated":
        temporary = tempfile.TemporaryDirectory(prefix="ATLAS_packing_")
        build_directory = Path(temporary.name)
    try:
        output = workbook_builder.build_unified_packing_slip_workbook(
            processed,
            list(processed),
            request.customer.strip(),
            request.project.strip(),
            request.purchase_order.strip() or "TBD",
            request.sales_order.strip() or "TBD",
            str(build_directory),
            family_for_ip=engine._family_by_ip,
            display_ip_for_key=engine._display_ip_for_key,
        )
        if request.mode == "consolidated":
            safe_customer = sanitize_filename_component(request.customer)
            safe_project = sanitize_filename_component(request.project)
            final_path = request.output_directory / (
                f"PackingSlip_{safe_customer}_{safe_project}_Consolidated.xlsx"
            )
            _build_consolidated_workbook(
                Path(output), final_path, request.customer, request.project,
                workbook_builder,
            )
            output = str(final_path)
    finally:
        if temporary is not None:
            temporary.cleanup()
    emit(f"Saved packing-slip workbook: {output}")
    return Path(output)


def _build_consolidated_workbook(
    source_path: Path,
    output_path: Path,
    customer: str,
    project: str,
    builder,
) -> None:
    """Combine every real device sheet into the consolidated template."""
    template = get_data_dir() / "ATLAS_Consolidated_Packing_Slip.xlsx"
    if not template.is_file():
        template = Path(builder.packing_slip_template)
    destination = openpyxl.load_workbook(template)
    sheet = destination.active
    sheet["C5"] = customer
    sheet["C6"] = project

    source = openpyxl.load_workbook(source_path, read_only=True, data_only=True)
    row_number = 15
    for sheet_name in _device_sheet_names(source):
        ws = source[sheet_name]
        for row in ws.iter_rows(min_row=15, values_only=True):
            if len(row) < 6:
                continue
            purchase_order, part, serial, description = row[2], row[3], row[4], row[5]
            if not any(value not in (None, "", "nan") for value in (part, serial, description)):
                continue
            sanitize = builder._sanitize_cell
            sheet.cell(row_number, 2, sanitize(sheet_name))
            sheet.cell(row_number, 3, sanitize(purchase_order or ""))
            sheet.cell(row_number, 4, sanitize(part or ""))
            sheet.cell(row_number, 5, sanitize(serial or ""))
            sheet.cell(row_number, 6, sanitize(description or ""))
            row_number += 1
    source.close()
    builder.autosize_workbook_columns(destination)
    destination.save(output_path)
    destination.close()
