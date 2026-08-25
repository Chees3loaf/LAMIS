"""Packing-slip inspection and generation without GUI callbacks."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pandas as pd

from gui.packing_slip_frame import PackingSlipFrame
from services.raw_processing_service import create_raw_workbook_builder
from utils.helpers import strip_dataframe_strings, validate_uploaded_file


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
        excel = pd.ExcelFile(source)
        device_sheets = [
            name for name in excel.sheet_names if "summary" not in str(name).lower()
        ]
        multisheet = len(excel.sheet_names) > 1 and bool(device_sheets)
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
    output = workbook_builder.build_unified_packing_slip_workbook(
        processed,
        list(processed),
        request.customer.strip(),
        request.project.strip(),
        request.purchase_order.strip() or "TBD",
        request.sales_order.strip() or "TBD",
        str(request.output_directory),
        family_for_ip=engine._family_by_ip,
        display_ip_for_key=engine._display_ip_for_key,
    )
    emit(f"Saved packing-slip workbook: {output}")
    return Path(output)
