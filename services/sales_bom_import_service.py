"""Inspection and generation services for Sales BOM imports."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

import openpyxl

from services.raw_processing_service import create_raw_workbook_builder
from utils.helpers import validate_uploaded_file


ProgressCallback = Callable[[str], None]


@dataclass(frozen=True)
class SalesBomSource:
    path: Path
    sheet_names: tuple[str, ...]


def inspect_sales_bom(path: str | Path) -> SalesBomSource:
    source = Path(validate_uploaded_file(str(path), allowed_kinds=("xlsx",)))
    workbook = openpyxl.load_workbook(source, read_only=True, data_only=True)
    try:
        sheets = tuple(workbook.sheetnames)
    finally:
        workbook.close()
    if not sheets:
        raise ValueError("The Sales BOM workbook has no worksheets.")
    return SalesBomSource(source, sheets)


def run_sales_bom_import(
    source: SalesBomSource,
    selected_sheets: Sequence[str],
    output_path: str | Path,
    *,
    customer: str = "",
    project: str = "",
    progress: ProgressCallback | None = None,
    builder=None,
) -> Path:
    selected = list(dict.fromkeys(selected_sheets))
    if not selected:
        raise ValueError("Select at least one Sales BOM worksheet.")
    missing = [name for name in selected if name not in source.sheet_names]
    if missing:
        raise ValueError(f"Worksheet(s) not found in the source: {', '.join(missing)}")
    output = Path(output_path)
    if output.suffix.lower() != ".xlsx":
        raise ValueError("The Sales BOM output must be an .xlsx workbook.")
    if output.resolve() == source.path.resolve():
        raise ValueError("Choose an output file different from the source workbook.")
    output.parent.mkdir(parents=True, exist_ok=True)

    emit = progress or (lambda _message: None)
    emit(f"Selected {len(selected)} worksheet(s): {', '.join(selected)}")
    emit("Building per-site Sales BOM workbook…")
    workbook_builder = builder or create_raw_workbook_builder()
    result = workbook_builder.build_sales_bom_packing_slip_workbook(
        source_path=str(source.path),
        selected_sheets=selected,
        output_file=str(output),
        customer=customer.strip(),
        project=project.strip(),
    )
    emit(f"Saved Sales BOM workbook: {result}")
    return Path(result)
