"""Tests for the Qt-facing Sales BOM import service."""
from pathlib import Path
from unittest.mock import MagicMock

import openpyxl
import pytest

from services.sales_bom_import_service import inspect_sales_bom, run_sales_bom_import


def _source(path: Path) -> None:
    workbook = openpyxl.Workbook()
    workbook.active.title = "Final"
    workbook.create_sheet("Expansion")
    workbook.save(path)
    workbook.close()


def test_inspection_returns_workbook_sheet_order(tmp_path) -> None:
    path = tmp_path / "sales.xlsx"
    _source(path)
    source = inspect_sales_bom(path)
    assert source.sheet_names == ("Final", "Expansion")


def test_generation_delegates_selected_sheets_and_metadata(tmp_path) -> None:
    source_path = tmp_path / "sales.xlsx"
    output = tmp_path / "site-packing.xlsx"
    _source(source_path)
    source = inspect_sales_bom(source_path)
    builder = MagicMock()
    builder.build_sales_bom_packing_slip_workbook.return_value = str(output)
    messages = []

    result = run_sales_bom_import(
        source, ["Final", "Expansion"], output,
        customer=" ACME ", project=" Phase 4 ",
        progress=messages.append, builder=builder,
    )

    assert result == output
    builder.build_sales_bom_packing_slip_workbook.assert_called_once_with(
        source_path=str(source_path), selected_sheets=["Final", "Expansion"],
        output_file=str(output), customer="ACME", project="Phase 4",
    )
    assert messages[-1].startswith("Saved Sales BOM workbook:")


def test_generation_rejects_unknown_sheet(tmp_path) -> None:
    path = tmp_path / "sales.xlsx"
    _source(path)
    with pytest.raises(ValueError, match="not found"):
        run_sales_bom_import(inspect_sales_bom(path), ["Missing"], tmp_path / "out.xlsx", builder=MagicMock())
