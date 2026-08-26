"""Tests for the GUI-independent BOM comparison adapter."""
from pathlib import Path
from unittest.mock import patch

import openpyxl
import pytest

from services.bom_compare_core import BomCompareEngine
from services.bom_compare_service import default_compare_output, run_bom_compare


def _workbook(path: Path) -> None:
    workbook = openpyxl.Workbook()
    workbook.save(path)
    workbook.close()


def test_default_output_preserves_legacy_name(tmp_path) -> None:
    assert default_compare_output(tmp_path / "factory.xlsx") == tmp_path / "factory.COMPARE.xlsx"


def test_service_passes_explicit_output_and_progress(tmp_path) -> None:
    factory = tmp_path / "factory.xlsx"
    sales = tmp_path / "sales.xlsx"
    output = tmp_path / "chosen.xlsx"
    _workbook(factory)
    _workbook(sales)
    messages = []

    with patch.object(BomCompareEngine, "_compare", autospec=True, return_value=str(output)) as compare:
        result = run_bom_compare(
            factory, sales, output_path=output, progress=messages.append,
            builder=object(),
        )

    assert result == output
    engine = compare.call_args.args[0]
    assert engine.gui.workbook_builder is not None
    engine._append_log("progress")
    assert messages == ["progress"]
    assert compare.call_args.args[1:] == (str(factory), str(sales), str(output))


def test_service_rejects_same_workbook(tmp_path) -> None:
    source = tmp_path / "same.xlsx"
    _workbook(source)
    with pytest.raises(ValueError, match="different"):
        run_bom_compare(source, source, builder=object())
