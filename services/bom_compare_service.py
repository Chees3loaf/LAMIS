"""Qt-facing adapter for the established BOM comparison engine."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Callable

from gui.bom_compare_frame import BomCompareFrame
from services.raw_processing_service import create_raw_workbook_builder
from utils.helpers import validate_uploaded_file


ProgressCallback = Callable[[str], None]


def default_compare_output(factory_path: str | Path) -> Path:
    """Return the legacy-compatible output name beside the factory file."""
    source = Path(factory_path)
    return source.with_name(f"{source.stem}.COMPARE{source.suffix or '.xlsx'}")


def run_bom_compare(
    factory_path: str | Path,
    sales_path: str | Path,
    *,
    output_path: str | Path | None = None,
    progress: ProgressCallback | None = None,
    builder=None,
) -> Path:
    """Compare a live inventory BOM to a sales BOM without Tk callbacks."""
    factory = Path(validate_uploaded_file(str(factory_path), allowed_kinds=("xlsx",)))
    sales = Path(validate_uploaded_file(str(sales_path), allowed_kinds=("xlsx",)))
    if factory.resolve() == sales.resolve():
        raise ValueError("Select two different workbooks to compare.")

    output = Path(output_path) if output_path else default_compare_output(factory)
    if output.suffix.lower() != ".xlsx":
        raise ValueError("The comparison output must be an .xlsx workbook.")
    output.parent.mkdir(parents=True, exist_ok=True)

    emit = progress or (lambda _message: None)
    engine = BomCompareFrame.__new__(BomCompareFrame)
    engine.gui = SimpleNamespace(
        workbook_builder=builder or create_raw_workbook_builder()
    )
    engine._append_log = emit
    result = engine._compare(str(factory), str(sales), str(output))
    return Path(result)
