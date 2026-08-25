"""UI-independent entry point for building or refreshing an ATLAS BOM."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Callable

from gui.bom_frame import BomFrame
from gui.workbook_builder import WorkbookBuilder
import script_interface
from utils.helpers import get_data_dir


ProgressCallback = Callable[[str], None]


def create_workbook_builder() -> WorkbookBuilder:
    """Create the same builder configuration used by the production GUI."""
    data_dir = get_data_dir()
    return WorkbookBuilder(
        script_interface.get_cache(),
        str(data_dir / "Device_Report_Template.xlsx"),
        str(data_dir / "ATLAS_Packing_Slip.xlsx"),
    )


def run_bom_build(
    source_path: str | Path,
    *,
    progress: ProgressCallback | None = None,
    builder: WorkbookBuilder | None = None,
) -> Path:
    """Build ``<source>.BOM.xlsx`` using the production BOM engine.

    ``BomFrame._build`` is already extensively regression-tested but is still
    housed in the Tk module. This adapter deliberately bypasses widget
    construction and exposes the engine as a front-end-neutral operation.
    """
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"Inventory workbook not found: {source}")
    if source.suffix.lower() != ".xlsx":
        raise ValueError("BOM Build requires an .xlsx workbook.")

    emit = progress or (lambda _message: None)
    engine = BomFrame.__new__(BomFrame)
    engine.gui = SimpleNamespace(
        workbook_builder=builder or create_workbook_builder()
    )
    engine._append_log = emit
    return Path(engine._build(str(source)))
