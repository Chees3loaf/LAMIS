"""UI-independent orchestration for the Asset Import workflow."""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

import openpyxl

from utils.asset_import import AssetImportResult, apply_asset_data_to_inventory, parse_asset_doc


ProgressCallback = Callable[[str], None]


@dataclass(frozen=True)
class AssetImportOutcome:
    """Files and merge statistics produced by one import."""

    inventory_path: Path
    backup_path: Path
    asset_records: int
    result: AssetImportResult


def run_asset_import(
    inventory_path: str | Path,
    asset_path: str | Path,
    *,
    progress: ProgressCallback | None = None,
    now: datetime | None = None,
) -> AssetImportOutcome:
    """Back up and update an ATLAS inventory workbook.

    The backup is created before the inventory workbook is opened for mutation.
    Messages are emitted through ``progress`` so GUI implementations do not
    need to duplicate workflow logic.
    """

    inventory = Path(inventory_path)
    asset_doc = Path(asset_path)
    emit = progress or (lambda _message: None)

    if not inventory.is_file():
        raise FileNotFoundError(f"Inventory workbook not found: {inventory}")
    if not asset_doc.is_file():
        raise FileNotFoundError(f"Asset document not found: {asset_doc}")

    emit(f"Inventory: {inventory}")
    emit(f"Asset doc: {asset_doc}")
    asset_map = parse_asset_doc(str(asset_doc))
    emit(f"Parsed {len(asset_map)} serial(s) from asset doc")

    timestamp = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")
    backup = inventory.with_name(
        f"{inventory.stem}.bak_{timestamp}{inventory.suffix}"
    )
    shutil.copy2(inventory, backup)
    emit(f"Backup: {backup.name}")

    workbook = openpyxl.load_workbook(str(inventory))
    try:
        result = apply_asset_data_to_inventory(workbook, asset_map)
        workbook.save(str(inventory))
    finally:
        workbook.close()

    emit(f"Saved: {inventory}")
    return AssetImportOutcome(
        inventory_path=inventory,
        backup_path=backup,
        asset_records=len(asset_map),
        result=result,
    )
