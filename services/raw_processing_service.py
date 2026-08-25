"""Front-end-neutral raw CLI transcript processing and report export."""
from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict

import pandas as pd

import script_interface
from services.raw_processing_core import (
    AUTO_DETECT_NOKIA,
    FAMILY_BY_MODULE,
    normalize_device_id,
    normalize_device_map,
    read_excel_sheets,
    read_text_folder,
    resolve_script_module,
    split_raw_output_by_commands,
)
from gui.workbook_builder import WorkbookBuilder
from utils.helpers import get_data_dir, get_database_path


ProgressCallback = Callable[[str], None]


@dataclass(frozen=True)
class RawProcessingRequest:
    input_path: Path
    output_path: Path
    script_name: str = AUTO_DETECT_NOKIA
    device_id: str = ""
    customer: str = ""
    project: str = ""
    purchase_order: str = ""
    sales_order: str = ""


@dataclass(frozen=True)
class RawProcessingOutcome:
    output_path: Path
    devices_found: int
    devices_parsed: int
    family: str


def create_raw_workbook_builder() -> WorkbookBuilder:
    data_dir = get_data_dir()
    return WorkbookBuilder(
        script_interface.get_cache(),
        str(data_dir / "Device_Report_Template.xlsx"),
        str(data_dir / "ATLAS_Packing_Slip.xlsx"),
    )


def load_raw_sources(path: Path, device_id: str = "") -> Dict[str, str]:
    if path.is_dir():
        return normalize_device_map(read_text_folder(str(path)))
    if not path.is_file():
        raise FileNotFoundError(f"Raw input not found: {path}")
    if path.suffix.lower() in (".xlsx", ".xls"):
        return normalize_device_map(read_excel_sheets(str(path)))
    text = path.read_text(encoding="utf-8", errors="replace")
    return {normalize_device_id(device_id or path.stem): text}


def _parse_device(
    raw_text: str,
    device_id: str,
    module_path: str,
    outputs: Dict[str, Any],
    *,
    db_cache: Any,
    db_path: str,
    progress: ProgressCallback,
) -> bool:
    try:
        module = importlib.import_module(module_path)
        script = module.Script(
            ip_address=device_id,
            connection_type="ssh",
            db_cache=db_cache,
            db_path=db_path,
        )
        commands = script.get_commands()
        sections = split_raw_output_by_commands(raw_text, commands)
        found = sum(1 for section in sections if section.strip())
        progress(f"{device_id}: {found}/{len(commands)} command sections matched")
        if found == 0:
            outputs[device_id] = {
                "unmatched_data": {
                    "DataFrame": pd.DataFrame([{
                        "System Name": device_id,
                        "System Type": "Unknown",
                        "Type": "No inventory sections matched",
                        "Part Number": "UNPARSED",
                        "Serial Number": "",
                        "Description": "Transcript did not contain expected inventory commands",
                        "Name": "No Inventory Data",
                        "Source": "Manual",
                    }]),
                    "System Info": {
                        "System Name": device_id,
                        "System Type": "Unknown",
                        "Source": "Manual",
                    },
                }
            }
            return True
        script.process_outputs(sections, device_id, outputs)
        if device_id in outputs and isinstance(outputs[device_id], dict):
            for section_data in outputs[device_id].values():
                if not isinstance(section_data, dict):
                    continue
                frame = section_data.get("DataFrame")
                if frame is not None and hasattr(frame, "__setitem__"):
                    frame["System Name"] = device_id
                    frame["Source"] = "Manual"
                system_info = section_data.get("System Info")
                if isinstance(system_info, dict):
                    system_info["System Name"] = device_id
                    system_info["Source"] = "Manual"
        return True
    except Exception as exc:
        progress(f"{device_id}: parser failed — {exc}")
        return False


def run_raw_processing(
    request: RawProcessingRequest,
    *,
    progress: ProgressCallback | None = None,
    builder: WorkbookBuilder | None = None,
    db_cache: Any | None = None,
) -> RawProcessingOutcome:
    emit = progress or (lambda _message: None)
    sources = load_raw_sources(request.input_path, request.device_id)
    if not sources:
        raise RuntimeError("No raw transcript files were found.")
    emit(f"Loaded {len(sources)} device transcript(s)")

    cache = db_cache or script_interface.get_cache()
    outputs: Dict[str, Any] = {}
    modules: list[str] = []
    parsed = 0
    for device_id, raw_text in sources.items():
        module_path = resolve_script_module(raw_text, device_id, request.script_name)
        emit(f"Processing {device_id} with {module_path}")
        if _parse_device(
            raw_text,
            device_id,
            module_path,
            outputs,
            db_cache=cache,
            db_path=str(get_database_path()),
            progress=emit,
        ):
            parsed += 1
            modules.append(module_path)
    if not parsed:
        raise RuntimeError("No devices produced inventory data.")

    manual_outputs: Dict[str, Any] = {}
    width = len(str(len(outputs))) if len(outputs) > 1 else 1
    for index, data in enumerate(outputs.values(), start=1):
        key = "Manual" if index == 1 else f"Manual_{str(index).zfill(width)}"
        manual_outputs[key] = data

    families = {FAMILY_BY_MODULE.get(module, "default") for module in modules}
    non_default = families - {"default"}
    family = next(iter(non_default)) if len(non_default) == 1 else "default"
    workbook_builder = builder or create_raw_workbook_builder()
    request.output_path.parent.mkdir(parents=True, exist_ok=True)
    kwargs = dict(
        customer=request.customer,
        project=request.project,
        customer_po=request.purchase_order,
        sales_order=request.sales_order,
    )
    data_dir = get_data_dir()
    if family == "psi":
        workbook_builder.build_psi_report_workbook(
            manual_outputs,
            str(request.output_path),
            psi_template_path=str(data_dir / "Nokia_PSI_Report_Template.xlsx"),
            **kwargs,
        )
    elif family == "rls":
        workbook_builder.build_unified_report_workbook(
            {"rls": manual_outputs},
            str(request.output_path),
            rls_template_path=str(data_dir / "Ciena_RLS_Report_Template.xlsx"),
            psi_template_path=str(data_dir / "Nokia_PSI_Report_Template.xlsx"),
            **kwargs,
        )
    else:
        workbook_builder.build_report_workbook(
            manual_outputs, str(request.output_path), **kwargs
        )
    emit(f"Saved report: {request.output_path}")
    return RawProcessingOutcome(request.output_path, len(sources), parsed, family)
