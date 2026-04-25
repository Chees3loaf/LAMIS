"""
WorkbookBuilder: Excel workbook generation logic for LAMIS.

Separated from the main GUI class so it can be tested and maintained independently.
Handles both inventory reports and packing slip workbooks.
"""

from datetime import datetime
import logging
import os
import re
import shutil
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

import openpyxl
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter
import pandas as pd

from utils.helpers import extract_ip_sort_key


class WorkbookBuilder:
    """Builds Excel workbooks for inventory reports and packing slips."""

    def __init__(self, db_cache: Any, template_path: str, packing_slip_template: str) -> None:
        self.db_cache = db_cache
        self.template_path = template_path
        self.packing_slip_template = packing_slip_template
        self._export_running = False

    # ------------------------------------------------------------------
    # Sheet utilities
    # ------------------------------------------------------------------

    def autosize_sheet_columns(self, sheet: Any, min_width: int = 10, max_width: int = 60) -> None:
        """Auto-size all populated columns in a worksheet with sane bounds."""
        max_col = sheet.max_column or 0
        max_row = sheet.max_row or 0
        if max_col <= 0 or max_row <= 0:
            return

        for col_idx in range(1, max_col + 1):
            longest = 0
            for row_idx in range(1, max_row + 1):
                val = sheet.cell(row=row_idx, column=col_idx).value
                if val is None:
                    continue
                text_len = len(str(val))
                if text_len > longest:
                    longest = text_len

            if longest == 0:
                continue

            width = min(max(longest + 2, min_width), max_width)
            sheet.column_dimensions[get_column_letter(col_idx)].width = width

    def copy_sheet(self, source_sheet: Any, target_wb: Any, new_sheet_name: str) -> Any:
        """Copy an entire sheet from one workbook to another while preserving formatting."""
        new_sheet = target_wb.create_sheet(title=new_sheet_name)

        for row in source_sheet.iter_rows():
            for cell in row:
                new_sheet[cell.coordinate].value = cell.value
                if cell.has_style:
                    new_sheet[cell.coordinate].font = cell.font
                    new_sheet[cell.coordinate].border = cell.border
                    new_sheet[cell.coordinate].fill = cell.fill
                    new_sheet[cell.coordinate].number_format = cell.number_format
                    new_sheet[cell.coordinate].protection = cell.protection
                    new_sheet[cell.coordinate].alignment = cell.alignment

        return new_sheet

    # ------------------------------------------------------------------
    # Shared summary-sheet helpers (used by both workbook builders)
    # ------------------------------------------------------------------

    def _setup_summary_sheet_header(self, summary_sheet: Any, customer: str, project: str, ip_list: List[str]) -> None:
        """Common header setup for summary sheets in both report and packing slip workbooks."""
        summary_sheet["B5"] = "Customer"
        summary_sheet["B7"] = customer or ""
        summary_sheet["D5"] = "Project"
        summary_sheet["D7"] = project or ""

        capture_time = datetime.now().strftime('%Y-%m-%d @ %H:%M:%S')
        summary_sheet["A2"] = f"Capture Time = {capture_time}"
        summary_sheet["A2"].font = Font(color="00FF00", bold=True)
        summary_sheet["A2"].fill = PatternFill(start_color="000000", end_color="000000", fill_type="solid")

        summary_sheet["B9"] = "#"
        summary_sheet["C9"] = "IP Address"
        summary_sheet["D9"] = "Device Name"

        summary_sheet["F5"] = "IP Addresses"
        summary_sheet["F7"] = ", ".join(ip_list) if ip_list else ""

    def _populate_summary_table(self, summary_sheet: Any, summary_items: List[tuple], start_row: int = 10) -> None:
        """Populate summary table with device entries, sorted by IP."""
        ordered_items = sorted(summary_items, key=lambda item: extract_ip_sort_key(item[0]))

        for row_offset, (ip, device_name, sheet_title) in enumerate(ordered_items):
            row_num = start_row + row_offset
            summary_sheet[f"B{row_num}"] = row_offset + 1
            summary_sheet[f"C{row_num}"] = str(ip)
            summary_sheet[f"D{row_num}"] = str(device_name)
            summary_sheet[f"D{row_num}"].hyperlink = f"#'{sheet_title}'!A1"
            summary_sheet[f"D{row_num}"].style = "Hyperlink"

        self.autosize_sheet_columns(summary_sheet)

    # ------------------------------------------------------------------
    # Data combination
    # ------------------------------------------------------------------

    def combine_and_format_data(self, ip_data: Dict[str, pd.DataFrame]) -> pd.DataFrame:
        """Concatenate per-IP DataFrames from *ip_data* into a single DataFrame.

        Accepts dict values that are either a bare DataFrame or a dict with a
        "DataFrame" key.  Logs a warning and skips any entry that doesn't
        match either shape.  Returns an empty DataFrame when *ip_data* is
        empty or contains no usable data.
        """
        all_data = []
        logging.info(f"Starting combination of {len(ip_data)} data entries.")

        for key, value in ip_data.items():
            if isinstance(value, pd.DataFrame):
                all_data.append(value)
                logging.info(f"Processed DataFrame under key '{key}' with {len(value)} rows.")
            elif isinstance(value, dict) and "DataFrame" in value and isinstance(value["DataFrame"], pd.DataFrame):
                df = value["DataFrame"]
                all_data.append(df)
                logging.info(f"Unwrapped DataFrame under key '{key}' with {len(df)} rows.")
            else:
                logging.warning(f"Expected DataFrame under key '{key}' but got {type(value)}. Skipping.")

        if all_data:
            combined_df = pd.concat(all_data, ignore_index=True)
            logging.info(f"Combined DataFrame created with {len(combined_df)} rows from {len(all_data)} DataFrames.")
        else:
            combined_df = pd.DataFrame()
            logging.warning("No data to combine. Returning empty DataFrame.")

        return combined_df

    # ------------------------------------------------------------------
    # Inventory report workbook
    # ------------------------------------------------------------------

    def build_report_workbook(self, outputs: Dict[str, Any], output_file: str, customer: str = "", project: str = "", customer_po: str = "", sales_order: str = "", append_mode: bool = False) -> Dict[str, Any]:
        """Build (or append to) an inventory report Excel workbook.

        Args:
            outputs: Per-IP data keyed by IP address.
            output_file: Destination .xlsx path.
            customer: Customer name written to the summary sheet.
            project: Project name written to the summary sheet.
            customer_po: Purchase order number.
            sales_order: Sales order number.
            append_mode: When True, open an existing workbook and add new
                device sheets rather than creating a new file.

        Returns:
            Dict of per-IP processed data (used when generating packing slips
            immediately after export).

        Raises:
            RuntimeError: If an export is already in progress.
        """
        if getattr(self, "_export_running", False):
            raise RuntimeError("Export already running")
        self._export_running = True

        logging.info("Starting Excel export process...")
        try:
            def clean_str(v: object) -> str:
                if v is None:
                    return ""
                s = str(v).strip()
                return "" if s.lower() == "nan" else s

            def nonempty_col(col):
                if col is None:
                    return None
                s = col.astype(str).str.strip()
                return s.ne("") & s.str.lower().ne("nan")

            def first_nonempty(series, fallback=""):
                if series is None:
                    return fallback
                for v in series:
                    s = clean_str(v)
                    if s:
                        return s
                return fallback

            if not os.path.exists(self.template_path):
                raise FileNotFoundError(f"Template file not found at {self.template_path}")

            if append_mode:
                if not os.path.exists(output_file):
                    raise FileNotFoundError(f"Existing report file not found at {output_file}")
                wb = openpyxl.load_workbook(output_file)
                sheet = None
            else:
                wb = openpyxl.load_workbook(self.template_path)
                sheet = wb.active

            template_wb = openpyxl.load_workbook(self.template_path)
            template_sheet = template_wb.active

            db_exists = os.path.isfile(self.db_cache.db_path)
            logging.info(f"[EXCEL] Using DB cache path: {self.db_cache.db_path} (exists={db_exists})")
            logging.info(f"Starting Excel export for {len(outputs)} devices.")

            processed_data = {}
            summary_index = {}

            if "Summary" in wb.sheetnames:
                summary_sheet = wb["Summary"]
            else:
                summary_sheet = wb.create_sheet(title="Summary", index=0)

            if append_mode:
                for row_num in range(10, summary_sheet.max_row + 1):
                    existing_ip = summary_sheet[f"C{row_num}"].value
                    existing_name = summary_sheet[f"D{row_num}"].value
                    if existing_ip is None or existing_name is None:
                        continue

                    existing_ip_str = str(existing_ip).strip()
                    existing_name_str = str(existing_name).strip()
                    if not existing_ip_str:
                        continue

                    sheet_title = None
                    if summary_sheet[f"D{row_num}"].hyperlink and summary_sheet[f"D{row_num}"].hyperlink.target:
                        target = summary_sheet[f"D{row_num}"].hyperlink.target
                        match = re.match(r"#'(.+)'!", str(target))
                        if match:
                            sheet_title = match.group(1)

                    if sheet_title and sheet_title in wb.sheetnames:
                        summary_index[existing_ip_str] = (existing_name_str, sheet_title)

            self._setup_summary_sheet_header(summary_sheet, customer, project, list(outputs.keys()))

            def make_unique_sheet_title(base_name):
                clean_base = re.sub(r'[^a-zA-Z0-9_]', '_', str(base_name).strip())[:31]
                if not clean_base:
                    clean_base = "Device"

                if clean_base not in wb.sheetnames:
                    return clean_base

                counter = 2
                while True:
                    suffix = f"_{counter}"
                    candidate = f"{clean_base[:31 - len(suffix)]}{suffix}"
                    if candidate not in wb.sheetnames:
                        return candidate
                    counter += 1

            ordered_outputs = sorted(outputs.items(), key=lambda item: extract_ip_sort_key(item[0]))
            for seq, (ip, data_dict) in enumerate(ordered_outputs, start=1):
                try:
                    logging.info(f"Processing data for IP {ip}.")
                    combined_df = self.combine_and_format_data(data_dict)
                    if combined_df.empty:
                        logging.warning(f"No data to write for IP {ip}")
                        continue

                    system_name = clean_str(first_nonempty(
                        combined_df.get("System Name"),
                        f"System_{ip.replace('.', '_')}"
                    ))[:31].replace(":", "_").replace("/", "_")

                    system_type = clean_str(first_nonempty(combined_df.get("System Type"), ""))
                    if not system_type:
                        system_type = clean_str(first_nonempty(combined_df.get("Type"), ""))
                    system_type = system_type[:31].replace(":", "_").replace("/", "_")

                    source_val = clean_str(first_nonempty(combined_df.get("Source"), ""))

                    logging.info(f"Creating sheet for system '{system_name}' with {len(combined_df)} rows.")
                    ip_key = str(ip)
                    if append_mode and ip_key in summary_index:
                        prior_sheet_title = summary_index[ip_key][1]
                        if prior_sheet_title in wb.sheetnames and prior_sheet_title != summary_sheet.title:
                            del wb[prior_sheet_title]

                    new_sheet_title = make_unique_sheet_title(system_name)
                    if append_mode:
                        new_sheet = self.copy_sheet(template_sheet, wb, new_sheet_title)
                    else:
                        new_sheet = wb.copy_worksheet(sheet)
                        new_sheet.title = new_sheet_title

                    # Add quick navigation back to summary for easier review workflow.
                    new_sheet["A1"] = "Return"
                    new_sheet["A1"].hyperlink = f"#'{summary_sheet.title}'!A1"
                    new_sheet["A1"].style = "Hyperlink"

                    new_sheet["C5"] = customer
                    new_sheet["C6"] = project
                    new_sheet["C7"] = customer_po
                    new_sheet["D7"] = sales_order
                    new_sheet["F5"] = source_val
                    new_sheet["F6"] = system_name
                    new_sheet["F7"] = system_type

                    has_part = combined_df.get("Part Number")
                    has_model = combined_df.get("Model Number")

                    mask_part = nonempty_col(has_part)
                    mask_model = nonempty_col(has_model)

                    if mask_part is not None and mask_model is not None:
                        write_df = combined_df[mask_part | mask_model].copy()
                    elif mask_part is not None:
                        write_df = combined_df[mask_part].copy()
                    elif mask_model is not None:
                        write_df = combined_df[mask_model].copy()
                    else:
                        write_df = combined_df.iloc[0:0].copy()

                    start_row = 15
                    for i, row in write_df.reset_index(drop=True).iterrows():
                        row_num = start_row + i

                        part_number = clean_str(row.get("Part Number", "")) or clean_str(row.get("Model Number", ""))
                        info_type = clean_str(row.get("Information Type", "")).lower()
                        name_value = clean_str(row.get("Name", ""))

                        if "mda card" in info_type:
                            match = re.search(r"\d+", name_value)
                            mda_number = match.group() if match else "Unknown"
                            name_value = f"MDA {mda_number}"

                        type_value = clean_str(row.get("Type", ""))
                        serial_val = clean_str(row.get("Serial Number", ""))

                        if not any([name_value, type_value, part_number, serial_val]):
                            continue

                        description = ""
                        if part_number and db_exists:
                            description = self.db_cache.lookup_part(part_number[:10])
                            if not description or description == "Not Found":
                                try:
                                    with sqlite3.connect(self.db_cache.db_path) as tmpconn:
                                        tcur = tmpconn.cursor()
                                        tcur.execute(
                                            "SELECT description FROM parts WHERE part_number LIKE ?",
                                            (part_number[:10] + "%",),
                                        )
                                        res = tcur.fetchone()
                                        if res:
                                            description = res[0]
                                except Exception as exc:
                                    logging.debug(f"[EXCEL] Fallback DB lookup failed: {exc}")

                        new_sheet[f"B{row_num}"] = name_value
                        new_sheet[f"C{row_num}"] = type_value
                        new_sheet[f"D{row_num}"] = part_number
                        new_sheet[f"E{row_num}"] = serial_val
                        new_sheet[f"F{row_num}"] = description
                        write_df.at[row.name, "Description"] = description

                    self.autosize_sheet_columns(new_sheet)

                    processed_data[ip] = write_df
                    summary_index[str(ip)] = (system_name, new_sheet.title)
                except Exception as exc:
                    logging.error(f"Failed to process data for IP {ip}. Error: {exc}")

            if summary_sheet.max_row >= 10:
                for row_num in range(10, summary_sheet.max_row + 1):
                    summary_sheet[f"B{row_num}"] = None
                    summary_sheet[f"C{row_num}"] = None
                    summary_sheet[f"D{row_num}"] = None

            # Populate summary table using shared helper
            summary_items = [(ip, device_name, sheet_title) for ip, (device_name, sheet_title) in summary_index.items()]
            self._populate_summary_table(summary_sheet, summary_items, start_row=10)

            if not append_mode and len(wb.sheetnames) > 1 and sheet and sheet.title in wb.sheetnames:
                wb.remove(sheet)

            # Keep tabs ordered by IP sequence, with Summary first.
            ordered_summary_items = sorted(summary_items, key=lambda item: extract_ip_sort_key(item[0]))
            ordered_device_tabs = [sheet_title for (_, _, sheet_title) in ordered_summary_items if sheet_title in wb.sheetnames]
            pinned_tabs = [summary_sheet.title] + ordered_device_tabs
            remaining_tabs = [name for name in wb.sheetnames if name not in pinned_tabs]
            ordered_tabs = pinned_tabs + remaining_tabs
            wb._sheets = [wb[name] for name in ordered_tabs]

            save_dir = os.path.dirname(output_file)
            os.makedirs(save_dir, exist_ok=True)
            wb.save(output_file)
            logging.info(f"Data successfully saved to {output_file}")
            template_wb.close()
            return processed_data
        finally:
            self._export_running = False

    # ------------------------------------------------------------------
    # Packing slip workbook
    # ------------------------------------------------------------------

    def build_packing_slip_workbook(self, processed_data: Dict[str, Any], ip_list: List[str], customer: str, project: str, customer_po: str, sales_order: str, save_folder: str) -> str:
        """Generate a packing-slip Excel workbook from *processed_data*.

        Copies the packing slip template, populates a per-device sheet for
        each entry in *processed_data*, writes a summary sheet, then saves
        the finished file to *save_folder*.

        Args:
            processed_data: Dict keyed by IP/device ID with DataFrame values.
            ip_list: Ordered list of IPs for the summary table.
            customer: Customer name for the header.
            project: Project name for the header.
            customer_po: Purchase order number.
            sales_order: Sales order number.
            save_folder: Directory in which to write the output file.

        Returns:
            Absolute path to the saved packing slip file.

        Raises:
            FileNotFoundError: If the packing slip template does not exist.
        """
        packing_template_path = self.packing_slip_template
        logging.info(f"Loading packing slip template: {packing_template_path}")

        if not os.path.exists(packing_template_path):
            raise FileNotFoundError(f"Packing slip template not found at: {packing_template_path}")

        temp_packing_slip = os.path.join(os.getcwd(), "PackingSlip_Temp.xlsx")
        shutil.copy(packing_template_path, temp_packing_slip)

        try:
            wb_final = openpyxl.load_workbook(temp_packing_slip)

            # Find the summary sheet and the device template sheet dynamically
            # so the template file can use any sheet name.
            summary_sheet = None
            template_sheet = None
            for name in wb_final.sheetnames:
                if "summary" in name.lower():
                    summary_sheet = wb_final[name]
                else:
                    template_sheet = wb_final[name]

            if not summary_sheet:
                raise ValueError(f"No summary sheet found. Available: {wb_final.sheetnames}")
            if not template_sheet:
                raise ValueError(f"No device template sheet found. Available: {wb_final.sheetnames}")

            timestamp = datetime.now().strftime('%Y-%m-%d')
            safe_customer = re.sub(r'[^a-zA-Z0-9_]', '_', (customer or "Unknown").strip())
            safe_project = re.sub(r'[^a-zA-Z0-9_]', '_', (project or "Unknown").strip())

            filename = f"PackingSlip_{safe_customer}_{safe_project}_{timestamp}.xlsx"
            save_path = os.path.join(save_folder, filename)

            logging.info(f"Packing slips will be saved as: {save_path}")

            # New template already has column labels at rows 5-6 (Customer, Project,
            # IP Address, Device ID). Write a timestamp at A2 and leave the labels alone.
            capture_time = datetime.now().strftime('%Y-%m-%d @ %H:%M:%S')
            summary_sheet["A2"] = f"Capture Time = {capture_time}"
            summary_sheet["A2"].font = Font(color="00FF00", bold=True)
            summary_sheet["A2"].fill = PatternFill(start_color="000000", end_color="000000", fill_type="solid")

            ordered_items = sorted(processed_data.items(), key=lambda item: extract_ip_sort_key(item[0]))
            # Data rows start at row 7 (after the merged label rows 5-6).
            summary_start_row = 7
            summary_rows = []

            logging.info(f"Generating packing slips for {len(processed_data)} device(s)")

            for seq, (ip, device_data) in enumerate(ordered_items, start=1):
                if device_data.empty:
                    logging.warning(f"No data for {ip} - skipping")
                    continue

                logging.info(f"Columns for {ip}: {list(device_data.columns)}")

                try:
                    device_name = "Unknown_Device"
                    # Priority order: exact phrase match before broad "name" substring.
                    for pattern in ("system name", "device name", "hostname"):
                        for col in device_data.columns:
                            if pattern in col.lower():
                                device_name = str(device_data.iloc[0].get(col, "Unknown_Device"))
                                break
                        if device_name != "Unknown_Device":
                            break
                    if device_name == "Unknown_Device":
                        for col in device_data.columns:
                            if "name" in col.lower():
                                device_name = str(device_data.iloc[0].get(col, "Unknown_Device"))
                                break

                    device_name_clean = re.sub(r'[^a-zA-Z0-9_]', '_', device_name.strip())[:31]
                    if not device_name_clean:
                        device_name_clean = f"Device_{seq}"

                    new_sheet = wb_final.copy_worksheet(template_sheet)
                    new_sheet.title = device_name_clean

                    # Add quick navigation back to summary for easier review workflow.
                    new_sheet["A1"] = "Return"
                    new_sheet["A1"].hyperlink = f"#'{summary_sheet.title}'!A1"
                    new_sheet["A1"].style = "Hyperlink"

                    # NOTE: copy_worksheet already copies merged cell ranges;
                    # do NOT re-apply them or openpyxl raises ValueError.
                    # Labels (Customer:, Project:, Device ID:) and column headers
                    # at row 14 are already present in the template — only write values.
                    new_sheet["C5"] = customer or ""
                    new_sheet["C6"] = project or ""
                    new_sheet["C7"] = device_name

                    start_row = 15
                    for idx, row_dict in enumerate(device_data.to_dict('records')):
                        row_num = start_row + idx

                        # Case-insensitive column lookup so files with any casing work
                        row_lower = {k.lower(): v for k, v in row_dict.items()}
                        part_number = str(row_lower.get("part number", "")).strip()
                        serial_number = str(row_lower.get("serial number", "")).strip()
                        description = str(row_lower.get("description", "")).strip()

                        if not part_number:
                            part_number = str(row_lower.get("model number", "")).strip()

                        if part_number.lower() in ("nan", ""):
                            part_number = ""
                        if serial_number.lower() in ("nan", ""):
                            serial_number = ""
                        if description.lower() in ("nan", ""):
                            description = ""

                        if part_number or serial_number or description:
                            new_sheet[f"B{row_num}"] = sales_order or ""
                            new_sheet[f"C{row_num}"] = customer_po or ""
                            new_sheet[f"D{row_num}"] = part_number
                            new_sheet[f"E{row_num}"] = serial_number
                            new_sheet[f"F{row_num}"] = description

                    self.autosize_sheet_columns(new_sheet)

                    summary_rows.append((seq, ip, device_name, new_sheet.title))

                    logging.debug(f"Written {len(device_data)} line items for device '{device_name}' with SO/PO")
                except Exception as exc:
                    logging.error(f"Error creating sheet for {ip}: {exc}")

            # New summary template columns: B=Customer, D=Project, F=IP Address, H=Device ID
            for row_offset, (seq, ip, device_name, sheet_title) in enumerate(summary_rows):
                row_num = summary_start_row + row_offset
                summary_sheet[f"B{row_num}"] = customer or ""
                summary_sheet[f"D{row_num}"] = project or ""
                summary_sheet[f"F{row_num}"] = str(ip)
                summary_sheet[f"H{row_num}"] = str(device_name)
                summary_sheet[f"H{row_num}"].hyperlink = f"#'{sheet_title}'!A1"
                summary_sheet[f"H{row_num}"].style = "Hyperlink"

            self.autosize_sheet_columns(summary_sheet)

            if summary_sheet.title in wb_final.sheetnames:
                idx = wb_final.sheetnames.index(summary_sheet.title)
                wb_final._sheets.insert(0, wb_final._sheets.pop(idx))

            if template_sheet.title in wb_final.sheetnames:
                del wb_final[template_sheet.title]

            wb_final.save(save_path)
            logging.info(f"Packing slips saved successfully: {save_path}")
            return save_path
        finally:
            if os.path.exists(temp_packing_slip):
                try:
                    os.remove(temp_packing_slip)
                except OSError:
                    pass
