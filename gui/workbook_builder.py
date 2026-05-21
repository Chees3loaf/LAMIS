"""
WorkbookBuilder: Excel workbook generation logic for ATLAS.

Separated from the main GUI class so it can be tested and maintained independently.
Handles both inventory reports and packing slip workbooks.
"""

from datetime import datetime
from copy import copy
import logging
import os
import re
import shutil
import sqlite3
import tempfile
from typing import Any, Dict, List, Optional, Tuple

import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
import pandas as pd

from utils.helpers import extract_ip_sort_key


# Hostnames a device reports when it has not been provisioned. Map each
# default to a short human-readable prefix; when a scan hits one of
# these, the workbook label falls back to "<prefix>-<chassis-serial>"
# so multiple un-provisioned shelves stay uniquely identifiable in the
# tab strip and BoM column headers instead of all collapsing onto
# rls / rls_2 / rls_3.
_FACTORY_DEFAULT_HOSTNAMES: Dict[str, str] = {
    "rls": "RLS",
}


def _chassis_serial_from_df(df: pd.DataFrame) -> str:
    """Return the chassis serial number from *df*, or "" if not found.

    The chassis row is identified by Type == "Shelf" (Ciena RLS / Nokia
    1830) or "Chassis" (Nokia SAR / IXR). We take the first matching
    row with a non-empty Serial Number.
    """
    if df is None or df.empty:
        return ""
    type_col = df.get("Type")
    serial_col = df.get("Serial Number")
    if type_col is None or serial_col is None:
        return ""
    for tval, sval in zip(type_col, serial_col):
        tlow = str(tval).strip().lower() if tval is not None else ""
        ser = str(sval).strip() if sval is not None else ""
        if tlow in ("shelf", "chassis") and ser:
            return ser
    return ""


class WorkbookBuilder:
    """Builds Excel workbooks for inventory reports and packing slips."""

    def __init__(self, db_cache: Any, template_path: str, packing_slip_template: str, bom_template: Optional[str] = None) -> None:
        self.db_cache = db_cache
        self.template_path = template_path
        self.packing_slip_template = packing_slip_template
        # Default the BOM template to BOM_Template.xlsx alongside the main
        # report template so the same data/ directory carries both files.
        if bom_template is None and template_path:
            bom_template = os.path.join(os.path.dirname(template_path), "BOM_Template.xlsx")
        self.bom_template = bom_template
        # Per-device-family BOM category overrides are stored alongside the
        # template as data/BOM_Categories_<Family>.xlsx files. Loaded lazily
        # on first BOM build so a missing data directory doesn't break init.
        self._bom_part_overrides: Optional[Dict[str, str]] = None
        self._export_running = False

    @property
    def bom_part_overrides(self) -> Dict[str, str]:
        """Part-number → BOM group map, unioned across every BOM_Categories_*.xlsx."""
        if self._bom_part_overrides is None:
            self._bom_part_overrides = self._load_bom_part_overrides()
        return self._bom_part_overrides

    def _load_bom_part_overrides(self) -> Dict[str, str]:
        """Discover and load all data/BOM_Categories_*.xlsx files.

        Each file has rows of (Part Number, Group, Description) starting at
        row 2. Groups outside the known set (Chassis/Shelf, Cards, Optics,
        Additional Material) are logged and skipped. Part numbers are
        normalized to upper case for case-insensitive matching against
        DataFrame rows.
        """
        overrides: Dict[str, str] = {}
        if not self.bom_template:
            return overrides
        data_dir = os.path.dirname(self.bom_template)
        if not data_dir or not os.path.isdir(data_dir):
            return overrides

        import glob
        pattern = os.path.join(data_dir, "BOM_Categories_*.xlsx")
        known_groups = {"Chassis/Shelf", "Cards", "Optics", "Additional Material"}
        for path in sorted(glob.glob(pattern)):
            try:
                cat_wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
                try:
                    ws = cat_wb.active
                    for row in ws.iter_rows(min_row=2, values_only=True):
                        if not row or row[0] is None:
                            continue
                        part = str(row[0]).strip().upper()
                        group = str(row[1]).strip() if len(row) > 1 and row[1] else ""
                        if not part or not group:
                            continue
                        if group not in known_groups:
                            logging.warning(
                                f"[BOM] Skipping {part!r} in {os.path.basename(path)}: "
                                f"unknown group {group!r} (expected one of {sorted(known_groups)})"
                            )
                            continue
                        overrides[part] = group
                finally:
                    cat_wb.close()
            except Exception as exc:
                logging.warning(f"[BOM] Failed to load category overrides from {path}: {exc}")

        if overrides:
            logging.info(f"[BOM] Loaded {len(overrides)} part-number category overrides")
        return overrides

    # ------------------------------------------------------------------
    # Security helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitize_cell(value: Any) -> Any:
        """Prevent Excel formula injection AND strip illegal control chars.

        - Strips NUL/control characters that openpyxl rejects with
          ``IllegalCharacterError`` (these can leak in from raw device
          telnet output, e.g. the 1830 sends ``\\x0d\\x00`` sequences).
        - Prefixes formula-like leading characters (=, +, -, @, tab, CR)
          with a single quote so Excel treats them as text.
        """
        if isinstance(value, str):
            if value:
                # openpyxl rejects \x00-\x08, \x0B, \x0C, \x0E-\x1F
                value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", value)
            if value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
                return "'" + value
        return value

    # ------------------------------------------------------------------
    # Sheet utilities
    # ------------------------------------------------------------------

    def autosize_sheet_columns(self, sheet: Any, min_width: int = 10, max_width: int = 80) -> None:
        """Auto-size all populated columns in a worksheet with sane bounds.

        Skips cells that anchor a merged range spanning multiple columns —
        titles and banners are decorative and would unfairly inflate one
        column. Scales the measured length up slightly for bold cells and
        large fonts so wider visual glyphs still fit without being clipped.

        The default cap (80) accommodates typical device-inventory
        descriptions ("2P 10GE+4P GE ETH CARD (-48/+24VDC) WITH POWER
        REDUNDANCY" is 63 chars; Nokia 1830 cards can run up to ~75) while
        keeping a single very long string from monopolising the screen.
        """
        max_col = sheet.max_column or 0
        max_row = sheet.max_row or 0
        if max_col <= 0 or max_row <= 0:
            return

        # Pre-compute the set of cells (row, col) that anchor merged ranges
        # that span more than one column — we'll ignore those for autosize.
        multi_col_anchors: set = set()
        try:
            for rng in sheet.merged_cells.ranges:
                if rng.max_col > rng.min_col:
                    multi_col_anchors.add((rng.min_row, rng.min_col))
        except Exception:
            multi_col_anchors = set()

        for col_idx in range(1, max_col + 1):
            longest = 0.0
            for row_idx in range(1, max_row + 1):
                if (row_idx, col_idx) in multi_col_anchors:
                    continue
                cell = sheet.cell(row=row_idx, column=col_idx)
                val = cell.value
                if val is None:
                    continue
                text_len = float(len(str(val)))
                font = cell.font
                if font is not None:
                    if getattr(font, "bold", False):
                        text_len *= 1.10
                    size = getattr(font, "size", None)
                    if size and size > 11:
                        text_len *= float(size) / 11.0
                if text_len > longest:
                    longest = text_len

            if longest <= 0:
                continue

            width = min(max(int(round(longest)) + 2, min_width), max_width)
            sheet.column_dimensions[get_column_letter(col_idx)].width = width

    def autosize_workbook_columns(self, wb: Any, min_width: int = 10, max_width: int = 80) -> None:
        """Auto-size populated columns in every visible sheet of a workbook."""
        for sheet_name in wb.sheetnames:
            try:
                self.autosize_sheet_columns(wb[sheet_name], min_width, max_width)
            except Exception as exc:
                logging.warning(f"Autosize failed for sheet '{sheet_name}': {exc}")

    def copy_sheet(self, source_sheet: Any, target_wb: Any, new_sheet_name: str) -> Any:
        """Copy an entire sheet from one workbook to another while preserving formatting."""
        new_sheet = target_wb.create_sheet(title=new_sheet_name)

        for row in source_sheet.iter_rows():
            for cell in row:
                new_sheet[cell.coordinate].value = cell.value
                if cell.has_style:
                    # Openpyxl style objects must be cloned when copied across workbooks.
                    new_sheet[cell.coordinate].font = copy(cell.font)
                    new_sheet[cell.coordinate].border = copy(cell.border)
                    new_sheet[cell.coordinate].fill = copy(cell.fill)
                    new_sheet[cell.coordinate].number_format = cell.number_format
                    new_sheet[cell.coordinate].protection = copy(cell.protection)
                    new_sheet[cell.coordinate].alignment = copy(cell.alignment)

        for key, dimension in source_sheet.column_dimensions.items():
            # ColumnDimensions can span a range (min..max); copy width to
            # every letter in the span so per-site columns keep their
            # widths in the destination workbook.
            try:
                lo = int(dimension.min) if dimension.min else None
                hi = int(dimension.max) if dimension.max else None
            except (TypeError, ValueError):
                lo = hi = None
            if lo and hi and hi >= lo:
                for col_idx in range(lo, hi + 1):
                    letter = get_column_letter(col_idx)
                    new_sheet.column_dimensions[letter].width = dimension.width
                    new_sheet.column_dimensions[letter].hidden = dimension.hidden
            else:
                new_sheet.column_dimensions[key].width = dimension.width
                new_sheet.column_dimensions[key].hidden = dimension.hidden

        for key, dimension in source_sheet.row_dimensions.items():
            new_sheet.row_dimensions[key].height = dimension.height
            new_sheet.row_dimensions[key].hidden = dimension.hidden

        for merged_range in source_sheet.merged_cells.ranges:
            new_sheet.merge_cells(str(merged_range))

        if source_sheet.freeze_panes:
            new_sheet.freeze_panes = source_sheet.freeze_panes

        # Copy embedded images (e.g. the LightRiver banner on the BOM template).
        # Each image's byte data is reread from disk so the new workbook owns
        # an independent copy rather than aliasing the source's buffer.
        try:
            from openpyxl.drawing.image import Image as XLImage
            from io import BytesIO
            for src_img in getattr(source_sheet, "_images", []) or []:
                try:
                    data_fn = getattr(src_img, "_data", None)
                    if not callable(data_fn):
                        continue
                    img_bytes = data_fn()
                    if not img_bytes:
                        continue
                    new_img = XLImage(BytesIO(img_bytes))
                    if src_img.anchor is not None:
                        new_img.anchor = copy(src_img.anchor)
                    new_sheet.add_image(new_img)
                except Exception as exc:
                    logging.debug(f"[copy_sheet] Skipped one image: {exc}")
        except Exception as exc:
            logging.debug(f"[copy_sheet] Image-copy block failed: {exc}")

        return new_sheet

    # ------------------------------------------------------------------
    # Shared summary-sheet helpers (used by both workbook builders)
    # ------------------------------------------------------------------

    @staticmethod
    def _append_summary_timestamp(summary_sheet: Any, label: str) -> int:
        """Stamp ``<label> = <now>`` in the next empty cell of column A.

        Older stamps stay where they are; the newest sits at the bottom of
        the column-A list. Uses the same green-on-black style as the
        original "Capture Time" cell so the timeline reads as a single
        continuous block. Returns the row written to.
        """
        ts = datetime.now().strftime('%Y-%m-%d @ %H:%M:%S')
        last_used = 1
        scan_to = max(summary_sheet.max_row or 0, 8)
        for r in range(1, scan_to + 1):
            v = summary_sheet.cell(r, 1).value
            if v is not None and str(v).strip():
                last_used = r
        target = last_used + 1
        cell = summary_sheet.cell(target, 1)
        cell.value = f"{label} = {ts}"
        cell.font = Font(color="00FF00", bold=True)
        cell.fill = PatternFill(start_color="000000", end_color="000000", fill_type="solid")
        return target

    def _setup_summary_sheet_header(self, summary_sheet: Any, customer: str, project: str, ip_list: List[str]) -> None:
        """Common header setup for summary sheets in both report and packing slip workbooks."""
        summary_sheet["B5"] = "Customer"
        summary_sheet["D5"] = "Project"
        # Preserve any pre-existing customer/project on append-mode runs so
        # changes the user makes in the run-context popup only flow into the
        # NEW device sheet (written further down with C5/C6), not back into
        # the workbook-wide summary.
        if not summary_sheet["B7"].value:
            summary_sheet["B7"] = customer or ""
        if not summary_sheet["D7"].value:
            summary_sheet["D7"] = project or ""

        capture_time = datetime.now().strftime('%Y-%m-%d @ %H:%M:%S')
        # Preserve any pre-existing capture stamp so reruns / append-mode
        # builds don't overwrite the workbook's original timestamp. The
        # rerun emits its own "Additional Capture" stamp lower in column A
        # via _append_summary_timestamp.
        if not summary_sheet["A2"].value:
            summary_sheet["A2"] = f"Capture Time = {capture_time}"
            summary_sheet["A2"].font = Font(color="00FF00", bold=True)
            summary_sheet["A2"].fill = PatternFill(start_color="000000", end_color="000000", fill_type="solid")

        summary_sheet["B9"] = "#"
        summary_sheet["C9"] = "IP Address"
        summary_sheet["D9"] = "Device Name"
        # Operator-editable column — values typed into E10+ propagate onto
        # the corresponding device tab's Chassis/Shelf row at the next
        # BoM build (see WorkbookBuilder.propagate_asset_tags_to_tabs).
        summary_sheet["E9"] = "Asset Tag"

        summary_sheet["F5"] = "Device Count"
        summary_sheet["F7"] = 0  # Updated with actual count after processing

    def _format_summary_sheet(self, summary_sheet: Any, data_row_count: int, title: str = "Device Summary") -> None:
        """Apply a consistent visual layout to summary sheets.

        ``title`` lets callers swap the banner text — inventory sheets use
        the default "Device Summary"; packing-slip sheets pass "Packing
        Slip Summary" so the same layout serves both flows.
        """
        accent_fill = PatternFill(start_color="FF0087FF", end_color="FF0087FF", fill_type="solid")
        dark_fill = PatternFill(start_color="000000", end_color="000000", fill_type="solid")
        white_font = Font(color="FFFFFFFF", bold=True)
        bold_font = Font(bold=True)
        thin_side = Side(style="thin", color="FF0087FF")
        border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)
        center = Alignment(horizontal="center", vertical="center")

        summary_sheet.merge_cells("B2:F3")
        summary_sheet["B2"] = title
        summary_sheet["B2"].fill = accent_fill
        summary_sheet["B2"].font = Font(color="FFFFFFFF", bold=True, size=18)
        summary_sheet["B2"].alignment = center

        for row in range(5, 8):
            for col in range(2, 7):
                cell = summary_sheet.cell(row=row, column=col)
                cell.border = border
                cell.alignment = center if row == 5 else Alignment(vertical="center")
                if row == 5:
                    cell.fill = accent_fill
                    cell.font = white_font

        summary_sheet["A2"].fill = dark_fill

        # Row 9 column headers — include E so "Asset Tag" picks up the
        # same accent/border styling as #, IP Address, Device Name.
        for col in range(2, 6):
            cell = summary_sheet.cell(row=9, column=col)
            cell.fill = accent_fill
            cell.font = white_font
            cell.border = border
            cell.alignment = center

        end_row = max(10, 9 + data_row_count)
        for row in range(10, end_row + 1):
            for col in range(2, 6):
                cell = summary_sheet.cell(row=row, column=col)
                cell.border = border
                if col == 2:
                    cell.alignment = center

        summary_sheet.freeze_panes = "B10"

    @staticmethod
    def _reset_summary_sheet_layout(summary_sheet: Any) -> None:
        """Wipe legacy template cells / merges from a Summary sheet.

        Packing-slip templates shipped with an older layout (header labels
        at row 5 cols B/D/F/H, device count at J5/J6, data starting at
        row 7). Before applying the uniform inventory layout we strip the
        leftover values, hyperlinks, and merged ranges so the new format
        can render cleanly without colliding with template-resident cells
        like the old "Device Name" at H5 or the old B2:H3 title merge.
        Idempotent on fresh sheets.
        """
        # Unmerge every range — the new formatter re-merges B2:F3.
        for rng in list(summary_sheet.merged_cells.ranges):
            try:
                summary_sheet.unmerge_cells(str(rng))
            except Exception:
                pass

        # Clear a generous bounding box: rows 1-200, cols A-L. Catches any
        # legacy headers (H5, J5, J6) and stale per-row Customer/Project
        # repeats from the old packing-slip layout (cols B/D/F/H, rows 7+).
        max_row = max(summary_sheet.max_row or 0, 50)
        max_col = max(summary_sheet.max_column or 0, 12)
        for r in range(1, max_row + 1):
            for c in range(1, max_col + 1):
                cell = summary_sheet.cell(row=r, column=c)
                cell.value = None
                cell.hyperlink = None

    def _format_packing_slip_summary(self, summary_sheet: Any, data_row_count: int) -> None:
        """Deprecated alias — packing-slip summaries now share the
        uniform inventory layout. Kept so any external caller keeps
        working; new code should call ``_format_summary_sheet`` with
        ``title='Packing Slip Summary'`` directly.
        """
        self._format_summary_sheet(
            summary_sheet, data_row_count, title="Packing Slip Summary"
        )

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

        summary_sheet["F7"] = len(ordered_items)
        self._format_summary_sheet(summary_sheet, len(ordered_items))
        self.autosize_sheet_columns(summary_sheet)

    # ------------------------------------------------------------------
    # Bill of Materials (aggregate) helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_information_type(info_type: str) -> str:
        """Map an "Information Type" value to a BOM group label.

        Returns "Chassis/Shelf", "Cards", "Optics", or "" (skip).
        """
        s = (info_type or "").strip().lower()
        if s == "error":
            return ""
        if "transceiver" in s or "optic" in s:
            return "Optics"
        if "card" in s:
            return "Cards"
        # Empty / "component" / "shelf" / "logical port" / anything else
        # falls under chassis-level inventory (chassis, fans, PSU, panels,
        # licenses, surge protection, alarm cords, etc.).
        return "Chassis/Shelf"

    def _collect_bom_entries_from_df(self, df: Any) -> List[Tuple[str, str, str]]:
        """Pull (part_number, description, group) tuples from a per-IP DataFrame.

        Used for standard inventory reports where rows carry an
        "Information Type" column. One tuple is emitted per row that has
        a usable part number; the caller aggregates by part number.
        """
        if df is None:
            return []
        try:
            if df.empty:
                return []
        except AttributeError:
            return []

        entries: List[Tuple[str, str, str]] = []
        for _, row in df.iterrows():
            part = str(
                row.get("Part Number", "") or row.get("Model Number", "") or ""
            ).strip()
            if not part or part.lower() in ("nan", "unparsed"):
                # Skip raw-processing placeholder rows that signal a parse
                # failure rather than a real part.
                continue
            group = self._classify_information_type(
                str(row.get("Information Type", "") or "")
            )
            if not group:
                continue
            desc = str(row.get("Description", "") or "").strip()
            if desc.lower() == "nan":
                desc = ""
            entries.append((part, desc, group))
        return entries

    def _collect_bom_entries_from_psi_data(self, data_dict: Any) -> List[Tuple[str, str, str]]:
        """Pull (part_number, description, group) tuples from a PSI per-IP dict.

        PSI parsing splits inventory across dict keys, so the group is
        determined by which key the row came from rather than an
        "Information Type" cell.
        """
        if not isinstance(data_dict, dict):
            return []

        group_map = {
            "shelf_detail": "Chassis/Shelf",
            "shelf_inventory": "Chassis/Shelf",
            "card_inventory": "Cards",
            "module_inventory": "Optics",
        }

        def _unwrap(entry: Any) -> Optional[pd.DataFrame]:
            if isinstance(entry, dict) and isinstance(entry.get("DataFrame"), pd.DataFrame):
                return entry["DataFrame"]
            if isinstance(entry, pd.DataFrame):
                return entry
            return None

        entries: List[Tuple[str, str, str]] = []
        for key, group in group_map.items():
            df = _unwrap(data_dict.get(key))
            if df is None or df.empty:
                continue
            for _, row in df.iterrows():
                part = str(row.get("Part Number", "") or "").strip()
                if not part or part.lower() == "nan":
                    continue
                desc = str(row.get("Description", "") or "").strip()
                if desc.lower() == "nan":
                    desc = ""
                entries.append((part, desc, group))
        return entries

    # Matches an "N/A QTY:34" (or just "QTY:34") cell in the Serial Number
    # column.  Some sites stock identical accessories — impedance panels,
    # blank face plates, surge protectors — that ship without per-unit serial
    # tracking, so a single row carries the rolled-up count for the BOM. The
    # scanner expands such rows into N entries so the aggregator counts the
    # full quantity instead of treating it as a single unit.
    _QTY_BUCKET_RE = re.compile(r"^\s*(?:N/?A\s+)?QTY\s*:?\s*(\d+)\s*$", re.IGNORECASE)

    def _expand_qty_buckets_on_sheet(
        self,
        ws: Any,
        start_row: int = 15,
        name_col: int = 2,
        type_col: int = 3,
        part_col: int = 4,
        serial_col: int = 5,
        desc_col: int = 6,
    ) -> int:
        """Rewrite any ``N/A QTY:N`` rows on *ws* into N individual rows,
        each carrying ``N/A`` in the Serial Number column. Returns the
        number of extra rows added (0 when no buckets were found).

        Done in-place on the sheet so the saved workbook itself shows the
        full equipment list rather than a bucket count — the operator sees
        the same row count they'd see if every unit had been entered
        individually to begin with.
        """
        last_row = ws.max_row or 0
        if last_row < start_row:
            return 0

        # Snapshot the data range so we can rewrite it without shifting
        # rows manually (openpyxl's insert/delete row shuffles formatting
        # in ways that are hard to predict on imported workbooks).
        end_col = max(name_col, type_col, part_col, serial_col, desc_col)
        existing: List[List[Any]] = []
        for r in range(start_row, last_row + 1):
            row_vals = [ws.cell(row=r, column=c).value for c in range(1, end_col + 1)]
            existing.append(row_vals)

        expanded: List[List[Any]] = []
        for row_vals in existing:
            serial_val = row_vals[serial_col - 1] if len(row_vals) >= serial_col else None
            part_val = row_vals[part_col - 1] if len(row_vals) >= part_col else None
            # Only treat a row as a QTY bucket when there's actually a
            # part number on it — otherwise the regex might fire on a
            # stray annotation cell.
            if part_val is not None and str(part_val).strip():
                m = self._QTY_BUCKET_RE.match(str(serial_val) if serial_val is not None else "")
                if m:
                    qty = max(0, int(m.group(1)))
                    new_vals = list(row_vals)
                    new_vals[serial_col - 1] = "N/A"
                    for _ in range(qty):
                        expanded.append(list(new_vals))
                    continue
            expanded.append(row_vals)

        # Row-count delta (positive = expanded buckets added rows,
        # negative = qty:0 buckets removed rows, zero = no change).
        delta = len(expanded) - len(existing)
        if delta == 0:
            return 0

        # Wipe the original data range and rewrite from start_row.
        for r in range(start_row, last_row + 1):
            for c in range(1, end_col + 1):
                ws.cell(row=r, column=c).value = None

        for offset, row_vals in enumerate(expanded):
            r = start_row + offset
            for c, v in enumerate(row_vals, start=1):
                if v is None:
                    continue
                ws.cell(row=r, column=c).value = v

        return delta

    # Column G on every device tab carries the asset tag the operator
    # typed into the Summary's "Asset Tag" column for that device row.
    # Kept off to the right of the BOM data columns (B-F) so it doesn't
    # collide with serial / part / description writes.
    _ASSET_TAG_COL_ON_DEVICE_TAB = 7  # G

    def read_asset_tags_from_summary(self, summary_sheet: Any) -> Dict[str, str]:
        """Read the operator-typed Asset Tag column off a Summary sheet.

        Returns ``{device_name: asset_tag}`` for every data row (10+) that
        has both a Device Name (column D) and a non-empty Asset Tag
        (column E). The device name is matched verbatim against device-tab
        sheet titles in the caller.
        """
        out: Dict[str, str] = {}
        last_row = summary_sheet.max_row or 0
        for r in range(10, last_row + 1):
            name_cell = summary_sheet.cell(row=r, column=4).value
            tag_cell = summary_sheet.cell(row=r, column=5).value
            if name_cell is None or tag_cell is None:
                continue
            name = str(name_cell).strip()
            tag = str(tag_cell).strip()
            if name and tag:
                out[name] = tag
        return out

    def write_asset_tag_to_chassis_row(
        self,
        ws: Any,
        asset_tag: str,
        start_row: int = 15,
        name_col: int = 2,
        type_col: int = 3,
        desc_col: int = 6,
    ) -> Optional[int]:
        """Stamp *asset_tag* on the device tab's chassis/shelf row.

        Searches rows from ``start_row`` onward for the first row whose
        Name / Type / Description cell looks like a chassis or shelf
        entry; if none matches, falls back to ``start_row`` so the tag
        still lands somewhere visible. Returns the row written to, or
        ``None`` if the sheet has no data rows at all.
        """
        last_row = ws.max_row or 0
        if last_row < start_row:
            return None

        target = None
        for r in range(start_row, last_row + 1):
            name = str(ws.cell(row=r, column=name_col).value or "").strip().lower()
            type_v = str(ws.cell(row=r, column=type_col).value or "").strip().lower()
            desc = str(ws.cell(row=r, column=desc_col).value or "").strip().lower()
            if any(kw in name for kw in ("chassis", "shelf")):
                target = r
                break
            if any(kw in type_v for kw in ("chassis", "shelf")):
                target = r
                break
            if any(kw in desc for kw in ("chassis", "shelf")):
                target = r
                break
        if target is None:
            target = start_row
        ws.cell(row=target, column=self._ASSET_TAG_COL_ON_DEVICE_TAB).value = asset_tag
        return target

    def propagate_asset_tags_to_tabs(
        self,
        wb: Any,
        display_to_tab: Optional[Dict[str, str]] = None,
    ) -> int:
        """Read the Summary's Asset Tag column and stamp each entry on the
        corresponding device tab. Returns the number of tabs updated.

        ``display_to_tab`` (optional) maps Summary's Device Name labels to
        the actual sheet title when they differ — e.g., "STJO Extra
        Materials" → "STJO". Falls back to using the display label as the
        tab name directly when not supplied.
        """
        if "Summary" not in wb.sheetnames:
            return 0
        tags = self.read_asset_tags_from_summary(wb["Summary"])
        if not tags:
            return 0
        updated = 0
        for display_name, tag in tags.items():
            tab = (display_to_tab or {}).get(display_name, display_name)
            if tab not in wb.sheetnames:
                continue
            try:
                self.write_asset_tag_to_chassis_row(wb[tab], tag)
                updated += 1
            except Exception:
                logging.exception(
                    f"[ASSET-TAG] Failed to write tag for tab '{tab}'"
                )
        return updated

    def ensure_return_link_in_a1(self, ws: Any, target_sheet: str = "BOM") -> bool:
        """Add (or refresh) a ``Return`` hyperlink in A1 pointing at
        *target_sheet* if the cell isn't already wired up that way.

        Spares-style workbooks come without per-tab Return links — adding
        one here keeps the device-report convention consistent across
        every tab the BOM builder touches. Returns True when the cell
        was modified."""
        cell = ws["A1"]
        if cell.value == "Return" and cell.hyperlink is not None:
            return False
        cell.value = "Return"
        cell.hyperlink = f"#'{target_sheet}'!A1"
        cell.style = "Hyperlink"
        return True

    def apply_device_data_borders(
        self,
        ws: Any,
        start_row: int = 15,
        first_col: int = 2,
        last_col: int = 6,
    ) -> int:
        """Apply thin borders to populated data rows on a device tab.

        Walks from *start_row* through ``ws.max_row`` and surrounds every
        row that has at least one non-empty cell in the data columns.
        Empty trailing rows stay borderless so the operator can still
        tell where the data ends.

        Returns the number of rows that received a border.
        """
        thin = Side(style="thin", color="888888")
        border = Border(left=thin, right=thin, top=thin, bottom=thin)
        last_row = ws.max_row or 0
        bordered = 0
        for r in range(start_row, last_row + 1):
            row_has_data = any(
                ws.cell(row=r, column=c).value not in (None, "")
                for c in range(first_col, last_col + 1)
            )
            if not row_has_data:
                continue
            for c in range(first_col, last_col + 1):
                ws.cell(row=r, column=c).border = border
            bordered += 1
        return bordered

    def _collect_bom_entries_from_sheet(
        self,
        ws: Any,
        start_row: int = 15,
        end_row: Optional[int] = None,
        part_col: int = 4,
        name_col: int = 2,
        type_col: int = 3,
        desc_col: int = 6,
        serial_col: int = 5,
    ) -> List[Tuple[str, str, str]]:
        """Scan a written device sheet for part rows when no source DataFrame is available.

        Used in append mode where existing tabs predate this run. Group is
        inferred heuristically from the Name/Type/Description cells since
        the original "Information Type" column isn't preserved on the
        rendered sheet.

        Rows whose Serial Number cell reads ``N/A QTY:<n>`` are expanded
        into ``n`` entries so the BOM aggregator surfaces the correct
        quantity for serial-less accessories (impedance panels, blanks,
        surge kits, etc.).
        """
        entries: List[Tuple[str, str, str]] = []
        last_row = ws.max_row or 0
        if end_row is None:
            end_row = last_row
        else:
            end_row = min(end_row, last_row)

        for r in range(start_row, end_row + 1):
            part_val = ws.cell(row=r, column=part_col).value
            if part_val is None:
                continue
            part = str(part_val).strip()
            if not part or part.lower() in ("nan", "unparsed"):
                continue
            name = str(ws.cell(row=r, column=name_col).value or "").strip().lower()
            type_v = str(ws.cell(row=r, column=type_col).value or "").strip().lower()
            desc_raw = str(ws.cell(row=r, column=desc_col).value or "").strip()
            desc = "" if desc_raw.lower() == "nan" else desc_raw
            desc_l = desc.lower()

            if (
                any(kw in type_v for kw in ("sfp", "xfp", "qsfp", "cfp", "transceiver", "optic"))
                or any(kw in desc_l for kw in ("sfp", "xfp", "qsfp", "transceiver"))
            ):
                group = "Optics"
            elif name.startswith("mda") or "card" in type_v or "mda" in type_v:
                group = "Cards"
            else:
                group = "Chassis/Shelf"

            # Detect "N/A QTY:N" buckets in the Serial Number column.  When
            # present, emit N copies of the entry so the BOM aggregator
            # surfaces the full quantity instead of one row.
            qty = 1
            serial_raw = ws.cell(row=r, column=serial_col).value
            if serial_raw is not None:
                m = self._QTY_BUCKET_RE.match(str(serial_raw))
                if m:
                    try:
                        qty = max(0, int(m.group(1)))
                    except ValueError:
                        qty = 1
            for _ in range(qty):
                entries.append((part, desc, group))
        return entries

    def normalize_long_part_numbers(
        self,
        bom_data: Dict[str, List[Tuple[str, str, str]]],
    ) -> int:
        """Clean and canonicalize part numbers across *bom_data*.

        Pipeline per entry:
          1. Strip any leading vendor prefix (``1P`` or ``P``) — these are
             packaging markers that physical scans tack onto the canonical
             part. Always applied so the trimmed PN is at most the
             canonical 10-char form.
          2. Take the first 10 chars and look the prefix up in the parts
             DB. On a real hit, replace the part number with that prefix
             and overwrite the description with the canonical DB text so
             the BOM aggregates consistently.
          3. If the DB has no entry but the strip changed the value, keep
             the cleaned form anyway so all entries enter the BOM with a
             consistent leading-character convention.

        Mutates *bom_data* in place. Returns the number of entries
        modified (either via DB hit or vendor-prefix strip).
        """
        try:
            db_path = self.db_cache.db_path
        except AttributeError:
            db_path = None

        prefix_re = re.compile(r"^(?:1P|P)")
        rewrites = 0
        for sheet_title, entries in bom_data.items():
            for i, (part, desc, group) in enumerate(entries):
                if not part:
                    continue
                stripped = prefix_re.sub("", part, count=1)
                candidate = stripped[:10]
                new_part, new_desc = part, desc

                if db_path and os.path.isfile(db_path):
                    try:
                        db_desc = self.db_cache.lookup_part(candidate)
                    except Exception as exc:
                        logging.debug(f"[BOM] lookup failed for {candidate!r}: {exc}")
                        db_desc = None
                    if db_desc and db_desc not in ("Not Found", "Invalid part number") and not db_desc.startswith("DB Error"):
                        new_part, new_desc = candidate, db_desc

                if new_part == part and stripped != part:
                    # No DB hit, but at least drop the vendor prefix so
                    # downstream aggregation/match is consistent.
                    new_part = stripped

                if new_part != part or new_desc != desc:
                    entries[i] = (new_part, new_desc, group)
                    rewrites += 1
        return rewrites

    def normalize_device_tab_part_numbers(
        self,
        wb: Any,
        skip_sheets: Tuple[str, ...] = ("Summary", "BOM"),
    ) -> int:
        """Apply the same 1P/P-strip + DB-lookup pipeline to every device tab.

        Locates the equipment table by finding a header row containing
        ``PART NUMBER`` (and optionally ``DESCRIPTION``) in the first 25
        rows, then walks each data row below it. The Serial Number
        column is intentionally never touched; only the part-number cell
        and (on a DB hit) the description cell are rewritten.

        Returns the total number of cells updated across all tabs.
        """
        try:
            db_path = self.db_cache.db_path
        except AttributeError:
            db_path = None
        if not db_path or not os.path.isfile(db_path):
            return 0

        prefix_re = re.compile(r"^(?:1P|P)")
        updates = 0

        for sname in wb.sheetnames:
            if sname in skip_sheets:
                continue
            ws = wb[sname]
            max_r = ws.max_row or 0
            max_c = ws.max_column or 0
            if max_r < 2 or max_c < 1:
                continue

            # Locate header row + part / description columns.
            pn_col = desc_col = header_row = None
            scan_limit = min(max_r, 25)
            for r in range(1, scan_limit + 1):
                for c in range(1, max_c + 1):
                    v = ws.cell(r, c).value
                    if v is None:
                        continue
                    label = str(v).strip().upper().replace("  ", " ")
                    if label == "PART NUMBER":
                        pn_col = c
                        header_row = r
                    elif label == "DESCRIPTION" and header_row == r:
                        desc_col = c
                if pn_col is not None:
                    break
            if pn_col is None or header_row is None:
                continue

            for r in range(header_row + 1, max_r + 1):
                cell = ws.cell(r, pn_col)
                v = cell.value
                if v is None:
                    continue
                part = str(v).strip()
                if not part:
                    continue
                stripped = prefix_re.sub("", part, count=1)
                candidate = stripped[:10]
                new_part = part
                new_desc = None
                try:
                    db_desc = self.db_cache.lookup_part(candidate)
                except Exception as exc:
                    logging.debug(f"[BOM] tab lookup failed for {candidate!r}: {exc}")
                    db_desc = None
                if db_desc and db_desc not in ("Not Found", "Invalid part number") and not db_desc.startswith("DB Error"):
                    new_part, new_desc = candidate, db_desc
                elif stripped != part:
                    new_part = stripped

                if new_part != part:
                    cell.value = new_part
                    updates += 1
                if new_desc is not None and desc_col is not None:
                    desc_cell = ws.cell(r, desc_col)
                    if str(desc_cell.value or "").strip() != new_desc:
                        desc_cell.value = new_desc
                        updates += 1
        return updates

    @staticmethod
    def retarget_return_links_to_bom(
        wb: Any,
        skip_sheets: Tuple[str, ...] = ("Summary", "BOM"),
    ) -> int:
        """Rewrite any Summary-targeted hyperlink on device tabs to point at BOM.

        Inventory workbooks built before the BOM existed leave each
        device tab with a "Return" hyperlink to ``Summary``. After we
        add a BOM the more useful jump is to BOM, so we walk the first
        few cells of each non-skipped sheet and retarget hyperlinks
        whose location resolves to the Summary sheet. Returns the
        number of links rewritten.
        """
        if "BOM" not in wb.sheetnames:
            return 0
        retargeted = 0
        for sname in wb.sheetnames:
            if sname in skip_sheets:
                continue
            ws = wb[sname]
            # Return links are conventionally near the top-left; scan a
            # small window rather than the whole sheet to keep this fast.
            max_r = min(ws.max_row or 0, 10)
            max_c = min(ws.max_column or 0, 10)
            for r in range(1, max_r + 1):
                for c in range(1, max_c + 1):
                    cell = ws.cell(r, c)
                    link = cell.hyperlink
                    if link is None:
                        continue
                    raw = link.location or link.target or ""
                    if "summary" not in str(raw).lower():
                        continue
                    cell.hyperlink = "#'BOM'!A1"
                    cell.style = "Hyperlink"
                    retargeted += 1
        return retargeted

    def _lookup_part_description(self, part_number: str, fallback: str = "") -> str:
        """Resolve a description for *part_number* via the cache, then SQLite."""
        if not part_number:
            return fallback
        try:
            db_path = self.db_cache.db_path
        except AttributeError:
            return fallback
        if not db_path or not os.path.isfile(db_path):
            return fallback

        try:
            cached = self.db_cache.lookup_part(part_number[:10])
        except Exception as exc:
            logging.debug(f"[BOM] cache lookup failed for {part_number!r}: {exc}")
            cached = None
        if cached and cached != "Not Found":
            return cached
        if fallback:
            return fallback
        try:
            with sqlite3.connect(db_path) as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT description FROM parts WHERE part_number LIKE ?",
                    (part_number[:10] + "%",),
                )
                res = cur.fetchone()
                if res and res[0] and res[0] != "Not Found":
                    return res[0]
        except Exception as exc:
            logging.debug(f"[BOM] fallback DB lookup failed for {part_number!r}: {exc}")
        return fallback

    @staticmethod
    def _site_group_key(site_title: str) -> Optional[str]:
        """Leading run of letters before the first digit, uppercased.

        STJO001_7250 -> ``STJO``; ``rls_2`` -> ``RLS``; ``6500_RLS_…`` -> ``None``.
        Used to roll multiple sub-systems at one location into a single
        location-total column on the BOM.
        """
        m = re.match(r"^([A-Za-z]+)", site_title or "")
        return m.group(1).upper() if m else None

    def _scan_existing_bom(
        self, ws: Any
    ) -> Dict[str, List[Tuple[str, str, str]]]:
        """Recover ``bom_data``-shaped entries from a previously-built BOM sheet.

        Lets the merge-in-place rebuild preserve quantities for sites whose
        device tabs are no longer present in the workbook.
        """
        result: Dict[str, List[Tuple[str, str, str]]] = {}
        hdr_row = None
        for r in range(1, 20):
            v = ws.cell(r, 1).value
            if v and str(v).strip().lower() == "item":
                hdr_row = r
                break
        if hdr_row is None:
            return result

        site_cols: Dict[str, int] = {}
        c = 4
        while c <= ws.max_column:
            h = ws.cell(hdr_row, c).value
            if h is None or str(h).strip() == "":
                break
            label = str(h).strip()
            if label.lower() == "total":
                break
            # Skip location-rollup columns (e.g. ``STJO``); they have no
            # ``Qty`` sub-header on the row below the site name.
            sub = ws.cell(hdr_row + 1, c).value
            if sub and str(sub).strip().lower() == "qty":
                site_cols[label] = c
            c += 1

        current_group: Optional[str] = None
        for r in range(hdr_row + 2, ws.max_row + 1):
            a = ws.cell(r, 1).value
            b = ws.cell(r, 2).value
            cval = ws.cell(r, 3).value
            if a and not b:
                current_group = str(a).strip()
                continue
            if not b:
                continue
            part = str(b).strip()
            desc = str(cval or "").strip()
            grp = current_group or "Cards"
            for st, col in site_cols.items():
                qv = ws.cell(r, col).value
                if isinstance(qv, (int, float)) and qv:
                    bucket = result.setdefault(st, [])
                    for _ in range(int(qv)):
                        bucket.append((part, desc, grp))
        return result

    def _build_bom_sheet(
        self,
        wb: Any,
        summary_items: List[Tuple[str, str, str]],
        bom_data: Dict[str, List[Tuple[str, str, str]]],
        display_to_tab: Optional[Dict[str, str]] = None,
    ) -> None:
        """Build (or replace) the aggregate BOM sheet at index 1 in *wb*.

        Layout
        ------
        Row 1 : Return hyperlink (A1) + title block ``Bill of Materials``
        Row 3 : ``Item`` | ``Part No.`` | ``Equipment Description`` |
                <site name>... | <location rollup>... | ``Total``
        Row 4 : (merged with row 3 for the first three cols) | ``Qty`` ...
        Row 5+: group banner row, then part rows sorted by total qty desc.

        Each Summary row contributes a site column (even with zero parts).
        Sites sharing a location key (leading-alpha prefix) are followed by
        a rollup column summing their quantities. Quantity cells link the
        BOM to the underlying device tab via the column header hyperlink.
        """
        # Merge-in-place: salvage entries from a previously-built BOM for
        # sites whose device tabs are missing from the current run, then
        # replace the sheet.
        if "BOM" in wb.sheetnames:
            try:
                salvaged = self._scan_existing_bom(wb["BOM"])
            except Exception as exc:
                logging.debug(f"[BOM] could not scan existing BOM for merge: {exc}")
                salvaged = {}
            for st, entries in salvaged.items():
                if st not in bom_data or not bom_data[st]:
                    bom_data[st] = entries
            del wb["BOM"]

        # Prefer copying the BOM template (carries title, fixed-column headers,
        # widths, freeze panes). Fall back to a programmatic scaffold if the
        # template is missing so installs without the file still produce a BOM.
        template_used = False
        bom_sheet = None
        if self.bom_template and os.path.exists(self.bom_template):
            try:
                tpl_wb = openpyxl.load_workbook(self.bom_template)
                try:
                    tpl_ws = tpl_wb.active
                    bom_sheet = self.copy_sheet(tpl_ws, wb, "BOM")
                    template_used = True
                finally:
                    tpl_wb.close()
            except Exception as exc:
                logging.warning(f"[BOM] Failed to load template {self.bom_template}: {exc}")

        if bom_sheet is None:
            bom_sheet = wb.create_sheet(title="BOM", index=1)

        # Move BOM to index 1 (right after Summary) regardless of where copy_sheet
        # appended it.
        if wb.sheetnames.index("BOM") != 1:
            idx = wb.sheetnames.index("BOM")
            wb._sheets.insert(1, wb._sheets.pop(idx))

        ordered_sites = sorted(
            summary_items, key=lambda item: extract_ip_sort_key(item[0])
        )
        site_titles = [t for (_, _, t) in ordered_sites]

        groups = ["Chassis/Shelf", "Cards", "Optics", "Additional Material"]
        agg: Dict[str, Dict[str, Dict[str, Any]]] = {g: {} for g in groups}
        # First sighting wins so a part number doesn't appear in two groups,
        # unless an explicit override from data/BOM_Categories_*.xlsx applies.
        part_to_group: Dict[str, str] = {}
        overrides = self.bom_part_overrides

        for sheet_title, entries in bom_data.items():
            for part, desc, group in entries:
                # Explicit per-part overrides win over heuristic classification
                # (e.g. RLS PIMs / access panels that aren't tagged as shelf
                # items in the source DataFrames).
                override = overrides.get(part.upper())
                if override:
                    group = override
                if group not in agg:
                    continue
                resolved = part_to_group.setdefault(part, group)
                bucket = agg[resolved].setdefault(
                    part, {"description": desc, "site_qty": {}}
                )
                if not bucket["description"] and desc:
                    bucket["description"] = desc
                bucket["site_qty"][sheet_title] = (
                    bucket["site_qty"].get(sheet_title, 0) + 1
                )

        # Fill in missing descriptions from the parts DB once per unique part.
        for grp in groups:
            for part, info in agg[grp].items():
                if not info["description"]:
                    info["description"] = self._lookup_part_description(part)

        accent_fill = PatternFill(start_color="FF0087FF", end_color="FF0087FF", fill_type="solid")
        group_fill = PatternFill(start_color="FF005EBA", end_color="FF005EBA", fill_type="solid")
        white_font = Font(color="FFFFFFFF", bold=True)
        bold_font = Font(bold=True)
        thin_side = Side(style="thin", color="FF7F7F7F")
        border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)
        center = Alignment(horizontal="center", vertical="center", wrap_text=True)
        left_align = Alignment(horizontal="left", vertical="center", wrap_text=True)

        # Layout when the BOM template is in use:
        #   Rows 1-5 : banner image (title "Factory Bill of Materials" baked in)
        #   Row 6    : Return link
        #   Rows 7-8 : Fixed-column headers (A-C merged) + site name row + Qty row
        #   Row 9+   : Section banners and data
        # When the template is missing, fall back to a compact layout without
        # the banner area: Return at A1, fixed headers at rows 2-3, data at row 4+.
        if template_used:
            return_row = 6
            site_header_row = 7
            qty_header_row = 8
            first_data_row = 9
        else:
            return_row = 1
            site_header_row = 2
            qty_header_row = 3
            first_data_row = 4

        bom_sheet.cell(row=return_row, column=1, value="Return")
        bom_sheet.cell(row=return_row, column=1).hyperlink = "#'Summary'!A1"
        bom_sheet.cell(row=return_row, column=1).style = "Hyperlink"

        # Build column layout: site columns grouped by location key, with a
        # rollup column inserted after each group of 2+ siblings, and a final
        # ``Total`` column at the far right.
        key_to_sites: Dict[Optional[str], List[str]] = {}
        group_order: List[Optional[str]] = []
        for st in site_titles:
            k = self._site_group_key(st)
            if k not in key_to_sites:
                key_to_sites[k] = []
                group_order.append(k)
            key_to_sites[k].append(st)

        site_col_idx: Dict[str, int] = {}
        rollup_col_idx: Dict[str, int] = {}
        col_cursor = 4
        for k in group_order:
            for st in key_to_sites[k]:
                site_col_idx[st] = col_cursor
                col_cursor += 1
            if k is not None and len(key_to_sites[k]) >= 2:
                rollup_col_idx[k] = col_cursor
                col_cursor += 1
        total_col_idx = col_cursor
        total_cols = total_col_idx

        # Fixed-column headers (A=Item, B=Part No., C=Equipment Description)
        # are styled by the template; only paint them programmatically when
        # the template wasn't available.
        if not template_used:
            fixed_headers = [(1, "Item"), (2, "Part No."), (3, "Equipment Description")]
            for col, label in fixed_headers:
                head = bom_sheet.cell(row=site_header_row, column=col, value=label)
                head.fill = accent_fill
                head.font = white_font
                head.alignment = center
                head.border = border
                sub = bom_sheet.cell(row=qty_header_row, column=col)
                sub.fill = accent_fill
                sub.border = border
                bom_sheet.merge_cells(
                    start_row=site_header_row, end_row=qty_header_row,
                    start_column=col, end_column=col,
                )

        site_palette = [
            "FFDA9694", "FFFCD5B4", "FFC4D79B", "FF95B3D7", "FFB1A0C7",
            "FFFFE699", "FFD9E1F2", "FFE2EFDA", "FFFFF2CC", "FFFCE4D6",
        ]
        for palette_idx, sheet_title in enumerate(site_titles):
            col = site_col_idx[sheet_title]
            color = site_palette[palette_idx % len(site_palette)]
            fill = PatternFill(start_color=color, end_color=color, fill_type="solid")
            head = bom_sheet.cell(row=site_header_row, column=col, value=sheet_title)
            head.fill = fill
            head.font = bold_font
            head.alignment = center
            head.border = border
            # Resolve to the actual data tab when the display name differs
            # (e.g. "STJO Extra Materials" → tab "STJO").
            target_tab = (display_to_tab or {}).get(sheet_title, sheet_title)
            if target_tab in wb.sheetnames:
                head.hyperlink = f"#'{target_tab}'!A1"
                head.style = "Hyperlink"
            qty = bom_sheet.cell(row=qty_header_row, column=col, value="Qty")
            qty.fill = fill
            qty.font = bold_font
            qty.alignment = center
            qty.border = border

        # Location rollup columns (e.g. ``STJO`` summing all STJOxxx_xxxx
        # sub-systems). Header is merged across the site/qty rows so the
        # location label reads as a single banner over the rollup formulas.
        rollup_fill = PatternFill(
            start_color="FFBDD7EE", end_color="FFBDD7EE", fill_type="solid"
        )
        for key, col in rollup_col_idx.items():
            head = bom_sheet.cell(row=site_header_row, column=col, value=key)
            head.fill = rollup_fill
            head.font = bold_font
            head.alignment = center
            head.border = border
            sub = bom_sheet.cell(row=qty_header_row, column=col)
            sub.fill = rollup_fill
            sub.border = border
            bom_sheet.merge_cells(
                start_row=site_header_row, end_row=qty_header_row,
                start_column=col, end_column=col,
            )

        # Totals column at the far right — row-wise sum across every site.
        # Styled in the darker brand-blue group color so it visually anchors
        # the right edge of the grid the same way the group banners anchor
        # the left edge.
        total_header_fill = PatternFill(
            start_color="FF005EBA", end_color="FF005EBA", fill_type="solid"
        )
        total_head = bom_sheet.cell(
            row=site_header_row, column=total_col_idx, value="Total"
        )
        total_head.fill = total_header_fill
        total_head.font = white_font
        total_head.alignment = center
        total_head.border = border
        total_sub = bom_sheet.cell(
            row=qty_header_row, column=total_col_idx, value="Qty"
        )
        total_sub.fill = total_header_fill
        total_sub.font = white_font
        total_sub.alignment = center
        total_sub.border = border

        current_row = first_data_row
        item_counter = 0

        for group_name in groups:
            items_for_group = agg.get(group_name) or {}
            if not items_for_group:
                continue

            # Section banner confined to the A-C "label box". Site columns
            # on this row stay blank so the right panel reads as a clean grid.
            bom_sheet.merge_cells(
                start_row=current_row, end_row=current_row,
                start_column=1, end_column=3,
            )
            banner = bom_sheet.cell(row=current_row, column=1, value=group_name)
            banner.fill = group_fill
            banner.font = white_font
            banner.alignment = center
            for c in range(1, 4):
                bom_sheet.cell(row=current_row, column=c).border = border
            current_row += 1

            sorted_items = sorted(
                items_for_group.items(),
                key=lambda kv: (-sum(kv[1]["site_qty"].values()), kv[0]),
            )
            for part_no, info in sorted_items:
                item_counter += 1
                bom_sheet.cell(row=current_row, column=1, value=item_counter).alignment = center
                pn_cell = bom_sheet.cell(
                    row=current_row, column=2, value=self._sanitize_cell(part_no)
                )
                pn_cell.alignment = center
                pn_cell.font = bold_font
                bom_sheet.cell(
                    row=current_row, column=3, value=self._sanitize_cell(info["description"])
                ).alignment = left_align

                site_qty = info["site_qty"]
                for st in site_titles:
                    qty = site_qty.get(st, 0)
                    cell = bom_sheet.cell(
                        row=current_row, column=site_col_idx[st], value=qty or None
                    )
                    cell.alignment = center

                # Location rollup formulas — sum sibling site columns sharing
                # the location key. Always contiguous because we ordered the
                # site columns by group above.
                for key, rcol in rollup_col_idx.items():
                    sibs = key_to_sites[key]
                    first_letter = get_column_letter(site_col_idx[sibs[0]])
                    last_letter = get_column_letter(site_col_idx[sibs[-1]])
                    rcell = bom_sheet.cell(
                        row=current_row, column=rcol,
                        value=f"=SUM({first_letter}{current_row}:{last_letter}{current_row})",
                    )
                    rcell.alignment = center
                    rcell.font = bold_font

                # Grand total — SUM only the site columns, skipping the
                # rollup columns so location subtotals aren't double-counted.
                if site_titles:
                    site_refs = ",".join(
                        f"{get_column_letter(site_col_idx[st])}{current_row}"
                        for st in site_titles
                    )
                    total_formula = f"=SUM({site_refs})"
                    total_cell = bom_sheet.cell(
                        row=current_row, column=total_col_idx, value=total_formula
                    )
                else:
                    total_cell = bom_sheet.cell(
                        row=current_row, column=total_col_idx, value=0
                    )
                total_cell.alignment = center
                total_cell.font = bold_font

                for c in range(1, total_cols + 1):
                    bom_sheet.cell(row=current_row, column=c).border = border
                current_row += 1

        # Freeze just below the header rows so the banner + headers stay
        # visible while scrolling through long part lists.
        bom_sheet.freeze_panes = f"D{first_data_row}"
        self.autosize_sheet_columns(bom_sheet, min_width=8, max_width=50)

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
            bom_data: Dict[str, List[Tuple[str, str, str]]] = {}

            if "Summary" in wb.sheetnames:
                summary_sheet = wb["Summary"]
            else:
                summary_sheet = wb.create_sheet(title="Summary", index=0)

            # name_index lets us dedupe Serial-mode rescans by device hostname
            # rather than by the port string ("COM3"), which would otherwise
            # collapse every device ever scanned through the same port.
            name_index: Dict[str, Tuple[str, str]] = {}
            if append_mode:
                # Read existing devices directly from their sheets (F5=IP, F6=device name).
                # This is more reliable than parsing Summary rows, which can become stale
                # after a partial run leaves rows with orphaned hyperlinks and no IP values.
                for sname in wb.sheetnames:
                    if sname == "Summary":
                        continue
                    try:
                        ws = wb[sname]
                        ip_val = ws["F5"].value
                        name_val = ws["F6"].value
                        if ip_val is None or name_val is None:
                            continue
                        ip_str = str(ip_val).strip()
                        name_str = str(name_val).strip()
                        if not ip_str or ip_str.lower() == "nan":
                            continue
                        summary_index[ip_str] = (name_str, sname)
                        if name_str:
                            name_index[name_str.lower()] = (ip_str, sname)
                    except Exception as _exc:
                        logging.debug(f"[EXCEL] Could not read device info from sheet '{sname}': {_exc}")

            # Snapshot of pre-existing IPs so we can detect whether this run
            # added new sites and stamp an "Additional Capture" timestamp.
            pre_existing_ips = set(summary_index.keys())

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
                new_sheet = None
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

                    # Un-provisioned shelves report a bare platform default
                    # (e.g. Ciena RLS ships as "rls"), which would collapse
                    # every device onto rls / rls_2 / rls_3 tabs and BoM
                    # columns. Swap in the chassis serial so each device is
                    # individually identifiable until the operator sets a
                    # real hostname.
                    _default_prefix = _FACTORY_DEFAULT_HOSTNAMES.get(
                        system_name.strip().lower()
                    )
                    if _default_prefix:
                        chassis_serial = _chassis_serial_from_df(combined_df)
                        if chassis_serial:
                            system_name = (
                                f"{_default_prefix}-{chassis_serial}"
                            )[:31].replace(":", "_").replace("/", "_")
                            logging.info(
                                f"Bare default hostname detected for IP {ip}; "
                                f"using chassis serial fallback '{system_name}'."
                            )

                    source_val = clean_str(first_nonempty(combined_df.get("Source"), ""))

                    logging.info(f"Creating sheet for system '{system_name}' with {len(combined_df)} rows.")
                    ip_key = str(ip)
                    prior_sheet_title = None
                    if append_mode:
                        # Prefer hostname match: handles Serial mode (where the
                        # "IP" is a COM port shared across devices) and LAN mode
                        # cases where multiple devices reuse the same mgmt IP.
                        hit = name_index.get(system_name.strip().lower())
                        if hit:
                            prior_ip, prior_sheet_title = hit
                            if prior_ip != ip_key:
                                summary_index.pop(prior_ip, None)
                        elif ip_key in summary_index:
                            prior_sheet_title = summary_index[ip_key][1]

                    new_sheet_title = make_unique_sheet_title(system_name)
                    new_sheet = self.copy_sheet(template_sheet, wb, new_sheet_title)

                    # Quick navigation back to the BOM (one click from any
                    # device tab into the aggregate view).
                    new_sheet["A1"] = "Return"
                    new_sheet["A1"].hyperlink = "#'BOM'!A1"
                    new_sheet["A1"].style = "Hyperlink"

                    new_sheet["C5"] = customer
                    new_sheet["C6"] = project
                    new_sheet["C7"] = customer_po
                    new_sheet["D7"] = sales_order
                    new_sheet["F5"] = source_val
                    new_sheet["F6"] = self._sanitize_cell(system_name)
                    new_sheet["F7"] = self._sanitize_cell(system_type)

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
                            name_value = f"MDA {name_value}" if name_value else "MDA"

                        type_value = clean_str(row.get("Type", ""))
                        serial_val = clean_str(row.get("Serial Number", ""))

                        if not any([name_value, type_value, part_number, serial_val]):
                            continue

                        description = clean_str(row.get("Description", ""))
                        if part_number and db_exists:
                            db_description = self.db_cache.lookup_part(part_number[:10])
                            if db_description and db_description != "Not Found":
                                description = db_description
                            elif not description:
                                try:
                                    with sqlite3.connect(self.db_cache.db_path) as tmpconn:
                                        tcur = tmpconn.cursor()
                                        tcur.execute(
                                            "SELECT description FROM parts WHERE part_number LIKE ?",
                                            (part_number[:10] + "%",),
                                        )
                                        res = tcur.fetchone()
                                        if res and res[0] and res[0] != "Not Found":
                                            description = res[0]
                                except Exception as exc:
                                    logging.debug(f"[EXCEL] Fallback DB lookup failed: {exc}")

                        new_sheet[f"B{row_num}"] = self._sanitize_cell(name_value)
                        new_sheet[f"C{row_num}"] = self._sanitize_cell(type_value)
                        new_sheet[f"D{row_num}"] = self._sanitize_cell(part_number)
                        new_sheet[f"E{row_num}"] = self._sanitize_cell(serial_val)
                        new_sheet[f"F{row_num}"] = self._sanitize_cell(description)
                        write_df.at[row.name, "Description"] = description

                    self.autosize_sheet_columns(new_sheet)
                    # Freeze the header block (rows 1-14) so it stays visible
                    # while the equipment list (row 15+) scrolls.
                    new_sheet.freeze_panes = "A15"
                    # Borders around every populated data row so the
                    # equipment list reads as a table rather than free text.
                    self.apply_device_data_borders(new_sheet)

                    if prior_sheet_title and prior_sheet_title in wb.sheetnames and prior_sheet_title != summary_sheet.title:
                        del wb[prior_sheet_title]

                    if prior_sheet_title and new_sheet.title != system_name and system_name not in wb.sheetnames:
                        new_sheet.title = system_name

                    processed_data[ip] = write_df
                    summary_index[str(ip)] = (system_name, new_sheet.title)
                    bom_data[new_sheet.title] = self._collect_bom_entries_from_df(write_df)
                except Exception as exc:
                    logging.error(f"Failed to process data for IP {ip}. Error: {exc}")
                    if new_sheet is not None and new_sheet.title in wb.sheetnames:
                        del wb[new_sheet.title]

            if summary_sheet.max_row >= 10:
                for row_num in range(10, summary_sheet.max_row + 1):
                    for col in ("B", "C", "D"):
                        cell = summary_sheet[f"{col}{row_num}"]
                        cell.value = None
                        cell.hyperlink = None

            # Populate summary table using shared helper (also sets the correct device count).
            summary_items = [(ip, device_name, sheet_title) for ip, (device_name, sheet_title) in summary_index.items()]
            self._populate_summary_table(summary_sheet, summary_items, start_row=10)

            if not append_mode and sheet and sheet.title in wb.sheetnames:
                wb.remove(sheet)

            # In append mode, scan any existing device sheets we didn't touch
            # this run so their parts still appear in the BOM aggregate.
            for _, _, sheet_title in summary_items:
                if sheet_title in bom_data or sheet_title not in wb.sheetnames:
                    continue
                try:
                    bom_data[sheet_title] = self._collect_bom_entries_from_sheet(wb[sheet_title])
                except Exception as exc:
                    logging.debug(f"[BOM] Could not scan existing sheet '{sheet_title}': {exc}")

            self._build_bom_sheet(wb, summary_items, bom_data)

            # If new sites landed during this run, stamp Summary col A so
            # the workbook carries an audit trail of when each batch was
            # added. The original Capture Time stays where it is.
            new_ips = [ip for ip in summary_index if ip not in pre_existing_ips]
            if new_ips and pre_existing_ips:
                self._append_summary_timestamp(summary_sheet, "Additional Capture")

            # Keep tabs ordered by IP sequence, with Summary first, BOM second.
            ordered_summary_items = sorted(summary_items, key=lambda item: extract_ip_sort_key(item[0]))
            ordered_device_tabs = [sheet_title for (_, _, sheet_title) in ordered_summary_items if sheet_title in wb.sheetnames]
            pinned_tabs = [summary_sheet.title, "BOM"] + ordered_device_tabs
            remaining_tabs = [name for name in wb.sheetnames if name not in pinned_tabs]
            ordered_tabs = pinned_tabs + remaining_tabs
            wb._sheets = [wb[name] for name in ordered_tabs]

            save_dir = os.path.dirname(output_file)
            os.makedirs(save_dir, exist_ok=True)
            self.autosize_workbook_columns(wb)
            # Pick up any operator-entered Asset Tag values from Summary E10+
            # and stamp them onto each device tab's Chassis/Shelf row. Useful
            # in append_mode against a workbook the operator has already
            # filled in; on a fresh first run the column is empty (no-op).
            try:
                self.propagate_asset_tags_to_tabs(wb)
            except Exception:
                logging.exception("[ASSET-TAG] propagation failed during inventory save")
            wb.save(output_file)
            logging.info(f"Data successfully saved to {output_file}")
            template_wb.close()
            return processed_data
        finally:
            self._export_running = False

    # ------------------------------------------------------------------
    # Packing slip workbook
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Nokia PSI report workbook
    # ------------------------------------------------------------------

    def build_psi_report_workbook(
        self,
        outputs: Dict[str, Any],
        output_file: str,
        customer: str = "",
        project: str = "",
        customer_po: str = "",
        sales_order: str = "",
        append_mode: bool = False,
        psi_template_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build a Nokia PSI inventory report using the PSI-specific template.

        Template row layout
        -------------------
        15  - 54  : Equipment inventory (shelf / card / module)
        62  - 71  : Software information
        74  - 103 : Slot status
        106 - 115 : Redundancy information
        118 - 127 : Power feed status
        130 - 169 : Interface topology
        """
        if psi_template_path is None:
            psi_template_path = os.path.join(
                os.path.dirname(self.template_path), "Nokia_PSI_Report_Template.xlsx"
            )
        if not os.path.exists(psi_template_path):
            raise FileNotFoundError(f"PSI template not found at {psi_template_path}")

        template_wb = openpyxl.load_workbook(psi_template_path)
        template_sheet = template_wb.active

        if append_mode and os.path.exists(output_file):
            wb = openpyxl.load_workbook(output_file)
            base_sheet = None
        else:
            wb = openpyxl.load_workbook(psi_template_path)
            base_sheet = wb.active

        summary_sheet = (
            wb["Summary"] if "Summary" in wb.sheetnames
            else wb.create_sheet(title="Summary", index=0)
        )
        self._setup_summary_sheet_header(summary_sheet, customer, project, list(outputs.keys()))

        def _s(v):
            if v is None:
                return ""
            s = str(v).strip()
            return "" if s.lower() == "nan" else s

        def _first(series, fallback=""):
            if series is None:
                return fallback
            for v in series:
                s = _s(v)
                if s:
                    return s
            return fallback

        def _df(entry) -> pd.DataFrame:
            if isinstance(entry, dict) and "DataFrame" in entry:
                return entry["DataFrame"]
            if isinstance(entry, pd.DataFrame):
                return entry
            return pd.DataFrame()

        sanitize = self._sanitize_cell

        def _wr(ws, r, b="", c="", d="", e="", f=""):
            ws[f"B{r}"] = sanitize(b)
            ws[f"C{r}"] = sanitize(c)
            ws[f"D{r}"] = sanitize(d)
            ws[f"E{r}"] = sanitize(e)
            ws[f"F{r}"] = sanitize(f)

        def _write_inventory(ws, df, start=15, end=54):
            for i, (_, row) in enumerate(df.iterrows()):
                r = start + i
                if r > end:
                    break
                _wr(ws, r,
                    b=_s(row.get("Name", "")),
                    c=_s(row.get("Type", "")),
                    d=_s(row.get("Part Number", "")),
                    e=_s(row.get("Serial Number", "")),
                    f=_s(row.get("Description", "")),
                )

        def _write_software(ws, df, start=62, end=71):
            for i, (_, row) in enumerate(df.iterrows()):
                r = start + i
                if r > end:
                    break
                desc = _s(row.get("Description", ""))
                m = re.search(r"RPMS Loaded:\s*(\S+)\s*/\s*(\S+)", desc)
                _wr(ws, r,
                    b=_s(row.get("Name", "")),
                    c=_s(row.get("Part Number", "")),
                    d=m.group(1) if m else "",
                    e=m.group(2) if m else "",
                )

        def _write_slot(ws, df, start=74, end=103):
            for i, (_, row) in enumerate(df.iterrows()):
                r = start + i
                if r > end:
                    break
                desc = _s(row.get("Description", ""))
                m = re.search(r"Admin:\s*(\S+)\s*\|\s*Oper:\s*(\S+)(?:\s*\|\s*(.+))?", desc)
                admin_state = m.group(1) if m else ""
                oper_state = m.group(2) if m else ""
                qualifier = m.group(3).strip() if m and m.group(3) else ""
                _wr(ws, r,
                    b=_s(row.get("Name", "")),
                    c=_s(row.get("Part Number", "")),
                    d=_s(row.get("Present Type", "")),
                    e=admin_state,
                    f=f"{oper_state}{' | ' + qualifier if qualifier else ''}",
                )

        def _write_redundancy(ws, df, start=106, end=115):
            for i, (_, row) in enumerate(df.iterrows()):
                r = start + i
                if r > end:
                    break
                desc = _s(row.get("Description", ""))
                m_c = re.search(r"Clock Switch:\s*(\S+)", desc)
                m_e = re.search(r"EC Selection:\s*(\S+)", desc)
                _wr(ws, r,
                    b=_s(row.get("Name", "")),
                    c=m_c.group(1) if m_c else "",
                    d=m_e.group(1) if m_e else "",
                )

        def _write_power(ws, df, start=118, end=127):
            for i, (_, row) in enumerate(df.iterrows()):
                r = start + i
                if r > end:
                    break
                desc = _s(row.get("Description", ""))
                m_a = re.search(r"Admin:\s*(\S+)", desc)
                m_o = re.search(r"Oper:\s*(\S+)", desc)
                _wr(ws, r,
                    b=_s(row.get("Name", "")),
                    c=_s(row.get("Type", "")),
                    d=m_a.group(1) if m_a else "",
                    e=m_o.group(1) if m_o else "",
                )

        def _write_topology(ws, df, start=130, end=169):
            for i, (_, row) in enumerate(df.iterrows()):
                r = start + i
                if r > end:
                    break
                desc = _s(row.get("Description", ""))
                m_c = re.search(r"Connected To:\s*(\S+)", desc)
                m_f = re.search(r"From:\s*(\S+)", desc)
                _wr(ws, r,
                    b=_s(row.get("Name", "")),
                    c=_s(row.get("Type", "")),
                    d=m_c.group(1) if m_c else "",
                    e=m_f.group(1) if m_f else "",
                )

        processed_data: Dict[str, Any] = {}
        summary_index: Dict[str, tuple] = {}
        bom_data: Dict[str, List[Tuple[str, str, str]]] = {}

        def _unique_title(base):
            clean = re.sub(r"[^a-zA-Z0-9_]", "_", str(base).strip())[:31] or "Device"
            if clean not in wb.sheetnames:
                return clean
            n = 2
            while True:
                suf = f"_{n}"
                cand = f"{clean[:31 - len(suf)]}{suf}"
                if cand not in wb.sheetnames:
                    return cand
                n += 1

        for ip, data_dict in sorted(outputs.items(), key=lambda x: extract_ip_sort_key(x[0])):
            try:
                system_name = system_type = source_val = ""
                for key in ("shelf_detail", "shelf_inventory", "card_inventory"):
                    entry = data_dict.get(key)
                    if entry:
                        df = _df(entry)
                        if not df.empty:
                            if not system_name:
                                system_name = _s(_first(df.get("System Name")))
                            if not system_type:
                                system_type = _s(_first(df.get("System Type")))
                            if not source_val:
                                source_val = _s(_first(df.get("Source"), str(ip)))
                    if system_name:
                        break
                if not system_name:
                    system_name = f"PSI_{ip.replace('.', '_')}"
                if not source_val:
                    source_val = str(ip)

                _default_prefix = _FACTORY_DEFAULT_HOSTNAMES.get(
                    system_name.strip().lower()
                )
                if _default_prefix:
                    chassis_serial = ""
                    for key in ("shelf_inventory", "shelf_detail", "card_inventory"):
                        df_chk = _df(data_dict.get(key))
                        chassis_serial = _chassis_serial_from_df(df_chk)
                        if chassis_serial:
                            break
                    if chassis_serial:
                        system_name = (
                            f"{_default_prefix}-{chassis_serial}"
                        )[:31].replace(":", "_").replace("/", "_")
                        logging.info(
                            f"Bare default hostname detected for IP {ip}; "
                            f"using chassis serial fallback '{system_name}'."
                        )

                title = _unique_title(system_name)
                if append_mode:
                    ns = self.copy_sheet(template_sheet, wb, title)
                else:
                    ns = wb.copy_worksheet(base_sheet)
                    ns.title = title

                ns["A1"] = "Return"
                ns["A1"].hyperlink = "#'BOM'!A1"
                ns["A1"].style = "Hyperlink"
                ns["C5"] = customer
                ns["C6"] = project
                ns["C7"] = customer_po
                ns["D7"] = sales_order
                ns["F5"] = source_val
                ns["F6"] = self._sanitize_cell(system_name)
                ns["F7"] = self._sanitize_cell(system_type)

                shelf_detail_df = _df(data_dict.get("shelf_detail"))
                shelf_inventory_df = _df(data_dict.get("shelf_inventory")).copy()
                card_inventory_df = _df(data_dict.get("card_inventory"))
                module_inventory_df = _df(data_dict.get("module_inventory"))

                inv_parts = []
                if not shelf_inventory_df.empty:
                    if not shelf_detail_df.empty:
                        main_shelf_name = _s(_first(shelf_detail_df.get("Name"), "Main Shelf"))
                        mask = shelf_inventory_df.get("Type", pd.Series(dtype=str)).astype(str).str.strip().eq("Shelf")
                        if mask.any():
                            shelf_row_index = shelf_inventory_df[mask].index[0]
                            shelf_inventory_df.at[shelf_row_index, "Name"] = main_shelf_name
                    inv_parts.append(shelf_inventory_df)
                elif not shelf_detail_df.empty:
                    inv_parts.append(shelf_detail_df)

                for df in (card_inventory_df, module_inventory_df):
                    if not df.empty:
                        inv_parts.append(df)

                if inv_parts:
                    _write_inventory(ns, pd.concat(inv_parts, ignore_index=True))

                _write_software(ns, _df(data_dict.get("software_info")))
                _write_slot(ns, _df(data_dict.get("slot_info")))
                _write_redundancy(ns, _df(data_dict.get("redundancy_info")))
                _write_power(ns, _df(data_dict.get("power_info")))
                _write_topology(ns, _df(data_dict.get("topology")))

                self.autosize_sheet_columns(ns)
                # Freeze the header block (rows 1-14) so it stays visible
                # while the equipment list (row 15+) scrolls.
                ns.freeze_panes = "A15"
                # Borders around every populated data row so the equipment
                # list reads as a table rather than free text.
                self.apply_device_data_borders(ns)
                summary_index[str(ip)] = (system_name, title)
                processed_data[ip] = pd.DataFrame()
                bom_data[title] = self._collect_bom_entries_from_psi_data(data_dict)

            except Exception as exc:
                logging.error(f"PSI report: failed for IP {ip}: {exc}", exc_info=True)

        items = [(ip, n, t) for ip, (n, t) in summary_index.items()]
        self._populate_summary_table(summary_sheet, items, start_row=10)

        if not append_mode and base_sheet and base_sheet.title in wb.sheetnames and len(wb.sheetnames) > 1:
            wb.remove(base_sheet)

        # In append mode, pull part rows from any pre-existing PSI device
        # sheets so the BOM still represents the whole workbook. PSI inventory
        # lives at rows 15-54 with Part Number in column D, same layout as the
        # standard report so the generic scanner works.
        for _, _, sheet_title in items:
            if sheet_title in bom_data or sheet_title not in wb.sheetnames:
                continue
            try:
                bom_data[sheet_title] = self._collect_bom_entries_from_sheet(
                    wb[sheet_title], start_row=15, end_row=54
                )
            except Exception as exc:
                logging.debug(f"[BOM] Could not scan existing PSI sheet '{sheet_title}': {exc}")

        self._build_bom_sheet(wb, items, bom_data)

        ordered = [summary_sheet.title, "BOM"] + [
            t for _, _, t in sorted(items, key=lambda x: extract_ip_sort_key(x[0]))
            if t in wb.sheetnames
        ]
        ordered = [n for n in ordered if n in wb.sheetnames]
        remaining = [n for n in wb.sheetnames if n not in ordered]
        wb._sheets = [wb[n] for n in ordered + remaining]

        save_dir = os.path.dirname(output_file)
        if save_dir:
            os.makedirs(save_dir, exist_ok=True)
        self.autosize_workbook_columns(wb)
        try:
            self.propagate_asset_tags_to_tabs(wb)
        except Exception:
            logging.exception("[ASSET-TAG] propagation failed during PSI save")
        wb.save(output_file)
        logging.info(f"PSI report saved: {output_file}")
        template_wb.close()
        return processed_data

    # ------------------------------------------------------------------
    # Unified multi-template workbook
    # ------------------------------------------------------------------

    def build_unified_report_workbook(
        self,
        family_buckets: Dict[str, Dict[str, Any]],
        output_file: str,
        customer: str = "",
        project: str = "",
        customer_po: str = "",
        sales_order: str = "",
        append_mode: bool = False,
        rls_template_path: Optional[str] = None,
        psi_template_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build a single workbook containing per-device sheets from multiple
        template families.

        ``family_buckets`` maps a family key (``"rls"``, ``"psi"``,
        ``"default"``) to ``{ip: device_outputs}``. Each non-empty bucket is
        first rendered to a temporary workbook by the appropriate
        family-specific builder, then their device sheets are merged into a
        single output workbook with one unified Summary sheet.
        """
        # 1. Render each family to a temp file using the existing builders.
        non_empty: Dict[str, Dict[str, Any]] = {
            fam: ips for fam, ips in family_buckets.items() if ips
        }
        if not non_empty:
            logging.warning("build_unified_report_workbook: no devices to write.")
            return {}

        common = dict(
            customer=customer,
            project=project,
            customer_po=customer_po,
            sales_order=sales_order,
            append_mode=False,  # always build temp wbs from scratch
        )

        tempdir = tempfile.mkdtemp(prefix="atlas_unified_")
        family_files: Dict[str, str] = {}
        processed_all: Dict[str, Any] = {}

        try:
            for fam, ips in non_empty.items():
                tmp_path = os.path.join(tempdir, f"{fam}.xlsx")
                if fam == "rls":
                    pd_part = self.build_psi_report_workbook(
                        ips, tmp_path,
                        psi_template_path=rls_template_path or psi_template_path,
                        **common,
                    )
                elif fam == "psi":
                    pd_part = self.build_psi_report_workbook(
                        ips, tmp_path,
                        psi_template_path=psi_template_path,
                        **common,
                    )
                else:
                    pd_part = self.build_report_workbook(ips, tmp_path, **common)
                processed_all.update(pd_part or {})
                family_files[fam] = tmp_path

            # 2. Pick a base workbook to merge into. Order: default, psi, rls
            # so the chrome (theme/styles) of the standard report wins when
            # available — matches existing single-family behavior.
            order = [f for f in ("default", "psi", "rls") if f in family_files]
            base_fam = order[0]
            base_path = family_files[base_fam]

            # If append_mode and the output file already exists, load it as
            # the base instead so we extend the existing report.
            if append_mode and os.path.exists(output_file):
                wb = openpyxl.load_workbook(output_file)
            else:
                wb = openpyxl.load_workbook(base_path)

            # The base family wb carries its own BOM tab; drop it so we can
            # build a single unified one covering devices across all families.
            if "BOM" in wb.sheetnames:
                del wb["BOM"]

            # Collect (ip, device_name, sheet_title) entries from each family
            # by scanning each family wb's Summary sheet.
            unified_summary: List[Tuple[str, str, str]] = []

            def _scan_family_summary(src_wb) -> List[Tuple[str, str, str]]:
                items: List[Tuple[str, str, str]] = []
                if "Summary" not in src_wb.sheetnames:
                    return items
                ss = src_wb["Summary"]
                for r in range(10, ss.max_row + 1):
                    ip_val = ss[f"C{r}"].value
                    name_val = ss[f"D{r}"].value
                    if ip_val is None or name_val is None:
                        continue
                    ip_s = str(ip_val).strip()
                    name_s = str(name_val).strip()
                    if not ip_s:
                        continue
                    target = ""
                    hl = ss[f"D{r}"].hyperlink
                    if hl and hl.target:
                        m = re.match(r"#'(.+?)'!", str(hl.target))
                        if m:
                            target = m.group(1)
                    if not target:
                        target = name_s[:31]
                    items.append((ip_s, name_s, target))
                return items

            # Seed unified summary with whatever's already in the base wb.
            unified_summary.extend(_scan_family_summary(wb))

            existing_titles = set(wb.sheetnames)

            def _unique_title(base):
                clean = re.sub(r"[^a-zA-Z0-9_]", "_", str(base).strip())[:31] or "Device"
                if clean not in existing_titles:
                    return clean
                n = 2
                while True:
                    suf = f"_{n}"
                    cand = f"{clean[:31 - len(suf)]}{suf}"
                    if cand not in existing_titles:
                        return cand
                    n += 1

            # 3. Merge sheets from the other family workbooks into wb.
            for fam in order[1:]:
                src_path = family_files[fam]
                src_wb = openpyxl.load_workbook(src_path)
                try:
                    src_items = _scan_family_summary(src_wb)
                    for ip_s, name_s, src_title in src_items:
                        if src_title not in src_wb.sheetnames:
                            logging.warning(
                                f"Unified merge: source sheet '{src_title}' missing in {fam} wb; skipping IP {ip_s}."
                            )
                            continue
                        new_title = _unique_title(src_title)
                        new_sheet = self.copy_sheet(src_wb[src_title], wb, new_title)
                        existing_titles.add(new_title)
                        # Repoint the per-sheet "Return" hyperlink to the
                        # unified BOM (one click from any device tab into the
                        # aggregate view; BOM is created at the end of the
                        # unified build).
                        try:
                            if new_sheet["A1"].value == "Return":
                                new_sheet["A1"].hyperlink = "#'BOM'!A1"
                        except Exception:
                            pass
                        unified_summary.append((ip_s, name_s, new_title))
                finally:
                    src_wb.close()

            # 4. Rebuild Summary in the unified wb covering all devices.
            if "Summary" in wb.sheetnames:
                summary_sheet = wb["Summary"]
                # Clear prior table rows (10+) so we don't double-populate.
                for r in range(10, summary_sheet.max_row + 1):
                    for col in ("B", "C", "D"):
                        cell = summary_sheet[f"{col}{r}"]
                        cell.value = None
                        cell.hyperlink = None
            else:
                summary_sheet = wb.create_sheet(title="Summary", index=0)

            # Move Summary to front.
            if wb.sheetnames[0] != "Summary":
                wb._sheets.insert(0, wb._sheets.pop(wb.sheetnames.index("Summary")))

            all_ips = list({ip for ip in (it[0] for it in unified_summary)})
            self._setup_summary_sheet_header(summary_sheet, customer, project, all_ips)
            self._populate_summary_table(summary_sheet, unified_summary, start_row=10)

            # Build a unified BOM by re-collecting from each family's raw
            # outputs and mapping each IP onto the post-merge sheet title.
            ip_to_title: Dict[str, str] = {str(ip): title for ip, _, title in unified_summary}
            unified_bom_data: Dict[str, List[Tuple[str, str, str]]] = {}
            for fam, ips in non_empty.items():
                for ip, data_dict in ips.items():
                    title = ip_to_title.get(str(ip))
                    if not title:
                        continue
                    if fam in ("psi", "rls"):
                        entries = self._collect_bom_entries_from_psi_data(data_dict)
                    else:
                        # Default family: processed_all has the write_df with
                        # "Information Type" preserved.
                        df = processed_all.get(ip)
                        entries = self._collect_bom_entries_from_df(df)
                    if entries:
                        unified_bom_data.setdefault(title, []).extend(entries)

            # In append mode, scan any pre-existing device sheets that didn't
            # come from this run so their parts still appear in the BOM.
            for _, _, title in unified_summary:
                if title in unified_bom_data or title not in wb.sheetnames:
                    continue
                try:
                    unified_bom_data[title] = self._collect_bom_entries_from_sheet(
                        wb[title], start_row=15
                    )
                except Exception as exc:
                    logging.debug(f"[BOM] Could not scan existing unified sheet '{title}': {exc}")

            self._build_bom_sheet(wb, unified_summary, unified_bom_data)

            # Order device sheets by IP for predictable layout (BOM pinned 2nd).
            ordered_titles = [t for _, _, t in sorted(unified_summary, key=lambda x: extract_ip_sort_key(x[0])) if t in wb.sheetnames]
            pinned = ["Summary"] + (["BOM"] if "BOM" in wb.sheetnames else [])
            remaining = [n for n in wb.sheetnames if n not in pinned and n not in ordered_titles]
            wb._sheets = [wb[n] for n in pinned] + [wb[t] for t in ordered_titles] + [wb[n] for n in remaining]

            save_dir = os.path.dirname(output_file)
            if save_dir:
                os.makedirs(save_dir, exist_ok=True)
            self.autosize_workbook_columns(wb)
            try:
                self.propagate_asset_tags_to_tabs(wb)
            except Exception:
                logging.exception("[ASSET-TAG] propagation failed during unified save")
            wb.save(output_file)
            logging.info(f"Unified report saved: {output_file} ({len(unified_summary)} devices across {len(family_files)} template families)")
            return processed_all
        finally:
            try:
                shutil.rmtree(tempdir, ignore_errors=True)
            except Exception:
                pass

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

        # Use secure temporary file instead of hardcoded path in cwd to prevent race conditions and symlink attacks
        temp_fd, temp_packing_slip = tempfile.mkstemp(prefix="PackingSlip_", suffix=".xlsx", dir=None)
        try:
            os.close(temp_fd)  # Close the file descriptor; we'll use the path
            shutil.copy(packing_template_path, temp_packing_slip)
        except Exception:
            try:
                os.unlink(temp_packing_slip)
            except Exception:
                pass
            raise

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
            resolved_folder = os.path.realpath(save_folder)
            save_path = os.path.realpath(os.path.join(resolved_folder, filename))
            if not save_path.startswith(resolved_folder + os.sep) and save_path != resolved_folder:
                raise ValueError(f"Resolved save path escapes the target folder: {save_path}")

            logging.info(f"Packing slips will be saved as: {save_path}")

            # Wipe legacy template cells (old layout had headers at H5 /
            # J5 / J6 and data starting row 7); the uniform layout below
            # mirrors the inventory summary exactly.
            self._reset_summary_sheet_layout(summary_sheet)

            # Timestamp in A2 — fill/title block applied later by _format_summary_sheet.
            capture_time = datetime.now().strftime('%Y-%m-%d @ %H:%M:%S')
            summary_sheet["A2"] = f"Capture Time = {capture_time}"
            summary_sheet["A2"].font = Font(color="00FF00", bold=True)

            ordered_items = sorted(processed_data.items(), key=lambda item: extract_ip_sort_key(item[0]))
            # Data rows start at row 10 to match the inventory Summary
            # layout — B=#, C=IP, D=Device Name, E=Asset Tag.
            summary_start_row = 10
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
                            if pattern in str(col).lower():
                                device_name = str(device_data.iloc[0].get(col, "Unknown_Device"))
                                break
                        if device_name != "Unknown_Device":
                            break
                    if device_name == "Unknown_Device":
                        for col in device_data.columns:
                            if "name" in str(col).lower():
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

                    # SO and PO are written once at fixed cells B15 / C15
                    new_sheet["B15"] = sales_order or ""
                    new_sheet["C15"] = customer_po or ""

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

                        if str(part_number).lower() in ("nan", ""):
                            part_number = ""
                        if str(serial_number).lower() in ("nan", ""):
                            serial_number = ""
                        if str(description).lower() in ("nan", ""):
                            description = ""

                        if part_number or serial_number or description:
                            new_sheet[f"B{row_num}"] = sales_order or ""
                            new_sheet[f"C{row_num}"] = customer_po or ""
                            new_sheet[f"D{row_num}"] = self._sanitize_cell(part_number)
                            new_sheet[f"E{row_num}"] = self._sanitize_cell(serial_number)
                            new_sheet[f"F{row_num}"] = self._sanitize_cell(description)

                    self.autosize_sheet_columns(new_sheet)
                    # Match the device-report convention: rows 1-14 stay
                    # visible while the equipment list scrolls.
                    new_sheet.freeze_panes = "A15"

                    summary_rows.append((seq, ip, device_name, new_sheet.title))

                    logging.debug(f"Written {len(device_data)} line items for device '{device_name}' with SO/PO")
                except Exception as exc:
                    logging.error(f"Error creating sheet for {ip}: {exc}")

            # Uniform layout (matches inventory Summary): B=#, C=IP,
            # D=Device Name (hyperlinked), E=Asset Tag (operator-editable,
            # propagated to device tabs at next build). Customer / Project
            # live in the header block at B7 / D7 via _setup_summary_sheet_header.
            self._setup_summary_sheet_header(
                summary_sheet, customer, project,
                [row[3] for row in summary_rows],
            )
            for row_offset, (seq, ip, device_name, sheet_title) in enumerate(summary_rows):
                row_num = summary_start_row + row_offset
                summary_sheet[f"B{row_num}"] = row_offset + 1
                summary_sheet[f"C{row_num}"] = str(ip)
                summary_sheet[f"D{row_num}"] = str(device_name)
                summary_sheet[f"D{row_num}"].hyperlink = f"#'{sheet_title}'!A1"
                summary_sheet[f"D{row_num}"].style = "Hyperlink"
            summary_sheet["F7"] = len(summary_rows)

            self._format_summary_sheet(
                summary_sheet, len(summary_rows), title="Packing Slip Summary"
            )
            self.autosize_sheet_columns(summary_sheet)

            if summary_sheet.title in wb_final.sheetnames:
                idx = wb_final.sheetnames.index(summary_sheet.title)
                wb_final._sheets.insert(0, wb_final._sheets.pop(idx))

            if template_sheet.title in wb_final.sheetnames:
                del wb_final[template_sheet.title]

            self.autosize_workbook_columns(wb_final)
            # First-run packing slips have an empty Asset Tag column (no-op);
            # re-runs against a workbook the operator has filled in get
            # their tags stamped onto each device sheet's chassis row.
            try:
                self.propagate_asset_tags_to_tabs(wb_final)
            except Exception:
                logging.exception("[ASSET-TAG] propagation failed during packing slip save")
            wb_final.save(save_path)
            logging.info(f"Packing slips saved successfully: {save_path}")
            return save_path
        finally:
            if os.path.exists(temp_packing_slip):
                try:
                    os.remove(temp_packing_slip)
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Per-family packing slip support
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_family_from_dataframe(df: Any) -> str:
        """Best-effort detect device family from an uploaded packing-slip dataframe.

        Looks at any column containing 'system type' or 'type' for known
        family signatures. Falls back to 'default'.
        """
        try:
            for col in df.columns:
                col_l = str(col).lower()
                if "type" not in col_l:
                    continue
                values = " ".join(str(v) for v in df[col].dropna().astype(str).head(10)).lower()
                if "rls" in values or "ciena" in values:
                    return "rls"
                if "psi" in values or "1830" in values or "nokia" in values:
                    return "psi"
        except Exception:
            pass
        return "default"

    def _populate_default_packing_slip_sheet(
        self,
        new_sheet: Any,
        device_data: Any,
        customer: str,
        project: str,
        customer_po: str,
        sales_order: str,
        device_name: str,
    ) -> None:
        """Default packing slip layout: B=SO, C=PO, D=PartNum, E=Serial, F=Description from row 15."""
        new_sheet["C5"] = customer or ""
        new_sheet["C6"] = project or ""
        new_sheet["C7"] = device_name
        new_sheet["B15"] = sales_order or ""
        new_sheet["C15"] = customer_po or ""

        start_row = 15
        for idx, row_dict in enumerate(device_data.to_dict("records")):
            row_num = start_row + idx
            row_lower = {str(k).lower(): v for k, v in row_dict.items()}
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
                new_sheet[f"D{row_num}"] = self._sanitize_cell(part_number)
                new_sheet[f"E{row_num}"] = self._sanitize_cell(serial_number)
                new_sheet[f"F{row_num}"] = self._sanitize_cell(description)
        new_sheet.freeze_panes = "A15"

    def _populate_report_layout_packing_slip_sheet(
        self,
        new_sheet: Any,
        device_data: Any,
        customer: str,
        project: str,
        customer_po: str,
        sales_order: str,
        device_name: str,
        source_ip: str,
    ) -> None:
        """RLS/PSI report-template layout packing slip: SO/PO in C7 header, equipment in B-F from row 15.

        Columns: B=Slot/Port, C=Part Type, D=Part Number, E=Serial Number, F=Description.
        """
        new_sheet["C5"] = customer or ""
        new_sheet["C6"] = project or ""
        # Combined SO/PO in C7 (header label was set to "Sales Order / PO:" when template was created).
        so = (sales_order or "").strip()
        po = (customer_po or "").strip()
        if so and po:
            new_sheet["C7"] = f"SO {so} / PO {po}"
        elif so:
            new_sheet["C7"] = f"SO {so}"
        elif po:
            new_sheet["C7"] = f"PO {po}"
        # Right-side header block
        new_sheet["F5"] = source_ip or ""
        new_sheet["F6"] = device_name

        start_row = 15
        for idx, row_dict in enumerate(device_data.to_dict("records")):
            row_num = start_row + idx
            row_lower = {str(k).lower(): v for k, v in row_dict.items()}

            def pick(*keys: str) -> str:
                for k in keys:
                    v = row_lower.get(k)
                    if v is None:
                        continue
                    s = str(v).strip()
                    if s and s.lower() != "nan":
                        return s
                return ""

            slot = pick("slot/port", "slot", "slot/port number", "name")
            part_type = pick("part type", "type")
            part_number = pick("part number", "model number")
            serial_number = pick("serial number", "serial")
            description = pick("description")

            if slot or part_type or part_number or serial_number or description:
                new_sheet[f"B{row_num}"] = self._sanitize_cell(slot)
                new_sheet[f"C{row_num}"] = self._sanitize_cell(part_type)
                new_sheet[f"D{row_num}"] = self._sanitize_cell(part_number)
                new_sheet[f"E{row_num}"] = self._sanitize_cell(serial_number)
                new_sheet[f"F{row_num}"] = self._sanitize_cell(description)
        new_sheet.freeze_panes = "A15"

    def build_unified_packing_slip_workbook(
        self,
        processed_data: Dict[str, Any],
        ip_list: List[str],
        customer: str,
        project: str,
        customer_po: str,
        sales_order: str,
        save_folder: str,
        family_for_ip: Optional[Dict[str, str]] = None,
        rls_packing_slip_template: Optional[str] = None,
        psi_packing_slip_template: Optional[str] = None,
    ) -> str:
        """Generate a packing slip workbook using the default template for all devices.

        Always uses the standard default packing slip template regardless of device
        family (PSI, RLS, or default). Per-family template selection has been removed
        per user request — all packing slips use the same format.
        """
        # Always use the default template for all devices.
        return self.build_packing_slip_workbook(
            processed_data, ip_list, customer, project, customer_po, sales_order, save_folder,
        )

    @staticmethod
    def _unique_title(wb: Any, base: str) -> str:
        """Return a unique sheet title in *wb* derived from *base* (Excel 31-char limit)."""
        title = base[:31]
        if title not in wb.sheetnames:
            return title
        i = 2
        while True:
            suffix = f"_{i}"
            candidate = (base[: 31 - len(suffix)] + suffix)
            if candidate not in wb.sheetnames:
                return candidate
            i += 1
