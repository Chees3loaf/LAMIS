"""
gui/bom_compare_frame.py - "BoM Comparison" sub-mode under File Processing.

Loads a Factory BoM workbook and a Sales BoM workbook, parses each BOM
sheet for per-site quantities, and emits a new workbook with three tabs:
* Missing BOM    — BOM-style layout (mirrors Sales site columns) showing
                   per-site shortfalls. A trailing ``Spares Available``
                   column reflects how many of each missing part the
                   Factory's Spares/Spare Materials tab can backfill.
* Factory BoM    — full-fidelity copy of the Factory BOM sheet.
* Sales BoM      — full-fidelity copy of the Sales BOM sheet.
"""
import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from utils.helpers import get_data_dir


# Header keywords used to recognize the fixed left-side columns.
_PN_HEADERS = ("part no", "part #", "part number", "part")
_DESC_HEADERS = ("description", "equipment description")
_QTY_HEADERS = ("total", "qty", "quantity", "total qty")
_ITEM_HEADERS = ("item", "#")

# Section banners to skip when comparing — these are intangible line items
# on the Sales BoM (and equivalents on the Factory side) and must not feed
# the per-site shortfall.
_EXCLUDED_SECTIONS = (
    "unit price", "price", "maintenance", "software",
    "services", "service", "support", "warranty", "labor",
    "training", "installation", "license",
)
# Section banners that represent real hardware. Anything not matched here
# AND not in the excluded list is included by default so unfamiliar
# section labels don't silently drop parts.
_INCLUDED_SECTIONS = (
    "chassis", "shelf", "card", "cards", "optic", "optics",
    "amplifier", "amplifiers", "amp", "amps", "transponder", "transponders",
    "module", "modules", "passive", "passives",
)
# Description-level keywords that mark a row as intangible regardless of
# any section banner. Catches flat Sales BoMs that don't use banners and
# items like "5 YEAR – Technical Support", "Software Subscription Plan",
# "Software Release Subscription", etc.
_INTANGIBLE_DESC_KEYWORDS = (
    "subscription", "support", "maintenance", "warranty",
    "training", "installation", "services",
    "year - tech", "year tech", "year - software", "year software",
    "release subscription", "license",
)
# Column-header keywords that should NEVER be treated as a per-site
# column (they're price/cost/metadata columns, not site quantities).
_NON_SITE_HEADERS = (
    "unit price", "price", "cost", "ext price", "extended price",
    "list price", "msrp", "discount", "amount", "$", "usd", "currency",
    "uom", "unit", "weight", "lead time", "vendor", "manufacturer",
    "category", "notes", "comment", "network",
)


def _hkey(s: Any) -> str:
    """Normalize a header cell for keyword matching: lower, trim, drop trailing dots/colons."""
    return re.sub(r"[.\s:]+$", "", str(s or "").strip().lower())


def _norm_site(name: str) -> str:
    """Case/whitespace-insensitive site key for cross-workbook matching."""
    return re.sub(r"\s+", " ", str(name or "").strip()).lower()


# Vendor-prefix strip used so "1P3HE13584AA" / "P3HE13584AA" / "3HE13584AA"
# all canonicalize to the same alias key.
_VENDOR_PREFIX_RE = re.compile(r"^(?:1P|P)", re.IGNORECASE)


def _strip_vendor_prefix(pn: str) -> str:
    return _VENDOR_PREFIX_RE.sub("", (pn or "").strip(), count=1)


def load_part_aliases(path: Optional[str] = None) -> Dict[str, str]:
    """Load the alias → canonical part-number map from ``data/part_aliases.json``.

    Returns an empty dict if the file is missing or malformed — the BoM
    comparison still works without aliases, just without bundle/component
    correlation. All keys and values are uppercased + vendor-prefix
    stripped so lookup is uniform regardless of how the source BoMs typed
    the SKU.
    """
    if path is None:
        path = str(get_data_dir() / "part_aliases.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        logging.warning(f"[BOM-COMPARE] Could not load part aliases from {path}: {exc}")
        return {}

    raw = payload.get("aliases") if isinstance(payload, dict) else None
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        ak = _strip_vendor_prefix(k).upper()
        av = _strip_vendor_prefix(v).upper()
        if ak and av:
            out[ak] = av
    return out


def canonical_part(pn: str, aliases: Dict[str, str]) -> str:
    """Resolve *pn* to its canonical part number through the alias map.

    Handles 1P/P vendor prefixes and case differences. Falls back to the
    original (uppercased, prefix-stripped) part number when no alias is
    registered.
    """
    if not pn:
        return ""
    key = _strip_vendor_prefix(pn).upper()
    return aliases.get(key, key)


def fold_aliased_parts(
    parts: Dict[str, Dict[str, Any]],
    aliases: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    """Collapse aliased SKUs in a ``_parse_per_site_bom`` result into the
    canonical part number.

    Quantities are summed per site; descriptions prefer the canonical
    SKU's description when both forms are present (so the Missing BOM
    sheet shows the bare-chassis text, not the bundle text). Returns a
    new dict; *parts* is not mutated.
    """
    if not aliases:
        return parts
    folded: Dict[str, Dict[str, Any]] = {}
    for pn, info in parts.items():
        canon = canonical_part(pn, aliases)
        is_canonical_input = (canon == _strip_vendor_prefix(pn).upper() == canon)
        existing = folded.get(canon)
        if existing is None:
            folded[canon] = {
                "desc": info.get("desc", ""),
                "site_qty": dict(info.get("site_qty", {})),
                # Track whether the description came from the canonical SKU
                # so a later alias entry doesn't overwrite the better text.
                "_desc_is_canonical": is_canonical_input,
            }
            continue
        for site, q in info.get("site_qty", {}).items():
            existing["site_qty"][site] = existing["site_qty"].get(site, 0) + int(q)
        # Prefer the canonical description if we have one; otherwise the
        # first non-empty wins.
        if is_canonical_input and info.get("desc"):
            existing["desc"] = info["desc"]
            existing["_desc_is_canonical"] = True
        elif not existing.get("desc") and info.get("desc"):
            existing["desc"] = info["desc"]
    # Drop the bookkeeping flag before returning.
    for v in folded.values():
        v.pop("_desc_is_canonical", None)
    return folded


class BomCompareFrame(ttk.Frame):
    """UI panel for diffing a Sales BoM against the Factory BoM."""

    def __init__(self, parent: tk.Widget, gui: Any) -> None:
        super().__init__(parent)
        self.gui = gui
        self._factory_path: Optional[str] = None
        self._sales_path: Optional[str] = None
        self._running = False
        self._setup_ui()

    # ------------------------------------------------------------------
    # Widget construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        pad: Dict[str, int] = {"padx": 8, "pady": 4}

        f1 = ttk.LabelFrame(self, text="Factory BoM workbook")
        f1.pack(fill=tk.X, **pad)
        self._factory_label = tk.StringVar(value="No workbook selected")
        ttk.Label(f1, textvariable=self._factory_label, width=80, anchor="w").pack(
            side=tk.LEFT, padx=6, pady=6
        )
        ttk.Button(f1, text="Browse…", command=self._browse_factory).pack(
            side=tk.LEFT, padx=6, pady=6
        )

        f2 = ttk.LabelFrame(self, text="Sales BoM workbook")
        f2.pack(fill=tk.X, **pad)
        self._sales_label = tk.StringVar(value="No workbook selected")
        ttk.Label(f2, textvariable=self._sales_label, width=80, anchor="w").pack(
            side=tk.LEFT, padx=6, pady=6
        )
        ttk.Button(f2, text="Browse…", command=self._browse_sales).pack(
            side=tk.LEFT, padx=6, pady=6
        )

        ctrl = ttk.Frame(self)
        ctrl.pack(fill=tk.X, **pad)
        self._run_btn = ttk.Button(ctrl, text="Compare", command=self._on_run)
        self._run_btn.pack(side=tk.LEFT, padx=6)
        self._status_var = tk.StringVar(value="Ready — pick both workbooks and click Compare")
        ttk.Label(ctrl, textvariable=self._status_var, foreground="gray").pack(
            side=tk.LEFT, padx=12
        )

        log_frame = ttk.LabelFrame(self, text="Compare Log")
        log_frame.pack(fill=tk.BOTH, expand=True, **pad)
        self._log = scrolledtext.ScrolledText(
            log_frame, height=14, state="disabled", wrap="word"
        )
        self._log.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _append_log(self, msg: str) -> None:
        def _do():
            self._log.configure(state="normal")
            self._log.insert(tk.END, msg + "\n")
            self._log.see(tk.END)
            self._log.configure(state="disabled")
        try:
            self.after(0, _do)
        except Exception:
            _do()

    def _set_status(self, msg: str) -> None:
        try:
            self.after(0, lambda: self._status_var.set(msg))
        except Exception:
            self._status_var.set(msg)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _browse_factory(self) -> None:
        p = filedialog.askopenfilename(
            title="Select Factory BoM workbook",
            filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")],
        )
        if p:
            self._factory_path = p
            self._factory_label.set(p)

    def _browse_sales(self) -> None:
        p = filedialog.askopenfilename(
            title="Select Sales BoM workbook",
            filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")],
        )
        if p:
            self._sales_path = p
            self._sales_label.set(p)

    def _on_run(self) -> None:
        if self._running:
            return
        if not self._factory_path or not os.path.isfile(self._factory_path):
            messagebox.showerror("BoM Comparison", "Pick a valid Factory BoM workbook.")
            return
        if not self._sales_path or not os.path.isfile(self._sales_path):
            messagebox.showerror("BoM Comparison", "Pick a valid Sales BoM workbook.")
            return
        self._running = True
        self._run_btn.configure(state="disabled")
        self._set_status("Comparing…")
        threading.Thread(
            target=self._run_worker,
            args=(self._factory_path, self._sales_path),
            daemon=True,
        ).start()

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    def _run_worker(self, factory_path: str, sales_path: str) -> None:
        try:
            out_path = self._compare(factory_path, sales_path)
            self._append_log(f"Wrote: {out_path}")
            self._set_status(f"Done — {os.path.basename(out_path)}")
        except Exception as exc:
            logging.exception("[BoM Compare] failed")
            self._append_log(f"ERROR: {exc}")
            self._set_status("Failed")
            try:
                msg = str(exc)
                self.after(0, lambda m=msg: messagebox.showerror("BoM Comparison", m))
            except Exception:
                pass
        finally:
            self._running = False
            try:
                self.after(0, lambda: self._run_btn.configure(state="normal"))
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Core compare
    # ------------------------------------------------------------------

    def _compare(self, factory_path: str, sales_path: str) -> str:
        self._append_log(f"Loading Factory: {factory_path}")
        fac_data = openpyxl.load_workbook(factory_path, data_only=True)
        fac_full = openpyxl.load_workbook(factory_path, data_only=False)
        self._append_log(f"Loading Sales:   {sales_path}")
        sal_data = openpyxl.load_workbook(sales_path, data_only=True)
        sal_full = openpyxl.load_workbook(sales_path, data_only=False)

        fac_bom = self._find_bom_sheet(fac_data, required=True)
        sal_bom = self._find_bom_sheet(sal_data, required=False)
        fac_bom_full = fac_full[fac_bom.title]
        sal_bom_full = sal_full[sal_bom.title]
        self._append_log(f"Factory sheet: '{fac_bom.title}'  |  Sales sheet: '{sal_bom.title}'")

        fac_sites, fac_parts, fac_inline_spares, fac_part_to_group = self._parse_per_site_bom(fac_bom)
        sal_sites, sal_parts, _, sal_part_to_group = self._parse_per_site_bom(sal_bom)
        self._append_log(
            f"Factory: {len(fac_parts)} parts across {len(fac_sites)} site col(s)  |  "
            f"Sales: {len(sal_parts)} parts across {len(sal_sites)} site col(s)"
        )

        # Fold alias SKUs (e.g. CHASSIS BUNDLE -> bare CHASSIS) into their
        # canonical part numbers on BOTH sides before any keyed lookup so
        # bundle/component pairs correlate cleanly during the diff.
        aliases = load_part_aliases()
        if aliases:
            fac_before, sal_before = len(fac_parts), len(sal_parts)
            fac_parts = fold_aliased_parts(fac_parts, aliases)
            sal_parts = fold_aliased_parts(sal_parts, aliases)
            # Re-key the per-part group maps too so the breakdown picks up
            # canonical SKUs (otherwise group="Optics" fallback kicks in).
            fac_part_to_group = {
                canonical_part(pn, aliases): grp
                for pn, grp in fac_part_to_group.items()
            }
            sal_part_to_group = {
                canonical_part(pn, aliases): grp
                for pn, grp in sal_part_to_group.items()
            }
            collapsed = (fac_before - len(fac_parts)) + (sal_before - len(sal_parts))
            self._append_log(
                f"Aliases: {len(aliases)} registered, "
                f"{collapsed} row(s) folded into canonical SKUs"
            )

        # Prefer a Spare/Spare Materials column on the Factory BoM sheet
        # itself; fall back to a separate Spares tab when the column isn't
        # present.
        spares = fac_inline_spares or self._parse_spares(fac_data)
        if spares and aliases:
            # Spares pool must also be canonicalized so an alias-keyed
            # shortfall finds its backfill regardless of which form the
            # Spares column used.
            canon_spares: Dict[str, int] = {}
            for pn, qty in spares.items():
                ck = canonical_part(pn, aliases)
                canon_spares[ck] = canon_spares.get(ck, 0) + int(qty)
            spares = canon_spares
        if spares:
            src = "BOM column" if fac_inline_spares else "separate tab"
            self._append_log(f"Spares pool ({src}): {len(spares)} unique parts available for backfill")
        else:
            self._append_log("Spares pool: none found (no Spare column on BOM and no Spares tab)")

        # Build a Factory site-key index so Sales site names can be matched
        # case/whitespace-insensitively.
        fac_site_by_key = { _norm_site(s): s for s in fac_sites }

        # Compute per-site shortfall keyed by Sales site columns.
        # rows: List of (part, desc, {sales_site: missing_qty}, total_missing, spares_avail)
        rows: List[Tuple[str, str, Dict[str, int], int, int]] = []
        for pn, info in sal_parts.items():
            desc = info["desc"]
            sales_site_qty = info["site_qty"]
            fac_info = fac_parts.get(pn)
            fac_site_qty = fac_info["site_qty"] if fac_info else {}
            if not desc and fac_info:
                desc = fac_info["desc"]

            short_per_site: Dict[str, int] = {}
            for s_site in sal_sites:
                s_qty = sales_site_qty.get(s_site, 0)
                if s_qty <= 0:
                    continue
                # Match Sales site name to a Factory site name; if no match,
                # treat factory_qty as 0 for that site.
                f_site = fac_site_by_key.get(_norm_site(s_site))
                f_qty = fac_site_qty.get(f_site, 0) if f_site else 0
                short = s_qty - f_qty
                if short > 0:
                    short_per_site[s_site] = short

            if not short_per_site:
                continue
            total_missing = sum(short_per_site.values())
            spares_avail = spares.get(pn, 0)
            rows.append((pn, desc, short_per_site, total_missing, spares_avail))

        rows.sort(key=lambda r: (-r[3], r[0]))
        self._append_log(
            f"Shortfall lines: {len(rows)}  |  Total missing units: {sum(r[3] for r in rows)}  |  "
            f"Backfilled from spares (full): {sum(1 for r in rows if r[4] >= r[3])}"
        )

        out_wb = openpyxl.Workbook()
        del out_wb[out_wb.sheetnames[0]]

        miss_ws = out_wb.create_sheet("Missing BOM")
        self._write_missing_sheet(miss_ws, sal_sites, rows)

        # Breakdown — for each part where spares can cover at least some
        # of the shortfall, show how those spares get distributed across
        # the needy sites (smallest-shortfall-first so the most sites get
        # fully unblocked). Rendered using the Factory BoM template so it
        # matches the rest of the workbook's hardware breakdown layout.
        breakdown_rows = self._build_breakdown(rows)
        self._append_log(
            f"Breakdown: {len(breakdown_rows)} parts can be partially or fully covered from spares"
        )

        builder = self.gui.workbook_builder
        builder.copy_sheet(fac_bom_full, out_wb, "Factory BoM")
        builder.copy_sheet(sal_bom_full, out_wb, "Sales BoM")

        # Build BOM-template-shaped allocation data: each (part, desc, group)
        # tuple appears once per allocated unit. Group is taken from the
        # source BoMs (sales first, factory fallback); unknown parts default
        # to "Optics" so they still land in a real bucket on the sheet.
        #
        # Per the user, the Breakdown columns must come from the FACTORY BoM
        # site names (rolled up — e.g. STJO001+STJO002 -> STJO). The Sales
        # BoM is often a flat single-quote sheet, so its column headers
        # aren't meaningful as allocation targets; the factory's per-site
        # distribution is the source of truth.
        #
        # Per-part dispersal: spares for a given part are distributed across
        # the factory locations that already received that part, weighted by
        # the factory's per-location qty (largest-first remainder
        # allocation). If a part has no factory presence at all, the spares
        # land on the first factory location so the row still surfaces.
        def _loc_key(site_name: str) -> str:
            k = builder._site_group_key(site_name)
            return k if k else (site_name or "").strip()

        # Roll factory site columns up to location keys, preserving first-
        # seen order so the Breakdown matches the Factory BoM's left-to-right
        # site ordering.
        loc_order: List[str] = []
        seen_loc: set = set()
        for s in fac_sites:
            loc = _loc_key(s)
            if loc and loc not in seen_loc:
                seen_loc.add(loc)
                loc_order.append(loc)

        # Build {part: {loc: factory_qty}} so we can weight spares allocation
        # by the factory's existing per-location distribution.
        fac_part_loc_qty: Dict[str, Dict[str, int]] = {}
        for pn, info in fac_parts.items():
            loc_qty: Dict[str, int] = {}
            for site, q in info.get("site_qty", {}).items():
                loc = _loc_key(site)
                if not loc:
                    continue
                loc_qty[loc] = loc_qty.get(loc, 0) + int(q)
            if loc_qty:
                fac_part_loc_qty[pn] = loc_qty

        bom_data: Dict[str, List[Tuple[str, str, str]]] = {loc: [] for loc in loc_order}
        for pn, desc, _alloc_per_sales_site, _ta, spares_used, _sl in breakdown_rows:
            if spares_used <= 0:
                continue
            grp = sal_part_to_group.get(pn) or fac_part_to_group.get(pn) or "Optics"

            # Distribute spares_used units across factory locations weighted
            # by fac_part_loc_qty[pn]. Largest-remainder rounding so the
            # totals match exactly.
            weights = fac_part_loc_qty.get(pn, {})
            if weights:
                total_weight = sum(weights.values())
                raw = [
                    (loc, spares_used * w / total_weight)
                    for loc, w in weights.items()
                ]
                base = [(loc, int(v)) for loc, v in raw]
                remainder = spares_used - sum(v for _, v in base)
                # Sort by fractional part desc to assign leftover units to
                # the locations with the largest truncated remainder.
                fracs = sorted(
                    [(loc, v - int(v)) for loc, v in raw],
                    key=lambda kv: -kv[1],
                )
                bumps = {loc: 0 for loc, _ in base}
                for loc, _frac in fracs[: max(0, remainder)]:
                    bumps[loc] += 1
                alloc_by_loc = {loc: q + bumps[loc] for loc, q in base}
            else:
                # No factory presence — drop everything on the first
                # location so the row is still visible.
                if not loc_order:
                    continue
                alloc_by_loc = {loc_order[0]: spares_used}

            for loc, q in alloc_by_loc.items():
                if q <= 0:
                    continue
                if loc not in seen_loc:
                    seen_loc.add(loc)
                    loc_order.append(loc)
                bucket = bom_data.setdefault(loc, [])
                for _ in range(q):
                    bucket.append((pn, desc, grp))

        # Drop locations that received zero allocations — the Breakdown
        # only shows sites that actually need parts.
        active_locs = [loc for loc in loc_order if bom_data.get(loc)]
        bom_data = {loc: bom_data[loc] for loc in active_locs}

        summary_items: List[Tuple[str, str, str]] = [(loc, loc, loc) for loc in active_locs]
        display_to_tab: Dict[str, str] = {loc: loc for loc in active_locs}
        builder._build_bom_sheet(out_wb, summary_items, bom_data, display_to_tab=display_to_tab)
        # Rename the template-built "BOM" sheet to "Breakdown" and reposition
        # it right after Missing BOM so the final order is:
        # Missing BOM | Breakdown | Factory BoM | Sales BoM.
        if "BOM" in out_wb.sheetnames:
            bd_sheet = out_wb["BOM"]
            bd_sheet.title = "Breakdown"
            target_idx = out_wb.sheetnames.index("Missing BOM") + 1
            cur_idx = out_wb.sheetnames.index("Breakdown")
            if cur_idx != target_idx:
                out_wb._sheets.insert(target_idx, out_wb._sheets.pop(cur_idx))
            # _build_bom_sheet runs autosize on the data columns, which
            # shrinks A-C below the BOM template's defaults and clips the
            # LightRiver banner image. Restore the template widths so the
            # logo renders at full size.
            for letter, width in (("A", 8.0), ("B", 18.0), ("C", 44.0)):
                bd_sheet.column_dimensions[letter].width = width

        out_path = self._derive_out_path(factory_path)
        out_wb.save(out_path)
        return out_path

    # ------------------------------------------------------------------
    # Sheet discovery
    # ------------------------------------------------------------------

    @staticmethod
    def _sheet_has_bom_header(ws: Any) -> bool:
        """Return True when *ws* has both a Part-Number and a Total/Qty header
        within the first 25 rows. Used to identify which tab in a multi-sheet
        Sales workbook actually holds the BOM grid (vs Summary, Notes, etc.)."""
        max_r = min(ws.max_row or 0, 25)
        max_c = ws.max_column or 0
        if max_r == 0 or max_c == 0:
            return False
        for r in range(1, max_r + 1):
            f_pn = f_total = False
            for c in range(1, max_c + 1):
                v = ws.cell(r, c).value
                if v is None:
                    continue
                s = _hkey(v)
                if not s:
                    continue
                if s in _PN_HEADERS:
                    f_pn = True
                elif s in _QTY_HEADERS:
                    f_total = True
                if f_pn and f_total:
                    return True
        return False

    @classmethod
    def _find_bom_sheet(cls, wb: Any, required: bool = True) -> Any:
        # Exact "BOM" match wins regardless of position.
        for name in wb.sheetnames:
            if name.strip().lower() == "bom":
                return wb[name]
        if required:
            raise RuntimeError("Workbook has no 'BOM' sheet — cannot compare.")
        # Sales workbooks frequently lead with Summary/Notes tabs and put the
        # actual BOM grid on a sheet the engineer named themselves (e.g.
        # "CBR v1"). Probe each sheet for a Part-Number + Total/Qty header
        # pair so we land on the real BOM instead of the first non-empty
        # sheet.
        for name in wb.sheetnames:
            ws = wb[name]
            if cls._sheet_has_bom_header(ws):
                return ws
        # Last-ditch fallback — first non-empty sheet, then sheet 0.
        for name in wb.sheetnames:
            ws = wb[name]
            if (ws.max_row or 0) > 1:
                return ws
        return wb[wb.sheetnames[0]]

    @staticmethod
    def _find_spares_sheet(wb: Any) -> Optional[Any]:
        """Return a Spares/Spare Materials sheet if one exists in *wb*."""
        for name in wb.sheetnames:
            low = name.strip().lower()
            if low == "spares" or low == "spare materials" or "spare" in low:
                return wb[name]
        return None

    @staticmethod
    def _section_to_group(section_norm: str) -> Optional[str]:
        """Map a normalized section banner to a Factory BoM group name.

        Returns one of "Chassis/Shelf", "Cards", "Optics", or None when
        the banner doesn't map to a hardware group. Amplifiers and
        transponders fold into the "Optics" group since the Factory BoM
        template only supports those three buckets.
        """
        if not section_norm:
            return None
        if "chassis" in section_norm or "shelf" in section_norm:
            return "Chassis/Shelf"
        if "card" in section_norm:
            return "Cards"
        if (
            "optic" in section_norm
            or "amp" in section_norm
            or "transponder" in section_norm
            or "module" in section_norm
            or "passive" in section_norm
        ):
            return "Optics"
        return None

    # ------------------------------------------------------------------
    # BOM parsing — per-site
    # ------------------------------------------------------------------

    @classmethod
    def _parse_per_site_bom(
        cls, ws: Any
    ) -> Tuple[List[str], Dict[str, Dict[str, Any]], Dict[str, int], Dict[str, str]]:
        """Parse a BOM-shaped sheet into ``(sites, parts, spares, part_to_group)``.

        ``sites``: ordered list of per-site column names.
        ``parts``: ``{part: {desc, site_qty: {site: qty}}}``.
        ``spares``: ``{part: qty}`` extracted from a sibling Spare/Spares
        column on the same sheet (empty dict if no such column exists).
        ``part_to_group``: ``{part: "Chassis/Shelf" | "Cards" | "Optics"}``
        derived from the section banner active when the part was seen.
        Used by the Breakdown sheet to slot allocations under the right
        Factory-BoM-template group.

        Auto-detects the header row by scanning the first 25 rows for the
        first row that contains both a Part-Number-style header and a
        Total/Qty-style header. The site columns are every non-empty
        header cell between Description (or Part No. if Description is
        absent) and Total. Aggregates duplicates by summing per-site qty.

        Falls back to a single bucket named after the sheet when no
        per-site columns are present.
        """
        max_r = ws.max_row or 0
        max_c = ws.max_column or 0
        if max_r == 0 or max_c == 0:
            return [], {}, {}, {}

        hdr_row = None
        pn_col = desc_col = total_col = None
        scan_to = min(max_r, 25)
        # Independent matching per category — a single row can supply PN,
        # Desc, AND Total. Prefer an explicit "Total" header over the first
        # "Qty" column: BoMs with two-row headers (site names on row N,
        # repeated "Qty" subheaders on row N+1) anchor on the subheader
        # row, where every site column reads "Qty". If we picked the
        # first "Qty" as total_col, the per-site loop (which stops at
        # total_col) would never iterate. The right answer is the
        # rightmost true "Total" column; "Qty" only acts as a fallback
        # for sheets that don't carry a Total column at all.
        _TOTAL_PRIMARY = ("total", "total qty")
        for r in range(1, scan_to + 1):
            f_pn = f_desc = f_total = f_qty_fallback = None
            for c in range(1, max_c + 1):
                v = ws.cell(r, c).value
                if v is None:
                    continue
                s = _hkey(v)
                if not s:
                    continue
                if f_pn is None and s in _PN_HEADERS:
                    f_pn = c
                if f_desc is None and s in _DESC_HEADERS:
                    f_desc = c
                if s in _TOTAL_PRIMARY:
                    f_total = c  # take the rightmost "Total"
                elif f_qty_fallback is None and s in _QTY_HEADERS:
                    f_qty_fallback = c
            chosen_total = f_total if f_total is not None else f_qty_fallback
            if f_pn is not None and chosen_total is not None:
                hdr_row = r
                pn_col, desc_col, total_col = f_pn, f_desc, chosen_total
                break
        if hdr_row is None:
            raise RuntimeError(
                f"Sheet '{ws.title}' has no recognizable BOM header "
                "(need a Part Number column and a Total/Qty column)."
            )

        # Site columns sit between (desc_col or pn_col) and total_col.
        # Two-row header support: real-world BoMs commonly put site names
        # on row N and a repeated "Qty" subheader on row N+1 (the row that
        # carries Part No./Total and thus anchors hdr_row). When the cell
        # at hdr_row reads "Qty"/"Total", consult hdr_row-1 for the actual
        # site name. Without this fallback every per-site column collapses
        # to the single header keyword and gets filtered out.
        left_anchor = desc_col if desc_col is not None else pn_col
        site_cols: List[Tuple[int, str]] = []
        spares_col: Optional[int] = None
        super_row = hdr_row - 1 if hdr_row > 1 else None
        # Scan all the way to the right edge (not just up to total_col) so
        # a Spare Material column placed after Total still gets picked up.
        scan_end = max_c
        for c in range(left_anchor + 1, scan_end + 1):
            sub_v = ws.cell(hdr_row, c).value
            sup_v = ws.cell(super_row, c).value if super_row else None
            sub_s = str(sub_v).strip() if sub_v is not None else ""
            sup_s = str(sup_v).strip() if sup_v is not None else ""
            sub_low = _hkey(sub_v) if sub_s else ""
            sup_low = _hkey(sup_v) if sup_s else ""
            # Spare detection on EITHER header row.
            if "spare" in sub_low or "spare" in sup_low:
                if spares_col is None:
                    spares_col = c
                continue
            # Pick the most descriptive name: prefer the super-header when
            # the sub-header is a generic Qty/Total subheader.
            if sub_low and sub_low not in _QTY_HEADERS:
                s, low = sub_s, sub_low
            elif sup_s:
                s, low = sup_s, sup_low
            else:
                continue
            if c >= total_col:
                # Past the Total column — only spares cols are interesting
                # out here; everything else is metadata.
                continue
            if low in _ITEM_HEADERS or low in _PN_HEADERS or low in _DESC_HEADERS or low in _QTY_HEADERS:
                continue
            # Skip price/cost/metadata columns — they're not site quantities.
            if any(bad in low for bad in _NON_SITE_HEADERS):
                continue
            # Drop columns whose header matches an excluded-section keyword
            # (Maintenance, Software, Services, etc.) — these are roll-up
            # totals, not real sites.
            if any(ex in low for ex in _EXCLUDED_SECTIONS):
                continue
            site_cols.append((c, s))

        # If no per-site columns, treat the whole sheet as one bucket
        # named after the sheet itself so the diff still works.
        single_bucket = not site_cols
        if single_bucket:
            site_cols = [(total_col, ws.title)]

        # Dedupe site names while preserving first-seen order. Some Sales
        # BoMs repeat a site label across multiple columns (e.g. two BENT
        # columns); quantities are summed by name below, and the Missing
        # BOM writer keys on name, so collapsing here prevents a blank
        # column from a dict-key collision.
        _seen: set = set()
        sites: List[str] = []
        for (_, name) in site_cols:
            if name not in _seen:
                _seen.add(name)
                sites.append(name)
        out: Dict[str, Dict[str, Any]] = {}
        spares_out: Dict[str, int] = {}
        part_to_group: Dict[str, str] = {}

        # Track the active section banner. A banner row has text in col A
        # (or the desc col) but no part number in the PN col; if its text
        # matches an excluded section keyword, every following data row
        # is skipped until the next banner.
        section_excluded = False
        current_group: Optional[str] = None

        for r in range(hdr_row + 1, max_r + 1):
            pn = ws.cell(r, pn_col).value
            pn_s = str(pn).strip() if pn is not None else ""

            # Banner detection: PN cell empty but col A (or desc col) has
            # heading-like text. Update section state and move on.
            if not pn_s:
                banner_text = ""
                for cand_col in (1, desc_col, 2):
                    if cand_col is None:
                        continue
                    cv = ws.cell(r, cand_col).value
                    if cv is None:
                        continue
                    cs = str(cv).strip()
                    if cs and not cs.replace(".", "").isdigit():
                        banner_text = cs
                        break
                if banner_text:
                    bn = _hkey(banner_text)
                    if any(ex in bn for ex in _EXCLUDED_SECTIONS):
                        section_excluded = True
                    elif any(inc in bn for inc in _INCLUDED_SECTIONS):
                        section_excluded = False
                        grp = cls._section_to_group(bn)
                        if grp:
                            current_group = grp
                continue

            # Some Sales BoMs put section banners directly in the PN col
            # (e.g., "1830 PSS-8 Maintenance" with no qty). Detect those:
            # if the PN text matches an excluded-section keyword AND the
            # row has zero quantity in every site column, flip section
            # state and skip the row instead of treating the banner as a
            # part number.
            pn_norm = _hkey(pn_s)
            looks_like_excluded_banner = any(ex in pn_norm for ex in _EXCLUDED_SECTIONS)
            looks_like_included_banner = any(inc in pn_norm for inc in _INCLUDED_SECTIONS)
            if looks_like_excluded_banner or looks_like_included_banner:
                row_has_qty = False
                for col, _ in site_cols:
                    qv = ws.cell(r, col).value
                    try:
                        if qv not in (None, "") and int(float(qv)) > 0:
                            row_has_qty = True
                            break
                    except (TypeError, ValueError):
                        continue
                if not row_has_qty:
                    section_excluded = looks_like_excluded_banner
                    if looks_like_included_banner:
                        grp = cls._section_to_group(pn_norm)
                        if grp:
                            current_group = grp
                    continue

            if section_excluded:
                continue

            low = _hkey(pn_s)
            if low in _PN_HEADERS or low in _QTY_HEADERS or low in _ITEM_HEADERS:
                continue

            desc = ""
            if desc_col is not None:
                desc = str(ws.cell(r, desc_col).value or "").strip()

            # Description-level intangible filter — catches flat Sales
            # BoMs that don't use section banners (e.g., software/support
            # subscriptions interleaved with hardware).
            desc_norm = _hkey(desc)
            if desc_norm and any(kw in desc_norm for kw in _INTANGIBLE_DESC_KEYWORDS):
                continue

            site_qty: Dict[str, int] = {}
            row_total = 0
            for col, site_name in site_cols:
                qv = ws.cell(r, col).value
                try:
                    q = int(float(qv)) if qv not in (None, "") else 0
                except (TypeError, ValueError):
                    q = 0
                if q > 0:
                    site_qty[site_name] = site_qty.get(site_name, 0) + q
                    row_total += q

            if row_total <= 0:
                continue

            existing = out.setdefault(pn_s, {"desc": "", "site_qty": {}})
            if desc and not existing["desc"]:
                existing["desc"] = desc
            for s_name, q in site_qty.items():
                existing["site_qty"][s_name] = existing["site_qty"].get(s_name, 0) + q
            if pn_s not in part_to_group and current_group:
                part_to_group[pn_s] = current_group

            # Spares column on the same row → accumulate into the spares
            # pool keyed by part number. Spares qty doesn't gate row_total
            # so a part with only a spares value still counts.
            if spares_col is not None:
                sv = ws.cell(r, spares_col).value
                try:
                    sq = int(float(sv)) if sv not in (None, "") else 0
                except (TypeError, ValueError):
                    sq = 0
                if sq > 0:
                    spares_out[pn_s] = spares_out.get(pn_s, 0) + sq

        # Second pass: pick up parts that ONLY appear with a spares qty
        # (zero across all site cols) so the spares pool isn't missing
        # those entries. Walk again only when a spares col exists.
        if spares_col is not None:
            for r in range(hdr_row + 1, max_r + 1):
                pn = ws.cell(r, pn_col).value
                if pn is None:
                    continue
                pn_s = str(pn).strip()
                if not pn_s or pn_s in spares_out:
                    continue
                low = _hkey(pn_s)
                if low in _PN_HEADERS or low in _QTY_HEADERS or low in _ITEM_HEADERS:
                    continue
                sv = ws.cell(r, spares_col).value
                try:
                    sq = int(float(sv)) if sv not in (None, "") else 0
                except (TypeError, ValueError):
                    sq = 0
                if sq > 0:
                    spares_out[pn_s] = spares_out.get(pn_s, 0) + sq

        return sites, out, spares_out, part_to_group

    @classmethod
    def _parse_spares(cls, wb: Any) -> Dict[str, int]:
        """Return ``{part: total_qty}`` from a Spares/Spare Materials tab."""
        ws = cls._find_spares_sheet(wb)
        if ws is None:
            return {}
        try:
            _, parts, inline_spares, _ = cls._parse_per_site_bom(ws)
        except Exception as exc:
            logging.debug(f"[BoM Compare] spares parse failed for '{ws.title}': {exc}")
            return {}
        # Prefer an inline Spare column on the spares sheet itself; fall
        # back to summing every per-site qty when the tab is just a flat
        # list of available parts.
        if inline_spares:
            return inline_spares
        return {pn: sum(info["site_qty"].values()) for pn, info in parts.items()}

    # ------------------------------------------------------------------
    # Missing-sheet writer (BOM-style layout)
    # ------------------------------------------------------------------

    @staticmethod
    def _write_missing_sheet(
        ws: Any,
        sites: List[str],
        rows: List[Tuple[str, str, Dict[str, int], int, int]],
    ) -> None:
        thin = Side(style="thin", color="FF7F7F7F")
        border = Border(left=thin, right=thin, top=thin, bottom=thin)
        accent_fill = PatternFill(start_color="FF0087FF", end_color="FF0087FF", fill_type="solid")
        total_fill = PatternFill(start_color="FF005EBA", end_color="FF005EBA", fill_type="solid")
        spares_fill = PatternFill(start_color="FF548235", end_color="FF548235", fill_type="solid")
        need_fill = PatternFill(start_color="FFC00000", end_color="FFC00000", fill_type="solid")
        site_palette = [
            "FFDA9694", "FFFCD5B4", "FFC4D79B", "FF95B3D7", "FFB1A0C7",
            "FFFFE699", "FFD9E1F2", "FFE2EFDA", "FFFFF2CC", "FFFCE4D6",
        ]
        white_bold = Font(color="FFFFFFFF", bold=True)
        bold = Font(bold=True)
        center = Alignment(horizontal="center", vertical="center", wrap_text=True)
        left = Alignment(horizontal="left", vertical="center", wrap_text=True)
        green_font = Font(bold=True, color="FF548235")
        red_font = Font(bold=True, color="FFC00000")

        # Column layout: 1=Item, 2=Part No., 3=Description, 4..=site cols,
        # then Total Missing, Spares Available, Still Needed.
        site_cols: Dict[str, int] = {s: 4 + i for i, s in enumerate(sites)}
        total_col = 4 + len(sites)
        spares_col = total_col + 1
        need_col = spares_col + 1
        last_col = need_col

        # Title row
        ws.cell(1, 1, "Missing BOM — Sales BoM vs Factory BoM").font = Font(bold=True, size=13)
        ws.merge_cells(start_row=1, end_row=1, start_column=1, end_column=last_col)

        # Header rows (mirror Factory BoM: site/qty two-row header)
        site_hdr_row, qty_hdr_row, first_data_row = 3, 4, 5

        for col, label in ((1, "Item"), (2, "Part No."), (3, "Equipment Description")):
            head = ws.cell(site_hdr_row, col, label)
            head.fill = accent_fill
            head.font = white_bold
            head.alignment = center
            head.border = border
            sub = ws.cell(qty_hdr_row, col)
            sub.fill = accent_fill
            sub.border = border
            ws.merge_cells(
                start_row=site_hdr_row, end_row=qty_hdr_row,
                start_column=col, end_column=col,
            )

        for i, s in enumerate(sites):
            color = site_palette[i % len(site_palette)]
            fill = PatternFill(start_color=color, end_color=color, fill_type="solid")
            head = ws.cell(site_hdr_row, site_cols[s], s)
            head.fill = fill
            head.font = bold
            head.alignment = center
            head.border = border
            sub = ws.cell(qty_hdr_row, site_cols[s], "Missing")
            sub.fill = fill
            sub.font = bold
            sub.alignment = center
            sub.border = border

        for col, label, fill in (
            (total_col, "Total Missing", total_fill),
            (spares_col, "Spares Available", spares_fill),
            (need_col, "Still Needed", need_fill),
        ):
            head = ws.cell(site_hdr_row, col, label)
            head.fill = fill
            head.font = white_bold
            head.alignment = center
            head.border = border
            sub = ws.cell(qty_hdr_row, col, "Qty")
            sub.fill = fill
            sub.font = white_bold
            sub.alignment = center
            sub.border = border

        # Data rows
        for i, (pn, desc, short_per_site, total_missing, spares_avail) in enumerate(rows, start=first_data_row):
            usable_spares = min(spares_avail, total_missing)
            still_needed = max(0, total_missing - spares_avail)

            ws.cell(i, 1, i - first_data_row + 1).alignment = center
            pn_cell = ws.cell(i, 2, pn)
            pn_cell.font = bold
            pn_cell.alignment = center
            ws.cell(i, 3, desc).alignment = left
            for s in sites:
                v = short_per_site.get(s, 0)
                cell = ws.cell(i, site_cols[s], v or None)
                cell.alignment = center
            tcell = ws.cell(i, total_col, total_missing)
            tcell.alignment = center
            tcell.font = bold

            scell = ws.cell(i, spares_col, usable_spares or None)
            scell.alignment = center
            if usable_spares > 0:
                scell.font = green_font

            ncell = ws.cell(i, need_col, still_needed or None)
            ncell.alignment = center
            if still_needed > 0:
                ncell.font = red_font
            elif total_missing > 0:
                # Fully covered by spares — leave qty blank but mark green.
                ncell.font = green_font

            for c in range(1, last_col + 1):
                ws.cell(i, c).border = border

        # Column widths + freeze panes
        widths = {1: 6, 2: 18, 3: 50}
        for col, w in widths.items():
            ws.column_dimensions[get_column_letter(col)].width = w
        for s, col in site_cols.items():
            ws.column_dimensions[get_column_letter(col)].width = max(10, min(20, len(s) + 2))
        ws.column_dimensions[get_column_letter(total_col)].width = 14
        ws.column_dimensions[get_column_letter(spares_col)].width = 16
        ws.column_dimensions[get_column_letter(need_col)].width = 14
        ws.freeze_panes = f"D{first_data_row}"

        if not rows:
            note = ws.cell(first_data_row, 1, "No shortfalls — Sales BoM is fully covered by Factory BoM.")
            note.alignment = center
            ws.merge_cells(
                start_row=first_data_row, end_row=first_data_row,
                start_column=1, end_column=last_col,
            )

    # ------------------------------------------------------------------
    # Spares allocation + Breakdown writer
    # ------------------------------------------------------------------

    @staticmethod
    def _build_breakdown(
        rows: List[Tuple[str, str, Dict[str, int], int, int]],
    ) -> List[Tuple[str, str, Dict[str, int], int, int, int]]:
        """Allocate spares to needy sites smallest-shortfall-first.

        For each Missing-BOM row that has any spares available, walk the
        per-site shortfall in ascending order and pull from the spares
        pool until either every site is satisfied or the pool is empty.
        Maximizes the number of sites that get fully covered.

        Returns ``[(part, desc, allocated_per_site, total_allocated,
        spares_used, spares_remaining), ...]`` for parts where at least
        one unit could be allocated.
        """
        breakdown: List[Tuple[str, str, Dict[str, int], int, int, int]] = []
        for pn, desc, short_per_site, total_missing, spares_avail in rows:
            if spares_avail <= 0 or total_missing <= 0:
                continue
            sorted_sites = sorted(
                short_per_site.items(), key=lambda kv: (kv[1], kv[0])
            )
            remaining = spares_avail
            allocated: Dict[str, int] = {}
            for site, need in sorted_sites:
                if remaining <= 0:
                    break
                give = min(need, remaining)
                if give > 0:
                    allocated[site] = give
                    remaining -= give
            total_alloc = sum(allocated.values())
            if total_alloc <= 0:
                continue
            spares_used = total_alloc
            spares_left = max(0, spares_avail - spares_used)
            breakdown.append((pn, desc, allocated, total_alloc, spares_used, spares_left))
        return breakdown

    # ------------------------------------------------------------------
    # Output path
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_out_path(factory_path: str) -> str:
        base, ext = os.path.splitext(factory_path)
        return f"{base}.COMPARE{ext or '.xlsx'}"
