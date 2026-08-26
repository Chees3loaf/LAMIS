"""
gui/bom_compare_frame.py - "BoM Comparison" sub-mode under File Processing.

Loads a Factory BoM workbook and a Sales BoM workbook, parses each BOM
sheet for per-site quantities, and emits a new workbook with three tabs:

* Shortfall      — workbook-level comparison per part with six columns:
                   ``Item | Part No. | Equipment Description | Total
                   Ordered | Live Inventory | Difference``. Total Ordered
                   is the Sales BoM's Total column (per-site + Sales
                   spares); Live Inventory is the Factory per-site total
                   + Factory spares. Difference = Live − Ordered, colored
                   **red** when negative (short) and **green** when
                   positive (surplus). Sort is delta-ascending so the
                   worst shortages appear at the top.
* Live Inventory — values-only copy of the source Factory BOM sheet,
                   renamed to reflect "what's currently on hand".
* Sales BoM      — values-only copy of the Sales BOM sheet (price
                   columns hidden, branding artwork stripped).
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
from services.bom_compare_core import BomCompareEngine


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
# Column-header version of the exclude list. "License points" columns
# are excluded here just like the banner version: the operator reported
# that counting that column produced false positives (it's a license-
# accounting bucket, not a hardware-order column), so any header
# containing "license" is dropped as a site source.
_EXCLUDED_COLUMN_HEADERS = (
    "unit price", "price", "maintenance", "software",
    "services", "service", "support", "warranty", "labor",
    "training", "installation", "license",
)
# Per-site DETAIL tab titles to skip during the detail-tab walk. These
# are non-site buckets that shouldn't contribute qty: the workbook's
# own Summary plus the License-Points pool (see _EXCLUDED_COLUMN_HEADERS).
_DETAIL_TAB_SKIP_TITLES = ("summary", "license points")
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
    "training", "installation",
    "year - tech", "year tech", "year - software", "year software",
    "release subscription", "license",
    # NSP "Feature Pack" software products — caught by the trailing
    # " fp" (e.g. "NSP NETWORK INFRASTRUCTURE MANAGEMENT FP" or
    # "NSP SERVICE ACTIVATION + CONFIG. FP"). Word-boundary match
    # via leading space avoids false positives on "SFP" / "QSFP".
    " fp", "feature pack",
    # "services" intentionally NOT listed — too broad, matches real
    # hardware like "Integrated Services Card". Software-services
    # rows are already caught by the other keywords (subscription /
    # support / maintenance / year - software).
)
# Column-header keywords that should NEVER be treated as a per-site
# column (they're price/cost/metadata columns, not site quantities).
_NON_SITE_HEADERS = (
    "unit price", "price", "cost", "ext price", "extended price",
    "list price", "msrp", "discount", "amount", "$", "usd", "currency",
    "uom", "unit", "weight", "lead time", "vendor", "manufacturer",
    "category", "notes", "comment",
    # "network" intentionally NOT excluded — Sales BoMs use a "Network"
    # column as a real qty bucket for network-wide hardware allocations
    # (cards/MDAs that aren't tied to a specific site). The row-level
    # description filter (_INTANGIBLE_DESC_KEYWORDS) still drops
    # software/license rows that happen to land in that column.
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


def _qty_cell_to_int(qv: Any) -> int:
    """Parse a worksheet cell value to a non-negative int, tolerating
    forms real-world Sales BoMs use:

    * ``None`` / ``""`` -> 0
    * plain int / float -> int(float(qv))
    * ``"7"`` (plain numeric string) -> 7
    * ``'"7"'`` (quoted numeric string — someone typed ``="7"`` or
      pasted a value with literal quotes) -> 7
    * anything else (text, ``#REF!``, ``N/A``) -> 0

    Centralized so every parser site (per-site, spares, banner check,
    detail tabs) handles the same edge cases consistently.
    """
    if qv is None or qv == "":
        return 0
    if isinstance(qv, str):
        cleaned = qv.strip().strip('"').strip("'").strip()
        if not cleaned:
            return 0
        try:
            return int(float(cleaned))
        except (TypeError, ValueError):
            return 0
    try:
        return int(float(qv))
    except (TypeError, ValueError):
        return 0


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


def load_part_kits(path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load kit-grouping definitions from ``data/part_aliases.json``.

    Each kit is ``{"kit": "<kit_sku>", "components": ["<sku>", ...],
    "kit_description": "<desc>"}``. When ALL components are present on
    a given BoM side (per-site count > 0 for each), the comparison
    rolls them into the kit SKU using ``min(component counts)``. If
    any component is missing on that side, the others stay listed as
    individual lines — see :func:`fold_kits` for the folding rule.
    Returns an empty list when the file or section is missing.
    """
    if path is None:
        path = str(get_data_dir() / "part_aliases.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    raw = payload.get("kits") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        kit = entry.get("kit")
        comps = entry.get("components")
        if not isinstance(kit, str) or not isinstance(comps, list):
            continue
        kit_canonical = _strip_vendor_prefix(kit).upper()
        comp_canonical = [
            _strip_vendor_prefix(c).upper()
            for c in comps if isinstance(c, str) and c
        ]
        if not kit_canonical or not comp_canonical:
            continue
        out.append({
            "kit": kit_canonical,
            "components": comp_canonical,
            "kit_description": str(entry.get("kit_description", "")),
        })
    return out


def load_excluded_parts(path: Optional[str] = None) -> set:
    """Load the discontinued / excluded part-number set from
    ``data/part_aliases.json`` under the ``"excluded_parts"`` key.

    These SKUs are dropped from the comparison entirely — they never
    appear on Shortfall, Site Allocation, or Trace, regardless of which
    side lists them. Use for vendor-discontinued hardware (e.g. CFP2
    optics) that shouldn't be reconciled.

    Each entry may be a bare PN string or ``{"pn": ..., "reason": ...}``.
    Returns a set of canonical (vendor-prefix-stripped, uppercased)
    part numbers. Empty set when the file or section is missing.
    """
    if path is None:
        path = str(get_data_dir() / "part_aliases.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return set()
    raw = payload.get("excluded_parts") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return set()
    out: set = set()
    for entry in raw:
        pn = entry.get("pn") if isinstance(entry, dict) else entry
        if isinstance(pn, str) and pn.strip():
            out.add(_strip_vendor_prefix(pn).upper())
    return out


def compute_kit_fold_ops(
    totals_per_pn: Dict[str, int],
    kits: List[Dict[str, Any]],
) -> List[Tuple[str, int, List[str]]]:
    """Return the list of folds ``fold_kits`` would apply to
    *totals_per_pn*, without mutating anything.

    Each entry is ``(kit_sku, k_folds, [component_pns])``. ``k_folds``
    is the kit qty that gets synthesized; component counts are
    decremented by the same value. Returns an empty list when no
    kit's full component set is present.

    Used by the Trace sheet writer so the kit-folded units have a
    visible audit row under the kit SKU, otherwise the Trace's
    Live-side sum would fall short of the Shortfall's Live Inventory
    by ``k_folds`` per kit.
    """
    ops: List[Tuple[str, int, List[str]]] = []
    if not kits:
        return ops
    for kit_def in kits:
        kit = kit_def["kit"]
        comps = kit_def["components"]
        counts = [int(totals_per_pn.get(c, 0)) for c in comps]
        if not all(n > 0 for n in counts):
            continue
        k = min(counts)
        if k > 0:
            ops.append((kit, k, list(comps)))
    return ops


def fold_kits(
    totals_per_pn: Dict[str, int],
    kits: List[Dict[str, Any]],
) -> Dict[str, int]:
    """Fold component SKU totals into their kit SKU using the
    ``all-components-present + min`` rule.

    Mutates *totals_per_pn* in place and also returns it for chaining.
    For each kit definition:

    - Look up the count of every listed component in *totals_per_pn*.
    - If ANY component has count ``0`` (or is missing), skip the kit —
      the remaining components stay listed as their own SKUs. This is
      the user's "must see all three to count as a kit" rule.
    - Otherwise let ``k = min(component counts)``. Subtract ``k`` from
      every component's total (consuming them into kits) and add ``k``
      to the kit SKU's total.

    Spares are NOT included in kit folding — they're tracked separately
    by the caller and stay associated with the original component SKU.
    """
    if not kits:
        return totals_per_pn
    for kit_def in kits:
        kit = kit_def["kit"]
        comps = kit_def["components"]
        counts = [int(totals_per_pn.get(c, 0)) for c in comps]
        if not all(n > 0 for n in counts):
            # User's rule: any component missing → no folding for this kit.
            continue
        k = min(counts)
        for c in comps:
            totals_per_pn[c] = int(totals_per_pn.get(c, 0)) - k
        totals_per_pn[kit] = int(totals_per_pn.get(kit, 0)) + k
    return totals_per_pn


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
    SKU's description when both forms are present (so the Shortfall
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


class BomCompareFrame(ttk.Frame, BomCompareEngine):
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

        f1 = ttk.LabelFrame(self, text="Live Inventory workbook (Factory BoM)")
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
        if msg.strip():
            logging.info("[BOM COMPARE] %s", msg.rstrip())

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
            title="Select Live Inventory workbook (Factory BoM)",
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
            messagebox.showerror("BoM Comparison", "Pick a valid Live Inventory (Factory BoM) workbook.")
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
