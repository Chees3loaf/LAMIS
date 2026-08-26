"""
gui/bom_frame.py - "BoM" sub-mode under File Processing.

Adds (or refreshes) a Bill of Materials sheet on an existing inventory
workbook by reading the Summary sheet's display labels, following each
row's hyperlink to the underlying device tab, and aggregating part rows
through ``WorkbookBuilder._build_bom_sheet``.
"""
import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

import openpyxl

from services.workbook_builder import (
    INVENTORY_TAB_NAME,
    _LEGACY_INVENTORY_TAB_NAME,
    find_inventory_sheet_name,
)
from services.bom_build_core import BomBuildEngine


_HYPERLINK_TARGET_RE = re.compile(r"^#?'?([^'!]+?)'?!")

# Tabs that should never end up on a synthesized BOM: template/metadata
# leftovers (Customer-project, Customer, Project, Header, Cover) and
# aggregate Task Order roll-up sheets (T##, TO##) whose contents the BOM
# itself is meant to replace.  Matched case-insensitively against the tab
# name.  Only applied when we synthesize the Summary — if the workbook
# already shipped a Summary we trust what it lists.
_TEMPLATE_TAB_NAMES = {"customer-project", "customer", "project", "header", "cover"}
_AGGREGATE_TAB_RE = re.compile(r"^TO?\d{1,3}$", re.IGNORECASE)


def _is_non_inventory_tab(name: str) -> bool:
    s = (name or "").strip().lower()
    if s in _TEMPLATE_TAB_NAMES:
        return True
    if _AGGREGATE_TAB_RE.match(name or ""):
        return True
    return False


def _unique_display_title(label: str, used: set) -> str:
    """Return a stable BOM column label without collapsing duplicate TIDs."""
    if label not in used:
        used.add(label)
        return label
    occurrence = 2
    while f"{label} ({occurrence})" in used:
        occurrence += 1
    title = f"{label} ({occurrence})"
    used.add(title)
    return title


def _resolve_hyperlink_target(cell: Any) -> Optional[str]:
    """Return the underlying sheet name a Summary cell links to, if any."""
    link = getattr(cell, "hyperlink", None)
    if link is None:
        return None
    raw = getattr(link, "location", None) or getattr(link, "target", None)
    if not raw:
        return None
    m = _HYPERLINK_TARGET_RE.match(str(raw))
    return m.group(1).strip() if m else None


class BomFrame(ttk.Frame, BomBuildEngine):
    """UI panel for adding / refreshing the BOM sheet on an existing workbook."""

    def __init__(self, parent: tk.Widget, gui: Any) -> None:
        super().__init__(parent)
        self.gui = gui
        self._input_path: Optional[str] = None
        self._running = False
        self._setup_ui()

    # ------------------------------------------------------------------
    # Widget construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        pad: Dict[str, int] = {"padx": 8, "pady": 4}

        file_frame = ttk.LabelFrame(self, text="Workbook (.xlsx with a Summary sheet)")
        file_frame.pack(fill=tk.X, **pad)

        self._file_label = tk.StringVar(value="No workbook selected")
        ttk.Label(file_frame, textvariable=self._file_label, width=80, anchor="w").pack(
            side=tk.LEFT, padx=6, pady=6
        )
        ttk.Button(file_frame, text="Browse…", command=self._browse_file).pack(
            side=tk.LEFT, padx=6, pady=6
        )

        ctrl_frame = ttk.Frame(self)
        ctrl_frame.pack(fill=tk.X, **pad)

        self._run_btn = ttk.Button(
            ctrl_frame, text="Build / Refresh BOM", command=self._on_run
        )
        self._run_btn.pack(side=tk.LEFT, padx=6)

        self._status_var = tk.StringVar(value="Ready — select a workbook and click Build / Refresh BOM")
        ttk.Label(ctrl_frame, textvariable=self._status_var, foreground="gray").pack(
            side=tk.LEFT, padx=12
        )

        log_frame = ttk.LabelFrame(self, text="Build Log")
        log_frame.pack(fill=tk.BOTH, expand=True, **pad)
        self._log = scrolledtext.ScrolledText(log_frame, height=14, state="disabled", wrap="word")
        self._log.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _append_log(self, msg: str) -> None:
        if msg.strip():
            logging.info("[BOM] %s", msg.rstrip())

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

    def _browse_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select inventory workbook",
            filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")],
        )
        if not path:
            return
        self._input_path = path
        self._file_label.set(path)
        self._set_status("Ready — click Build / Refresh BOM")

    def _on_run(self) -> None:
        if self._running:
            return
        if not self._input_path or not os.path.isfile(self._input_path):
            messagebox.showerror("BoM", "Select a valid .xlsx workbook first.")
            return
        self._running = True
        self._run_btn.configure(state="disabled")
        self._set_status("Building BOM…")
        threading.Thread(target=self._run_worker, args=(self._input_path,), daemon=True).start()

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    def _run_worker(self, path: str) -> None:
        try:
            out_path = self._build(path)
            self._append_log(f"Wrote: {out_path}")
            self._set_status(f"Done — {os.path.basename(out_path)}")
        except Exception as exc:
            logging.exception("[BoM] build failed")
            # Snapshot the message before the except block exits — Python
            # deletes the bound `exc` at the end of `except`, so capturing it
            # inside the after() lambda's free scope blows up with NameError.
            err_msg = str(exc)
            self._append_log(f"ERROR: {err_msg}")
            self._set_status("Failed")
            try:
                self.after(0, lambda: messagebox.showerror("BoM", err_msg))
            except Exception:
                pass
        finally:
            self._running = False
            try:
                self.after(0, lambda: self._run_btn.configure(state="normal"))
            except Exception:
                pass
