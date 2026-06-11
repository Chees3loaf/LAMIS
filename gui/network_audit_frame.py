"""Network Audit frame — Diagnostics → RLS REST-based network audit.

Drives ``scripts/Network/RLS_Audit.py`` (adapted from Apple's
``rls_audit_updated`` reference). One seed host + credentials are
enough — the audit's first REST call
(``restconf/data/ciena-6500r-nodes:nodes=*``) discovers the full
topology and walks every node automatically. Seed file, max-hop, and
seed-TID inputs from the old TDS-based version are gone; they're
unnecessary with REST discovery.
"""
from __future__ import annotations

import datetime
import ipaddress
import logging
import os
import re
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from utils.helpers import (
    friendly_error,
    get_desktop_dir,
    load_user_prefs,
    save_user_prefs,
    scrub_password_widget,
)


_PREFS_KEY_AUDIT_DIR = "network_audit_output_dir"


def _resolve_default_output_dir() -> str:
    """Pick the directory the Browse dialog opens in / Output File
    defaults under.

    Order of preference:
      1. Last directory the operator browsed to, if it still exists.
      2. The OS Desktop directory.
      3. The user's home directory (only if Desktop is missing).
    """
    prefs = load_user_prefs()
    remembered = prefs.get(_PREFS_KEY_AUDIT_DIR)
    if isinstance(remembered, str) and remembered:
        if os.path.isdir(remembered):
            return remembered
    desktop = get_desktop_dir()
    if desktop.is_dir():
        return str(desktop)
    return os.path.expanduser("~")


def _is_valid_host(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9.\-]*$", value) and "&" not in value)


class NetworkAuditFrame(ttk.Frame):
    """Tk frame for the RLS REST Network Audit (Diagnostics sub-mode)."""

    def __init__(self, parent: ttk.Frame, controller) -> None:
        super().__init__(parent)
        self.controller = controller
        self._running = False
        self._build()

    def _build(self) -> None:
        cfg = ttk.LabelFrame(self, text="Network Audit Configuration")
        cfg.pack(fill=tk.X, pady=5)

        tk.Label(cfg, text="Seed IP / Hostname:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.seed_entry = tk.Entry(cfg, width=30)
        self.seed_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        tk.Label(
            cfg,
            text="(one node — the audit auto-discovers the rest via RESTCONF)",
            fg="gray",
        ).grid(row=0, column=2, columnspan=2, sticky="w", padx=5)

        # Pre-fill with the Ciena RLS RESTCONF defaults from the
        # encrypted credential store. The shell user ``su`` does NOT
        # have REST API access; ``diaguser`` does. The operator can
        # override either field if the network has rotated the
        # factory defaults.
        try:
            from utils.credentials import get_default_credential_for_vendor
            _default_user, _default_pass = (
                get_default_credential_for_vendor("ciena-rls-rest")
                or ("diaguser", "Ciena123")
            )
        except Exception:
            _default_user, _default_pass = ("diaguser", "Ciena123")

        tk.Label(cfg, text="Username:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.username_entry = tk.Entry(cfg, width=20)
        self.username_entry.insert(0, _default_user)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        tk.Label(cfg, text="Password:").grid(row=1, column=2, sticky="w", padx=5, pady=5)
        self.password_entry = tk.Entry(cfg, width=20, show="*")
        self.password_entry.insert(0, _default_pass)
        self.password_entry.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        tk.Label(
            cfg,
            text=(
                "(RLS RESTCONF default: 'diaguser' / 'Ciena123' --"
                " override only if your network has rotated)"
            ),
            fg="gray",
        ).grid(row=2, column=0, columnspan=4, sticky="w", padx=5)

        tk.Label(cfg, text="Output File:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.output_entry = tk.Entry(cfg, width=50)
        self.output_entry.grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky="w")
        # Default output dir: last-used directory the operator browsed
        # to (if it still exists), else the OS Desktop. Path is built
        # at frame construction so the timestamp reflects when the
        # operator opened the screen, not when the audit fires.
        default_dir = _resolve_default_output_dir()
        default_out = os.path.join(
            default_dir,
            f"RLS_Audit_{datetime.datetime.now():%Y-%m-%d_%H%M%S}.xlsx",
        )
        self.output_entry.insert(0, default_out)
        tk.Button(cfg, text="Browse…", command=self._browse_output).grid(
            row=3, column=3, padx=5, pady=5, sticky="w",
        )

        # Optional toggles
        opts = ttk.LabelFrame(self, text="Optional Data Collection")
        opts.pack(fill=tk.X, pady=5)
        self.capture_alarms_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            opts, text="Capture active alarms (adds 'Alarms' sheet)",
            variable=self.capture_alarms_var,
        ).pack(anchor="w", padx=10, pady=2)
        self.capture_history_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            opts, text="Capture alarm history (adds 'Alarm History' sheet)",
            variable=self.capture_history_var,
        ).pack(anchor="w", padx=10, pady=2)

        controls = ttk.Frame(self)
        controls.pack(fill=tk.X, pady=10)
        self.run_button = tk.Button(
            controls, text="Run Network Audit", command=self.run_audit,
        )
        self.run_button.pack(side=tk.RIGHT, padx=5)
        self.status_label = tk.Label(controls, text="Status: Ready", anchor="w")
        self.status_label.pack(side=tk.RIGHT, padx=10)

    def _browse_output(self) -> None:
        current = self.output_entry.get().strip()
        # Open the dialog in the same directory the entry currently
        # shows, falling back to the prefs/Desktop resolver -- avoids
        # opening at "(My Documents)" when the user has explicitly
        # picked another folder during this session.
        initial_dir = os.path.dirname(current) if current else ""
        if not initial_dir or not os.path.isdir(initial_dir):
            initial_dir = _resolve_default_output_dir()
        path = filedialog.asksaveasfilename(
            title="Save audit report as",
            defaultextension=".xlsx",
            filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")],
            initialdir=initial_dir,
            initialfile=os.path.basename(current or "RLS_Audit.xlsx"),
        )
        if path:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, path)

    def run_audit(self) -> None:
        if self._running:
            return
        seed = self.seed_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        output_path = self.output_entry.get().strip()
        capture_alarms = self.capture_alarms_var.get()
        capture_history = self.capture_history_var.get()

        if not seed:
            messagebox.showerror("Input Error", "Seed IP / hostname is required.")
            return
        if not _is_valid_host(seed):
            messagebox.showerror("Input Error", f"Invalid seed: {seed!r}")
            return
        if not username:
            messagebox.showerror("Input Error", "Username is required.")
            return
        if not password:
            messagebox.showerror("Input Error", "Password is required.")
            return
        if not output_path:
            messagebox.showerror("Input Error", "Output file path is required.")
            return
        out_dir = os.path.dirname(output_path)
        if out_dir and not os.path.isdir(out_dir):
            try:
                os.makedirs(out_dir, exist_ok=True)
            except OSError as exc:
                messagebox.showerror(
                    "Input Error",
                    f"Could not create output directory:\n{out_dir}\n\n{exc}",
                )
                return

        self._running = True
        self.run_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Discovering…")
        out = self.controller.output_screen
        out.insert(tk.END, f"\n── RLS Network Audit ──\n")
        out.insert(tk.END, f"Seed     : {seed}\n")
        out.insert(tk.END, f"Output   : {output_path}\n")
        out.insert(tk.END, f"Alarms   : {'on' if capture_alarms else 'off'}\n")
        out.insert(tk.END, f"History  : {'on' if capture_history else 'off'}\n")
        out.see(tk.END)

        root = self.controller.root

        def _log_to_panel(msg: str) -> None:
            """Forward audit progress lines to the main output panel. Must
            be marshaled to the Tk thread."""
            def _do() -> None:
                out.insert(tk.END, str(msg) + "\n")
                out.see(tk.END)
            try:
                root.after(0, _do)
            except Exception:
                pass

        def _worker() -> None:
            try:
                from scripts.Network.RLS_Audit import run_audit
                run_audit(
                    seed_host=seed,
                    username=username,
                    password=password,
                    output_path=output_path,
                    capture_alarms=capture_alarms,
                    capture_alarm_history=capture_history,
                    log_callback=_log_to_panel,
                )
                scrub_password_widget(self.password_entry)
                # Remember the directory the operator just used so the
                # next audit defaults to it. Only persisted on success
                # -- a failed run shouldn't move the default away from
                # somewhere the operator was already using.
                try:
                    chosen_dir = os.path.dirname(output_path)
                    if chosen_dir and os.path.isdir(chosen_dir):
                        prefs = load_user_prefs()
                        prefs[_PREFS_KEY_AUDIT_DIR] = chosen_dir
                        save_user_prefs(prefs)
                except Exception:
                    logging.exception(
                        "Could not persist last network-audit output dir"
                    )

                def on_complete() -> None:
                    self.run_button.config(state=tk.NORMAL)
                    self.status_label.config(text="Status: Ready")
                    self._running = False
                    out.insert(tk.END, f"\nAudit complete. Saved to:\n  {output_path}\n")
                    out.see(tk.END)
                    messagebox.showinfo(
                        "Network Audit Complete",
                        f"Audit finished.\n\nReport: {output_path}",
                    )

                root.after(0, on_complete)
            except RuntimeError as exc:
                # ``_audit_abort`` raises RuntimeError when the audit
                # decides it can't proceed (bad DNS, no nodes reachable,
                # etc.). Surface the message clearly. Capture ``exc`` to
                # a separate name -- Python deletes ``exc`` at the end
                # of the except block (PEP 3110), but the nested
                # callback runs later via ``root.after``.
                abort_msg = str(exc)

                def on_audit_abort() -> None:
                    self.run_button.config(state=tk.NORMAL)
                    self.status_label.config(text="Status: Aborted")
                    self._running = False
                    out.insert(tk.END, f"\n[ABORT] {abort_msg}\n")
                    out.see(tk.END)
                    messagebox.showerror("Network Audit Aborted", abort_msg)

                root.after(0, on_audit_abort)
            except Exception as exc:
                logging.exception("RLS Network Audit unexpected error")
                # Same PEP 3110 hazard as above -- bind the message
                # string in this scope, not the exception object itself,
                # so the deferred callback can still read it.
                err_msg = friendly_error(exc)

                def on_error() -> None:
                    self.run_button.config(state=tk.NORMAL)
                    self.status_label.config(text="Status: Error")
                    self._running = False
                    out.insert(tk.END, f"\n[ERROR] {err_msg}\n")
                    out.see(tk.END)
                    messagebox.showerror("Network Audit Error", err_msg)

                root.after(0, on_error)

        threading.Thread(target=_worker, daemon=True).start()
