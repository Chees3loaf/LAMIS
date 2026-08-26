"""NetworkAuditFrame — GUI panel for RLS network audit configuration and execution."""

import logging
import os
import tempfile
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional, Callable

from utils.credentials import get_default_credential_for_vendor


class NetworkAuditFrame(ttk.Frame):
    """Frame for RLS network audit configuration.
    
    Pre-fills with diaguser/Ciena123 (RLS RESTCONF defaults) and manages
    the audit execution via run_audit callback.
    """

    def __init__(self, parent: ttk.Frame, controller=None) -> None:
        super().__init__(parent)
        self.controller = controller
        self._build()

    def _build(self) -> None:
        """Build the network audit configuration frame."""
        # --- Configuration frame ---
        cfg = ttk.LabelFrame(self, text="Network Audit Configuration")
        cfg.pack(fill=tk.X, pady=5, padx=10)

        # Seed host
        tk.Label(cfg, text="Seed Host (IP or hostname):").grid(
            row=0, column=0, sticky="w", padx=5, pady=5
        )
        self.seed_host_entry = tk.Entry(cfg, width=30)
        self.seed_host_entry.grid(row=0, column=1, padx=5, pady=5)

        # Username
        tk.Label(cfg, text="Username:").grid(
            row=1, column=0, sticky="w", padx=5, pady=5
        )
        self.username_entry = tk.Entry(cfg, width=30)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        # Pre-fill with RLS RESTCONF default (diaguser)
        self.username_entry.insert(0, "diaguser")

        # Username hint
        hint_label = tk.Label(
            cfg, text="(RLS RESTCONF default)", foreground="blue", font=("Arial", 9)
        )
        hint_label.grid(row=1, column=2, sticky="w", padx=5, pady=5)

        # Password
        tk.Label(cfg, text="Password:").grid(
            row=2, column=0, sticky="w", padx=5, pady=5
        )
        self.password_entry = tk.Entry(cfg, width=30, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        # Pre-fill with RLS RESTCONF default password
        self.password_entry.insert(0, "Ciena123")

        # Capture alarms
        self.capture_alarms_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            cfg,
            text="Capture alarms",
            variable=self.capture_alarms_var,
        ).grid(row=3, column=0, sticky="w", padx=5, pady=5)

        # Capture alarm history
        self.capture_alarm_history_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            cfg,
            text="Capture alarm history",
            variable=self.capture_alarm_history_var,
        ).grid(row=3, column=1, sticky="w", padx=5, pady=5)

        # Debug
        self.debug_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            cfg,
            text="Debug mode",
            variable=self.debug_var,
        ).grid(row=4, column=0, sticky="w", padx=5, pady=5)

        # Output path
        tk.Label(cfg, text="Output workbook:").grid(
            row=5, column=0, sticky="w", padx=5, pady=5
        )
        self.output_path_entry = tk.Entry(cfg, width=30)
        self.output_path_entry.grid(row=5, column=1, padx=5, pady=5)
        # Default to a temp location
        self.output_path_entry.insert(0, os.path.join(tempfile.gettempdir(), "audit.xlsx"))

        # Control buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, pady=10, padx=10)

        self.run_button = tk.Button(
            btn_frame, text="Run Audit", command=self.run_audit, width=15
        )
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = tk.Button(
            btn_frame, text="Clear", command=self.clear_fields, width=15
        )
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Status label
        self.status_label = tk.Label(self, text="Status: Ready", foreground="green")
        self.status_label.pack(fill=tk.X, padx=10, pady=5)

        # Output text
        self.output_text = tk.Text(
            self, height=15, width=80, state=tk.DISABLED, wrap=tk.WORD
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def run_audit(self) -> None:
        """Validate inputs and launch the network audit in a background thread."""
        seed_host = self.seed_host_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        output_path = self.output_path_entry.get().strip()

        if not seed_host:
            messagebox.showerror("Input Error", "Please enter a seed host IP or hostname.")
            return
        if not username:
            messagebox.showerror("Input Error", "Please enter a username.")
            return
        if not password:
            messagebox.showerror("Input Error", "Please enter a password.")
            return
        if not output_path:
            messagebox.showerror("Input Error", "Please enter an output workbook path.")
            return

        self.status_label.config(text="Status: Running...", foreground="orange")
        self.run_button.config(state=tk.DISABLED)

        thread = threading.Thread(
            target=self._run_audit_thread,
            args=(seed_host, username, password, output_path),
            daemon=True,
        )
        thread.start()

    def _run_audit_thread(
        self, seed_host: str, username: str, password: str, output_path: str
    ) -> None:
        """Execute the audit in a background thread."""
        try:
            self._log_output(f"Starting network audit on {seed_host}...\n")

            from scripts.Network import RLS_Audit

            def log_callback(msg: str) -> None:
                self._log_output(msg + "\n")

            RLS_Audit.run_audit(
                seed_host=seed_host,
                username=username,
                password=password,
                output_path=output_path,
                capture_alarms=self.capture_alarms_var.get(),
                capture_alarm_history=self.capture_alarm_history_var.get(),
                debug=self.debug_var.get(),
                log_callback=log_callback,
            )

            self._log_output(f"Audit complete. Results stored in {output_path}\n")
            self.status_label.config(text="Status: Complete", foreground="green")
            messagebox.showinfo("Audit Complete", f"Results saved to:\n{output_path}")

        except Exception as e:
            error_msg = f"Audit failed: {e}\n"
            self._log_output(error_msg)
            self.status_label.config(text="Status: Failed", foreground="red")
            logging.exception("Network audit error")
            messagebox.showerror("Audit Error", error_msg)

        finally:
            self.run_button.config(state=tk.NORMAL)

    def _log_output(self, msg: str) -> None:
        """Append a message to the output text widget (thread-safe)."""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, msg)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.output_text.update()

    def clear_fields(self) -> None:
        """Clear all input fields."""
        self.seed_host_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.username_entry.insert(0, "diaguser")
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, "Ciena123")
        self.output_path_entry.delete(0, tk.END)
        self.output_path_entry.insert(0, os.path.join(tempfile.gettempdir(), "audit.xlsx"))
        self.capture_alarms_var.set(False)
        self.capture_alarm_history_var.set(False)
        self.debug_var.set(False)
        self.status_label.config(text="Status: Ready", foreground="green")
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
