"""TDS diagnostics frame — widgets and logic for the TDS mode."""
import os
import sys
import logging
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import config


class TDSFrame(ttk.Frame):
    """Tkinter frame for the TDS (Diagnostics) mode.

    Owns all TDS configuration widgets and the ``run_tds`` worker.  Uses
    *controller* only to access ``controller.root`` (for ``root.after``) and
    ``controller.output_screen`` (to append log lines).
    """

    def __init__(self, parent: ttk.Frame, controller) -> None:
        super().__init__(parent)
        self.controller = controller
        self._build()

    # ------------------------------------------------------------------
    # Frame construction
    # ------------------------------------------------------------------

    def _build(self) -> None:
        config_frame = ttk.LabelFrame(self, text="TDS Configuration")
        config_frame.pack(fill=tk.X, pady=5)

        tk.Label(config_frame, text="IP Address:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.tds_ip_entry = tk.Entry(config_frame, width=25)
        self.tds_ip_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(config_frame, text="Platform (6500/rls):").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.tds_platform_var = tk.StringVar(value="rls")
        self.tds_platform_combo = ttk.Combobox(
            config_frame, textvariable=self.tds_platform_var,
            values=["rls", "6500"], width=10, state="readonly",
        )
        self.tds_platform_combo.grid(row=0, column=3, padx=5, pady=5)

        tk.Label(config_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.tds_username_entry = tk.Entry(config_frame, width=25)
        self.tds_username_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(config_frame, text="Password:").grid(row=1, column=2, sticky="w", padx=5, pady=5)
        self.tds_password_entry = tk.Entry(config_frame, width=25, show="*")
        self.tds_password_entry.grid(row=1, column=3, padx=5, pady=5)

        tk.Label(config_frame, text="File Name:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.tds_filename_entry = tk.Entry(config_frame, width=25)
        self.tds_filename_entry.grid(row=2, column=1, padx=5, pady=5)

        tds_control_frame = ttk.Frame(self)
        tds_control_frame.pack(fill=tk.X, pady=10)

        self.tds_run_button = tk.Button(tds_control_frame, text="Run Diagnostics", command=self.run_tds)
        self.tds_run_button.pack(side=tk.RIGHT, padx=5)

        self.tds_status_label = tk.Label(tds_control_frame, text="Status: Ready", anchor="w")
        self.tds_status_label.pack(side=tk.RIGHT, padx=10)

    # ------------------------------------------------------------------
    # TDS worker
    # ------------------------------------------------------------------

    def run_tds(self) -> None:
        """Validate inputs and launch the TDS script in a background thread."""
        ip = self.tds_ip_entry.get().strip()
        platform = (self.tds_platform_var.get() or "rls").strip().lower()
        username = self.tds_username_entry.get().strip()
        password = self.tds_password_entry.get()
        file_name = self.tds_filename_entry.get().strip()

        if not ip:
            messagebox.showerror("Input Error", "Please enter a device IP address.")
            return
        if platform not in ("6500", "rls"):
            messagebox.showerror("Input Error", "Platform must be either 6500 or rls.")
            return
        if not username:
            messagebox.showerror("Input Error", "Please enter a username.")
            return
        if not password:
            messagebox.showerror("Input Error", "Please enter a password.")
            return
        if not file_name:
            messagebox.showerror("Input Error", "Please enter a file name.")
            return

        tds_script_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "TDS", "TDS_v6.2.py")
        )
        if not os.path.isfile(tds_script_path):
            messagebox.showerror("TDS Error", f"TDS script not found:\n{tds_script_path}")
            return

        self.tds_status_label.config(text="Status: Running...")
        self.tds_run_button.config(state=tk.DISABLED)
        out = self.controller.output_screen
        out.insert(tk.END, f"Starting TDS diagnostics at {ip} (platform={platform})...\n")
        out.see(tk.END)

        root = self.controller.root

        def _worker() -> None:
            try:
                command = [
                    sys.executable, tds_script_path,
                    "--non-interactive",
                    "--host", ip,
                    "--platform", platform,
                    "--username", username,
                    "--file-name", file_name,
                ]
                run_env = os.environ.copy()
                run_env["TDS_PASSWORD"] = password

                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    cwd=os.path.dirname(tds_script_path),
                    env=run_env,
                    timeout=config.TDS_TIMEOUT,
                )

                combined = ""
                if result.stdout:
                    combined += result.stdout
                if result.stderr:
                    combined += ("\n" if combined else "") + result.stderr

                def on_complete() -> None:
                    self.tds_run_button.config(state=tk.NORMAL)
                    self.tds_status_label.config(text="Status: Ready")
                    if combined.strip():
                        out.insert(tk.END, combined + "\n")
                        out.see(tk.END)
                    if result.returncode == 0:
                        messagebox.showinfo("TDS Complete", "TDS diagnostics completed successfully.")
                    else:
                        messagebox.showerror("TDS Error", f"TDS script exited with code {result.returncode}.")

                root.after(0, on_complete)

            except subprocess.TimeoutExpired:
                def on_timeout() -> None:
                    self.tds_run_button.config(state=tk.NORMAL)
                    self.tds_status_label.config(text="Status: Timeout")
                    messagebox.showerror("TDS Timeout", "TDS diagnostics timed out.")

                root.after(0, on_timeout)

            except Exception as exc:
                def on_error() -> None:
                    self.tds_run_button.config(state=tk.NORMAL)
                    self.tds_status_label.config(text="Status: Error")
                    messagebox.showerror("TDS Error", f"Failed to run TDS script:\n{exc}")

                root.after(0, on_error)

        threading.Thread(target=_worker, daemon=True).start()
