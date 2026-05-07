"""Network Audit frame — UI for the LLDP-driven RLS network walk.

Wraps ``scripts/TDS/RLS_Network_Audit.py`` which itself spawns one TDS
subprocess per discovered host. Validations always run in walk mode.
"""
import ipaddress
import os
import re
import sys
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import config
from utils.helpers import (
    ensure_host_key_known,
    friendly_error,
    scrub_password_widget,
)


def _is_valid_host(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9.\-]*$", value) and "&" not in value)


class NetworkAuditFrame(ttk.Frame):
    """Tk frame for the RLS Network Audit sub-mode of Diagnostics."""

    def __init__(self, parent: ttk.Frame, controller) -> None:
        super().__init__(parent)
        self.controller = controller
        self._build()

    def _build(self) -> None:
        cfg = ttk.LabelFrame(self, text="Network Audit Configuration")
        cfg.pack(fill=tk.X, pady=5)

        tk.Label(cfg, text="Seed IP / Hostname:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.seed_entry = tk.Entry(cfg, width=25)
        self.seed_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(cfg, text="(or leave blank and use seed file)").grid(row=0, column=2, columnspan=2, sticky="w", padx=5)

        tk.Label(cfg, text="Seed File:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.seedfile_entry = tk.Entry(cfg, width=40)
        self.seedfile_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="w")
        tk.Button(cfg, text="Browse...", command=self._browse_seedfile).grid(row=1, column=3, padx=5, pady=5)

        tk.Label(cfg, text="Username:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.username_entry = tk.Entry(cfg, width=25)
        self.username_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Label(cfg, text="Password:").grid(row=2, column=2, sticky="w", padx=5, pady=5)
        self.password_entry = tk.Entry(cfg, width=25, show="*")
        self.password_entry.grid(row=2, column=3, padx=5, pady=5)

        tk.Label(cfg, text="Seed TID (optional):").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.seed_tid_entry = tk.Entry(cfg, width=25)
        self.seed_tid_entry.grid(row=3, column=1, padx=5, pady=5)

        tk.Label(cfg, text="Max Hops:").grid(row=3, column=2, sticky="w", padx=5, pady=5)
        self.max_hops_var = tk.IntVar(value=3)
        tk.Spinbox(cfg, from_=0, to=10, width=5, textvariable=self.max_hops_var).grid(
            row=3, column=3, padx=5, pady=5, sticky="w"
        )

        controls = ttk.Frame(self)
        controls.pack(fill=tk.X, pady=10)

        self.run_button = tk.Button(controls, text="Run Network Audit", command=self.run_audit)
        self.run_button.pack(side=tk.RIGHT, padx=5)

        self.status_label = tk.Label(controls, text="Status: Ready", anchor="w")
        self.status_label.pack(side=tk.RIGHT, padx=10)

    def _browse_seedfile(self) -> None:
        path = filedialog.askopenfilename(
            title="Select seed file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self.seedfile_entry.delete(0, tk.END)
            self.seedfile_entry.insert(0, path)

    def run_audit(self) -> None:
        seed = self.seed_entry.get().strip()
        seedfile = self.seedfile_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        seed_tid = self.seed_tid_entry.get().strip()
        try:
            max_hops = int(self.max_hops_var.get())
        except (TypeError, ValueError):
            max_hops = 3

        if not seed and not seedfile:
            messagebox.showerror("Input Error", "Provide a seed IP/hostname or a seed file.")
            return
        if seed and not _is_valid_host(seed):
            messagebox.showerror("Input Error", "Invalid seed IP/hostname.")
            return
        if seedfile and not os.path.isfile(seedfile):
            messagebox.showerror("Input Error", f"Seed file not found:\n{seedfile}")
            return
        if not username:
            messagebox.showerror("Input Error", "Please enter a username.")
            return
        if not password:
            messagebox.showerror("Input Error", "Please enter a password.")
            return
        if max_hops < 0:
            messagebox.showerror("Input Error", "Max Hops must be >= 0.")
            return

        # Pre-verify host key for the seed (each discovered hop is verified
        # by TDS when its subprocess runs — but if the seed key is missing,
        # the very first hop will fail silently).
        if seed and not ensure_host_key_known(seed):
            messagebox.showerror(
                "Host Key Verification Failed",
                f"Could not verify the SSH host key for {seed}. "
                "Network Audit will not be launched.",
            )
            return

        orchestrator_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "TDS", "RLS_Network_Audit.py")
        )
        if not os.path.isfile(orchestrator_path):
            messagebox.showerror(
                "Network Audit Error",
                f"Orchestrator script not found:\n{orchestrator_path}",
            )
            return

        self.status_label.config(text="Status: Running walk...")
        self.run_button.config(state=tk.DISABLED)
        out = self.controller.output_screen
        seed_summary = seed if seed else f"file: {seedfile}"
        out.insert(tk.END, f"Starting RLS Network Audit (seed={seed_summary}, max-hops={max_hops})...\n")
        out.see(tk.END)

        root = self.controller.root

        def _worker() -> None:
            try:
                cmd = [
                    sys.executable, orchestrator_path,
                    "--username", username,
                    "--read-password-stdin",
                    "--max-hops", str(max_hops),
                ]
                if seed:
                    cmd.extend(["--seed", seed])
                if seedfile:
                    cmd.extend(["--seedfile", seedfile])
                if seed_tid:
                    cmd.extend(["--seed-tid", seed_tid])

                # The walk can take a while (per-host timeout * max hosts).
                # Use the configured TDS timeout multiplied to be safe.
                per_host = getattr(config, "TDS_TIMEOUT", 600)
                walk_timeout = max(per_host * 4, 1800)

                result = subprocess.run(
                    cmd,
                    input=password,
                    capture_output=True,
                    text=True,
                    cwd=os.path.dirname(orchestrator_path),
                    timeout=walk_timeout,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )

                scrub_password_widget(self.password_entry)

                combined = ""
                if result.stdout:
                    combined += result.stdout
                if result.stderr:
                    combined += ("\n" if combined else "") + result.stderr

                def on_complete() -> None:
                    self.run_button.config(state=tk.NORMAL)
                    self.status_label.config(text="Status: Ready")
                    if combined.strip():
                        out.insert(tk.END, combined + "\n")
                        out.see(tk.END)
                    if result.returncode == 0:
                        messagebox.showinfo(
                            "Network Audit Complete",
                            "Walk finished. See Walk_Summary.csv and per-host *_RLS_Validation.csv files.",
                        )
                    else:
                        messagebox.showerror(
                            "Network Audit Error",
                            f"Orchestrator exited with code {result.returncode}.",
                        )

                root.after(0, on_complete)

            except subprocess.TimeoutExpired:
                def on_timeout() -> None:
                    self.run_button.config(state=tk.NORMAL)
                    self.status_label.config(text="Status: Timeout")
                    messagebox.showerror("Network Audit Timeout", "Walk exceeded the timeout.")

                root.after(0, on_timeout)

            except Exception as exc:
                def on_error() -> None:
                    self.run_button.config(state=tk.NORMAL)
                    self.status_label.config(text="Status: Error")
                    messagebox.showerror(
                        "Network Audit Error",
                        f"Failed to run audit:\n{friendly_error(exc)}",
                    )

                root.after(0, on_error)

        threading.Thread(target=_worker, daemon=True).start()
