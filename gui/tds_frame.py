"""TDS diagnostics frame — widgets and logic for the TDS mode."""
import ipaddress
import os
import re
import sys
import logging
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import config
from utils.helpers import ensure_host_key_known, friendly_error
from utils.credentials import get_default_credential_for_vendor


def _resolve_ciena_default() -> tuple:
    """Pull the Ciena 6500 / RLS default credentials from the same Fernet
    source every other ATLAS component uses (``credentials_config.json``).

    Returns ``(None, None)`` when the encrypted store is unreachable or
    defaults have been disabled via ``LAMIS_DISABLE_DEFAULT_CREDS`` so the
    caller falls straight through to the operator prompt instead of
    attempting an unauthenticated login.
    """
    pair = get_default_credential_for_vendor("ciena")
    if pair:
        return pair
    return (None, None)

# Markers in the subprocess output that mean the device rejected the login.
# Keep narrow so a benign "Permission" word in some other context doesn't
# trigger a needless re-prompt.
_AUTH_FAILURE_RE = re.compile(
    r"(?i)\b("
    r"authentication failed|"
    r"permission denied|"
    r"login (?:failed|incorrect)|"
    r"invalid (?:credentials|username|password|login)|"
    r"access denied|"
    r"bad (?:username|password)"
    r")\b"
)


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
        config_frame = ttk.LabelFrame(self, text="TDS Diagnostics")
        config_frame.pack(fill=tk.X, pady=5)

        # Row 0 — target device
        tk.Label(config_frame, text="IP Address:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.tds_ip_entry = tk.Entry(config_frame, width=25)
        self.tds_ip_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(config_frame, text="Platform:").grid(row=0, column=2, sticky="e", padx=5, pady=5)
        self.tds_platform_var = tk.StringVar(value="rls")
        self.tds_platform_combo = ttk.Combobox(
            config_frame, textvariable=self.tds_platform_var,
            values=["rls", "6500"], width=10, state="readonly",
        )
        self.tds_platform_combo.grid(row=0, column=3, padx=5, pady=5)

        # Row 1 — output filename
        tk.Label(config_frame, text="File Name:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.tds_filename_entry = tk.Entry(config_frame, width=25)
        self.tds_filename_entry.grid(row=1, column=1, padx=5, pady=5)

        # Row 2 — optional BFS network walk (RLS only)
        self.tds_network_walk_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            config_frame, text="Network walk (BFS, RLS only)",
            variable=self.tds_network_walk_var,
            command=self._on_network_walk_toggle,
        ).grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        tk.Label(config_frame, text="Max hops:").grid(row=2, column=2, sticky="e", padx=(5, 2), pady=5)
        self.tds_max_hops_var = tk.StringVar(value="3")
        self.tds_max_hops_entry = tk.Entry(
            config_frame, textvariable=self.tds_max_hops_var, width=5, state=tk.DISABLED,
        )
        self.tds_max_hops_entry.grid(row=2, column=3, sticky="w", padx=(0, 5), pady=5)

        # Row 3 — credential hint (so operators know what login is being tried)
        # Pulls the username out of the same Fernet store every other ATLAS
        # component reads from; only the username is shown, never the secret.
        u, _ = _resolve_ciena_default()
        if u:
            hint_text = f"Login: {u} (Ciena default — prompts on failure)"
        else:
            hint_text = "Login: prompt on connect (defaults disabled or unavailable)"
        hint = tk.Label(
            config_frame, text=hint_text,
            anchor="w", foreground="#555555",
        )
        hint.grid(row=3, column=0, columnspan=4, sticky="w", padx=5, pady=(2, 5))

        # Run controls
        tds_control_frame = ttk.Frame(self)
        tds_control_frame.pack(fill=tk.X, pady=10)

        self.tds_run_button = tk.Button(tds_control_frame, text="Run Diagnostics", command=self.run_tds)
        self.tds_run_button.pack(side=tk.RIGHT, padx=5)

        self.tds_status_label = tk.Label(tds_control_frame, text="Status: Ready", anchor="w")
        self.tds_status_label.pack(side=tk.RIGHT, padx=10)

    def _on_network_walk_toggle(self) -> None:
        """Enable/disable the Max-hops entry to match the Network-walk
        checkbox state."""
        state = tk.NORMAL if self.tds_network_walk_var.get() else tk.DISABLED
        self.tds_max_hops_entry.config(state=state)

    # ------------------------------------------------------------------
    # Credential helpers
    # ------------------------------------------------------------------

    def _prompt_user_for_credentials(self):
        """Show a credential dialog on the main thread and return (user, pw)
        or ``None`` if cancelled. Caller is responsible for being on the
        Tk main thread (the worker should marshal via ``root.after``)."""
        try:
            from utils.credentials import prompt_for_credentials_gui
            return prompt_for_credentials_gui(parent_window=self.controller.root)
        except Exception as exc:
            logging.exception("TDS credential prompt failed")
            messagebox.showerror(
                "Credential Prompt Error",
                f"Could not display the credential prompt:\n{friendly_error(exc)}",
            )
            return None

    def _looks_like_auth_failure(self, output: str) -> bool:
        return bool(output) and bool(_AUTH_FAILURE_RE.search(output))

    # ------------------------------------------------------------------
    # TDS worker
    # ------------------------------------------------------------------

    def run_tds(self) -> None:
        """Validate inputs and launch the TDS script in a background thread.

        Uses the Ciena factory default from the encrypted credential store
        (looked up by vendor key, never hardcoded) for the first attempt
        and re-prompts the operator on the main thread if the device rejects
        it. Retries the subprocess once with the supplied credentials before
        giving up.
        """
        ip = self.tds_ip_entry.get().strip()
        platform = (self.tds_platform_var.get() or "rls").strip().lower()
        file_name = self.tds_filename_entry.get().strip()

        if not ip:
            messagebox.showerror("Input Error", "Please enter a device IP address.")
            return
        # Validate: must be a valid IP or a safe hostname (alphanumeric, dots, dashes only)
        _ip_valid = False
        try:
            ipaddress.ip_address(ip)
            _ip_valid = True
        except ValueError:
            _ip_valid = bool(re.match(r'^[A-Za-z0-9][A-Za-z0-9.\-]*$', ip))
        if not _ip_valid:
            messagebox.showerror("Input Error", "Invalid IP address or hostname format.")
            return
        if platform not in ("6500", "rls"):
            messagebox.showerror("Input Error", "Platform must be either 6500 or rls.")
            return
        if not file_name:
            messagebox.showerror("Input Error", "Please enter a file name.")
            return

        # Network walk options (RLS only).
        network_walk = bool(self.tds_network_walk_var.get())
        max_hops = 0
        if network_walk:
            if platform != "rls":
                messagebox.showerror(
                    "Input Error",
                    "Network walk is RLS-only. Switch platform to 'rls' "
                    "or uncheck Network walk.",
                )
                return
            try:
                max_hops = int(self.tds_max_hops_var.get().strip())
            except ValueError:
                max_hops = -1
            if max_hops < 0 or max_hops > 20:
                messagebox.showerror(
                    "Input Error",
                    "Max hops must be an integer between 0 and 20.",
                )
                return

        # F009: pre-verify the device's SSH host key in the GUI thread (where
        # the Tk prompt can run) before launching the TDS subprocess. The
        # subprocess uses RejectPolicy and will refuse if the key isn't in
        # known_hosts, so this step is what makes that strict mode usable.
        if not ensure_host_key_known(ip):
            messagebox.showerror(
                "Host Key Verification Failed",
                f"Could not verify the SSH host key for {ip}. "
                "TDS will not be launched.",
            )
            return

        # TDS now runs through the same binary as ATLAS — frozen builds
        # self-spawn ATLAS.exe with --tds-mode, dev runs use the Python
        # interpreter against TDS_v6.2.py directly.
        if getattr(sys, "frozen", False):
            tds_command_prefix = [sys.executable, "--tds-mode"]
            tds_cwd = os.path.dirname(sys.executable)
        else:
            tds_script_path = os.path.normpath(
                os.path.join(os.path.dirname(__file__), "..", "scripts", "TDS", "TDS_v6.2.py")
            )
            if not os.path.isfile(tds_script_path):
                messagebox.showerror("TDS Error", f"TDS script not found:\n{tds_script_path}")
                return
            tds_command_prefix = [sys.executable, tds_script_path]
            tds_cwd = os.path.dirname(tds_script_path)

        self.tds_status_label.config(text="Status: Running...")
        self.tds_run_button.config(state=tk.DISABLED)
        out = self.controller.output_screen
        if network_walk:
            out.insert(
                tk.END,
                f"Starting RLS network walk from seed {ip} (max-hops={max_hops})...\n",
            )
        else:
            out.insert(tk.END, f"Starting TDS diagnostics at {ip} (platform={platform})...\n")
        out.see(tk.END)

        root = self.controller.root

        # Source the default credentials from the encrypted store on every
        # run so a one-time edit to credentials_config.json takes effect
        # without restarting ATLAS.
        default_user, default_pass = _resolve_ciena_default()

        if network_walk:
            self._run_network_walk(
                ip, default_user or "", default_pass or "",
                file_name, max_hops, tds_cwd, out, root,
            )
            return

        # Background worker — runs the subprocess once with defaults; if the
        # subprocess fails with an auth-style error, marshals back to the
        # main thread to prompt the user and retries once.
        def _invoke(username: str, password: str):
            command = tds_command_prefix + [
                "--non-interactive",
                "--host", ip,
                "--platform", platform,
                "--username", username,
                "--file-name", file_name,
                "--read-password-stdin",
            ]
            if platform == "rls":
                command.extend(["--validate", "--walk-mode"])

            return subprocess.run(
                command,
                input=password,
                capture_output=True,
                text=True,
                cwd=tds_cwd,
                timeout=config.TDS_TIMEOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

        def _combined(result) -> str:
            buf = result.stdout or ""
            if result.stderr:
                buf += ("\n" if buf else "") + result.stderr
            return buf

        def _ask_user_creds_blocking() -> "tuple|None":
            """Marshal a credential prompt to the main thread and wait for
            the answer. Returns (user, pw) or None if cancelled."""
            result_holder: dict = {'value': None}
            ready = threading.Event()

            def _on_main():
                try:
                    out.insert(
                        tk.END,
                        f"[{ip}] Default credentials failed — please enter credentials.\n",
                    )
                    out.see(tk.END)
                    result_holder['value'] = self._prompt_user_for_credentials()
                finally:
                    ready.set()

            root.after(0, _on_main)
            ready.wait()
            return result_holder['value']

        def _worker() -> None:
            try:
                # First attempt: Ciena default credentials from the Fernet store.
                # If the store is unreachable / defaults are disabled, jump
                # straight to the operator prompt.
                if default_user and default_pass:
                    result = _invoke(default_user, default_pass)
                    combined = _combined(result)
                else:
                    result = None
                    combined = ""

                # If we never tried (no default available) OR the device
                # rejected the login, re-prompt and retry once.
                need_prompt = (
                    result is None
                    or (result.returncode != 0
                        and self._looks_like_auth_failure(combined))
                )
                if need_prompt:
                    logging.info(
                        f"[TDS] Default credentials rejected for {ip}; "
                        f"prompting user for credentials"
                    )
                    answer = _ask_user_creds_blocking()
                    if answer and answer[0] and answer[1]:
                        user2, pass2 = answer
                        result = _invoke(user2, pass2)
                        combined = _combined(result)
                    elif answer is None:
                        # User cancelled — fall through with the original result
                        # so the existing error path reports cleanly.
                        logging.info(f"[TDS] Operator cancelled credential prompt for {ip}")

                def on_complete() -> None:
                    self.tds_run_button.config(state=tk.NORMAL)
                    self.tds_status_label.config(text="Status: Ready")
                    if combined.strip():
                        out.insert(tk.END, combined + "\n")
                        out.see(tk.END)
                    if result is None:
                        # No default available AND operator cancelled the prompt —
                        # nothing was attempted.
                        messagebox.showwarning(
                            "TDS Cancelled",
                            "No credentials were provided; TDS did not run.",
                        )
                    elif result.returncode == 0:
                        messagebox.showinfo("TDS Complete", "TDS diagnostics completed successfully.")
                    else:
                        messagebox.showerror(
                            "TDS Error",
                            f"TDS script exited with code {result.returncode}.",
                        )

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
                    messagebox.showerror(
                        "TDS Error",
                        f"Failed to run TDS script:\n{friendly_error(exc)}",
                    )
                root.after(0, on_error)

        threading.Thread(target=_worker, daemon=True).start()

    # ------------------------------------------------------------------
    # Network walk worker (RLS only)
    # ------------------------------------------------------------------

    def _run_network_walk(self, seed_ip: str, username: str, password: str,
                          file_name: str, max_hops: int, workdir: str,
                          out_widget, root) -> None:
        """Drive RLS_Network_Audit.run_audit on a background thread.

        The audit imports cleanly (no Tk dependency) and internally
        subprocesses per host using the same TDS_v6.2.py / TDS.exe entry
        point the single-host run uses. We forward the password via
        ``TDS_PASSWORD`` env so each subprocess picks it up, then unset
        it once the walk completes.

        If the seed host rejects the Ciena default (sourced from the
        encrypted credentials store) we re-prompt the operator and
        re-launch the walk with the supplied credentials.
        """
        def _log_to_gui(msg: str) -> None:
            text = msg if msg.endswith("\n") else (msg + "\n")
            def _do():
                out_widget.insert(tk.END, text)
                out_widget.see(tk.END)
            try:
                root.after(0, _do)
            except Exception:
                pass

        def _attempt(username: str, password: str):
            os.environ["TDS_PASSWORD"] = password
            try:
                from scripts.TDS.RLS_Network_Audit import run_audit
                return run_audit(
                    seeds=[seed_ip],
                    username=username,
                    max_hops=max_hops,
                    workdir=workdir,
                    file_name_seed=file_name,
                    per_host_timeout=config.TDS_TIMEOUT,
                    log=_log_to_gui,
                )
            finally:
                os.environ.pop("TDS_PASSWORD", None)

        def _ask_user_creds_blocking():
            result_holder: dict = {}
            ready = threading.Event()

            def _on_main():
                out_widget.insert(
                    tk.END,
                    f"[{seed_ip}] Default credentials failed — please enter credentials.\n",
                )
                out_widget.see(tk.END)
                result_holder['value'] = self._prompt_user_for_credentials()
                ready.set()

            root.after(0, _on_main)
            ready.wait()
            return result_holder.get('value')

        def _worker() -> None:
            try:
                if username and password:
                    try:
                        result_path = _attempt(username, password)
                    except PermissionError as auth_err:
                        # Some auth failures propagate as PermissionError
                        # from the underlying paramiko transport — re-prompt
                        # and retry.
                        logging.info(
                            f"[NETWORK-WALK] Default credentials rejected for "
                            f"{seed_ip}: {auth_err}"
                        )
                        answer = _ask_user_creds_blocking()
                        if not answer or not answer[0] or not answer[1]:
                            raise
                        user2, pass2 = answer
                        result_path = _attempt(user2, pass2)
                else:
                    # No defaults available — prompt up-front, then attempt.
                    answer = _ask_user_creds_blocking()
                    if not answer or not answer[0] or not answer[1]:
                        def on_cancel():
                            self.tds_run_button.config(state=tk.NORMAL)
                            self.tds_status_label.config(text="Status: Ready")
                            messagebox.showwarning(
                                "Network Walk Cancelled",
                                "No credentials provided; network walk did not run.",
                            )
                        root.after(0, on_cancel)
                        return
                    user2, pass2 = answer
                    result_path = _attempt(user2, pass2)

                def on_complete():
                    self.tds_run_button.config(state=tk.NORMAL)
                    self.tds_status_label.config(text="Status: Ready")
                    if result_path:
                        out_widget.insert(
                            tk.END,
                            f"Network walk complete. Output: {result_path}\n",
                        )
                        out_widget.see(tk.END)
                        messagebox.showinfo(
                            "Network Walk Complete",
                            f"Network workbook written to:\n{result_path}",
                        )
                    else:
                        messagebox.showerror(
                            "Network Walk Error",
                            "Network walk finished but no output workbook was produced.",
                        )
                root.after(0, on_complete)

            except ImportError as imp_err:
                def on_imp_err():
                    self.tds_run_button.config(state=tk.NORMAL)
                    self.tds_status_label.config(text="Status: Error")
                    messagebox.showerror(
                        "Network Walk Error",
                        f"Could not import RLS_Network_Audit:\n{friendly_error(imp_err)}",
                    )
                root.after(0, on_imp_err)

            except Exception as exc:
                logging.exception("Network walk worker failed")
                def on_error():
                    self.tds_run_button.config(state=tk.NORMAL)
                    self.tds_status_label.config(text="Status: Error")
                    messagebox.showerror(
                        "Network Walk Error",
                        f"Network walk failed:\n{friendly_error(exc)}",
                    )
                root.after(0, on_error)

        threading.Thread(target=_worker, daemon=True).start()
