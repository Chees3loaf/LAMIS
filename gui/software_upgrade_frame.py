"""
gui/software_upgrade_frame.py — "Software Upgrades" mode.

Stages a local folder of upgrade artifacts so a target device (Ciena RLS or
Nokia PSI) can pull them over HTTP. Workflow:

  1. User browses to the folder holding the software bundle.
  2. User picks a device type (Ciena RLS / Nokia PSI).
  3. User enters the IP the local PC NIC should be set to (so the device on
     the other end of the direct-connect link is on the same subnet).
  4. "Apply Static IP" runs `netsh interface ipv4 set address …` — auto-
     elevates via UAC if ATLAS is not already running as admin.
  5. "Start Server" launches an in-process ThreadingHTTPServer on
     :8000 rooted at the selected folder. The custom handler streams files
     in chunks and pushes byte-progress to the frame's progress bar.
  6. "Stop Server" tears the listener down. "Restore DHCP" puts the NIC
     back to dynamic.

The actual per-device upgrade command sequence is not implemented in this
first pass — only the HTTP staging side. Device type is captured for
future wiring.
"""
from __future__ import annotations

import ctypes
import logging
import os
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional, Tuple

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

try:
    from serial.tools import list_ports as _serial_list_ports
except Exception:  # pragma: no cover — pyserial-extras absent in some envs
    _serial_list_ports = None

try:
    import win32event
    import win32process
    import win32con
    from win32com.shell.shell import ShellExecuteEx
    from win32com.shell import shellcon
    _HAS_PYWIN32 = True
except ImportError:
    _HAS_PYWIN32 = False


# ── Constants ───────────────────────────────────────────────────────────────

_HTTP_PORT = 8000
_DEFAULT_MASK = "255.255.255.0"
_CHUNK_SIZE = 64 * 1024  # 64 KiB per progress tick

# Per-device-family defaults. For Ciena RLS, the shelf reaches the PC via
# the CTM internal /29 network. The PC takes .2 (CTM41) or .6 (CTM42); the
# RLS itself sits at .1 / .5 respectively.
_RLS_CTM_NET = {
    "CTM41": {"pc_ip": "10.0.0.2", "device_ip": "10.0.0.1"},
    "CTM42": {"pc_ip": "10.0.0.6", "device_ip": "10.0.0.5"},
}

# Nokia G42 connects over its link-local service interface. The PC sits at
# 169.254.0.101 and the chassis answers SSH at 169.254.0.1.
_G42_NET = {"pc_ip": "169.254.0.101", "device_ip": "169.254.0.1"}

# Nokia PSI service network — same /24, PC at .101 and PSI management at .1.
_PSI_NET = {"pc_ip": "172.16.0.101", "device_ip": "172.16.0.1"}

# Ciena Waveserver 5 — provisioned via serial first (no factory mgmt IP),
# then SSH'd to at the address WE set. /22 subnet because that's what the
# operator's lab playbook uses; both values flow into the upgrade script.
_WS5_NET = {
    "pc_ip": "10.9.49.101",
    "device_ip": "10.9.49.36",
    "device_ip_cidr": "10.9.49.36/22",
    "mask": "255.255.252.0",  # /22
}
_WS5_HOSTNAME = "WS5_1"

# Dropdown of device families that have a wired-up upgrade flow. Add a
# new entry here (and a matching elif in `_run_upgrade`) when wiring up a
# new device type.
_SUPPORTED_UPGRADES = [
    "Ciena RLS",
    "Ciena Waveserver 5",
    "Nokia G42",
    "Nokia PSI",
]

# Windows subprocess flag to suppress the brief console flash from spawning
# netsh.exe under PyInstaller-bundled apps. No-op on POSIX.
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


# ── Admin / elevation helpers ───────────────────────────────────────────────

def _is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0  # type: ignore[attr-defined]
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_netsh(args: list[str], timeout: float = 30.0) -> Tuple[bool, str]:
    """Run `netsh <args>`. If ATLAS isn't elevated, prompt UAC via
    ShellExecuteEx and wait for the elevated child to exit.

    Returns ``(success, message)``. The elevated path captures
    stdout+stderr via a cmd.exe redirect into a temp file so the
    operator sees netsh's actual error message (e.g. "The system
    cannot find the file specified" when the NIC name doesn't match
    a real interface) instead of a bare ``netsh exit code 1``.
    """
    if os.name != "nt":
        return False, "netsh is only available on Windows."

    # Log the exact command we're about to run -- if netsh rejects the
    # invocation, the operator's first question will be "what did you
    # actually pass to it?", and this answers it without needing to
    # repro under a debugger.
    logging.info(
        "[NETSH] running: netsh %s",
        subprocess.list2cmdline(args),
    )

    if _is_admin():
        try:
            proc = subprocess.run(
                ["netsh"] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=_CREATE_NO_WINDOW,
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            return proc.returncode == 0, output.strip() or "OK"
        except subprocess.TimeoutExpired:
            return False, "netsh timed out."
        except Exception as exc:
            return False, f"netsh failed: {exc}"

    if not _HAS_PYWIN32:
        return False, (
            "Setting a static IP requires administrator privileges. "
            "Re-launch ATLAS as administrator, or install pywin32 to enable "
            "auto-elevation."
        )

    # ShellExecuteEx-launched processes don't inherit our stdout/stderr
    # pipes, so a direct ``netsh.exe`` invocation gives us nothing to
    # display beyond the exit code. Workaround: launch ``cmd.exe /c
    # netsh <args> > <tmp> 2>&1`` so the elevated cmd writes both
    # streams to a file we can read after the child exits.
    tmp_log_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", prefix="atlas_netsh_",
            delete=False, encoding="utf-8",
        ) as _tmp:
            tmp_log_path = _tmp.name
    except Exception as exc:
        # Fall through to no-capture path if /tmp is borked -- better
        # than refusing to elevate at all.
        logging.warning(f"[NETSH] could not create capture tempfile: {exc}")

    try:
        if tmp_log_path:
            cmd_line = (
                f'/c netsh {subprocess.list2cmdline(args)} > '
                f'"{tmp_log_path}" 2>&1'
            )
            se = ShellExecuteEx(
                nShow=win32con.SW_HIDE,
                fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                lpVerb="runas",
                lpFile="cmd.exe",
                lpParameters=cmd_line,
            )
        else:
            se = ShellExecuteEx(
                nShow=win32con.SW_HIDE,
                fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                lpVerb="runas",
                lpFile="netsh.exe",
                lpParameters=subprocess.list2cmdline(args),
            )
        handle = se["hProcess"]
        wait_rc = win32event.WaitForSingleObject(handle, int(timeout * 1000))
        if wait_rc != 0:  # WAIT_OBJECT_0
            return False, "Elevated netsh timed out or was interrupted."
        rc = win32process.GetExitCodeProcess(handle)

        captured = ""
        if tmp_log_path:
            try:
                with open(tmp_log_path, "r", encoding="utf-8", errors="replace") as f:
                    captured = f.read().strip()
            except Exception as exc:
                captured = f"(could not read netsh output: {exc})"
            finally:
                try:
                    os.unlink(tmp_log_path)
                except Exception:
                    pass

        if rc == 0:
            return True, captured or "OK"
        # Non-zero exit: surface whatever netsh printed. If we have
        # nothing (no capture / empty output), keep the bare code so
        # at least the operator knows the elevated child ran.
        msg = captured or f"netsh exit code {rc}"
        return False, msg
    except Exception as exc:
        # Most common: user clicked Cancel on UAC prompt → "The operation
        # was canceled by the user." (1223).
        if tmp_log_path:
            try:
                os.unlink(tmp_log_path)
            except Exception:
                pass
        return False, f"Elevation cancelled or failed: {exc}"


def _set_static_ipv4(nic: str, ip: str, mask: str) -> Tuple[bool, str]:
    """Set *nic* to a static IPv4 address, robust against stale
    bindings from a previous run.

    Why this exists: plain ``netsh interface ipv4 set address NAME
    static IP MASK`` fails with ``The object already exists.`` when
    *any* previous run already bound the same IP on this NIC, even
    after a successful ``set address … source=dhcp`` to restore
    DHCP. Windows persists the static binding in the registry and
    DHCP-restore doesn't always clear it before the next ``set``
    runs. The reliable pattern is:

      1. Best-effort ``delete address NAME addr=IP`` to drop the
         stale binding if it's there. Failure (e.g. "the specified
         entry was not found") is fine -- it just means there was
         nothing to delete.
      2. ``set address NAME static IP MASK``.

    Returns ``(success, message)`` matching :func:`_run_netsh`.
    """
    # Step 1: idempotent cleanup of any prior binding of this exact
    # address. Ignore the result -- the only failure mode that
    # matters is the subsequent ``set``.
    del_ok, del_msg = _run_netsh(
        ["interface", "ipv4", "delete", "address",
         f"name={nic}", f"addr={ip}"],
        timeout=15.0,
    )
    if not del_ok:
        # Log at debug-ish level; this is expected when the address
        # wasn't bound.
        logging.info(
            f"[NETSH] pre-clean delete of {ip} on {nic} returned: {del_msg}"
        )

    # Step 2: set the new static address as the primary binding.
    return _run_netsh(
        ["interface", "ipv4", "set", "address",
         f"name={nic}", "static", ip, mask],
    )


# NIC names the operator never wants in the dropdown for a wired
# upgrade session. Pattern-matched case-insensitively against the
# adapter friendly name from psutil:
#   * Wi-Fi / wireless adapters
#   * The MS virtual "Local Area Connection* N" hotspot adapters
#   * Bluetooth Network Connection
#   * Hyper-V / WSL vEthernet, VMware, VirtualBox virtual switches
#   * Loopback
# Substring match (lowercased).
_NIC_EXCLUDE_PATTERNS = (
    "wi-fi",
    "wifi",
    "wireless",
    "local area connection*",
    "bluetooth",
    "vethernet",
    "vmware",
    "virtualbox",
    "loopback",
)


def _list_nics() -> list[str]:
    """Return the names of usable wired Ethernet NICs for the upgrade
    dropdown.

    Filters (all must pass):
      1. Name doesn't substring-match anything in
         :data:`_NIC_EXCLUDE_PATTERNS` (wireless / Bluetooth /
         virtual switches / loopback).
      2. Interface is currently UP -- ``psutil.net_if_stats().isup``
         is the equivalent of ``ipconfig`` reporting an actual
         binding instead of ``Media disconnected``. This naturally
         hides the laptop's onboard Ethernet ports when no cable is
         plugged in (and lets ``Ethernet 4``+ remain visible the
         instant the operator plugs into them, without us having to
         maintain a manual allow/exclude list of numbered ports).
      3. Adapter has at least one IPv4 address (covers APIPA /
         static / DHCP). Pure-IPv6 doesn't work for our setup.
    """
    if not _HAS_PSUTIL:
        return []

    try:
        stats = psutil.net_if_stats()
    except Exception:
        stats = {}

    names: list[str] = []
    for name, addrs in psutil.net_if_addrs().items():
        low = name.lower()
        if any(pat in low for pat in _NIC_EXCLUDE_PATTERNS):
            continue
        st = stats.get(name)
        if st is not None and not st.isup:
            continue
        if any(a.family == socket.AF_INET for a in addrs):
            names.append(name)
    # Alphabetical -- every remaining entry is a wired Ethernet the
    # operator knows by number.
    names.sort(key=lambda n: n.lower())
    return names


# ── In-process HTTP server with progress reporting ──────────────────────────

class _ProgressHTTPHandler(SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler that streams files in 64 KiB chunks and
    invokes ``self.server.on_progress(filename, sent, total)`` after each
    chunk so the GUI can drive its progress bar.
    """

    # Quieter default log_message — route through `self.server.on_log` if set
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        try:
            msg = f"{self.address_string()} - {fmt % args}"
        except Exception:
            msg = fmt
        on_log = getattr(self.server, "on_log", None)
        if callable(on_log):
            try:
                on_log(msg)
            except Exception:
                pass
        else:
            logging.getLogger("software_upgrade.http").info(msg)

    def copyfile(self, source, outputfile):  # type: ignore[override]
        """Chunked copy with progress callback. Mirrors the behaviour of
        ``shutil.copyfileobj`` but reports each chunk."""
        on_progress = getattr(self.server, "on_progress", None)
        # ``source`` is the open file; size lives on the response headers we
        # already sent. Re-derive from path for safety.
        try:
            total = os.fstat(source.fileno()).st_size
        except Exception:
            total = 0
        sent = 0
        fname = os.path.basename(self.path.split("?", 1)[0])

        if callable(on_progress):
            try:
                on_progress(fname, 0, total)
            except Exception:
                pass

        while True:
            buf = source.read(_CHUNK_SIZE)
            if not buf:
                break
            outputfile.write(buf)
            sent += len(buf)
            if callable(on_progress):
                try:
                    on_progress(fname, sent, total)
                except Exception:
                    pass

        if callable(on_progress):
            try:
                on_progress(fname, sent, total, done=True)
            except Exception:
                pass


class _UpgradeHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that pins serving to a specific root directory
    (via ``directory=`` on the handler) and exposes ``on_progress`` /
    ``on_log`` callbacks for the GUI to subscribe to.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: Tuple[str, int],
        directory: str,
        on_progress: Optional[Callable[..., None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._directory = directory
        self.on_progress = on_progress
        self.on_log = on_log

        def _factory(*args, **kwargs):
            # SimpleHTTPRequestHandler honours `directory=` to chroot the
            # listing/serving to that path.
            return _ProgressHTTPHandler(*args, directory=directory, **kwargs)

        super().__init__(server_address, _factory)


# ── Frame ───────────────────────────────────────────────────────────────────

class SoftwareUpgradeFrame(ttk.Frame):
    """Tkinter frame for the Software Upgrades mode."""

    def __init__(self, parent: ttk.Frame, controller: Any) -> None:
        super().__init__(parent)
        self.controller = controller

        self._server: Optional[_UpgradeHTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        # Track current NIC state so "Restore DHCP" knows which interface
        # we last touched, and so we can revert on app shutdown.
        self._static_ip_applied_on: Optional[str] = None

        # RLS upgrade thread + stop flag
        self._upgrade_thread: Optional[threading.Thread] = None
        self._upgrade_stop = False

        self._build()

    # ── UI construction ─────────────────────────────────────────────────────

    def _build(self) -> None:
        # Row 1 — software folder browser
        folder_frame = ttk.LabelFrame(self, text="Software Folder")
        folder_frame.pack(fill=tk.X, padx=5, pady=4)

        self._folder_var = tk.StringVar()
        ttk.Entry(folder_frame, textvariable=self._folder_var, width=60).pack(
            side=tk.LEFT, padx=(6, 2), pady=4
        )
        ttk.Button(folder_frame, text="Browse…", command=self._browse_folder).pack(
            side=tk.LEFT, padx=2
        )
        self._folder_status = ttk.Label(
            folder_frame, text="No folder selected", foreground="gray"
        )
        self._folder_status.pack(side=tk.LEFT, padx=8)

        # Row 2 — pick which device family to upgrade
        dev_frame = ttk.LabelFrame(self, text="Target Device")
        dev_frame.pack(fill=tk.X, padx=5, pady=4)

        ttk.Label(dev_frame, text="Device:").pack(side=tk.LEFT, padx=(6, 2))
        self._dtype_var = tk.StringVar(value=_SUPPORTED_UPGRADES[0])
        self._dtype_combo = ttk.Combobox(
            dev_frame,
            textvariable=self._dtype_var,
            values=_SUPPORTED_UPGRADES,
            state="readonly",
            width=20,
        )
        self._dtype_combo.pack(side=tk.LEFT, padx=2, pady=4)
        self._dtype_combo.bind("<<ComboboxSelected>>", self._on_dtype_change)

        # Row 3 — PC NIC static IP controls
        nic_frame = ttk.LabelFrame(self, text="PC Static IP (netsh)")
        nic_frame.pack(fill=tk.X, padx=5, pady=4)

        ttk.Label(nic_frame, text="NIC:").pack(side=tk.LEFT, padx=(6, 2))
        self._nic_var = tk.StringVar()
        self._nic_combo = ttk.Combobox(
            nic_frame, textvariable=self._nic_var, state="readonly", width=28
        )
        self._nic_combo.pack(side=tk.LEFT, padx=2)
        ttk.Button(nic_frame, text="↺", width=2, command=self._refresh_nics).pack(
            side=tk.LEFT, padx=1
        )

        ttk.Label(nic_frame, text="  PC IP:").pack(side=tk.LEFT, padx=(10, 2))
        self._pc_ip_var = tk.StringVar()
        ttk.Entry(nic_frame, textvariable=self._pc_ip_var, width=16).pack(
            side=tk.LEFT, padx=2
        )

        ttk.Label(nic_frame, text="  Mask:").pack(side=tk.LEFT, padx=(8, 2))
        self._mask_var = tk.StringVar(value=_DEFAULT_MASK)
        ttk.Entry(nic_frame, textvariable=self._mask_var, width=16).pack(
            side=tk.LEFT, padx=2
        )

        nic_btn_frame = ttk.Frame(self)
        nic_btn_frame.pack(fill=tk.X, padx=5, pady=(0, 4))
        self._apply_btn = ttk.Button(
            nic_btn_frame, text="Apply Static IP", command=self._apply_static_ip
        )
        self._apply_btn.pack(side=tk.LEFT, padx=6)
        self._dhcp_btn = ttk.Button(
            nic_btn_frame, text="Restore DHCP", command=self._restore_dhcp
        )
        self._dhcp_btn.pack(side=tk.LEFT, padx=6)
        self._nic_status = ttk.Label(nic_btn_frame, text="", foreground="gray")
        self._nic_status.pack(side=tk.LEFT, padx=10)

        # Row 4 — HTTP server controls
        srv_frame = ttk.LabelFrame(self, text=f"HTTP Server (port {_HTTP_PORT})")
        srv_frame.pack(fill=tk.X, padx=5, pady=4)

        self._start_btn = ttk.Button(
            srv_frame, text="▶  Start Server", command=self._start_server
        )
        self._start_btn.pack(side=tk.LEFT, padx=6, pady=4)
        self._stop_btn = ttk.Button(
            srv_frame, text="■  Stop Server", command=self._stop_server, state=tk.DISABLED
        )
        self._stop_btn.pack(side=tk.LEFT, padx=6)
        self._srv_status = ttk.Label(srv_frame, text="Stopped", foreground="gray")
        self._srv_status.pack(side=tk.LEFT, padx=10)

        # Row 4b — Ciena RLS-specific upgrade controls (shown only when
        # device type == Ciena RLS).
        self._rls_frame = ttk.LabelFrame(self, text="Ciena RLS Upgrade")

        rls_row1 = ttk.Frame(self._rls_frame)
        rls_row1.pack(fill=tk.X, padx=4, pady=(4, 2))
        ttk.Label(rls_row1, text="Active CTM:").pack(side=tk.LEFT, padx=(4, 2))
        self._rls_ctm_var = tk.StringVar(value="CTM41")
        for label in _RLS_CTM_NET:
            tk.Radiobutton(
                rls_row1, text=label, variable=self._rls_ctm_var, value=label,
                command=self._on_rls_ctm_change,
            ).pack(side=tk.LEFT, padx=4)

        ttk.Label(rls_row1, text="  Software File:").pack(side=tk.LEFT, padx=(14, 2))
        self._rls_file_var = tk.StringVar()
        self._rls_file_combo = ttk.Combobox(
            rls_row1, textvariable=self._rls_file_var, state="readonly", width=42
        )
        self._rls_file_combo.pack(side=tk.LEFT, padx=2)
        ttk.Button(rls_row1, text="↺", width=2, command=self._refresh_rls_files).pack(
            side=tk.LEFT, padx=1
        )

        rls_row2 = ttk.Frame(self._rls_frame)
        rls_row2.pack(fill=tk.X, padx=4, pady=(0, 4))
        ttk.Label(rls_row2, text="SSH User:").pack(side=tk.LEFT, padx=(4, 2))
        self._rls_user_var = tk.StringVar(value="su")
        ttk.Entry(rls_row2, textvariable=self._rls_user_var, width=10).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Label(rls_row2, text="  Password:").pack(side=tk.LEFT, padx=(8, 2))
        self._rls_pass_var = tk.StringVar(value="admin")
        ttk.Entry(rls_row2, textvariable=self._rls_pass_var, show="*", width=12).pack(
            side=tk.LEFT, padx=2
        )

        self._rls_run_btn = ttk.Button(
            rls_row2, text="▶  Run Upgrade", command=self._run_rls_upgrade
        )
        self._rls_run_btn.pack(side=tk.LEFT, padx=14)
        self._rls_stop_btn = ttk.Button(
            rls_row2, text="■  Stop", command=self._stop_rls_upgrade, state=tk.DISABLED
        )
        self._rls_stop_btn.pack(side=tk.LEFT, padx=4)
        self._rls_status = ttk.Label(rls_row2, text="", foreground="gray")
        self._rls_status.pack(side=tk.LEFT, padx=10)

        # Row 4c — Nokia G42-specific upgrade controls (shown only when
        # device type == Nokia G42).
        self._g42_frame = ttk.LabelFrame(self, text="Nokia G42 Upgrade")

        g42_row1 = ttk.Frame(self._g42_frame)
        g42_row1.pack(fill=tk.X, padx=4, pady=(4, 2))
        ttk.Label(g42_row1, text="Manifest File:").pack(side=tk.LEFT, padx=(4, 2))
        self._g42_file_var = tk.StringVar()
        self._g42_file_combo = ttk.Combobox(
            g42_row1, textvariable=self._g42_file_var, state="readonly", width=52
        )
        self._g42_file_combo.pack(side=tk.LEFT, padx=2)
        ttk.Button(g42_row1, text="↺", width=2, command=self._refresh_g42_files).pack(
            side=tk.LEFT, padx=1
        )

        g42_row2 = ttk.Frame(self._g42_frame)
        g42_row2.pack(fill=tk.X, padx=4, pady=(0, 4))
        ttk.Label(g42_row2, text="SSH User:").pack(side=tk.LEFT, padx=(4, 2))
        self._g42_user_var = tk.StringVar(value="admin")
        ttk.Entry(g42_row2, textvariable=self._g42_user_var, width=10).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Label(g42_row2, text="  Password:").pack(side=tk.LEFT, padx=(8, 2))
        self._g42_pass_var = tk.StringVar(value="admin")
        ttk.Entry(g42_row2, textvariable=self._g42_pass_var, show="*", width=12).pack(
            side=tk.LEFT, padx=2
        )

        self._g42_run_btn = ttk.Button(
            g42_row2, text="▶  Run Upgrade", command=self._run_g42_upgrade
        )
        self._g42_run_btn.pack(side=tk.LEFT, padx=14)
        self._g42_stop_btn = ttk.Button(
            g42_row2, text="■  Stop", command=self._stop_g42_upgrade, state=tk.DISABLED
        )
        self._g42_stop_btn.pack(side=tk.LEFT, padx=4)
        self._g42_status = ttk.Label(g42_row2, text="", foreground="gray")
        self._g42_status.pack(side=tk.LEFT, padx=10)

        # Row 4d — Nokia PSI-specific upgrade controls (shown only when
        # device type == Nokia PSI). Login is 2-phase, mirroring the
        # existing 1830 flow: outer cli/admin, inner admin/admin.
        self._psi_frame = ttk.LabelFrame(self, text="Nokia PSI Upgrade")

        # Folder-structure reminder banner — the PSI fetches from /CC/,
        # so the user's selected folder needs a CC/ subdirectory.
        ttk.Label(
            self._psi_frame,
            text="Note: the PSI fetches http://172.16.0.101:8000/CC/<file>. "
                 "Pick a folder that contains a CC/ subdirectory.",
            foreground="gray",
        ).pack(anchor=tk.W, padx=6, pady=(4, 0))

        psi_row1 = ttk.Frame(self._psi_frame)
        psi_row1.pack(fill=tk.X, padx=4, pady=(4, 2))
        ttk.Label(psi_row1, text="Software File:").pack(side=tk.LEFT, padx=(4, 2))
        self._psi_file_var = tk.StringVar()
        self._psi_file_combo = ttk.Combobox(
            psi_row1, textvariable=self._psi_file_var, state="readonly", width=52
        )
        self._psi_file_combo.pack(side=tk.LEFT, padx=2)
        ttk.Button(psi_row1, text="↺", width=2, command=self._refresh_psi_files).pack(
            side=tk.LEFT, padx=1
        )

        psi_row2 = ttk.Frame(self._psi_frame)
        psi_row2.pack(fill=tk.X, padx=4, pady=(0, 2))
        ttk.Label(psi_row2, text="SSH User:").pack(side=tk.LEFT, padx=(4, 2))
        self._psi_user_var = tk.StringVar(value="cli")
        ttk.Entry(psi_row2, textvariable=self._psi_user_var, width=10).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Label(psi_row2, text="  SSH Pwd:").pack(side=tk.LEFT, padx=(8, 2))
        self._psi_pass_var = tk.StringVar(value="admin")
        ttk.Entry(psi_row2, textvariable=self._psi_pass_var, show="*", width=12).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Label(psi_row2, text="  Inner User:").pack(side=tk.LEFT, padx=(8, 2))
        self._psi_inner_user_var = tk.StringVar(value="admin")
        ttk.Entry(psi_row2, textvariable=self._psi_inner_user_var, width=10).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Label(psi_row2, text="  Inner Pwd:").pack(side=tk.LEFT, padx=(8, 2))
        self._psi_inner_pass_var = tk.StringVar(value="admin")
        ttk.Entry(psi_row2, textvariable=self._psi_inner_pass_var, show="*", width=12).pack(
            side=tk.LEFT, padx=2
        )

        psi_row3 = ttk.Frame(self._psi_frame)
        psi_row3.pack(fill=tk.X, padx=4, pady=(0, 4))
        self._psi_run_btn = ttk.Button(
            psi_row3, text="▶  Run Upgrade", command=self._run_psi_upgrade
        )
        self._psi_run_btn.pack(side=tk.LEFT, padx=4)
        self._psi_stop_btn = ttk.Button(
            psi_row3, text="■  Stop", command=self._stop_psi_upgrade, state=tk.DISABLED
        )
        self._psi_stop_btn.pack(side=tk.LEFT, padx=4)
        self._psi_status = ttk.Label(psi_row3, text="", foreground="gray")
        self._psi_status.pack(side=tk.LEFT, padx=10)

        # Row 4e — Ciena Waveserver 5 controls (shown only when
        # device type == Ciena Waveserver 5). This one is two-phase:
        # serial first (provision the device IP + hostname), then SSH
        # over the DCN-1 port to drive the software download/activate.
        self._ws5_frame = ttk.LabelFrame(self, text="Ciena Waveserver 5 Upgrade")

        ttk.Label(
            self._ws5_frame,
            text=(
                "Phase 1 (serial @ 115200 on console port) provisions "
                f"{_WS5_NET['device_ip_cidr']} and gateway "
                f"{_WS5_NET['pc_ip']}. Phase 2 (SSH over DCN-1) downloads + "
                "activates the load. Stops at 'Activation In Progress' — "
                "manual commit on the device required."
            ),
            foreground="gray", wraplength=620, justify=tk.LEFT,
        ).pack(anchor=tk.W, padx=6, pady=(4, 0))

        ws5_row1 = ttk.Frame(self._ws5_frame)
        ws5_row1.pack(fill=tk.X, padx=4, pady=(4, 2))
        ttk.Label(ws5_row1, text="Software File:").pack(side=tk.LEFT, padx=(4, 2))
        self._ws5_file_var = tk.StringVar()
        self._ws5_file_combo = ttk.Combobox(
            ws5_row1, textvariable=self._ws5_file_var, state="readonly", width=42
        )
        self._ws5_file_combo.pack(side=tk.LEFT, padx=2)
        ttk.Button(ws5_row1, text="↺", width=2, command=self._refresh_ws5_files).pack(
            side=tk.LEFT, padx=1
        )

        ttk.Label(ws5_row1, text="  Serial Port:").pack(side=tk.LEFT, padx=(14, 2))
        self._ws5_serial_var = tk.StringVar()
        self._ws5_serial_combo = ttk.Combobox(
            ws5_row1, textvariable=self._ws5_serial_var, state="readonly", width=12
        )
        self._ws5_serial_combo.pack(side=tk.LEFT, padx=2)
        ttk.Button(ws5_row1, text="↺", width=2, command=self._refresh_ws5_serial_ports).pack(
            side=tk.LEFT, padx=1
        )

        ws5_row2 = ttk.Frame(self._ws5_frame)
        ws5_row2.pack(fill=tk.X, padx=4, pady=(0, 4))
        self._ws5_run_btn = ttk.Button(
            ws5_row2, text="▶  Run Upgrade", command=self._run_ws5_upgrade
        )
        self._ws5_run_btn.pack(side=tk.LEFT, padx=14)
        self._ws5_stop_btn = ttk.Button(
            ws5_row2, text="■  Stop", command=self._stop_ws5_upgrade, state=tk.DISABLED
        )
        self._ws5_stop_btn.pack(side=tk.LEFT, padx=4)
        self._ws5_status = ttk.Label(ws5_row2, text="", foreground="gray")
        self._ws5_status.pack(side=tk.LEFT, padx=10)

        # Row 5 — progress bar
        prog_frame = ttk.LabelFrame(self, text="Transfer Progress")
        prog_frame.pack(fill=tk.X, padx=5, pady=4)

        self._progress_var = tk.DoubleVar(value=0.0)
        self._progress = ttk.Progressbar(
            prog_frame,
            mode="determinate",
            maximum=100.0,
            variable=self._progress_var,
        )
        self._progress.pack(fill=tk.X, padx=8, pady=(8, 2))
        self._progress_lbl = ttk.Label(prog_frame, text="Idle", foreground="gray")
        self._progress_lbl.pack(anchor=tk.W, padx=8, pady=(0, 6))

        # Row 6 — log
        log_frame = ttk.LabelFrame(self, text="Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=4)

        self._log_text = scrolledtext.ScrolledText(
            log_frame, height=10, wrap=tk.WORD, state=tk.DISABLED
        )
        self._log_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        ttk.Button(log_frame, text="Clear", command=self._clear_log).pack(
            anchor=tk.E, padx=4, pady=(0, 4)
        )

        # Initial state
        self._refresh_nics()
        self._refresh_ws5_serial_ports()
        self._on_dtype_change()
        self._on_rls_ctm_change()

    # ── Event handlers ──────────────────────────────────────────────────────

    def _browse_folder(self) -> None:
        path = filedialog.askdirectory(title="Select software folder")
        if not path:
            return
        self._folder_var.set(path)
        try:
            count = sum(1 for _ in Path(path).iterdir())
        except OSError as exc:
            self._folder_status.config(text=f"Error: {exc}", foreground="red")
            return
        self._folder_status.config(
            text=f"{count} item(s) in folder", foreground="green"
        )
        self._refresh_rls_files()
        self._refresh_g42_files()
        self._refresh_psi_files()
        self._refresh_ws5_files()

    def _on_dtype_change(self, _event=None) -> None:
        """Show/hide device-specific panels based on device type."""
        dtype = self._dtype_var.get()
        # Hide all panels first
        self._rls_frame.pack_forget()
        self._g42_frame.pack_forget()
        self._psi_frame.pack_forget()
        self._ws5_frame.pack_forget()

        # pack_forget+pack would re-add at the end of the parent's geometry
        # list, pushing the progress + log panels around. `before=` anchors
        # device panels just above the progress frame so the layout stays
        # stable regardless of which device is selected.
        before = self._progress.master
        if dtype == "Ciena RLS":
            self._rls_frame.pack(fill=tk.X, padx=5, pady=4, before=before)
        elif dtype == "Ciena Waveserver 5":
            self._ws5_frame.pack(fill=tk.X, padx=5, pady=4, before=before)
        elif dtype == "Nokia G42":
            self._g42_frame.pack(fill=tk.X, padx=5, pady=4, before=before)
        elif dtype == "Nokia PSI":
            self._psi_frame.pack(fill=tk.X, padx=5, pady=4, before=before)

    def _on_rls_ctm_change(self) -> None:
        """When the CTM changes, auto-fill the PC IP to the matching internal
        address so the user doesn't have to remember CTM41=.2 / CTM42=.6."""
        net = _RLS_CTM_NET.get(self._rls_ctm_var.get())
        if net:
            self._pc_ip_var.set(net["pc_ip"])

    def _refresh_rls_files(self) -> None:
        """Populate the software-file dropdown from the selected folder.

        For RLS we filter to .tgz; if the user has the folder pointed at a
        bundle directory with no .tgz we show everything so they can pick
        manually.
        """
        self._populate_file_combo(self._rls_file_combo, self._rls_file_var, ".tgz")

    def _refresh_ws5_files(self) -> None:
        """Populate the Waveserver 5 software-file dropdown — filter to
        .tar.gz, fall back to all files if none match. The activate
        command derives the version from the filename so the operator
        needs to pick the actual tarball, not a manifest."""
        self._populate_file_combo(self._ws5_file_combo, self._ws5_file_var, ".tar.gz")

    def _refresh_ws5_serial_ports(self) -> None:
        """Populate the WS5 serial-port combobox from pyserial. Falls back
        to a single ``COM1`` placeholder when pyserial isn't usable so the
        widget never goes blank."""
        if _serial_list_ports is None:
            ports = ["COM1"]
        else:
            try:
                ports = sorted(p.device for p in _serial_list_ports.comports())
            except Exception as exc:
                logging.debug(f"Could not enumerate serial ports: {exc}")
                ports = []
        if not ports:
            ports = ["COM1"]
        current = self._ws5_serial_var.get()
        self._ws5_serial_combo["values"] = ports
        if current in ports:
            self._ws5_serial_var.set(current)
        else:
            self._ws5_serial_var.set(ports[0])

    def _refresh_g42_files(self) -> None:
        """Populate the manifest dropdown — filter to .manifest, fall back
        to all files if none match."""
        self._populate_file_combo(self._g42_file_combo, self._g42_file_var, ".manifest")

    def _refresh_psi_files(self) -> None:
        """Populate the PSI software-file dropdown. PSI loads live under a
        CC/ subdirectory of the chosen folder; list anything that looks
        like a load (no extension filter — PSI files are typically named
        without a meaningful extension)."""
        folder = self._folder_var.get().strip()
        cc_path = Path(folder) / "CC" if folder else None
        if cc_path is None or not cc_path.is_dir():
            self._psi_file_combo["values"] = []
            self._psi_file_var.set("")
            return
        try:
            entries = sorted(
                p.name for p in cc_path.iterdir() if p.is_file()
            )
        except OSError:
            entries = []
        self._psi_file_combo["values"] = entries
        if entries and not self._psi_file_var.get():
            self._psi_file_var.set(entries[0])

    def _populate_file_combo(
        self, combo: ttk.Combobox, var: tk.StringVar, ext: str
    ) -> None:
        folder = self._folder_var.get().strip()
        if not folder or not os.path.isdir(folder):
            combo["values"] = []
            var.set("")
            return
        try:
            entries = sorted(
                p.name for p in Path(folder).iterdir() if p.is_file()
            )
        except OSError:
            entries = []
        matches = [e for e in entries if e.lower().endswith(ext)]
        files = matches or entries
        combo["values"] = files
        if files and not var.get():
            var.set(files[0])

    def _refresh_nics(self) -> None:
        nics = _list_nics()
        current = self._nic_var.get()
        self._nic_combo["values"] = nics
        if current in nics:
            self._nic_var.set(current)
        elif nics:
            self._nic_var.set(nics[0])
        else:
            self._nic_var.set("")

    def _apply_static_ip(self) -> None:
        nic = self._nic_var.get().strip()
        ip = self._pc_ip_var.get().strip()
        mask = self._mask_var.get().strip() or _DEFAULT_MASK
        if not nic:
            messagebox.showerror("Error", "Select a network interface.")
            return
        if not ip:
            messagebox.showerror("Error", "Enter the PC IP to assign.")
            return

        self._set_nic_status("Applying static IP…", "blue")
        self._log(f"netsh: setting {nic} to {ip}/{mask}")

        def _worker() -> None:
            # Pre-clean any stale binding of the same IP before
            # asking netsh to set it, otherwise a previous run's
            # leftover causes "The object already exists." even on
            # a fresh boot.
            ok, msg = _set_static_ipv4(nic, ip, mask)
            if ok:
                self._static_ip_applied_on = nic
                self._set_nic_status(f"Static {ip} on {nic}", "green")
                self._log(f"netsh OK: {msg}")
            else:
                self._set_nic_status("Failed — see log", "red")
                self._log(f"netsh FAILED: {msg}")

        threading.Thread(target=_worker, daemon=True).start()

    def _restore_dhcp(self) -> None:
        nic = self._nic_var.get().strip() or self._static_ip_applied_on
        if not nic:
            messagebox.showerror("Error", "Select a network interface.")
            return

        self._set_nic_status("Restoring DHCP…", "blue")
        self._log(f"netsh: restoring DHCP on {nic}")

        def _worker() -> None:
            ok, msg = _run_netsh(
                ["interface", "ipv4", "set", "address",
                 f"name={nic}", "source=dhcp"]
            )
            # Also restore DNS to DHCP
            _run_netsh(
                ["interface", "ipv4", "set", "dnsservers",
                 f"name={nic}", "source=dhcp"]
            )
            if ok:
                self._static_ip_applied_on = None
                self._set_nic_status(f"DHCP on {nic}", "green")
                self._log(f"netsh OK: {msg}")
            else:
                self._set_nic_status("Failed — see log", "red")
                self._log(f"netsh FAILED: {msg}")

        threading.Thread(target=_worker, daemon=True).start()

    def _start_server(self) -> None:
        if self._server is not None:
            messagebox.showinfo("Already running", "HTTP server is already running.")
            return

        folder = self._folder_var.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Error", "Pick a valid software folder first.")
            return

        try:
            self._server = _UpgradeHTTPServer(
                ("0.0.0.0", _HTTP_PORT),
                directory=folder,
                on_progress=self._on_progress,
                on_log=self._log,
            )
        except OSError as exc:
            self._server = None
            messagebox.showerror(
                "Bind failed",
                f"Could not bind to port {_HTTP_PORT}:\n{exc}\n\n"
                "Another process may already be listening on that port.",
            )
            return

        self._server_thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._server_thread.start()

        bind_ip = self._pc_ip_var.get().strip() or "<PC IP>"
        self._set_srv_status(f"Serving {Path(folder).name} on :{_HTTP_PORT}", "green")
        self._log(f"HTTP server up at http://{bind_ip}:{_HTTP_PORT}/ (root: {folder})")
        self._start_btn.config(state=tk.DISABLED)
        self._stop_btn.config(state=tk.NORMAL)

    def _stop_server(self) -> None:
        server = self._server
        if server is None:
            return
        self._set_srv_status("Stopping…", "orange")
        self._log("Stopping HTTP server…")

        def _shutdown() -> None:
            try:
                server.shutdown()
                server.server_close()
            except Exception as exc:
                self._log(f"HTTP shutdown error: {exc}")
            finally:
                self._server = None
                self._server_thread = None
                self._set_srv_status("Stopped", "gray")
                self._log("HTTP server stopped.")
                self.after(0, lambda: self._start_btn.config(state=tk.NORMAL))
                self.after(0, lambda: self._stop_btn.config(state=tk.DISABLED))

        # server.shutdown() must run off the serving thread.
        threading.Thread(target=_shutdown, daemon=True).start()

    # ── RLS upgrade ─────────────────────────────────────────────────────────

    def _run_rls_upgrade(self) -> None:
        if self._upgrade_thread is not None and self._upgrade_thread.is_alive():
            messagebox.showinfo("Already running", "An upgrade is already in progress.")
            return
        if self._server is None:
            if not messagebox.askyesno(
                "HTTP server not running",
                "The HTTP server is not running, so the device will not be "
                "able to pull the upgrade file. Start it now?",
            ):
                return
            self._start_server()
            if self._server is None:
                return  # start failed, message already shown

        filename = self._rls_file_var.get().strip()
        if not filename:
            messagebox.showerror(
                "Error", "Pick a software file from the dropdown."
            )
            return

        # Derive both the PC IP and the RLS management IP from the CTM
        # selection. CTM41 → PC .2 / RLS .1; CTM42 → PC .6 / RLS .5.
        ctm = self._rls_ctm_var.get()
        net = _RLS_CTM_NET.get(ctm)
        if not net:
            messagebox.showerror("Error", f"Unknown CTM selection: {ctm!r}")
            return
        pc_ip = net["pc_ip"]
        device_ip = net["device_ip"]
        # Reflect the derived PC IP in the netsh frame so the user can see
        # what the worker is about to apply.
        self._pc_ip_var.set(pc_ip)

        nic = self._nic_var.get().strip()
        if not nic:
            messagebox.showerror(
                "Error",
                "No network interface selected. Click ↺ in the PC Static IP "
                "row to refresh, then pick the NIC connected to the shelf.",
            )
            return

        mask = self._mask_var.get().strip() or _DEFAULT_MASK
        server_url = f"http://{pc_ip}:{_HTTP_PORT}/{filename}"
        user = self._rls_user_var.get().strip() or "su"
        pwd = self._rls_pass_var.get()

        self._upgrade_stop = False
        self._set_rls_status("Running…", "blue")
        self._rls_run_btn.config(state=tk.DISABLED)
        self._rls_stop_btn.config(state=tk.NORMAL)
        self._log(f"\n──── RLS upgrade ({ctm}): {device_ip} ← {server_url} ────")

        def _worker() -> None:
            try:
                # Step 1 — set PC NIC to the CTM-internal IP. If a UAC prompt
                # appears, the user has to approve it before SSH can start.
                # Use the static-IP helper so a stale binding from an
                # earlier run doesn't trip "The object already exists."
                self._log(f"Setting {nic} to {pc_ip}/{mask} via netsh…")
                self._set_nic_status("Applying static IP…", "blue")
                ok, msg = _set_static_ipv4(nic, pc_ip, mask)
                if not ok:
                    self._set_nic_status("Failed — see log", "red")
                    self._set_rls_status("Failed ✘", "red")
                    self._log(f"netsh FAILED: {msg}")
                    self._log(
                        "Aborting upgrade — the device cannot reach the PC "
                        "until the static IP is in place."
                    )
                    return
                self._static_ip_applied_on = nic
                self._set_nic_status(f"Static {pc_ip} on {nic}", "green")
                self._log(f"netsh OK: {msg}")
                # Give Windows a beat to bring the interface up with the new
                # address before we initiate the SSH connection.
                time.sleep(2.0)

                # Step 2 — SSH + software-install + poll.
                from scripts.Network.Ciena_RLS_Upgrade import RLSUpgradeScript

                script = RLSUpgradeScript(
                    ip_address=device_ip,
                    username=user,
                    password=pwd,
                    server_url=server_url,
                    output_callback=self._log,
                    stop_callback=lambda: self._upgrade_stop,
                )
                ok_run = script.run()
                if ok_run:
                    self._set_rls_status("Done ✔", "green")
                    self._log("✔ RLS upgrade reported complete.")
                    self._log(
                        "Reminder: click 'Restore DHCP' when you're done to "
                        "return the NIC to dynamic addressing."
                    )
                else:
                    self._set_rls_status("Failed ✘", "red")
                    self._log("✘ RLS upgrade did not complete — see log.")
            except Exception as exc:
                logging.exception("RLS upgrade worker error")
                self._set_rls_status("Error", "red")
                self._log(f"[ERROR] {exc}")
            finally:
                self.after(0, lambda: self._rls_run_btn.config(state=tk.NORMAL))
                self.after(0, lambda: self._rls_stop_btn.config(state=tk.DISABLED))

        self._upgrade_thread = threading.Thread(target=_worker, daemon=True)
        self._upgrade_thread.start()

    def _stop_rls_upgrade(self) -> None:
        if self._upgrade_thread is None or not self._upgrade_thread.is_alive():
            return
        self._upgrade_stop = True
        self._set_rls_status("Stopping…", "orange")
        self._log(
            "Stop requested — local polling will halt. The install on the "
            "device is not cancelled and will continue independently."
        )

    # ── Nokia G42 upgrade ───────────────────────────────────────────────────

    def _run_g42_upgrade(self) -> None:
        if self._upgrade_thread is not None and self._upgrade_thread.is_alive():
            messagebox.showinfo("Already running", "An upgrade is already in progress.")
            return
        if self._server is None:
            if not messagebox.askyesno(
                "HTTP server not running",
                "The HTTP server is not running, so the device will not be "
                "able to pull the upgrade file. Start it now?",
            ):
                return
            self._start_server()
            if self._server is None:
                return

        manifest = self._g42_file_var.get().strip()
        if not manifest:
            messagebox.showerror(
                "Error", "Pick a .manifest file from the dropdown."
            )
            return

        pc_ip = _G42_NET["pc_ip"]
        device_ip = _G42_NET["device_ip"]
        # Reflect derived PC IP in the netsh frame so the user can see
        # what the worker is about to apply.
        self._pc_ip_var.set(pc_ip)

        nic = self._nic_var.get().strip()
        if not nic:
            messagebox.showerror(
                "Error",
                "No network interface selected. Click ↺ in the PC Static IP "
                "row to refresh, then pick the NIC connected to the shelf.",
            )
            return

        mask = self._mask_var.get().strip() or _DEFAULT_MASK
        server_url = f"http://{pc_ip}:{_HTTP_PORT}/{manifest}"
        user = self._g42_user_var.get().strip() or "admin"
        pwd = self._g42_pass_var.get()

        self._upgrade_stop = False
        self._set_g42_status("Running…", "blue")
        self._g42_run_btn.config(state=tk.DISABLED)
        self._g42_stop_btn.config(state=tk.NORMAL)
        self._log(f"\n──── G42 upgrade: {device_ip} ← {server_url} ────")

        def _worker() -> None:
            try:
                # Step 1 — set PC NIC to the link-local service IP.
                # Helper handles stale-binding cleanup.
                self._log(f"Setting {nic} to {pc_ip}/{mask} via netsh…")
                self._set_nic_status("Applying static IP…", "blue")
                ok, msg = _set_static_ipv4(nic, pc_ip, mask)
                if not ok:
                    self._set_nic_status("Failed — see log", "red")
                    self._set_g42_status("Failed ✘", "red")
                    self._log(f"netsh FAILED: {msg}")
                    self._log(
                        "Aborting upgrade — the device cannot reach the PC "
                        "until the static IP is in place."
                    )
                    return
                self._static_ip_applied_on = nic
                self._set_nic_status(f"Static {pc_ip} on {nic}", "green")
                self._log(f"netsh OK: {msg}")
                time.sleep(2.0)

                # Step 2 — multi-phase SSH upgrade.
                from scripts.Network.Nokia_G42_Upgrade import NokiaG42UpgradeScript

                script = NokiaG42UpgradeScript(
                    ip_address=device_ip,
                    username=user,
                    password=pwd,
                    server_url=server_url,
                    manifest_name=manifest,
                    output_callback=self._log,
                    stop_callback=lambda: self._upgrade_stop,
                )
                ok_run = script.run()
                if ok_run:
                    self._set_g42_status("Done ✔", "green")
                    self._log("✔ G42 upgrade reported complete.")
                    self._log(
                        "Reminder: click 'Restore DHCP' when you're done to "
                        "return the NIC to dynamic addressing."
                    )
                else:
                    self._set_g42_status("Failed ✘", "red")
                    self._log("✘ G42 upgrade did not complete — see log.")
            except Exception as exc:
                logging.exception("G42 upgrade worker error")
                self._set_g42_status("Error", "red")
                self._log(f"[ERROR] {exc}")
            finally:
                self.after(0, lambda: self._g42_run_btn.config(state=tk.NORMAL))
                self.after(0, lambda: self._g42_stop_btn.config(state=tk.DISABLED))

        self._upgrade_thread = threading.Thread(target=_worker, daemon=True)
        self._upgrade_thread.start()

    def _stop_g42_upgrade(self) -> None:
        if self._upgrade_thread is None or not self._upgrade_thread.is_alive():
            return
        self._upgrade_stop = True
        self._set_g42_status("Stopping…", "orange")
        self._log(
            "Stop requested — the upgrade on the device continues "
            "independently and may not be safely interruptible."
        )

    def _set_g42_status(self, msg: str, color: str = "gray") -> None:
        def _do() -> None:
            self._g42_status.config(text=msg, foreground=color)
        try:
            self.after(0, _do)
        except Exception:
            pass

    # ── Nokia PSI upgrade ───────────────────────────────────────────────────

    def _run_psi_upgrade(self) -> None:
        if self._upgrade_thread is not None and self._upgrade_thread.is_alive():
            messagebox.showinfo("Already running", "An upgrade is already in progress.")
            return
        if self._server is None:
            if not messagebox.askyesno(
                "HTTP server not running",
                "The HTTP server is not running, so the device will not be "
                "able to pull the upgrade file. Start it now?",
            ):
                return
            self._start_server()
            if self._server is None:
                return

        filename = self._psi_file_var.get().strip()
        if not filename:
            messagebox.showerror(
                "Error",
                "Pick a software file from the dropdown. The folder you "
                "selected needs a CC/ subdirectory; we list files from "
                "there.",
            )
            return

        pc_ip = _PSI_NET["pc_ip"]
        device_ip = _PSI_NET["device_ip"]
        self._pc_ip_var.set(pc_ip)

        nic = self._nic_var.get().strip()
        if not nic:
            messagebox.showerror(
                "Error",
                "No network interface selected. Click ↺ in the PC Static IP "
                "row to refresh, then pick the NIC connected to the shelf.",
            )
            return

        mask = self._mask_var.get().strip() or _DEFAULT_MASK
        user = self._psi_user_var.get().strip() or "cli"
        pwd = self._psi_pass_var.get()
        inner_user = self._psi_inner_user_var.get().strip() or "admin"
        inner_pwd = self._psi_inner_pass_var.get()

        self._upgrade_stop = False
        self._set_psi_status("Running…", "blue")
        self._psi_run_btn.config(state=tk.DISABLED)
        self._psi_stop_btn.config(state=tk.NORMAL)
        self._log(f"\n──── PSI upgrade: {device_ip} ← /CC/{filename} ────")

        def _worker() -> None:
            try:
                # Step 1 — set PC NIC to the PSI service IP.
                # Helper handles stale-binding cleanup.
                self._log(f"Setting {nic} to {pc_ip}/{mask} via netsh…")
                self._set_nic_status("Applying static IP…", "blue")
                ok, msg = _set_static_ipv4(nic, pc_ip, mask)
                if not ok:
                    self._set_nic_status("Failed — see log", "red")
                    self._set_psi_status("Failed ✘", "red")
                    self._log(f"netsh FAILED: {msg}")
                    self._log(
                        "Aborting upgrade — the device cannot reach the PC "
                        "until the static IP is in place."
                    )
                    return
                self._static_ip_applied_on = nic
                self._set_nic_status(f"Static {pc_ip} on {nic}", "green")
                self._log(f"netsh OK: {msg}")
                time.sleep(2.0)

                # Step 2 — 2-phase SSH login + FTP config + audit/load/activate.
                from scripts.Network.Nokia_PSI_Upgrade import NokiaPSIUpgradeScript

                script = NokiaPSIUpgradeScript(
                    ip_address=device_ip,
                    username=user,
                    password=pwd,
                    inner_username=inner_user,
                    inner_password=inner_pwd,
                    software_filename=filename,
                    output_callback=self._log,
                    stop_callback=lambda: self._upgrade_stop,
                )
                ok_run = script.run()
                if ok_run:
                    self._set_psi_status("Done ✔", "green")
                    self._log("✔ PSI upgrade reported complete.")
                    self._log(
                        "Reminder: click 'Restore DHCP' when you're done to "
                        "return the NIC to dynamic addressing."
                    )
                else:
                    self._set_psi_status("Failed ✘", "red")
                    self._log("✘ PSI upgrade did not complete — see log.")
            except Exception as exc:
                logging.exception("PSI upgrade worker error")
                self._set_psi_status("Error", "red")
                self._log(f"[ERROR] {exc}")
            finally:
                self.after(0, lambda: self._psi_run_btn.config(state=tk.NORMAL))
                self.after(0, lambda: self._psi_stop_btn.config(state=tk.DISABLED))

        self._upgrade_thread = threading.Thread(target=_worker, daemon=True)
        self._upgrade_thread.start()

    def _stop_psi_upgrade(self) -> None:
        if self._upgrade_thread is None or not self._upgrade_thread.is_alive():
            return
        self._upgrade_stop = True
        self._set_psi_status("Stopping…", "orange")
        self._log(
            "Stop requested — local polling will halt. The load on the "
            "device is not cancelled and will continue independently."
        )

    def _set_psi_status(self, msg: str, color: str = "gray") -> None:
        def _do() -> None:
            self._psi_status.config(text=msg, foreground=color)
        try:
            self.after(0, _do)
        except Exception:
            pass

    # ── Ciena Waveserver 5 upgrade ──────────────────────────────────────────

    def _run_ws5_upgrade(self) -> None:
        if self._upgrade_thread is not None and self._upgrade_thread.is_alive():
            messagebox.showinfo("Already running", "An upgrade is already in progress.")
            return

        # Pre-flight: WS5 is two-phase and the operator MUST have both
        # cables connected before phase 1 even starts — serial on console
        # for provisioning, Cat-5 on DCN-1 for the subsequent SSH.
        if not messagebox.askokcancel(
            "Waveserver 5 — Pre-flight",
            "Before continuing, confirm:\n\n"
            "  • Serial cable connected from this PC to the Waveserver "
            "console port (115200 baud).\n"
            "  • Cat-5 connected from this PC to the Waveserver DCN-1 "
            "port.\n\n"
            "The program will set your NIC to 10.9.49.101/22 (acting as "
            "the device's gateway) and start an HTTP server on port 8000 "
            "rooted at the selected software folder.\n\n"
            "Click OK to begin.",
        ):
            return

        if self._server is None:
            if not messagebox.askyesno(
                "HTTP server not running",
                "The HTTP server is not running, so the Waveserver won't "
                "be able to pull the upgrade file in phase 2. Start it now?",
            ):
                return
            self._start_server()
            if self._server is None:
                return

        filename = self._ws5_file_var.get().strip()
        if not filename:
            messagebox.showerror(
                "Error", "Pick a .tar.gz software file from the dropdown."
            )
            return

        serial_port = self._ws5_serial_var.get().strip()
        if not serial_port:
            messagebox.showerror(
                "Error",
                "Select the serial port wired to the Waveserver console. "
                "Click ↺ next to the Serial Port dropdown to refresh.",
            )
            return

        pc_ip = _WS5_NET["pc_ip"]
        device_ip = _WS5_NET["device_ip"]
        device_ip_cidr = _WS5_NET["device_ip_cidr"]
        mask = _WS5_NET["mask"]
        self._pc_ip_var.set(pc_ip)

        nic = self._nic_var.get().strip()
        if not nic:
            messagebox.showerror(
                "Error",
                "No network interface selected. Click ↺ in the PC Static IP "
                "row to refresh, then pick the NIC connected to DCN-1.",
            )
            return

        server_url = f"http://{pc_ip}:{_HTTP_PORT}/{filename}"

        self._upgrade_stop = False
        self._set_ws5_status("Running…", "blue")
        self._ws5_run_btn.config(state=tk.DISABLED)
        self._ws5_stop_btn.config(state=tk.NORMAL)
        self._log(
            f"\n──── Waveserver 5 upgrade: {device_ip_cidr} via {serial_port} "
            f"+ SSH @ {device_ip} ← {server_url} ────"
        )

        def _worker() -> None:
            try:
                # Step 1 — point the NIC at 10.9.49.101/22 so the device
                # can reach the HTTP server once phase 1 finishes.
                # Use the helper that pre-deletes any stale binding of
                # the same IP so a previous run's leftover doesn't
                # cause ``The object already exists.``
                self._log(f"Setting {nic} to {pc_ip}/{mask} via netsh…")
                self._set_nic_status("Applying static IP…", "blue")
                ok, msg = _set_static_ipv4(nic, pc_ip, mask)
                if not ok:
                    self._set_nic_status("Failed — see log", "red")
                    self._set_ws5_status("Failed ✘", "red")
                    self._log(f"netsh FAILED: {msg}")
                    self._log(
                        "Aborting upgrade — without the static IP the "
                        "Waveserver cannot reach the HTTP server."
                    )
                    return
                self._static_ip_applied_on = nic
                self._set_nic_status(f"Static {pc_ip} on {nic}", "green")
                self._log(f"netsh OK: {msg}")
                time.sleep(2.0)

                # Step 2 — run the two-phase upgrade script. The script
                # handles serial provisioning, the SSH download/activate
                # flow, and polls upgrade-status for us.
                from scripts.Network.Ciena_Waveserver5_Upgrade import (
                    Waveserver5UpgradeScript,
                )

                script = Waveserver5UpgradeScript(
                    serial_port=serial_port,
                    software_filename=filename,
                    server_url=server_url,
                    device_ip=device_ip,
                    device_ip_cidr=device_ip_cidr,
                    gateway_ip=pc_ip,
                    hostname=_WS5_HOSTNAME,
                    output_callback=self._log,
                    stop_callback=lambda: self._upgrade_stop,
                )
                ok_run = script.run()
                if ok_run:
                    self._set_ws5_status("Activating ✔", "green")
                    self._log("✔ Waveserver 5 reached 'Activation In Progress'.")
                    self._log(
                        "Reminder: click 'Restore DHCP' when you're done to "
                        "return the NIC to dynamic addressing."
                    )
                    # Final popup matches the operator's verbatim text from
                    # the spec — it's what they expect at end-of-run.
                    self.after(0, lambda: messagebox.showinfo(
                        "Waveserver 5 — Complete",
                        "Software Activation in Progress. Manual Commit "
                        "Required. Safe to Disconnect.",
                    ))
                else:
                    self._set_ws5_status("Failed ✘", "red")
                    self._log("✘ Waveserver 5 upgrade did not complete — see log.")
            except Exception as exc:
                logging.exception("Waveserver 5 upgrade worker error")
                self._set_ws5_status("Error", "red")
                self._log(f"[ERROR] {exc}")
            finally:
                self.after(0, lambda: self._ws5_run_btn.config(state=tk.NORMAL))
                self.after(0, lambda: self._ws5_stop_btn.config(state=tk.DISABLED))

        self._upgrade_thread = threading.Thread(target=_worker, daemon=True)
        self._upgrade_thread.start()

    def _stop_ws5_upgrade(self) -> None:
        if self._upgrade_thread is None or not self._upgrade_thread.is_alive():
            return
        self._upgrade_stop = True
        self._set_ws5_status("Stopping…", "orange")
        self._log(
            "Stop requested — local polling will halt. Once a software "
            "download is in flight on the device it continues independently."
        )

    def _set_ws5_status(self, msg: str, color: str = "gray") -> None:
        def _do() -> None:
            self._ws5_status.config(text=msg, foreground=color)
        try:
            self.after(0, _do)
        except Exception:
            pass

    def _set_rls_status(self, msg: str, color: str = "gray") -> None:
        def _do() -> None:
            self._rls_status.config(text=msg, foreground=color)
        try:
            self.after(0, _do)
        except Exception:
            pass

    # ── Progress + status helpers ───────────────────────────────────────────

    def _on_progress(
        self, filename: str, sent: int, total: int, done: bool = False
    ) -> None:
        pct = (sent / total * 100.0) if total else 0.0

        def _do() -> None:
            self._progress_var.set(pct)
            if done:
                self._progress_lbl.config(
                    text=f"Sent {filename} ({sent:,} bytes)", foreground="green"
                )
            else:
                self._progress_lbl.config(
                    text=f"{filename}: {sent:,}/{total:,} bytes ({pct:.1f}%)",
                    foreground="blue",
                )
        try:
            self.after(0, _do)
        except Exception:
            pass

    def _set_nic_status(self, msg: str, color: str = "gray") -> None:
        def _do() -> None:
            self._nic_status.config(text=msg, foreground=color)
        try:
            self.after(0, _do)
        except Exception:
            pass

    def _set_srv_status(self, msg: str, color: str = "gray") -> None:
        def _do() -> None:
            self._srv_status.config(text=msg, foreground=color)
        try:
            self.after(0, _do)
        except Exception:
            pass

    def _log(self, msg: str) -> None:
        """Tee a single log line to every sink the operator might be
        watching:

          * the per-frame ``Log`` widget at the bottom of the upgrade
            tab (timestamped),
          * the shared bottom output panel ``controller.output_screen``
            (same panel every other ATLAS mode logs to), so the
            operator can leave it docked and still see progress here,
          * Python's root logger, which writes to the rolling ATLAS
            log file -- without this, GUI-side breadcrumbs like
            ``Setting NIC...`` only existed inside the Tk widget and
            disappeared the moment the window closed.

        Each sink is best-effort: a failure in one (Tk widget
        destroyed, controller missing the output_screen attr,
        logging handler error) must not break the others.
        """
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"

        # 1) Per-frame log widget. Marshaled to the Tk main loop so
        # worker threads can safely call this.
        def _do() -> None:
            try:
                self._log_text.config(state=tk.NORMAL)
                self._log_text.insert(tk.END, line)
                self._log_text.see(tk.END)
                self._log_text.config(state=tk.DISABLED)
            except Exception:
                pass
        try:
            self.after(0, _do)
        except Exception:
            pass

        # 2) Shared bottom output panel (used by every other mode).
        # Wrapped in try because some test contexts construct the
        # frame with a stub controller that doesn't have the attr.
        out = getattr(self.controller, "output_screen", None)
        if out is not None:
            def _do_shared() -> None:
                try:
                    out.insert(tk.END, line)
                    out.see(tk.END)
                except Exception:
                    pass
            try:
                self.after(0, _do_shared)
            except Exception:
                pass

        # 3) Python logger -> ATLAS rolling log file. INFO level so
        # the operator can attach the file to a bug report and have
        # the full transcript. Strip the leading newline some calls
        # add for visual spacing in the widget -- the file logger
        # adds its own line terminator.
        try:
            logging.info(msg.lstrip("\n"))
        except Exception:
            pass

    def _clear_log(self) -> None:
        self._log_text.config(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        self._log_text.config(state=tk.DISABLED)

    # ── Lifecycle hook ──────────────────────────────────────────────────────

    def on_app_shutdown(self) -> None:
        """Called by the main GUI when the app is closing — make sure the
        listener is torn down so the next launch can re-bind :8000."""
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None
