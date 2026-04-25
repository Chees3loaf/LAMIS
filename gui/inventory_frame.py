"""Inventory scanning frame — widgets and UI logic for the Inventory mode."""
import os
import logging
import tkinter as tk
from tkinter import ttk, filedialog

import config


class InventoryFrame(ttk.Frame):
    """Tkinter frame for the Inventory (network scan) mode.

    Owns all pod/IP selection widgets, run/pause/abort controls, progress bar,
    and append-mode report selection.  Calls back into *controller* (an
    ``InventoryGUI`` instance) for cross-cutting operations such as
    ``run_script``, ``pause_program``, and ``abort_program``.
    """

    def __init__(self, parent: ttk.Frame, controller) -> None:
        super().__init__(parent)
        self.controller = controller
        self.inventory_report_path: str | None = None
        self._build()

    # ------------------------------------------------------------------
    # Frame construction
    # ------------------------------------------------------------------

    def _build(self) -> None:
        # --- Connection type row ---
        connection_frame = ttk.LabelFrame(self, text="Connection Type")
        connection_frame.pack(fill=tk.X, pady=5)
        self.connection_type = tk.StringVar(value="Network")
        tk.Radiobutton(
            connection_frame, text="Network",
            variable=self.connection_type, value="Network",
        ).pack(side=tk.LEFT, padx=10)

        # --- Optional existing report (append mode) ---
        report_frame = ttk.LabelFrame(self, text="Device Report (Optional)")
        report_frame.pack(fill=tk.X, pady=5)
        self.inventory_file_label = tk.Label(
            report_frame,
            text="No report selected (new workbook will be created)",
            foreground="gray",
        )
        self.inventory_file_label.pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(report_frame, text="Browse", command=self.upload_inventory_report).pack(side=tk.LEFT, padx=5)
        tk.Button(report_frame, text="Clear", command=self.clear_inventory_report_upload).pack(side=tk.LEFT, padx=5)

        # --- Pod / IP selection (two columns) ---
        middle_frame = ttk.Frame(self)
        middle_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=20)

        left_middle_frame = ttk.Frame(middle_frame)
        left_middle_frame.pack(side=tk.LEFT, expand=True, padx=10, pady=20)

        right_middle_frame = ttk.Frame(middle_frame)
        right_middle_frame.pack(side=tk.RIGHT, expand=True, padx=10, pady=20)

        pod_options = [f"{config.POD_MIN + i}" for i in range(config.POD_COUNT)]

        # Pod 1 (left column)
        pod_frame_1 = ttk.LabelFrame(left_middle_frame, text="Pod Selection 1")
        pod_frame_1.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(pod_frame_1, text="Pod:").pack(side=tk.LEFT, padx=5)
        self.pod_var_1 = tk.StringVar()
        self.pod_combobox_1 = ttk.Combobox(pod_frame_1, textvariable=self.pod_var_1, values=pod_options)
        self.pod_combobox_1.pack(side=tk.LEFT, padx=5)
        self.pod_combobox_1.set("100")

        ip_frame_1 = ttk.LabelFrame(left_middle_frame, text="IP Selection 1")
        ip_frame_1.pack(fill=tk.X, padx=10, pady=5)
        ip_container_1 = ttk.Frame(ip_frame_1)
        ip_container_1.pack()
        self.start_ip_label_1 = tk.Label(
            ip_container_1,
            text=f"Start IP: {config.POD_NETWORK_PREFIX}.{self.pod_var_1.get()}.",
        )
        self.start_ip_label_1.pack(side=tk.LEFT)
        self.start_ip_entry_1 = tk.Entry(ip_container_1, width=3, justify="center")
        self.start_ip_entry_1.pack(side=tk.LEFT)
        self.end_ip_label_1 = tk.Label(
            ip_container_1,
            text=f"End IP: {config.POD_NETWORK_PREFIX}.{self.pod_var_1.get()}.",
        )
        self.end_ip_label_1.pack(side=tk.LEFT)
        self.end_ip_entry_1 = tk.Entry(ip_container_1, width=3, justify="center")
        self.end_ip_entry_1.pack(side=tk.LEFT)
        self.pod_var_1.trace_add(
            "write",
            lambda *_: self._update_ip_labels(self.pod_var_1, self.start_ip_label_1, self.end_ip_label_1),
        )

        # Pod 2 (right column)
        pod_frame_2 = ttk.LabelFrame(right_middle_frame, text="Pod Selection 2")
        pod_frame_2.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(pod_frame_2, text="Pod:").pack(side=tk.LEFT, padx=5)
        self.pod_var_2 = tk.StringVar()
        self.pod_combobox_2 = ttk.Combobox(pod_frame_2, textvariable=self.pod_var_2, values=pod_options)
        self.pod_combobox_2.pack(side=tk.LEFT, padx=5)
        self.pod_combobox_2.set("100")

        ip_frame_2 = ttk.LabelFrame(right_middle_frame, text="IP Selection 2")
        ip_frame_2.pack(fill=tk.X, padx=10, pady=5)
        ip_container_2 = ttk.Frame(ip_frame_2)
        ip_container_2.pack()
        self.start_ip_label_2 = tk.Label(
            ip_container_2,
            text=f"Start IP: {config.POD_NETWORK_PREFIX}.{self.pod_var_2.get()}.",
        )
        self.start_ip_label_2.pack(side=tk.LEFT)
        self.start_ip_entry_2 = tk.Entry(ip_container_2, width=3, justify="center")
        self.start_ip_entry_2.pack(side=tk.LEFT)
        self.end_ip_label_2 = tk.Label(
            ip_container_2,
            text=f"End IP: {config.POD_NETWORK_PREFIX}.{self.pod_var_2.get()}.",
        )
        self.end_ip_label_2.pack(side=tk.LEFT)
        self.end_ip_entry_2 = tk.Entry(ip_container_2, width=3, justify="center")
        self.end_ip_entry_2.pack(side=tk.LEFT)
        self.pod_var_2.trace_add(
            "write",
            lambda *_: self._update_ip_labels(self.pod_var_2, self.start_ip_label_2, self.end_ip_label_2),
        )

        # --- Action buttons + status ---
        control_frame = ttk.Frame(self)
        control_frame.pack(fill=tk.X, pady=10)

        self.run_button = tk.Button(control_frame, text="Run", command=self.controller.run_script)
        self.run_button.pack(side=tk.RIGHT, padx=5)
        self.pause_button = tk.Button(
            control_frame, text="Pause",
            command=self.controller.pause_program, state=tk.DISABLED,
        )
        self.pause_button.pack(side=tk.RIGHT, padx=5)
        self.abort_button = tk.Button(
            control_frame, text="Abort",
            command=self.controller.abort_program, state=tk.DISABLED,
        )
        self.abort_button.pack(side=tk.RIGHT, padx=5)

        self.status_label = tk.Label(control_frame, text="Status: Ready", anchor="w")
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # --- Progress bar ---
        progress_frame = ttk.Frame(self)
        progress_frame.pack(fill=tk.X, padx=10, pady=(0, 4))
        self.progress_bar = ttk.Progressbar(
            progress_frame, orient="horizontal", mode="determinate", maximum=100
        )
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.progress_label = tk.Label(progress_frame, text="", width=28, anchor="w")
        self.progress_label.pack(side=tk.LEFT)

    # ------------------------------------------------------------------
    # Public API used by InventoryGUI
    # ------------------------------------------------------------------

    def update_status(self, message: str) -> None:
        """Update the status label and flush pending UI events."""
        self.status_label.config(text=message)
        self.controller.root.update_idletasks()

    def set_run_controls(self, running: bool) -> None:
        """Enable or disable run/pause/abort buttons based on *running* state."""
        self.run_button.config(state=tk.DISABLED if running else tk.NORMAL)
        pa_state = tk.NORMAL if running else tk.DISABLED
        self.pause_button.config(state=pa_state)
        self.abort_button.config(state=pa_state)

    def update_progress(self, current: int, total: int, label: str) -> None:
        """Advance the progress bar to *current*/*total* and set the label text."""
        if total > 0:
            self.progress_bar["value"] = (current / total) * 100
        self.progress_label.config(text=label)

    def reset_progress(self) -> None:
        """Reset progress bar to zero and clear the label."""
        self.progress_bar["value"] = 0
        self.progress_label.config(text="")

    def upload_inventory_report(self) -> None:
        """Prompt for an existing report file to enable append mode."""
        file_path = filedialog.askopenfilename(
            title="Select Existing Device Report",
            filetypes=[("Excel files", "*.xlsx *.xls"), ("All files", "*.*")],
        )
        if not file_path:
            return

        self.inventory_report_path = file_path
        file_name = os.path.basename(file_path)
        self.inventory_file_label.config(
            text=f"Using existing report: {file_name}", foreground="green"
        )
        out = self.controller.output_screen
        out.insert(tk.END, f"Inventory append mode enabled: {file_name}\n")
        out.see(tk.END)
        logging.info(f"Inventory report selected for append: {file_path}")

    def clear_inventory_report_upload(self) -> None:
        """Clear the append-mode report selection."""
        self.inventory_report_path = None
        self.inventory_file_label.config(
            text="No report selected (new workbook will be created)", foreground="gray"
        )
        out = self.controller.output_screen
        out.insert(tk.END, "Inventory append mode disabled; a new report will be created.\n")
        out.see(tk.END)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_ip_labels(self, pod_var: tk.StringVar, start_label: tk.Label, end_label: tk.Label) -> None:
        pod = pod_var.get()
        start_label.config(text=f"Start IP: {config.POD_NETWORK_PREFIX}.{pod}.")
        end_label.config(text=f"End IP: {config.POD_NETWORK_PREFIX}.{pod}.")
