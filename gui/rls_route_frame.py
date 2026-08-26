"""Legacy Tk route-builder interface backed by the neutral RLS core."""
from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from services.rls_route_core import *  # noqa: F401,F403


class RlsRouteFrame(ttk.Frame):
    """Master/detail route editor for mixed Ciena RLS shelf projects."""

    def __init__(self, parent: tk.Widget, controller: Any = None) -> None:
        super().__init__(parent)
        self.controller = controller
        self._rows: list[_ShelfEditorRow] = []
        self._links: list[RouteLink] = []
        self._links_populated = False
        self._project_id = uuid4().hex
        self._project_notes = ""
        self._diagram_source: Mapping[str, Any] = {}
        self._attached_workbook_diagram: WorkbookDiagram | None = None
        self._current_path: Optional[Path] = None
        self._dirty = False
        self._editor_dirty = False
        self._editor_shelf_id = ""
        self._loading_project = False
        self._loading_editor = False
        self._editor_power_is_atlas_default = False
        self._restoring_tree_selection = False
        self._destroyed = False
        self._job_generation = 0
        self._foreground_job: tuple[str, int] | None = None
        self._config_labels: dict[str, str] = {}
        self._config_after_id: Optional[str] = None
        self._poll_after_id: Optional[str] = None
        self._preview_fingerprint = ""
        self._preview_path: Optional[Path] = None
        self._preview_tempdirs: list[tempfile.TemporaryDirectory[str]] = []
        self._config_review_window: Optional[tk.Toplevel] = None
        self._worker_results: Queue[_WorkerResult] = Queue()
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="atlas-rls-route",
        )
        self._diagram_provider_factory: Callable[[], Any] = (
            _default_diagram_provider
        )
        self._profile_pairs = profile_choices()
        self._profile_id_by_label = {
            display_name: profile_id
            for profile_id, display_name in self._profile_pairs
        }
        self._profile_label_by_id = dict(self._profile_pairs)
        self._build()
        self._refresh_tree()
        self._refresh_status()
        self._poll_after_id = self.after(100, self._drain_worker_results)
        self.bind("<Destroy>", self._on_destroy, add="+")
        _log_route_event("Route Builder initialized.")

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky=tk.EW, padx=8, pady=(5, 3))
        ttk.Label(
            header,
            text="Ciena RLS R4.0 Route Project & FBN Deliverable",
            font=("TkDefaultFont", 11, "bold"),
        ).pack(anchor=tk.W)
        ttk.Label(
            header,
            text=PLANNING_CLI_NOTICE,
            foreground="#8a4d00",
            justify=tk.LEFT,
            wraplength=1120,
        ).pack(anchor=tk.W, pady=(2, 0))

        project_group = ttk.LabelFrame(self, text="Project")
        project_group.grid(row=1, column=0, sticky=tk.EW, padx=8, pady=4)
        project_group.grid_columnconfigure(3, weight=1)

        self._route_code_var = tk.StringVar()
        self._title_var = tk.StringVar()
        self._revision_var = tk.StringVar(value="1")
        self._ospf_area_var = tk.StringVar()
        self._neighbor_dns_suffix_var = tk.StringVar()
        self._a_input_patch_loss_var = tk.StringVar(value="0.5")
        self._a_output_patch_loss_var = tk.StringVar(value="0.5")
        self._z_input_patch_loss_var = tk.StringVar(value="0.2")
        self._z_output_patch_loss_var = tk.StringVar(value="0.2")
        self._colan_ospf_metric_var = tk.StringVar(value="10")
        self._route_fiber_type_var = tk.StringVar()
        self._route_fiber_observation_var = tk.StringVar(
            value="Diagram fiber: not available."
        )
        self._project_entry(
            project_group, row=0, column=0, label="Route", variable=self._route_code_var
        )
        self._project_entry(
            project_group,
            row=0,
            column=2,
            label="Deliverable title",
            variable=self._title_var,
            width=48,
        )
        self._project_entry(
            project_group,
            row=0,
            column=4,
            label="Revision",
            variable=self._revision_var,
            width=9,
        )
        self._project_entry(
            project_group,
            row=1,
            column=0,
            label="OSPF area",
            variable=self._ospf_area_var,
        )
        ttk.Label(project_group, text="Native CLI fiber type:").grid(
            row=1, column=2, sticky=tk.E, padx=(7, 3), pady=5
        )
        ttk.Combobox(
            project_group,
            textvariable=self._route_fiber_type_var,
            values=FIBER_TYPES,
            state="readonly",
            width=24,
        ).grid(row=1, column=3, sticky=tk.W, padx=(0, 5), pady=5)
        self._apply_route_fiber_button = ttk.Button(
            project_group,
            text="Apply to all spans",
            command=self._apply_route_native_fiber_type,
        )
        self._apply_route_fiber_button.grid(
            row=1, column=4, columnspan=2, sticky=tk.W, padx=(0, 8), pady=5
        )
        ttk.Label(
            project_group,
            textvariable=self._route_fiber_observation_var,
            foreground="#666666",
        ).grid(
            row=2,
            column=0,
            columnspan=4,
            sticky=tk.W,
            padx=(7, 8),
            pady=5,
        )
        ttk.Label(
            project_group,
            text=(
                "Choose one audited native CLI token for the route. The "
                "diagram label remains separate and is never alias-converted."
            ),
            foreground="#666666",
        ).grid(
            row=2,
            column=4,
            columnspan=2,
            sticky=tk.W,
            padx=(7, 8),
            pady=5,
        )
        self._project_entry(
            project_group,
            row=3,
            column=0,
            label="Node/neighbor DNS suffix",
            variable=self._neighbor_dns_suffix_var,
        )
        self._project_entry(
            project_group,
            row=3,
            column=2,
            label="A input patch loss (dB)",
            variable=self._a_input_patch_loss_var,
            width=9,
        )
        self._project_entry(
            project_group,
            row=3,
            column=4,
            label="A output patch loss (dB)",
            variable=self._a_output_patch_loss_var,
            width=9,
        )
        self._project_entry(
            project_group,
            row=4,
            column=0,
            label="Z input patch loss (dB)",
            variable=self._z_input_patch_loss_var,
            width=9,
        )
        self._project_entry(
            project_group,
            row=4,
            column=2,
            label="Z output patch loss (dB)",
            variable=self._z_output_patch_loss_var,
            width=9,
        )
        self._project_entry(
            project_group,
            row=4,
            column=4,
            label="COLAN OSPF metric",
            variable=self._colan_ospf_metric_var,
            width=9,
        )
        for variable in (
            self._route_code_var,
            self._title_var,
            self._revision_var,
        ):
            variable.trace_add("write", self._on_project_edited)
        self._ospf_area_var.trace_add("write", self._on_ospf_area_edited)
        for variable in (
            self._neighbor_dns_suffix_var,
            self._a_input_patch_loss_var,
            self._a_output_patch_loss_var,
            self._z_input_patch_loss_var,
            self._z_output_patch_loss_var,
            self._colan_ospf_metric_var,
        ):
            variable.trace_add("write", self._on_customer_policy_edited)

        workspace = ttk.Panedwindow(self, orient=tk.VERTICAL)
        workspace.grid(row=2, column=0, sticky=tk.NSEW, padx=8, pady=4)

        list_group = ttk.LabelFrame(workspace, text="Ordered route shelves")
        editor_group = ttk.LabelFrame(workspace, text="Shelf details")
        workspace.add(list_group, weight=3)
        workspace.add(editor_group, weight=2)
        list_group.grid_columnconfigure(0, weight=1)
        list_group.grid_rowconfigure(0, weight=1)

        self._tree = ttk.Treeview(
            list_group,
            columns=_TABLE_COLUMNS,
            show="headings",
            selectmode="browse",
            height=10,
        )
        column_setup = {
            "order": ("#", 42, tk.CENTER),
            "profile": ("Shelf type", 145, tk.W),
            "site": ("Site", 92, tk.W),
            "tid": ("TID", 126, tk.W),
            "ip": ("Primary OAM IP", 122, tk.W),
            "release": ("Release", 86, tk.W),
            "raman": ("RAMAN", 80, tk.W),
            "power": ("Power", 78, tk.W),
            "provider": ("Provider", 285, tk.W),
            "direction": ("Direction map", 225, tk.W),
            "readiness": ("CLI readiness", 165, tk.W),
        }
        for key, (heading, width, anchor) in column_setup.items():
            self._tree.heading(key, text=heading)
            self._tree.column(key, width=width, minwidth=36, anchor=anchor)
        self._tree.grid(row=0, column=0, sticky=tk.NSEW)
        yscroll = ttk.Scrollbar(
            list_group, orient=tk.VERTICAL, command=self._tree.yview
        )
        yscroll.grid(row=0, column=1, sticky=tk.NS)
        xscroll = ttk.Scrollbar(
            list_group, orient=tk.HORIZONTAL, command=self._tree.xview
        )
        xscroll.grid(row=1, column=0, sticky=tk.EW)
        self._tree.configure(
            yscrollcommand=yscroll.set,
            xscrollcommand=xscroll.set,
        )
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        order_controls = ttk.Frame(list_group)
        order_controls.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=4)
        ttk.Button(
            order_controls, text="Move Up", command=lambda: self._move_selected(-1)
        ).pack(side=tk.LEFT, padx=(2, 3))
        ttk.Button(
            order_controls, text="Move Down", command=lambda: self._move_selected(1)
        ).pack(side=tk.LEFT, padx=3)
        ttk.Button(
            order_controls, text="Remove", command=self._remove_selected
        ).pack(side=tk.LEFT, padx=3)
        ttk.Label(
            order_controls,
            text="Rack diagrams are populated in this order, eight shelves per rack.",
            foreground="#666666",
        ).pack(side=tk.LEFT, padx=12)

        self._build_editor(editor_group)

        footer = ttk.Frame(self)
        footer.grid(row=3, column=0, sticky=tk.EW, padx=8, pady=(3, 7))
        self._new_button = ttk.Button(
            footer, text="New", command=self._new_project
        )
        self._new_button.pack(side=tk.LEFT, padx=(0, 3))
        self._open_button = ttk.Button(
            footer, text="Open Project…", command=self._open_project
        )
        self._open_button.pack(side=tk.LEFT, padx=3)
        self._save_button = ttk.Button(
            footer, text="Save Project…", command=self._save_project
        )
        self._save_button.pack(side=tk.LEFT, padx=3)
        self._upload_button = ttk.Button(
            footer,
            text="Upload Route Diagram…",
            command=self._upload_route_diagram,
        )
        self._upload_button.pack(side=tk.LEFT, padx=(8, 3))
        self._reattach_diagram_button = ttk.Button(
            footer,
            text="Reattach Diagram…",
            command=self._reattach_route_diagram,
        )
        self._reattach_diagram_button.pack(side=tk.LEFT, padx=3)
        self._preview_button = ttk.Button(
            footer,
            text="Preview MOP",
            command=self._preview_mop,
        )
        self._preview_button.pack(side=tk.LEFT, padx=3)
        self._bundle_button = ttk.Button(
            footer, text="Export Route Bundle…", command=self._export_bundle
        )
        self._bundle_button.pack(side=tk.LEFT, padx=3)
        self._status_var = tk.StringVar()
        ttk.Label(
            footer,
            textvariable=self._status_var,
            foreground="#555555",
            justify=tk.LEFT,
        ).pack(side=tk.LEFT, padx=9)

    @staticmethod
    def _project_entry(
        parent: tk.Widget,
        *,
        row: int,
        column: int,
        label: str,
        variable: tk.StringVar,
        width: int = 22,
    ) -> None:
        ttk.Label(parent, text=f"{label}:").grid(
            row=row, column=column, sticky=tk.E, padx=(7, 3), pady=5
        )
        ttk.Entry(parent, textvariable=variable, width=width).grid(
            row=row, column=column + 1, sticky=tk.EW, padx=(0, 8), pady=5
        )

    def _build_editor(self, parent: ttk.LabelFrame) -> None:
        for column in (1, 3, 5):
            parent.grid_columnconfigure(column, weight=1)

        first_profile = self._profile_pairs[0][1] if self._profile_pairs else ""
        first_profile_id = (
            self._profile_pairs[0][0] if self._profile_pairs else ""
        )
        initial_power = power_label_for_profile(first_profile_id)
        self._profile_var = tk.StringVar(value=first_profile)
        self._site_code_var = tk.StringVar()
        self._site_name_var = tk.StringVar()
        self._tid_var = tk.StringVar()
        self._ip_var = tk.StringVar()
        self._release_var = tk.StringVar(value=R40_UI_RELEASE)
        self._variant_var = tk.StringVar()
        self._raman_var = tk.StringVar()
        self._power_var = tk.StringVar(value=initial_power)
        self._editor_power_is_atlas_default = bool(initial_power)
        for variable in (
            self._profile_var,
            self._site_code_var,
            self._site_name_var,
            self._tid_var,
            self._ip_var,
            self._release_var,
            self._variant_var,
            self._raman_var,
            self._power_var,
        ):
            variable.trace_add("write", self._on_editor_edited)
        self._power_var.trace_add("write", self._on_power_edited)

        profile = ttk.Combobox(
            parent,
            textvariable=self._profile_var,
            values=tuple(label for _profile_id, label in self._profile_pairs),
            state="readonly",
            width=24,
        )
        profile.bind("<<ComboboxSelected>>", self._on_profile_selected)
        self._editor_field(parent, 0, 0, "Shelf type", profile)
        self._editor_field(
            parent, 0, 2, "Site code", ttk.Entry(parent, textvariable=self._site_code_var)
        )
        self._editor_field(
            parent, 0, 4, "Site name", ttk.Entry(parent, textvariable=self._site_name_var)
        )
        self._editor_field(
            parent, 1, 0, "TID", ttk.Entry(parent, textvariable=self._tid_var)
        )
        self._editor_field(
            parent,
            1,
            2,
            "Primary OAM IP",
            ttk.Entry(parent, textvariable=self._ip_var),
        )
        self._editor_field(
            parent,
            1,
            4,
            "Software release",
            ttk.Entry(
                parent,
                textvariable=self._release_var,
                state="readonly",
            ),
        )
        self._editor_field(
            parent,
            2,
            0,
            "Shelf variant / PEC",
            ttk.Entry(parent, textvariable=self._variant_var),
        )
        self._editor_field(
            parent,
            2,
            2,
            "RAMAN display",
            ttk.Entry(parent, textvariable=self._raman_var),
        )
        self._editor_field(
            parent,
            2,
            4,
            "Power",
            ttk.Entry(parent, textvariable=self._power_var),
        )

        actions = ttk.Frame(parent)
        actions.grid(row=3, column=0, columnspan=6, sticky=tk.EW, pady=(6, 5))
        ttk.Button(actions, text="Add Shelf", command=self._add_shelf).pack(
            side=tk.LEFT, padx=(7, 3)
        )
        ttk.Button(actions, text="Update Selected", command=self._update_selected).pack(
            side=tk.LEFT, padx=3
        )
        ttk.Button(
            actions,
            text="Confirm & Next Pending",
            command=self._confirm_and_next_pending,
        ).pack(side=tk.LEFT, padx=3)
        self._review_config_button = ttk.Button(
            actions,
            text="Review Configuration…",
            command=self._review_selected_configuration,
        )
        self._review_config_button.pack(side=tk.LEFT, padx=3)
        ttk.Button(actions, text="Clear Editor", command=self._clear_editor).pack(
            side=tk.LEFT, padx=3
        )
        ttk.Label(
            actions,
            text=(
                "RAMAN and power text are deliverable labels. Reviewed "
                "structured SRA evidence separately gates provider "
                "compatibility; it never enables CLI."
            ),
            foreground="#666666",
        ).pack(side=tk.LEFT, padx=12)

    @staticmethod
    def _editor_field(
        parent: tk.Widget,
        row: int,
        column: int,
        label: str,
        control: tk.Widget,
    ) -> None:
        ttk.Label(parent, text=f"{label}:").grid(
            row=row, column=column, sticky=tk.E, padx=(7, 3), pady=4
        )
        control.grid(
            row=row, column=column + 1, sticky=tk.EW, padx=(0, 8), pady=4
        )

    def _on_project_edited(self, *_args: object) -> None:
        if self._loading_project:
            return
        self._dirty = True
        self._invalidate_project_results()
        self._schedule_config_evaluation()
        self._refresh_status()

    def _on_ospf_area_edited(self, *_args: object) -> None:
        if self._loading_project:
            return
        self._rows, cleared = _clear_provider_payloads(self._rows)
        if cleared:
            _log_route_event(
                f"OSPF area changed; cleared {cleared} route-bound "
                "configuration payload(s).",
                logging.WARNING,
            )
        self._on_project_edited()
        if cleared:
            self._refresh_tree()
            self._refresh_status(
                "OSPF area changed. Review every affected configuration again."
            )

    def _on_customer_policy_edited(self, *_args: object) -> None:
        if self._loading_project:
            return
        self._rows, cleared = _clear_provider_payloads(self._rows)
        if cleared:
            _log_route_event(
                "Route customer policy changed; cleared "
                f"{cleared} route-bound configuration payload(s).",
                logging.WARNING,
            )
        self._on_project_edited()
        if cleared:
            self._refresh_tree()
            self._refresh_status(
                "Customer policy changed. Review every affected "
                "configuration again."
            )

    def _customer_policy(self) -> RouteCustomerPolicy:
        def number(variable: tk.StringVar, label: str) -> float:
            raw = variable.get().strip()
            try:
                return float(raw)
            except ValueError as exc:
                raise ValueError(f"{label} must be a number.") from exc

        raw_metric = self._colan_ospf_metric_var.get().strip()
        try:
            metric = int(raw_metric)
        except ValueError as exc:
            raise ValueError(
                "COLAN OSPF metric must be an integer."
            ) from exc
        policy = RouteCustomerPolicy(
            neighbor_dns_suffix=self._neighbor_dns_suffix_var.get().strip(),
            a_input_patch_loss_db=number(
                self._a_input_patch_loss_var,
                "A-side input patch loss",
            ),
            a_output_patch_loss_db=number(
                self._a_output_patch_loss_var,
                "A-side output patch loss",
            ),
            z_input_patch_loss_db=number(
                self._z_input_patch_loss_var,
                "Z-side input patch loss",
            ),
            z_output_patch_loss_db=number(
                self._z_output_patch_loss_var,
                "Z-side output patch loss",
            ),
            colan_ospf_metric=metric,
        )
        policy.assert_valid()
        return policy

    def _sync_route_fiber_controls(self) -> None:
        """Refresh the one route-wide native token and source-label summary."""

        from utils.rls_config.route_project import route_native_fiber_review

        status, token = route_native_fiber_review(self._links)
        observed = _observed_route_fiber_types(
            self._diagram_source,
            self._links,
        )
        if status == "confirmed":
            self._route_fiber_type_var.set(token)
        elif len(observed) == 1 and observed[0] in FIBER_TYPES:
            self._route_fiber_type_var.set(observed[0])
        else:
            self._route_fiber_type_var.set("")
        if not observed:
            observed_text = "Diagram fiber: not available."
        elif len(observed) == 1:
            observed_text = f"Diagram fiber: {observed[0]}."
        else:
            observed_text = (
                "Diagram fibers conflict: " + ", ".join(observed) + "."
            )
        if status == "confirmed":
            observed_text += f" Confirmed native route token: {token}."
        elif status == "invalid":
            observed_text += (
                " Stored route-wide native review is invalid and blocks CLI."
            )
        elif status == "missing" and self._links:
            observed_text += " Select and apply one native token for all spans."
        self._route_fiber_observation_var.set(observed_text)

    def _apply_route_native_fiber_type(self) -> bool:
        """Apply one operator-confirmed native token to every route path."""

        _log_route_event("Route-wide native fiber-type apply requested.")
        if not self._require_committed_editor():
            return False
        token = self._route_fiber_type_var.get().strip()
        if token not in FIBER_TYPES:
            messagebox.showwarning(
                "Native fiber type required",
                (
                    "Select one exact native RLS fiber token before applying "
                    "it to the route. Diagram labels are never alias-converted."
                ),
                parent=self,
            )
            _log_route_event(
                "Route-wide fiber apply refused: no supported native fiber type "
                "was selected.",
                logging.WARNING,
            )
            return False
        path_count = sum(len(link.paths) for link in self._links)
        if not path_count:
            messagebox.showwarning(
                "No optical spans",
                "Add or import the ordered route spans before applying a fiber type.",
                parent=self,
            )
            _log_route_event(
                "Route-wide fiber apply refused: route has no optical paths.",
                logging.WARNING,
            )
            return False

        from utils.rls_config.route_project import route_native_fiber_review

        status, prior_token = route_native_fiber_review(self._links)
        if status == "confirmed" and prior_token == token:
            self._refresh_status(
                f"Native fiber type {token} is already applied to every span."
            )
            _log_route_event(
                "Route-wide native fiber apply made no changes; the selected "
                "fiber type is already confirmed on every optical path."
            )
            return True
        payload_count = sum(bool(row.profile_payload) for row in self._rows)
        endpoint_review_count = sum(
            len(path.endpoint_reviews)
            for link in self._links
            for path in link.paths
        )
        if (
            payload_count or endpoint_review_count
        ) and not messagebox.askyesno(
            "Replace route fiber type",
            (
                "Changing the route-wide native fiber type clears every exact "
                "configuration payload and optical-path endpoint review. "
                "Continue?"
            ),
            parent=self,
        ):
            _log_route_event(
                "Route-wide native fiber change cancelled; reviewed "
                "configurations and endpoint paths were retained."
            )
            return False

        marker = {
            "value": token,
            "scope": "all_active_route_spans",
            "action": "operator_apply_route_native_fiber",
            "status": "confirmed",
            "deployable_cli": False,
        }
        reviewed_links: list[RouteLink] = []
        for link in self._links:
            reviewed_paths: list[OpticalPath] = []
            for path in link.paths:
                source_evidence = dict(path.source_evidence)
                source_evidence[_ROUTE_NATIVE_FIBER_REVIEW_KEY] = marker
                reviewed_paths.append(
                    replace(
                        path,
                        fiber_type=token,
                        review_state="pending",
                        source_evidence=source_evidence,
                        endpoint_reviews=(),
                    )
                )
            reviewed_links.append(
                replace(link, paths=tuple(reviewed_paths))
            )
        self._links = reviewed_links
        self._rows, cleared_payloads = _clear_provider_payloads(self._rows)
        self._committed_project_changed()
        self._sync_route_fiber_controls()
        self._refresh_tree()
        self._refresh_status(
            f"Applied native fiber type {token} to {path_count} route span"
            f"{'' if path_count == 1 else 's'}. Exact configuration and "
            "endpoint-path review remain required."
        )
        _log_route_event(
            "Applied one operator-confirmed native fiber type across all route "
            f"paths; paths={path_count}, cleared_payloads={cleared_payloads}, "
            f"cleared_endpoint_reviews={endpoint_review_count}. "
            "deployable_cli=false until exact reviews pass."
        )
        return True

    def _on_editor_edited(self, *_args: object) -> None:
        if self._loading_editor:
            return
        self._editor_dirty = True
        self._dirty = True
        self._invalidate_project_results()
        self._refresh_status("Shelf editor has uncommitted changes.")

    def _invalidate_project_results(self) -> None:
        """Invalidate every snapshot-derived result on the Tk thread."""

        self._job_generation += 1
        self._preview_fingerprint = ""
        self._preview_path = None
        self._config_labels.clear()
        tree = getattr(self, "_tree", None)
        if tree is not None:
            self._update_tree_readiness_cells()

    def _refresh_terminal_title_after_topology_change(self) -> bool:
        """Keep an imported terminal title aligned with the current A/Z order."""

        prior_marker = self._diagram_source.get("route_title_derivation")
        if (
            not isinstance(prior_marker, Mapping)
            or prior_marker.get("rule_id") != _TERMINAL_ROUTE_TITLE_RULE_ID
        ):
            return False
        source_sha256 = str(
            self._diagram_source.get("source_sha256", "") or ""
        ).strip()
        derived = _current_terminal_route_title(
            self._rows,
            prior_marker=prior_marker,
            source_sha256=source_sha256,
        )
        self._loading_project = True
        try:
            if derived is None:
                self._title_var.set("")
                self._diagram_source["route_title_derivation"] = {
                    "rule_id": _TERMINAL_ROUTE_TITLE_RULE_ID,
                    "status": "operator_review_required",
                    "value": "",
                    "source_sha256": source_sha256,
                    "deployable_cli": False,
                }
                return True
            title, marker = derived
            self._title_var.set(title)
            self._diagram_source["route_title_derivation"] = dict(marker)
            return True
        finally:
            self._loading_project = False

    def _committed_project_changed(self) -> None:
        self._dirty = True
        self._editor_dirty = False
        self._invalidate_project_results()
        self._schedule_config_evaluation()

    def _schedule_config_evaluation(self) -> None:
        if self._destroyed:
            return
        if self._config_after_id is not None:
            try:
                self.after_cancel(self._config_after_id)
            except tk.TclError:
                pass
        self._config_after_id = self.after(350, self._start_config_evaluation)

    def _start_config_evaluation(self) -> None:
        self._config_after_id = None
        if self._destroyed or self._foreground_job is not None:
            return
        try:
            project = self._build_project(require_valid=False)
            fingerprint = route_project_fingerprint(project)
        except (TypeError, ValueError):
            self._config_labels.clear()
            self._update_tree_readiness_cells()
            self._refresh_status(
                "Configuration assessment is waiting for complete route fields."
            )
            _log_route_event(
                "Configuration assessment deferred until route fields are complete.",
                logging.DEBUG,
            )
            return
        self._submit_background(
            "config",
            lambda: evaluate_route_configs(project),
            fingerprint=fingerprint,
        )

    def _submit_background(
        self,
        kind: str,
        work: Callable[[], Any],
        *,
        fingerprint: str = "",
        context: Any = None,
        foreground: bool = False,
    ) -> None:
        """Submit work without allowing a worker to touch Tk state."""

        if self._destroyed:
            return
        generation = self._job_generation
        if foreground:
            if self._foreground_job is not None:
                _log_route_event(
                    f"{kind} task refused because "
                    f"{self._foreground_job[0]} is still running.",
                    logging.WARNING,
                )
                messagebox.showwarning(
                    "Route task in progress",
                    "Wait for the current route task to finish.",
                    parent=self,
                )
                return
            self._foreground_job = (kind, generation)
            self._set_foreground_busy(True)
        _log_route_event(
            f"Submitted background {kind} task at route generation {generation}.",
            logging.INFO if foreground else logging.DEBUG,
        )
        try:
            self._executor.submit(
                _run_background_job,
                self._worker_results,
                kind=kind,
                generation=generation,
                fingerprint=fingerprint,
                work=work,
                context=context,
            )
        except RuntimeError as exc:
            if foreground:
                self._foreground_job = None
                self._set_foreground_busy(False)
            _log_route_event(
                f"Could not submit background {kind} task: "
                f"{friendly_error(exc)}",
                logging.ERROR,
            )
            messagebox.showerror(
                "Route task unavailable",
                friendly_error(exc, "The background task could not be started."),
                parent=self,
            )

    def _drain_worker_results(self) -> None:
        """Apply queued completions on the Tk event thread."""

        self._poll_after_id = None
        if self._destroyed:
            return
        while True:
            try:
                result = self._worker_results.get_nowait()
            except Empty:
                break
            self._handle_worker_result(result)
        if not self._destroyed:
            self._poll_after_id = self.after(100, self._drain_worker_results)

    def _handle_worker_result(self, result: _WorkerResult) -> None:
        foreground_match = self._foreground_job == (
            result.kind,
            result.generation,
        )
        if foreground_match:
            self._foreground_job = None
            self._set_foreground_busy(False)

        if not self._worker_result_is_current(result):
            self._discard_worker_context(result)
            self._refresh_status(
                f"Discarded stale {result.kind} result after route edits."
            )
            _log_route_event(
                f"Discarded stale {result.kind} result from generation "
                f"{result.generation}.",
                logging.WARNING,
            )
            return
        if result.error is not None:
            self._discard_worker_context(result)
            self._handle_worker_error(result.kind, result.error)
            return
        if result.kind == "diagram_import":
            self._apply_diagram_import(result.value)
        elif result.kind == "config":
            self._apply_config_evaluation(result.value)
        elif result.kind == "preview":
            self._complete_preview(result)
        elif result.kind == "bundle":
            self._complete_bundle(result.value)

    def _worker_result_is_current(self, result: _WorkerResult) -> bool:
        if result.generation != self._job_generation:
            return False
        if not result.fingerprint:
            return True
        try:
            current = route_project_fingerprint(
                self._build_project(require_valid=False)
            )
        except (TypeError, ValueError):
            return False
        return current == result.fingerprint

    @staticmethod
    def _discard_worker_context(result: _WorkerResult) -> None:
        if result.kind == "preview" and result.context is not None:
            try:
                result.context.cleanup()
            except Exception:
                LOGGER.debug("Could not remove stale MOP preview", exc_info=True)

    def _handle_worker_error(self, kind: str, error: Exception) -> None:
        _log_route_event(
            f"{kind} task failed: {friendly_error(error)}",
            logging.ERROR,
        )
        if kind == "config":
            self._config_labels.clear()
            self._update_tree_readiness_cells()
            self._refresh_status(
                "Configuration assessment failed; final bundle validation "
                "remains authoritative."
            )
            return
        title, fallback = {
            "diagram_import": (
                "Route diagram import failed",
                "The customer diagram could not be transcribed.",
            ),
            "preview": (
                "MOP preview failed",
                "The preview workbook could not be created.",
            ),
            "bundle": (
                "Route bundle export failed",
                "The route bundle could not be exported.",
            ),
        }.get(kind, ("Route task failed", "The route task could not be completed."))
        messagebox.showerror(
            title,
            friendly_error(error, fallback),
            parent=self,
        )

    def _set_foreground_busy(self, busy: bool) -> None:
        state = ["disabled"] if busy else ["!disabled"]

        def visit(widget: tk.Misc) -> None:
            for child in widget.winfo_children():
                if isinstance(
                    child,
                    (ttk.Button, ttk.Entry, ttk.Combobox, ttk.Treeview),
                ):
                    try:
                        child.state(state)
                    except tk.TclError:
                        pass
                visit(child)

        visit(self)
        self._refresh_status("Working…" if busy else "")

    def _on_destroy(self, event: tk.Event[tk.Misc]) -> None:
        if event.widget is not self or self._destroyed:
            return
        self._destroyed = True
        self._job_generation += 1
        for callback_id in (self._config_after_id, self._poll_after_id):
            if callback_id is not None:
                try:
                    self.after_cancel(callback_id)
                except tk.TclError:
                    pass
        self._executor.shutdown(wait=False, cancel_futures=True)
        review_window = self._config_review_window
        if review_window is not None:
            try:
                self._close_config_review(
                    review_window,
                    reason="route_destroy",
                )
            except tk.TclError:
                pass
        for preview_dir in self._preview_tempdirs:
            try:
                preview_dir.cleanup()
            except Exception:
                LOGGER.debug("Could not remove MOP preview directory", exc_info=True)
        self._preview_tempdirs.clear()

    def _on_profile_selected(self, _event: object = None) -> None:
        # Release is a fixed product boundary; provider/hardware selection
        # remains an explicit action in the per-shelf review.
        self._release_var.set(R40_UI_RELEASE)
        default_power = power_label_for_profile(self._selected_profile_id())
        if not default_power:
            return
        if (
            self._power_var.get().strip()
            and not getattr(
                self,
                "_editor_power_is_atlas_default",
                False,
            )
        ):
            return
        was_loading = self._loading_editor
        self._loading_editor = True
        try:
            self._power_var.set(default_power)
        finally:
            self._loading_editor = was_loading
        self._editor_power_is_atlas_default = True

    def _on_power_edited(self, *_args: object) -> None:
        """Mark a typed power value as an operator override."""

        if not self._loading_editor:
            self._editor_power_is_atlas_default = False

    def _selected_profile_id(self) -> str:
        label = self._profile_var.get().strip()
        return self._profile_id_by_label.get(label, label)

    def _read_editor_row(
        self,
        *,
        shelf_id: str = "",
        site_key: str = "",
        notes: str = "",
        site_address: str = "",
        network_site_id: str = "",
        profile_payload: Optional[Mapping[str, Any]] = None,
        review_state: str = "manual",
        source_evidence: Optional[Mapping[str, Any]] = None,
    ) -> _ShelfEditorRow:
        values = {
            "shelf type": self._selected_profile_id().strip(),
            "site code": self._site_code_var.get().strip(),
            "site name": self._site_name_var.get().strip(),
            "TID": self._tid_var.get().strip(),
            "primary OAM IP": self._ip_var.get().strip(),
            "software release": self._release_var.get().strip(),
            "shelf variant / PEC": self._variant_var.get().strip(),
            "power": self._power_var.get().strip(),
        }
        missing = [label for label, value in values.items() if not value]
        if missing:
            raise ValueError("Complete these shelf fields: " + ", ".join(missing) + ".")
        if values["shelf type"] not in _R40_UI_PROFILE_ID_SET:
            raise ValueError("Select an RLS R4.0 Add/Drop, ILA, or ROADM role.")
        if not _release_is_exact(values["software release"], 4, 0):
            raise ValueError(
                "Software release is fixed to exact 'RLS R4.0' in this "
                "Route Builder."
            )
        try:
            ipaddress.ip_address(values["primary OAM IP"])
        except ValueError as exc:
            raise ValueError("Primary OAM IP must be a valid IP address.") from exc

        reviewed_source_evidence = dict(source_evidence or {})
        default_power = power_label_for_profile(values["shelf type"])
        if (
            getattr(self, "_editor_power_is_atlas_default", False)
            and default_power
            and values["power"] == default_power
        ):
            reviewed_source_evidence[_POWER_LABEL_ROLE_DEFAULT_KEY] = (
                _power_label_role_default_marker(values["shelf type"])
            )
        else:
            reviewed_source_evidence.pop(
                _POWER_LABEL_ROLE_DEFAULT_KEY,
                None,
            )

        return _ShelfEditorRow(
            shelf_id=shelf_id or uuid4().hex,
            profile_id=values["shelf type"],
            site_key=site_key or _site_key_for(values["site code"]),
            site_code=values["site code"],
            site_name=values["site name"],
            tid=values["TID"],
            primary_oam_ip=values["primary OAM IP"],
            software_release=values["software release"],
            shelf_variant=values["shelf variant / PEC"],
            raman_label=self._raman_var.get().strip(),
            power_label=values["power"],
            site_address=site_address,
            network_site_id=network_site_id,
            notes=notes,
            profile_payload=dict(profile_payload or {}),
            review_state=review_state,
            source_evidence=reviewed_source_evidence,
        )

    def _add_shelf(self) -> None:
        try:
            row = self._read_editor_row()
        except ValueError as exc:
            _log_route_event(
                f"Add shelf refused: {friendly_error(exc)}",
                logging.WARNING,
            )
            messagebox.showwarning("Shelf details incomplete", str(exc), parent=self)
            return
        self._rows.append(row)
        self._rows, cleared_payloads = _clear_provider_payloads(self._rows)
        self._rows, invalidated_directions = (
            _invalidate_route_direction_evidence(
                self._rows,
                reason="shelf added to ordered route",
            )
        )
        self._rows, endpoint_role_changes = (
            _reconcile_route_endpoint_profiles(self._rows)
        )
        links_populated = bool(getattr(self, "_links_populated", False))
        self._links = _reconcile_route_links(
            self._rows,
            getattr(self, "_links", ()),
            populate_missing=links_populated,
        )
        title_refresh = getattr(
            self,
            "_refresh_terminal_title_after_topology_change",
            None,
        )
        if callable(title_refresh):
            title_rederived = bool(title_refresh())
        elif hasattr(self, "_diagram_source") and hasattr(self, "_title_var"):
            title_rederived = bool(
                RlsRouteFrame._refresh_terminal_title_after_topology_change(
                    self
                )
            )
        else:
            title_rederived = False
        self._committed_project_changed()
        self._sync_route_fiber_controls()
        self._refresh_tree(select_id=row.shelf_id)
        self._refresh_status(
            "Shelf added. Route order updated."
            + (
                f" Cleared {cleared_payloads} route-bound configuration(s); "
                "review affected shelves again."
                if cleared_payloads
                else ""
            )
            + (
                f" Recomputed {endpoint_role_changes} A/Z endpoint role(s)."
                if endpoint_role_changes
                else ""
            )
            + (
                f" Invalidated {invalidated_directions} source direction "
                "suggestion(s)."
                if invalidated_directions
                else ""
            )
        )
        _log_route_event(
            f"Added shelf {row.tid!r} at site {row.site_code!r} "
            f"with role {row.profile_id!r}; route now has {len(self._rows)} "
            f"shelf(s); cleared_payloads={cleared_payloads}; "
            f"endpoint_role_changes={endpoint_role_changes}; "
            f"invalidated_direction_suggestions={invalidated_directions}; "
            f"title_rederived={str(title_rederived).casefold()}."
        )

    def _selected_index(self) -> Optional[int]:
        selected = self._tree.selection()
        if not selected:
            return None
        selected_id = selected[0]
        return next(
            (
                index
                for index, row in enumerate(self._rows)
                if row.shelf_id == selected_id
            ),
            None,
        )

    def _update_selected(self) -> bool:
        index = self._selected_index()
        if index is None:
            _log_route_event(
                "Update shelf refused: no shelf selected.", logging.WARNING
            )
            messagebox.showwarning(
                "No shelf selected",
                "Select a shelf in the route table before updating it.",
                parent=self,
            )
            return False
        current = self._rows[index]
        edited_site_code = self._site_code_var.get().strip()
        site_key = (
            current.site_key
            if edited_site_code.casefold() == current.site_code.casefold()
            else ""
        )
        try:
            replacement = self._read_editor_row(
                shelf_id=current.shelf_id,
                site_key=site_key,
                site_address=current.site_address,
                network_site_id=current.network_site_id,
                notes=current.notes,
                profile_payload=current.profile_payload,
                review_state=current.review_state,
                source_evidence=current.source_evidence,
            )
        except ValueError as exc:
            _log_route_event(
                f"Update shelf refused: {friendly_error(exc)}",
                logging.WARNING,
            )
            messagebox.showwarning("Shelf details incomplete", str(exc), parent=self)
            return False
        reviewed_evidence, sra_compatibility_changed = (
            _review_raman_callout_evidence(
                replacement.source_evidence,
                replacement.raman_label,
            )
        )
        replacement = replace(
            replacement,
            source_evidence=reviewed_evidence,
        )
        provider_fact_corrections = tuple(
            field_name
            for field_name in ("profile_id", "shelf_variant")
            if str(getattr(current, field_name)).strip()
            != str(getattr(replacement, field_name)).strip()
        )
        if provider_fact_corrections:
            corrected_evidence = dict(replacement.source_evidence)
            corrected_evidence[_PROVIDER_PRESELECTION_INVALIDATION_KEY] = {
                "reason": "operator corrected provider-relevant shelf facts",
                "fields": provider_fact_corrections,
                "deployable_cli": False,
            }
            replacement = replace(
                replacement,
                source_evidence=corrected_evidence,
            )
        identity_changed = (
            provider_identity_changed(current, replacement)
            or sra_compatibility_changed
        )
        payload_cleared = identity_changed and bool(current.profile_payload)
        if identity_changed:
            replacement = replace(replacement, profile_payload={})
        nondefault_source_evidence = set(current.source_evidence) - {
            _POWER_LABEL_ROLE_DEFAULT_KEY
        }
        if nondefault_source_evidence or current.review_state in {
            "pending",
            "confirmed",
            "corrected",
        }:
            review_state = (
                "corrected"
                if current.review_state == "corrected"
                or imported_values_changed(current, replacement)
                else "confirmed"
            )
            replacement = replace(replacement, review_state=review_state)
        self._rows[index] = replacement
        cleared_payloads = 0
        endpoint_role_changes = 0
        if identity_changed:
            self._rows, cleared_payloads = _clear_provider_payloads(self._rows)
            self._rows, endpoint_role_changes = (
                _reconcile_route_endpoint_profiles(self._rows)
            )
            replacement = self._rows[index]
        title_refresh = getattr(
            self,
            "_refresh_terminal_title_after_topology_change",
            None,
        )
        if identity_changed and callable(title_refresh):
            title_rederived = bool(title_refresh())
        elif (
            identity_changed
            and hasattr(self, "_diagram_source")
            and hasattr(self, "_title_var")
        ):
            title_rederived = bool(
                RlsRouteFrame._refresh_terminal_title_after_topology_change(
                    self
                )
            )
        else:
            title_rederived = False
        total_cleared_payloads = cleared_payloads + int(payload_cleared)
        self._committed_project_changed()
        self._refresh_tree(select_id=replacement.shelf_id)
        if reviewed_evidence.get("raman_callouts"):
            _log_route_event(
                "Structured RAMAN slot/port review "
                f"{reviewed_evidence.get('raman_callout_review', 'pending')} "
                f"for shelf {replacement.tid!r}; deployable_cli=false."
            )
        if payload_cleared or cleared_payloads:
            self._refresh_status(
                "Selected shelf updated. A deployment payload was cleared "
                "because provider-relevant identity changed; all affected "
                "route shelves must revalidate their configuration review "
                "before bundle export."
                + (
                    f" Recomputed {endpoint_role_changes} A/Z endpoint role(s)."
                    if endpoint_role_changes
                    else ""
                )
            )
            _log_route_event(
                f"Updated shelf {replacement.tid!r}; provider identity or "
                "structured SRA compatibility changed and "
                f"{total_cleared_payloads} route-bound deployment payload(s) "
                "were cleared; "
                f"endpoint_role_changes={endpoint_role_changes}; "
                f"title_rederived={str(title_rederived).casefold()}.",
                logging.WARNING,
            )
        elif replacement.review_state == "corrected":
            self._refresh_status(
                "Imported shelf corrected and marked reviewed."
            )
            _log_route_event(
                f"Corrected imported shelf {replacement.tid!r} and marked it reviewed."
            )
        elif replacement.review_state == "confirmed":
            self._refresh_status(
                "Imported shelf confirmed and marked reviewed."
            )
            _log_route_event(
                f"Confirmed imported shelf {replacement.tid!r}."
            )
        else:
            self._refresh_status("Selected shelf updated.")
            _log_route_event(f"Updated shelf {replacement.tid!r}.")
        return True

    def _confirm_and_next_pending(self) -> None:
        """Commit one shelf review and advance without bulk-accepting facts."""

        current_index = self._selected_index()
        if current_index is None:
            self._update_selected()
            return
        payload_count_before = sum(
            bool(row.profile_payload) for row in self._rows
        )
        if not self._update_selected():
            return
        payloads_cleared = max(
            0,
            payload_count_before
            - sum(bool(row.profile_payload) for row in self._rows),
        )
        next_id = _next_pending_shelf_id(self._rows, current_index)
        pending_count = sum(
            row.review_state == "pending" for row in self._rows
        )
        if next_id:
            self._refresh_tree(select_id=next_id)
            self._on_tree_select()
            message = (
                f"Shelf review saved; {pending_count} imported shelf"
                f"{'' if pending_count == 1 else 's'} "
                f"{'remains' if pending_count == 1 else 'remain'} pending."
            )
            if payloads_cleared:
                message += (
                    f" Cleared {payloads_cleared} route-bound configuration"
                    f"{'' if payloads_cleared == 1 else 's'}."
                )
            self._refresh_status(message)
            _log_route_event(
                "Guided shelf review advanced to the next pending shelf; "
                f"pending_shelves={pending_count}, "
                f"cleared_payloads={payloads_cleared}."
            )
            return

        message = (
            "All imported shelf facts are reviewed. Continue with exact "
            "configuration and optical-path review."
        )
        if payloads_cleared:
            message += (
                f" Cleared {payloads_cleared} route-bound configuration"
                f"{'' if payloads_cleared == 1 else 's'}."
            )
        next_config_id = RlsRouteFrame._offer_next_exact_config_review(
            self,
            current_index,
            trigger="shelf_fact_review_complete",
            status_prefix=message,
        )
        _log_route_event(
            "Guided shelf fact review completed; pending_shelves=0, "
            f"cleared_payloads={payloads_cleared}; "
            f"next_review_shelf_id={next_config_id or 'none'}. Exact "
            "configuration and optical-path review remain required."
        )

    def _offer_next_exact_config_review(
        self,
        current_index: int,
        *,
        trigger: str,
        status_prefix: str = "",
        preferred_shelf_id: str = "",
    ) -> str:
        """Select and advertise the next review without opening a modal."""

        next_id = ""
        if preferred_shelf_id:
            from utils.rls_config.r4_0_generator import (
                provider_profiles_for_role,
            )

            preferred_row = next(
                (
                    row
                    for row in self._rows
                    if row.shelf_id == preferred_shelf_id
                ),
                None,
            )
            if (
                preferred_row is not None
                and _r40_payload_version_state(
                    preferred_row.profile_payload
                )
                != "current"
            ):
                preferred_providers = provider_profiles_for_role(
                    preferred_row.profile_id
                )
                if _has_accepted_structured_sra(
                    preferred_row.source_evidence
                ):
                    preferred_providers = tuple(
                        provider
                        for provider in preferred_providers
                        if provider.supports_raman
                    )
                if preferred_providers:
                    next_id = preferred_row.shelf_id
        if not next_id:
            next_id = _next_exact_config_review_shelf_id(
                self._rows,
                current_index,
            )
        completed, total = _exact_config_review_progress(self._rows)
        remaining = max(0, total - completed)
        next_row = next(
            (row for row in self._rows if row.shelf_id == next_id),
            None,
        )
        button = getattr(self, "_review_config_button", None)
        if next_row is not None:
            self._refresh_tree(select_id=next_row.shelf_id)
            self._on_tree_select()
            if button is not None:
                button.configure(text=f"Review Next: {next_row.tid}…")
            queue_message = (
                f"Next exact configuration review: {next_row.tid} "
                f"({completed}/{total} complete; {remaining} remaining). "
                "Use Review Next when ready."
            )
        elif remaining:
            if button is not None:
                button.configure(text="Review Configuration…")
            queue_message = (
                f"Exact configuration reviews: {completed}/{total} complete; "
                f"{remaining} remain, but no additional audited-provider "
                "review is currently available. Select a blocked shelf to "
                "inspect or correct its route facts."
            )
        else:
            if button is not None:
                button.configure(text="Review Configuration…")
            queue_message = (
                f"Exact configuration reviews complete ({completed}/{total})."
            )
        self._refresh_status(
            " ".join(
                part.strip()
                for part in (status_prefix, queue_message)
                if part.strip()
            )
        )
        _log_route_event(
            "Guided exact-configuration review offer updated; "
            f"trigger={trigger}, completed={completed}, total={total}, "
            f"remaining={remaining}, "
            f"next_shelf_id={next_id or 'none'}, "
            f"next_tid={next_row.tid if next_row is not None else 'none'}, "
            f"preferred_shelf_id={preferred_shelf_id or 'none'}, "
            "modal_opened=false."
        )
        return next_id

    def _finish_applied_config_review(
        self,
        window: tk.Toplevel,
        current_index: int,
        *,
        provider_id: str,
        reviewed_tid: str,
        pending_peer_ids: Sequence[str] = (),
        validated_peer_ids: Sequence[str] = (),
        restaged_peer_ids: Sequence[str] = (),
    ) -> None:
        """Close an applied review, then offer the next shelf."""

        self._close_config_review(window, reason="applied")
        preferred_peer_id = (
            str(pending_peer_ids[0]) if pending_peer_ids else ""
        )
        if pending_peer_ids:
            status_prefix = (
                "Staged the locally validated SRA endpoint; paired SRA peer "
                "review is pending. Deployable CLI and route-bundle export "
                "remain blocked."
            )
            trigger = "configuration_staged_pending_sra_peer"
            sra_pair_state = "pending_peer"
            log_action = "Staged non-deployable exact R4.0 provider"
        elif validated_peer_ids:
            status_prefix = (
                "Applied and reciprocally validated the paired SRA endpoints "
                "against one route snapshot."
            )
            trigger = "paired_sra_configuration_validated"
            sra_pair_state = "validated_complete"
            log_action = "Applied reciprocally validated exact R4.0 provider"
        else:
            status_prefix = (
                "Applied validated exact R4.0 configuration and "
                "endpoint-path review."
            )
            trigger = "configuration_applied"
            sra_pair_state = "not_applicable"
            log_action = "Applied exact R4.0 provider"
        next_id = RlsRouteFrame._offer_next_exact_config_review(
            self,
            current_index,
            trigger=trigger,
            status_prefix=status_prefix,
            preferred_shelf_id=preferred_peer_id,
        )
        next_row = next(
            (row for row in self._rows if row.shelf_id == next_id),
            None,
        )
        _log_route_event(
            f"{log_action} {provider_id!r} for "
            f"{reviewed_tid!r}; preserved other reviewed shelf payloads; "
            f"review_window_closed=true, "
            f"next_review_shelf_id={next_id or 'none'}, "
            f"next_review_tid="
            f"{next_row.tid if next_row is not None else 'none'}, "
            f"sra_pair_state={sra_pair_state}, "
            "pending_peer_ids="
            f"{','.join(str(item) for item in pending_peer_ids) or 'none'}, "
            "validated_peer_ids="
            f"{','.join(str(item) for item in validated_peer_ids) or 'none'}, "
            "restaged_peer_ids="
            f"{','.join(str(item) for item in restaged_peer_ids) or 'none'}, "
            "next_review_modal_opened=false."
        )

    def _close_config_review(
        self,
        window: tk.Toplevel,
        *,
        reason: str = "operator",
    ) -> None:
        was_open = (
            getattr(self, "_config_review_window", None) is window
        )
        if window.winfo_exists():
            try:
                window.grab_release()
            except tk.TclError:
                pass
            window.destroy()
        if getattr(self, "_config_review_window", None) is window:
            self._config_review_window = None
        if was_open:
            _log_route_event(
                "Closed selected-shelf configuration review; "
                f"reason={reason}, queue_advanced=false."
            )

    def _review_selected_configuration(self) -> None:
        """Open the release-scoped review for the selected route shelf."""

        _log_route_event("Selected-shelf configuration review requested.")
        if not self._require_committed_editor():
            return
        index = self._selected_index()
        if index is None:
            messagebox.showwarning(
                "No shelf selected",
                "Select a shelf in the ordered route before reviewing it.",
                parent=self,
            )
            _log_route_event(
                "Configuration review refused: no shelf selected.",
                logging.WARNING,
            )
            return
        pending_rows = [
            row for row in self._rows if row.review_state == "pending"
        ]
        if pending_rows:
            first_pending = pending_rows[0]
            self._refresh_tree(select_id=first_pending.shelf_id)
            self._on_tree_select()
            messagebox.showwarning(
                "Shelf fact review required",
                (
                    "Review and confirm every imported shelf before opening "
                    "an exact configuration review. "
                    f"{len(pending_rows)} shelf"
                    f"{'' if len(pending_rows) == 1 else 's'} "
                    f"{'remains' if len(pending_rows) == 1 else 'remain'} "
                    "pending. "
                    "Use Confirm & Next Pending to continue."
                ),
                parent=self,
            )
            _log_route_event(
                "Configuration review refused until imported shelf facts are "
                f"reviewed; pending_shelves={len(pending_rows)}.",
                logging.WARNING,
            )
            return
        unresolved_raman_rows = [
            row
            for row in self._rows
            if _raman_callout_review_status(row.source_evidence)
            in {"pending", "invalid"}
        ]
        if unresolved_raman_rows:
            first_unresolved = unresolved_raman_rows[0]
            self._refresh_tree(select_id=first_unresolved.shelf_id)
            self._on_tree_select()
            messagebox.showwarning(
                "RAMAN callout review required",
                (
                    "Every structured RAMAN/SRA callout must be explicitly "
                    "accepted or rejected before exact configuration review. "
                    f"{len(unresolved_raman_rows)} shelf"
                    f"{'' if len(unresolved_raman_rows) == 1 else 's'} "
                    f"{'still requires' if len(unresolved_raman_rows) == 1 else 'still require'} "
                    "a valid callout disposition."
                ),
                parent=self,
            )
            _log_route_event(
                "Configuration review refused until structured RAMAN/SRA "
                "callouts are resolved; "
                f"unresolved_shelves={len(unresolved_raman_rows)}.",
                logging.WARNING,
            )
            return
        from utils.rls_config.route_project import route_native_fiber_review

        fiber_review_status, _fiber_token = route_native_fiber_review(
            self._links
        )
        if fiber_review_status in {"missing", "invalid"}:
            messagebox.showwarning(
                "Route fiber type review required",
                (
                    "Select one exact native CLI fiber type and use Apply to "
                    "all spans before opening configuration review. The "
                    "diagram fiber label remains separate and is never "
                    "automatically converted to a native token."
                ),
                parent=self,
            )
            _log_route_event(
                "Configuration review refused until one route-wide native "
                f"fiber choice is confirmed; fiber_review={fiber_review_status}.",
                logging.WARNING,
            )
            return
        try:
            project = self._build_project(require_valid=False)
            fingerprint = route_project_fingerprint(project)
        except (TypeError, ValueError) as exc:
            messagebox.showwarning(
                "Route not ready for review",
                str(exc),
                parent=self,
            )
            _log_route_event(
                f"Configuration review refused: {friendly_error(exc)}",
                logging.WARNING,
            )
            return
        row = self._rows[index]
        unsupported = _r40_only_rows_error((row,))
        if unsupported:
            messagebox.showwarning(
                "RLS R4.0 configuration review unavailable",
                unsupported,
                parent=self,
            )
            _log_route_event(
                f"Configuration review refused for {row.tid!r}: {unsupported}",
                logging.WARNING,
            )
            return
        self._open_r4_0_review(row, project, fingerprint)

    def _new_review_window(self, title: str) -> tk.Toplevel:
        prior = self._config_review_window
        if prior is not None:
            try:
                self._close_config_review(prior, reason="replaced")
            except tk.TclError:
                self._config_review_window = None
        window = tk.Toplevel(self)
        self._config_review_window = window
        window.title(title)
        window.geometry("1180x780")
        window.minsize(900, 620)
        window.transient(self.winfo_toplevel())
        window.protocol(
            "WM_DELETE_WINDOW",
            lambda current=window: self._close_config_review(current),
        )
        return window

    def _review_snapshot_is_current(
        self,
        fingerprint: str,
        shelf_id: str,
    ) -> int:
        current = self._build_project(require_valid=False)
        if route_project_fingerprint(current) != fingerprint:
            raise ValueError(
                "The route changed while this review was open. Close it and "
                "review the selected shelf again from the current route."
            )
        index = next(
            (
                item_index
                for item_index, item in enumerate(self._rows)
                if item.shelf_id == shelf_id
            ),
            None,
        )
        if index is None:
            raise ValueError("The reviewed shelf is no longer in the route.")
        return index

    def _open_r4_0_review(
        self,
        row: _ShelfEditorRow,
        project: RouteProject,
        fingerprint: str,
    ) -> None:
        if not _release_is_exact(row.software_release, 4, 0):
            messagebox.showwarning(
                "R4.0 configuration review unavailable",
                (
                    "This review requires exact software release 'RLS R4.0'. "
                    "Update and save the selected shelf first."
                ),
                parent=self,
            )
            _log_route_event(
                f"R4.0 review refused for {row.tid!r}: exact release missing.",
                logging.WARNING,
            )
            return

        from gui.rls_r4_0_config_frame import RlsR40ConfigFrame
        from utils.rls_config.r4_0_generator import (
            R40_PAYLOAD_SCHEMA_VERSION,
            decode_r40_exact_payload,
            encode_r40_exact_payload,
            provider_profiles_for_role,
        )

        providers = provider_profiles_for_role(row.profile_id)
        if _has_accepted_structured_sra(row.source_evidence):
            providers = tuple(
                provider
                for provider in providers
                if provider.supports_raman
            )
            if not providers:
                messagebox.showwarning(
                    "SRA-capable R4.0 provider required",
                    (
                        "The selected shelf has reviewed RAMAN/SRA slot-port "
                        "evidence, but no registered role-compatible exact "
                        "R4.0 provider matches that SRA slot and fixed port "
                        "map. ATLAS will not open a no-SRA configuration "
                        "review or infer RAMAN commands."
                    ),
                    parent=self,
                )
                _log_route_event(
                    f"R4.0 exact review refused for {row.tid!r}: reviewed "
                    "structured SRA evidence has no compatible audited "
                    "provider.",
                    logging.WARNING,
                )
                return
        if not providers:
            messagebox.showwarning(
                "R4.0 configuration review unavailable",
                (
                    "No exact audited R4.0 provider is registered for this "
                    "route role. Choose only a role supported by an exact "
                    "hardware/topology provider."
                ),
                parent=self,
            )
            _log_route_event(
                f"R4.0 exact review refused for {row.tid!r}: no compatible "
                f"provider for role {row.profile_id!r}.",
                logging.WARNING,
            )
            return

        request = None
        if row.profile_payload:
            try:
                request = decode_r40_exact_payload(row.profile_payload)
            except (TypeError, ValueError) as exc:
                if (
                    row.profile_payload.get("schema_id")
                    == "ciena.rls.r4-0-exact-request"
                    and row.profile_payload.get("schema_version")
                    != R40_PAYLOAD_SCHEMA_VERSION
                ):
                    messagebox.showwarning(
                        "Stored R4.0 review requires re-review",
                        (
                            "This shelf's exact configuration was saved with "
                            "a retired payload schema. ATLAS corrected the "
                            "bidirectional RLA terminology and DLE ILA "
                            "upstream/downstream neighbor mapping, so the old "
                            "request cannot be regenerated silently.\n\n"
                            "The review will open from current diagram and "
                            "route facts. Validate and apply it to replace the "
                            "old payload with the current audited schema "
                            f"{R40_PAYLOAD_SCHEMA_VERSION}."
                        ),
                        parent=self,
                    )
                    _log_route_event(
                        f"Stored exact R4.0 payload for {row.tid!r} uses "
                        "retired schema "
                        f"{row.profile_payload.get('schema_version')!r}; "
                        f"opened current schema {R40_PAYLOAD_SCHEMA_VERSION} "
                        "for deliberate re-review; old payload retained until "
                        "apply.",
                        logging.WARNING,
                    )
                    request = None
                else:
                    messagebox.showwarning(
                        "Stored R4.0 configuration is invalid",
                        (
                            f"{friendly_error(exc)}\n\n"
                            "ATLAS will not discard or infer replacements for "
                            "an invalid exact-provider payload. Correct the "
                            "saved route project data or remove and "
                            "deliberately review this shelf again."
                        ),
                        parent=self,
                    )
                    _log_route_event(
                        f"R4.0 exact review refused for {row.tid!r}: stored "
                        "payload failed strict decoding: "
                        f"{friendly_error(exc)}",
                        logging.ERROR,
                    )
                    return

        try:
            route_seed = _r4_0_editor_seed(project, row.shelf_id)
        except (TypeError, ValueError) as exc:
            messagebox.showwarning(
                "R4.0 configuration review unavailable",
                friendly_error(exc),
                parent=self,
            )
            _log_route_event(
                f"R4.0 exact review refused for {row.tid!r}: "
                f"{friendly_error(exc)}",
                logging.WARNING,
            )
            return

        raw_provider_resolution = route_seed.get("provider_resolution", {})
        provider_resolution = (
            raw_provider_resolution
            if isinstance(raw_provider_resolution, Mapping)
            else {}
        )
        raw_review_provider_ids = provider_resolution.get(
            "review_provider_ids"
        )
        review_provider_ids = (
            {
                provider_id
                for provider_id in raw_review_provider_ids
                if isinstance(provider_id, str) and provider_id
            }
            if isinstance(raw_review_provider_ids, (list, tuple))
            else {provider.provider_id for provider in providers}
        )
        if request is not None and request.provider_id not in review_provider_ids:
            messagebox.showwarning(
                "Stored R4.0 provider no longer matches route scope",
                (
                    "The stored exact-provider request conflicts with the "
                    "current reviewed diagram/route constraints and will not "
                    "be loaded into this review. ATLAS is preserving the saved "
                    "payload until a compatible review is deliberately "
                    "applied or the route data is corrected.\n\n"
                    "Provider validation and CLI export remain blocked."
                ),
                parent=self,
            )
            _log_route_event(
                f"Stored exact R4.0 payload for {row.tid!r} was not loaded; "
                f"provider_id={request.provider_id!r}, "
                "reason_code=R40_STORED_PROVIDER_ROUTE_SCOPE_MISMATCH.",
                logging.WARNING,
            )
            request = None
        if not review_provider_ids:
            reason_codes = provider_resolution.get("reason_codes", ())
            reason_text = (
                ", ".join(
                    item
                    for item in reason_codes
                    if isinstance(item, str)
                )
                if isinstance(reason_codes, (list, tuple))
                else ""
            )
            messagebox.showwarning(
                "No compatible audited R4.0 provider",
                (
                    "No registered exact provider matches the reviewed shelf "
                    "and route scope. ATLAS will open the planning review so "
                    "you can inspect the diagram-derived identity and optical "
                    "path facts, but provider validation, Apply, and CLI "
                    "generation remain blocked.\n\n"
                    + (
                        "For this terminal, one physical bidirectional route "
                        "degree is not a missing return direction; A→Z and Z→A "
                        "share its mux/demux pair. ATLAS will not substitute "
                        "an exact provider whose audited band, SRA state, "
                        "degree cardinality, or fixed hardware conflicts with "
                        "the imported shelf facts."
                        if row.profile_id != "ila"
                        else (
                            "ATLAS will not substitute a role-compatible "
                            "provider whose audited band or installed hardware "
                            "scope conflicts with the imported ILA facts."
                        )
                    )
                    + (
                        f"\n\nReason codes: {reason_text}"
                        if reason_text
                        else ""
                    )
                ),
                parent=self,
            )
            _log_route_event(
                f"R4.0 planning review for {row.tid!r} has no route-compatible "
                "audited provider; reason_codes="
                f"{reason_text or 'none'}; exact CLI remains blocked.",
                logging.WARNING,
            )

        assumptions_text = ""
        try:
            from utils.rls_config.r4_0_review import build_r4_0_review

            assumptions_text = build_r4_0_review(
                row.profile_id,
                _r4_0_assumption_facts(project, row.shelf_id),
            ).report_text
        except (TypeError, ValueError) as exc:
            # Exact-provider review remains available even when the older
            # role-only narrative cannot resolve an endpoint side.
            _log_route_event(
                f"Role-only R4.0 assumptions summary unavailable for "
                f"{row.tid!r}; exact editor opened without it; "
                f"reason_code={type(exc).__name__}.",
                logging.WARNING,
            )

        window = self._new_review_window(
            f"Review Exact RLS R4.0 Configuration — {row.tid}"
        )

        def apply_reviewed(request_value: Any, _artifact: Any) -> None:
            current_index = self._review_snapshot_is_current(
                fingerprint,
                row.shelf_id,
            )
            payload = encode_r40_exact_payload(request_value)
            current = self._rows[current_index]
            current_rows = list(self._rows)
            current_rows[current_index] = replace(
                current,
                profile_payload=payload,
                review_state=(
                    "corrected"
                    if current.review_state == "corrected"
                    else "confirmed"
                ),
            )
            previous_request = None
            if current.profile_payload:
                try:
                    previous_request = decode_r40_exact_payload(
                        current.profile_payload
                    )
                except (TypeError, ValueError):
                    previous_request = None
            current_rows, restaged_peer_ids = (
                _restage_changed_r40_sra_peers(
                    current_rows,
                    project,
                    row.shelf_id,
                    previous_request,
                    request_value,
                )
            )
            reviewed_links = _apply_r40_reviewed_lines_to_links(
                current_rows,
                self._links,
                row.shelf_id,
                request_value,
            )
            candidate_project = build_route_project(
                route_code=self._route_code_var.get(),
                title=self._title_var.get(),
                revision=self._revision_var.get(),
                rows=current_rows,
                project_id=self._project_id,
                notes=self._project_notes,
                ospf_area=self._ospf_area_var.get(),
                customer_policy=self._customer_policy(),
                links=reviewed_links,
                diagram_source=self._diagram_source,
                require_valid=False,
            )
            candidate_shelf = next(
                shelf
                for shelf in candidate_project.shelves
                if shelf.shelf_id == row.shelf_id
            )
            current_provider_resolution, _direction_resolution = (
                _r4_0_provider_prepopulation(
                    candidate_project,
                    candidate_shelf,
                )
            )
            current_raw_review_ids = current_provider_resolution.get(
                "review_provider_ids"
            )
            current_review_ids = (
                {
                    provider_id
                    for provider_id in current_raw_review_ids
                    if isinstance(provider_id, str) and provider_id
                }
                if isinstance(current_raw_review_ids, (list, tuple))
                else {
                    provider.provider_id
                    for provider in provider_profiles_for_role(
                        candidate_shelf.profile_id
                    )
                }
            )
            if request_value.provider_id not in current_review_ids:
                reason_codes = current_provider_resolution.get(
                    "reason_codes",
                    (),
                )
                reason_text = (
                    ", ".join(
                        item
                        for item in reason_codes
                        if isinstance(item, str)
                    )
                    if isinstance(reason_codes, (list, tuple))
                    else ""
                )
                _log_route_event(
                    f"Rejected exact R4.0 apply for {row.tid!r}; provider_id="
                    f"{request_value.provider_id!r} is outside current "
                    "project-aware provider options; reason_codes="
                    f"{reason_text or 'none'}.",
                    logging.WARNING,
                )
                raise ValueError(
                    "The selected exact provider is incompatible with the "
                    "current reviewed shelf/route scope. Reopen the review "
                    "after correcting the diagram facts or importing verified "
                    "installed inventory."
                )
            try:
                pair_review = _validate_r40_candidate_pair_review(
                    candidate_project,
                    candidate_shelf.shelf_id,
                )
            except ValueError as exc:
                _log_route_event(
                    f"Rejected exact R4.0 apply for {row.tid!r}; "
                    "reason_code=R40_COMPLETE_CANDIDATE_READINESS_FAILED, "
                    f"error_type={type(exc).__name__}, "
                    "route_mutated=false.",
                    logging.WARNING,
                )
                raise
            pending_peer_ids = pair_review.pending_peer_ids
            validated_peer_ids = pair_review.validated_peer_ids
            self._rows = current_rows
            self._links = reviewed_links
            self._links_populated = True
            self._committed_project_changed()
            window.after_idle(
                lambda current_window=window: (
                    RlsRouteFrame._finish_applied_config_review(
                        self,
                        current_window,
                        current_index,
                        provider_id=request_value.provider_id,
                        reviewed_tid=row.tid,
                        pending_peer_ids=pending_peer_ids,
                        validated_peer_ids=validated_peer_ids,
                        restaged_peer_ids=restaged_peer_ids,
                    )
                )
            )

        editor = RlsR40ConfigFrame(
            window,
            self.controller,
            role_profile=row.profile_id,
            route_seed=route_seed,
            initial_request=request,
            assumptions_text=assumptions_text,
            on_apply=apply_reviewed,
        )
        editor.pack(fill=tk.BOTH, expand=True)

        def request_close() -> None:
            if editor.has_unapplied_changes() and not messagebox.askyesno(
                "Discard R4.0 review edits?",
                "This shelf has unapplied configuration-review changes. "
                "Discard them and close the review?",
                parent=window,
            ):
                _log_route_event(
                    f"Kept exact R4.0 review open for {row.tid!r}; "
                    "discard was cancelled."
                )
                return
            self._close_config_review(window, reason="operator")

        window.protocol("WM_DELETE_WINDOW", request_close)
        window.grab_set()
        window.focus_set()
        prepopulation = route_seed.get("prepopulation", {})
        route_seed_count = 0
        derivation_count = 0
        default_count = 0
        exclusion_count = 0
        manual_count = 0
        prepopulated_keys: tuple[str, ...] = ()
        derivation_keys: tuple[str, ...] = ()
        default_keys: tuple[str, ...] = ()
        exclusion_keys: tuple[str, ...] = ()
        manual_keys: tuple[str, ...] = ()
        if isinstance(prepopulation, Mapping):
            for key, target in (
                ("route_reviewed_fields", "route"),
                ("controlled_derivations", "derivation"),
                ("controlled_defaults", "default"),
                ("policy_exclusions", "exclusion"),
                ("manual_fields", "manual"),
            ):
                raw_items = prepopulation.get(key, ())
                count = (
                    len(raw_items)
                    if isinstance(raw_items, (list, tuple))
                    else 0
                )
                if target == "route":
                    route_seed_count = count
                    prepopulated_keys = (
                        tuple(
                            item
                            for item in raw_items
                            if isinstance(item, str)
                            and re.fullmatch(
                                r"[A-Za-z0-9_.-]{1,96}",
                                item,
                            )
                        )
                        if isinstance(raw_items, (list, tuple))
                        else ()
                    )
                elif target == "derivation":
                    derivation_count = count
                    derivation_keys = (
                        tuple(
                            item
                            for item in raw_items
                            if isinstance(item, str)
                            and re.fullmatch(
                                r"[A-Za-z0-9_.-]{1,96}",
                                item,
                            )
                        )
                        if isinstance(raw_items, (list, tuple))
                        else ()
                    )
                elif target == "default":
                    default_count = count
                    default_keys = (
                        tuple(
                            item
                            for item in raw_items
                            if isinstance(item, str)
                            and re.fullmatch(
                                r"[A-Za-z0-9_.-]{1,96}",
                                item,
                            )
                        )
                        if isinstance(raw_items, (list, tuple))
                        else ()
                    )
                elif target == "exclusion":
                    exclusion_count = count
                    exclusion_keys = (
                        tuple(
                            item
                            for item in raw_items
                            if isinstance(item, str)
                            and re.fullmatch(
                                r"[A-Za-z0-9_.-]{1,96}",
                                item,
                            )
                        )
                        if isinstance(raw_items, (list, tuple))
                        else ()
                    )
                else:
                    manual_count = count
                    manual_keys = (
                        tuple(
                            item
                            for item in raw_items
                            if isinstance(item, str)
                            and re.fullmatch(
                                r"[A-Za-z0-9_.-]{1,96}",
                                item,
                            )
                        )
                        if isinstance(raw_items, (list, tuple))
                        else ()
                    )
        provider_preselected = (
            isinstance(provider_resolution, Mapping)
            and provider_resolution.get("preselect_allowed") is True
        )
        resolved_provider_id = str(
            provider_resolution.get("provider_id", "") or ""
        ).strip()
        resolution_status = str(
            provider_resolution.get("status", "") or ""
        ).strip()
        sole_route_candidate_populated = bool(
            resolution_status in {"exact_match", "unique_candidate"}
            and resolved_provider_id
            and review_provider_ids == {resolved_provider_id}
        )
        if request is not None:
            provider_selection_state = "loaded from stored payload"
        elif provider_preselected:
            provider_selection_state = "advisory diagram candidate preselected"
        elif sole_route_candidate_populated:
            provider_selection_state = (
                "sole route-compatible candidate populated"
            )
        else:
            provider_selection_state = "required"
        raw_direction_resolution = route_seed.get("direction_resolution", {})
        direction_resolution = (
            raw_direction_resolution
            if isinstance(raw_direction_resolution, Mapping)
            else {}
        )
        direction_source = {
            "exact_match": "direct_port",
            "controlled_fallback": "audited_provider_role_fallback",
        }.get(
            str(direction_resolution.get("status", "") or ""),
            "operator_required",
        )

        _log_route_event(
            f"Opened integrated exact R4.0 configuration review for "
            f"{row.tid!r}; provider selection "
            f"{provider_selection_state}; "
            "provider_resolution_status="
            f"{str(provider_resolution.get('status', '') or '') or 'unknown'}; "
            "provider_resolution_reason_codes="
            f"{','.join(str(item) for item in provider_resolution.get('reason_codes', ()) if isinstance(item, str)) or 'none'}; "
            "review_provider_ids="
            f"{','.join(sorted(review_provider_ids)) or 'none'}; "
            "provider_band_scope="
            f"{str(provider_resolution.get('band_scope', '') or '') or 'none'}; "
            "provider_band_scope_source="
            f"{str(provider_resolution.get('band_scope_source', '') or '') or 'none'}; "
            "represented_route_degrees="
            f"{provider_resolution.get('represented_route_degree_count', 'unknown')}; "
            "candidate_provider_degrees="
            f"{provider_resolution.get('candidate_provider_degree_count', 'unknown')}; "
            "fixed_direction="
            f"{str(route_seed.get('line_1_route_side', '') or '') or 'operator_required'}; "
            f"fixed_direction_source={direction_source}; "
            f"prepopulated_route_fields={route_seed_count}, "
            f"controlled_derivations={derivation_count}, "
            f"controlled_defaults={default_count}, "
            f"policy_exclusions={exclusion_count}, "
            f"manual_review_groups={manual_count}, "
            "prepopulated_field_keys="
            f"{','.join(prepopulated_keys) or 'none'}, "
            f"controlled_derivation_keys={','.join(derivation_keys) or 'none'}, "
            f"controlled_default_keys={','.join(default_keys) or 'none'}, "
            f"policy_exclusion_keys={','.join(exclusion_keys) or 'none'}, "
            f"manual_review_keys={','.join(manual_keys) or 'none'}, "
            f"assumptions_summary={'available' if assumptions_text else 'unavailable'}."
        )

    def _remove_selected(self) -> None:
        if not self._require_committed_editor():
            return
        index = self._selected_index()
        if index is None:
            _log_route_event(
                "Remove shelf refused: no shelf selected.", logging.WARNING
            )
            messagebox.showwarning(
                "No shelf selected",
                "Select a shelf in the route table before removing it.",
                parent=self,
            )
            return
        row = self._rows[index]
        if not messagebox.askyesno(
            "Remove shelf",
            f"Remove {row.tid} from this route project?",
            parent=self,
        ):
            _log_route_event(
                f"Remove shelf cancelled for {row.tid!r}."
            )
            return
        del self._rows[index]
        self._rows, cleared_payloads = _clear_provider_payloads(self._rows)
        self._rows, invalidated_directions = (
            _invalidate_route_direction_evidence(
                self._rows,
                reason="shelf removed from ordered route",
            )
        )
        self._rows, endpoint_role_changes = (
            _reconcile_route_endpoint_profiles(self._rows)
        )
        self._links = _reconcile_route_links(
            self._rows,
            getattr(self, "_links", ()),
            populate_missing=bool(
                getattr(self, "_links_populated", False)
            ),
        )
        title_refresh = getattr(
            self,
            "_refresh_terminal_title_after_topology_change",
            None,
        )
        if callable(title_refresh):
            title_rederived = bool(title_refresh())
        elif hasattr(self, "_diagram_source") and hasattr(self, "_title_var"):
            title_rederived = bool(
                RlsRouteFrame._refresh_terminal_title_after_topology_change(
                    self
                )
            )
        else:
            title_rederived = False
        self._committed_project_changed()
        self._sync_route_fiber_controls()
        self._clear_editor()
        self._refresh_tree()
        self._refresh_status(
            "Shelf removed. Route order updated."
            + (
                f" Cleared {cleared_payloads} route-bound configuration(s)."
                if cleared_payloads
                else ""
            )
            + (
                f" Recomputed {endpoint_role_changes} A/Z endpoint role(s)."
                if endpoint_role_changes
                else ""
            )
            + (
                f" Invalidated {invalidated_directions} source direction "
                "suggestion(s)."
                if invalidated_directions
                else ""
            )
        )
        _log_route_event(
            f"Removed shelf {row.tid!r}; route now has {len(self._rows)} "
            f"shelf(s); cleared_payloads={cleared_payloads}; "
            f"endpoint_role_changes={endpoint_role_changes}; "
            f"invalidated_direction_suggestions={invalidated_directions}; "
            f"title_rederived={str(title_rederived).casefold()}."
        )

    def _move_selected(self, offset: int) -> None:
        if not self._require_committed_editor():
            return
        index = self._selected_index()
        if index is None:
            _log_route_event(
                "Reorder refused: no shelf selected.", logging.WARNING
            )
            messagebox.showwarning(
                "No shelf selected",
                "Select a shelf before changing route order.",
                parent=self,
            )
            return
        destination = index + offset
        if destination < 0 or destination >= len(self._rows):
            _log_route_event(
                "Reorder ignored: selected shelf is already at the route boundary.",
                logging.DEBUG,
            )
            return
        row = self._rows.pop(index)
        self._rows.insert(destination, row)
        self._rows, cleared_payloads = _clear_provider_payloads(self._rows)
        self._rows, invalidated_directions = (
            _invalidate_route_direction_evidence(
                self._rows,
                reason="shelf order changed",
            )
        )
        self._rows, endpoint_role_changes = (
            _reconcile_route_endpoint_profiles(self._rows)
        )
        self._links = _reconcile_route_links(
            self._rows,
            getattr(self, "_links", ()),
            populate_missing=bool(
                getattr(self, "_links_populated", False)
            ),
        )
        title_refresh = getattr(
            self,
            "_refresh_terminal_title_after_topology_change",
            None,
        )
        if callable(title_refresh):
            title_rederived = bool(title_refresh())
        elif hasattr(self, "_diagram_source") and hasattr(self, "_title_var"):
            title_rederived = bool(
                RlsRouteFrame._refresh_terminal_title_after_topology_change(
                    self
                )
            )
        else:
            title_rederived = False
        self._committed_project_changed()
        self._sync_route_fiber_controls()
        self._refresh_tree(select_id=row.shelf_id)
        self._refresh_status(
            "Route order updated."
            + (
                f" Cleared {cleared_payloads} route-bound configuration(s); "
                "review affected shelves again."
                if cleared_payloads
                else ""
            )
            + (
                f" Recomputed {endpoint_role_changes} A/Z endpoint role(s)."
                if endpoint_role_changes
                else ""
            )
            + (
                f" Invalidated {invalidated_directions} source direction "
                "suggestion(s)."
                if invalidated_directions
                else ""
            )
        )
        _log_route_event(
            f"Moved shelf {row.tid!r} from position {index + 1} "
            f"to {destination + 1}; cleared_payloads={cleared_payloads}; "
            f"endpoint_role_changes={endpoint_role_changes}; "
            f"invalidated_direction_suggestions={invalidated_directions}; "
            f"title_rederived={str(title_rederived).casefold()}."
        )

    def _on_tree_select(self, _event: object = None) -> None:
        if getattr(self, "_restoring_tree_selection", False):
            return
        index = self._selected_index()
        if index is None:
            return
        row = self._rows[index]
        loaded_shelf_id = getattr(self, "_editor_shelf_id", "")
        if self._editor_dirty:
            if row.shelf_id == loaded_shelf_id:
                return
            self._restoring_tree_selection = True
            try:
                if loaded_shelf_id and self._tree.exists(loaded_shelf_id):
                    self._tree.selection_set(loaded_shelf_id)
                    self._tree.focus(loaded_shelf_id)
                    self._tree.see(loaded_shelf_id)
                else:
                    for item in self._tree.selection():
                        self._tree.selection_remove(item)
            finally:
                self._restoring_tree_selection = False
            action = (
                "Update Selected or Confirm & Next Pending"
                if loaded_shelf_id
                else "Add Shelf"
            )
            _log_route_event(
                "Shelf selection change refused because the editor has "
                f"uncommitted changes; operator must use {action}.",
                logging.WARNING,
            )
            messagebox.showwarning(
                "Shelf edits not applied",
                (
                    f"Use {action} or Clear Editor before selecting another "
                    "shelf. The visible editor values were preserved."
                ),
                parent=self,
            )
            return
        self._load_editor_row(row)
        button = getattr(self, "_review_config_button", None)
        if button is not None:
            button.configure(text=f"Review Configuration: {row.tid}…")

    def _load_editor_row(self, row: _ShelfEditorRow) -> None:
        """Load one committed row without triggering editor-dirty traces."""

        self._loading_editor = True
        try:
            self._profile_var.set(
                self._profile_label_by_id.get(
                    row.profile_id, profile_display_name(row.profile_id)
                )
            )
            self._site_code_var.set(row.site_code)
            self._site_name_var.set(row.site_name)
            self._tid_var.set(row.tid)
            self._ip_var.set(row.primary_oam_ip)
            self._release_var.set(R40_UI_RELEASE)
            self._variant_var.set(row.shelf_variant)
            self._raman_var.set(row.raman_label)
            self._power_var.set(row.power_label)
            self._editor_power_is_atlas_default = (
                _has_exact_power_label_role_default(
                    row.source_evidence,
                    row.profile_id,
                    row.power_label,
                )
            )
        finally:
            self._loading_editor = False
        self._editor_shelf_id = row.shelf_id
        self._editor_dirty = False

    def _clear_editor(self) -> None:
        self._loading_editor = True
        try:
            for variable in (
                self._site_code_var,
                self._site_name_var,
                self._tid_var,
                self._ip_var,
                self._variant_var,
                self._raman_var,
                self._power_var,
            ):
                variable.set("")
            self._release_var.set(R40_UI_RELEASE)
            if self._profile_pairs:
                self._profile_var.set(self._profile_pairs[0][1])
            selected_profile = self._selected_profile_id()
            default_power = power_label_for_profile(selected_profile)
            self._power_var.set(default_power)
            self._editor_power_is_atlas_default = bool(default_power)
        finally:
            self._loading_editor = False
        self._editor_shelf_id = ""
        self._editor_dirty = False
        button = getattr(self, "_review_config_button", None)
        if button is not None:
            button.configure(text="Review Configuration…")
        for item in self._tree.selection():
            self._tree.selection_remove(item)

    def _refresh_tree(self, *, select_id: str = "") -> None:
        current = select_id
        if not current:
            selection = self._tree.selection()
            current = selection[0] if selection else ""
        project: RouteProject | None = None
        project_shelves: dict[str, ShelfInstance] = {}
        try:
            project = self._build_project(require_valid=False)
        except (TypeError, ValueError):
            pass
        else:
            project_shelves = {
                shelf.shelf_id: shelf for shelf in project.shelves
            }
        self._tree.delete(*self._tree.get_children())
        for index, row in enumerate(self._rows, start=1):
            project_shelf = project_shelves.get(row.shelf_id)
            provider_label, direction_label = (
                _r40_shelf_glance_labels(project, project_shelf)
                if project is not None and project_shelf is not None
                else (
                    "Provider pending route data",
                    "Direction pending route data",
                )
            )
            self._tree.insert(
                "",
                tk.END,
                iid=row.shelf_id,
                values=(
                    index,
                    profile_display_name(row.profile_id),
                    row.site_code,
                    row.tid,
                    row.primary_oam_ip,
                    row.software_release,
                    row.raman_label,
                    row.power_label,
                    provider_label,
                    direction_label,
                    profile_readiness_label(
                        row.profile_id,
                        review_state=row.review_state,
                        advisory_label=self._config_labels.get(row.shelf_id, ""),
                        profile_payload=row.profile_payload,
                    ),
                ),
            )
        if current and self._tree.exists(current):
            self._tree.selection_set(current)
            self._tree.focus(current)
            self._tree.see(current)

    def _update_tree_readiness_cells(self) -> None:
        """Patch only readiness cells so the selected editor is untouched."""

        for row in self._rows:
            if not self._tree.exists(row.shelf_id):
                continue
            values = list(self._tree.item(row.shelf_id, "values"))
            if len(values) != len(_TABLE_COLUMNS):
                continue
            values[_TABLE_COLUMNS.index("readiness")] = profile_readiness_label(
                row.profile_id,
                review_state=row.review_state,
                advisory_label=self._config_labels.get(row.shelf_id, ""),
                profile_payload=row.profile_payload,
            )
            self._tree.item(row.shelf_id, values=values)

    def _build_project(self, *, require_valid: bool = True) -> RouteProject:
        return build_route_project(
            route_code=self._route_code_var.get(),
            title=self._title_var.get(),
            revision=self._revision_var.get(),
            rows=self._rows,
            project_id=self._project_id,
            notes=self._project_notes,
            ospf_area=self._ospf_area_var.get(),
            customer_policy=self._customer_policy(),
            links=self._links,
            diagram_source=self._diagram_source,
            require_valid=require_valid,
        )

    def _require_committed_editor(self) -> bool:
        if not self._editor_dirty:
            return True
        action = (
            "Update Selected or Confirm & Next Pending"
            if getattr(self, "_editor_shelf_id", "")
            else "Add Shelf"
        )
        _log_route_event(
            f"Action refused: shelf editor has uncommitted changes; "
            f"operator must use {action}.",
            logging.WARNING,
        )
        messagebox.showwarning(
            "Shelf edits not applied",
            (
                f"Use {action} or Clear Editor before saving, previewing, "
                "or exporting. This prevents visible shelf edits from being "
                "silently omitted."
            ),
            parent=self,
        )
        return False

    def _new_project(self) -> None:
        if self._dirty and not messagebox.askyesno(
            "Start a new project",
            "Discard the current unsaved route edits?",
            parent=self,
        ):
            _log_route_event("New project cancelled; unsaved route retained.")
            return
        self._rows.clear()
        self._links = []
        self._links_populated = False
        self._project_id = uuid4().hex
        self._project_notes = ""
        self._diagram_source = {}
        self._attached_workbook_diagram = None
        self._current_path = None
        self._loading_project = True
        try:
            self._route_code_var.set("")
            self._title_var.set("")
            self._revision_var.set("1")
            self._ospf_area_var.set("")
            self._neighbor_dns_suffix_var.set("")
            self._a_input_patch_loss_var.set("0.5")
            self._a_output_patch_loss_var.set("0.5")
            self._z_input_patch_loss_var.set("0.2")
            self._z_output_patch_loss_var.set("0.2")
            self._colan_ospf_metric_var.set("10")
        finally:
            self._loading_project = False
        self._dirty = False
        self._sync_route_fiber_controls()
        self._clear_editor()
        self._invalidate_project_results()
        self._refresh_tree()
        self._refresh_status("New route project.")
        _log_route_event("Created a new empty route project.")

    def _save_project(self) -> None:
        _log_route_event("Save project requested.")
        if not self._require_committed_editor():
            return
        try:
            project = self._build_project(require_valid=False)
        except (TypeError, ValueError) as exc:
            _log_route_event(
                f"Save project refused: {friendly_error(exc)}",
                logging.WARNING,
            )
            messagebox.showwarning("Route not ready", str(exc), parent=self)
            return
        initial = (
            self._current_path.name
            if self._current_path is not None
            else f"{_filename_stem(project.route_code)}_route_project.json"
        )
        destination = filedialog.asksaveasfilename(
            parent=self,
            title="Save Ciena RLS route project",
            initialdir=str(get_desktop_dir()),
            initialfile=initial,
            defaultextension=".json",
            filetypes=(("Route project", "*.json"), ("All files", "*.*")),
        )
        if not destination:
            _log_route_event("Save project cancelled by operator.")
            return
        try:
            output = save_route_project_draft(project, Path(destination))
        except (OSError, TypeError, ValueError) as exc:
            LOGGER.exception("Could not save Ciena RLS route project")
            messagebox.showerror(
                "Project save failed",
                friendly_error(exc, "The route project could not be saved."),
                parent=self,
            )
            return
        self._project_id = project.project_id
        self._project_notes = project.notes
        self._current_path = Path(output) if output is not None else Path(destination)
        self._dirty = False
        self._refresh_status(f"Saved project: {self._current_path.name}")
        _log_route_event(
            f"Saved project {project.project_id} with {len(project.shelves)} "
            f"shelf(s) to {self._current_path}."
        )

    def _open_project(self) -> None:
        _log_route_event("Open project requested.")
        if self._dirty and not messagebox.askyesno(
            "Open another project",
            "Discard the current unsaved route edits?",
            parent=self,
        ):
            _log_route_event("Open project cancelled; unsaved route retained.")
            return
        source = filedialog.askopenfilename(
            parent=self,
            title="Open Ciena RLS route project",
            initialdir=str(get_desktop_dir()),
            filetypes=(("Route project", "*.json"), ("All files", "*.*")),
        )
        if not source:
            _log_route_event("Open project cancelled by operator.")
            return
        try:
            project = load_route_project_draft(Path(source))
            self._load_project(project)
        except (OSError, TypeError, ValueError) as exc:
            LOGGER.exception("Could not open Ciena RLS route project")
            messagebox.showerror(
                "Project open failed",
                friendly_error(exc, "The selected route project is not valid."),
                parent=self,
            )
            return
        self._current_path = Path(source)
        self._dirty = False
        diagram_reattachment_required = isinstance(
            self._diagram_source.get(WORKBOOK_DIAGRAM_MARKER_KEY),
            Mapping,
        )
        self._refresh_status(
            f"Opened project: {self._current_path.name}"
            + (
                ". Reattach the original diagram before preview/export."
                if diagram_reattachment_required
                else ""
            )
        )
        _log_route_event(
            f"Opened project {project.project_id} with {len(project.shelves)} "
            f"shelf(s) from {self._current_path}; "
            "diagram_reattachment_required="
            f"{str(diagram_reattachment_required).casefold()}."
        )

    def _load_project(self, project: RouteProject) -> None:
        unsupported = _r40_only_rows_error(project.shelves)
        if unsupported:
            raise ValueError(
                unsupported
                + " The current route was not replaced. Use an RLS R4.0 "
                "project or convert it through an explicitly reviewed process."
            )
        sites = {site.site_key: site for site in project.sites}
        rows: list[_ShelfEditorRow] = []
        for shelf in project.shelves:
            site = sites.get(
                shelf.site_key,
                Site(
                    site_key=shelf.site_key,
                    code="",
                    name="",
                ),
            )
            rows.append(
                _ShelfEditorRow(
                    shelf_id=shelf.shelf_id,
                    profile_id=shelf.profile_id,
                    site_key=shelf.site_key,
                    site_code=site.code,
                    site_name=site.name,
                    tid=shelf.tid,
                    primary_oam_ip=shelf.primary_oam_ip,
                    software_release=shelf.software_release,
                    shelf_variant=shelf.shelf_variant,
                    raman_label=shelf.raman_label,
                    power_label=shelf.power_label,
                    site_address=site.address,
                    network_site_id=site.network_site_id,
                    notes=shelf.notes,
                    profile_payload=dict(shelf.profile_payload),
                    review_state=shelf.review_state,
                    source_evidence=dict(shelf.source_evidence),
                )
            )
        self._project_id = project.project_id
        self._project_notes = project.notes
        self._diagram_source = dict(project.diagram_source)
        # Pixel content is deliberately session-only and never serialized
        # into the route-project JSON. A project that requires a Diagram-tab
        # image must be rebound to the same local source before rendering.
        self._attached_workbook_diagram = None
        self._rows = rows
        self._links = list(project.links)
        self._links_populated = bool(project.links)
        self._loading_project = True
        try:
            self._route_code_var.set(project.route_code)
            self._title_var.set(project.title)
            self._revision_var.set(project.revision)
            self._ospf_area_var.set(project.ospf_area)
            policy = project.customer_policy
            self._neighbor_dns_suffix_var.set(
                policy.neighbor_dns_suffix
            )
            self._a_input_patch_loss_var.set(
                f"{policy.a_input_patch_loss_db:g}"
            )
            self._a_output_patch_loss_var.set(
                f"{policy.a_output_patch_loss_db:g}"
            )
            self._z_input_patch_loss_var.set(
                f"{policy.z_input_patch_loss_db:g}"
            )
            self._z_output_patch_loss_var.set(
                f"{policy.z_output_patch_loss_db:g}"
            )
            self._colan_ospf_metric_var.set(
                str(policy.colan_ospf_metric)
            )
        finally:
            self._loading_project = False
        self._sync_route_fiber_controls()
        self._clear_editor()
        self._invalidate_project_results()
        self._refresh_tree()
        self._schedule_config_evaluation()

    def _upload_route_diagram(self) -> None:
        _log_route_event("Route diagram upload requested.")
        if import_route_diagram is None:
            detail = (
                friendly_error(_DIAGRAM_IMPORT_ERROR)
                if _DIAGRAM_IMPORT_ERROR is not None
                else "Route diagram importer unavailable."
            )
            messagebox.showerror(
                "Route diagram importer unavailable",
                detail,
                parent=self,
            )
            _log_route_event(
                f"Diagram upload unavailable: {detail}", logging.ERROR
            )
            return
        if not self._require_committed_editor():
            _log_route_event(
                "Diagram upload stopped before file selection because shelf "
                "editor changes are uncommitted.",
                logging.WARNING,
            )
            return
        source = filedialog.askopenfilename(
            parent=self,
            title="Upload customer Ciena RLS route diagram",
            initialdir=str(get_desktop_dir()),
            filetypes=(
                ("Supported route diagrams", "*.docx *.png *.jpg *.jpeg"),
                ("Word document", "*.docx"),
                ("Image", "*.png *.jpg *.jpeg"),
                ("All files", "*.*"),
            ),
        )
        if not source:
            _log_route_event("Route diagram selection cancelled.")
            return
        _log_route_event(f"Selected route diagram {Path(source).name!r}.")
        if self._rows and not messagebox.askyesno(
            "Replace current route shelves",
            (
                "A diagram import represents a complete route and will replace "
                "the current shelf list after successful transcription. Continue?"
            ),
            parent=self,
        ):
            _log_route_event(
                "Diagram import cancelled; operator retained current shelf list."
            )
            return
        raman_callout_enabled = messagebox.askyesno(
            "RAMAN slot/port convention",
            (
                "For this diagram only, should ATLAS treat small red N/5 and "
                "N/6 boxes as RAMAN slot/port annotations?\n\n"
                "Choose Yes only when the customer/source convention is "
                "confirmed. A detached 3/5–3/6 legend sample and large red "
                "equipment boxes will not be assigned to a shelf. This choice "
                "does not authorize SRA hardware or CLI."
            ),
            default="no",
            parent=self,
        )
        raman_convention_id = (
            RAMAN_CALLOUT_CONVENTION_SMALL_RED_SLOT_PORT
            if raman_callout_enabled
            else RAMAN_CALLOUT_CONVENTION_DISABLED
        )
        if DiagramImportConventions is None:
            raise DiagramImportError("Route diagram importer is unavailable.")
        conventions = DiagramImportConventions(
            raman_callout_convention=raman_convention_id
        )
        _log_route_event(
            "Source-scoped RAMAN slot/port convention "
            f"{'enabled' if raman_callout_enabled else 'disabled'} for "
            f"{Path(source).name!r}."
        )
        if not messagebox.askyesno(
            "External AI privacy confirmation",
            (
                f"{DIAGRAM_PRIVACY_NOTICE}\n\n"
                f"Selected file: {Path(source).name}\n\nContinue?"
            ),
            parent=self,
        ):
            _log_route_event(
                "Diagram import cancelled at external-AI privacy confirmation."
            )
            return
        source_path = Path(source)
        _log_route_event(
            f"External-AI privacy confirmation accepted for "
            f"{source_path.name!r}; transcription starting."
        )
        provider_factory = self._diagram_provider_factory
        self._refresh_status(
            f"Transcribing {source_path.name} in the background…"
        )
        self._submit_background(
            "diagram_import",
            lambda: _import_diagram_worker(
                source_path,
                provider_factory,
                conventions,
            ),
            foreground=True,
        )

    def _reattach_route_diagram(self) -> None:
        """Rebind saved hash-only provenance to local pixels without AI."""

        _log_route_event("Local route diagram reattachment requested.")
        if (
            load_diagram_source is None
            or workbook_diagram_from_source is None
            or validate_workbook_diagram_for_project is None
        ):
            detail = (
                friendly_error(_DIAGRAM_ASSET_IMPORT_ERROR)
                if _DIAGRAM_ASSET_IMPORT_ERROR is not None
                else "Diagram attachment support is unavailable."
            )
            messagebox.showerror(
                "Diagram attachment unavailable",
                detail,
                parent=self,
            )
            _log_route_event(
                f"Diagram reattachment unavailable: {detail}",
                logging.ERROR,
            )
            return
        if not self._require_committed_editor():
            return
        marker = self._diagram_source.get(WORKBOOK_DIAGRAM_MARKER_KEY)
        if not isinstance(marker, Mapping):
            messagebox.showwarning(
                "No uploaded diagram provenance",
                (
                    "This route project has no controlled Diagram-tab source "
                    "marker. Use Upload Route Diagram to transcribe and bind a "
                    "customer diagram to the route."
                ),
                parent=self,
            )
            _log_route_event(
                "Diagram reattachment refused: project has no workbook "
                "diagram provenance marker.",
                logging.WARNING,
            )
            return
        source = filedialog.askopenfilename(
            parent=self,
            title="Reattach the original customer route diagram",
            initialdir=str(get_desktop_dir()),
            filetypes=(
                ("Supported route diagrams", "*.docx *.png *.jpg *.jpeg"),
                ("Word document", "*.docx"),
                ("Image", "*.png *.jpg *.jpeg"),
                ("All files", "*.*"),
            ),
        )
        if not source:
            _log_route_event("Diagram reattachment cancelled by operator.")
            return
        try:
            normalized_source = load_diagram_source(Path(source))
            diagram = workbook_diagram_from_source(normalized_source)
            project = self._build_project(require_valid=False)
            validate_workbook_diagram_for_project(project, diagram)
        except (DiagramAssetError, DiagramImportError, OSError, TypeError, ValueError) as exc:
            _log_route_event(
                "Diagram reattachment refused because local content did not "
                f"match saved provenance: {friendly_error(exc)}",
                logging.WARNING,
            )
            messagebox.showwarning(
                "Diagram does not match this project",
                friendly_error(
                    exc,
                    "The selected diagram does not match the uploaded source "
                    "record saved with this route.",
                ),
                parent=self,
            )
            return
        prior_normalization = str(marker.get("normalization", "") or "")
        current_marker = diagram.marker_dict(
            required_in_mop=bool(marker.get("required_in_mop", True))
        )
        if prior_normalization != current_marker["normalization"]:
            self._diagram_source = dict(self._diagram_source)
            self._diagram_source[WORKBOOK_DIAGRAM_MARKER_KEY] = current_marker
            self._dirty = True
            self._invalidate_project_results()
            _log_route_event(
                "Upgraded reattached workbook-diagram provenance from "
                f"{prior_normalization or 'unspecified'} to "
                f"{current_marker['normalization']}."
            )
        self._attached_workbook_diagram = diagram
        self._refresh_status(
            f"Reattached Diagram-tab source: {diagram.source_file_name}"
        )
        _log_route_event(
            f"Reattached local Diagram-tab source "
            f"{diagram.source_file_name!r}; sha256={diagram.source_sha256}; "
            f"image_occurrences={len(diagram.images)}; "
            "external_ai_processing=false."
        )

    def _apply_diagram_import(self, result: DiagramImportResult) -> None:
        try:
            integrity_blockers = diagram_import_mutation_blockers(result)
            if integrity_blockers:
                codes = sorted({blocker.code for blocker in integrity_blockers})
                fields = sorted({blocker.field for blocker in integrity_blockers})
                summary = "\n".join(
                    (
                        f"- [{blocker.code}] {blocker.field}: "
                        f"{blocker.message}"
                    )
                    for blocker in integrity_blockers[:8]
                )
                remaining = len(integrity_blockers) - min(
                    len(integrity_blockers), 8
                )
                if remaining:
                    summary += f"\n- …and {remaining} more integrity failure(s)."
                detail_log = " | ".join(
                    f"{blocker.field}: {blocker.message}"
                    for blocker in integrity_blockers[:8]
                )
                if remaining:
                    detail_log += f" | ...and {remaining} more"
                importer_issues = tuple(getattr(result, "issues", ()) or ())
                importer_issue_codes = sorted(
                    {
                        str(getattr(issue, "code", "UNKNOWN"))
                        for issue in importer_issues
                    }
                )
                importer_blocker_count = sum(
                    bool(getattr(issue, "blocking", False))
                    for issue in importer_issues
                )
                _log_route_event(
                    "Diagram transcription rejected before route replacement; "
                    f"shelves={len(result.active_shelves)}, "
                    f"spans={len(result.active_spans)}, "
                    f"integrity_codes={','.join(codes)}, "
                    f"integrity_fields={','.join(fields)}, "
                    f"integrity_details={detail_log}, "
                    f"importer_blockers={importer_blocker_count}, "
                    "importer_issue_codes="
                    f"{','.join(importer_issue_codes) or 'none'}. "
                    "Current route unchanged.",
                    logging.WARNING,
                )
                self._refresh_status(
                    "Diagram transcription incomplete; current route unchanged."
                )
                messagebox.showwarning(
                    "Diagram transcription incomplete — route unchanged",
                    (
                        "ATLAS could not establish a complete, contiguous route "
                        "from this transcription. The existing route was not "
                        "replaced.\n\n"
                        f"{summary}\n\n"
                        "Configuration-readiness fields such as software "
                        "release are evaluated separately and did not cause "
                        "this rejection."
                    ),
                    parent=self,
                )
                return
            rows = _diagram_editor_rows(result)
            unsupported = _r40_only_rows_error(rows)
            if unsupported:
                _log_route_event(
                    "Diagram transcription rejected by the RLS R4.0 product "
                    f"boundary before route replacement: {unsupported}",
                    logging.WARNING,
                )
                self._refresh_status(
                    "Diagram contains unsupported release or shelf roles; "
                    "current route unchanged."
                )
                messagebox.showwarning(
                    "RLS R4.0 route required — current route unchanged",
                    (
                        f"{unsupported}\n\n"
                        "ATLAS did not replace the current route. Correct the "
                        "customer source or use an explicitly reviewed RLS "
                        "R4.0-only diagram."
                    ),
                    parent=self,
                )
                return
            links = _diagram_route_links(result, rows)
            diagram_source = _diagram_source_record(result)
            workbook_diagram: WorkbookDiagram | None = None
            source_images = tuple(
                getattr(getattr(result, "source", None), "images", ()) or ()
            )
            if source_images:
                if workbook_diagram_from_source is None:
                    raise DiagramAssetError(
                        "Diagram attachment support is unavailable."
                    )
                workbook_diagram = workbook_diagram_from_source(result.source)
                diagram_source[WORKBOOK_DIAGRAM_MARKER_KEY] = (
                    workbook_diagram.marker_dict(required_in_mop=True)
                )
            elif str(
                getattr(getattr(result, "source", None), "path", "") or ""
            ).strip():
                # A production import always retains normalized source images.
                # Only older headless fixtures omit them.
                raise DiagramAssetError(
                    "The imported diagram has no renderable source image."
                )
            revision_scope_defaulted = not str(result.revision or "").strip()
            if revision_scope_defaulted:
                diagram_source["route_revision_scope_default"] = {
                    "value": "1",
                    "reason": _ROUTE_REVISION_SCOPE_DEFAULT_REASON,
                }
        except (DiagramAssetError, DiagramImportError, TypeError, ValueError) as exc:
            self._handle_worker_error("diagram_import", exc)
            return
        if not rows:
            _log_route_event(
                "Diagram transcription produced no active shelves; route unchanged.",
                logging.WARNING,
            )
            messagebox.showwarning(
                "No active shelves found",
                (
                    "The diagram transcription did not contain an active shelf. "
                    "The current route was not changed."
                ),
                parent=self,
            )
            return

        self._rows = rows
        self._links = links
        self._links_populated = True
        self._project_id = uuid4().hex
        self._project_notes = ""
        self._diagram_source = diagram_source
        self._attached_workbook_diagram = workbook_diagram
        self._current_path = None
        self._loading_project = True
        try:
            self._route_code_var.set(result.route_code or "")
            self._title_var.set(result.title or "")
            self._revision_var.set(result.revision or "1")
            ospf_variable = getattr(self, "_ospf_area_var", None)
            if ospf_variable is not None:
                ospf_variable.set(result.ospf_area or "")
        finally:
            self._loading_project = False
        self._clear_editor()
        self._committed_project_changed()
        self._sync_route_fiber_controls()
        self._refresh_tree(select_id=rows[0].shelf_id)

        issue_accounting = account_diagram_review_issues(
            result,
            rows,
            revision_default=diagram_source.get(
                "route_revision_scope_default"
            ),
            links=links,
        )
        source_issue_aggregate = issue_accounting.raw
        issue_aggregate = issue_accounting.unresolved
        required_review_count = issue_aggregate.required_review_count
        blocker_summary = diagram_issue_summary(
            issue_accounting.unresolved_issues
        )
        unresolved_role_orders = [
            str(order)
            for order, row in enumerate(rows, start=1)
            if not row.profile_id.strip()
        ]
        unresolved_role_count = len(unresolved_role_orders)
        suggested_site_code_count = sum(
            "site_code_review_suggestion" in row.source_evidence for row in rows
        )
        suggested_shelf_variant_count = sum(
            "shelf_variant_chassis_suggestion" in row.source_evidence
            for row in rows
        )
        raman_callouts = tuple(
            getattr(result, "raman_callouts", ()) or ()
        )
        raman_endpoint_callout_count = sum(
            getattr(callout, "context", "") == "shelf_endpoint"
            and bool(getattr(callout, "shelf_tid", None))
            for callout in raman_callouts
        )
        raman_legend_callout_count = sum(
            getattr(callout, "context", "") == "legend_sample"
            for callout in raman_callouts
        )
        raman_unresolved_callout_count = sum(
            getattr(callout, "context", "") == "unknown"
            or (
                getattr(callout, "context", "") == "shelf_endpoint"
                and not getattr(callout, "shelf_tid", None)
            )
            for callout in raman_callouts
        )
        raman_suggested_shelf_count = sum(
            "raman_callout_suggestion" in row.source_evidence for row in rows
        )
        fiber_scope = diagram_fiber_type_scope(result)
        route_band_status = _diagram_route_optical_band_status(result)
        route_band = (
            str(getattr(result, "optical_band", "") or "").strip()
            if route_band_status == "direct_supported"
            else ""
        )
        _log_route_event(
            f"Imported diagram {result.source.file_name!r} "
            f"sha256={result.source.sha256}; images={len(result.source.images)}, "
            "mop_diagram_images="
            f"{len(workbook_diagram.images) if workbook_diagram is not None else 0}, "
            "mop_diagram_required="
            f"{str(workbook_diagram is not None).casefold()}, "
            f"shelves={len(rows)}, spans={len(result.active_spans)}, "
            "route_integrity=accepted, "
            "transcription_required_review="
            f"{required_review_count}, "
            "transcription_source_required_review="
            f"{source_issue_aggregate.required_review_count}, "
            "transcription_source_absences="
            f"{issue_accounting.source_absence_count}, "
            "transcription_review_accounting="
            f"{_format_count_pairs(issue_accounting.category_counts)}, "
            f"transcription_advisories={source_issue_aggregate.advisory_count}, "
            "transcription_issue_codes="
            f"{_format_count_pairs(source_issue_aggregate.code_counts)}, "
            "transcription_required_paths="
            f"{_format_count_pairs(issue_aggregate.required_path_counts)}, "
            "transcription_missing_fields="
            f"{_format_count_pairs(issue_aggregate.missing_leaf_counts)}, "
            "transcription_missing_paths="
            f"{_format_count_pairs(issue_aggregate.missing_path_counts)}, "
            "transcription_source_missing_fields="
            f"{_format_count_pairs(source_issue_aggregate.missing_leaf_counts)}, "
            "transcription_source_missing_paths="
            f"{_format_count_pairs(source_issue_aggregate.missing_path_counts)}, "
            "revision_scope_defaulted="
            f"{str(revision_scope_defaulted).casefold()}, "
            f"route_optical_band={route_band or 'not_prepopulated'}, "
            f"route_optical_band_status={route_band_status}, "
            f"site_code_review_suggestions={suggested_site_code_count}, "
            "shelf_variant_chassis_suggestions="
            f"{suggested_shelf_variant_count}, "
            f"raman_endpoint_callouts={raman_endpoint_callout_count}, "
            f"raman_legend_callouts={raman_legend_callout_count}, "
            f"raman_unresolved_callouts={raman_unresolved_callout_count}, "
            f"raman_shelf_suggestions={raman_suggested_shelf_count}, "
            "fiber_scope_inherited_spans="
            f"{issue_accounting.scope_inherited_count}, "
            "route_native_fiber_review=pending, "
            f"unresolved_roles={unresolved_role_count}, "
            "unresolved_role_orders="
            f"{','.join(unresolved_role_orders) or 'none'}, "
            "deployment_readiness=not_authorized_pending_review.",
            logging.WARNING if required_review_count else logging.INFO,
        )
        self._refresh_status(
            f"Imported {len(rows)} shelf draft(s); route topology accepted; "
            f"{required_review_count} unresolved required value(s); "
            "raw source findings retained in the log; "
            "deployment readiness not authorized."
            + (
                f" Resolve {unresolved_role_count} shelf role(s)."
                if unresolved_role_count
                else ""
            )
        )
        unresolved_note = (
            (
                f"\n\n{unresolved_role_count} shelf role(s) could not be "
                "established from sufficient diagram evidence. They are shown "
                f"as {UNRESOLVED_PROFILE_LABEL!r}; select each visible role "
                "and use Confirm & Next Pending before configuration review."
            )
            if unresolved_role_count
            else ""
        )
        suggestion_note = (
            (
                f"\n\nATLAS supplied {suggested_site_code_count} editable "
                "site-code suggestion(s) from TID prefixes"
                + (
                    f" and {suggested_shelf_variant_count} chassis-family "
                    "shelf-variant suggestion(s)"
                    if suggested_shelf_variant_count
                    else ""
                )
                + (
                    " and started deliverable revision 1"
                    if revision_scope_defaulted
                    else ""
                )
                + ". These are workflow suggestions, not diagram evidence; "
                "verify them before using Confirm & Next Pending."
            )
            if (
                suggested_site_code_count
                or suggested_shelf_variant_count
                or revision_scope_defaulted
            )
            else ""
        )
        raman_note = (
            (
                f"\n\nATLAS found {raman_endpoint_callout_count} attached "
                "RAMAN slot/port callout(s) and prepared "
                f"{raman_suggested_shelf_count} pending shelf display "
                "suggestion(s). Confirming a suggestion records SRA presence "
                "for compatibility review; it never enables RAMAN CLI."
                + (
                    f" {raman_legend_callout_count} detached legend sample "
                    "callout(s) were retained as context only."
                    if raman_legend_callout_count
                    else ""
                )
                + (
                    f" {raman_unresolved_callout_count} callout(s) remain "
                    "unassigned and will block bundle export."
                    if raman_unresolved_callout_count
                    else ""
                )
            )
            if raman_callouts
            else ""
        )
        fiber_scope_note = (
            (
                "\n\nATLAS found one directly evidenced fiber label shared by "
                f"{len(fiber_scope.observed_span_orders)} active spans and "
                "scoped it to the one missing active-span record as a pending "
                "route-level suggestion. Select one audited Native CLI fiber "
                "type and use Apply to all spans. The source label is retained "
                "separately and is never converted to a CLI token."
            )
            if fiber_scope is not None
            else ""
        )
        route_band_note = (
            (
                "\n\nATLAS preserved the directly evidenced route-header "
                f"optical band {_display_optical_band_for_review(route_band)} "
                "as read-only exact-review context. It is not copied into "
                "each shelf and does not select a provider or BOM."
            )
            if route_band
            else (
                "\n\nA route-header optical-band candidate was not "
                "prepopulated because its direct evidence did not pass "
                "review."
                if route_band_status == "unverified"
                else ""
            )
        )
        messagebox.showwarning(
            "Diagram imported — human review required",
            (
                f"Imported {len(rows)} active shelf draft(s). Every row remains "
                "pending until you select it, verify each visible field, and use "
                "Confirm & Next Pending.\n\n"
                "Route topology integrity passed and the draft was imported. "
                f"After workflow accounting, {required_review_count} required "
                "field value(s) remain unresolved. The source transcription "
                f"reported {issue_accounting.source_absence_count} absent "
                "field value(s); "
                f"{issue_accounting.defaulted_count} received controlled "
                "workflow defaults, "
                f"{issue_accounting.suggestion_pending_count} received "
                "pending review suggestions, "
                f"{issue_accounting.scope_inherited_count} fiber omission(s) "
                "received a unanimous route-scope suggestion pending operator "
                "review, "
                f"{issue_accounting.optional_count} are optional, and "
                f"{issue_accounting.lifecycle_excluded_count} belong to "
                "excluded lifecycle records"
                + (
                    f". The source also reported "
                    f"{source_issue_aggregate.advisory_count} advisory issue(s)"
                    if source_issue_aggregate.advisory_count
                    else ""
                )
                + ".\n\n"
                f"{blocker_summary}{unresolved_note}{suggestion_note}"
                f"{raman_note}{fiber_scope_note}{route_band_note}"
                "\n\nConfiguration deployment readiness is a separate "
                "assessment and is not authorized by diagram transcription."
            ),
            parent=self,
        )

    def _preview_mop(self) -> None:
        _log_route_event("MOP preview requested.")
        if export_mop is None:
            detail = (
                friendly_error(_MOP_IMPORT_ERROR)
                if _MOP_IMPORT_ERROR is not None
                else "MOP exporter unavailable."
            )
            messagebox.showerror("MOP exporter unavailable", detail, parent=self)
            _log_route_event(
                f"MOP preview unavailable: {detail}", logging.ERROR
            )
            return
        if not self._require_committed_editor():
            return
        try:
            project = self._build_project(require_valid=False)
            fingerprint = route_project_fingerprint(project)
        except (TypeError, ValueError) as exc:
            _log_route_event(
                f"MOP preview refused: {friendly_error(exc)}",
                logging.WARNING,
            )
            messagebox.showwarning("Route not ready", str(exc), parent=self)
            return
        try:
            workbook_diagram = _validated_diagram_attachment(
                project,
                getattr(self, "_attached_workbook_diagram", None),
            )
        except (DiagramAssetError, TypeError, ValueError) as exc:
            _log_route_event(
                "MOP preview refused: Diagram-tab attachment is missing or "
                f"stale; {friendly_error(exc)}",
                logging.WARNING,
            )
            messagebox.showwarning(
                "Diagram reattachment required",
                (
                    f"{friendly_error(exc)}\n\n"
                    "Use Reattach Diagram to select the original local source. "
                    "This local-only step does not send the diagram to AI or "
                    "replace the reviewed route."
                ),
                parent=self,
            )
            return
        preview_dir = tempfile.TemporaryDirectory(
            prefix="atlas_rls_mop_preview_",
            ignore_cleanup_errors=True,
        )
        output_path = (
            Path(preview_dir.name)
            / f"{_filename_stem(project.route_code)}_MOP_PREVIEW.xlsx"
        )
        self._refresh_status("Creating a watermarked MOP preview…")
        _log_route_event(
            f"Creating watermarked MOP preview for route "
            f"{project.route_code!r} with {len(project.shelves)} shelf(s)."
        )
        self._submit_background(
            "preview",
            lambda: export_mop(
                project,
                output_path,
                purpose="preview",
                diagram=workbook_diagram,
            ),
            fingerprint=fingerprint,
            context=preview_dir,
            foreground=True,
        )

    def _complete_preview(self, result: _WorkerResult) -> None:
        output = Path(result.value)
        self._preview_fingerprint = result.fingerprint
        self._preview_path = output
        if result.context is not None:
            self._preview_tempdirs.append(result.context)
        self._refresh_status(
            f"Current watermarked MOP preview: {output.name}"
        )
        _log_route_event(f"Created watermarked MOP preview at {output}.")
        try:
            _open_preview_file(output)
            _log_route_event(f"Opened MOP preview {output.name!r}.")
        except OSError as exc:
            _log_route_event(
                f"Could not open MOP preview {output}: {friendly_error(exc)}",
                logging.ERROR,
            )
            messagebox.showerror(
                "Could not open MOP preview",
                (
                    f"{friendly_error(exc)}\n\nThe current preview was created at "
                    f"{output}."
                ),
                parent=self,
            )

    def _apply_config_evaluation(self, result: RouteConfigBuild) -> None:
        labels: dict[str, str] = {}
        for status in result.readiness.shelf_statuses:
            if status.ready:
                labels[status.shelf_id] = "Config validated — bundle only"
            elif "PENDING_SHELF_REVIEW" in status.reason_codes:
                labels[status.shelf_id] = "Pending review — CLI blocked"
            elif "PENDING_RAMAN_CALLOUT_REVIEW" in status.reason_codes:
                labels[status.shelf_id] = "Review RAMAN — CLI blocked"
            elif "R40_EXACT_PROVIDER_SRA_CONFLICT" in status.reason_codes:
                labels[status.shelf_id] = (
                    "SRA provider required — CLI blocked"
                )
            elif R40_PENDING_SRA_PEER_REVIEW in status.reason_codes:
                labels[status.shelf_id] = (
                    "Paired SRA peer review pending — CLI blocked"
                )
            elif (
                "R40_SRA_CAPABLE_PROVIDER_UNAVAILABLE"
                in status.reason_codes
            ):
                labels[status.shelf_id] = (
                    "SRA provider required — CLI blocked"
                )
            elif "PLANNING_ONLY_PROVIDER_NOT_IMPLEMENTED" in status.reason_codes:
                labels[status.shelf_id] = "R4.0 review only — CLI gated"
            elif "EXACT_PROVIDER_REVIEW_REQUIRED" in status.reason_codes:
                labels[status.shelf_id] = (
                    "Select exact provider — CLI pending"
                )
            elif "PROPAGATION_PATH_INCOMPLETE" in status.reason_codes:
                labels[status.shelf_id] = (
                    "Review A→Z/Z→A propagation — CLI blocked"
                )
            elif "UNREVIEWED_OPTICAL_PATH" in status.reason_codes:
                labels[status.shelf_id] = (
                    "Review physical span layout — CLI blocked"
                )
            else:
                labels[status.shelf_id] = "Config validation blocked"
        self._config_labels = labels
        self._update_tree_readiness_cells()
        ready_count = sum(
            1 for status in result.readiness.shelf_statuses if status.ready
        )
        blocked_count = len(result.readiness.shelf_statuses) - ready_count
        route_rows = tuple(getattr(self, "_rows", ()) or ())
        reviewed_shelf_count = sum(
            getattr(row, "review_state", "") != "pending"
            for row in route_rows
        )
        exact_payload_count = sum(
            _r40_payload_version_state(
                getattr(row, "profile_payload", None)
            )
            == "current"
            for row in route_rows
        )
        optical_paths = tuple(
            path
            for link in tuple(getattr(self, "_links", ()) or ())
            for path in tuple(getattr(link, "paths", ()) or ())
        )
        reviewed_path_count = sum(
            getattr(path, "review_state", "") in {"confirmed", "corrected"}
            for path in optical_paths
        )
        propagation_views = tuple(
            view
            for link in tuple(getattr(self, "_links", ()) or ())
            for view in route_link_propagation_views(link)
        )
        reviewed_propagation_count = sum(
            view.egress_review is not None for view in propagation_views
        )
        reason_counts = _count_labels(
            _safe_diagnostic_code(code)
            for status in result.readiness.shelf_statuses
            if not status.ready
            for code in tuple(status.reason_codes)
        )
        if result.ready:
            message = (
                "Configuration deployment readiness passed for "
                f"{ready_count} shelf(s); final bundle export revalidates the "
                "current snapshot."
            )
        else:
            message = (
                "Configuration deployment readiness: "
                f"{ready_count} ready, {blocked_count} blocked. "
                f"Shelves reviewed {reviewed_shelf_count}/{len(route_rows)}; "
                f"exact configuration reviews {exact_payload_count}/"
                f"{len(route_rows)}; A→Z/Z→A propagation reviews "
                f"{reviewed_propagation_count}/{len(propagation_views)}; "
                f"physical spans reviewed "
                f"{reviewed_path_count}/{len(optical_paths)}."
            )
        self._refresh_status(message)
        _log_route_event(
            "Configuration deployment-readiness assessment completed: "
            f"ready_shelves={ready_count}, blocked_shelves={blocked_count}, "
            f"reviewed_shelves={reviewed_shelf_count}/{len(route_rows)}, "
            f"exact_payloads={exact_payload_count}/{len(route_rows)}, "
            "reviewed_propagation_paths="
            f"{reviewed_propagation_count}/{len(propagation_views)}, "
            "reviewed_physical_spans="
            f"{reviewed_path_count}/{len(optical_paths)}, "
            f"candidate_configs={getattr(result, 'config_count', 0)}, "
            f"reason_codes={_format_count_pairs(reason_counts)}.",
            logging.INFO if result.ready else logging.WARNING,
        )

    def _export_bundle(self) -> None:
        """Export the complete route documentation bundle, never partial CLI."""

        _log_route_event("Final route bundle export requested.")
        if export_route_bundle is None:
            detail = (
                friendly_error(_BUNDLE_IMPORT_ERROR)
                if _BUNDLE_IMPORT_ERROR is not None
                else "Route bundle exporter unavailable."
            )
            messagebox.showerror("Bundle exporter unavailable", detail, parent=self)
            _log_route_event(
                f"Bundle export unavailable: {detail}", logging.ERROR
            )
            return
        if not self._require_committed_editor():
            return
        try:
            project = self._build_project(require_valid=True)
            fingerprint = route_project_fingerprint(project)
        except (TypeError, ValueError) as exc:
            _log_route_event(
                f"Bundle export refused: {friendly_error(exc)}",
                logging.WARNING,
            )
            messagebox.showwarning("Route not ready", str(exc), parent=self)
            return
        try:
            workbook_diagram = _validated_diagram_attachment(
                project,
                getattr(self, "_attached_workbook_diagram", None),
            )
        except (DiagramAssetError, TypeError, ValueError) as exc:
            _log_route_event(
                "Bundle export refused: Diagram-tab attachment is missing or "
                f"stale; {friendly_error(exc)}",
                logging.WARNING,
            )
            messagebox.showwarning(
                "Diagram reattachment required",
                (
                    f"{friendly_error(exc)}\n\n"
                    "Use Reattach Diagram before previewing and exporting the "
                    "current deliverable."
                ),
                parent=self,
            )
            return
        readiness = project.deployment_readiness()
        if not readiness.ready:
            actions = _bundle_preflight_actions(project, readiness)
            action_counts = tuple(
                (code, count) for code, _label, count in actions
            )
            reason_counts = _count_labels(
                _safe_diagnostic_code(code)
                for status in readiness.shelf_statuses
                for code in status.reason_codes
            )
            _log_route_event(
                "Bundle export refused by deployment-readiness preflight; "
                f"actions={_format_count_pairs(action_counts)}, "
                f"reason_codes={_format_count_pairs(reason_counts)}, "
                "background_submitted=false, artifacts_created=false.",
                logging.WARNING,
            )
            messagebox.showwarning(
                "Route bundle not ready",
                _bundle_preflight_message(actions),
                parent=self,
            )
            return
        if (
            not self._preview_fingerprint
            or self._preview_fingerprint != fingerprint
            or self._preview_path is None
            or not self._preview_path.is_file()
        ):
            _log_route_event(
                "Bundle export refused: current MOP preview is missing or stale.",
                logging.WARNING,
            )
            messagebox.showwarning(
                "Current MOP preview required",
                (
                    "Preview the current route before exporting its final bundle. "
                    "Any route or shelf edit invalidates the prior preview."
                ),
                parent=self,
            )
            return
        destination = filedialog.askdirectory(
            parent=self,
            title="Choose a folder for the Ciena RLS route bundle",
            initialdir=str(get_desktop_dir()),
            mustexist=True,
        )
        if not destination:
            _log_route_event("Bundle export cancelled by operator.")
            return
        self._refresh_status(
            "Building the final fail-closed route bundle in the background…"
        )
        _log_route_event(
            f"Building final route bundle for {project.route_code!r} with "
            f"{len(project.shelves)} shelf(s) in {destination}."
        )
        self._submit_background(
            "bundle",
            lambda: export_route_bundle(
                project,
                Path(destination),
                diagram=workbook_diagram,
            ),
            fingerprint=fingerprint,
            foreground=True,
        )

    def _complete_bundle(self, artifacts: Mapping[str, Path]) -> None:
        paths = tuple(Path(path) for path in artifacts.values())
        bundle_dir = paths[0].parent if paths else Path(".")
        self._refresh_status(f"Exported route bundle: {bundle_dir.name}")
        _log_route_event(
            f"Exported route bundle {bundle_dir} with {len(paths)} artifact(s)."
        )
        messagebox.showinfo(
            "Route bundle exported",
            (
                f"Created {bundle_dir.name} with the route project, final FBN "
                "MOP, complete per-shelf configuration candidates, validation "
                "report, and manifest.\n\n"
                "The final exporter revalidated and regenerated every candidate "
                "from this route snapshot. Candidate CLI is not declared "
                "deployable without the required engineering review."
            ),
            parent=self,
        )

    def _refresh_status(self, message: str = "") -> None:
        count = len(self._rows)
        rack_count = max(1, (count + 7) // 8) if count else 0
        planning_count = sum(
            1 for row in self._rows if profile_is_planning_only(row.profile_id)
        )
        pending_count = sum(
            1 for row in self._rows if row.review_state == "pending"
        )
        state = (
            f"{count} shelf{'ves' if count != 1 else ''}; "
            f"{rack_count} rack diagram{'s' if rack_count != 1 else ''}; "
            f"{pending_count} pending review; {planning_count} CLI-gated."
        )
        if self._dirty:
            state += " Unsaved changes."
        self._status_var.set(f"{message}  {state}".strip())


__all__ = [
    "DIAGRAM_PRIVACY_NOTICE",
    "PLANNING_CLI_NOTICE",
    "R40_UI_PROFILE_IDS",
    "R40_UI_RELEASE",
    "UNRESOLVED_PROFILE_LABEL",
    "DiagramImportMutationBlocker",
    "DiagramReviewAccounting",
    "RlsRouteFrame",
    "account_diagram_review_issues",
    "build_route_project",
    "diagram_import_mutation_blockers",
    "diagram_issue_summary",
    "imported_values_changed",
    "profile_choices",
    "profile_display_name",
    "profile_is_planning_only",
    "profile_readiness_label",
    "provider_identity_changed",
]
