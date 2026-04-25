"""Packing slip frame — widgets and logic for the Packing Slip (From File) mode."""
import os
import tempfile
import logging
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Dict, List

import openpyxl
import pandas as pd


class PackingSlipFrame(ttk.Frame):
    """Tkinter frame for the Packing Slip (From File) mode.

    Owns file-upload widgets, project information fields, and all packing slip
    generation logic for file-based input.  Uses *controller* to access
    ``controller.output_screen`` and ``controller.workbook_builder``.
    """

    def __init__(self, parent: ttk.Frame, controller) -> None:
        super().__init__(parent)
        self.controller = controller
        self.uploaded_file_path: str | None = None
        self.uploaded_file_data: pd.DataFrame | None = None
        self._build()

    # ------------------------------------------------------------------
    # Frame construction
    # ------------------------------------------------------------------

    def _build(self) -> None:
        file_frame = ttk.LabelFrame(self, text="Upload File")
        file_frame.pack(fill=tk.X, pady=5)

        self.file_path_label = tk.Label(file_frame, text="No file selected", foreground="gray")
        self.file_path_label.pack(side=tk.LEFT, padx=10, pady=5)

        tk.Button(file_frame, text="Browse", command=self.upload_file).pack(side=tk.LEFT, padx=5)

        info_frame = ttk.LabelFrame(self, text="Project Information")
        info_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(info_frame, text="Customer:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.ps_customer_entry = tk.Entry(info_frame, width=40)
        self.ps_customer_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(info_frame, text="Project:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.ps_project_entry = tk.Entry(info_frame, width=40)
        self.ps_project_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(info_frame, text="Purchase Order:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.ps_po_entry = tk.Entry(info_frame, width=40)
        self.ps_po_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Label(info_frame, text="Sales Order:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.ps_so_entry = tk.Entry(info_frame, width=40)
        self.ps_so_entry.grid(row=3, column=1, padx=5, pady=5)

        ps_control_frame = ttk.Frame(self)
        ps_control_frame.pack(fill=tk.X, pady=10)

        self.ps_run_button = tk.Button(
            ps_control_frame, text="Generate Packing Slips",
            command=self.generate_packing_slips_from_file,
        )
        self.ps_run_button.pack(side=tk.RIGHT, padx=5)

        self.ps_status_label = tk.Label(ps_control_frame, text="Status: Ready", anchor="w")
        self.ps_status_label.pack(side=tk.RIGHT, padx=10)

    # ------------------------------------------------------------------
    # File upload
    # ------------------------------------------------------------------

    def upload_file(self) -> None:
        """Prompt for a CSV or Excel file and load it into memory."""
        file_path = filedialog.askopenfilename(
            title="Select File (CSV or Excel)",
            filetypes=[
                ("Excel files", "*.xlsx *.xls"),
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
        )
        if not file_path:
            return

        try:
            self.uploaded_file_path = file_path
            if file_path.endswith(".csv"):
                self.uploaded_file_data = pd.read_csv(file_path)
            elif file_path.endswith((".xlsx", ".xls")):
                self.uploaded_file_data = pd.read_excel(file_path)
            else:
                messagebox.showerror("File Error", "Unsupported file format. Please use CSV or Excel files.")
                return

            file_name = os.path.basename(file_path)
            self.file_path_label.config(
                text=f"✓ {file_name} ({len(self.uploaded_file_data)} rows)",
                foreground="green",
            )
            out = self.controller.output_screen
            out.insert(tk.END, f"Loaded file: {file_name} with {len(self.uploaded_file_data)} rows\n")
            out.see(tk.END)
            logging.info(f"File uploaded: {file_path} with {len(self.uploaded_file_data)} rows")

        except Exception as e:
            messagebox.showerror("File Error", f"Failed to load file:\n{e}")
            logging.error(f"File upload error: {e}")

    # ------------------------------------------------------------------
    # Packing slip generation
    # ------------------------------------------------------------------

    def generate_packing_slips_from_file(self) -> None:
        """Validate inputs and generate packing slips from the uploaded file."""
        if self.uploaded_file_data is None:
            messagebox.showwarning("No File", "Please upload a file first.")
            return

        customer = self.ps_customer_entry.get().strip()
        project = self.ps_project_entry.get().strip()
        customer_po = self.ps_po_entry.get().strip()
        sales_order = self.ps_so_entry.get().strip()

        if not all([customer, project, customer_po, sales_order]):
            messagebox.showerror("Missing Info", "Please fill in all project information fields.")
            return

        save_folder = filedialog.askdirectory(title="Select Packing Slip Save Location")
        if not save_folder:
            return

        self.ps_run_button.config(state=tk.DISABLED)
        self.ps_status_label.config(text="Status: Processing...")
        self.controller.root.update_idletasks()

        try:
            processed_data = self._process_file_for_packing_slip(self.uploaded_file_data)

            if not processed_data:
                self.ps_status_label.config(text="Status: Ready")
                messagebox.showwarning("No Data", "No valid data found in the file.")
                return

            ip_list = list(processed_data.keys())
            save_path = self.controller.workbook_builder.build_packing_slip_workbook(
                processed_data, ip_list, customer, project, customer_po, sales_order, save_folder,
            )

            self.ps_status_label.config(text="Status: Ready")
            messagebox.showinfo("Success", f"Packing slips saved to:\n{save_path}")
            out = self.controller.output_screen
            out.insert(tk.END, f"Packing slips generated successfully: {save_path}\n")
            out.see(tk.END)
            self._show_print_selection_dialog(save_path)

        except Exception as e:
            self.ps_status_label.config(text="Status: Error")
            messagebox.showerror("Generation Error", f"Failed to generate packing slips:\n{e}")
            logging.error(f"Packing slip generation error: {e}")
        finally:
            self.ps_run_button.config(state=tk.NORMAL)

    # ------------------------------------------------------------------
    # Print selection
    # ------------------------------------------------------------------

    def _show_print_selection_dialog(self, workbook_path: str) -> None:
        """Open a dialog listing device sheets as checkboxes so the user can
        choose which ones to send to the printer."""
        try:
            wb = openpyxl.load_workbook(workbook_path, read_only=True)
            summary_sheets = [n for n in wb.sheetnames if "summary" in n.lower()]
            device_sheets = [n for n in wb.sheetnames if "summary" not in n.lower()]
            wb.close()
        except Exception as e:
            logging.error(f"Could not read workbook for print selection: {e}")
            return

        if not device_sheets:
            return

        dialog = tk.Toplevel(self.controller.root)
        dialog.title("Select Sheets to Print")
        dialog.grab_set()
        dialog.resizable(False, False)

        tk.Label(dialog, text="Select device sheets to print:", font=("TkDefaultFont", 10, "bold")).pack(
            padx=15, pady=(12, 4), anchor="w"
        )

        # Scrollable checkbox list
        list_frame = ttk.Frame(dialog)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=4)

        canvas_height = min(300, len(device_sheets) * 28 + 10)
        canvas = tk.Canvas(list_frame, height=canvas_height, highlightthickness=0)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        inner.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        if len(device_sheets) > 10:
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        vars_: Dict[str, tk.BooleanVar] = {}
        for name in device_sheets:
            var = tk.BooleanVar(value=True)
            vars_[name] = var
            ttk.Checkbutton(inner, text=name, variable=var).pack(anchor="w", padx=5, pady=2)

        # Select / Deselect All
        sel_frame = ttk.Frame(dialog)
        sel_frame.pack(fill=tk.X, padx=15, pady=(2, 6))
        tk.Button(sel_frame, text="Select All",   command=lambda: [v.set(True)  for v in vars_.values()]).pack(side=tk.LEFT, padx=2)
        tk.Button(sel_frame, text="Deselect All", command=lambda: [v.set(False) for v in vars_.values()]).pack(side=tk.LEFT, padx=2)

        # Consolidated vs Individual toggle
        ttk.Separator(dialog, orient="horizontal").pack(fill=tk.X, padx=15, pady=(4, 0))
        mode_frame = ttk.LabelFrame(dialog, text="Print Mode")
        mode_frame.pack(fill=tk.X, padx=15, pady=(6, 4))
        print_mode = tk.StringVar(value="consolidated")
        tk.Radiobutton(
            mode_frame, text="Consolidated  (all selected in one file)",
            variable=print_mode, value="consolidated",
        ).pack(anchor="w", padx=10, pady=2)
        tk.Radiobutton(
            mode_frame, text="Individual  (separate file per device)",
            variable=print_mode, value="individual",
        ).pack(anchor="w", padx=10, pady=2)

        def on_print() -> None:
            selected = [name for name, var in vars_.items() if var.get()]
            if not selected:
                messagebox.showwarning("No Selection", "Please select at least one sheet.", parent=dialog)
                return
            mode = print_mode.get()
            dialog.destroy()
            self._print_selected_sheets(workbook_path, selected, summary_sheets, mode)

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=15, pady=(4, 12))
        tk.Button(btn_frame, text="Print Selected", command=on_print, width=16).pack(side=tk.RIGHT, padx=2)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy, width=10).pack(side=tk.RIGHT, padx=2)

        dialog.wait_window()

    def _print_selected_sheets(self, source_path: str, selected_sheets: List[str], summary_sheets: List[str], mode: str = "consolidated") -> None:
        """Open selected sheets for printing.

        mode='consolidated': one file containing the summary + all selected sheets.
        mode='individual':   one file per selected sheet, each with the summary included.
        """
        try:
            temp_dir = tempfile.gettempdir()
            base_name = os.path.splitext(os.path.basename(source_path))[0]

            if mode == "individual":
                opened = 0
                for sheet_name in selected_sheets:
                    wb_src = openpyxl.load_workbook(source_path)
                    sheets_to_keep = set(summary_sheets + [sheet_name])
                    for name in list(wb_src.sheetnames):
                        if name not in sheets_to_keep:
                            del wb_src[name]
                    safe = sheet_name.replace("/", "_").replace("\\", "_")
                    temp_path = os.path.join(temp_dir, f"LAMIS_Print_{base_name}_{safe}.xlsx")
                    wb_src.save(temp_path)
                    try:
                        os.startfile(temp_path, "print")
                    except Exception:
                        os.startfile(temp_path)
                    opened += 1

                out = self.controller.output_screen
                out.insert(tk.END, f"Opened {opened} individual file(s) for printing.\n")
                out.see(tk.END)
                logging.info(f"Individual print: opened {opened} file(s) from {source_path}")

            else:  # consolidated
                wb_src = openpyxl.load_workbook(source_path)
                sheets_to_keep = set(summary_sheets + selected_sheets)
                for name in list(wb_src.sheetnames):
                    if name not in sheets_to_keep:
                        del wb_src[name]
                temp_path = os.path.join(temp_dir, f"LAMIS_Print_{base_name}.xlsx")
                wb_src.save(temp_path)
                try:
                    os.startfile(temp_path, "print")
                except Exception:
                    os.startfile(temp_path)

                out = self.controller.output_screen
                out.insert(tk.END, f"Opened {len(selected_sheets)} sheet(s) for printing (consolidated).\n")
                out.see(tk.END)
                logging.info(f"Consolidated print: {len(selected_sheets)} sheet(s) from {source_path}")

        except Exception as e:
            messagebox.showerror("Print Error", f"Failed to prepare sheets for printing:\n{e}")
            logging.error(f"Print selection error: {e}")

    # ------------------------------------------------------------------
    # File processing
    # ------------------------------------------------------------------

    def _process_file_for_packing_slip(self, df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
        """Convert uploaded DataFrame to per-device dict for the workbook builder."""
        processed_data: Dict[str, pd.DataFrame] = {}
        try:
            # Use lowercased column names only for device key detection; preserve
            # original column casing so the workbook builder can access "Part Number" etc.
            col_lower_map = {col: str(col).lower() for col in df.columns}

            # Check patterns from most specific to least specific to avoid
            # matching unrelated columns like "Part Name" or "File Name".
            # "ip" is NOT used as a bare substring because it matches "Description".
            device_key = None
            priority_patterns = ["system name", "device", "ip address", " ip"]
            fallback_patterns = ["name"]
            for pattern_list in (priority_patterns, fallback_patterns):
                for pattern in pattern_list:
                    for col, col_lower in col_lower_map.items():
                        if pattern in col_lower or (col_lower.strip() == "ip" and pattern == " ip"):
                            device_key = col
                            break
                    if device_key:
                        break
                if device_key:
                    break

            if device_key:
                for device_id, group in df.groupby(device_key, sort=False):
                    processed_data[str(device_id)] = group.reset_index(drop=True)
            else:
                processed_data["Device_0"] = df.reset_index(drop=True)

            return processed_data

        except Exception as e:
            logging.error(f"Error processing file: {e}")
            raise
