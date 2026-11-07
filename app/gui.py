"""Interfaz Tkinter: una pestaña por componente (App, Backend, Admin Panel, ...)."""

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from .export import export_csv, export_xlsx
from .models import SEVERITY_ORDER
from .osv_runner import OsvScanError, run_scan
from .package_view import group_by_package

VULN_COLUMNS = [
    ("cve", "CVE", 150),
    ("published", "Published", 100),
    ("osv_url", "OSV URL", 260),
    ("cvss", "CVSS", 60),
    ("severity", "Severity", 80),
    ("ecosystem", "Ecosystem", 80),
    ("package", "Package", 160),
    ("version", "Version", 100),
    ("fixed_version", "Fixed version", 120),
    ("component", "Component", 100),
]

PACKAGE_COLUMNS = [
    ("component", "Component", 100),
    ("package_and_version", "Package(s) & Version", 220),
    ("open_findings", "Open findings", 90),
    ("where_it_runs", "Where it runs", 220),
    ("justification", "Justification / Disposition", 280),
    ("risk_accepted_until", "Risk accepted until", 130),
]


class ComponentTab(ttk.Frame):
    def __init__(self, parent, name: str, on_change=None):
        super().__init__(parent, padding=10)
        self.component_name = name
        self.on_change = on_change or (lambda: None)
        self.findings: list = []
        self.total_packages = 0
        self.view_mode = "vuln"  # o "package"

        self.cdx_path = tk.StringVar()
        self.lock_path = tk.StringVar()
        self.toml_path = tk.StringVar()
        self.use_toml_filter = tk.BooleanVar(value=False)
        self.use_toml_justification = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="Elegí al menos el package-lock.json y presioná Ejecutar análisis.")

        self._build_file_pickers()
        self._build_run_button()
        self._build_summary_panel()
        self._build_table()
        self._build_status_bar()

    # --- construcción de widgets -------------------------------------------------

    def _build_file_pickers(self):
        frame = ttk.LabelFrame(self, text=f"Archivos de entrada — {self.component_name}")
        frame.pack(fill="x", pady=(0, 8))
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="CDX json (referencia, no se usa para escanear):").grid(
            row=0, column=0, sticky="w", padx=4, pady=4
        )
        ttk.Entry(frame, textvariable=self.cdx_path).grid(row=0, column=1, sticky="ew", padx=4, pady=4)
        ttk.Button(frame, text="Elegir...", command=self._pick_cdx).grid(row=0, column=2, padx=4, pady=4)

        ttk.Label(frame, text="package-lock.json:").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(frame, textvariable=self.lock_path).grid(row=1, column=1, sticky="ew", padx=4, pady=4)
        ttk.Button(frame, text="Elegir...", command=self._pick_lock).grid(row=1, column=2, padx=4, pady=4)

        ttk.Label(frame, text="osv-scanner.toml (opcional):").grid(row=2, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(frame, textvariable=self.toml_path).grid(row=2, column=1, sticky="ew", padx=4, pady=4)
        ttk.Button(frame, text="Elegir...", command=self._pick_toml).grid(row=2, column=2, padx=4, pady=4)

        toml_opts = ttk.Frame(frame)
        toml_opts.grid(row=3, column=0, columnspan=3, sticky="w", padx=4, pady=(0, 4))
        ttk.Checkbutton(
            toml_opts, text="Usarlo como filtro (reduce el conteo de vulnerabilidades)",
            variable=self.use_toml_filter,
        ).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(
            toml_opts, text="Usarlo como justificación en la tabla (no filtra nada)",
            variable=self.use_toml_justification,
        ).pack(side="left")

    def _build_run_button(self):
        ttk.Button(self, text="Ejecutar análisis", command=self._run).pack(anchor="w", pady=(0, 8))

    def _build_summary_panel(self):
        frame = ttk.LabelFrame(self, text="Resumen")
        frame.pack(fill="x", pady=(0, 8))

        self.packages_var = tk.StringVar(value="Paquetes escaneados: -")
        self.affected_var = tk.StringVar(value="Paquetes afectados: -")
        self.total_var = tk.StringVar(value="Vulnerabilidades: -")
        ttk.Label(frame, textvariable=self.packages_var).grid(row=0, column=0, sticky="w", padx=8, pady=4)
        ttk.Label(frame, textvariable=self.total_var).grid(row=0, column=1, sticky="w", padx=8, pady=4)
        ttk.Label(frame, textvariable=self.affected_var).grid(row=0, column=2, sticky="w", padx=8, pady=4)

        self.severity_vars: dict[str, tk.StringVar] = {}
        for i, sev in enumerate(SEVERITY_ORDER):
            var = tk.StringVar(value=f"{sev}: -")
            self.severity_vars[sev] = var
            ttk.Label(frame, textvariable=var).grid(row=1, column=i, sticky="w", padx=8, pady=4)

    def _build_table(self):
        # Esta barra va siempre pegada arriba de la tabla (no después, donde en una
        # ventana chica podía quedar fuera de la vista con mucho contenido arriba).
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", pady=(0, 4))
        self.toggle_button = ttk.Button(
            toolbar, text="Ver por paquete", command=self._toggle_view_mode
        )
        self.toggle_button.pack(side="left")
        ttk.Label(toolbar, text="  |  ").pack(side="left")
        ttk.Button(toolbar, text="Exportar a Excel (.xlsx)", command=self._export_xlsx).pack(side="left", padx=(0, 8))
        ttk.Button(toolbar, text="Exportar a CSV", command=self._export_csv).pack(side="left")
        ttk.Label(toolbar, text="  |  Clic derecho o Ctrl/Cmd+C para copiar.", foreground="#777").pack(side="left")

        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, pady=(0, 8))

        self.tree = ttk.Treeview(frame, show="headings", selectmode="extended")
        self._set_tree_columns(VULN_COLUMNS)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self._build_copy_support()

    def _set_tree_columns(self, columns_spec):
        keys = [c[0] for c in columns_spec]
        self.tree["columns"] = keys
        for key, title, width in columns_spec:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w")

    # --- copiar al portapapeles --------------------------------------------------

    def _build_copy_support(self):
        self.tree.bind("<Control-c>", lambda e: self._copy_selection())
        self.tree.bind("<Command-c>", lambda e: self._copy_selection())

        menu = tk.Menu(self.tree, tearoff=False)
        menu.add_command(label="Copiar selección", command=self._copy_selection)
        menu.add_command(label="Copiar todo", command=self._copy_all)

        def show_menu(event):
            row = self.tree.identify_row(event.y)
            if row and row not in self.tree.selection():
                self.tree.selection_set(row)
            menu.tk_popup(event.x_root, event.y_root)

        self.tree.bind("<Button-3>", show_menu)      # clic derecho (Windows/Linux)
        self.tree.bind("<Button-2>", show_menu)      # clic derecho en algunos mouse de Mac
        self.tree.bind("<Control-Button-1>", show_menu)  # Mac sin botón derecho físico

    def _rows_as_tsv(self, item_ids) -> str:
        headers = [self.tree.heading(col)["text"] for col in self.tree["columns"]]
        lines = ["\t".join(headers)]
        for item_id in item_ids:
            values = self.tree.item(item_id, "values")
            lines.append("\t".join(str(v) for v in values))
        return "\n".join(lines)

    def _copy_selection(self):
        selected = self.tree.selection()
        if not selected:
            return
        self._copy_to_clipboard(self._rows_as_tsv(selected))

    def _copy_all(self):
        self._copy_to_clipboard(self._rows_as_tsv(self.tree.get_children()))

    def _copy_to_clipboard(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status.set("Copiado al portapapeles.")

    def _build_status_bar(self):
        ttk.Label(self, textvariable=self.status, foreground="#555").pack(anchor="w")

    # --- selección de archivos ----------------------------------------------------

    def _pick_cdx(self):
        path = filedialog.askopenfilename(title="Elegir CDX json", filetypes=[("JSON", "*.json"), ("Todos", "*.*")])
        if path:
            self.cdx_path.set(path)

    def _pick_lock(self):
        path = filedialog.askopenfilename(
            title="Elegir package-lock.json", filetypes=[("JSON", "*.json"), ("Todos", "*.*")]
        )
        if path:
            self.lock_path.set(path)

    def _pick_toml(self):
        path = filedialog.askopenfilename(
            title="Elegir osv-scanner.toml", filetypes=[("TOML", "*.toml"), ("Todos", "*.*")]
        )
        if path:
            self.toml_path.set(path)

    # --- ejecución del escaneo ------------------------------------------------------

    def _run(self):
        toml = self.toml_path.get().strip() or None
        self.status.set("Ejecutando osv-scanner...")
        self.update_idletasks()

        try:
            findings, total_packages = run_scan(
                self.lock_path.get().strip(), toml,
                self.use_toml_filter.get(), self.use_toml_justification.get(),
                self.component_name,
            )
        except OsvScanError as exc:
            messagebox.showerror("Error al ejecutar el análisis", str(exc))
            self.status.set("Falló el último análisis. Revisá los archivos seleccionados.")
            return

        self.findings = findings
        self.total_packages = total_packages
        self._refresh_table()
        self._refresh_summary()
        self.status.set(f"Análisis completo. {len(findings)} vulnerabilidades en {total_packages} paquetes.")
        self.on_change()

    def _refresh_summary(self):
        affected = len({(f.package, f.version) for f in self.findings})
        self.packages_var.set(f"Paquetes escaneados: {self.total_packages}")
        self.total_var.set(f"Vulnerabilidades: {len(self.findings)}")
        self.affected_var.set(f"Paquetes afectados: {affected}")
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        for sev, var in self.severity_vars.items():
            var.set(f"{sev}: {counts[sev]}")

    def _toggle_view_mode(self):
        if self.view_mode == "vuln":
            self.view_mode = "package"
            self.toggle_button.config(text="Ver por vulnerabilidad")
        else:
            self.view_mode = "vuln"
            self.toggle_button.config(text="Ver por paquete")
        self._refresh_table()

    def _refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        if self.view_mode == "vuln":
            self._set_tree_columns(VULN_COLUMNS)
            for finding in self.findings:
                self.tree.insert("", "end", values=(
                    finding.cve, finding.published, finding.osv_url, finding.cvss_display,
                    finding.severity, finding.ecosystem, finding.package, finding.version,
                    finding.fixed_version, finding.component,
                ))
        else:
            self._set_tree_columns(PACKAGE_COLUMNS)
            for row in group_by_package(self.findings):
                self.tree.insert("", "end", values=(
                    row.component, row.package_and_version, row.open_findings,
                    row.where_it_runs, row.justification, row.risk_accepted_until,
                ))

    # --- exportación -----------------------------------------------------------------

    def _export_xlsx(self):
        if not self._check_has_findings():
            return
        path = filedialog.asksaveasfilename(
            title="Exportar a Excel", defaultextension=".xlsx",
            initialfile=f"{self.component_name}_vulnerabilities.xlsx",
            filetypes=[("Excel", "*.xlsx")],
        )
        if not path:
            return
        try:
            export_xlsx(self.findings, path)
        except ImportError:
            messagebox.showerror(
                "Falta una dependencia",
                "Para exportar a Excel instalá openpyxl:\n\npip install -r requirements.txt",
            )
            return
        self.status.set(f"Exportado a {path}")

    def _export_csv(self):
        if not self._check_has_findings():
            return
        path = filedialog.asksaveasfilename(
            title="Exportar a CSV", defaultextension=".csv",
            initialfile=f"{self.component_name}_vulnerabilities.csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not path:
            return
        export_csv(self.findings, path)
        self.status.set(f"Exportado a {path}")

    def _check_has_findings(self) -> bool:
        if not self.findings:
            messagebox.showinfo("Nada para exportar", "Ejecutá el análisis primero.")
            return False
        return True


ICON_PATH = Path(__file__).resolve().parent.parent / "assets" / "icon.png"


class App(tk.Tk):
    def _set_icon(self):
        """Ícono de la ventana / barra de tareas / Dock."""
        try:
            self._icon = tk.PhotoImage(file=str(ICON_PATH))
            self.iconphoto(True, self._icon)
        except tk.TclError:
            pass

    def __init__(self):
        super().__init__()
        self.title("SBOM Vulnerability Report — osv-scanner")
        self.geometry("1200x800")
        self.minsize(900, 600)
        self._set_icon()

        toolbar = ttk.Frame(self, padding=(10, 8))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="+ Agregar pestaña", command=self._add_tab_dialog).pack(side="left")
        ttk.Button(toolbar, text="Cerrar pestaña actual", command=self._close_current_tab).pack(side="left", padx=(8, 0))

        self._build_global_summary()

        self.empty_label = ttk.Label(
            self,
            text='No hay pestañas todavía. Usá "+ Agregar pestaña" y ponele el nombre que quieras '
                 "(el componente que estés analizando en este proyecto).",
            foreground="#777", padding=20,
        )

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._update_empty_state()

    def _build_global_summary(self):
        frame = ttk.LabelFrame(self, text="Resumen global (todas las pestañas)", padding=8)
        frame.pack(fill="x", padx=10, pady=(0, 4))

        self.global_packages_var = tk.StringVar(value="Paquetes escaneados: -")
        self.global_affected_var = tk.StringVar(value="Paquetes afectados: -")
        self.global_total_var = tk.StringVar(value="Vulnerabilidades: -")
        ttk.Label(frame, textvariable=self.global_packages_var).grid(row=0, column=0, sticky="w", padx=8, pady=2)
        ttk.Label(frame, textvariable=self.global_total_var).grid(row=0, column=1, sticky="w", padx=8, pady=2)
        ttk.Label(frame, textvariable=self.global_affected_var).grid(row=0, column=2, sticky="w", padx=8, pady=2)

        self.global_severity_vars: dict[str, tk.StringVar] = {}
        for i, sev in enumerate(SEVERITY_ORDER):
            var = tk.StringVar(value=f"{sev}: -")
            self.global_severity_vars[sev] = var
            ttk.Label(frame, textvariable=var).grid(row=1, column=i, sticky="w", padx=8, pady=2)

    def _recompute_global_summary(self):
        tabs = [self.notebook.nametowidget(t) for t in self.notebook.tabs()]
        total_packages = sum(tab.total_packages for tab in tabs)
        all_findings = [f for tab in tabs for f in tab.findings]
        affected = len({(f.package, f.version, f.component) for f in all_findings})

        self.global_packages_var.set(f"Paquetes escaneados: {total_packages}")
        self.global_total_var.set(f"Vulnerabilidades: {len(all_findings)}")
        self.global_affected_var.set(f"Paquetes afectados: {affected}")

        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in all_findings:
            counts[finding.severity] += 1
        for sev, var in self.global_severity_vars.items():
            var.set(f"{sev}: {counts[sev]}")

    def _add_tab(self, name: str):
        tab = ComponentTab(self.notebook, name, on_change=self._recompute_global_summary)
        self.notebook.add(tab, text=name)
        self.notebook.select(tab)
        self._update_empty_state()

    def _add_tab_dialog(self):
        name = simpledialog.askstring("Nueva pestaña", "Nombre de esta pestaña (el componente que vas a analizar):")
        if name and name.strip():
            self._add_tab(name.strip())

    def _close_current_tab(self):
        current = self.notebook.select()
        if not current:
            return
        self.notebook.forget(current)
        self._update_empty_state()
        self._recompute_global_summary()

    def _update_empty_state(self):
        if self.notebook.tabs():
            self.empty_label.pack_forget()
        else:
            self.empty_label.pack(fill="x")
