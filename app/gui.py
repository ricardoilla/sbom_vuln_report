"""Interfaz Tkinter: una pestaña por componente (App, Backend, Admin Panel, ...)."""

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from .export import export_csv, export_xlsx
from .models import SEVERITY_ORDER
from .osv_runner import OsvScanError, run_scan

COLUMNS = [
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


class ComponentTab(ttk.Frame):
    def __init__(self, parent, name: str):
        super().__init__(parent, padding=10)
        self.component_name = name
        self.findings: list = []

        self.cdx_path = tk.StringVar()
        self.lock_path = tk.StringVar()
        self.toml_path = tk.StringVar()
        self.use_toml = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Elegí al menos el package-lock.json y presioná Ejecutar análisis.")

        self._build_file_pickers()
        self._build_run_button()
        self._build_summary_panel()
        self._build_table()
        self._build_export_buttons()
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

        ttk.Checkbutton(
            frame, text="Usar osv-scanner.toml (si no, se ignora)", variable=self.use_toml
        ).grid(row=2, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(frame, textvariable=self.toml_path).grid(row=2, column=1, sticky="ew", padx=4, pady=4)
        ttk.Button(frame, text="Elegir...", command=self._pick_toml).grid(row=2, column=2, padx=4, pady=4)

    def _build_run_button(self):
        ttk.Button(self, text="Ejecutar análisis", command=self._run).pack(anchor="w", pady=(0, 8))

    def _build_summary_panel(self):
        frame = ttk.LabelFrame(self, text="Resumen")
        frame.pack(fill="x", pady=(0, 8))

        self.packages_var = tk.StringVar(value="Paquetes escaneados: -")
        self.total_var = tk.StringVar(value="Vulnerabilidades: -")
        ttk.Label(frame, textvariable=self.packages_var).grid(row=0, column=0, sticky="w", padx=8, pady=4)
        ttk.Label(frame, textvariable=self.total_var).grid(row=0, column=1, sticky="w", padx=8, pady=4)

        self.severity_vars: dict[str, tk.StringVar] = {}
        for i, sev in enumerate(SEVERITY_ORDER):
            var = tk.StringVar(value=f"{sev}: -")
            self.severity_vars[sev] = var
            ttk.Label(frame, textvariable=var).grid(row=1, column=i, sticky="w", padx=8, pady=4)

    def _build_table(self):
        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, pady=(0, 8))

        columns = [c[0] for c in COLUMNS]
        self.tree = ttk.Treeview(frame, columns=columns, show="headings")
        for key, title, width in COLUMNS:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

    def _build_export_buttons(self):
        frame = ttk.Frame(self)
        frame.pack(fill="x", pady=(0, 4))
        ttk.Button(frame, text="Exportar a Excel (.xlsx)", command=self._export_xlsx).pack(side="left", padx=(0, 8))
        ttk.Button(frame, text="Exportar a CSV", command=self._export_csv).pack(side="left")

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
            self.use_toml.set(True)

    # --- ejecución del escaneo ------------------------------------------------------

    def _run(self):
        toml = self.toml_path.get().strip() if self.use_toml.get() else None
        self.status.set("Ejecutando osv-scanner...")
        self.update_idletasks()

        try:
            findings, total_packages = run_scan(self.lock_path.get().strip(), toml, self.component_name)
        except OsvScanError as exc:
            messagebox.showerror("Error al ejecutar el análisis", str(exc))
            self.status.set("Falló el último análisis. Revisá los archivos seleccionados.")
            return

        self.findings = findings
        self._refresh_table()
        self._refresh_summary(total_packages)
        self.status.set(f"Análisis completo. {len(findings)} vulnerabilidades en {total_packages} paquetes.")

    def _refresh_summary(self, total_packages: int):
        self.packages_var.set(f"Paquetes escaneados: {total_packages}")
        self.total_var.set(f"Vulnerabilidades: {len(self.findings)}")
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        for sev, var in self.severity_vars.items():
            var.set(f"{sev}: {counts[sev]}")

    def _refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        for finding in self.findings:
            self.tree.insert("", "end", values=(
                finding.cve, finding.published, finding.osv_url, finding.cvss_display,
                finding.severity, finding.ecosystem, finding.package, finding.version,
                finding.fixed_version, finding.component,
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


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SBOM Vulnerability Report — osv-scanner")
        self.geometry("1150x650")

        toolbar = ttk.Frame(self, padding=(10, 8))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="+ Agregar pestaña", command=self._add_tab_dialog).pack(side="left")
        ttk.Button(toolbar, text="Cerrar pestaña actual", command=self._close_current_tab).pack(side="left", padx=(8, 0))

        self.empty_label = ttk.Label(
            self,
            text='No hay pestañas todavía. Usá "+ Agregar pestaña" y ponele el nombre que quieras '
                 "(el componente que estés analizando en este proyecto).",
            foreground="#777", padding=20,
        )

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._update_empty_state()

    def _add_tab(self, name: str):
        tab = ComponentTab(self.notebook, name)
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

    def _update_empty_state(self):
        if self.notebook.tabs():
            self.empty_label.pack_forget()
        else:
            self.empty_label.pack(fill="x")
