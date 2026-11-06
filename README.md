# SBOM Vulnerability Report

Interfaz de escritorio (Tkinter) para correr [osv-scanner](https://github.com/google/osv-scanner)
sobre uno o varios componentes (App, Backend, Admin Panel, ...) y ver/exportar el
detalle de vulnerabilidades.

## Requisitos

- Python 3.10+
- [osv-scanner](https://github.com/google/osv-scanner) instalado y en el `PATH`:
  ```bash
  brew install osv-scanner
  ```
- Dependencias de Python (solo para exportar a Excel):
  ```bash
  pip install -r requirements.txt
  ```

## Uso

```bash
python3 main.py
```

La app abre con 3 pestañas por defecto: **App**, **Backend**, **Admin Panel**.
Podés agregar más con "+ Agregar pestaña" o cerrar la actual.

En cada pestaña:

1. Elegí el `package-lock.json` del componente (obligatorio — es lo que escanea osv-scanner).
2. Opcionalmente, elegí el CDX json (solo como referencia; osv-scanner no lo usa para escanear).
3. Si querés que se respete el `osv-scanner.toml` de excepciones del equipo, tildá la
   casilla y elegilo. Si la dejás destildada, el análisis es el resultado **crudo**,
   sin aplicar ninguna excepción.
4. "Ejecutar análisis". Abajo vas a ver:
   - Paquetes escaneados y total de vulnerabilidades.
   - Desglose por severidad (Critical / High / Medium / Low / Unknown).
   - La tabla detallada (CVE, Published, OSV URL, CVSS, Severity, Ecosystem,
     Package, Version, Fixed version, Component), ordenada de mayor a menor CVSS.
5. "Exportar a Excel (.xlsx)" o "Exportar a CSV" para guardar esa tabla.

## Estructura

- `main.py` — punto de entrada.
- `app/osv_runner.py` — corre `osv-scanner` como subproceso y parsea el JSON a `Finding`.
- `app/models.py` — el dataclass `Finding` y el criterio de severidad por CVSS.
- `app/export.py` — exportar a CSV / Excel.
- `app/gui.py` — la interfaz Tkinter (pestañas, tabla, botones).
