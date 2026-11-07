# SBOM Vulnerability Report

Interfaz de escritorio (Tkinter) para correr [osv-scanner](https://github.com/google/osv-scanner)
sobre uno o varios componentes (App, Backend, Admin Panel, ...) y ver/exportar el
detalle de vulnerabilidades.

## Inicio rápido

```bash
./run.sh      # macOS / Linux
run.bat       # Windows (doble clic o desde cmd)
```

Eso crea el entorno virtual (`.venv`) la primera vez, instala las dependencias y abre la app.
Las siguientes veces solo la abre.

> Requiere Python 3.10+ y [osv-scanner](https://github.com/google/osv-scanner)
> (`brew install osv-scanner` en macOS; en Windows, descargá el binario desde
> [releases](https://github.com/google/osv-scanner/releases) y ponelo en el `PATH`).

### Manual (sin el script)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

## Uso

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
