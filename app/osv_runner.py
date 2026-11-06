"""Ejecuta osv-scanner sobre un package-lock.json y devuelve Finding(s).

El .toml de excepciones es opcional y cumple dos roles independientes:
- Si apply_toml_filter=True, se copia junto al lockfile en un directorio
  temporal y osv-scanner lo aplica como filtro real (reduce el conteo).
- Se parsea siempre (si se indicó un path), para anotar cada Finding que
  matchee con su "reason"/"ignoreUntil" — eso alimenta la vista por paquete
  aunque el finding no se haya filtrado, que es el uso recomendado: escanear
  sin aplicar el filtro y mostrar la aceptación de riesgo como dato aparte.
"""

import json
import re
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

from .models import Finding, severity_bucket

_FOUND_PACKAGES_RE = re.compile(r"found (\d+) packages")


class OsvScanError(RuntimeError):
    pass


def _parse_toml_lookup(toml_path: str) -> dict[str, dict]:
    """Lee [[IgnoredVulns]] del .toml y devuelve {id: {"reason", "ignoreUntil"}}."""
    try:
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return {}

    lookup: dict[str, dict] = {}
    for entry in data.get("IgnoredVulns", []):
        vuln_id = entry.get("id")
        if not vuln_id:
            continue
        ignore_until = entry.get("ignoreUntil")
        lookup[vuln_id] = {
            "reason": entry.get("reason", "") or "",
            "ignoreUntil": ignore_until.isoformat() if hasattr(ignore_until, "isoformat") else str(ignore_until or ""),
        }
    return lookup


def _pick_fixed_version(installed: str, candidates: set[str]) -> str:
    """Si una advisory lista fixes de varias ramas mayores, nos quedamos con
    la que corresponde a la versión instalada (mismo criterio manual que se
    usó en todo el análisis); si no hay ninguna de esa rama, mostramos todas."""
    if not candidates:
        return "-"

    def major(v: str) -> str:
        return v.split(".")[0] if v else ""

    inst_major = major(installed)
    same_major = sorted(c for c in candidates if major(c) == inst_major)
    if same_major:
        return same_major[0]
    return ", ".join(sorted(candidates))


def run_scan(
    package_lock_path: str,
    toml_path: str | None,
    apply_toml_filter: bool,
    component: str,
) -> tuple[list[Finding], int]:
    """Corre osv-scanner y devuelve (findings ordenados por CVSS desc, total de paquetes escaneados)."""
    if shutil.which("osv-scanner") is None:
        raise OsvScanError(
            "No se encontró 'osv-scanner' en el PATH. Instalalo con: brew install osv-scanner"
        )
    if not package_lock_path or not Path(package_lock_path).is_file():
        raise OsvScanError("Elegí un package-lock.json válido antes de ejecutar el análisis.")

    toml_lookup: dict[str, dict] = {}
    if toml_path:
        if not Path(toml_path).is_file():
            raise OsvScanError("El archivo .toml seleccionado no existe.")
        toml_lookup = _parse_toml_lookup(toml_path)

    with tempfile.TemporaryDirectory(prefix="osv_scan_") as tmp:
        tmp_dir = Path(tmp)
        tmp_lock = tmp_dir / "package-lock.json"
        shutil.copy(package_lock_path, tmp_lock)

        if toml_path and apply_toml_filter:
            shutil.copy(toml_path, tmp_dir / "osv-scanner.toml")

        out_path = tmp_dir / "result.json"
        proc = subprocess.run(
            [
                "osv-scanner", "scan", "source",
                "-L", str(tmp_lock),
                "--format", "json",
                "--output-file", str(out_path),
            ],
            capture_output=True,
            text=True,
        )

        # osv-scanner devuelve código 1 cuando encuentra vulnerabilidades; no es un error.
        if proc.returncode not in (0, 1):
            raise OsvScanError(f"osv-scanner falló (código {proc.returncode}):\n{proc.stderr.strip()}")
        if not out_path.exists():
            raise OsvScanError(f"osv-scanner no generó resultados:\n{proc.stderr.strip()}")

        data = json.loads(out_path.read_text())
        match = _FOUND_PACKAGES_RE.search(proc.stderr)
        total_packages = int(match.group(1)) if match else 0

    # .results[].packages[] de osv-scanner solo lista los paquetes CON hallazgos;
    # el total realmente escaneado se toma de la línea "found N packages" de stderr.
    findings: list[Finding] = []

    for result in data.get("results", []):
        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {})
            pkg_name = pkg_info.get("name", "-")
            pkg_version = pkg_info.get("version", "-")
            groups = pkg.get("groups", [])

            for vuln in pkg.get("vulnerabilities", []):
                vuln_id = vuln.get("id", "-")
                cve = next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), "-")
                published = (vuln.get("published") or "")[:10] or "-"

                group = next((g for g in groups if vuln_id in g.get("ids", [])), {})
                cvss_raw = group.get("max_severity")
                try:
                    cvss = float(cvss_raw) if cvss_raw not in (None, "?", "") else None
                except ValueError:
                    cvss = None

                fixed_candidates = {
                    event["fixed"]
                    for affected in vuln.get("affected", [])
                    if affected.get("package", {}).get("name") == pkg_name
                    for rng in affected.get("ranges", [])
                    for event in rng.get("events", [])
                    if "fixed" in event
                }

                toml_info = toml_lookup.get(vuln_id)
                if toml_info is None:
                    alias_match = next((a for a in vuln.get("aliases", []) if a in toml_lookup), None)
                    toml_info = toml_lookup.get(alias_match) if alias_match else None

                findings.append(Finding(
                    cve=cve,
                    published=published,
                    osv_url=f"https://osv.dev/{vuln_id}",
                    cvss=cvss,
                    severity=severity_bucket(cvss),
                    ecosystem=pkg_info.get("ecosystem", "-"),
                    package=pkg_name,
                    version=pkg_version,
                    fixed_version=_pick_fixed_version(pkg_version, fixed_candidates),
                    component=component,
                    toml_reason=(toml_info or {}).get("reason", ""),
                    toml_risk_accepted_until=(toml_info or {}).get("ignoreUntil", ""),
                ))

    findings.sort(key=lambda f: f.cvss if f.cvss is not None else -1.0, reverse=True)
    return findings, total_packages
