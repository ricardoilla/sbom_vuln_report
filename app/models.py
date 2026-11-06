"""Tipos de datos compartidos por el escaneo y la UI."""

from dataclasses import dataclass

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]


def severity_bucket(cvss: float | None) -> str:
    """Mismo criterio usado en todo el proyecto: Critical >=9, High 7-8.9,
    Medium 4-6.9, Low 0.1-3.9, Unknown si no hay score."""
    if cvss is None:
        return "Unknown"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0.0:
        return "Low"
    return "Unknown"


@dataclass
class Finding:
    cve: str
    published: str
    osv_url: str
    cvss: float | None
    severity: str
    ecosystem: str
    package: str
    version: str
    fixed_version: str
    component: str
    # Si el finding aparece en el .toml de excepciones, su "reason" e "ignoreUntil".
    # Vacío si no hay .toml o si ese finding en particular no está ahí.
    toml_reason: str = ""
    toml_risk_accepted_until: str = ""

    @property
    def cvss_display(self) -> str:
        return f"{self.cvss:.1f}" if self.cvss is not None else "-"
