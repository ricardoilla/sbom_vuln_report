"""Agrupa Finding(s) por paquete para la vista estilo 'remediation status'."""

from dataclasses import dataclass

from .models import Finding


@dataclass
class PackageRow:
    component: str
    package_and_version: str
    open_findings: int
    where_it_runs: str
    justification: str
    risk_accepted_until: str
    max_cvss: float


def group_by_package(findings: list[Finding]) -> list[PackageRow]:
    order: list[str] = []
    by_package: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.package not in by_package:
            by_package[finding.package] = []
            order.append(finding.package)
        by_package[finding.package].append(finding)

    rows: list[PackageRow] = []
    for package in order:
        items = by_package[package]
        versions = sorted({item.version for item in items})
        reasons = sorted({item.toml_reason for item in items if item.toml_reason})
        until_dates = sorted({item.toml_risk_accepted_until for item in items if item.toml_risk_accepted_until})
        cvss_values = [item.cvss for item in items if item.cvss is not None]

        rows.append(PackageRow(
            component=items[0].component,
            package_and_version=f"{package} {' / '.join(versions)}",
            open_findings=len(items),
            where_it_runs="",  # no se puede derivar de forma confiable del .toml; queda para completar a mano
            justification=" | ".join(reasons),
            risk_accepted_until=", ".join(until_dates),
            max_cvss=max(cvss_values) if cvss_values else -1.0,
        ))

    rows.sort(key=lambda r: r.max_cvss, reverse=True)
    return rows
