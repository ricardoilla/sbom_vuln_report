"""Exportar la lista de Finding a CSV o Excel."""

import csv

HEADERS = [
    "CVE", "Published", "OSV URL", "CVSS", "Severity",
    "Ecosystem", "Package", "Version", "Fixed version", "Component",
]


def _row(finding) -> list:
    return [
        finding.cve, finding.published, finding.osv_url, finding.cvss_display,
        finding.severity, finding.ecosystem, finding.package, finding.version,
        finding.fixed_version, finding.component,
    ]


def export_csv(findings, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)
        for finding in findings:
            writer.writerow(_row(finding))


def export_xlsx(findings, path: str) -> None:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"
    ws.append(HEADERS)
    for finding in findings:
        ws.append(_row(finding))

    for col_idx, header in enumerate(HEADERS, start=1):
        column_letter = ws.cell(row=1, column=col_idx).column_letter
        ws.column_dimensions[column_letter].width = max(12, len(header) + 2)

    wb.save(path)
