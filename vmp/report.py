"""CSV, Markdown, and HTML exports for developers."""

from __future__ import annotations

import csv
import html
from pathlib import Path

from vmp.dedup import fingerprint
from vmp.models import Finding

CSV_COLUMNS = [
    "rank",
    "risk_score",
    "risk_band",
    "scanner_severity",
    "fingerprint",
    "title",
    "cve",
    "cwe",
    "cvss_score",
    "cvss_vector",
    "cvss_source",
    "epss",
    "epss_percentile",
    "epss_status",
    "kev",
    "exposure",
    "component",
    "version",
    "fixed_version",
    "location",
    "parameter",
    "tools",
    "duplicate_count",
    "remediation",
]


def _csv_safe(value: object) -> str:
    """Prefix spreadsheet formula characters so Excel treats the cell as text."""
    text = "" if value is None else str(value)
    if text and text[0] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


def _fmt_score(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:.2f}"


def _fmt_epss(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:.5f}"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -(finding.risk_score or 0),
            -(finding.cvss_score or 0),
            finding.cve or "zzz",
            fingerprint(finding),
        ),
    )


def _row(rank: int, finding: Finding) -> dict[str, str]:
    breakdown = finding.score_breakdown or {}
    return {
        "rank": str(rank),
        "risk_score": _fmt_score(finding.risk_score),
        "risk_band": finding.risk_band or "",
        "scanner_severity": finding.severity,
        "fingerprint": fingerprint(finding),
        "title": finding.title,
        "cve": finding.cve or "",
        "cwe": finding.cwe or "",
        "cvss_score": _fmt_score(finding.cvss_score),
        "cvss_vector": finding.cvss_vector or "",
        "cvss_source": str(breakdown.get("cvss_source") or ""),
        "epss": _fmt_epss(finding.epss),
        "epss_percentile": _fmt_epss(finding.epss_percentile),
        "epss_status": finding.epss_status,
        "kev": "yes" if finding.kev else "no",
        "exposure": finding.exposure,
        "component": finding.component or "",
        "version": finding.version or "",
        "fixed_version": finding.fixed_version or "",
        "location": finding.location,
        "parameter": finding.parameter or "",
        "tools": ",".join(finding.sources),
        "duplicate_count": str(finding.duplicate_count),
        "remediation": finding.remediation,
    }


def write_csv(findings: list[Finding], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for rank, finding in enumerate(findings, start=1):
            writer.writerow({key: _csv_safe(value) for key, value in _row(rank, finding).items()})


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        band = finding.risk_band or "info"
        counts[band] = counts.get(band, 0) + 1
    return counts


def _md_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _note(finding: Finding) -> str:
    if finding.epss_status == "not_applicable":
        return (
            "EPSS and KEV are CVE catalogs. This finding has no CVE, so those "
            "terms are zero. A lower rank is not a reason to ignore an "
            "internet-facing issue the scanner confirmed."
        )
    if finding.epss_status == "unknown":
        return "EPSS was not available (cache miss or lookup failure). That term contributed 0."
    if finding.kev:
        return "Listed in the CISA Known Exploited Vulnerabilities catalog."
    return "Not listed in the bundled or fetched KEV snapshot."


def render_markdown(findings: list[Finding]) -> str:
    counts = _counts(findings)
    lines = [
        "# Vulnerability priority report",
        "",
        "Scanner severity and the risk band are different columns. "
        "The band is the priority score below, not the scanner's own label.",
        "",
        "## Summary",
        "",
        f"- Findings after deduplication: {len(findings)}",
        f"- Critical: {counts['critical']}",
        f"- High: {counts['high']}",
        f"- Medium: {counts['medium']}",
        f"- Low: {counts['low']}",
        f"- Info: {counts['info']}",
        "",
        "Score = 0.45·CVSS + 0.25·EPSS + 0.20·KEV + 0.10·exposure, "
        "on a 0–100 scale. Known-exploited CVEs are raised to at least 80.",
        "",
        "## Queue",
        "",
        "| Rank | Score | Band | ID | Component | Location | Tools |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for rank, finding in enumerate(findings, start=1):
        lines.append(
            "| "
            + " | ".join(
                [
                    str(rank),
                    _fmt_score(finding.risk_score),
                    _md_cell(finding.risk_band),
                    _md_cell(finding.display_id),
                    _md_cell(finding.component_label),
                    _md_cell(finding.location),
                    _md_cell(",".join(finding.sources)),
                ]
            )
            + " |"
        )
    lines.extend(["", "## Findings", ""])
    for rank, finding in enumerate(findings, start=1):
        breakdown = finding.score_breakdown or {}
        lines.append(f"### {rank}. {finding.title}")
        lines.append("")
        lines.append(f"- ID: {finding.display_id}")
        lines.append(f"- Risk: {_fmt_score(finding.risk_score)} ({finding.risk_band})")
        lines.append(f"- Scanner severity: {finding.severity}")
        lines.append(
            f"- CVSS base: {_fmt_score(finding.cvss_score)} ({breakdown.get('cvss_source', '')})"
        )
        if finding.cvss_vector:
            lines.append(f"- CVSS vector: `{finding.cvss_vector}`")
        if finding.other_cvss_vectors:
            kept = ", ".join(f"`{item}`" for item in finding.other_cvss_vectors)
            lines.append(f"- Other CVSS vectors kept: {kept}")
        lines.append(
            f"- EPSS: {_fmt_epss(finding.epss) or 'n/a'} "
            f"(percentile {_fmt_epss(finding.epss_percentile) or 'n/a'}, {finding.epss_status})"
        )
        kev = "yes" if finding.kev else "no"
        if finding.kev_name:
            kev = f"{kev} ({finding.kev_name})"
        lines.append(f"- KEV: {kev}")
        lines.append(f"- Exposure: {finding.exposure}")
        if finding.component_label:
            lines.append(f"- Component: {finding.component_label}")
        lines.append(f"- Location: {finding.location}")
        if finding.parameter:
            lines.append(f"- Parameter: {finding.parameter}")
        tools = ", ".join(finding.sources)
        lines.append(f"- Tools: {tools} (reports merged: {finding.duplicate_count})")
        if finding.remediation:
            lines.append(f"- Remediation: {finding.remediation}")
        lines.append(f"- Note: {_note(finding)}")
        if finding.description:
            lines.append("")
            lines.append(finding.description.strip())
        lines.append("")
    lines.append("Generated by vmp. Scan only systems you own or isolated lab targets.")
    lines.append("")
    return "\n".join(lines)


def render_html(findings: list[Finding]) -> str:
    counts = _counts(findings)
    rows = []
    for rank, finding in enumerate(findings, start=1):
        rows.append(
            "<tr>"
            f"<td>{rank}</td>"
            f"<td>{html.escape(_fmt_score(finding.risk_score))}</td>"
            f"<td>{html.escape(finding.risk_band or '')}</td>"
            f"<td>{html.escape(finding.display_id)}</td>"
            f"<td>{html.escape(finding.component_label)}</td>"
            f"<td>{html.escape(finding.location)}</td>"
            f"<td>{html.escape(', '.join(finding.sources))}</td>"
            f"<td>{html.escape(finding.remediation)}</td>"
            "</tr>"
        )
    body = "\n".join(rows)
    summary = (
        f"{len(findings)} findings after deduplication. "
        f"Critical {counts['critical']}, high {counts['high']}, "
        f"medium {counts['medium']}, low {counts['low']}, info {counts['info']}."
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vulnerability priority report</title>
<style>
  body {{ font-family: sans-serif; margin: 2rem; color: #1c1c1c; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{
    border-bottom: 1px solid #ddd;
    text-align: left;
    padding: 0.4rem;
    vertical-align: top;
  }}
  th {{ background: #f4f4f4; }}
</style>
</head>
<body>
<h1>Vulnerability priority report</h1>
<p>{html.escape(summary)}</p>
<p>Score = 0.45·CVSS + 0.25·EPSS + 0.20·KEV + 0.10·exposure. Known-exploited CVEs floor at 80.</p>
<table>
<thead>
<tr><th>Rank</th><th>Score</th><th>Band</th><th>ID</th><th>Component</th><th>Location</th><th>Tools</th><th>Remediation</th></tr>
</thead>
<tbody>
{body}
</tbody>
</table>
</body>
</html>
"""


def write_reports(findings: list[Finding], out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ordered = sort_findings(findings)
    csv_path = out_dir / "findings.csv"
    md_path = out_dir / "report.md"
    html_path = out_dir / "report.html"
    write_csv(ordered, csv_path)
    md_path.write_text(render_markdown(ordered), encoding="utf-8")
    html_path.write_text(render_html(ordered), encoding="utf-8")
    return {"csv": csv_path, "markdown": md_path, "html": html_path}
