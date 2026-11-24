"""Parsers for Trivy JSON, OWASP ZAP JSON, and Nuclei JSONL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vmp.models import Finding

ZAP_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


class ParseError(ValueError):
    """The file is not a recognized scanner report."""


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        for item in value:
            text = _first_str(item)
            if text:
                return text
        return None
    text = str(value).strip()
    return text or None


def _cve_from_id(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip().upper()
    if text.startswith("CVE-"):
        return text
    return None


def _trivy_cvss(vuln: dict[str, Any]) -> tuple[str | None, float | None]:
    block = vuln.get("CVSS") or {}
    if not isinstance(block, dict):
        return None, None
    preferred = ("nvd", "ghsa", "redhat", "bitnami")
    vendors = [name for name in preferred if name in block]
    vendors.extend(name for name in block if name not in vendors)
    vector = None
    score = None
    for name in vendors:
        entry = block.get(name) or {}
        if not isinstance(entry, dict):
            continue
        if vector is None and entry.get("V3Vector"):
            vector = str(entry["V3Vector"])
        if score is None and entry.get("V3Score") is not None:
            try:
                score = float(entry["V3Score"])
            except (TypeError, ValueError):
                score = None
        if vector is not None:
            break
    return vector, score


def _remediation_for_package(component: str | None, version: str | None, fixed: str | None) -> str:
    label = component or "the component"
    if version:
        label = f"{label} {version}"
    if fixed:
        return f"Upgrade {label} to {fixed} or later."
    return f"No upstream fix is recorded for {label}. Remove it or reduce exposure."


def parse_trivy(data: dict[str, Any], *, source: str) -> list[Finding]:
    findings: list[Finding] = []
    results = data.get("Results") or []
    if not isinstance(results, list):
        return findings
    for result in results:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or data.get("ArtifactName") or "")
        vulns = result.get("Vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            vuln_id = _first_str(vuln.get("VulnerabilityID")) or ""
            cve = _cve_from_id(vuln_id)
            cwe = _first_str(_as_list(vuln.get("CweIDs")))
            component = _first_str(vuln.get("PkgName"))
            version = _first_str(vuln.get("InstalledVersion"))
            fixed = _first_str(vuln.get("FixedVersion"))
            vector, score = _trivy_cvss(vuln)
            location = _first_str(vuln.get("PkgPath")) or target
            references = [str(item) for item in _as_list(vuln.get("References")) if item]
            primary = _first_str(vuln.get("PrimaryURL"))
            if primary and primary not in references:
                references.insert(0, primary)
            title = _first_str(vuln.get("Title")) or vuln_id or "Trivy finding"
            description = _first_str(vuln.get("Description")) or ""
            findings.append(
                Finding(
                    title=title,
                    severity=str(vuln.get("Severity") or "unknown"),
                    tool="trivy",
                    location=location,
                    cve=cve,
                    cwe=cwe,
                    component=component,
                    version=version,
                    fixed_version=fixed,
                    description=description,
                    remediation=_remediation_for_package(component, version, fixed),
                    cvss_vector=vector,
                    cvss_score=score,
                    references=references,
                    raw_id=vuln_id or None,
                    sources=["trivy"],
                )
            )
    return findings


def _zap_sites(data: dict[str, Any]) -> list[dict[str, Any]]:
    sites = data.get("site")
    if isinstance(sites, dict):
        return [sites]
    if isinstance(sites, list):
        return [site for site in sites if isinstance(site, dict)]
    return []


def parse_zap(data: dict[str, Any], *, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for site in _zap_sites(data):
        site_name = str(site.get("@name") or site.get("name") or "")
        alerts = site.get("alerts") or []
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            title = _first_str(alert.get("alert")) or _first_str(alert.get("name")) or "ZAP alert"
            risk = str(alert.get("riskcode") if alert.get("riskcode") is not None else "")
            severity = ZAP_RISK.get(risk, str(alert.get("riskdesc") or "info").split()[0])
            cwe = _first_str(alert.get("cweid"))
            description = _first_str(alert.get("desc")) or ""
            remediation = _first_str(alert.get("solution")) or ""
            reference = _first_str(alert.get("reference")) or ""
            references = [line.strip() for line in reference.splitlines() if line.strip()]
            instances = alert.get("instances") or []
            if not isinstance(instances, list) or not instances:
                instances = [{"uri": site_name, "param": None}]
            for instance in instances:
                if not isinstance(instance, dict):
                    continue
                uri = _first_str(instance.get("uri")) or site_name
                param = _first_str(instance.get("param"))
                findings.append(
                    Finding(
                        title=title,
                        severity=severity,
                        tool="zap",
                        location=uri,
                        cwe=cwe,
                        description=description,
                        remediation=remediation,
                        parameter=param,
                        references=list(references),
                        raw_id=_first_str(alert.get("pluginid")),
                        sources=["zap"],
                    )
                )
    return findings


def _nuclei_objects(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    objects: list[dict[str, Any]] = []
    warnings: list[str] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            warnings.append(f"nuclei line {line_no}: {exc.msg}")
            continue
        if isinstance(data, dict):
            objects.append(data)
        else:
            warnings.append(f"nuclei line {line_no}: expected a JSON object")
    return objects, warnings


def parse_nuclei(text: str, *, source: str) -> tuple[list[Finding], list[str]]:
    objects, warnings = _nuclei_objects(text)
    findings: list[Finding] = []
    for data in objects:
        info = data.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        classification = info.get("classification") or {}
        if not isinstance(classification, dict):
            classification = {}
        cve = _cve_from_id(_first_str(classification.get("cve-id") or classification.get("cve_id")))
        cwe = _first_str(classification.get("cwe-id") or classification.get("cwe_id"))
        vector = _first_str(
            classification.get("cvss-metrics") or classification.get("cvss_metrics")
        )
        score = None
        raw_score = classification.get("cvss-score", classification.get("cvss_score"))
        if raw_score is not None and raw_score != "":
            try:
                score = float(raw_score)
            except (TypeError, ValueError):
                score = None
        location = _first_str(data.get("matched-at")) or _first_str(data.get("host")) or ""
        title = (
            _first_str(info.get("name")) or _first_str(data.get("template-id")) or "Nuclei finding"
        )
        remediation = _first_str(info.get("remediation")) or ""
        description = _first_str(info.get("description")) or ""
        reference = info.get("reference") or []
        references = [str(item) for item in _as_list(reference) if item]
        findings.append(
            Finding(
                title=title,
                severity=str(info.get("severity") or "unknown"),
                tool="nuclei",
                location=location,
                cve=cve,
                cwe=cwe,
                description=description,
                remediation=remediation,
                cvss_vector=vector,
                cvss_score=score,
                references=references,
                raw_id=_first_str(data.get("template-id")),
                sources=["nuclei"],
            )
        )
    return findings, warnings


def parse_scan(path: Path) -> tuple[list[Finding], list[str]]:
    """Parse one scanner file. Returns findings and non-fatal warnings."""
    text = path.read_text(encoding="utf-8-sig")
    source = path.name
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        findings, warnings = parse_nuclei(text, source=source)
        meaningful = [
            line for line in text.splitlines() if line.strip() and not line.startswith("#")
        ]
        if meaningful and not findings and not warnings:
            raise ParseError(f"{path}: unrecognized scan format") from None
        if meaningful and not findings and warnings:
            raise ParseError(f"{path}: invalid scan file ({warnings[0]})") from None
        return findings, warnings
    if not isinstance(data, dict):
        raise ParseError(f"{path}: expected a JSON object")
    if "Results" in data or "ArtifactName" in data:
        return parse_trivy(data, source=source), []
    if "site" in data:
        return parse_zap(data, source=source), []
    if "template-id" in data or "templateID" in data:
        return parse_nuclei(text, source=source)
    raise ParseError(f"{path}: unrecognized scan format")


def detect_tool(path: Path) -> str:
    """Return ``trivy``, ``zap``, or ``nuclei`` for a scanner file."""
    text = path.read_text(encoding="utf-8-sig")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "nuclei"
    if not isinstance(data, dict):
        raise ParseError(f"{path}: unrecognized scan format")
    if "Results" in data or "ArtifactName" in data:
        return "trivy"
    if "site" in data:
        return "zap"
    if "template-id" in data or "templateID" in data:
        return "nuclei"
    raise ParseError(f"{path}: unrecognized scan format")
