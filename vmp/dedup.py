"""Tool-agnostic fingerprints and deduplication."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from vmp.models import SEVERITY_ORDER, Finding

_PUNCT_RE = re.compile(r"[^\w\s-]+", re.UNICODE)
_SPACE_RE = re.compile(r"\s+")
_SLASH_RE = re.compile(r"/+")


def title_key(title: str) -> str:
    collapsed = _SPACE_RE.sub(" ", _PUNCT_RE.sub(" ", title.lower())).strip()
    return collapsed or "untitled"


def location_parts(location: str, parameter: str | None = None) -> tuple[str, str]:
    """Split a location into ``(asset, place)``.

    HTTP(S) URLs become ``(scheme://host[:port], path?param_names)``. Query
    values are dropped so two reports of the same parameter match even when
    the payload differs. Other strings are treated as file paths.
    """
    raw = (location or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        host = (parsed.hostname or "").lower()
        try:
            port = parsed.port
        except ValueError:
            port = None
        if (
            port is None
            or (parsed.scheme == "http" and port == 80)
            or (parsed.scheme == "https" and port == 443)
        ):
            origin = f"{parsed.scheme}://{host}"
        else:
            origin = f"{parsed.scheme}://{host}:{port}"
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        names = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name]
        if parameter and parameter not in names:
            names.append(parameter)
        unique = sorted(set(names))
        place = path if not unique else f"{path}?{'&'.join(unique)}"
        return origin, place

    place = raw.replace("\\", "/")
    place = _SLASH_RE.sub("/", place)
    if place.startswith("./"):
        place = place[2:]
    return "", place


def fingerprint(finding: Finding) -> str:
    """Stable key: CVE, else raw id, else CWE, else title, plus place.

    A GHSA, OSV, or ALAS id in ``raw_id`` is part of the key. Two advisories
    that share a CWE and a package stay distinct. The scanner name is not.
    """
    identity = finding.cve or finding.raw_id or finding.cwe or title_key(finding.title)
    origin, place = location_parts(finding.location, finding.parameter)
    if finding.component:
        asset = finding.component.lower()
        if finding.version:
            asset = f"{asset}@{finding.version}"
    else:
        asset = origin
    return f"{identity}|{asset}|{place}"


def _richness(finding: Finding) -> tuple[int, int, int, int]:
    return (
        SEVERITY_ORDER.get(finding.severity, 0),
        1 if finding.cvss_vector else 0,
        len(finding.description or ""),
        len(finding.references),
    )


def _other_vectors(group: list[Finding]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in group:
        for vector in item.other_cvss_vectors:
            if vector and vector not in seen:
                seen.add(vector)
                ordered.append(vector)
    return ordered


def _fill(target: Finding, others: list[Finding], attr: str) -> None:
    if getattr(target, attr):
        return
    for item in others:
        value = getattr(item, attr)
        if value:
            setattr(target, attr, value)
            return


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that share a fingerprint. First-seen order is kept."""
    groups: dict[str, list[Finding]] = {}
    order: list[str] = []
    for finding in findings:
        key = fingerprint(finding)
        if key not in groups:
            order.append(key)
            groups[key] = []
        groups[key].append(finding)

    merged: list[Finding] = []
    for key in order:
        group = groups[key]
        ranked = sorted(group, key=_richness, reverse=True)
        base = ranked[0]
        sources = sorted({source for item in group for source in item.sources})
        references = sorted({ref for item in group for ref in item.references if ref})
        result = Finding(
            title=base.title,
            severity=base.severity,
            tool=base.tool,
            location=base.location,
            cve=base.cve,
            cwe=base.cwe,
            component=base.component,
            version=base.version,
            fixed_version=base.fixed_version,
            description=base.description,
            remediation=base.remediation,
            cvss_vector=base.cvss_vector,
            cvss_score=base.cvss_score,
            other_cvss_vectors=_other_vectors(group),
            parameter=base.parameter,
            references=references,
            raw_id=base.raw_id,
            sources=sources,
            duplicate_count=len(group),
        )
        for attr in (
            "cve",
            "cwe",
            "component",
            "version",
            "fixed_version",
            "description",
            "remediation",
            "cvss_vector",
            "parameter",
            "raw_id",
        ):
            _fill(result, ranked[1:], attr)
        if result.cvss_score is None:
            for item in ranked[1:]:
                if item.cvss_score is not None:
                    result.cvss_score = item.cvss_score
                    break
        merged.append(result)
    return merged
