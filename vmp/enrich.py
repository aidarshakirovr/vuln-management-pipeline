"""EPSS and CISA KEV enrichment with a local cache and soft failures."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from vmp.models import Finding

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "vmp/0.1 (lab vulnerability management; +https://www.first.org/epss/)"
CACHE_TTL = timedelta(hours=24)
EPSS_BATCH = 100


class EnrichmentError(Exception):
    """A remote catalog could not be read. Callers fall back to cache."""


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _get_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise EnrichmentError(str(exc)) from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnrichmentError(f"invalid JSON from {url}") from exc
    if not isinstance(data, dict):
        raise EnrichmentError(f"unexpected payload from {url}")
    return data


def _fresh(payload: dict[str, Any] | None, now: datetime) -> bool:
    if not payload:
        return False
    fetched = _parse_time(str(payload.get("fetched_at") or ""))
    if fetched is None:
        return False
    return now - fetched <= CACHE_TTL


def _epss_scores(payload: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not payload:
        return {}
    scores = payload.get("scores") or {}
    if not isinstance(scores, dict):
        return {}
    return {str(key).upper(): value for key, value in scores.items() if isinstance(value, dict)}


def _kev_entries(payload: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not payload:
        return {}
    entries = payload.get("vulnerabilities") or {}
    if not isinstance(entries, dict):
        return {}
    return {str(key).upper(): value for key, value in entries.items() if isinstance(value, dict)}


def _fetch_epss(cves: list[str], timeout: float) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for start in range(0, len(cves), EPSS_BATCH):
        batch = cves[start : start + EPSS_BATCH]
        url = f"{EPSS_URL}?cve={','.join(batch)}"
        data = _get_json(url, timeout)
        if str(data.get("status", "")).upper() != "OK":
            raise EnrichmentError("EPSS API returned a non-OK status")
        rows = data.get("data") or []
        if not isinstance(rows, list):
            raise EnrichmentError("EPSS API returned an unexpected data field")
        for row in rows:
            if not isinstance(row, dict) or not row.get("cve"):
                continue
            try:
                epss = float(row["epss"])
                percentile = float(row.get("percentile") or 0)
            except (KeyError, TypeError, ValueError):
                continue
            if not 0 <= epss <= 1:
                continue
            found[str(row["cve"]).upper()] = {
                "epss": epss,
                "percentile": percentile,
                "date": row.get("date"),
            }
    return found


def _fetch_kev(timeout: float) -> tuple[dict[str, dict[str, Any]], str | None]:
    data = _get_json(KEV_URL, timeout)
    rows = data.get("vulnerabilities") or []
    if not isinstance(rows, list):
        raise EnrichmentError("KEV catalog is missing vulnerabilities")
    entries: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not row.get("cveID"):
            continue
        cve = str(row["cveID"]).upper()
        entries[cve] = {
            "vulnerability_name": row.get("vulnerabilityName"),
            "date_added": row.get("dateAdded"),
            "due_date": row.get("dueDate"),
            "known_ransomware_campaign_use": row.get("knownRansomwareCampaignUse"),
        }
    version = data.get("catalogVersion")
    return entries, str(version) if version else None


def _cves(findings: list[Finding]) -> list[str]:
    return sorted({finding.cve for finding in findings if finding.cve})


def enrich(
    findings: list[Finding],
    *,
    cache_dir: Path,
    offline: bool,
    timeout: float = 20.0,
    now: datetime | None = None,
) -> list[str]:
    """Fill EPSS and KEV fields. Network errors become warnings, not exceptions."""
    moment = now or _now()
    warnings: list[str] = []
    cache_dir = Path(cache_dir)
    epss_path = cache_dir / "epss.json"
    kev_path = cache_dir / "kev.json"
    cves = _cves(findings)

    epss_payload = _read_json(epss_path)
    kev_payload = _read_json(kev_path)
    epss_map = _epss_scores(epss_payload)
    kev_map = _kev_entries(kev_payload)
    kev_complete = bool(kev_payload and kev_payload.get("complete"))

    if not cves and not findings:
        return warnings

    missing_epss = [cve for cve in cves if cve not in epss_map]
    epss_is_fresh = _fresh(epss_payload, moment)
    if offline:
        if cves and epss_payload is None:
            warnings.append("EPSS cache is missing; scores stay unknown.")
        elif missing_epss:
            warnings.append("EPSS cache has no score for: " + ", ".join(missing_epss) + ".")
    elif cves and (missing_epss or not epss_is_fresh):
        try:
            fetched = _fetch_epss(cves, timeout)
            epss_map.update(fetched)
            _write_json(
                epss_path,
                {
                    "format": 1,
                    "source": EPSS_URL,
                    "fetched_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "scores": {key: epss_map[key] for key in sorted(epss_map)},
                },
            )
        except EnrichmentError as exc:
            warnings.append(f"EPSS lookup failed ({exc}). Using the local cache.")
            if not epss_map:
                warnings.append("EPSS cache is empty; those terms contribute 0.")

    need_kev = bool(cves)
    kev_is_fresh = _fresh(kev_payload, moment)
    if offline:
        if need_kev and kev_payload is None:
            warnings.append("KEV cache is missing; nothing is marked as known-exploited.")
        elif need_kev and not kev_complete:
            warnings.append(
                "KEV cache is a partial snapshot. CVEs absent from it are treated as not listed."
            )
    elif need_kev and (not kev_is_fresh or not kev_complete):
        try:
            fetched_entries, version = _fetch_kev(timeout)
            kev_map = fetched_entries
            kev_complete = True
            _write_json(
                kev_path,
                {
                    "format": 1,
                    "source": KEV_URL,
                    "fetched_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "catalog_version": version,
                    "complete": True,
                    "vulnerabilities": {key: kev_map[key] for key in sorted(kev_map)},
                },
            )
        except EnrichmentError as exc:
            warnings.append(f"KEV lookup failed ({exc}). Using the local cache.")
            if not kev_map:
                warnings.append("KEV cache is empty; nothing is marked as known-exploited.")
            elif not kev_complete:
                warnings.append(
                    "KEV cache is a partial snapshot. "
                    "CVEs absent from it are treated as not listed."
                )

    for finding in findings:
        if not finding.cve:
            finding.epss = None
            finding.epss_percentile = None
            finding.epss_status = "not_applicable"
            finding.kev = False
            finding.kev_name = None
            continue
        record = epss_map.get(finding.cve)
        if record and record.get("epss") is not None:
            finding.epss = float(record["epss"])
            percentile = record.get("percentile")
            finding.epss_percentile = float(percentile) if percentile is not None else None
            finding.epss_status = "known"
        else:
            finding.epss = None
            finding.epss_percentile = None
            finding.epss_status = "unknown"
        entry = kev_map.get(finding.cve)
        if entry:
            finding.kev = True
            name = entry.get("vulnerability_name")
            finding.kev_name = str(name) if name else None
        else:
            finding.kev = False
            finding.kev_name = None
    return warnings
