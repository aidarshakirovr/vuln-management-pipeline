"""CVSS v3.1 normalization and the risk-priority score.

The weights live here and are repeated in the README. Tests lock both.
"""

from __future__ import annotations

from cvss import CVSS3
from cvss.exceptions import CVSSError

from vmp.models import SEVERITY_TO_CVSS, Exposure, Finding

CVSS_WEIGHT = 0.45
EPSS_WEIGHT = 0.25
KEV_WEIGHT = 0.20
EXPOSURE_WEIGHT = 0.10
KEV_FLOOR = 80.0

EXPOSURE_SCORES = {
    Exposure.INTERNET: 100.0,
    Exposure.INTERNAL: 40.0,
    Exposure.UNKNOWN: 20.0,
}

# Inclusive lower bounds, evaluated high to low.
BANDS = (
    (80.0, "critical"),
    (60.0, "high"),
    (40.0, "medium"),
    (15.0, "low"),
)


def band_for(score: float) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "info"


def cvss_base_score(vector: str | None) -> float | None:
    """Return the CVSS v3.0/v3.1 base score for a vector, or None if it is unusable."""
    if not vector:
        return None
    text = vector.strip()
    if not text:
        return None
    if text.upper().startswith("AV:"):
        text = f"CVSS:3.1/{text}"
    try:
        parsed = CVSS3(text)
        score = float(parsed.scores()[0])
    except CVSSError:
        return None
    if score < 0 or score > 10:
        return None
    return score


def resolve_cvss(finding: Finding) -> tuple[float, str]:
    """Prefer a recomputed vector, then the scanner score, then a severity map."""
    from_vector = cvss_base_score(finding.cvss_vector)
    if from_vector is not None:
        return from_vector, "vector"
    if finding.cvss_score is not None:
        score = float(finding.cvss_score)
        if 0 <= score <= 10:
            return score, "scanner"
    return SEVERITY_TO_CVSS[finding.severity], "severity_map"


def _points(weight: float, normalized: float) -> float:
    return weight * normalized


def score_finding(finding: Finding, exposure: Exposure) -> Finding:
    """Attach CVSS, breakdown, risk score, and band. Does not return a copy."""
    base, source = resolve_cvss(finding)
    scanner_score = finding.cvss_score
    finding.cvss_score = base
    finding.exposure = exposure.value

    cvss_norm = base / 10.0 * 100.0
    if finding.epss_status == "known" and finding.epss is not None:
        epss_norm = max(0.0, min(1.0, finding.epss)) * 100.0
    else:
        epss_norm = 0.0
    kev_norm = 100.0 if finding.kev else 0.0
    exposure_norm = EXPOSURE_SCORES[exposure]

    cvss_points = _points(CVSS_WEIGHT, cvss_norm)
    epss_points = _points(EPSS_WEIGHT, epss_norm)
    kev_points = _points(KEV_WEIGHT, kev_norm)
    exposure_points = _points(EXPOSURE_WEIGHT, exposure_norm)
    raw = cvss_points + epss_points + kev_points + exposure_points

    floored = False
    final = raw
    if finding.kev and final < KEV_FLOOR:
        final = KEV_FLOOR
        floored = True
    final = max(0.0, min(100.0, final))
    rounded = float(f"{final:.2f}")

    finding.risk_score = rounded
    finding.risk_band = band_for(rounded)
    finding.score_breakdown = {
        "cvss_base": base,
        "cvss_source": source,
        "scanner_score": scanner_score,
        "cvss_norm": cvss_norm,
        "cvss_weight": CVSS_WEIGHT,
        "cvss_points": cvss_points,
        "epss": finding.epss,
        "epss_status": finding.epss_status,
        "epss_weight": EPSS_WEIGHT,
        "epss_points": epss_points,
        "kev": finding.kev,
        "kev_weight": KEV_WEIGHT,
        "kev_points": kev_points,
        "exposure": exposure.value,
        "exposure_norm": exposure_norm,
        "exposure_weight": EXPOSURE_WEIGHT,
        "exposure_points": exposure_points,
        "raw": raw,
        "kev_floor_applied": floored,
        "risk_score": rounded,
        "risk_band": finding.risk_band,
    }
    return finding


def score_findings(findings: list[Finding], exposure: Exposure) -> list[Finding]:
    for finding in findings:
        score_finding(finding, exposure)
    return findings
