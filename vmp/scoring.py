"""CVSS v3.1 normalization and the risk-priority score.

The weights live here and are repeated in the README. Tests lock both.
"""

from __future__ import annotations

from cvss import CVSS2, CVSS3, CVSS4
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


def _vector_kind(vector: str) -> str:
    """Return v2, v3, v4, or unknown. A bare ``AV:`` metric block is v3 unless it uses v2's Au."""
    text = vector.strip()
    upper = text.upper()
    if upper.startswith("CVSS:4"):
        return "v4"
    if upper.startswith("CVSS:2"):
        return "v2"
    if upper.startswith("CVSS:3"):
        return "v3"
    if upper.startswith("AV:") and "/AU:" in upper:
        return "v2"
    if upper.startswith("AV:"):
        return "v3"
    return "unknown"


def _score_in_range(score: float) -> float | None:
    if score < 0 or score > 10:
        return None
    return score


def cvss_base_score(vector: str | None) -> float | None:
    """Recompute a base score. v3 is preferred; v2 and v4 are scored, not discarded."""
    scored, _source = score_vector(vector)
    return scored


def score_vector(vector: str | None) -> tuple[float | None, str | None]:
    """Return ``(base, source)``. ``source`` is vector, vector_v2, or vector_v4.

    v3 wins when the stored vector is v3. v2 and v4 are converted when they
    are the vector we kept. A vector that fails to parse is left on the finding.
    """
    if not vector:
        return None, None
    text = vector.strip()
    if not text:
        return None, None
    kind = _vector_kind(text)
    try:
        if kind == "v2":
            metric = text.split("/", 1)[1] if text.upper().startswith("CVSS:2.0/") else text
            parsed = CVSS2(metric)
            return _score_in_range(float(parsed.scores()[0])), "vector_v2"
        if kind == "v4":
            metric = text if text.upper().startswith("CVSS:") else f"CVSS:4.0/{text}"
            parsed = CVSS4(metric)
            return _score_in_range(float(parsed.scores()[0])), "vector_v4"
        if kind == "v3":
            metric = text if text.upper().startswith("CVSS:") else f"CVSS:3.1/{text}"
            parsed = CVSS3(metric)
            return _score_in_range(float(parsed.scores()[0])), "vector"
    except CVSSError:
        return None, None
    return None, None


def resolve_cvss(finding: Finding) -> tuple[float, str]:
    """Prefer a recomputed vector (v3, else v2 or v4), then the scanner score, then severity."""
    from_vector, source = score_vector(finding.cvss_vector)
    if from_vector is not None and source is not None:
        return from_vector, source
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
        "cvss_vector": finding.cvss_vector,
        "other_cvss_vectors": list(finding.other_cvss_vectors),
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
