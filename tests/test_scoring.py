from vmp.models import Exposure, Finding
from vmp.scoring import (
    CVSS_WEIGHT,
    EPSS_WEIGHT,
    EXPOSURE_WEIGHT,
    KEV_FLOOR,
    KEV_WEIGHT,
    band_for,
    cvss_base_score,
    score_finding,
)


def test_weights_sum_to_one():
    total = CVSS_WEIGHT + EPSS_WEIGHT + KEV_WEIGHT + EXPOSURE_WEIGHT
    assert abs(total - 1.0) < 1e-9


def test_vector_overrides_scanner_score():
    finding = Finding(
        title="log4j",
        severity="low",
        tool="trivy",
        location="app/log4j.jar",
        cve="CVE-2021-44228",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cvss_score=5.0,
        epss=0.0,
        epss_status="known",
    )
    score_finding(finding, Exposure.INTERNAL)
    assert finding.cvss_score == 10.0
    assert finding.score_breakdown["cvss_source"] == "vector"


def test_bare_vector_gets_a_prefix():
    assert cvss_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5


def test_invalid_vector_falls_back_to_scanner_score():
    finding = Finding(
        title="broken",
        severity="high",
        tool="trivy",
        location="app/x",
        cve="CVE-2024-0001",
        cvss_vector="nope",
        cvss_score=4.0,
        epss_status="unknown",
    )
    score_finding(finding, Exposure.UNKNOWN)
    assert finding.cvss_score == 4.0
    assert finding.score_breakdown["cvss_source"] == "scanner"


def test_severity_map_when_no_cvss():
    finding = Finding(
        title="banner",
        severity="info",
        tool="nuclei",
        location="http://127.0.0.1/",
        epss_status="not_applicable",
    )
    score_finding(finding, Exposure.INTERNET)
    assert finding.cvss_score == 0.0
    assert finding.score_breakdown["cvss_source"] == "severity_map"
    # Only the exposure term remains: 0.10 * 100 = 10.
    assert finding.risk_score == 10.0
    assert finding.risk_band == "info"


def test_kev_floor_raises_a_low_cvss_known_exploited_cve():
    finding = Finding(
        title="listed",
        severity="medium",
        tool="trivy",
        location="pkg",
        cve="CVE-2099-0001",
        cvss_score=5.0,
        epss=0.0,
        epss_status="known",
        kev=True,
    )
    score_finding(finding, Exposure.INTERNAL)
    # 0.45*50 + 0 + 0.20*100 + 0.10*40 = 22.5 + 20 + 4 = 46.5, then floor 80.
    assert finding.score_breakdown["raw"] == 46.5
    assert finding.score_breakdown["kev_floor_applied"] is True
    assert finding.risk_score == KEV_FLOOR
    assert finding.risk_band == "critical"


def test_high_cvss_without_exploitation_signals_is_not_critical():
    finding = Finding(
        title="theoretical",
        severity="critical",
        tool="trivy",
        location="pkg",
        cve="CVE-2099-0002",
        cvss_score=9.0,
        epss=0.01,
        epss_status="known",
        kev=False,
    )
    score_finding(finding, Exposure.INTERNAL)
    # 0.45*90 + 0.25*1 + 0 + 0.10*40 = 40.5 + 0.25 + 4 = 44.75
    assert finding.risk_score == 44.75
    assert finding.risk_band == "medium"


def test_band_thresholds():
    assert band_for(80) == "critical"
    assert band_for(79.99) == "high"
    assert band_for(60) == "high"
    assert band_for(40) == "medium"
    assert band_for(15) == "low"
    assert band_for(14.99) == "info"
