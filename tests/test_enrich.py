import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vmp.enrich import enrich
from vmp.models import Finding


def _cve(cve: str) -> Finding:
    return Finding(title=cve, severity="high", tool="trivy", location="app.jar", cve=cve)


def test_offline_cache_fills_epss_and_kev():
    cache = Path(__file__).resolve().parents[1] / "samples" / "cache"
    before = {path.name: path.read_bytes() for path in cache.iterdir() if path.is_file()}
    findings = [_cve("CVE-2021-44228"), _cve("CVE-2024-0727"), _cve("CVE-2099-1111")]
    warnings = enrich(findings, cache_dir=cache, offline=True)
    log4j, openssl, missing = findings
    assert log4j.kev is True
    assert log4j.epss == pytest.approx(0.99999)
    assert log4j.epss_status == "known"
    assert openssl.kev is False
    assert openssl.epss == pytest.approx(0.03187)
    assert missing.epss_status == "unknown"
    assert missing.kev is False
    assert any("partial snapshot" in warning for warning in warnings)
    assert any("CVE-2099-1111" in warning for warning in warnings)
    after = {path.name: path.read_bytes() for path in cache.iterdir() if path.is_file()}
    assert before == after


def test_finding_without_cve_is_not_applicable():
    finding = Finding(
        title="SQLi", severity="high", tool="zap", location="http://127.0.0.1/", cwe="89"
    )
    warnings = enrich([finding], cache_dir=Path("/tmp/does-not-matter"), offline=True)
    assert finding.epss_status == "not_applicable"
    assert finding.kev is False
    assert warnings == []


def test_network_failure_keeps_stale_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    epss = {
        "format": 1,
        "fetched_at": "2020-01-01T00:00:00Z",
        "scores": {"CVE-2021-44228": {"epss": 0.5, "percentile": 0.9, "date": "2020-01-01"}},
    }
    kev = {
        "format": 1,
        "fetched_at": "2020-01-01T00:00:00Z",
        "complete": True,
        "vulnerabilities": {
            "CVE-2021-44228": {"vulnerability_name": "Log4j", "date_added": "2021-12-10"}
        },
    }
    (tmp_path / "epss.json").write_text(json.dumps(epss), encoding="utf-8")
    (tmp_path / "kev.json").write_text(json.dumps(kev), encoding="utf-8")

    def explode(*_args, **_kwargs):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
    finding = _cve("CVE-2021-44228")
    warnings = enrich(
        [finding],
        cache_dir=tmp_path,
        offline=False,
        now=datetime(2026, 11, 24, tzinfo=UTC),
    )
    assert finding.epss == 0.5
    assert finding.kev is True
    assert any("EPSS lookup failed" in warning for warning in warnings)
    assert any("KEV lookup failed" in warning for warning in warnings)


def test_offline_pipeline_does_not_touch_the_network(monkeypatch: pytest.MonkeyPatch):
    def explode(*_args, **_kwargs):
        raise AssertionError("network used")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
    cache = Path(__file__).resolve().parents[1] / "samples" / "cache"
    finding = _cve("CVE-2021-44228")
    enrich([finding], cache_dir=cache, offline=True)
    assert finding.kev is True
