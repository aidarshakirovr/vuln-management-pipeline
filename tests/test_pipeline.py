from pathlib import Path

from vmp.models import Exposure, Finding
from vmp.pipeline import run_pipeline
from vmp.report import write_reports

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_demo_samples_dedup_score_and_export(tmp_path: Path):
    result = run_pipeline(
        [SAMPLES / "trivy.json", SAMPLES / "zap.json", SAMPLES / "nuclei.jsonl"],
        cache_dir=SAMPLES / "cache",
        offline=True,
        exposure=Exposure.INTERNET,
        out_dir=tmp_path,
    )
    assert result.raw_count == 12
    assert len(result.findings) == 11
    log4j = next(finding for finding in result.findings if finding.cve == "CVE-2021-44228")
    assert log4j.duplicate_count == 2
    assert log4j.risk_band == "critical"
    assert log4j.risk_score >= 99
    sqli = [finding for finding in result.findings if finding.cwe == "CWE-89"]
    assert {tuple(finding.sources) for finding in sqli} == {("nuclei",), ("zap",)}
    assert all(finding.duplicate_count == 1 for finding in sqli)
    assert all(finding.epss_status == "not_applicable" for finding in sqli)
    openssl = next(finding for finding in result.findings if finding.cve == "CVE-2024-0727")
    assert openssl.kev is False
    assert openssl.risk_score < min(finding.risk_score or 0 for finding in sqli)
    assert result.findings[0].cve == "CVE-2021-44228"
    assert result.findings == sorted(
        result.findings, key=lambda finding: finding.risk_score or 0, reverse=True
    )
    csv_text = (tmp_path / "findings.csv").read_text(encoding="utf-8")
    assert "CVE-2021-44228" in csv_text
    assert "risk_score" in csv_text.splitlines()[0]
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "CVE-2021-44228" in html
    assert (tmp_path / "report.md").is_file()


def test_csv_neutralizes_formula_injection(tmp_path: Path):
    finding = Finding(
        title="=HYPERLINK()",
        severity="low",
        tool="zap",
        location="http://127.0.0.1/",
        remediation="+cmd",
        epss_status="not_applicable",
    )
    from vmp.scoring import score_finding

    score_finding(finding, Exposure.UNKNOWN)
    write_reports([finding], tmp_path)
    text = (tmp_path / "findings.csv").read_text(encoding="utf-8")
    assert "'=HYPERLINK()" in text
    assert "'+cmd" in text


def test_html_escapes_titles(tmp_path: Path):
    finding = Finding(
        title="<script>alert(1)</script>",
        severity="low",
        tool="zap",
        location="http://127.0.0.1/",
        epss_status="not_applicable",
    )
    from vmp.scoring import score_finding

    score_finding(finding, Exposure.UNKNOWN)
    write_reports([finding], tmp_path)
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_readme_documents_the_weights():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for piece in ("0.45", "0.25", "0.20", "0.10", "80"):
        assert piece in readme
