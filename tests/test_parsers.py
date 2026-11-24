import json
from pathlib import Path

import pytest

from vmp.dedup import deduplicate
from vmp.parsers import ParseError, parse_scan

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_trivy_sample_extracts_cve_package_and_vector():
    findings, warnings = parse_scan(SAMPLES / "trivy.json")
    assert warnings == []
    log4j = [finding for finding in findings if finding.cve == "CVE-2021-44228"]
    assert len(log4j) == 2
    assert log4j[0].component == "org.apache.logging.log4j:log4j-core"
    assert log4j[0].version == "2.14.1"
    assert log4j[0].fixed_version == "2.17.1"
    assert log4j[0].cvss_vector.startswith("CVSS:3.1/")
    assert log4j[0].severity == "critical"
    assert log4j[0].cwe == "CWE-917"
    assert "Upgrade" in log4j[0].remediation


def test_zap_sample_uses_riskcode_and_parameter():
    findings, warnings = parse_scan(SAMPLES / "zap.json")
    assert warnings == []
    sqli = next(finding for finding in findings if finding.cwe == "CWE-89")
    assert sqli.tool == "zap"
    assert sqli.severity == "high"
    assert sqli.parameter == "q"
    assert sqli.location.endswith("/rest/products/search")
    header = next(finding for finding in findings if finding.cwe == "CWE-693")
    assert header.severity == "low"
    assert header.parameter is None


def test_nuclei_jsonl_skips_comments():
    findings, warnings = parse_scan(SAMPLES / "nuclei.jsonl")
    assert warnings == []
    assert {finding.raw_id for finding in findings} == {"lab-sqli-search", "lab-server-version"}
    sqli = next(finding for finding in findings if finding.cwe == "CWE-89")
    assert sqli.cvss_score == 9.8
    assert sqli.severity == "high"


def test_nuclei_bad_line_warns_and_keeps_valid_rows(tmp_path: Path):
    path = tmp_path / "nuclei.jsonl"
    path.write_text(
        "\n".join(
            [
                "# comment",
                "this is not json",
                '{"template-id":"ok","info":{"name":"Ok","severity":"low"},"matched-at":"http://127.0.0.1/"}',
            ]
        ),
        encoding="utf-8",
    )
    findings, warnings = parse_scan(path)
    assert len(findings) == 1
    assert findings[0].raw_id == "ok"
    assert warnings


def test_invalid_json_object_raises(tmp_path: Path):
    path = tmp_path / "broken.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ParseError):
        parse_scan(path)


def test_trivy_without_vulnerabilities_is_empty(tmp_path: Path):
    path = tmp_path / "empty-trivy.json"
    path.write_text(
        '{"ArtifactName":"vuln-lab:local","Results":[{"Target":"x"}]}', encoding="utf-8"
    )
    findings, warnings = parse_scan(path)
    assert findings == []
    assert warnings == []


def test_cwe_placeholder_is_dropped(tmp_path: Path):
    path = tmp_path / "zap.json"
    path.write_text(
        """
        {"site":[{"@name":"http://127.0.0.1","alerts":[
          {"alert":"Info","riskcode":"0","cweid":"-1","instances":[{"uri":"http://127.0.0.1/"}]}
        ]}]}
        """,
        encoding="utf-8",
    )
    findings, _ = parse_scan(path)
    assert findings[0].cwe is None
    assert findings[0].severity == "info"


def test_trivy_keeps_distinct_ghsa_ids_and_non_v3_vectors(tmp_path: Path):
    path = tmp_path / "trivy.json"
    path.write_text(
        json.dumps(
            {
                "ArtifactName": "vuln-lab:local",
                "Results": [
                    {
                        "Target": "app",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "GHSA-1111-2222-3333",
                                "PkgName": "demo",
                                "InstalledVersion": "1.0.0",
                                "Severity": "HIGH",
                                "CweIDs": ["CWE-79"],
                                "PkgPath": "app/demo.jar",
                                "CVSS": {
                                    "nvd": {
                                        "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                        "V3Score": 7.5,
                                        "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                                        "V2Score": 5.0,
                                    }
                                },
                            },
                            {
                                "VulnerabilityID": "GHSA-aaaa-bbbb-cccc",
                                "PkgName": "demo",
                                "InstalledVersion": "1.0.0",
                                "Severity": "MEDIUM",
                                "CweIDs": ["CWE-79"],
                                "PkgPath": "app/demo.jar",
                                "CVSS": {
                                    "nvd": {
                                        "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                                        "V2Score": 5.0,
                                    }
                                },
                            },
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    findings, warnings = parse_scan(path)
    assert warnings == []
    assert len(deduplicate(findings)) == 2
    first, second = findings
    assert first.cve is None
    assert first.raw_id == "GHSA-1111-2222-3333"
    assert first.cvss_vector.startswith("CVSS:3.1/")
    assert first.other_cvss_vectors == ["AV:N/AC:L/Au:N/C:P/I:N/A:N"]
    assert second.raw_id == "GHSA-AAAA-BBBB-CCCC"
    assert second.cvss_vector == "AV:N/AC:L/Au:N/C:N/I:N/A:P"
    assert second.cwe == "CWE-79"
