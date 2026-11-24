from vmp.dedup import deduplicate, fingerprint, location_parts
from vmp.models import Finding


def _finding(**overrides) -> Finding:
    data = {
        "title": "Example",
        "severity": "high",
        "tool": "trivy",
        "location": "app/lib.jar",
        "cve": "CVE-2021-44228",
        "component": "log4j-core",
        "version": "2.14.1",
    }
    data.update(overrides)
    return Finding(**data)


def test_fingerprint_ignores_tool_and_is_stable():
    left = _finding(tool="trivy")
    right = _finding(tool="nuclei", title="different title")
    assert fingerprint(left) == fingerprint(right)
    assert "trivy" not in fingerprint(left)
    assert fingerprint(left) == "CVE-2021-44228|log4j-core@2.14.1|app/lib.jar"


def test_different_path_is_a_different_finding():
    left = _finding(location="app/a.jar")
    right = _finding(location="app/b.jar")
    assert fingerprint(left) != fingerprint(right)
    assert len(deduplicate([left, right])) == 2


def test_dedup_merges_sources_and_keeps_vector():
    plain = _finding(tool="trivy", cvss_vector=None, description="short")
    rich = _finding(
        tool="nuclei",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        description="a longer description of the same issue",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    )
    merged = deduplicate([plain, rich])
    assert len(merged) == 1
    assert merged[0].duplicate_count == 2
    assert merged[0].sources == ["nuclei", "trivy"]
    assert merged[0].cvss_vector.startswith("CVSS:3.1/")
    assert "longer" in merged[0].description


def test_web_fingerprint_drops_query_values_and_sorts_names():
    zap = Finding(
        title="SQL Injection",
        severity="high",
        tool="zap",
        location="http://127.0.0.1:3000/rest/products/search",
        parameter="q",
        cwe="89",
    )
    nuclei = Finding(
        title="SQL Injection",
        severity="high",
        tool="nuclei",
        location="http://127.0.0.1:3000/rest/products/search?q=anything",
        cwe="CWE-089",
    )
    assert fingerprint(zap) == fingerprint(nuclei)
    assert location_parts("http://127.0.0.1:3000/a?b=2&a=1")[1] == "/a?a&b"


def test_title_fallback_when_no_cve_or_cwe():
    left = Finding(title="Missing header!", severity="low", tool="zap", location="/health")
    right = Finding(title="missing header", severity="info", tool="nuclei", location="/health")
    assert fingerprint(left) == fingerprint(right)
