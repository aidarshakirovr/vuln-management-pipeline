import json
import ssl
from pathlib import Path
from urllib.request import Request

import pytest

from vmp.defectdojo import (
    DefectDojoError,
    encode_multipart,
    import_scan,
    nuclei_for_defectdojo,
    resolve_scan_type,
    ssl_context,
    upload_bytes,
)

ROOT = Path(__file__).resolve().parents[1]


def test_scan_type_detection():
    assert resolve_scan_type(ROOT / "samples" / "trivy.json", None) == "Trivy Scan"
    assert resolve_scan_type(ROOT / "samples" / "zap.json", "auto") == "ZAP Scan"
    assert resolve_scan_type(ROOT / "samples" / "nuclei.jsonl", "nuclei") == "Nuclei Scan"
    assert resolve_scan_type(ROOT / "samples" / "trivy.json", "Custom Scan") == "Custom Scan"


def test_import_posts_original_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scan = tmp_path / "trivy.json"
    scan.write_text((ROOT / "samples" / "trivy.json").read_text(encoding="utf-8"), encoding="utf-8")
    captured = {}

    class Response:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"test": 7, "engagement_id": 3}).encode()

    def fake_urlopen(request: Request, timeout: float = 0, context: object = None):
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        captured["data"] = request.data
        captured["timeout"] = timeout
        captured["context"] = context
        return Response()

    monkeypatch.setenv("DD_URL", "http://localhost:8080")
    monkeypatch.setenv("DD_API_TOKEN", "lab-token")
    monkeypatch.setenv("DD_PRODUCT_NAME", "lab-vuln-app")
    monkeypatch.setattr("vmp.defectdojo.urllib.request.urlopen", fake_urlopen)
    payload = import_scan(scan, reimport=True)
    assert payload["test"] == 7
    assert captured["url"] == "http://localhost:8080/api/v2/reimport-scan/"
    assert captured["headers"]["Authorization"] == "Token lab-token"
    body = captured["data"].decode()
    assert 'name="scan_type"' in body
    assert "Trivy Scan" in body
    assert "close_old_findings" in body
    assert "lab-token" not in body
    assert "CVE-2021-44228" in body


def test_placeholder_token_is_rejected(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DD_URL", "http://localhost:8080")
    monkeypatch.setenv("DD_API_TOKEN", "change-me")
    with pytest.raises(DefectDojoError):
        import_scan(ROOT / "samples" / "zap.json")


def test_missing_token_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DD_URL", raising=False)
    monkeypatch.delenv("DD_API_TOKEN", raising=False)
    with pytest.raises(DefectDojoError):
        import_scan(ROOT / "samples" / "zap.json")


def test_tls_verify_off_uses_an_unverified_context(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DD_TLS_VERIFY", "false")
    context = ssl_context()
    assert context is not None
    assert context.verify_mode == ssl.CERT_NONE
    monkeypatch.setenv("DD_TLS_VERIFY", "true")
    assert ssl_context() is None


def test_trivy_upload_keeps_one_log4j_row():
    _filename, content = upload_bytes(ROOT / "samples" / "trivy.json", "Trivy Scan")
    data = json.loads(content)
    log4j = []
    total = 0
    for result in data["Results"]:
        for vuln in result.get("Vulnerabilities") or []:
            total += 1
            if vuln.get("VulnerabilityID") == "CVE-2021-44228":
                log4j.append(vuln.get("PkgPath"))
    assert log4j == ["app/WEB-INF/lib/log4j-core-2.14.1.jar"]
    assert total == 7


def test_nuclei_upload_strips_the_comment_header():
    body = nuclei_for_defectdojo((ROOT / "samples" / "nuclei.jsonl").read_bytes())
    text = body.decode("utf-8")
    assert text.startswith("{")
    assert "\n#" not in text
    assert text.count("\n{") == 1 or text.count("{") >= 2


def test_zap_json_upload_is_xml_named_for_defectdojo():
    filename, content = upload_bytes(ROOT / "samples" / "zap.json", "ZAP Scan")
    assert filename.endswith(".xml")
    text = content.decode("utf-8")
    assert "<alertitem>" in text
    assert "SQL Injection" in text
    assert "<cweid>89</cweid>" in text
    assert "http://127.0.0.1:3000/rest/products/search" in text


def test_multipart_round_trip_names():
    body, content_type = encode_multipart(
        {"scan_type": "ZAP Scan"},
        file_field="file",
        filename="zap.json",
        content=b"{}",
    )
    assert content_type.startswith("multipart/form-data; boundary=")
    assert b'name="scan_type"' in body
    assert b'filename="zap.json"' in body
    assert b"{}" in body
