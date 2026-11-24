import json
from pathlib import Path
from urllib.request import Request

import pytest

from vmp.defectdojo import DefectDojoError, encode_multipart, import_scan, resolve_scan_type

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

    def fake_urlopen(request: Request, timeout: float = 0):
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        captured["data"] = request.data
        captured["timeout"] = timeout
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
