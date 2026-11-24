"""Optional upload of the original scanner file to DefectDojo."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from vmp.parsers import detect_tool

SCAN_TYPES = {
    "trivy": "Trivy Scan",
    "zap": "ZAP Scan",
    "nuclei": "Nuclei Scan",
}


class DefectDojoError(RuntimeError):
    """Configuration or API failure. The message never includes the API token."""


def resolve_scan_type(path: Path, requested: str | None) -> str:
    if not requested or requested == "auto":
        return SCAN_TYPES[detect_tool(path)]
    lowered = requested.strip().lower()
    if lowered in SCAN_TYPES:
        return SCAN_TYPES[lowered]
    return requested.strip()


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise DefectDojoError(f"set {name} in the environment (see .env.example)")
    return value


def _optional(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


def encode_multipart(
    fields: dict[str, str],
    *,
    file_field: str,
    filename: str,
    content: bytes,
) -> tuple[bytes, str]:
    boundary = "vmp" + uuid.uuid4().hex
    chunks: list[bytes] = []
    for key, value in fields.items():
        chunks.append(f"--{boundary}\r\n".encode())
        chunks.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode())
        chunks.append(value.encode("utf-8"))
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}\r\n".encode())
    safe_name = filename.replace('"', "")
    disposition = f'Content-Disposition: form-data; name="{file_field}"; filename="{safe_name}"\r\n'
    chunks.append(disposition.encode())
    chunks.append(b"Content-Type: application/octet-stream\r\n\r\n")
    chunks.append(content)
    chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def import_scan(
    path: Path, *, scan_type: str | None = None, reimport: bool = False, timeout: float = 60.0
) -> dict:
    """POST the original file to import-scan or reimport-scan.

    Reads DD_URL and DD_API_TOKEN from the environment. Product and engagement
    names default to the lab values in .env.example when unset.
    """
    base = _required("DD_URL").rstrip("/")
    token = _required("DD_API_TOKEN")
    if token == "change-me" or token.startswith("replace-"):
        raise DefectDojoError("DD_API_TOKEN is still the .env.example placeholder")
    resolved = resolve_scan_type(path, scan_type)
    endpoint = "reimport-scan" if reimport else "import-scan"
    url = f"{base}/api/v2/{endpoint}/"
    fields = {
        "scan_type": resolved,
        "product_name": _optional("DD_PRODUCT_NAME", "lab-vuln-app"),
        "product_type_name": _optional("DD_PRODUCT_TYPE_NAME", "Research and Development"),
        "engagement_name": _optional("DD_ENGAGEMENT_NAME", "local-assessment"),
        "auto_create_context": "true",
        "active": "true",
        "verified": "false",
        "minimum_severity": "Info",
    }
    if reimport:
        fields["close_old_findings"] = "true"
    body, content_type = encode_multipart(
        fields,
        file_field="file",
        filename=path.name,
        content=path.read_bytes(),
    )
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Token {token}",
            "Content-Type": content_type,
            "User-Agent": "vmp/0.1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise DefectDojoError(f"DefectDojo returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise DefectDojoError(f"DefectDojo request failed: {exc.reason}") from exc
    if not raw:
        return {"status_code": status}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return {"status_code": status, "body": raw.decode("utf-8", errors="replace")[:500]}
    if isinstance(payload, dict):
        payload["status_code"] = status
        return payload
    return {"status_code": status, "body": payload}
