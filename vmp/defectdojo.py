"""Optional upload of the original scanner file to DefectDojo."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from vmp.dedup import fingerprint
from vmp.parsers import detect_tool, parse_nuclei, parse_trivy, parse_zap

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


def ssl_context() -> ssl.SSLContext | None:
    """Skip certificate checks only when DD_TLS_VERIFY is explicitly false.

    The compose file generates a self-signed nginx certificate. Leave verification
    on for any other DefectDojo.
    """
    flag = os.environ.get("DD_TLS_VERIFY", "true").strip().lower()
    if flag in {"0", "false", "no"}:
        return ssl._create_unverified_context()
    return None


def _optional(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


def _xml_text(parent: ET.Element, tag: str, value: object) -> None:
    node = ET.SubElement(parent, tag)
    node.text = "" if value is None else str(value)


def zap_json_to_xml(text: str) -> bytes:
    """Turn classic ZAP JSON into the XML report DefectDojo 3.5 imports.

    The ZAP parser in that release rejects any upload whose filename does not
    end in ``.xml``.
    """
    data = dedupe_zap_document(json.loads(text))
    sites = data.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]
    root = ET.Element("OWASPZAPReport")
    for site in sites:
        if not isinstance(site, dict):
            continue
        site_node = ET.SubElement(root, "site")
        site_node.set("name", str(site.get("@name") or site.get("name") or ""))
        alerts_node = ET.SubElement(site_node, "alerts")
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            item = ET.SubElement(alerts_node, "alertitem")
            _xml_text(item, "pluginid", alert.get("pluginid") or "")
            _xml_text(item, "alert", alert.get("alert") or alert.get("name") or "")
            risk = alert.get("riskcode")
            _xml_text(item, "riskcode", "" if risk is None else risk)
            _xml_text(item, "confidence", alert.get("confidence") or "")
            _xml_text(item, "desc", alert.get("desc") or "")
            _xml_text(item, "solution", alert.get("solution") or "")
            _xml_text(item, "reference", alert.get("reference") or "")
            _xml_text(item, "cweid", alert.get("cweid") or "")
            instances = ET.SubElement(item, "instances")
            raw_instances = alert.get("instances") or []
            if not raw_instances:
                raw_instances = [{"uri": site_node.get("name"), "method": "", "param": ""}]
            for instance in raw_instances:
                if not isinstance(instance, dict):
                    continue
                node = ET.SubElement(instances, "instance")
                _xml_text(node, "uri", instance.get("uri") or site_node.get("name"))
                _xml_text(node, "method", instance.get("method") or "")
                _xml_text(node, "param", instance.get("param") or "")
                _xml_text(node, "evidence", instance.get("evidence") or "")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _keep_first(findings_for_item, seen: set[str]) -> bool:
    if not findings_for_item:
        return True
    key = fingerprint(findings_for_item[0])
    if key in seen:
        return False
    seen.add(key)
    return True


def dedupe_trivy_document(data: dict) -> dict:
    """Drop vulnerability objects that share a vmp fingerprint.

    DefectDojo does not deduplicate two rows inside one imported test, so the
    duplicate Log4j object in the sample Trivy file would be stored twice.
    """
    seen: set[str] = set()
    results = []
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            results.append(result)
            continue
        vulns = result.get("Vulnerabilities")
        if not isinstance(vulns, list):
            results.append(result)
            continue
        kept = []
        base = {key: value for key, value in result.items() if key != "Vulnerabilities"}
        for vuln in vulns:
            if not isinstance(vuln, dict):
                kept.append(vuln)
                continue
            parsed = parse_trivy(
                {
                    "ArtifactName": data.get("ArtifactName"),
                    "Results": [{**base, "Vulnerabilities": [vuln]}],
                },
                source="upload",
            )
            if _keep_first(parsed, seen):
                kept.append(vuln)
        results.append({**result, "Vulnerabilities": kept})
    return {**data, "Results": results}


def dedupe_zap_document(data: dict) -> dict:
    """Drop ZAP instances that share a fingerprint before the XML conversion."""
    seen: set[str] = set()
    sites = data.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]
    new_sites = []
    for site in sites:
        if not isinstance(site, dict):
            new_sites.append(site)
            continue
        alerts = []
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                alerts.append(alert)
                continue
            instances = alert.get("instances") or [None]
            kept_instances = []
            for instance in instances:
                one_instance = [] if instance is None else [instance]
                trial = {
                    "site": [
                        {
                            **{key: value for key, value in site.items() if key != "alerts"},
                            "alerts": [{**alert, "instances": one_instance}],
                        }
                    ]
                }
                if _keep_first(parse_zap(trial, source="upload"), seen):
                    if instance is not None:
                        kept_instances.append(instance)
            if kept_instances or not alert.get("instances"):
                alerts.append({**alert, "instances": kept_instances})
        new_sites.append({**site, "alerts": alerts})
    return {**data, "site": new_sites}


def dedupe_nuclei_lines(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    kept = []
    for line in lines:
        parsed, _warnings = parse_nuclei(line, source="upload")
        if _keep_first(parsed, seen):
            kept.append(line)
    return kept


def nuclei_for_defectdojo(content: bytes) -> bytes:
    """Drop comment lines. DefectDojo only treats the file as JSONL when it starts with ``{``."""
    text = content.decode("utf-8-sig")
    if text.lstrip().startswith("["):
        return text.encode("utf-8")
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    lines = dedupe_nuclei_lines(lines)
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


def upload_bytes(path: Path, scan_type: str) -> tuple[str, bytes]:
    """Return the filename and body DefectDojo should receive."""
    content = path.read_bytes()
    if scan_type == "Trivy Scan":
        text = content.decode("utf-8-sig")
        if text.lstrip().startswith("{"):
            deduped = dedupe_trivy_document(json.loads(text))
            return path.name, (json.dumps(deduped, indent=2) + "\n").encode("utf-8")
    if scan_type == "Nuclei Scan":
        return path.name, nuclei_for_defectdojo(content)
    if scan_type != "ZAP Scan" or path.name.lower().endswith(".xml"):
        return path.name, content
    text = content.decode("utf-8-sig")
    if text.lstrip().startswith(("{", "[")):
        return f"{path.stem}.xml", zap_json_to_xml(text)
    return path.name, content


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
    filename, content = upload_bytes(path, resolved)
    body, content_type = encode_multipart(
        fields,
        file_field="file",
        filename=filename,
        content=content,
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
        open_kwargs: dict[str, object] = {"timeout": timeout}
        context = ssl_context()
        if context is not None:
            open_kwargs["context"] = context
        with urllib.request.urlopen(request, **open_kwargs) as response:
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
