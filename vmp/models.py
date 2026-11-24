"""Shared finding model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Used only when a finding has neither a CVSS vector nor a scanner base score.
SEVERITY_TO_CVSS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
}

_SEVERITY_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "unknown": "info",
    "none": "info",
    "": "info",
}


class Exposure(StrEnum):
    INTERNET = "internet"
    INTERNAL = "internal"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: str) -> Exposure:
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            allowed = ", ".join(item.value for item in cls)
            raise ValueError(f"exposure must be one of: {allowed}") from exc


def normalize_severity(value: str | None) -> str:
    if value is None:
        return "info"
    return _SEVERITY_ALIASES.get(str(value).strip().lower(), "info")


def normalize_cve(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    if not text.startswith("CVE-"):
        return None
    return text


def normalize_cwe(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    if text in {"", "-1", "0", "CWE-0", "CWE--1"}:
        return None
    digits = "".join(char for char in text if char.isdigit())
    if not digits:
        return None
    number = int(digits)
    if number <= 0:
        return None
    return f"CWE-{number}"


@dataclass
class Finding:
    """One scanner result, before or after deduplication and scoring."""

    title: str
    severity: str
    tool: str
    location: str
    cve: str | None = None
    cwe: str | None = None
    component: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    description: str = ""
    remediation: str = ""
    cvss_vector: str | None = None
    cvss_score: float | None = None
    parameter: str | None = None
    references: list[str] = field(default_factory=list)
    raw_id: str | None = None
    sources: list[str] = field(default_factory=list)
    duplicate_count: int = 1
    epss: float | None = None
    epss_percentile: float | None = None
    epss_status: str = "unknown"
    kev: bool = False
    kev_name: str | None = None
    exposure: str = Exposure.UNKNOWN.value
    risk_score: float | None = None
    risk_band: str | None = None
    score_breakdown: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.cve = normalize_cve(self.cve)
        self.cwe = normalize_cwe(self.cwe)
        self.title = (self.title or self.cve or self.cwe or "untitled").strip()
        self.location = (self.location or "").strip()
        self.tool = (self.tool or "unknown").strip().lower()
        if self.component:
            self.component = self.component.strip() or None
        if self.version:
            self.version = self.version.strip() or None
        if not self.sources:
            self.sources = [self.tool]

    @property
    def display_id(self) -> str:
        return self.cve or self.cwe or self.raw_id or self.title

    @property
    def component_label(self) -> str:
        if not self.component:
            return ""
        if self.version:
            return f"{self.component}@{self.version}"
        return self.component
