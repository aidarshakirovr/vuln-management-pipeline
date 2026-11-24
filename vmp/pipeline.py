"""Parse, deduplicate, enrich, score, and export."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vmp.dedup import deduplicate
from vmp.enrich import enrich
from vmp.models import Exposure, Finding
from vmp.parsers import ParseError, parse_scan
from vmp.report import sort_findings, write_reports
from vmp.scoring import score_findings


@dataclass
class PipelineResult:
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)
    raw_count: int = 0
    paths: dict[str, Path] = field(default_factory=dict)


def run_pipeline(
    scan_paths: list[Path],
    *,
    cache_dir: Path,
    offline: bool,
    exposure: Exposure,
    out_dir: Path | None = None,
) -> PipelineResult:
    raw: list[Finding] = []
    warnings: list[str] = []
    for path in scan_paths:
        try:
            findings, parse_warnings = parse_scan(path)
        except ParseError as exc:
            raise ParseError(str(exc)) from exc
        raw.extend(findings)
        warnings.extend(f"{path.name}: {warning}" for warning in parse_warnings)

    merged = deduplicate(raw)
    warnings.extend(enrich(merged, cache_dir=cache_dir, offline=offline))
    score_findings(merged, exposure)
    ordered = sort_findings(merged)
    paths: dict[str, Path] = {}
    if out_dir is not None:
        paths = write_reports(ordered, out_dir)
    return PipelineResult(
        findings=ordered,
        warnings=warnings,
        raw_count=len(raw),
        paths=paths,
    )
