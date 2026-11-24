"""Command line interface for vmp."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vmp import __version__
from vmp.defectdojo import DefectDojoError, import_scan
from vmp.models import Exposure
from vmp.parsers import ParseError
from vmp.pipeline import run_pipeline

BAND_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vmp",
        description="Parse scanner output, deduplicate it, and write a priority report.",
    )
    parser.add_argument("--version", action="version", version=f"vmp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Parse, dedupe, enrich, score, and write reports")
    ingest.add_argument("scans", nargs="+", type=Path, help="Trivy JSON, ZAP JSON, or Nuclei JSONL")
    ingest.add_argument(
        "--offline",
        action="store_true",
        help="Do not call FIRST or CISA. Use only the local cache.",
    )
    ingest.add_argument(
        "--cache-dir",
        default=".vmp-cache",
        help="Directory for epss.json and kev.json (default: .vmp-cache)",
    )
    ingest.add_argument(
        "--exposure",
        default=Exposure.UNKNOWN.value,
        choices=[item.value for item in Exposure],
        help="How reachable the affected assets are (default: unknown)",
    )
    ingest.add_argument(
        "--out-dir",
        default="out",
        help="Where to write findings.csv, report.md, and report.html",
    )
    ingest.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit 1 when any finding's risk band is at or above this level",
    )

    upload = sub.add_parser("upload", help="Import an original scanner file into DefectDojo")
    upload.add_argument("scan", type=Path)
    upload.add_argument(
        "--scan-type",
        default="auto",
        help="DefectDojo scan type, or trivy/zap/nuclei (default: auto)",
    )
    upload.add_argument(
        "--reimport",
        action="store_true",
        help="Reimport and close findings missing from this file",
    )
    return parser


def _print_table(result_findings: list) -> None:
    headers = ("rank", "score", "band", "id", "asset")
    rows = [headers]
    for rank, finding in enumerate(result_findings, start=1):
        rows.append(
            (
                str(rank),
                f"{finding.risk_score:.2f}",
                finding.risk_band or "",
                finding.display_id,
                finding.component_label or finding.location,
            )
        )
    widths = [max(len(row[index]) for row in rows) for index in range(len(headers))]
    for row in rows:
        print("  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)))


def _cmd_ingest(args: argparse.Namespace) -> int:
    missing = [path for path in args.scans if not path.is_file()]
    if missing:
        print("scan file not found: " + ", ".join(str(path) for path in missing), file=sys.stderr)
        return 2
    try:
        exposure = Exposure.parse(args.exposure)
        result = run_pipeline(
            list(args.scans),
            cache_dir=Path(args.cache_dir),
            offline=args.offline,
            exposure=exposure,
            out_dir=Path(args.out_dir),
        )
    except ParseError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print(
        f"parsed {result.raw_count} findings, {len(result.findings)} after deduplication "
        f"(exposure={exposure.value}, offline={args.offline})"
    )
    kev_count = sum(1 for finding in result.findings if finding.kev)
    known_epss = sum(1 for finding in result.findings if finding.epss_status == "known")
    print(f"enrichment: EPSS known on {known_epss} findings, KEV listed on {kev_count}")
    if result.findings:
        print()
        _print_table(result.findings)
    for label, path in result.paths.items():
        print(f"wrote {path} ({label})")
    if args.fail_on:
        threshold = BAND_ORDER[args.fail_on]
        blocked = [
            finding
            for finding in result.findings
            if BAND_ORDER.get(finding.risk_band or "info", 0) >= threshold
        ]
        if blocked:
            print(f"fail-on: at least one finding is {args.fail_on} or higher", file=sys.stderr)
            return 1
    return 0


def _cmd_upload(args: argparse.Namespace) -> int:
    if not args.scan.is_file():
        print(f"scan file not found: {args.scan}", file=sys.stderr)
        return 2
    try:
        payload = import_scan(args.scan, scan_type=args.scan_type, reimport=args.reimport)
    except DefectDojoError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    test_id = payload.get("test_id") or payload.get("test")
    engagement = payload.get("engagement_id")
    print(
        f"uploaded {args.scan.name} "
        f"({'reimport' if args.reimport else 'import'}) "
        f"status={payload.get('status_code')} test={test_id} engagement={engagement}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "ingest":
        return _cmd_ingest(args)
    if args.command == "upload":
        return _cmd_upload(args)
    parser.error(f"unknown command {args.command}")
    return 2
