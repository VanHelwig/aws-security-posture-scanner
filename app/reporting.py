import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from app.config import settings
from app.models import Finding


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_timestamp(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def format_scan_id(value: datetime) -> str:
    timestamp = value.replace(microsecond=0)
    return timestamp.strftime("%Y-%m-%dT%H-%M-%SZ")


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    for finding in findings:
        if finding.severity not in summary:
            raise ValueError(f"Unknown finding severity: {finding.severity}")

        summary[finding.severity] += 1

    return summary


def build_report(
    *,
    account_id: str,
    regions_scanned: list[str],
    findings: list[Finding],
    started_at: datetime,
    completed_at: datetime,
) -> dict:
    return {
        "schema_version": settings.schema_version,
        "scanner_version": settings.scanner_version,
        "scan_id": format_scan_id(started_at),
        "account_id": account_id,
        "regions_scanned": regions_scanned,
        "started_at": format_timestamp(started_at),
        "completed_at": format_timestamp(completed_at),
        "finding_summary": summarize_findings(findings),
        "findings": [asdict(finding) for finding in findings],
    }


def write_json_report(report: dict, output_dir: Path | None = None) -> Path:
    target_dir = output_dir or settings.output_dir
    target_dir.mkdir(parents=True, exist_ok=True)

    scan_id = report["scan_id"]
    report_path = target_dir / f"report-{scan_id}.json"

    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2)
        report_file.write("\n")

    return report_path
