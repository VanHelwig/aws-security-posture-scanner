from app.models import AwsScanContext
from app.aws_session import create_scan_context
from app.reporting import build_report, utc_now, write_json_report


def run_scan() -> AwsScanContext:
    """Execute the scanner orchestration lifecycle.
    Current MVP responsibilities:
    - initialize AWS scan context
    - capture scan timing metadata
    - build canonical report structure
    - write local JSON report output

    Future responsibilities include:
    - service check orchestration
    - error handling and partial scan recovery
    - CSV export support
    - S3 report upload
    - structured logging
    - execution metrics
    """

    context = create_scan_context()
    started_at = utc_now()
    completed_at = utc_now()

    report = build_report(
        account_id=context.account_id,
        regions_scanned=context.regions,
        findings=context.findings,
        started_at=started_at,
        completed_at=completed_at,
    )

    report_path = write_json_report(report)

    print(f"Report written: {report_path}")

    return context
