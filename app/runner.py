from app.models import AwsScanContext
from app.aws_session import create_scan_context
from app.reporting import build_report, utc_now, write_json_report
from app.checks import s3
from app.config import settings
from app.s3_writer import upload_json_report


def run_scan() -> AwsScanContext:
    """Execute the scanner orchestration lifecycle.
    Current MVP responsibilities:
    - initialize AWS scan context
    - capture scan timing metadata
    - execute enabled security checks
    - attach normalized findings to the scan context
    - build canonical report structure
    - write local JSON report output
    - upload JSON report to S3 when REPORT_BUCKET is configured

    Future responsibilities include:
    - error handling and partial scan recovery
    - CSV export support
    - structured logging
    - execution metrics
    """

    started_at = utc_now()

    context = create_scan_context()

    findings = []
    findings.extend(
        s3.run(
            session=context.session,
            account_id=context.account_id,
            region=None,
        )
    )

    context.findings.extend(findings)

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

    if settings.report_bucket:
        object_key = upload_json_report(
            session=context.session,
            bucket_name=settings.report_bucket,
            report_path=report_path,
            report=report,
        )
        print(f"Report uploaded: s3://{settings.report_bucket}/{object_key}")
    else:
        print("S3 upload skipped: REPORT_BUCKET is not configured")

    return context
