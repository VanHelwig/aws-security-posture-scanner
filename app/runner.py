import logging

from app.models import AwsScanContext
from app.aws_session import create_scan_context
from app.reporting import build_report, utc_now, write_json_report
from app.checks import cloudtrail, iam, s3
from app.config import settings
from app.s3_writer import upload_json_report

logger = logging.getLogger(__name__)


def run_scan() -> AwsScanContext:
    """Execute the scanner orchestration lifecycle.
    Current responsibilities:
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
    findings.extend(
        iam.run(
            session=context.session,
            account_id=context.account_id,
            region=None,
        )
    )
    findings.extend(
        cloudtrail.run(
            session=context.session,
            account_id=context.account_id,
            region=context.regions[0] if context.regions else None,
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

    logger.info("report written: %s", report_path)

    if settings.report_bucket:
        object_key = upload_json_report(
            session=context.session,
            bucket_name=settings.report_bucket,
            report_path=report_path,
            report=report,
        )

        logger.info(
            "report uploaded: s3://%s/%s",
            settings.report_bucket,
            object_key,
        )

    else:
        logger.info("s3 upload skipped: REPORT_BUCKET is not configured")

    return context
