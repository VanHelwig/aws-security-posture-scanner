from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def build_s3_report_key(report: dict) -> str:
    account_id = report["account_id"]
    scan_id = report["scan_id"]
    scan_date = scan_id.split("T", maxsplit=1)[0]

    return f"account_id={account_id}/region_scope=multi/scan_date={scan_date}/report-{scan_id}.json"


def upload_json_report(
    *,
    session: boto3.Session,
    bucket_name: str,
    report_path: Path,
    report: dict,
) -> str:
    s3_client = session.client("s3")
    object_key = build_s3_report_key(report)

    try:
        s3_client.upload_file(
            str(report_path),
            bucket_name,
            object_key,
            ExtraArgs={
                "ContentType": "application/json",
                "ServerSideEncryption": "AES256",
            },
        )
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Unable to upload report to s3://{bucket_name}/{object_key}") from exc

    return object_key
