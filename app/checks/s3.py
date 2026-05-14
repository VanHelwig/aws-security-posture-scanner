from botocore.exceptions import ClientError

from app.models import Finding, generate_finding_id
from app.reporting import format_timestamp, utc_now

CHECK_ID = "S3_PUBLIC_ACCESS_BLOCK_DISABLED"

PUBLIC_ACCESS_BLOCK_KEYS = {
    "BlockPublicAcls": "block_public_acls",
    "BlockPublicPolicy": "block_public_policy",
    "IgnorePublicAcls": "ignore_public_acls",
    "RestrictPublicBuckets": "restrict_public_buckets",
}


def run(session, account_id: str, region: str | None) -> list[Finding]:
    s3_client = session.client("s3")
    findings: list[Finding] = []

    response = s3_client.list_buckets()

    for bucket in response.get("Buckets", []):
        bucket_name = bucket["Name"]
        bucket_region = _get_bucket_region(s3_client, bucket_name)
        public_access_block = _get_public_access_block(s3_client, bucket_name)

        if all(public_access_block.values()):
            continue

        findings.append(
            Finding(
                finding_id=generate_finding_id(
                    account_id=account_id,
                    region=bucket_region,
                    service="s3",
                    check_id=CHECK_ID,
                    resource_id=bucket_name,
                ),
                check_id=CHECK_ID,
                account_id=account_id,
                region=bucket_region,
                service="s3",
                resource_type="bucket",
                resource_id=bucket_name,
                severity="high",
                status="failed",
                title="S3 bucket Public Access Block is not fully enabled",
                description=(
                    "The S3 bucket does not have all account-level Public Access "
                    "Block controls enabled at the bucket level."
                ),
                remediation=(
                    "Enable all S3 Public Access Block settings for the bucket: "
                    "BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, and "
                    "RestrictPublicBuckets."
                ),
                evidence={
                    "bucket_name": bucket_name,
                    "public_access_block": public_access_block,
                },
                observed_at=format_timestamp(utc_now()),
            )
        )

    return findings


def _get_bucket_region(s3_client, bucket_name: str) -> str:
    response = s3_client.get_bucket_location(Bucket=bucket_name)
    location = response.get("LocationConstraint")

    if location is None:
        return "us-east-1"

    if location == "EU":
        return "eu-west-1"

    return location


def _get_public_access_block(s3_client, bucket_name: str) -> dict[str, bool]:
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        configuration = response["PublicAccessBlockConfiguration"]

        return {
            normalized_key: bool(configuration.get(api_key, False))
            for api_key, normalized_key in PUBLIC_ACCESS_BLOCK_KEYS.items()
        }

    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code")

        if error_code == "NoSuchPublicAccessBlockConfiguration":
            return {
                "block_public_acls": False,
                "block_public_policy": False,
                "ignore_public_acls": False,
                "restrict_public_buckets": False,
            }

        raise
