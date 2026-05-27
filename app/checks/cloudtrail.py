from botocore.exceptions import BotoCoreError, ClientError

from app.models import Finding, generate_finding_id
from app.reporting import format_timestamp, utc_now

NO_MULTI_REGION_TRAIL_CHECK_ID = "CLOUDTRAIL_NO_MULTI_REGION_TRAIL"
TRAIL_NOT_LOGGING_CHECK_ID = "CLOUDTRAIL_TRAIL_NOT_LOGGING"
LOG_FILE_VALIDATION_DISABLED_CHECK_ID = "CLOUDTRAIL_LOG_FILE_VALIDATION_DISABLED"

GLOBAL_REGION = "global"
ACCOUNT_MULTI_REGION_RESOURCE_ID = "account-cloudtrail-multiregion"


def run(session, account_id: str, region: str | None) -> list[Finding]:
    cloudtrail_client = session.client("cloudtrail", region_name=region)
    findings: list[Finding] = []

    try:
        trails = _list_unique_trails(cloudtrail_client)
    except (BotoCoreError, ClientError, KeyError, TypeError) as exc:
        return [
            _build_error_finding(
                account_id=account_id,
                check_id=NO_MULTI_REGION_TRAIL_CHECK_ID,
                region=GLOBAL_REGION,
                resource_type="account-cloudtrail-configuration",
                resource_id=ACCOUNT_MULTI_REGION_RESOURCE_ID,
                title="Unable to evaluate CloudTrail multi-region trail coverage",
                description=(
                    "The scanner could not determine whether the AWS account has "
                    "a multi-region CloudTrail trail configured."
                ),
                remediation=(
                    "Verify the scanner role has permission to call "
                    "cloudtrail:DescribeTrails, then rerun the scan."
                ),
                error=exc,
            )
        ]

    findings.extend(_check_multi_region_trail(account_id, trails))

    for trail in trails:
        findings.extend(_check_trail_status(session, account_id, trail))

    return findings


def _list_unique_trails(cloudtrail_client) -> list[dict]:
    response = cloudtrail_client.describe_trails(includeShadowTrails=True)
    trails_by_arn: dict[str, dict] = {}

    for trail in response.get("trailList", []):
        trail_arn = trail.get("TrailARN")

        if not trail_arn:
            continue

        trails_by_arn[trail_arn] = trail

    return sorted(
        trails_by_arn.values(),
        key=lambda trail: trail.get("TrailARN", ""),
    )


def _check_multi_region_trail(account_id: str, trails: list[dict]) -> list[Finding]:
    multi_region_trails = [
        trail for trail in trails if bool(trail.get("IsMultiRegionTrail", False))
    ]

    if multi_region_trails:
        return []

    evidence = {
        "api_source": "cloudtrail.describe_trails",
        "multi_region_trail_present": False,
        "trail_count": len(trails),
        "multi_region_trail_count": 0,
        "evaluated_trails": [_build_trail_summary(trail) for trail in trails],
    }

    return [
        Finding(
            finding_id=generate_finding_id(
                account_id=account_id,
                region=GLOBAL_REGION,
                service="cloudtrail",
                check_id=NO_MULTI_REGION_TRAIL_CHECK_ID,
                resource_id=ACCOUNT_MULTI_REGION_RESOURCE_ID,
            ),
            check_id=NO_MULTI_REGION_TRAIL_CHECK_ID,
            account_id=account_id,
            region=GLOBAL_REGION,
            service="cloudtrail",
            resource_type="account-cloudtrail-configuration",
            resource_id=ACCOUNT_MULTI_REGION_RESOURCE_ID,
            severity="high",
            status="failed",
            title="CloudTrail multi-region trail is not configured",
            description=(
                "The AWS account does not have a multi-region CloudTrail trail configured. "
                "Without a multi-region trail, activity in some AWS regions may not be "
                "captured by centralized account audit logging."
            ),
            remediation=(
                "Create or update a CloudTrail trail to apply to all regions. Ensure the "
                "trail is logging and configured to include global service events where "
                "appropriate."
            ),
            evidence=evidence,
            observed_at=format_timestamp(utc_now()),
        )
    ]


def _check_trail_status(session, account_id: str, trail: dict) -> list[Finding]:
    trail_name = trail.get("Name")
    trail_arn = trail.get("TrailARN")
    home_region = trail.get("HomeRegion") or GLOBAL_REGION

    if not trail_arn:
        return []

    try:
        cloudtrail_client = session.client("cloudtrail", region_name=home_region)
        response = cloudtrail_client.get_trail_status(Name=trail_arn)
    except (BotoCoreError, ClientError, KeyError, TypeError) as exc:
        return [
            _build_error_finding(
                account_id=account_id,
                check_id=TRAIL_NOT_LOGGING_CHECK_ID,
                region=home_region,
                resource_type="trail",
                resource_id=trail_arn,
                title="Unable to evaluate CloudTrail trail logging status",
                description=(
                    "The scanner could not determine whether the CloudTrail trail is "
                    "actively logging."
                ),
                remediation=(
                    "Verify the scanner role has permission to call "
                    "cloudtrail:GetTrailStatus for the trail, then rerun the scan."
                ),
                error=exc,
            )
        ]

    findings: list[Finding] = []
    is_logging = bool(response.get("IsLogging", False))

    if not is_logging:
        findings.append(
            _build_trail_not_logging_finding(
                account_id=account_id,
                trail=trail,
                status=response,
                trail_name=trail_name,
                trail_arn=trail_arn,
                home_region=home_region,
            )
        )
        return findings

    if not bool(trail.get("LogFileValidationEnabled", False)):
        findings.append(
            _build_log_file_validation_disabled_finding(
                account_id=account_id,
                trail=trail,
                trail_name=trail_name,
                trail_arn=trail_arn,
                home_region=home_region,
            )
        )

    return findings


def _build_trail_not_logging_finding(
    *,
    account_id: str,
    trail: dict,
    status: dict,
    trail_name: str | None,
    trail_arn: str,
    home_region: str,
) -> Finding:
    return Finding(
        finding_id=generate_finding_id(
            account_id=account_id,
            region=home_region,
            service="cloudtrail",
            check_id=TRAIL_NOT_LOGGING_CHECK_ID,
            resource_id=trail_arn,
        ),
        check_id=TRAIL_NOT_LOGGING_CHECK_ID,
        account_id=account_id,
        region=home_region,
        service="cloudtrail",
        resource_type="trail",
        resource_id=trail_arn,
        severity="high",
        status="failed",
        title="CloudTrail trail is not logging",
        description=(
            "The CloudTrail trail exists but is not actively logging. This can prevent "
            "AWS account activity from being captured for audit, investigation, and "
            "incident response."
        ),
        remediation=(
            "Start logging for the CloudTrail trail. Confirm that the trail can deliver "
            "logs to its configured destination and that delivery errors are resolved."
        ),
        evidence={
            "api_source": "cloudtrail.get_trail_status",
            "trail_name": trail_name,
            "trail_arn": trail_arn,
            "home_region": home_region,
            "is_logging": False,
            "latest_delivery_error_present": bool(status.get("LatestDeliveryError")),
            "latest_digest_delivery_error_present": bool(status.get("LatestDigestDeliveryError")),
            "stop_logging_time": _format_optional_timestamp(status.get("StopLoggingTime")),
            "is_multi_region_trail": bool(trail.get("IsMultiRegionTrail", False)),
            "is_organization_trail": bool(trail.get("IsOrganizationTrail", False)),
        },
        observed_at=format_timestamp(utc_now()),
    )


def _build_log_file_validation_disabled_finding(
    *,
    account_id: str,
    trail: dict,
    trail_name: str | None,
    trail_arn: str,
    home_region: str,
) -> Finding:
    return Finding(
        finding_id=generate_finding_id(
            account_id=account_id,
            region=home_region,
            service="cloudtrail",
            check_id=LOG_FILE_VALIDATION_DISABLED_CHECK_ID,
            resource_id=trail_arn,
        ),
        check_id=LOG_FILE_VALIDATION_DISABLED_CHECK_ID,
        account_id=account_id,
        region=home_region,
        service="cloudtrail",
        resource_type="trail",
        resource_id=trail_arn,
        severity="medium",
        status="failed",
        title="CloudTrail log file validation is disabled",
        description=(
            "The CloudTrail trail is logging but log file validation is not enabled. "
            "Without log file validation, it is harder to verify whether delivered "
            "CloudTrail log files were modified, deleted, or left unchanged after delivery."
        ),
        remediation=(
            "Enable CloudTrail log file validation for the trail. After enabling validation, "
            "CloudTrail will deliver digest files that can be used to validate log integrity."
        ),
        evidence={
            "api_source": "cloudtrail.describe_trails",
            "trail_name": trail_name,
            "trail_arn": trail_arn,
            "home_region": home_region,
            "is_logging": True,
            "log_file_validation_enabled": False,
            "is_multi_region_trail": bool(trail.get("IsMultiRegionTrail", False)),
            "is_organization_trail": bool(trail.get("IsOrganizationTrail", False)),
        },
        observed_at=format_timestamp(utc_now()),
    )


def _build_trail_summary(trail: dict) -> dict:
    return {
        "name": trail.get("Name"),
        "trail_arn": trail.get("TrailARN"),
        "home_region": trail.get("HomeRegion"),
        "is_multi_region_trail": bool(trail.get("IsMultiRegionTrail", False)),
        "include_global_service_events": bool(trail.get("IncludeGlobalServiceEvents", False)),
        "is_organization_trail": bool(trail.get("IsOrganizationTrail", False)),
    }


def _format_optional_timestamp(value) -> str | None:
    if value is None:
        return None

    if hasattr(value, "isoformat"):
        return format_timestamp(value)

    return str(value)


def _build_error_finding(
    *,
    account_id: str,
    check_id: str,
    region: str,
    resource_type: str,
    resource_id: str,
    title: str,
    description: str,
    remediation: str,
    error: Exception,
) -> Finding:
    return Finding(
        finding_id=generate_finding_id(
            account_id=account_id,
            region=region,
            service="cloudtrail",
            check_id=check_id,
            resource_id=resource_id,
        ),
        check_id=check_id,
        account_id=account_id,
        region=region,
        service="cloudtrail",
        resource_type=resource_type,
        resource_id=resource_id,
        severity="informational",
        status="error",
        title=title,
        description=description,
        remediation=remediation,
        evidence={
            "error_type": type(error).__name__,
            "error_message": str(error),
        },
        observed_at=format_timestamp(utc_now()),
    )
