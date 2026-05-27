from botocore.exceptions import ClientError

import app.checks.cloudtrail as cloudtrail_checks


ACCOUNT_ID = "123456789012"
TRAIL_ARN = "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail"
SECOND_TRAIL_ARN = "arn:aws:cloudtrail:us-west-2:123456789012:trail/second-trail"


def client_error(code: str, operation_name: str = "CloudTrailOperation") -> ClientError:
    return ClientError(
        {
            "Error": {
                "Code": code,
                "Message": f"{operation_name} failed",
            }
        },
        operation_name,
    )


class FakeSession:
    def __init__(self, client):
        self._client = client
        self.client_calls = []

    def client(self, service_name: str, region_name=None):
        assert service_name == "cloudtrail"
        self.client_calls.append((service_name, region_name))
        return self._client


class FakeCloudTrailClient:
    def __init__(self, *, trails=None, statuses=None, describe_error=None, status_error=None):
        self.trails = trails or []
        self.statuses = statuses or {}
        self.describe_error = describe_error
        self.status_error = status_error
        self.describe_calls = []
        self.status_calls = []

    def describe_trails(self, includeShadowTrails):
        self.describe_calls.append(includeShadowTrails)

        if self.describe_error:
            raise self.describe_error

        return {"trailList": self.trails}

    def get_trail_status(self, Name):
        self.status_calls.append(Name)

        if self.status_error:
            raise self.status_error

        return self.statuses.get(Name, {"IsLogging": True})


def make_trail(
    *,
    trail_arn: str = TRAIL_ARN,
    name: str = "test-trail",
    home_region: str = "us-east-1",
    is_multi_region: bool = True,
    log_file_validation_enabled: bool = True,
) -> dict:
    return {
        "Name": name,
        "TrailARN": trail_arn,
        "HomeRegion": home_region,
        "IsMultiRegionTrail": is_multi_region,
        "LogFileValidationEnabled": log_file_validation_enabled,
        "IncludeGlobalServiceEvents": True,
        "IsOrganizationTrail": False,
    }


def run_cloudtrail_check(client):
    session = FakeSession(client)

    return cloudtrail_checks.run(
        session,
        account_id=ACCOUNT_ID,
        region="us-east-1",
    )


def test_no_trails_emits_no_multi_region_trail_finding():
    findings = run_cloudtrail_check(FakeCloudTrailClient(trails=[]))

    assert len(findings) == 1
    finding = findings[0]

    assert finding.check_id == cloudtrail_checks.NO_MULTI_REGION_TRAIL_CHECK_ID
    assert finding.region == "global"
    assert finding.resource_id == "account-cloudtrail-multiregion"
    assert finding.severity == "high"
    assert finding.status == "failed"
    assert finding.evidence["multi_region_trail_present"] is False
    assert finding.evidence["trail_count"] == 0


def test_multi_region_trail_emits_no_finding():
    client = FakeCloudTrailClient(
        trails=[make_trail()],
        statuses={TRAIL_ARN: {"IsLogging": True}},
    )

    findings = run_cloudtrail_check(client)

    assert findings == []


def test_stopped_trail_emits_trail_not_logging_finding():
    client = FakeCloudTrailClient(
        trails=[make_trail()],
        statuses={TRAIL_ARN: {"IsLogging": False, "LatestDeliveryError": "AccessDenied"}},
    )

    findings = run_cloudtrail_check(client)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.check_id == cloudtrail_checks.TRAIL_NOT_LOGGING_CHECK_ID
    assert finding.resource_id == TRAIL_ARN
    assert finding.region == "us-east-1"
    assert finding.severity == "high"
    assert finding.status == "failed"
    assert finding.evidence["trail_arn"] == TRAIL_ARN
    assert finding.evidence["home_region"] == "us-east-1"
    assert finding.evidence["is_logging"] is False
    assert finding.evidence["latest_delivery_error_present"] is True


def test_logging_trail_with_log_file_validation_disabled_emits_finding():
    client = FakeCloudTrailClient(
        trails=[make_trail(log_file_validation_enabled=False)],
        statuses={TRAIL_ARN: {"IsLogging": True}},
    )

    findings = run_cloudtrail_check(client)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.check_id == cloudtrail_checks.LOG_FILE_VALIDATION_DISABLED_CHECK_ID
    assert finding.resource_id == TRAIL_ARN
    assert finding.region == "us-east-1"
    assert finding.severity == "medium"
    assert finding.status == "failed"
    assert finding.evidence["trail_arn"] == TRAIL_ARN
    assert finding.evidence["home_region"] == "us-east-1"
    assert finding.evidence["is_logging"] is True
    assert finding.evidence["log_file_validation_enabled"] is False


def test_logging_trail_with_log_file_validation_enabled_emits_no_finding():
    client = FakeCloudTrailClient(
        trails=[make_trail(log_file_validation_enabled=True)],
        statuses={TRAIL_ARN: {"IsLogging": True}},
    )

    findings = run_cloudtrail_check(client)

    assert findings == []


def test_describe_trails_failure_emits_informational_error_finding():
    client = FakeCloudTrailClient(describe_error=client_error("AccessDenied", "DescribeTrails"))

    findings = run_cloudtrail_check(client)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.check_id == cloudtrail_checks.NO_MULTI_REGION_TRAIL_CHECK_ID
    assert finding.region == "global"
    assert finding.resource_id == "account-cloudtrail-multiregion"
    assert finding.severity == "informational"
    assert finding.status == "error"
    assert finding.evidence["error_type"] == "ClientError"


def test_get_trail_status_failure_emits_informational_error_finding():
    client = FakeCloudTrailClient(
        trails=[make_trail()],
        status_error=client_error("AccessDenied", "GetTrailStatus"),
    )

    findings = run_cloudtrail_check(client)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.check_id == cloudtrail_checks.TRAIL_NOT_LOGGING_CHECK_ID
    assert finding.region == "us-east-1"
    assert finding.resource_id == TRAIL_ARN
    assert finding.severity == "informational"
    assert finding.status == "error"
    assert finding.evidence["error_type"] == "ClientError"


def test_duplicate_shadow_trails_are_deduplicated_by_trail_arn():
    client = FakeCloudTrailClient(
        trails=[
            make_trail(log_file_validation_enabled=False),
            make_trail(log_file_validation_enabled=False),
            make_trail(
                trail_arn=SECOND_TRAIL_ARN,
                name="second-trail",
                home_region="us-west-2",
                is_multi_region=False,
                log_file_validation_enabled=True,
            ),
        ],
        statuses={
            TRAIL_ARN: {"IsLogging": True},
            SECOND_TRAIL_ARN: {"IsLogging": True},
        },
    )

    findings = run_cloudtrail_check(client)

    validation_findings = [
        finding
        for finding in findings
        if finding.check_id == cloudtrail_checks.LOG_FILE_VALIDATION_DISABLED_CHECK_ID
    ]

    assert len(validation_findings) == 1
    assert validation_findings[0].resource_id == TRAIL_ARN
    assert client.status_calls.count(TRAIL_ARN) == 1
