from botocore.exceptions import ClientError

import app.checks.s3 as s3_checks
from app.models import generate_finding_id


ACCOUNT_ID = "123456789012"

MISSING_PUBLIC_ACCESS_BLOCK = object()


class FakeSession:
    def __init__(self, client):
        self._client = client

    def client(self, service_name: str):
        assert service_name == "s3"
        return self._client


class FakeS3Client:
    def __init__(self, public_access_block, location_constraint=None):
        self.public_access_block = public_access_block
        self.location_constraint = location_constraint

    def list_buckets(self):
        return {"Buckets": [{"Name": "test-bucket"}]}

    def get_bucket_location(self, Bucket):
        return {"LocationConstraint": self.location_constraint}

    def get_public_access_block(self, Bucket):
        if self.public_access_block is MISSING_PUBLIC_ACCESS_BLOCK:
            raise ClientError(
                {
                    "Error": {
                        "Code": "NoSuchPublicAccessBlockConfiguration",
                        "Message": "Public Access Block configuration not found",
                    }
                },
                "GetPublicAccessBlock",
            )

        return {"PublicAccessBlockConfiguration": self.public_access_block}


def run_s3_check(public_access_block):
    client = FakeS3Client(public_access_block=public_access_block)
    session = FakeSession(client)

    return s3_checks.run(
        session,
        account_id=ACCOUNT_ID,
        region=None,
    )


def test_no_finding_when_public_access_block_fully_enabled():
    findings = run_s3_check(
        {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
    )

    assert findings == []


def test_finding_when_public_access_block_disabled():
    findings = run_s3_check(
        {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.check_id == s3_checks.CHECK_ID
    assert finding.severity == "high"
    assert finding.status == "failed"
    assert finding.resource_id == "test-bucket"
    assert finding.region == "us-east-1"

    assert finding.evidence["public_access_block"]["block_public_policy"] is False


def test_missing_public_access_block_defaults_to_all_false():
    findings = run_s3_check(MISSING_PUBLIC_ACCESS_BLOCK)

    assert len(findings) == 1

    assert findings[0].evidence["public_access_block"] == {
        "block_public_acls": False,
        "block_public_policy": False,
        "ignore_public_acls": False,
        "restrict_public_buckets": False,
    }


def test_finding_id_is_deterministic():
    findings_one = run_s3_check(
        {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
    )

    findings_two = run_s3_check(
        {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
    )

    expected_finding_id = generate_finding_id(
        account_id=ACCOUNT_ID,
        region="us-east-1",
        service="s3",
        check_id=s3_checks.CHECK_ID,
        resource_id="test-bucket",
    )

    assert findings_one[0].finding_id == findings_two[0].finding_id

    assert findings_one[0].finding_id == expected_finding_id


def run_s3_check_with_location(location_constraint):
    client = FakeS3Client(
        public_access_block={
            "BlockPublicAcls": False,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        },
        location_constraint=location_constraint,
    )
    session = FakeSession(client)

    return s3_checks.run(
        session,
        account_id=ACCOUNT_ID,
        region=None,
    )


def test_bucket_region_defaults_to_us_east_1_when_location_constraint_is_none():
    findings = run_s3_check_with_location(None)

    assert len(findings) == 1
    assert findings[0].region == "us-east-1"


def test_bucket_region_maps_eu_to_eu_west_1():
    findings = run_s3_check_with_location("EU")

    assert len(findings) == 1
    assert findings[0].region == "eu-west-1"


def test_bucket_region_preserves_normal_region():
    findings = run_s3_check_with_location("us-west-2")

    assert len(findings) == 1
    assert findings[0].region == "us-west-2"
