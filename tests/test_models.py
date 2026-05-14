from app.models import generate_finding_id


def test_generate_finding_id_is_stable() -> None:
    finding_id_1 = generate_finding_id(
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        check_id="S3_PUBLIC_ACCESS_BLOCK_DISABLED",
        resource_id="example-bucket",
    )

    finding_id_2 = generate_finding_id(
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        check_id="S3_PUBLIC_ACCESS_BLOCK_DISABLED",
        resource_id="example-bucket",
    )

    assert finding_id_1 == finding_id_2


def test_generate_finding_id_changes_when_resource_changes() -> None:
    finding_id_1 = generate_finding_id(
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        check_id="S3_PUBLIC_ACCESS_BLOCK_DISABLED",
        resource_id="example-bucket-1",
    )

    finding_id_2 = generate_finding_id(
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        check_id="S3_PUBLIC_ACCESS_BLOCK_DISABLED",
        resource_id="example-bucket-2",
    )

    assert finding_id_1 != finding_id_2
