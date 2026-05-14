import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.config import settings
from app.models import AwsScanContext


def create_scan_context() -> AwsScanContext:
    session = boto3.Session(region_name=settings.aws_region)
    account_id = get_account_id(session)
    regions = get_scan_regions()

    return AwsScanContext(
        session=session,
        account_id=account_id,
        regions=regions,
    )


def get_account_id(session: boto3.Session) -> str:
    try:
        sts_client = session.client("sts")
        response = sts_client.get_caller_identity()
        return response["Account"]
    except (BotoCoreError, ClientError, KeyError) as exc:
        raise RuntimeError("Unable to determine AWS account ID") from exc


def get_scan_regions() -> list[str]:
    return [settings.aws_region]
