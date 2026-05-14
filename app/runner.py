from app.models import AwsScanContext
from app.aws_session import create_scan_context


def run_scan() -> AwsScanContext:
    """Execute the scanner orchestration lifecycle.

    Current MVP behavior:
    - initialize scan context
    - return empty findings

    Future responsibilities include checks, reporting,
    and report persistence.
    """

    return create_scan_context()
