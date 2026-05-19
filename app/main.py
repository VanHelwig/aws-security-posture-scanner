import logging

from app.config import configure_logging
from app.runner import run_scan

logger = logging.getLogger(__name__)


def main() -> None:
    configure_logging()
    context = run_scan()

    logger.info("Scanner execution completed")
    logger.info("account_id=%s", context.account_id)
    logger.info("regions=%s", ",".join(context.regions))
    logger.info("findings=%s", len(context.findings))


if __name__ == "__main__":
    main()
