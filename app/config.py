from dataclasses import dataclass
from pathlib import Path
import logging
import os
import sys


@dataclass
class Settings:
    aws_region: str = os.getenv("AWS_REGION", "us-east-1")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    output_dir: Path = Path("output")
    scanner_version: str = "0.1.0"
    schema_version: str = "1.0"
    report_bucket: str | None = os.getenv("REPORT_BUCKET")


settings = Settings()


def configure_logging() -> None:
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
