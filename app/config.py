from dataclasses import dataclass
from pathlib import Path
import os


@dataclass
class Settings:
    aws_region: str = "us-east-1"
    log_level: str = "INFO"
    output_dir: Path = Path("output")
    scanner_version: str = "0.1.0"
    schema_version: str = "1.0"
    report_bucket: str | None = os.getenv("REPORT_BUCKET")


settings = Settings()
