from dataclasses import dataclass


@dataclass
class Settings:
    aws_region: str = "us-east-1"
    log_level: str = "INFO"


settings = Settings()
