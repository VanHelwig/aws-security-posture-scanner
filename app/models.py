from dataclasses import dataclass, field
from hashlib import sha256
import boto3


@dataclass
class Finding:
    finding_id: str
    check_id: str
    account_id: str
    region: str
    service: str
    resource_type: str
    resource_id: str
    severity: str
    status: str
    title: str
    description: str
    remediation: str
    evidence: dict
    observed_at: str


@dataclass(frozen=True)
class AwsScanContext:
    session: boto3.Session
    account_id: str
    regions: list[str]
    findings: list[Finding] = field(default_factory=list)


def generate_finding_id(
    *,
    account_id: str,
    region: str,
    service: str,
    check_id: str,
    resource_id: str,
) -> str:
    raw_id = "|".join(
        [
            account_id.strip(),
            region.strip(),
            service.strip().lower(),
            check_id.strip().upper(),
            resource_id.strip(),
        ]
    )

    return sha256(raw_id.encode("utf-8")).hexdigest()
