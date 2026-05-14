from dataclasses import dataclass, field
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