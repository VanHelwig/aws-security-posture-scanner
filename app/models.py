from dataclasses import dataclass

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