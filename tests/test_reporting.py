import json
from datetime import UTC, datetime

import pytest

from app.models import Finding
from app.reporting import build_report, summarize_findings, write_json_report


ACCOUNT_ID = "123456789012"
STARTED_AT = datetime(2026, 5, 27, 14, 0, 0, tzinfo=UTC)
COMPLETED_AT = datetime(2026, 5, 27, 14, 5, 0, tzinfo=UTC)


def make_finding(*, severity: str = "high", check_id: str = "TEST_CHECK") -> Finding:
    return Finding(
        finding_id=f"finding-{severity}-{check_id}",
        check_id=check_id,
        account_id=ACCOUNT_ID,
        region="us-east-1",
        service="test-service",
        resource_type="test-resource",
        resource_id="test-resource-1",
        severity=severity,
        status="failed",
        title="Test finding",
        description="Test description",
        remediation="Test remediation",
        evidence={"key": "value"},
        observed_at="2026-05-27T14:00:00Z",
    )


def test_summarize_findings_returns_correct_severity_counts():
    findings = [
        make_finding(severity="critical"),
        make_finding(severity="high"),
        make_finding(severity="high"),
        make_finding(severity="medium"),
        make_finding(severity="low"),
        make_finding(severity="informational"),
    ]

    assert summarize_findings(findings) == {
        "critical": 1,
        "high": 2,
        "medium": 1,
        "low": 1,
        "informational": 1,
    }


def test_summarize_findings_raises_value_error_for_unknown_severity():
    findings = [make_finding(severity="unknown")]

    with pytest.raises(ValueError, match="Unknown finding severity: unknown"):
        summarize_findings(findings)


def test_build_report_returns_canonical_report_structure():
    findings = [make_finding(severity="high")]

    report = build_report(
        account_id=ACCOUNT_ID,
        regions_scanned=["us-east-1", "us-west-2"],
        findings=findings,
        started_at=STARTED_AT,
        completed_at=COMPLETED_AT,
    )

    assert report["schema_version"] == "1.0"
    assert report["scanner_version"] == "0.1.0"
    assert report["scan_id"] == "2026-05-27T14-00-00Z"
    assert report["account_id"] == ACCOUNT_ID
    assert report["regions_scanned"] == ["us-east-1", "us-west-2"]
    assert report["started_at"] == "2026-05-27T14:00:00Z"
    assert report["completed_at"] == "2026-05-27T14:05:00Z"
    assert report["finding_summary"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }
    assert set(report.keys()) == {
        "schema_version",
        "scanner_version",
        "scan_id",
        "account_id",
        "regions_scanned",
        "started_at",
        "completed_at",
        "finding_summary",
        "findings",
    }


def test_build_report_serializes_findings_via_dataclass_shape():
    finding = make_finding(severity="medium", check_id="TEST_SERIALIZATION")

    report = build_report(
        account_id=ACCOUNT_ID,
        regions_scanned=["us-east-1"],
        findings=[finding],
        started_at=STARTED_AT,
        completed_at=COMPLETED_AT,
    )

    assert report["findings"] == [
        {
            "finding_id": "finding-medium-TEST_SERIALIZATION",
            "check_id": "TEST_SERIALIZATION",
            "account_id": ACCOUNT_ID,
            "region": "us-east-1",
            "service": "test-service",
            "resource_type": "test-resource",
            "resource_id": "test-resource-1",
            "severity": "medium",
            "status": "failed",
            "title": "Test finding",
            "description": "Test description",
            "remediation": "Test remediation",
            "evidence": {"key": "value"},
            "observed_at": "2026-05-27T14:00:00Z",
        }
    ]


def test_write_json_report_creates_expected_report_filename(tmp_path):
    report = {
        "scan_id": "2026-05-27T14-00-00Z",
        "account_id": ACCOUNT_ID,
        "findings": [],
    }

    report_path = write_json_report(report, output_dir=tmp_path)

    assert report_path == tmp_path / "report-2026-05-27T14-00-00Z.json"
    assert report_path.exists()


def test_write_json_report_writes_valid_json(tmp_path):
    report = {
        "scan_id": "2026-05-27T14-00-00Z",
        "account_id": ACCOUNT_ID,
        "finding_summary": {"high": 1},
        "findings": [{"check_id": "TEST_CHECK"}],
    }

    report_path = write_json_report(report, output_dir=tmp_path)

    with report_path.open(encoding="utf-8") as report_file:
        written_report = json.load(report_file)

    assert written_report == report
