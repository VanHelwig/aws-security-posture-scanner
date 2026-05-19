# AWS Security Posture Scanner

A lightweight AWS security assessment platform focused on deterministic findings, normalized reporting, and modular cloud security checks.

The project is designed as a realistic cloud security engineering system rather than a commercial CSPM replacement. The scanner performs read-only AWS API inspection using boto3, normalizes findings into stable schemas, generates machine-readable reports, and supports containerized execution for future ECS/Fargate deployment.

Current development focuses on disciplined architecture, explicit contracts, and extensibility over feature quantity.

---

## Current MVP Features

- AWS account scanning with boto3
- S3 Public Access Block inspection
- Deterministic finding ID generation
- Canonical JSON report generation
- Optional S3 report upload
- Podman container execution
- Non-root container runtime
- Terraform-managed development fixtures
- Modular check architecture

---

## Architecture Overview

```text
Local Development / CI
        |
        v
Podman Container Runtime
        |
        v
Read-Only AWS API Calls
        |
        v
Normalized Findings
        |
        v
JSON Reports
        |
        v
Optional S3 Report Upload
```

---

## Project Structure

```text
aws-security-posture-scanner/
├── app/
│   ├── checks/
│   ├── aws_session.py
│   ├── config.py
│   ├── main.py
│   ├── models.py
│   ├── reporting.py
│   ├── runner.py
│   └── s3_writer.py
├── tests/
├── terraform/
├── Dockerfile
├── Makefile
├── pyproject.toml
└── README.md
```

### Key Directories

| Path | Purpose |
| --- | --- |
| `app/` | Scanner application source code |
| `app/checks/` | Modular AWS security checks |
| `tests/` | Unit tests and mocked boto3 validation |
| `terraform/` | Infrastructure and development fixtures |
| `output/` | Local generated reports (gitignored) |

---

## Requirements

- Python 3.12+
- Podman or Docker
- AWS CLI configured locally
- Terraform 1.6+

---

## Installation

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install the project and development dependencies:

```bash
make install
```

Equivalent manual installation:

```bash
pip install -e ".[dev]"
```

---

## AWS Credentials

The scanner uses standard boto3 and AWS CLI credential resolution.

Local container execution mounts the host AWS configuration directory into the container runtime:

```text
~/.aws -> /home/scanner/.aws
```

Example local credential validation:

```bash
aws sts get-caller-identity
```

Future ECS/Fargate execution will use task-role authentication rather than mounted credential files.

### Local Container Credential Notes

If using rootless Podman with a non-root container user, the mounted AWS config files must be readable by the container runtime user.

Example:

```bash
chmod 644 ~/.aws/config
chmod 600 ~/.aws/credentials
```

Validate local credentials before running the scanner:

```bash
aws sts get-caller-identity
```

---

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `REPORT_BUCKET` | Optional S3 upload destination |
| `AWS_PROFILE` | Local AWS CLI profile for boto3 authentication |

---

## Running the Scanner Locally

Run directly as a Python module:

```bash
python -m app.main
```

The project also installs a console entrypoint during installation:

```bash
posture-scanner
```

Or use the Makefile helper:

```bash
make run
```

---

## Container Execution

Build the container image:

```bash
make container-build
```

Run the scanner locally in Podman:

```bash
make container-run
```

Run with S3 report upload enabled:

```bash
make container-run-s3 REPORT_BUCKET=my-report-bucket
```

---

## Example Report Structure

```json
{
  "schema_version": "1.0",
  "scanner_version": "0.1.0",
  "scan_id": "2026-05-19T15-06-08Z",
  "account_id": "123456789012",
  "regions_scanned": [
    "us-east-1"
  ],
  "finding_summary": {
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "informational": 0
  },
  "findings": []
}
```

---

## Terraform Development Fixtures

The repository includes Terraform-managed development fixtures used to validate scanner behavior against intentionally configured AWS resources.

Current fixtures include:

- private S3 bucket
- intentionally misconfigured S3 bucket for Public Access Block testing

---

## Security Design Principles

- No static credentials in source control
- Read-only AWS inspection
- Deterministic finding generation
- Explicit normalized schemas
- Stateless execution model
- Non-root container runtime
- Modular service-scoped checks

---

## Planned Features

- Additional AWS service checks
- ECS/Fargate scheduled execution
- EventBridge scheduling
- CloudWatch structured logging
- CI/CD pipeline integration
- Expanded Terraform infrastructure
- Multi-region scanning support

---

## License

This project is licensed under the terms defined in the repository LICENSE file.
