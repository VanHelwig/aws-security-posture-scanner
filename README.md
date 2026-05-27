# AWS Security Posture Scanner

A lightweight AWS security assessment platform focused on deterministic findings, normalized reporting, and modular cloud security checks.

The project is designed as a realistic cloud security engineering system rather than a commercial CSPM replacement.

The scanner performs read-only AWS API inspection using boto3, normalizes findings into stable schemas, generates machine-readable reports, and supports containerized ECS/Fargate execution. The current platform has successfully validated end-to-end ECS runtime execution, including ECR image pulls, CloudWatch log streaming, IAM task-role authentication, and S3 report uploads.

Current development focuses on disciplined architecture, explicit contracts, and extensibility over feature quantity.

---

## Current Features

### Scanner Functionality

- AWS account scanning with boto3
- S3 Public Access Block inspection
- Deterministic finding ID generation
- Canonical JSON report generation
- Local JSON report persistence
- Modular service-scoped check architecture

### Implemented Security Checks

- S3 Public Access Block validation
- IAM root MFA enforcement
- IAM password policy validation
- CloudTrail multi-region trail detection
- CloudTrail logging status validation
- CloudTrail log file validation enforcement

### Report Storage and Logging

- Optional S3 report upload
- CloudWatch runtime log streaming
- Structured runtime execution logging

### Containerized Runtime

- Local Podman-based container development
- Non-root container runtime
- ECS Fargate execution
- Cloud-native stateless runtime model

### Terraform-Managed Infrastructure

- S3 report storage
- ECR container registry
- CloudWatch Logs infrastructure
- ECS/Fargate runtime infrastructure
- IAM roles and policies
- EventBridge scheduled execution
- Runtime networking infrastructure

### Scheduled Runtime Execution

- EventBridge scheduled ECS task execution
- Stateless recurring scanner execution

### Development Tooling

- Makefile-based development workflows
- ECR container push workflow
- ECS task execution automation
- GitHub Actions CI pipeline
- Automated Ruff lint validation
- Automated pytest execution
- Terraform formatting validation

---

## Architecture Overview

```text
Local Development / CI
        |
        v
Podman Container Runtime
        |
        v
Amazon ECR
        |
        v
EventBridge Scheduler
        |
        v
ECS/Fargate Runtime
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

CloudWatch Logs receives runtime and orchestration logs.
```

---

## Project Structure

```text
aws-security-posture-scanner/
├── .github/
│   └── workflows/
│       └── ci.yml
├── app/
│   ├── checks/
│   │   ├── cloudtrail.py
│   │   ├── iam.py
│   │   └── s3.py
│   ├── aws_session.py
│   ├── config.py
│   ├── main.py
│   ├── models.py
│   ├── reporting.py
│   ├── runner.py
│   └── s3_writer.py
├── output/
├── terraform/
│   └── envs/
│       └── dev/
│           ├── ecr.tf
│           ├── ecs.tf
│           ├── eventbridge.tf
│           ├── iam.tf
│           ├── logs.tf
│           ├── network.tf
│           ├── outputs.tf
│           ├── providers.tf
│           ├── s3.tf
│           └── variables.tf
├── tests/
│   ├── test_cloudtrail_checks.py
│   ├── test_iam_checks.py
│   ├── test_models.py
│   ├── test_reporting.py
│   └── test_s3_checks.py
├── Dockerfile
├── LICENSE
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
| `terraform/` | Runtime infrastructure and scanner validation fixtures |
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

## Testing

The project uses pytest-based unit testing with lightweight mocked AWS clients and deterministic validation behavior.

Current test coverage includes:

- deterministic finding ID generation
- S3 security checks
- IAM security checks
- CloudTrail security checks
- report generation and serialization
- error handling behavior

Run tests locally:

```bash
make test
```

---

## Continuous Integration

The repository uses GitHub Actions for lightweight continuous integration validation.

Current CI pipeline responsibilities include:

- Python dependency installation
- Ruff lint validation
- Pytest execution
- Terraform formatting validation

Current CI workflow location:

```text
.github/workflows/ci.yml
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

ECS/Fargate execution uses IAM task-role authentication rather than mounted credential files.

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
| `AWS_REGION` | AWS region used for local scanner execution. Defaults to `us-east-1`. |
| `LOG_LEVEL` | Runtime logging level. Defaults to `INFO`. |

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

Build and push a container image to ECR:

```bash
make container-release-ecr
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

## ECS/Fargate Execution

Run the scanner as an ECS Fargate task:

```bash
make ecs-run-task
```

This workflow:

- retrieves runtime network configuration from Terraform outputs
- launches a Fargate task
- pulls the scanner image from ECR
- streams logs to CloudWatch
- uploads reports to S3
- exits cleanly after scan completion

Successful execution returns the ECS task ARN.

---

## Scheduled Execution

The scanner supports scheduled ECS/Fargate execution using Amazon EventBridge.

EventBridge launches ephemeral ECS tasks on a configurable schedule using Terraform-managed infrastructure and IAM permissions. This enables low-cost recurring cloud security assessments without requiring persistent compute resources.

Current scheduled execution architecture:

```text
EventBridge Scheduler
        |
        v
ECS/Fargate Task
        |
        v
AWS API Inspection
        |
        v
CloudWatch Logs + S3 Reports
```

### Scheduling Characteristics

- stateless recurring execution
- no always-on services
- no inbound networking
- Terraform-managed scheduling infrastructure
- dedicated EventBridge IAM invocation role
- ECS task-role authentication
- configurable enable/disable behavior
- public IP assignment enabled for low-cost networking posture

### EventBridge IAM Responsibilities

The EventBridge runtime role is scoped to:

- invoke ECS tasks
- pass the ECS task execution role
- pass the scanner task role

The scheduler does not receive direct AWS scanning permissions.

### Example Terraform Variables

Example terraform.tfvars configuration:

- Default posture:

```hcl
scanner_schedule_enabled    = false
scanner_schedule_expression = "rate(1 day)"
```

- Temporary rapid validation schedule:

```hcl
scanner_schedule_enabled    = true
scanner_schedule_expression = "rate(5 minutes)"
```

No manual `aws ecs run-task` execution is required once scheduling is enabled.

---

## Terraform Development Fixtures

The repository also includes Terraform-managed development fixtures used to validate scanner behavior against intentionally configured AWS resources.

Included fixtures:

- private S3 bucket
- intentionally misconfigured S3 bucket for Public Access Block testing

Future fixtures may include intentionally insecure IAM, EC2, and networking configurations for scanner validation testing.

---

## Terraform Runtime Infrastructure

Infrastructure is currently managed directly within:

```text
terraform/envs/dev/
```

Current Terraform-managed runtime infrastructure includes:

- S3 report storage
- ECR container registry
- CloudWatch Logs infrastructure
- IAM task execution role
- IAM scanner task role
- ECS cluster
- ECS Fargate task definition
- ECS task security group
- EventBridge scheduling
- Default VPC discovery for low-cost development networking

The project intentionally avoids reusable Terraform modules during early development to preserve infrastructure visibility and reduce abstraction complexity.

---

## CloudWatch Logging Infrastructure

The project includes Terraform-managed CloudWatch Logs infrastructure used by ECS/Fargate runtime execution.

Logging characteristics:

- deterministic ECS-oriented naming
- environment-scoped log groups
- 14-day retention policy
- low-cost operational posture

Log group naming convention:

```text
/ecs/aws-security-posture-scanner-dev
```

ECS task definitions use the `awslogs` log driver to emit runtime logs into this log group.

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
- Structured JSON logging
- CloudWatch metrics and alarms
- Container build validation in CI
- Expanded Terraform infrastructure
- Multi-region scanning support

---

## License

This project is licensed under the MIT License. See the repository LICENSE file for details.
