IMAGE_NAME := aws-security-posture-scanner
IMAGE_TAG ?= local
AWS_REGION ?= us-east-1
ENVIRONMENT ?= dev
AWS_ACCOUNT_ID ?= $(shell aws sts get-caller-identity --query Account --output text)

ECR_REPOSITORY := $(IMAGE_NAME)-$(ENVIRONMENT)
ECR_REGISTRY := $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
ECR_IMAGE_TAG ?= latest
ECR_IMAGE_URI := $(ECR_REGISTRY)/$(ECR_REPOSITORY):$(ECR_IMAGE_TAG)
TERRAFORM_ENV_DIR := terraform/envs/$(ENVIRONMENT)

# Local Commands
.PHONY: install
install:
	pip install -e ".[dev]"

.PHONY: lint
lint:
	ruff check .

.PHONY: format
format:
	ruff format .

.PHONY: test
test:
	pytest

.PHONY: setup
setup: install lint format test

.PHONY: run
run:
	python -m app.main

# Container Commands
.PHONY: container-build
container-build:
	podman build -t $(IMAGE_NAME):$(IMAGE_TAG) .

.PHONY: container-build-ecr
container-build-ecr: 
	podman build -t $(IMAGE_NAME):$(ECR_IMAGE_TAG) .
	podman tag $(IMAGE_NAME):$(ECR_IMAGE_TAG) $(ECR_IMAGE_URI)

.PHONY: container-run
container-run:
	podman run --rm \
		-e AWS_PROFILE=default \
		-v "$$HOME/.aws:/home/scanner/.aws:ro,Z" \
		$(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: container-run-s3
container-run-s3:
	podman run --rm \
		-e AWS_PROFILE=default \
		-e REPORT_BUCKET=$(REPORT_BUCKET) \
		-v "$$HOME/.aws:/home/scanner/.aws:ro,Z" \
		$(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: ecr-login
ecr-login: 
	aws ecr get-login-password --region $(AWS_REGION) | \
	podman login --username AWS --password-stdin $(ECR_REGISTRY)	

.PHONY: container-push-ecr
container-push-ecr:
	podman push $(ECR_IMAGE_URI)

.PHONY: container-release
container-release: ecr-login container-build-ecr container-push-ecr

.PHONY: ecs-run-task
ecs-run-task:
	@echo "Starting ECS scanner task..."
	@aws ecs run-task \
		--cluster $(IMAGE_NAME)-$(ENVIRONMENT) \
		--launch-type FARGATE \
		--task-definition $(IMAGE_NAME)-$(ENVIRONMENT) \
		--network-configuration "$$(terraform -chdir=$(TERRAFORM_ENV_DIR) output -json ecs_run_network_configuration)" \
		--query 'tasks[0].taskArn' \
		--output text

# Terraform Commands
.PHONY: terraform-init
terraform-init:
	terraform -chdir=$(TERRAFORM_ENV_DIR) init

.PHONY: terraform-validate
terraform-validate:
	terraform -chdir=$(TERRAFORM_ENV_DIR) validate

.PHONY: terraform-plan
terraform-plan:
	terraform -chdir=$(TERRAFORM_ENV_DIR) plan

.PHONY: terraform-apply
terraform-apply:
	terraform -chdir=$(TERRAFORM_ENV_DIR) apply

.PHONY: terraform-destroy
terraform-destroy:
	terraform -chdir=$(TERRAFORM_ENV_DIR) destroy

.PHONY: terraform-fmt
terraform-fmt:
	terraform -chdir=terraform fmt -recursive

.PHONY: terraform-fmt-check
terraform-fmt-check:
	terraform -chdir=terraform fmt -check -recursive

# Security Testing Commands
.PHONY: security-sast
security-sast:
	bandit -r app -ll

.PHONY: security-deps
security-deps:
	pip-audit

.PHONY: container-scan
container-scan:
	trivy image \
		--ignore-unfixed \
		--severity HIGH,CRITICAL \
		--exit-code 0 \
		$(IMAGE_NAME):$(CI_IMAGE_TAG)

.PHONY: security-all
security-all: security-sast security-deps

# Cleaning Commands
.PHONY: clean-python
clean-python:
	rm -rf output .pytest_cache .ruff_cache
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +

.PHONY: clean-containers
clean-containers:
	-podman rm -f $$(podman ps -aq --filter "ancestor=$(IMAGE_NAME):$(IMAGE_TAG)") 2>/dev/null || true
	-podman rmi -f $(IMAGE_NAME):$(IMAGE_TAG) 2>/dev/null || true
	-podman image prune -f 2>/dev/null || true

.PHONY: clean-all
clean-all: clean-python clean-containers