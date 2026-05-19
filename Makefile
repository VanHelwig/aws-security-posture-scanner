IMAGE_NAME := aws-security-posture-scanner
IMAGE_TAG := local
REPORT_BUCKET ?=

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

.PHONY: run
run:
	python -m app.main

.PHONY: container-build
container-build:
	podman build -t $(IMAGE_NAME):$(IMAGE_TAG) .

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

.PHONY: terraform-fmt
terraform-fmt:
	terraform -chdir=terraform fmt -recursive

.PHONY: clean
clean:
	rm -rf output .pytest_cache .ruff_cache
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +