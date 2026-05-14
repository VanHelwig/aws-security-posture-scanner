terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "scanner-fixture"
  suffix      = random_id.suffix.hex

  common_tags = {
    Project     = "aws-security-posture-scanner"
    Environment = "dev-fixture"
    ManagedBy   = "terraform"
    Purpose     = "scanner-testing"
  }
}

resource "aws_s3_bucket" "private_good" {
  bucket        = "${local.name_prefix}-private-${local.suffix}"
  force_destroy = true

  tags = merge(local.common_tags, {
    Name = "scanner-fixture-private"
  })
}

resource "aws_s3_bucket_public_access_block" "private_good" {
  bucket = aws_s3_bucket.private_good.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private_good" {
  bucket = aws_s3_bucket.private_good.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket" "pab_disabled_bad" {
  bucket        = "${local.name_prefix}-pab-disabled-${local.suffix}"
  force_destroy = true

  tags = merge(local.common_tags, {
    Name = "scanner-fixture-pab-disabled"
  })
}

resource "aws_s3_bucket_public_access_block" "pab_disabled_bad" {
  bucket = aws_s3_bucket.pab_disabled_bad.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "pab_disabled_bad" {
  bucket = aws_s3_bucket.pab_disabled_bad.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}