resource "aws_s3_bucket" "scanner_reports" {
  bucket = "${var.project_name}-reports-${var.environment}"

  tags = {
    Name        = "${var.project_name}-reports-${var.environment}"
    Environment = var.environment
    Project     = var.project_name
  }
}


resource "aws_s3_bucket_public_access_block" "scanner_reports" {
  bucket = aws_s3_bucket.scanner_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket_server_side_encryption_configuration" "scanner_reports" {
  bucket = aws_s3_bucket.scanner_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}


resource "aws_s3_bucket_versioning" "scanner_reports" {
  bucket = aws_s3_bucket.scanner_reports.id

  versioning_configuration {
    status = "Disabled"
  }
}


resource "aws_s3_bucket_lifecycle_configuration" "scanner_reports" {
  bucket = aws_s3_bucket.scanner_reports.id

  rule {
    id     = "report-retention"
    status = "Enabled"

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}