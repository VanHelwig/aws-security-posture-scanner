output "report_bucket_name" {
  value = aws_s3_bucket.scanner_reports.bucket
}

output "ecr_repository_url" {
  value = aws_ecr_repository.scanner.repository_url
}