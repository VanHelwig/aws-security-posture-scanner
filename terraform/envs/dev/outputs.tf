output "report_bucket_name" {
  value = aws_s3_bucket.scanner_reports.bucket
}

output "ecr_repository_url" {
  value = aws_ecr_repository.scanner.repository_url
}

output "cloudwatch_log_group_name" {
  value = aws_cloudwatch_log_group.scanner_runtime.name
}

output "ecs_task_execution_role_arn" {
  value = aws_iam_role.ecs_task_execution.arn
}

output "scanner_task_role_arn" {
  value = aws_iam_role.scanner_task.arn
}