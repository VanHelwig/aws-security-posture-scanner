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

output "ecs_cluster_name" {
  value = aws_ecs_cluster.scanner.name
}

output "ecs_task_definition_arn" {
  value = aws_ecs_task_definition.scanner.arn
}

output "ecs_task_definition_family" {
  value = aws_ecs_task_definition.scanner.family
}

output "scanner_task_security_group_id" {
  value = aws_security_group.scanner_task.id
}

output "default_vpc_id" {
  value = data.aws_vpc.default.id
}

output "ecs_run_network_configuration" {
  value = {
    awsvpcConfiguration = {
      subnets        = data.aws_subnets.default.ids
      securityGroups = [aws_security_group.scanner_task.id]
      assignPublicIp = "ENABLED"
    }
  }
}