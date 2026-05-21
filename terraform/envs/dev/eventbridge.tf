data "aws_iam_policy_document" "eventbridge_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "eventbridge_ecs_run_task" {
  name               = "${var.project_name}-${var.environment}-eventbridge-ecs-run-task"
  assume_role_policy = data.aws_iam_policy_document.eventbridge_assume_role.json

  tags = {
    Name        = "${var.project_name}-${var.environment}-eventbridge-ecs-run-task"
    Environment = var.environment
    Project     = var.project_name
  }
}

data "aws_iam_policy_document" "eventbridge_ecs_run_task" {
  statement {
    sid    = "AllowRunScannerTask"
    effect = "Allow"

    actions = [
      "ecs:RunTask",
    ]

    resources = [
      aws_ecs_task_definition.scanner.arn,
    ]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"

      values = [
        aws_ecs_cluster.scanner.arn,
      ]
    }
  }

  statement {
    sid    = "AllowPassScannerTaskRoles"
    effect = "Allow"

    actions = [
      "iam:PassRole",
    ]

    resources = [
      aws_iam_role.ecs_task_execution.arn,
      aws_iam_role.scanner_task.arn,
    ]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"

      values = [
        "ecs-tasks.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role_policy" "eventbridge_ecs_run_task" {
  name   = "${var.project_name}-${var.environment}-eventbridge-ecs-run-task"
  role   = aws_iam_role.eventbridge_ecs_run_task.id
  policy = data.aws_iam_policy_document.eventbridge_ecs_run_task.json
}

resource "aws_cloudwatch_event_rule" "scanner_schedule" {
  name                = "${var.project_name}-${var.environment}-scanner-schedule"
  description         = "Scheduled execution for the AWS Security Posture Scanner ECS task"
  schedule_expression = var.scanner_schedule_expression
  state               = var.scanner_schedule_enabled ? "ENABLED" : "DISABLED"

  tags = {
    Name        = "${var.project_name}-${var.environment}-scanner-schedule"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_cloudwatch_event_target" "scanner_ecs_task" {
  rule      = aws_cloudwatch_event_rule.scanner_schedule.name
  target_id = "scanner-ecs-task"
  arn       = aws_ecs_cluster.scanner.arn
  role_arn  = aws_iam_role.eventbridge_ecs_run_task.arn

  ecs_target {
    task_definition_arn = aws_ecs_task_definition.scanner.arn
    launch_type         = "FARGATE"
    platform_version    = "LATEST"
    task_count          = 1

    network_configuration {
      subnets          = data.aws_subnets.default.ids
      security_groups  = [aws_security_group.scanner_task.id]
      assign_public_ip = true
    }
  }
}