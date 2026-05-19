resource "aws_ecs_cluster" "scanner" {
  name = "${var.project_name}-${var.environment}"

  tags = {
    Name        = "${var.project_name}-${var.environment}"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_ecs_task_definition" "scanner" {
  family                   = "${var.project_name}-${var.environment}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512

  execution_role_arn = aws_iam_role.ecs_task_execution.arn
  task_role_arn      = aws_iam_role.scanner_task.arn

  container_definitions = jsonencode([
    {
      name      = "scanner"
      image     = "${aws_ecr_repository.scanner.repository_url}:latest"
      essential = true

      environment = [
        {
          name  = "REPORT_BUCKET"
          value = aws_s3_bucket.scanner_reports.bucket
        },
        {
          name  = "AWS_REGION"
          value = var.aws_region
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"

        options = {
          awslogs-group         = aws_cloudwatch_log_group.scanner_runtime.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "scanner"
        }
      }
    }
  ])

  tags = {
    Name        = "${var.project_name}-${var.environment}"
    Environment = var.environment
    Project     = var.project_name
  }
}