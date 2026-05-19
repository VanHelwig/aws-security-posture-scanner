data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "scanner_task" {
  name        = "${var.project_name}-${var.environment}-scanner-task"
  description = "Security group for scanner ECS Fargate tasks"
  vpc_id      = data.aws_vpc.default.id

  egress {
    description = "Allow outbound HTTPS for AWS API access"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-scanner-task"
    Environment = var.environment
    Project     = var.project_name
  }
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}