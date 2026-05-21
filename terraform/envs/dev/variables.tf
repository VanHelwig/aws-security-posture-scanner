variable "project_name" {
  type    = string
  default = "aws-security-posture-scanner"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "aws_region" {
  description = "AWS region used for dev infrastructure and ECS runtime configuration."
  type        = string
  default     = "us-east-1"
}

variable "scanner_schedule_expression" {
  description = "EventBridge schedule expression for recurring scanner execution."
  type        = string
  default     = "rate(1 day)"
}

variable "scanner_schedule_enabled" {
  description = "Whether the EventBridge scanner schedule is enabled."
  type        = bool
  default     = false
}