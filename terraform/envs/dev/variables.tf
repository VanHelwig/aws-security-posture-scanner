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