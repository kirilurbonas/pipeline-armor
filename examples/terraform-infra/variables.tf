// Input variables for the example module.

variable "region" {
  description = "AWS region in which to create resources."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix applied to every resource name for traceability."
  type        = string
  default     = "pipeline-armor-example"

  validation {
    condition     = length(var.name_prefix) > 0 && length(var.name_prefix) <= 32
    error_message = "name_prefix must be between 1 and 32 characters."
  }
}

variable "environment" {
  description = "Environment tag: dev|staging|prod."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "owner" {
  description = "Team or individual responsible for this stack."
  type        = string
  default     = "platform-engineering"
}
