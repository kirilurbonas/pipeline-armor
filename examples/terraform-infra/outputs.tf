// Outputs exposed for downstream stacks (CDK, Pulumi, sibling modules, etc.).

output "log_bucket_name" {
  description = "Name of the locked-down S3 log bucket."
  value       = aws_s3_bucket.logs.bucket
}

output "log_bucket_arn" {
  description = "ARN of the log bucket."
  value       = aws_s3_bucket.logs.arn
}

output "log_bucket_kms_key_arn" {
  description = "ARN of the KMS key that encrypts the log bucket."
  value       = aws_kms_key.logs.arn
  sensitive   = true
}
