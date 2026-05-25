// =============================================================================
// pipeline-armor :: examples/terraform-infra
// -----------------------------------------------------------------------------
// Minimal Terraform module exercising the IaC scan. We deliberately use a
// hardened S3 bucket configuration so the Checkov scan passes by default — a
// real consumer would point reusable-iac-scan.yml at their own modules.
//
// The intent here is to demonstrate the *expected* baseline; lowering any
// of these settings is what Checkov is built to catch.
// =============================================================================

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.46"
    }
  }
}

provider "aws" {
  region = var.region
}

// ---------------------------------------------------------------------------
// S3 bucket — locked-down baseline.
// ---------------------------------------------------------------------------
resource "aws_s3_bucket" "logs" {
  bucket = "${var.name_prefix}-logs"

  tags = {
    Name        = "${var.name_prefix}-logs"
    Environment = var.environment
    Owner       = var.owner
    Compliance  = "internal"
  }
}

// Versioning protects against accidental and malicious deletes.
resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

// SSE with KMS satisfies CIS 2.1 and PCI-DSS encryption-at-rest.
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
    bucket_key_enabled = true
  }
}

// Block ALL public access — covers checkov CKV_AWS_53/54/55/56.
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

// Access logging into a separate target bucket; we use the same bucket
// here only because this is a single-bucket example.
resource "aws_s3_bucket_logging" "logs" {
  bucket        = aws_s3_bucket.logs.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "access-logs/"
}

// ---------------------------------------------------------------------------
// KMS key for the bucket.
// ---------------------------------------------------------------------------
resource "aws_kms_key" "logs" {
  description             = "KMS key for ${var.name_prefix} log bucket"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "${var.name_prefix}-logs-kms"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.name_prefix}-logs"
  target_key_id = aws_kms_key.logs.key_id
}
