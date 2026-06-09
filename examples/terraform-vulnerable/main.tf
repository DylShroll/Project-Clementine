# DELIBERATELY INSECURE — fixture for Phase 0 acceptance tests.
#
# This module exercises every M1+M2 IaC scanner (tfsec, checkov, cfn-nag,
# gitleaks, trufflehog) and at least four severity levels. Do not deploy.
#
# Acceptance target: `clementine iac --config <fixture-cfg> --source dir:./examples/terraform-vulnerable --format sarif`
# must produce >=12 findings spanning >=4 severity levels and exit 1
# under `--max-severity HIGH`.

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region     = "us-east-1"
  # Hardcoded credentials — gitleaks/trufflehog should both flag.
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# --------------------------------------------------------------------
# Public S3 bucket — tfsec AVD-AWS-0086 / checkov CKV_AWS_53..56
# --------------------------------------------------------------------
resource "aws_s3_bucket" "public_data" {
  bucket = "clementine-public-fixture"
}

resource "aws_s3_bucket_acl" "public_data" {
  bucket = aws_s3_bucket.public_data.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket                  = aws_s3_bucket.public_data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# --------------------------------------------------------------------
# Over-permissive IAM role — checkov CKV_AWS_111 / tfsec AVD-AWS-0057
# --------------------------------------------------------------------
resource "aws_iam_role" "lambda_admin" {
  name = "clementine-fixture-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_admin" {
  name = "clementine-fixture-admin-policy"
  role = aws_iam_role.lambda_admin.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# --------------------------------------------------------------------
# Lambda with hardcoded secret in env block — chains with the
# planned-Lambda-env-secret pattern.
# --------------------------------------------------------------------
resource "aws_lambda_function" "demo" {
  function_name = "clementine-fixture-fn"
  role          = aws_iam_role.lambda_admin.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  filename      = "fn.zip"

  environment {
    variables = {
      # gitleaks should flag this as a generic API token / aws key
      DB_PASSWORD = "supersecret-prod-db-password-do-not-use"
      AWS_KEY     = "AKIAIOSFODNN7EXAMPLE"
    }
  }
  # No KMS key -> tfsec AVD-AWS-0066 / checkov CKV_AWS_173
}

# --------------------------------------------------------------------
# Wide-open security group — tfsec AVD-AWS-0107
# --------------------------------------------------------------------
resource "aws_security_group" "open_to_world" {
  name        = "clementine-fixture-open"
  description = "Intentionally insecure for fixture testing"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
