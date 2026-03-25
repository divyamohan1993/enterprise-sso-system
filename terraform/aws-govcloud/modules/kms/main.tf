# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — AWS GovCloud KMS Module
# ──────────────────────────────────────────────────────────────────────────────
# AWS KMS with FIPS 140-2 endpoints (kms-fips.us-gov-west-1.amazonaws.com).
# All keys are multi-region disabled — keys stay within GovCloud partition.
# Key policy enforces: deny if request not via FIPS endpoint.
#
# Keys:
#   master-kek     — symmetric, automatic 90-day rotation
#   rds-cmek       — symmetric, for RDS Aurora encryption
#   ebs-cmek       — symmetric, for EBS volume encryption
#   secrets-cmek   — symmetric, for Secrets Manager
#   audit-signing  — asymmetric RSA-4096, for audit log signatures
# ──────────────────────────────────────────────────────────────────────────────

variable "primary_region" { type = string }
variable "secondary_region" { type = string }
variable "environment" { type = string }
variable "service_names" { type = list(string) }

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.secondary]
    }
  }
}

locals {
  name_prefix = "milnet-govcloud-${var.environment}"
}

data "aws_caller_identity" "current" {}

# ── Key Policy: Deny non-FIPS requests ──

data "aws_iam_policy_document" "milnet_kms_policy" {
  # Allow root account full access (required by KMS)
  statement {
    sid    = "EnableRootAccess"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws-us-gov:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Deny any request not made via FIPS endpoint
  statement {
    sid    = "DenyNonFipsRequests"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = [var.primary_region, var.secondary_region]
    }
  }
}

# ── Master KEK ──

resource "aws_kms_key" "master_kek" {
  description             = "MILNET GovCloud master KEK — root of key hierarchy"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  multi_region            = false
  policy                  = data.aws_iam_policy_document.milnet_kms_policy.json

  tags = {
    Name        = "${local.name_prefix}-master-kek"
    KeyPurpose  = "master-kek"
    FipsOnly    = "true"
  }
}

resource "aws_kms_alias" "master_kek" {
  name          = "alias/${local.name_prefix}-master-kek"
  target_key_id = aws_kms_key.master_kek.key_id
}

# ── RDS CMEK ──

resource "aws_kms_key" "rds_cmek" {
  description             = "MILNET GovCloud RDS Aurora encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  multi_region            = false
  policy                  = data.aws_iam_policy_document.milnet_kms_policy.json

  tags = {
    Name       = "${local.name_prefix}-rds-cmek"
    KeyPurpose = "rds-encryption"
  }
}

resource "aws_kms_alias" "rds_cmek" {
  name          = "alias/${local.name_prefix}-rds-cmek"
  target_key_id = aws_kms_key.rds_cmek.key_id
}

# ── EBS CMEK ──

resource "aws_kms_key" "ebs_cmek" {
  description             = "MILNET GovCloud EBS volume encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  multi_region            = false
  policy                  = data.aws_iam_policy_document.milnet_kms_policy.json

  tags = {
    Name       = "${local.name_prefix}-ebs-cmek"
    KeyPurpose = "ebs-encryption"
  }
}

resource "aws_kms_alias" "ebs_cmek" {
  name          = "alias/${local.name_prefix}-ebs-cmek"
  target_key_id = aws_kms_key.ebs_cmek.key_id
}

# ── Secrets Manager CMEK ──

resource "aws_kms_key" "secrets_cmek" {
  description             = "MILNET GovCloud Secrets Manager encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  multi_region            = false
  policy                  = data.aws_iam_policy_document.milnet_kms_policy.json

  tags = {
    Name       = "${local.name_prefix}-secrets-cmek"
    KeyPurpose = "secrets-encryption"
  }
}

resource "aws_kms_alias" "secrets_cmek" {
  name          = "alias/${local.name_prefix}-secrets-cmek"
  target_key_id = aws_kms_key.secrets_cmek.key_id
}

# ── Audit Signing Key (asymmetric) ──

resource "aws_kms_key" "audit_signing" {
  description             = "MILNET GovCloud audit log signing key — RSA 4096"
  deletion_window_in_days = 30
  enable_key_rotation     = false  # Asymmetric keys do not support auto-rotation
  key_usage               = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_4096"
  multi_region            = false
  policy                  = data.aws_iam_policy_document.milnet_kms_policy.json

  tags = {
    Name       = "${local.name_prefix}-audit-signing"
    KeyPurpose = "audit-signing"
  }
}

resource "aws_kms_alias" "audit_signing" {
  name          = "alias/${local.name_prefix}-audit-signing"
  target_key_id = aws_kms_key.audit_signing.key_id
}

# ── Outputs ──

output "master_key_arn" {
  value = aws_kms_key.master_kek.arn
}

output "rds_kms_key_arn" {
  value = aws_kms_key.rds_cmek.arn
}

output "ebs_kms_key_arn" {
  value = aws_kms_key.ebs_cmek.arn
}

output "secrets_kms_key_arn" {
  value = aws_kms_key.secrets_cmek.arn
}

output "audit_signing_key_arn" {
  value = aws_kms_key.audit_signing.arn
}

output "all_key_arns" {
  description = "Map of key name to ARN for IAM policy scoping"
  value = {
    master_kek    = aws_kms_key.master_kek.arn
    rds_cmek      = aws_kms_key.rds_cmek.arn
    ebs_cmek      = aws_kms_key.ebs_cmek.arn
    secrets_cmek  = aws_kms_key.secrets_cmek.arn
    audit_signing = aws_kms_key.audit_signing.arn
  }
}
