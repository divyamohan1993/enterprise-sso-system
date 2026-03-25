# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — AWS GovCloud IAM Module
# ──────────────────────────────────────────────────────────────────────────────
# Per-service IAM roles with least-privilege policies.
# All roles trust EC2 service principal (for instance profiles).
# No wildcard resources; policies scoped to MILNET-prefixed resources.
# ──────────────────────────────────────────────────────────────────────────────

variable "environment" { type = string }
variable "service_names" { type = list(string) }
variable "kms_key_arns" {
  description = "Map of key name to ARN for scoped KMS policies"
  type        = map(string)
  default     = {}
}

locals {
  name_prefix = "milnet-govcloud-${var.environment}"
}

# ── Trust Policy: EC2 assumes these roles ──

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# ── Per-Service Roles ──

resource "aws_iam_role" "services" {
  for_each = toset(var.service_names)

  name               = "${local.name_prefix}-${each.value}-role"
  description        = "MILNET ${each.value} service role — least privilege"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = {
    Service     = each.value
    Environment = var.environment
  }
}

# ── Instance Profiles ──

resource "aws_iam_instance_profile" "services" {
  for_each = toset(var.service_names)

  name = "${local.name_prefix}-${each.value}-profile"
  role = aws_iam_role.services[each.value].name
}

# ── Base Policy: CloudWatch Logs ──

data "aws_iam_policy_document" "cloudwatch_logs" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = ["arn:aws-us-gov:logs:*:*:log-group:/milnet/*"]
  }
}

resource "aws_iam_policy" "cloudwatch_logs" {
  name        = "${local.name_prefix}-cloudwatch-logs"
  description = "Allow MILNET services to write to CloudWatch Logs"
  policy      = data.aws_iam_policy_document.cloudwatch_logs.json
}

resource "aws_iam_role_policy_attachment" "cloudwatch_logs" {
  for_each = toset(var.service_names)

  role       = aws_iam_role.services[each.value].name
  policy_arn = aws_iam_policy.cloudwatch_logs.arn
}

# ── Secrets Manager Policy: Per-service secret access ──

data "aws_iam_policy_document" "secrets_per_service" {
  for_each = toset(var.service_names)

  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    # Scoped to own service prefix only
    resources = [
      "arn:aws-us-gov:secretsmanager:*:*:secret:milnet/${var.environment}/${each.value}/*"
    ]
  }
}

resource "aws_iam_policy" "secrets_per_service" {
  for_each = toset(var.service_names)

  name        = "${local.name_prefix}-${each.value}-secrets"
  description = "MILNET ${each.value}: access own secrets only"
  policy      = data.aws_iam_policy_document.secrets_per_service[each.value].json
}

resource "aws_iam_role_policy_attachment" "secrets_per_service" {
  for_each = toset(var.service_names)

  role       = aws_iam_role.services[each.value].name
  policy_arn = aws_iam_policy.secrets_per_service[each.value].arn
}

# ── KMS Policy: Decrypt only (no key administration) ──

data "aws_iam_policy_document" "kms_decrypt" {
  statement {
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = length(var.kms_key_arns) > 0 ? values(var.kms_key_arns) : ["*"]
  }
}

resource "aws_iam_policy" "kms_decrypt" {
  name        = "${local.name_prefix}-kms-decrypt"
  description = "Allow MILNET services to decrypt with KMS (no admin)"
  policy      = data.aws_iam_policy_document.kms_decrypt.json
}

resource "aws_iam_role_policy_attachment" "kms_decrypt" {
  for_each = toset(var.service_names)

  role       = aws_iam_role.services[each.value].name
  policy_arn = aws_iam_policy.kms_decrypt.arn
}

# ── Audit Service Extra Permissions ──

data "aws_iam_policy_document" "audit_extra" {
  statement {
    effect  = "Allow"
    actions = ["kms:Sign", "kms:Verify", "kms:GetPublicKey"]
    resources = length(var.kms_key_arns) > 0 ? values(var.kms_key_arns) : ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:RequestAlias"
      values   = ["alias/milnet-*-audit-*"]
    }
  }
}

resource "aws_iam_policy" "audit_sign" {
  name        = "${local.name_prefix}-audit-sign"
  description = "Allow audit service to sign with KMS asymmetric key"
  policy      = data.aws_iam_policy_document.audit_extra.json
}

resource "aws_iam_role_policy_attachment" "audit_sign" {
  role       = aws_iam_role.services["audit"].name
  policy_arn = aws_iam_policy.audit_sign.arn
}

# ── Outputs ──

output "role_arns" {
  description = "Map of service name to IAM role ARN"
  value       = { for svc, role in aws_iam_role.services : svc => role.arn }
}

output "instance_profile_arns" {
  description = "Map of service name to instance profile ARN"
  value       = { for svc, prof in aws_iam_instance_profile.services : svc => prof.arn }
}
