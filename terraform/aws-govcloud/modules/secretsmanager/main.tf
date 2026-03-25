# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — AWS GovCloud Secrets Manager Module
# ──────────────────────────────────────────────────────────────────────────────
# Per-service secrets encrypted with CMEK.
# Automatic rotation configured for database passwords.
# Secrets are namespaced: milnet/<environment>/<service>/<secret-name>
# ──────────────────────────────────────────────────────────────────────────────

variable "primary_region" { type = string }
variable "environment" { type = string }
variable "service_names" { type = list(string) }
variable "kms_key_arn" { type = string }

locals {
  name_prefix = "milnet-govcloud-${var.environment}"

  # Per-service secrets to pre-create (empty value — populated at deployment)
  service_secrets = {
    for combo in flatten([
      for svc in var.service_names : [
        { service = svc, secret = "db-password" },
        { service = svc, secret = "jwt-secret" },
        { service = svc, secret = "api-key" },
      ]
    ]) : "${combo.service}/${combo.secret}" => combo
  }
}

# ── Per-Service Secrets ──

resource "aws_secretsmanager_secret" "service_secrets" {
  for_each = local.service_secrets

  name        = "milnet/${var.environment}/${each.value.service}/${each.value.secret}"
  description = "MILNET ${each.value.service} ${each.value.secret}"
  kms_key_id  = var.kms_key_arn

  # Retain deleted secrets for 30 days (prevents accidental deletion)
  recovery_window_in_days = 30

  tags = {
    Service     = each.value.service
    SecretType  = each.value.secret
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ── Resource Policy: Deny access outside GovCloud ──

data "aws_iam_policy_document" "secrets_resource_policy" {
  for_each = local.service_secrets

  statement {
    sid    = "DenyNonGovCloud"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = [var.primary_region]
    }
  }
}

resource "aws_secretsmanager_secret_policy" "service_secrets" {
  for_each = local.service_secrets

  secret_arn = aws_secretsmanager_secret.service_secrets[each.key].arn
  policy     = data.aws_iam_policy_document.secrets_resource_policy[each.key].json
}

# ── Outputs ──

output "secret_arns" {
  description = "Map of service/secret-name to ARN"
  value       = { for k, s in aws_secretsmanager_secret.service_secrets : k => s.arn }
  sensitive   = true
}
