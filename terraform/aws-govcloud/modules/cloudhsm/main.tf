# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — AWS GovCloud CloudHSM Module
# ──────────────────────────────────────────────────────────────────────────────
# AWS CloudHSM cluster in GovCloud.
# FIPS 140-3 Level 3 certified hardware.
# Minimum 2 HSMs for HA (CloudHSM requires 2+ for production clusters).
#
# After apply, the cluster must be initialized:
#   1. Get the CSR from cluster_certificates output
#   2. Sign with your CA
#   3. Run deploy/bare-metal/security/cloud-hsm-init.sh --provider=aws
# ──────────────────────────────────────────────────────────────────────────────

variable "primary_region" { type = string }
variable "environment" { type = string }
variable "subnet_ids" {
  description = "Subnet IDs for HSM placement (2+ required for HA)"
  type        = list(string)
}

locals {
  name_prefix = "milnet-govcloud-${var.environment}"
  is_prod     = var.environment == "production"
}

# ── CloudHSM Cluster ──

resource "aws_cloudhsm_v2_cluster" "milnet" {
  hsm_type   = "hsm1.medium"
  subnet_ids = slice(var.subnet_ids, 0, min(2, length(var.subnet_ids)))

  tags = {
    Name        = "${local.name_prefix}-cloudhsm"
    Environment = var.environment
    FipsLevel   = "140-3-level-3"
  }
}

# ── HSM Instances ──
# 2 HSMs for HA in production, 1 for dev/staging.

resource "aws_cloudhsm_v2_hsm" "primary" {
  cluster_id        = aws_cloudhsm_v2_cluster.milnet.cluster_id
  subnet_id         = var.subnet_ids[0]
  availability_zone = "${var.primary_region}a"
}

resource "aws_cloudhsm_v2_hsm" "secondary" {
  count = local.is_prod ? 1 : 0

  cluster_id        = aws_cloudhsm_v2_cluster.milnet.cluster_id
  subnet_id         = length(var.subnet_ids) > 1 ? var.subnet_ids[1] : var.subnet_ids[0]
  availability_zone = "${var.primary_region}b"

  depends_on = [aws_cloudhsm_v2_hsm.primary]
}

# ── Outputs ──

output "cluster_id" {
  description = "CloudHSM cluster ID"
  value       = aws_cloudhsm_v2_cluster.milnet.cluster_id
}

output "cluster_state" {
  description = "CloudHSM cluster state (must be INITIALIZED before use)"
  value       = aws_cloudhsm_v2_cluster.milnet.cluster_state
}

output "cluster_certificates" {
  description = "Cluster CSR — sign with CA to initialize"
  value       = aws_cloudhsm_v2_cluster.milnet.cluster_certificates
  sensitive   = true
}

output "hsm_eni_ids" {
  description = "ENI IDs for primary and secondary HSMs"
  value = concat(
    [aws_cloudhsm_v2_hsm.primary.hsm_eni_id],
    [for h in aws_cloudhsm_v2_hsm.secondary : h.hsm_eni_id]
  )
}
