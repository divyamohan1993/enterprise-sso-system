# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — AWS GovCloud Outputs
# ──────────────────────────────────────────────────────────────────────────────

output "vpc_id" {
  description = "VPC ID in primary GovCloud region"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = module.vpc.private_subnet_ids
}

output "cloudhsm_cluster_id" {
  description = "CloudHSM cluster ID"
  value       = module.cloudhsm.cluster_id
}

output "cloudhsm_cluster_certificates" {
  description = "CloudHSM cluster CSR (used to initialize cluster)"
  value       = module.cloudhsm.cluster_certificates
  sensitive   = true
}

output "rds_endpoint" {
  description = "RDS cluster writer endpoint"
  value       = module.rds.endpoint
  sensitive   = true
}

output "rds_port" {
  description = "RDS cluster port"
  value       = module.rds.port
}

output "kms_master_key_arn" {
  description = "ARN of the master KMS key"
  value       = module.kms.master_key_arn
}

output "instance_ids" {
  description = "Map of service name to EC2 instance ID"
  value       = module.ec2.instance_ids
}

output "iam_role_arns" {
  description = "Map of service name to IAM role ARN"
  value       = module.iam.role_arns
}
