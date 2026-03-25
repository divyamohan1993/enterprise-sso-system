# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — GCP India Outputs
# ──────────────────────────────────────────────────────────────────────────────

output "vpc_id" {
  description = "Self-link of the India VPC"
  value       = module.vpc.vpc_id
}

output "primary_subnet_id" {
  description = "Self-link of the asia-south1 subnet"
  value       = module.vpc.primary_subnet_id
}

output "secondary_subnet_id" {
  description = "Self-link of the asia-south2 subnet"
  value       = module.vpc.secondary_subnet_id
}

output "cloud_sql_connection_name" {
  description = "Cloud SQL instance connection name for application use"
  value       = module.cloud_sql.connection_name
}

output "cloud_sql_private_ip" {
  description = "Cloud SQL primary instance private IP address"
  value       = module.cloud_sql.private_ip
  sensitive   = true
}

output "kms_keyring_id" {
  description = "Cloud KMS keyring resource ID"
  value       = module.kms.keyring_id
}

output "kms_master_kek_id" {
  description = "Cloud KMS master KEK crypto key ID"
  value       = module.kms.master_kek_id
}

output "hsm_key_id" {
  description = "Cloud HSM-protected master key ID"
  value       = module.cloud_hsm.hsm_master_key_id
}

output "gcs_audit_bucket" {
  description = "GCS bucket name for audit logs"
  value       = module.gcs.audit_bucket_name
}

output "gcs_backup_bucket" {
  description = "GCS bucket name for backups"
  value       = module.gcs.backup_bucket_name
}

output "service_account_emails" {
  description = "Map of service name to service account email"
  value       = module.iam.service_account_emails
}
