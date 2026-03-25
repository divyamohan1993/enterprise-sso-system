# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — Terraform Outputs
# ──────────────────────────────────────────────────────────────────────────────

# ── Networking ──

output "vpc_id" {
  description = "Self-link of the VPC network"
  value       = module.networking.vpc_id
}

output "subnet_id" {
  description = "Self-link of the primary subnet"
  value       = module.networking.subnet_id
}

# ── KMS ──

output "kms_keyring_id" {
  description = "ID of the Cloud KMS keyring"
  value       = module.kms.keyring_id
}

output "master_kek_crypto_key_id" {
  description = "ID of the master KEK crypto key"
  value       = module.kms.master_kek_crypto_key_id
}

# ── Database ──

output "database_instance_name" {
  description = "Cloud SQL instance name"
  value       = module.database.instance_name
}

output "database_private_ip" {
  description = "Private IP address of the Cloud SQL instance"
  value       = module.database.private_ip
  sensitive   = true
}

output "database_connection_name" {
  description = "Cloud SQL connection name (project:region:instance)"
  value       = module.database.connection_name
}

# ── GKE ──

output "gke_cluster_name" {
  description = "Name of the GKE cluster"
  value       = module.gke.cluster_name
}

output "gke_cluster_endpoint" {
  description = "GKE cluster master endpoint (private)"
  value       = module.gke.cluster_endpoint
  sensitive   = true
}

# ── IAM ──

output "service_account_emails" {
  description = "Map of service name to service account email"
  value       = module.iam.service_account_emails
}

output "gke_node_sa_email" {
  description = "GKE node pool service account email"
  value       = module.iam.gke_node_sa_email
}

# ── Secrets ──

output "secret_ids" {
  description = "Map of secret name to Secret Manager secret ID"
  value       = module.secrets.secret_ids
}
