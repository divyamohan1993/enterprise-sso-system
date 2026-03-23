###############################################################################
# Outputs — Enterprise SSO Hyper-Scale Deployment
###############################################################################

# GKE Cluster
output "gke_cluster_endpoint" {
  description = "GKE cluster API server endpoint"
  value       = google_container_cluster.primary.endpoint
  sensitive   = true
}

output "gke_cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.primary.name
}

output "gke_cluster_location" {
  description = "GKE cluster location (region)"
  value       = google_container_cluster.primary.location
}

output "gke_cluster_ca_certificate" {
  description = "GKE cluster CA certificate (base64-encoded)"
  value       = google_container_cluster.primary.master_auth[0].cluster_ca_certificate
  sensitive   = true
}

# Load Balancer IPs
output "admin_lb_ip" {
  description = "Global external IP address for the Admin API HTTPS load balancer"
  value       = google_compute_global_address.admin_lb.address
}

output "gateway_ilb_ip" {
  description = "Internal IP address for the Gateway TCP load balancer"
  value       = google_compute_address.gateway_ilb.address
}

# Cloud SQL
output "cloudsql_connection_name" {
  description = "Cloud SQL instance connection name (project:region:instance)"
  value       = google_sql_database_instance.primary.connection_name
}

output "cloudsql_private_ip" {
  description = "Cloud SQL private IP address"
  value       = google_sql_database_instance.primary.private_ip_address
}

output "cloudsql_database_name" {
  description = "PostgreSQL database name"
  value       = google_sql_database.sso.name
}

# Redis
output "redis_host" {
  description = "Memorystore Redis host IP"
  value       = google_redis_instance.token_cache.host
}

output "redis_port" {
  description = "Memorystore Redis port"
  value       = google_redis_instance.token_cache.port
}

# Cloud KMS
output "kms_keyring_id" {
  description = "Cloud KMS keyring resource ID"
  value       = google_kms_key_ring.sso.id
}

output "kms_master_kek_id" {
  description = "Cloud KMS master KEK key resource ID (envelope encryption)"
  value       = google_kms_crypto_key.master_kek.id
}

output "kms_receipt_signing_key_id" {
  description = "Cloud KMS receipt signing key resource ID (OPAQUE receipts)"
  value       = google_kms_crypto_key.receipt_signing.id
}

output "kms_audit_signing_key_id" {
  description = "Cloud KMS audit signing key resource ID (audit log signatures)"
  value       = google_kms_crypto_key.audit_signing.id
}

# Artifact Registry
output "artifact_registry_url" {
  description = "Artifact Registry Docker repository URL"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.sso.repository_id}"
}

# Service Accounts
output "workload_service_account_email" {
  description = "GKE Workload Identity service account email"
  value       = google_service_account.gke_workload.email
}

output "cloud_build_service_account_email" {
  description = "Cloud Build service account email"
  value       = google_service_account.cloud_build.email
}

# Certificate Authority
output "ca_pool_id" {
  description = "Certificate Authority Service pool ID for mTLS"
  value       = google_privateca_ca_pool.sso.id
}

# Network
output "vpc_id" {
  description = "VPC network resource ID"
  value       = google_compute_network.vpc.id
}

output "vpc_name" {
  description = "VPC network name"
  value       = google_compute_network.vpc.name
}

# DNS
output "dns_zone_name" {
  description = "Private DNS zone name for service discovery"
  value       = google_dns_managed_zone.private.dns_name
}

# Audit Logs
output "audit_log_bucket" {
  description = "Cloud Storage bucket for audit log archival"
  value       = google_storage_bucket.audit_logs.name
}
