# ============================================================================
# MILNET SSO — Optimal Cost Outputs
# ============================================================================

# ── Cluster ──────────────────────────────────────────────────────────────────

output "cluster_name" {
  description = "GKE Autopilot cluster name"
  value       = google_container_cluster.autopilot.name
}

output "cluster_endpoint" {
  description = "GKE cluster API endpoint"
  value       = google_container_cluster.autopilot.endpoint
  sensitive   = true
}

output "cluster_ca_certificate" {
  description = "GKE cluster CA certificate (base64)"
  value       = google_container_cluster.autopilot.master_auth[0].cluster_ca_certificate
  sensitive   = true
}

output "kubeconfig_command" {
  description = "Command to configure kubectl"
  value       = "gcloud container clusters get-credentials ${google_container_cluster.autopilot.name} --zone ${var.zone} --project ${var.project_id}"
}

# ── Database ─────────────────────────────────────────────────────────────────

output "db_private_ip" {
  description = "Cloud SQL private IP address"
  value       = google_sql_database_instance.postgres.private_ip_address
}

output "db_connection_name" {
  description = "Cloud SQL connection name (for Cloud SQL Proxy)"
  value       = google_sql_database_instance.postgres.connection_name
}

output "db_instance_name" {
  description = "Cloud SQL instance name"
  value       = google_sql_database_instance.postgres.name
}

# ── Security ─────────────────────────────────────────────────────────────────

output "kms_key_ring" {
  description = "Cloud KMS key ring resource name"
  value       = google_kms_key_ring.sso.id
}

output "kms_token_signing_key" {
  description = "Cloud KMS token signing key resource name"
  value       = google_kms_crypto_key.token_signing.id
}

output "kms_data_encryption_key" {
  description = "Cloud KMS data encryption key resource name"
  value       = google_kms_crypto_key.data_encryption.id
}

output "kms_tss_shares_key" {
  description = "Cloud KMS TSS share encryption key resource name"
  value       = google_kms_crypto_key.tss_shares.id
}

output "workload_identity_sa" {
  description = "Workload Identity GCP service account email"
  value       = google_service_account.sso_workload.email
}

# ── Networking ───────────────────────────────────────────────────────────────

output "vpc_id" {
  description = "VPC network ID"
  value       = google_compute_network.vpc.id
}

output "subnet_id" {
  description = "Subnet ID"
  value       = google_compute_subnetwork.subnet.id
}

output "admin_lb_ip" {
  description = "Global static IP for Admin API load balancer — set DNS A record here"
  value       = google_compute_global_address.admin_lb.address
}

output "dns_instructions" {
  description = "DNS configuration instructions"
  value       = "Set an A record for ${var.domain} pointing to ${google_compute_global_address.admin_lb.address}"
}

# ── Container Registry ───────────────────────────────────────────────────────

output "artifact_registry_url" {
  description = "Artifact Registry repository URL for docker push"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.sso.repository_id}"
}

output "docker_push_commands" {
  description = "Commands to build and push container images"
  value       = <<-EOT
    # Authenticate Docker to Artifact Registry
    gcloud auth configure-docker ${var.region}-docker.pkg.dev

    # Build and push (from repo root)
    docker build -t ${local.ar_repo}/sso:${local.image_tag} .
    docker push ${local.ar_repo}/sso:${local.image_tag}
  EOT
}

# ── Monitoring ───────────────────────────────────────────────────────────────

output "uptime_check_id" {
  description = "Cloud Monitoring uptime check ID"
  value       = google_monitoring_uptime_check_config.admin_api.uptime_check_id
}

# ── Cost Summary ─────────────────────────────────────────────────────────────

output "estimated_monthly_cost" {
  description = "Estimated monthly cost breakdown"
  value       = <<-EOT
    MILNET SSO Optimal Cost Estimate (~$200-400/month):
    -------------------------------------------------------
    GKE Autopilot pods (pay-per-pod)  : ~$80-150/month
      - 10 services, minimal resources
      - Autopilot can scale to zero when idle
    Cloud SQL db-f1-micro (single)    : ~$10/month
    Cloud KMS software keys (3 keys)  : ~$1/month
    Secret Manager (5 secrets)        : ~$2/month
    Cloud NAT                         : ~$30/month
    Global HTTPS LB                   : ~$18/month
    Cloud Armor (basic)               : ~$5/month
    Managed SSL certificate           : Free
    Cloud Logging (GKE included)      : ~$0-20/month
    Cloud Monitoring + uptime check   : ~$0-5/month
    Artifact Registry                 : ~$1-5/month
    Static IP                         : ~$3/month
    -------------------------------------------------------
    Total estimate                    : ~$150-250/month base
                                        ~$200-400/month with traffic
  EOT
}
