# ============================================================================
# MILNET SSO — Dev/Test Outputs
# ============================================================================

# ── Test Runner VM ───────────────────────────────────────────────────────────

output "test_runner_ip" {
  description = "Public IP of the test runner VM"
  value       = google_compute_instance.test_runner.network_interface[0].access_config[0].nat_ip
}

output "test_runner_name" {
  description = "Name of the test runner VM instance"
  value       = google_compute_instance.test_runner.name
}

output "ssh_command" {
  description = "SSH command to connect to the test runner"
  value       = "gcloud compute ssh ${google_compute_instance.test_runner.name} --zone=${var.zone} --project=${var.project_id}"
}

output "tail_startup_logs" {
  description = "Command to tail startup script logs on the VM"
  value       = "gcloud compute ssh ${google_compute_instance.test_runner.name} --zone=${var.zone} --project=${var.project_id} --command='sudo tail -f /var/log/milnet-test.log'"
}

output "test_status_command" {
  description = "Command to check test status from VM metadata"
  value       = "gcloud compute instances describe ${google_compute_instance.test_runner.name} --zone=${var.zone} --project=${var.project_id} --format='value(metadata.items[key=test-status].value)'"
}

# ── Cloud SQL ────────────────────────────────────────────────────────────────

output "cloud_sql_instance" {
  description = "Cloud SQL instance name"
  value       = google_sql_database_instance.test_db.name
}

output "cloud_sql_connection_string" {
  description = "PostgreSQL connection string (use from within VPC or Cloud SQL Proxy)"
  value       = "postgres://milnet:****@${google_sql_database_instance.test_db.private_ip_address}:5432/milnet_sso"
}

output "cloud_sql_private_ip" {
  description = "Cloud SQL private IP address"
  value       = google_sql_database_instance.test_db.private_ip_address
}

output "cloud_sql_proxy_command" {
  description = "Command to connect via Cloud SQL Auth Proxy"
  value       = "cloud-sql-proxy ${var.project_id}:${var.region}:${google_sql_database_instance.test_db.name}"
}

# ── Cloud Run Services ───────────────────────────────────────────────────────

output "cloud_run_gateway_url" {
  description = "Cloud Run gateway service URL"
  value       = google_cloud_run_v2_service.services["gateway"].uri
}

output "cloud_run_service_urls" {
  description = "All Cloud Run service URLs"
  value = {
    for name, svc in google_cloud_run_v2_service.services :
    name => svc.uri
  }
}

output "cloud_run_tss_urls" {
  description = "TSS node Cloud Run URLs"
  value = [
    for svc in google_cloud_run_v2_service.tss :
    svc.uri
  ]
}

# ── Security ─────────────────────────────────────────────────────────────────

output "kms_keyring" {
  description = "Cloud KMS keyring name"
  value       = google_kms_key_ring.milnet_sso.name
}

output "kms_master_kek_id" {
  description = "Cloud KMS master KEK resource ID"
  value       = google_kms_crypto_key.master_kek.id
}

output "artifact_registry" {
  description = "Artifact Registry repository path"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.milnet_sso.repository_id}"
}

# ── Internal LB ──────────────────────────────────────────────────────────────

output "internal_lb_ip" {
  description = "Internal load balancer IP for gateway"
  value       = google_compute_forwarding_rule.gateway_ilb.ip_address
}

# ── Deployment Info ──────────────────────────────────────────────────────────

output "deployment_suffix" {
  description = "Random suffix for this deployment (used in all resource names)"
  value       = local.name_suffix
}

output "destroy_command" {
  description = "Command to destroy all resources"
  value       = "cd ${abspath(path.module)} && terraform destroy -auto-approve"
}
