# ============================================================================
# MILNET SSO — Production Deployment Outputs
# ============================================================================

# ── Public Endpoints ─────────────────────────────────────────────────────────

output "gateway_public_ip" {
  description = "Gateway VM public IP (port 9100)"
  value       = google_compute_instance.gateway.network_interface[0].access_config[0].nat_ip
}

output "gateway_url" {
  description = "Gateway API URL"
  value       = "http://${google_compute_instance.gateway.network_interface[0].access_config[0].nat_ip}:9100"
}

output "admin_api_url" {
  description = "Admin API URL"
  value       = "http://${google_compute_instance.core.network_interface[0].access_config[0].nat_ip}:8080"
}

# ── Internal IPs ─────────────────────────────────────────────────────────────

output "gateway_internal_ip" {
  description = "Gateway VM internal IP"
  value       = google_compute_instance.gateway.network_interface[0].network_ip
}

output "core_internal_ip" {
  description = "Core VM internal IP"
  value       = google_compute_instance.core.network_interface[0].network_ip
}

output "tss_internal_ip" {
  description = "TSS VM internal IP"
  value       = google_compute_instance.tss.network_interface[0].network_ip
}

# ── SSH Commands ─────────────────────────────────────────────────────────────

output "ssh_gateway" {
  description = "SSH to gateway VM"
  value       = "gcloud compute ssh milnet-gateway --zone=${var.zone} --project=${var.project_id}"
}

output "ssh_core" {
  description = "SSH to core VM"
  value       = "gcloud compute ssh milnet-core --zone=${var.zone} --project=${var.project_id}"
}

output "ssh_tss" {
  description = "SSH to TSS VM"
  value       = "gcloud compute ssh milnet-tss --zone=${var.zone} --project=${var.project_id}"
}

# ── Operational ──────────────────────────────────────────────────────────────

output "destroy_command" {
  description = "Command to destroy all resources"
  value       = "cd ${abspath(path.module)} && terraform destroy -auto-approve"
}

output "view_logs_gateway" {
  description = "View gateway startup logs"
  value       = "gcloud compute ssh milnet-gateway --zone=${var.zone} --project=${var.project_id} --command='sudo cat /var/log/milnet-startup.log'"
}

output "view_logs_core" {
  description = "View core startup logs"
  value       = "gcloud compute ssh milnet-core --zone=${var.zone} --project=${var.project_id} --command='sudo cat /var/log/milnet-startup.log'"
}

output "view_logs_tss" {
  description = "View TSS startup logs"
  value       = "gcloud compute ssh milnet-tss --zone=${var.zone} --project=${var.project_id} --command='sudo cat /var/log/milnet-startup.log'"
}
