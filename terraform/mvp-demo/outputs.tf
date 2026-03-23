output "vm_ip" {
  description = "External IP address of the SSO demo VM"
  value       = google_compute_address.sso_demo.address
}

output "ssh_command" {
  description = "SSH command to connect to the VM"
  value       = "gcloud compute ssh sso-demo-vm --zone=${var.zone} --project=${var.project_id}"
}

output "admin_url" {
  description = "Admin panel URL (HTTPS via nginx reverse proxy)"
  value       = "https://${google_compute_address.sso_demo.address}"
}

output "gateway_address" {
  description = "Gateway service address"
  value       = "${google_compute_address.sso_demo.address}:9100"
}

output "frontend_url" {
  description = "Frontend URL (redirects to HTTPS)"
  value       = "https://${google_compute_address.sso_demo.address}"
}

output "service_status_command" {
  description = "Command to check all milnet service statuses"
  value       = "gcloud compute ssh sso-demo-vm --zone=${var.zone} --project=${var.project_id} -- 'systemctl list-units milnet-*.service --no-pager'"
}
