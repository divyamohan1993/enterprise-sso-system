output "vm_ip" {
  description = "External IP address of the SSO demo VM"
  value       = google_compute_address.sso_demo.address
}

output "ssh_command" {
  description = "SSH command to connect to the VM"
  value       = "gcloud compute ssh sso-demo-vm --zone=${var.zone} --project=${var.project_id}"
}

output "admin_url" {
  description = "Admin panel URL"
  value       = "http://${google_compute_address.sso_demo.address}:8080"
}

output "gateway_address" {
  description = "Gateway service address"
  value       = "${google_compute_address.sso_demo.address}:9100"
}

output "frontend_url" {
  description = "Frontend URL"
  value       = "http://${google_compute_address.sso_demo.address}"
}
