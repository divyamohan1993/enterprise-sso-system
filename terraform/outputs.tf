output "server_ip" {
  description = "External IP address of the MILNET SSO server"
  value       = google_compute_instance.sso_server.network_interface[0].access_config[0].nat_ip
}

output "sso_url" {
  description = "URL to access the MILNET SSO admin API"
  value       = "http://${google_compute_instance.sso_server.network_interface[0].access_config[0].nat_ip}:8080"
}

output "instance_name" {
  description = "Name of the Compute Engine instance"
  value       = google_compute_instance.sso_server.name
}
