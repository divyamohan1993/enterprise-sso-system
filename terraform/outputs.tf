output "server_ip" {
  value       = google_compute_address.sso_ip.address
  description = "Public IP of the SSO server"
}

output "frontend_url" {
  value       = "http://${google_compute_address.sso_ip.address}:8080"
  description = "Frontend URL"
}

output "oidc_discovery" {
  value       = "http://${google_compute_address.sso_ip.address}:8080/.well-known/openid-configuration"
  description = "OIDC Discovery endpoint"
}

output "health_check" {
  value       = "http://${google_compute_address.sso_ip.address}:8080/api/health"
  description = "Health check endpoint"
}
