###############################################################################
# outputs.tf — Enterprise SSO Multi-VM GCE Deployment
###############################################################################

# ---------- Load Balancer IPs ----------

output "gateway_lb_ip" {
  description = "Global external IP for the gateway TCP load balancer"
  value       = google_compute_global_address.gateway_lb.address
}

output "admin_lb_ip" {
  description = "Internal IP for the admin HTTPS load balancer"
  value       = google_compute_address.admin_ilb.address
}

# ---------- TSS Node IPs ----------

output "tss_node_ips" {
  description = "Private IPs of the 5 TSS nodes"
  value       = { for k, v in google_compute_instance.tss : k => v.network_interface[0].network_ip }
}

# ---------- Audit Node IPs ----------

output "audit_node_ips" {
  description = "Private IPs of the 7 audit BFT nodes"
  value       = { for k, v in google_compute_instance.audit : k => v.network_interface[0].network_ip }
}

# ---------- Singleton / HA Pair IPs ----------

output "orchestrator_ips" {
  description = "Private IPs of orchestrator HA pair"
  value       = [for i in google_compute_instance.orchestrator : i.network_interface[0].network_ip]
}

output "opaque_ips" {
  description = "Private IPs of opaque HA pair"
  value       = [for i in google_compute_instance.opaque : i.network_interface[0].network_ip]
}

output "ratchet_ips" {
  description = "Private IPs of ratchet HA pair"
  value       = [for i in google_compute_instance.ratchet : i.network_interface[0].network_ip]
}

output "risk_ip" {
  description = "Private IP of risk scoring node"
  value       = google_compute_instance.risk.network_interface[0].network_ip
}

output "kt_ip" {
  description = "Private IP of key transparency node"
  value       = google_compute_instance.kt.network_interface[0].network_ip
}

# ---------- Database ----------

output "db_connection_name" {
  description = "Cloud SQL connection name"
  value       = google_sql_database_instance.primary.connection_name
}

output "db_private_ip" {
  description = "Cloud SQL private IP"
  value       = google_sql_database_instance.primary.private_ip_address
}

output "db_replica_connection_name" {
  description = "Cloud SQL replica connection name"
  value       = google_sql_database_instance.replica.connection_name
}

# ---------- Network ----------

output "vpc_id" {
  description = "VPC network self-link"
  value       = google_compute_network.sso_vpc.self_link
}

output "vpc_name" {
  description = "VPC network name"
  value       = google_compute_network.sso_vpc.name
}

output "private_subnet_self_link" {
  description = "Private subnet self-link"
  value       = google_compute_subnetwork.private.self_link
}

# ---------- Service Accounts ----------

output "service_accounts" {
  description = "Service account emails keyed by service name"
  value = {
    gateway      = google_service_account.gateway.email
    admin        = google_service_account.admin.email
    orchestrator = google_service_account.orchestrator.email
    opaque       = google_service_account.opaque.email
    tss          = google_service_account.tss.email
    verifier     = google_service_account.verifier.email
    ratchet      = google_service_account.ratchet.email
    risk         = google_service_account.risk.email
    audit        = google_service_account.audit.email
    kt           = google_service_account.kt.email
  }
}

# ---------- Instance Groups ----------

output "gateway_instance_group" {
  description = "Gateway managed instance group self-link"
  value       = google_compute_region_instance_group_manager.gateway.instance_group
}

output "admin_instance_group" {
  description = "Admin managed instance group self-link"
  value       = google_compute_region_instance_group_manager.admin.instance_group
}

output "verifier_instance_group" {
  description = "Verifier managed instance group self-link"
  value       = google_compute_region_instance_group_manager.verifier.instance_group
}
