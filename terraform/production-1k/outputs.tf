###############################################################################
# MILNET SSO — Production 1K Outputs
###############################################################################

output "gke_cluster_name" {
  value       = google_container_cluster.primary.name
  description = "GKE cluster name"
}

output "gke_cluster_endpoint" {
  value       = google_container_cluster.primary.endpoint
  description = "GKE cluster endpoint (private)"
  sensitive   = true
}

output "gke_cluster_ca_certificate" {
  value       = google_container_cluster.primary.master_auth[0].cluster_ca_certificate
  description = "GKE cluster CA certificate"
  sensitive   = true
}

output "cloud_sql_instance" {
  value       = google_sql_database_instance.primary.name
  description = "Cloud SQL instance name"
}

output "cloud_sql_private_ip" {
  value       = google_sql_database_instance.primary.private_ip_address
  description = "Cloud SQL private IP"
  sensitive   = true
}

output "redis_host" {
  value       = google_redis_instance.cache.host
  description = "Memorystore Redis private IP"
  sensitive   = true
}

output "redis_port" {
  value       = google_redis_instance.cache.port
  description = "Memorystore Redis port"
}

output "kms_keyring" {
  value       = google_kms_key_ring.sso.id
  description = "Cloud KMS keyring ID"
}

output "kms_master_kek" {
  value       = google_kms_crypto_key.master_kek.id
  description = "Cloud KMS master KEK ID"
}

output "artifact_registry" {
  value       = "${var.artifact_registry_location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.sso.repository_id}"
  description = "Artifact Registry URL for container images"
}

output "workload_service_account" {
  value       = google_service_account.gke_workload.email
  description = "GKE Workload Identity service account"
}

output "cloud_armor_policy" {
  value       = google_compute_security_policy.sso.name
  description = "Cloud Armor security policy name"
}

output "vpc_network" {
  value       = google_compute_network.vpc.name
  description = "VPC network name"
}

###############################################################################
# Cost Estimate Summary
###############################################################################

output "cost_estimate" {
  value = <<-EOT

    ╔═══════════════════════════════════════════════════════════════════════╗
    ║  MILNET SSO — Production 1K Cost Estimate (us-central1)             ║
    ╠═══════════════════════════════════════════════════════════════════════╣
    ║                                                                     ║
    ║  GKE Compute (4 node pools)                                         ║
    ║    General:      3x e2-standard-4  ......... ~$292/mo               ║
    ║    Compute:      2x t2d-standard-8 ......... ~$540/mo               ║
    ║    Confidential: 5x n2d-standard-2 ......... ~$307/mo               ║
    ║    Stateful:     7x e2-standard-2  ......... ~$343/mo               ║
    ║    Subtotal compute ......................... ~$1,482/mo             ║
    ║                                                                     ║
    ║  Cloud SQL Enterprise Plus (8 vCPU, 32 GB, HA)                      ║
    ║    Compute + Storage ....................... ~$1,200/mo              ║
    ║                                                                     ║
    ║  Memorystore Redis Standard HA (4 GB)                               ║
    ║    Cache ..................................... ~$140/mo              ║
    ║                                                                     ║
    ║  Cloud KMS HSM (envelope encryption only)                           ║
    ║    3 key versions, <100 ops/day .............. ~$4/mo               ║
    ║                                                                     ║
    ║  Cloud Armor Standard (6 WAF rules)                                 ║
    ║    Policy + rules + 2.6B req/mo ............. ~$600/mo              ║
    ║                                                                     ║
    ║  Networking (LB + NAT + VPC)                                        ║
    ║    Global HTTPS LB + Cloud NAT .............. ~$170/mo              ║
    ║                                                                     ║
    ║  Observability (Logging + Monitoring + Trace)                       ║
    ║    50 GiB logs + metrics + 2% trace ......... ~$120/mo              ║
    ║                                                                     ║
    ║  Secret Manager + Artifact Registry                                 ║
    ║    Secrets + container storage ................ ~$10/mo              ║
    ║                                                                     ║
    ╠═══════════════════════════════════════════════════════════════════════╣
    ║  TOTAL (on-demand) ........................ ~$3,726/mo              ║
    ║  TOTAL (1-year CUD, 25% off compute+DB) ... ~$3,050/mo             ║
    ║  TOTAL (3-year CUD, 52% off compute+DB) ... ~$2,400/mo             ║
    ╠═══════════════════════════════════════════════════════════════════════╣
    ║                                                                     ║
    ║  COMPARISON (at 100K users):                                        ║
    ║    Okta Enterprise:  $6/user/mo = $600,000/mo                       ║
    ║    Auth0 Enterprise: $3/user/mo = $300,000/mo                       ║
    ║    Azure AD P2:      $9/user/mo = $900,000/mo                       ║
    ║    MILNET SSO:       $0.037/user/mo = $3,726/mo                     ║
    ║                                                                     ║
    ║  SECURITY ADVANTAGE (vs ALL competitors):                           ║
    ║    ✓ Post-quantum crypto (ML-KEM-1024 + ML-DSA-87)                  ║
    ║    ✓ Threshold signing (3-of-5 FROST — no single key)               ║
    ║    ✓ Server-blind passwords (OPAQUE RFC 9497)                       ║
    ║    ✓ Forward-secret sessions (HKDF ratcheting)                      ║
    ║    ✓ BFT tamper-proof audit (7-node Byzantine tolerance)            ║
    ║    ✓ DPoP token binding (stolen tokens unusable)                    ║
    ║    ✓ Confidential Computing (AMD SEV encrypted RAM)                 ║
    ║    ✓ MIT Licensed — free forever                                    ║
    ║                                                                     ║
    ╚═══════════════════════════════════════════════════════════════════════╝

  EOT

  description = "Estimated monthly cost breakdown"
}
