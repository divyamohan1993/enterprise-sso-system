###############################################################################
# MILNET SSO — Production 10K Outputs
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

output "redis_cluster_discovery" {
  value       = google_redis_cluster.cache.discovery_endpoints
  description = "Memorystore Redis Cluster discovery endpoints"
  sensitive   = true
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

output "cdn_backend" {
  value       = var.enable_cloud_cdn ? google_compute_backend_bucket.jwks_cdn[0].self_link : "disabled"
  description = "Cloud CDN backend bucket for JWKS (if enabled)"
}

###############################################################################
# Cost Estimate Summary — Production 10K
###############################################################################

output "cost_estimate" {
  value = <<-EOT

    +=====================================================================+
    |  MILNET SSO -- Production 10K Cost Estimate (us-central1)           |
    +=====================================================================+
    |                                                                     |
    |  GKE Compute (4 node pools)                                         |
    |    General:      8x e2-standard-8  ......... ~$1,536/mo             |
    |    Compute:      6x c3d-standard-8 ......... ~$2,100/mo             |
    |    Confidential: 5x n2d-standard-4 ......... ~$614/mo              |
    |    Stateful:     7x e2-standard-4  ......... ~$1,250/mo             |
    |    Subtotal compute ......................... ~$5,500/mo             |
    |                                                                     |
    |  Cloud SQL Enterprise Plus (16 vCPU, 64 GB, HA)                     |
    |    Compute + Storage (500 GB SSD) .......... ~$2,800/mo             |
    |                                                                     |
    |  Memorystore Redis Cluster (16 GB, 4 shards)                        |
    |    Cache ................................... ~$350/mo               |
    |                                                                     |
    |  Cloud KMS HSM (envelope encryption only)                           |
    |    3 key versions, <100 ops/day ............ ~$15/mo               |
    |                                                                     |
    |  Cloud Armor Enterprise (flat rate)                                  |
    |    Adaptive protection + WAF + DDoS ........ ~$3,000/mo             |
    |                                                                     |
    |  Cloud CDN + Global HTTPS LB + Cloud NAT                            |
    |    CDN for JWKS + LB + NAT ................. ~$300/mo              |
    |                                                                     |
    |  Observability (Logging + Monitoring + Trace)                       |
    |    500 GiB logs + metrics + 2% trace ....... ~$300/mo              |
    |                                                                     |
    |  Secret Manager + Artifact Registry                                 |
    |    Secrets + container storage .............. ~$15/mo               |
    |                                                                     |
    +=====================================================================+
    |  TOTAL (on-demand) ....................... ~$12,265/mo              |
    |  TOTAL (1-year CUD, 25% off compute+DB) .. ~$10,000/mo             |
    |  TOTAL (3-year CUD, 52% off compute+DB) .. ~$8,500/mo              |
    +=====================================================================+
    |                                                                     |
    |  SCALING FROM PRODUCTION-1K:                                        |
    |                                                                     |
    |    +-------------------+----------+-----------+--------+            |
    |    | Component         | 1K/s     | 10K/s     | Factor |            |
    |    +-------------------+----------+-----------+--------+            |
    |    | GKE Compute       | $1,482   | $5,500    | 3.7x   |            |
    |    | Cloud SQL         | $1,200   | $2,800    | 2.3x   |            |
    |    | Redis             | $140     | $350      | 2.5x   |            |
    |    | Cloud Armor       | $600     | $3,000    | 5.0x   |            |
    |    | CDN + LB + NAT    | $170     | $300      | 1.8x   |            |
    |    | Observability     | $120     | $300      | 2.5x   |            |
    |    | KMS + Secrets     | $14      | $15       | 1.1x   |            |
    |    +-------------------+----------+-----------+--------+            |
    |    | TOTAL (on-demand) | $3,726   | $12,265   | 3.3x   |            |
    |    | TOTAL (3yr CUD)   | $2,400   | $8,500    | 3.5x   |            |
    |    +-------------------+----------+-----------+--------+            |
    |                                                                     |
    |  10x throughput for 3.3x cost = sublinear scaling                   |
    |                                                                     |
    +=====================================================================+
    |                                                                     |
    |  COMPARISON (at 1,000,000 users / 10K logins/sec):                  |
    |                                                                     |
    |    +------------------+-----------+------------------+              |
    |    | Provider         | Cost/mo   | Per-user/mo      |              |
    |    +------------------+-----------+------------------+              |
    |    | Okta Enterprise  | $6,000,000| $6.00            |              |
    |    | Azure AD P2      | $9,000,000| $9.00            |              |
    |    | Ping Identity    | $4,000,000| $4.00            |              |
    |    | Auth0 Enterprise | $3,000,000| $3.00            |              |
    |    | MILNET SSO       | $12,265   | $0.012           |              |
    |    +------------------+-----------+------------------+              |
    |                                                                     |
    |  MILNET SSO is 244x cheaper than Auth0, the cheapest competitor     |
    |                                                                     |
    +=====================================================================+
    |                                                                     |
    |  SECURITY ADVANTAGE (vs ALL competitors):                           |
    |    [x] Post-quantum crypto (ML-KEM-1024 + ML-DSA-87)               |
    |    [x] Threshold signing (3-of-5 FROST -- no single key)            |
    |    [x] Server-blind passwords (OPAQUE RFC 9497)                     |
    |    [x] Forward-secret sessions (HKDF ratcheting)                    |
    |    [x] BFT tamper-proof audit (7-node Byzantine tolerance)          |
    |    [x] DPoP token binding (stolen tokens unusable)                  |
    |    [x] Confidential Computing (AMD SEV encrypted RAM)               |
    |    [x] MIT Licensed -- free forever                                 |
    |                                                                     |
    +=====================================================================+

  EOT

  description = "Estimated monthly cost breakdown with scaling comparison"
}
