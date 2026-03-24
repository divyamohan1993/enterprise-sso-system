###############################################################################
# MILNET SSO — Production 10K Variables
# Optimized for 10,000 logins/sec, quantum-safe, cost-efficient at scale
###############################################################################

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region — us-central1 is cheapest for compute + networking"
  type        = string
  default     = "us-central1"
}

variable "zones" {
  description = "GCP Zones for multi-zone HA deployment"
  type        = list(string)
  default     = ["us-central1-a", "us-central1-b", "us-central1-c"]
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "domain" {
  description = "Primary domain for the SSO system"
  type        = string
  default     = "sso.dmj.one"
}

variable "enable_cloud_armor_enterprise" {
  description = "Enable Cloud Armor Enterprise ($3000/mo flat) — required at 26B req/mo"
  type        = bool
  default     = true
}

variable "enable_cloud_cdn" {
  description = "Enable Cloud CDN for JWKS/.well-known endpoints"
  type        = bool
  default     = true
}

variable "redis_memory_gb" {
  description = "Redis cluster memory in GB for session/revocation cache"
  type        = number
  default     = 16
}

variable "db_tier" {
  description = "Cloud SQL machine tier — 16 vCPU, 64 GB for 10K req/s"
  type        = string
  default     = "db-custom-16-65536"
}

variable "db_ha" {
  description = "Enable Cloud SQL HA (REGIONAL) — required for 10K production"
  type        = bool
  default     = true
}

variable "db_max_connections" {
  description = "Cloud SQL max connections — 1000 for 10K req/s with pooling"
  type        = number
  default     = 1000
}

variable "db_shared_buffers" {
  description = "PostgreSQL shared_buffers in MB (16 GB = 25% of 64 GB)"
  type        = number
  default     = 16384
}

variable "db_effective_cache_size" {
  description = "PostgreSQL effective_cache_size in MB (48 GB = 75% of 64 GB)"
  type        = number
  default     = 49152
}

variable "gke_general_min_nodes" {
  description = "Min nodes in general pool (8x e2-standard-8)"
  type        = number
  default     = 8
}

variable "gke_general_max_nodes" {
  description = "Max nodes in general pool"
  type        = number
  default     = 20
}

variable "gke_compute_min_nodes" {
  description = "Min nodes in compute-heavy pool (c3d-standard-8 for Argon2id)"
  type        = number
  default     = 6
}

variable "gke_compute_max_nodes" {
  description = "Max nodes in compute-heavy pool"
  type        = number
  default     = 15
}

variable "tss_signer_count" {
  description = "Number of FROST threshold signer nodes (5x n2d-standard-4 for 10x signing throughput)"
  type        = number
  default     = 5
}

variable "stateful_node_count" {
  description = "Number of stateful nodes for BFT audit + ratchet (7x e2-standard-4)"
  type        = number
  default     = 7
}

variable "audit_bft_count" {
  description = "Number of BFT audit nodes (must be >= 7 for 2-Byzantine tolerance)"
  type        = number
  default     = 7
}

variable "artifact_registry_location" {
  description = "Artifact Registry location"
  type        = string
  default     = "us-central1"
}
