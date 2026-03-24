###############################################################################
# MILNET SSO — Production 1K Variables
# Optimized for 1000 logins/sec, quantum-safe, minimum cost
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
  description = "Enable Cloud Armor Enterprise ($3000/mo) — set true only if >4B req/mo"
  type        = bool
  default     = false
}

variable "redis_memory_gb" {
  description = "Redis memory in GB for session/revocation cache"
  type        = number
  default     = 4
}

variable "db_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-custom-8-32768"
}

variable "db_ha" {
  description = "Enable Cloud SQL HA (REGIONAL) — doubles cost but zero-downtime failover"
  type        = bool
  default     = true
}

variable "gke_general_min_nodes" {
  description = "Min nodes in general pool"
  type        = number
  default     = 3
}

variable "gke_general_max_nodes" {
  description = "Max nodes in general pool"
  type        = number
  default     = 8
}

variable "gke_compute_min_nodes" {
  description = "Min nodes in compute-heavy pool (OPAQUE/Orchestrator)"
  type        = number
  default     = 2
}

variable "gke_compute_max_nodes" {
  description = "Max nodes in compute-heavy pool"
  type        = number
  default     = 5
}

variable "tss_signer_count" {
  description = "Number of FROST threshold signer nodes (must be >= 5 for 3-of-5)"
  type        = number
  default     = 5
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
