###############################################################################
# variables.tf — Enterprise SSO Multi-VM GCE Deployment
###############################################################################

variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "lmsforshantithakur"
}

variable "region" {
  description = "Primary GCP region"
  type        = string
  default     = "asia-south1"
}

variable "secondary_region" {
  description = "Secondary region for cross-region TSS/audit nodes"
  type        = string
  default     = "asia-south2"
}

variable "zones" {
  description = "Availability zones in primary region"
  type        = list(string)
  default     = ["asia-south1-a", "asia-south1-b", "asia-south1-c"]
}

variable "secondary_zones" {
  description = "Availability zones in secondary region"
  type        = list(string)
  default     = ["asia-south2-a", "asia-south2-b"]
}

# ---------- Binary artifact bucket ----------

variable "binary_bucket" {
  description = "GCS bucket containing compiled service binaries"
  type        = string
  default     = "enterprise-sso-binaries"
}

variable "binary_version" {
  description = "Version tag for binary artifacts in GCS"
  type        = string
  default     = "latest"
}

# ---------- Networking ----------

variable "vpc_cidr" {
  description = "CIDR for the VPC primary range"
  type        = string
  default     = "10.10.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR for the public (gateway) subnet"
  type        = string
  default     = "10.10.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR for the private services subnet"
  type        = string
  default     = "10.10.2.0/24"
}

variable "private_subnet_secondary_cidr" {
  description = "CIDR for secondary-region private subnet"
  type        = string
  default     = "10.10.3.0/24"
}

# ---------- Machine types ----------

variable "machine_type_gateway" {
  description = "Machine type for gateway (CPU-intensive crypto)"
  type        = string
  default     = "e2-standard-2"
}

variable "machine_type_admin" {
  description = "Machine type for admin API"
  type        = string
  default     = "e2-medium"
}

variable "machine_type_verifier" {
  description = "Machine type for verifier (CPU-intensive crypto)"
  type        = string
  default     = "e2-standard-2"
}

variable "machine_type_default" {
  description = "Machine type for most services"
  type        = string
  default     = "e2-medium"
}

variable "machine_type_small" {
  description = "Machine type for lightweight services (risk, kt)"
  type        = string
  default     = "e2-small"
}

# ---------- Auto-scaling ----------

variable "gateway_min_replicas" {
  type    = number
  default = 2
}

variable "gateway_max_replicas" {
  type    = number
  default = 10
}

variable "admin_min_replicas" {
  type    = number
  default = 2
}

variable "admin_max_replicas" {
  type    = number
  default = 5
}

variable "verifier_min_replicas" {
  type    = number
  default = 2
}

variable "verifier_max_replicas" {
  type    = number
  default = 8
}

variable "autoscaler_cpu_target" {
  description = "Target CPU utilization for autoscalers (0.0-1.0)"
  type        = number
  default     = 0.6
}

# ---------- Cloud SQL ----------

variable "db_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-custom-2-7680"
}

variable "db_disk_size_gb" {
  description = "Cloud SQL disk size in GB"
  type        = number
  default     = 50
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "enterprise_sso"
}

variable "db_user" {
  description = "Database admin user"
  type        = string
  default     = "sso_admin"
}

variable "db_password" {
  description = "Database admin password"
  type        = string
  sensitive   = true
}

# ---------- SSH ----------

variable "ssh_source_ranges" {
  description = "CIDR ranges allowed SSH access (bastion only)"
  type        = list(string)
  default     = ["35.235.240.0/20"] # IAP tunnel range
}

variable "vpn_source_ranges" {
  description = "CIDR ranges for VPN/admin access"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

# ---------- Labels ----------

variable "environment" {
  description = "Environment label (prod, staging, dev)"
  type        = string
  default     = "prod"
}

variable "labels" {
  description = "Common labels applied to all resources"
  type        = map(string)
  default = {
    managed_by = "terraform"
    system     = "enterprise-sso"
    security   = "military-grade"
  }
}

# ---------- TSS ----------

variable "tss_node_count" {
  description = "Number of TSS nodes (threshold signing)"
  type        = number
  default     = 5
}

variable "tss_threshold" {
  description = "TSS signing threshold (k of n)"
  type        = number
  default     = 3
}

# ---------- Audit BFT ----------

variable "audit_node_count" {
  description = "Number of audit BFT nodes"
  type        = number
  default     = 7
}

variable "audit_quorum" {
  description = "Audit BFT quorum size"
  type        = number
  default     = 5
}
