# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — Terraform Variables
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" {
  description = "GCP project ID for deployment"
  type        = string
  default     = "lmsforshantithakur"
}

variable "region" {
  description = "Primary GCP region"
  type        = string
  default     = "asia-south1"
}

variable "zone" {
  description = "Primary GCP zone within the region"
  type        = string
  default     = "asia-south1-a"
}

variable "environment" {
  description = "Deployment environment: dev, staging, production"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "environment must be one of: dev, staging, production"
  }
}

variable "deployment_suffix" {
  description = "Unique suffix appended to resource names to avoid collisions"
  type        = string
  default     = "de033d2b"
}

# ── Networking ──

variable "vpc_cidr" {
  description = "CIDR range for the primary VPC subnet"
  type        = string
  default     = "10.10.0.0/20"
}

variable "pods_cidr" {
  description = "Secondary CIDR range for GKE pods"
  type        = string
  default     = "10.20.0.0/14"
}

variable "services_cidr" {
  description = "Secondary CIDR range for GKE services"
  type        = string
  default     = "10.24.0.0/20"
}

variable "master_authorized_cidr" {
  description = "CIDR blocks authorized to access the GKE master endpoint"
  type        = list(string)
  default     = []
}

# ── Database ──

variable "db_tier" {
  description = "Cloud SQL machine tier (use db-f1-micro for free-tier testing)"
  type        = string
  default     = "db-f1-micro"
}

variable "db_availability_type" {
  description = "Cloud SQL availability: ZONAL or REGIONAL (HA)"
  type        = string
  default     = "ZONAL"
}

variable "db_backup_retention_days" {
  description = "Number of days to retain automated Cloud SQL backups"
  type        = number
  default     = 7
}

variable "db_maintenance_window_day" {
  description = "Day of week for Cloud SQL maintenance (1=Mon, 7=Sun)"
  type        = number
  default     = 7
}

variable "db_maintenance_window_hour" {
  description = "Hour (UTC) for Cloud SQL maintenance window start"
  type        = number
  default     = 2
}

# ── KMS ──

variable "kms_rotation_period" {
  description = "Automatic key rotation period for Cloud KMS crypto keys"
  type        = string
  default     = "7776000s" # 90 days
}

variable "kms_protection_level" {
  description = "Cloud KMS protection level: SOFTWARE or HSM"
  type        = string
  default     = "HSM"

  validation {
    condition     = contains(["SOFTWARE", "HSM"], var.kms_protection_level)
    error_message = "kms_protection_level must be SOFTWARE or HSM"
  }
}

# ── GKE ──

variable "gke_release_channel" {
  description = "GKE release channel: RAPID, REGULAR, STABLE"
  type        = string
  default     = "STABLE"
}

variable "gke_enable_confidential_nodes" {
  description = "Enable Confidential GKE Nodes (AMD SEV)"
  type        = bool
  default     = false
}

# ── Monitoring ──

variable "alert_notification_channels" {
  description = "List of Cloud Monitoring notification channel IDs for alerts"
  type        = list(string)
  default     = []
}

variable "uptime_check_host" {
  description = "Hostname for uptime checks (set after ingress is configured)"
  type        = string
  default     = ""
}

# ── Secrets ──

variable "service_names" {
  description = "List of MILNET SSO service names for per-service DB users and secrets"
  type        = list(string)
  default = [
    "gateway",
    "orchestrator",
    "verifier",
    "ratchet",
    "audit",
    "risk",
    "admin",
    "opaque",
    "tss",
    "fido",
    "kt",
    "shard",
  ]
}

# ── Labels ──

variable "labels" {
  description = "Common labels applied to all resources"
  type        = map(string)
  default = {
    project    = "milnet-sso"
    managed_by = "terraform"
    security   = "military-grade"
  }
}
