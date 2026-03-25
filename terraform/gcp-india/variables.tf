# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — GCP India Variables
# ──────────────────────────────────────────────────────────────────────────────
# All region values are validated to be India-only (asia-south1/asia-south2).
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "lmsforshantithakur"
}

variable "primary_region" {
  description = "Primary GCP region — must be India (asia-south1 = Mumbai)"
  type        = string
  default     = "asia-south1"

  validation {
    condition     = contains(["asia-south1", "asia-south2"], var.primary_region)
    error_message = "primary_region must be asia-south1 (Mumbai) or asia-south2 (Delhi) for India data residency."
  }
}

variable "secondary_region" {
  description = "Secondary GCP region — must be India (asia-south2 = Delhi)"
  type        = string
  default     = "asia-south2"

  validation {
    condition     = contains(["asia-south1", "asia-south2"], var.secondary_region)
    error_message = "secondary_region must be asia-south1 (Mumbai) or asia-south2 (Delhi) for India data residency."
  }
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

variable "service_names" {
  description = "List of MILNET SSO service names"
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
  ]
}

variable "labels" {
  description = "Common labels applied to all resources"
  type        = map(string)
  default = {
    project        = "milnet-sso"
    managed_by     = "terraform"
    security       = "military-grade"
    data_residency = "india"
    compliance     = "meitygov"
  }
}
