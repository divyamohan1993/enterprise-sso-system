# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — AWS GovCloud Variables
# ──────────────────────────────────────────────────────────────────────────────
# All region values validated to GovCloud-only partitions.
# ──────────────────────────────────────────────────────────────────────────────

variable "primary_region" {
  description = "Primary AWS GovCloud region"
  type        = string
  default     = "us-gov-west-1"

  validation {
    condition     = contains(["us-gov-west-1", "us-gov-east-1"], var.primary_region)
    error_message = "primary_region must be us-gov-west-1 or us-gov-east-1 (GovCloud only)."
  }
}

variable "secondary_region" {
  description = "Secondary AWS GovCloud region for replication and DR"
  type        = string
  default     = "us-gov-east-1"

  validation {
    condition     = contains(["us-gov-west-1", "us-gov-east-1"], var.secondary_region)
    error_message = "secondary_region must be us-gov-west-1 or us-gov-east-1 (GovCloud only)."
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

variable "enable_air_gap" {
  description = "Enable air-gap mode: remove all internet gateways (IL5/ITAR)"
  type        = bool
  default     = false
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

variable "tags" {
  description = "Common tags applied to all AWS resources"
  type        = map(string)
  default = {
    Project        = "milnet-sso"
    ManagedBy      = "terraform"
    Security       = "military-grade"
    Compliance     = "fedramp-high"
    Classification = "il4"
  }
}
