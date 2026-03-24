###############################################################################
# MILNET SSO — Demo Trial Variables
# Optimized for GCP Free Trial ($300 credit, 90 days)
# Target: <100 users/week | Budget: ~$16.30/mo (18 months on $300)
# Security: IDENTICAL to production (same Rust binary, same crypto)
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

variable "zone" {
  description = "GCP Zone for the single VM"
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "demo-trial"
}

variable "github_repo" {
  description = "GitHub repository URL for the SSO system source code"
  type        = string
  default     = "https://github.com/divyamohan1993/enterprise-sso-system.git"
}

variable "db_password" {
  description = "Cloud SQL database password (auto-generated if not set)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "vm_machine_type" {
  description = "VM machine type — e2-medium is cheapest with 4 GB RAM"
  type        = string
  default     = "e2-medium"
}

variable "db_tier" {
  description = "Cloud SQL machine tier — db-f1-micro is cheapest (shared core, 0.6 GB)"
  type        = string
  default     = "db-f1-micro"
}

variable "db_disk_size" {
  description = "Cloud SQL disk size in GB — 10 GB HDD minimum"
  type        = number
  default     = 10
}

variable "frost_signer_count" {
  description = "FROST threshold signer processes (5 for 3-of-5 scheme)"
  type        = number
  default     = 5

  validation {
    condition     = var.frost_signer_count >= 5
    error_message = "FROST 3-of-5 requires at least 5 signer processes."
  }
}

variable "bft_audit_node_count" {
  description = "BFT audit node processes (3 minimum for 1 Byzantine tolerance)"
  type        = number
  default     = 3

  validation {
    condition     = var.bft_audit_node_count >= 3
    error_message = "BFT requires at least 3 nodes for 1 Byzantine fault tolerance."
  }
}

variable "kms_protection_level" {
  description = "KMS key protection level — SOFTWARE saves $0.94/key/mo vs HSM"
  type        = string
  default     = "SOFTWARE"

  validation {
    condition     = contains(["SOFTWARE", "HSM"], var.kms_protection_level)
    error_message = "Protection level must be SOFTWARE or HSM."
  }
}
