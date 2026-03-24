# ============================================================================
# MILNET SSO — Dev/Test Deployment Variables
# ============================================================================

variable "project_id" {
  description = "GCP Project ID (required)"
  type        = string
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "asia-south1"
}

variable "zone" {
  description = "GCP zone for VM instances"
  type        = string
  default     = "asia-south1-a"
}

variable "github_repo" {
  description = "GitHub repository URL to clone"
  type        = string
  default     = "https://github.com/divyamohan1993/enterprise-sso-system.git"
}

variable "github_branch" {
  description = "Git branch to build and test"
  type        = string
  default     = "master"
}

variable "developer_mode" {
  description = "Enable developer mode (relaxed firewall, verbose logging, SSH from anywhere)"
  type        = bool
  default     = true
}

variable "machine_type" {
  description = "GCE machine type for the test runner VM"
  type        = string
  default     = "c2-standard-4"
}

variable "log_level" {
  description = "Log verbosity for test output"
  type        = string
  default     = "verbose"

  validation {
    condition     = contains(["verbose", "error"], var.log_level)
    error_message = "log_level must be \"verbose\" or \"error\"."
  }
}

variable "db_password" {
  description = "Password for the Cloud SQL milnet user"
  type        = string
  sensitive   = true
  default     = ""
}

variable "auto_destroy_on_failure" {
  description = "Automatically delete the test VM if tests fail"
  type        = bool
  default     = true
}

variable "cloud_run_min_instances" {
  description = "Minimum Cloud Run instances per service (0 for scale-to-zero)"
  type        = number
  default     = 0
}

variable "cloud_run_max_instances" {
  description = "Maximum Cloud Run instances per service"
  type        = number
  default     = 2
}

variable "tss_replica_count" {
  description = "Number of TSS service replicas for threshold signing"
  type        = number
  default     = 3
}

variable "container_image_tag" {
  description = "Container image tag for Cloud Run services"
  type        = string
  default     = "latest"
}
