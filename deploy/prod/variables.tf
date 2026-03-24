# ============================================================================
# MILNET SSO — Production Deployment Variables
# ============================================================================

variable "project_id" {
  description = "GCP Project ID"
  type        = string
  default     = "your-gcp-project-id"
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

variable "developer_mode" {
  description = "Enable developer mode (SSH from anywhere)"
  type        = bool
  default     = true
}

variable "db_password" {
  description = "Password for Cloud SQL milnet user (auto-generated if empty, stored in Secret Manager)"
  type        = string
  sensitive   = true
  default     = ""
}
