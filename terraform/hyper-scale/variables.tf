variable "project_id" {
  description = "GCP Project ID"
  type        = string
  default     = "dmjone"
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "zones" {
  description = "GCP Zones for multi-zone deployment"
  type        = list(string)
  default     = ["us-central1-a", "us-central1-b", "us-central1-c"]
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "db_password" {
  description = "PostgreSQL database password"
  type        = string
  sensitive   = true
}

variable "domain" {
  description = "Domain name for the SSO system"
  type        = string
  default     = "sso.example.com"
}

variable "github_repo" {
  description = "GitHub repository URL"
  type        = string
  default     = "https://github.com/divyamohan1993/enterprise-sso-system.git"
}
