# ============================================================================
# MILNET SSO — Optimal Cost Terraform Variables
# Target: <1000 logins/day, production-grade, ~$200-400/month
# ============================================================================

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region — single region for cost optimization"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP Zone — single zone deployment (saves 3x on compute)"
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "db_password" {
  description = "PostgreSQL database password (stored in Secret Manager)"
  type        = string
  sensitive   = true
}

variable "domain" {
  description = "Domain name for the SSO Admin API"
  type        = string
  default     = "sso.example.com"
}

variable "github_repo" {
  description = "GitHub repository URL for the SSO system source"
  type        = string
  default     = "https://github.com/divyamohan1993/enterprise-sso-system.git"
}

variable "db_tier" {
  description = "Cloud SQL machine tier — db-f1-micro for <1000 logins/day"
  type        = string
  default     = "db-f1-micro"
}

variable "db_disk_size_gb" {
  description = "Cloud SQL disk size in GB"
  type        = number
  default     = 10
}

variable "db_name" {
  description = "PostgreSQL database name"
  type        = string
  default     = "milnet_sso"
}

variable "db_user" {
  description = "PostgreSQL database user"
  type        = string
  default     = "milnet"
}

variable "audit_bft_replicas" {
  description = "Audit BFT node count — 3 for f=1 tolerance (cost-optimized from 7)"
  type        = number
  default     = 3
}

variable "cloud_armor_rate_limit" {
  description = "Cloud Armor rate limit — requests per minute per IP"
  type        = number
  default     = 120
}

variable "network_name" {
  description = "VPC network name"
  type        = string
  default     = "milnet-sso-vpc"
}

variable "subnet_cidr" {
  description = "Subnet CIDR range"
  type        = string
  default     = "10.0.0.0/20"
}

variable "pods_cidr" {
  description = "Secondary CIDR for GKE pods"
  type        = string
  default     = "10.16.0.0/14"
}

variable "services_cidr" {
  description = "Secondary CIDR for GKE services"
  type        = string
  default     = "10.20.0.0/20"
}

variable "container_image_tag" {
  description = "Container image tag to deploy"
  type        = string
  default     = "latest"
}
