# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — GCP India Infrastructure
# ──────────────────────────────────────────────────────────────────────────────
# All resources are constrained to India regions (asia-south1, asia-south2).
# Data residency: sovereign Indian cloud with no cross-border data transfer.
# Compliance: MeitY cloud policy, IT Act 2000, DPDP Act 2023.
# ──────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  backend "gcs" {
    bucket = "milnet-tf-state-india"
    prefix = "gcp-india"
  }
}

provider "google" {
  project = var.project_id
  region  = var.primary_region
}

# ── Enable Required APIs ──

resource "google_project_service" "required_apis" {
  for_each = toset([
    "compute.googleapis.com",
    "sqladmin.googleapis.com",
    "cloudkms.googleapis.com",
    "storage.googleapis.com",
    "iam.googleapis.com",
    "servicenetworking.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# ── Modules ──

module "vpc" {
  source = "./modules/vpc"

  project_id        = var.project_id
  primary_region    = var.primary_region
  secondary_region  = var.secondary_region
  environment       = var.environment

  depends_on = [google_project_service.required_apis]
}

module "kms" {
  source = "./modules/kms"

  project_id   = var.project_id
  region       = var.primary_region
  environment  = var.environment

  depends_on = [google_project_service.required_apis]
}

module "cloud_hsm" {
  source = "./modules/cloud-hsm"

  project_id   = var.project_id
  region       = var.primary_region
  environment  = var.environment
  kms_keyring  = module.kms.keyring_name

  depends_on = [module.kms]
}

module "cloud_sql" {
  source = "./modules/cloud-sql"

  project_id        = var.project_id
  primary_region    = var.primary_region
  secondary_region  = var.secondary_region
  environment       = var.environment
  vpc_id            = module.vpc.vpc_id
  kms_key_id        = module.kms.db_cmek_key_id

  depends_on = [module.vpc, module.kms]
}

module "compute" {
  source = "./modules/compute"

  project_id     = var.project_id
  primary_region = var.primary_region
  environment    = var.environment
  subnet_id      = module.vpc.primary_subnet_id
  service_names  = var.service_names

  depends_on = [module.vpc, module.iam]
}

module "iam" {
  source = "./modules/iam"

  project_id    = var.project_id
  environment   = var.environment
  service_names = var.service_names

  depends_on = [google_project_service.required_apis]
}

module "gcs" {
  source = "./modules/gcs"

  project_id   = var.project_id
  environment  = var.environment
  kms_key_id   = module.kms.master_kek_id

  depends_on = [module.kms]
}
