# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — Root Terraform Configuration
# ──────────────────────────────────────────────────────────────────────────────
#
# GCP Project : lmsforshantithakur
# Region      : asia-south1 (Delhi/Mumbai)
# Architecture: Military-grade distributed SSO with real prod resources at
#               minimal cost tiers.
# ──────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  backend "gcs" {
    bucket = "milnet-sso-tfstate"
    prefix = "terraform/state"

    # State file encryption — uses the default GCS encryption (CMEK can be
    # layered via bucket-level default KMS key outside this config).
  }
}

# ── Providers ──

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# ── Enable Required APIs ──

resource "google_project_service" "required_apis" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "cloudkms.googleapis.com",
    "secretmanager.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "servicenetworking.googleapis.com",
    "binaryauthorization.googleapis.com",
    "containeranalysis.googleapis.com",
    "artifactregistry.googleapis.com",
    "vpcaccess.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# ── Modules ──

module "networking" {
  source = "./modules/networking"

  project_id        = var.project_id
  region            = var.region
  deployment_suffix = var.deployment_suffix
  vpc_cidr          = var.vpc_cidr
  pods_cidr         = var.pods_cidr
  services_cidr     = var.services_cidr
  labels            = var.labels

  depends_on = [google_project_service.required_apis]
}

module "kms" {
  source = "./modules/kms"

  project_id        = var.project_id
  region            = var.region
  deployment_suffix = var.deployment_suffix
  rotation_period   = var.kms_rotation_period
  protection_level  = var.kms_protection_level
  labels            = var.labels

  depends_on = [google_project_service.required_apis]
}

module "secrets" {
  source = "./modules/secrets"

  project_id        = var.project_id
  region            = var.region
  deployment_suffix = var.deployment_suffix
  service_names     = var.service_names
  kms_crypto_key_id = module.kms.master_kek_crypto_key_id
  labels            = var.labels

  depends_on = [module.kms]
}

module "iam" {
  source = "./modules/iam"

  project_id        = var.project_id
  deployment_suffix = var.deployment_suffix
  service_names     = var.service_names
  kms_keyring_id    = module.kms.keyring_id
  labels            = var.labels

  depends_on = [google_project_service.required_apis]
}

module "database" {
  source = "./modules/database"

  project_id              = var.project_id
  region                  = var.region
  deployment_suffix       = var.deployment_suffix
  tier                    = var.db_tier
  availability_type       = var.db_availability_type
  backup_retention_days   = var.db_backup_retention_days
  maintenance_window_day  = var.db_maintenance_window_day
  maintenance_window_hour = var.db_maintenance_window_hour
  vpc_network_id          = module.networking.vpc_id
  private_ip_range_name   = module.networking.private_ip_range_name
  service_names           = var.service_names
  kms_crypto_key_id       = module.kms.db_encryption_key_id
  labels                  = var.labels

  depends_on = [module.networking, module.kms]
}

module "gke" {
  source = "./modules/gke"

  project_id                = var.project_id
  region                    = var.region
  zone                      = var.zone
  deployment_suffix         = var.deployment_suffix
  vpc_id                    = module.networking.vpc_id
  subnet_id                 = module.networking.subnet_id
  pods_range_name           = module.networking.pods_range_name
  services_range_name       = module.networking.services_range_name
  master_authorized_cidr    = var.master_authorized_cidr
  release_channel           = var.gke_release_channel
  enable_confidential_nodes = var.gke_enable_confidential_nodes
  service_account_email     = module.iam.gke_node_sa_email
  labels                    = var.labels

  depends_on = [module.networking, module.iam]
}

module "monitoring" {
  source = "./modules/monitoring"

  project_id                  = var.project_id
  deployment_suffix           = var.deployment_suffix
  alert_notification_channels = var.alert_notification_channels
  uptime_check_host           = var.uptime_check_host
  labels                      = var.labels

  depends_on = [google_project_service.required_apis]
}
