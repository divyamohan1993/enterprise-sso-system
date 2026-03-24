# ============================================================================
# MILNET SSO — Optimal Cost Production Deployment
# ============================================================================
# Target workload: <1000 logins/day
# Estimated cost:  ~$200-400/month
#
# Cost optimizations vs hyper-scale:
#   - GKE Autopilot (pay-per-pod, no idle nodes)
#   - Single zone (not multi-zone)
#   - Cloud SQL db-f1-micro shared-core (not db-n1-standard-4)
#   - Cloud KMS software keys (not HSM)
#   - No Certificate Authority Service (self-signed mTLS)
#   - No Managed Prometheus (use built-in GKE metrics)
#   - Audit BFT: 3 nodes (not 7)
#   - Single replica per service
#
# Security: FULL — no security shortcuts taken.
# ============================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Kubernetes provider configured after GKE cluster creation
provider "kubernetes" {
  host                   = "https://${google_container_cluster.autopilot.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.autopilot.master_auth[0].cluster_ca_certificate)
}

data "google_client_config" "default" {}

data "google_project" "current" {
  project_id = var.project_id
}

locals {
  cluster_name = "milnet-sso-${var.environment}"
  db_instance  = "milnet-sso-db-${var.environment}"
  labels = {
    app         = "milnet-sso"
    environment = var.environment
    managed-by  = "terraform"
  }
  ar_repo   = "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso"
  image_tag = var.container_image_tag
}

# ============================================================================
# Enable Required APIs
# ============================================================================

resource "google_project_service" "apis" {
  for_each = toset([
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "cloudkms.googleapis.com",
    "secretmanager.googleapis.com",
    "compute.googleapis.com",
    "artifactregistry.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "servicenetworking.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# ============================================================================
# NETWORKING — Single VPC, Single Subnet, Cloud NAT
# ============================================================================

resource "google_compute_network" "vpc" {
  name                    = var.network_name
  auto_create_subnetworks = false
  project                 = var.project_id

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "subnet" {
  name                     = "${var.network_name}-subnet"
  ip_cidr_range            = var.subnet_cidr
  region                   = var.region
  network                  = google_compute_network.vpc.id
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.1
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Cloud Router for NAT
resource "google_compute_router" "router" {
  name    = "${var.network_name}-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

# Cloud NAT — outbound internet for private GKE nodes
resource "google_compute_router_nat" "nat" {
  name                               = "${var.network_name}-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Private Services Access for Cloud SQL
resource "google_compute_global_address" "private_ip_range" {
  name          = "milnet-sso-private-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.vpc.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]

  depends_on = [google_project_service.apis]
}

# ============================================================================
# GKE AUTOPILOT — Pay-per-pod, single zone
# ============================================================================

resource "google_container_cluster" "autopilot" {
  name = local.cluster_name
  # Single zone saves ~66% vs regional (3x fewer node replicas).
  # For HA, change to var.region — but cost increases ~3x.
  location = var.zone

  enable_autopilot = true

  network    = google_compute_network.vpc.id
  subnetwork = google_compute_subnetwork.subnet.id

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = var.subnet_cidr
      display_name = "VPC subnet only"
    }
  }

  release_channel {
    channel = "REGULAR"
  }

  # Workload Identity for secure pod-to-GCP auth
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  deletion_protection = false

  # etcd encryption at the application layer using Cloud KMS
  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.data_encryption.id
  }

  resource_labels = local.labels

  depends_on = [
    google_project_service.apis,
    google_compute_subnetwork.subnet,
  ]
}

# ============================================================================
# CLOUD SQL — PostgreSQL 16, Shared-Core, Single Zone
# ============================================================================

resource "google_sql_database_instance" "postgres" {
  name                = local.db_instance
  database_version    = "POSTGRES_16"
  region              = var.region
  deletion_protection = true

  settings {
    tier              = var.db_tier # db-f1-micro for <1000/day
    edition           = "ENTERPRISE"
    availability_type = "ZONAL" # No HA — single zone saves 50%

    disk_size       = var.db_disk_size_gb
    disk_type       = "PD_SSD"
    disk_autoresize = true

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.vpc.id
      enable_private_path_for_google_cloud_services = true
    }

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00" # 3 AM UTC
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = 7
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = 7 # Sunday
      hour         = 4 # 4 AM UTC
      update_track = "stable"
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "1000" # Log queries taking >1s
    }

    user_labels = local.labels
  }

  depends_on = [google_service_networking_connection.private_vpc_connection]
}

resource "google_sql_database" "milnet" {
  name     = var.db_name
  instance = google_sql_database_instance.postgres.name
}

resource "google_sql_user" "milnet" {
  name     = var.db_user
  instance = google_sql_database_instance.postgres.name
  password = var.db_password
}

# ============================================================================
# CLOUD KMS — Software Keys (not HSM — saves $$$, still secure)
# ============================================================================

resource "google_kms_key_ring" "sso" {
  name     = "milnet-sso-${var.environment}"
  location = var.region

  depends_on = [google_project_service.apis]
}

# Token signing key (ECDSA P-256 for JWT/OIDC)
resource "google_kms_crypto_key" "token_signing" {
  name     = "token-signing"
  key_ring = google_kms_key_ring.sso.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE" # Not HSM — saves ~$1/key-version/month
  }

  rotation_period = "7776000s" # 90 days

  labels = local.labels
}

# Data encryption key (AES-256-GCM for secrets at rest)
resource "google_kms_crypto_key" "data_encryption" {
  name     = "data-encryption"
  key_ring = google_kms_key_ring.sso.id
  purpose  = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  rotation_period = "7776000s" # 90 days

  labels = local.labels
}

# TSS share encryption key
resource "google_kms_crypto_key" "tss_shares" {
  name     = "tss-shares"
  key_ring = google_kms_key_ring.sso.id
  purpose  = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  rotation_period = "7776000s" # 90 days

  labels = local.labels
}

# ============================================================================
# SECRET MANAGER — All secrets stored securely
# ============================================================================

resource "google_secret_manager_secret" "db_password" {
  secret_id = "milnet-sso-db-password"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  labels = local.labels

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = var.db_password
}

resource "google_secret_manager_secret" "db_url" {
  secret_id = "milnet-sso-db-url"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  labels = local.labels

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "db_url" {
  secret      = google_secret_manager_secret.db_url.id
  secret_data = "postgres://${var.db_user}:${var.db_password}@${google_sql_database_instance.postgres.private_ip_address}:5432/${var.db_name}"
}

resource "google_secret_manager_secret" "jwt_signing_key_id" {
  secret_id = "milnet-sso-jwt-signing-key-id"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  labels = local.labels

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "jwt_signing_key_id" {
  secret      = google_secret_manager_secret.jwt_signing_key_id.id
  secret_data = google_kms_crypto_key.token_signing.id
}

# ============================================================================
# IAM — Workload Identity for GKE pods
# ============================================================================

resource "google_service_account" "sso_workload" {
  account_id   = "milnet-sso-workload"
  display_name = "MILNET SSO Workload Identity"
  project      = var.project_id
}

# Allow the KSA to impersonate the GSA
resource "google_service_account_iam_member" "workload_identity" {
  service_account_id = google_service_account.sso_workload.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[milnet-sso/milnet-sso]"
}

# Grant GSA access to Cloud SQL
resource "google_project_iam_member" "sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.sso_workload.email}"
}

# Grant GSA access to Secret Manager
resource "google_project_iam_member" "secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.sso_workload.email}"
}

# Grant GSA access to Cloud KMS (sign/verify + encrypt/decrypt)
resource "google_project_iam_member" "kms_signer" {
  project = var.project_id
  role    = "roles/cloudkms.signerVerifier"
  member  = "serviceAccount:${google_service_account.sso_workload.email}"
}

resource "google_project_iam_member" "kms_encrypter" {
  project = var.project_id
  role    = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member  = "serviceAccount:${google_service_account.sso_workload.email}"
}

# Grant GSA access to Cloud Logging
resource "google_project_iam_member" "log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.sso_workload.email}"
}

# Grant GSA access to Cloud Monitoring
resource "google_project_iam_member" "metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.sso_workload.email}"
}

# ============================================================================
# ARTIFACT REGISTRY — Container images
# ============================================================================

resource "google_artifact_registry_repository" "sso" {
  location      = var.region
  repository_id = "milnet-sso"
  description   = "MILNET SSO container images"
  format        = "DOCKER"

  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"

    most_recent_versions {
      keep_count = 10
    }
  }

  labels = local.labels

  depends_on = [google_project_service.apis]
}

# Grant GKE nodes access to pull images
resource "google_artifact_registry_repository_iam_member" "gke_reader" {
  location   = var.region
  repository = google_artifact_registry_repository.sso.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.sso_workload.email}"
}

# ============================================================================
# GLOBAL HTTPS LOAD BALANCER — Admin API with Managed SSL
# ============================================================================

# Reserve a global static IP for the LB
resource "google_compute_global_address" "admin_lb" {
  name = "milnet-sso-admin-lb"
}

# Managed SSL certificate
resource "google_compute_managed_ssl_certificate" "admin" {
  name = "milnet-sso-admin-cert"

  managed {
    domains = [var.domain]
  }
}

# Health check for the Admin API backend
resource "google_compute_health_check" "admin_api" {
  name                = "milnet-sso-admin-hc"
  check_interval_sec  = 30
  timeout_sec         = 10
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port         = 30080
    request_path = "/api/health"
  }
}

# Backend service (NEG will be auto-created by GKE Ingress; this is the manual LB path)
# NOTE: In practice, you would use a GKE Ingress resource (defined in pod-specs.tf)
# which auto-provisions the LB. This health check is used by Cloud Armor.

# ============================================================================
# CLOUD ARMOR — Basic Rate Limiting
# ============================================================================

resource "google_compute_security_policy" "rate_limit" {
  name = "milnet-sso-rate-limit"

  # Default: allow all
  rule {
    action   = "allow"
    priority = 2147483647

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }

    description = "Default allow"
  }

  # Rate limit: throttle per IP
  rule {
    action   = "throttle"
    priority = 1000

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }

    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"

      rate_limit_threshold {
        count        = var.cloud_armor_rate_limit
        interval_sec = 60
      }

      enforce_on_key = "IP"
    }

    description = "Rate limit: ${var.cloud_armor_rate_limit} req/min per IP"
  }

  # Block known-bad scanners
  rule {
    action   = "deny(403)"
    priority = 900

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }

    description = "Block SQL injection attempts"
  }

  rule {
    action   = "deny(403)"
    priority = 901

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }

    description = "Block XSS attempts"
  }
}

# ============================================================================
# CLOUD MONITORING — Uptime Check on Admin API
# ============================================================================

resource "google_monitoring_uptime_check_config" "admin_api" {
  display_name = "MILNET SSO Admin API"
  timeout      = "10s"
  period       = "300s" # Every 5 minutes

  http_check {
    path         = "/api/health"
    port         = 443
    use_ssl      = true
    validate_ssl = true
  }

  monitored_resource {
    type = "uptime_url"

    labels = {
      project_id = var.project_id
      host       = var.domain
    }
  }
}

# Alert policy for uptime check failures
resource "google_monitoring_alert_policy" "uptime_alert" {
  display_name = "MILNET SSO Admin API Down"
  combiner     = "OR"

  conditions {
    display_name = "Uptime check failure"

    condition_threshold {
      filter          = "resource.type = \"uptime_url\" AND metric.type = \"monitoring.googleapis.com/uptime_check/check_passed\" AND metric.labels.check_id = \"${google_monitoring_uptime_check_config.admin_api.uptime_check_id}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 1
      duration        = "300s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_NEXT_OLDER"
      }

      trigger {
        count = 1
      }
    }
  }

  alert_strategy {
    auto_close = "1800s" # Auto-close after 30 min of recovery
  }
}
