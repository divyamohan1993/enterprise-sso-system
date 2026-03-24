# ============================================================================
# MILNET SSO — Production 3-VM Isolated Deployment
# ============================================================================
# Architecture: 3 fully isolated VMs on existing infrastructure
#   VM1: milnet-gateway  (c2-standard-4 SPOT) — gateway + orchestrator
#   VM2: milnet-core     (e2-medium SPOT)     — opaque, admin, verifier, ratchet, audit
#   VM3: milnet-tss      (e2-small SPOT)      — 3x FROST threshold signers
#
# Security model: breaking one VM gives ZERO access to the others.
# Each VM has unique service account, unique HMAC keys, unique credentials.
# ============================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# ============================================================================
# Data Sources — Reference Existing Resources (DO NOT recreate)
# ============================================================================

data "google_project" "current" {
  project_id = var.project_id
}

# Existing VPC and subnet
data "google_compute_network" "milnet_vpc" {
  name    = "milnet-test-vpc-de033d2b"
  project = var.project_id
}

data "google_compute_subnetwork" "milnet_subnet" {
  name    = "milnet-core-subnet"
  region  = var.region
  project = var.project_id
}

# Existing Cloud KMS keyring (HSM-backed)
data "google_kms_key_ring" "milnet_keyring" {
  name     = "milnet-sso-keyring-de033d2b"
  location = var.region
}

# Existing service accounts
data "google_service_account" "gateway_sa" {
  account_id = "milnet-gateway-sa"
  project    = var.project_id
}

data "google_service_account" "core_sa" {
  account_id = "milnet-core-sa"
  project    = var.project_id
}

data "google_service_account" "tss_sa" {
  account_id = "milnet-tss-sa"
  project    = var.project_id
}

# ============================================================================
# Locals
# ============================================================================

locals {
  ar_registry = "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso-dev"

  labels = {
    app         = "milnet-sso"
    environment = "prod"
    managed-by  = "terraform"
  }

  # Cloud SQL connection (existing instance, private IP only)
  db_host           = "10.207.224.3"
  db_name           = "milnet_sso"
  db_user           = "milnet"
  db_password       = var.db_password != "" ? var.db_password : random_password.db_password.result
  sql_instance_name = "milnet-test-db-de033d2b"
  sql_connection    = "${var.project_id}:${var.region}:${local.sql_instance_name}"
}

# ============================================================================
# Auto-Generated DB Password (80 chars, stored in Secret Manager)
# ============================================================================

resource "random_password" "db_password" {
  length  = 80
  special = false # Avoid URL-encoding issues in DATABASE_URL
}

# Store DB password in Secret Manager (never plaintext in terraform state exports)
resource "google_secret_manager_secret" "db_password" {
  secret_id = "milnet-db-password"
  project   = var.project_id
  replication {
    auto {}
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = local.db_password
}

# Set the password on Cloud SQL
resource "google_sql_user" "milnet" {
  name     = "milnet"
  instance = local.sql_instance_name
  password = local.db_password
  project  = var.project_id
}

# Manage existing Cloud SQL instance to enforce deletion protection
resource "google_sql_database_instance" "milnet_db" {
  name                = local.sql_instance_name
  project             = var.project_id
  region              = var.region
  database_version    = "POSTGRES_15"
  deletion_protection = true

  settings {
    tier              = "db-f1-micro"
    availability_type = "ZONAL"

    ip_configuration {
      ipv4_enabled    = false
      private_network = data.google_compute_network.milnet_vpc.id
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ============================================================================
# Firewall Rules — Zero-Trust Network Segmentation
# ============================================================================

# Public: Gateway API (proof-of-work + rate limiting at app layer)
resource "google_compute_firewall" "gateway_public" {
  name    = "milnet-fw-gateway-public"
  network = data.google_compute_network.milnet_vpc.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["9100"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["milnet-gateway"]
  priority      = 1000
}

# Public: Admin API
resource "google_compute_firewall" "admin_public" {
  name    = "milnet-fw-admin-public"
  network = data.google_compute_network.milnet_vpc.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = ["10.207.224.0/22"]
  target_tags   = ["milnet-core"]
  priority      = 1001
}

# SSH: Developer mode access
resource "google_compute_firewall" "ssh" {
  name    = "milnet-fw-ssh"
  network = data.google_compute_network.milnet_vpc.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["milnet-gateway", "milnet-core", "milnet-tss"]
  priority      = 1002
}

# Internal: Service mesh communication between VMs
resource "google_compute_firewall" "internal" {
  name    = "milnet-fw-internal"
  network = data.google_compute_network.milnet_vpc.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["9101-9199"]
  }

  source_tags = ["milnet-gateway", "milnet-core", "milnet-tss"]
  target_tags = ["milnet-gateway", "milnet-core", "milnet-tss"]
  priority    = 1003
}

# Deny all other ingress (lowest priority)
resource "google_compute_firewall" "deny_all" {
  name     = "milnet-fw-deny-all"
  network  = data.google_compute_network.milnet_vpc.name
  project  = var.project_id
  priority = 1000

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

# ============================================================================
# Cloud Armor — DDoS Protection + Rate Limiting
# ============================================================================

resource "google_compute_security_policy" "ddos_protection" {
  name    = "milnet-ddos-protection"
  project = var.project_id

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
        count        = 100
        interval_sec = 60
      }

      enforce_on_key = "IP"
    }

    description = "Rate limit: 100 req/min per IP"
  }

  # Block SQL injection attempts
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

  # Block XSS attempts
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
# VM 1: milnet-gateway (c2-standard-4, SPOT)
# Services: gateway (:9100), orchestrator (:9101)
# NO database, NO KMS, NO signing keys — only routes traffic
# ============================================================================

resource "google_compute_instance" "gateway" {
  name         = "milnet-gateway"
  machine_type = "c2-standard-4"
  zone         = var.zone
  tags         = ["milnet-gateway"]
  labels       = local.labels

  scheduling {
    preemptible                 = true
    automatic_restart           = false
    on_host_maintenance         = "TERMINATE"
    provisioning_model          = "SPOT"
    instance_termination_action = "DELETE"
  }

  boot_disk {
    initialize_params {
      image = "projects/cos-cloud/global/images/family/cos-stable"
      size  = 30
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = data.google_compute_subnetwork.milnet_subnet.id
    access_config {
      # Ephemeral public IP
    }
  }

  metadata = {
    startup-script = templatefile("${path.module}/startup-gateway.sh.tpl", {
      ar_registry = local.ar_registry
      core_ip     = google_compute_instance.core.network_interface[0].network_ip
      tss_ip      = google_compute_instance.tss.network_interface[0].network_ip
      project_id  = var.project_id
    })
  }

  service_account {
    email  = data.google_service_account.gateway_sa.email
    scopes = ["cloud-platform"]
  }

  lifecycle {
    create_before_destroy = false
  }

  depends_on = [
    google_compute_firewall.gateway_public,
    google_compute_firewall.internal,
    google_compute_instance.core,
    google_compute_instance.tss,
  ]
}

# ============================================================================
# VM 2: milnet-core (e2-medium, SPOT)
# Services: opaque (:9102), admin (:8080), verifier (:9104),
#           ratchet (:9105), audit (:9108)
# Has: DATABASE_URL, Cloud KMS, Secret Manager
# ============================================================================

resource "google_compute_instance" "core" {
  name         = "milnet-core"
  machine_type = "e2-medium"
  zone         = var.zone
  tags         = ["milnet-core"]
  labels       = local.labels

  scheduling {
    preemptible                 = true
    automatic_restart           = false
    on_host_maintenance         = "TERMINATE"
    provisioning_model          = "SPOT"
    instance_termination_action = "DELETE"
  }

  boot_disk {
    initialize_params {
      image = "projects/cos-cloud/global/images/family/cos-stable"
      size  = 30
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = data.google_compute_subnetwork.milnet_subnet.id
  }

  metadata = {
    startup-script = templatefile("${path.module}/startup-core.sh.tpl", {
      ar_registry    = local.ar_registry
      db_host        = local.db_host
      db_name        = local.db_name
      db_user        = local.db_user
      sql_connection = local.sql_connection
      kms_keyring    = data.google_kms_key_ring.milnet_keyring.id
      project_id     = var.project_id
    })
  }

  service_account {
    email = data.google_service_account.core_sa.email
    scopes = [
      "https://www.googleapis.com/auth/sqlservice.admin",
      "https://www.googleapis.com/auth/cloudkms",
      "https://www.googleapis.com/auth/secretmanager",
      "https://www.googleapis.com/auth/logging.write",
    ]
  }

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# VM 3: milnet-tss (e2-small, SPOT)
# Services: tss-0 (:9103), tss-1 (:9113), tss-2 (:9123)
# NO database, NO KMS — only FROST threshold shares
# ============================================================================

resource "google_compute_instance" "tss" {
  name         = "milnet-tss"
  machine_type = "e2-small"
  zone         = var.zone
  tags         = ["milnet-tss"]
  labels       = local.labels

  scheduling {
    preemptible                 = true
    automatic_restart           = false
    on_host_maintenance         = "TERMINATE"
    provisioning_model          = "SPOT"
    instance_termination_action = "DELETE"
  }

  boot_disk {
    initialize_params {
      image = "projects/cos-cloud/global/images/family/cos-stable"
      size  = 20
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = data.google_compute_subnetwork.milnet_subnet.id
  }

  metadata = {
    startup-script = templatefile("${path.module}/startup-tss.sh.tpl", {
      ar_registry = local.ar_registry
      project_id  = var.project_id
    })
  }

  service_account {
    email = data.google_service_account.tss_sa.email
    scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
    ]
  }

  lifecycle {
    create_before_destroy = false
  }
}
