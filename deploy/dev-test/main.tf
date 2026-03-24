# ============================================================================
# MILNET SSO — Prod-Identical Deployment at Sandbox Cost
# ============================================================================
# Purpose: Real production architecture with every resource identical to live
# deployment, just at the lowest-cost SKU/tier.
#
# Design principles:
#   - IDENTICAL architecture to production (same Cloud KMS HSM, same Cloud SQL,
#     same Cloud Run, same mTLS, same VPC isolation) — just smallest SKUs
#   - No mocks, no stubs, no dev shortcuts
#   - C2 Spot VM for fast Rust builds/tests (asia-south1)
#   - Every apply destroys previous resources first (create_before_destroy=false)
#   - Failures trigger VM self-deletion and replacement
#   - SSH access for debugging in developer_mode
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

# ── Data Sources ─────────────────────────────────────────────────────────────

data "google_project" "current" {
  project_id = var.project_id
}

# ── Random Suffix ────────────────────────────────────────────────────────────
# Ensures every deploy creates fresh resources (no name collisions).

resource "random_id" "suffix" {
  byte_length = 4

  keepers = {
    # Re-generate on every apply to force resource recreation
    timestamp = timestamp()
  }

  lifecycle {
    create_before_destroy = false
  }
}

# ── Generate DB Password ────────────────────────────────────────────────────

resource "random_password" "db_password" {
  length  = 24
  special = false

  lifecycle {
    create_before_destroy = false
  }
}

locals {
  name_suffix = random_id.suffix.hex
  db_password = var.db_password != "" ? var.db_password : random_password.db_password.result
  labels = {
    app         = "milnet-sso"
    environment = "dev-test"
    managed-by  = "terraform"
    ephemeral   = "true"
  }
}

# ============================================================================
# Enable Required APIs
# ============================================================================

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "sqladmin.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudkms.googleapis.com",
    "run.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "vpcaccess.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# Networking — VPC + Firewall
# ============================================================================

resource "google_compute_network" "test_vpc" {
  name                    = "milnet-test-vpc-${local.name_suffix}"
  auto_create_subnetworks = false
  project                 = var.project_id

  depends_on = [google_project_service.apis]

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_compute_subnetwork" "test_subnet" {
  name          = "milnet-test-subnet-${local.name_suffix}"
  ip_cidr_range = "10.10.0.0/24"
  region        = var.region
  network       = google_compute_network.test_vpc.id

  private_ip_google_access = true

  lifecycle {
    create_before_destroy = false
  }
}

# VPC connector for Cloud Run to reach Cloud SQL via private IP
resource "google_vpc_access_connector" "connector" {
  name          = "milnet-vpc-cx-${local.name_suffix}"
  region        = var.region
  network       = google_compute_network.test_vpc.name
  ip_cidr_range = "10.10.1.0/28"
  machine_type  = "e2-micro"
  min_instances = 2
  max_instances = 3

  depends_on = [google_project_service.apis]

  lifecycle {
    create_before_destroy = false
  }
}

# ── Firewall: SSH ────────────────────────────────────────────────────────────

resource "google_compute_firewall" "allow_ssh" {
  name    = "milnet-test-ssh-${local.name_suffix}"
  network = google_compute_network.test_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # In developer_mode, allow SSH from anywhere; otherwise restrict to IAP
  source_ranges = var.developer_mode ? ["0.0.0.0/0"] : ["35.235.240.0/20"]
  target_tags   = ["milnet-test"]

  lifecycle {
    create_before_destroy = false
  }
}

# ── Firewall: Internal traffic ───────────────────────────────────────────────

resource "google_compute_firewall" "allow_internal" {
  name    = "milnet-test-internal-${local.name_suffix}"
  network = google_compute_network.test_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = ["10.10.0.0/24"]

  lifecycle {
    create_before_destroy = false
  }
}

# ── Firewall: Deny all other ingress ─────────────────────────────────────────

resource "google_compute_firewall" "deny_all_ingress" {
  name     = "milnet-test-deny-all-${local.name_suffix}"
  network  = google_compute_network.test_vpc.name
  priority = 65534

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# Service Account
# ============================================================================

resource "google_service_account" "test_runner" {
  account_id   = "milnet-test-${local.name_suffix}"
  display_name = "MILNET SSO Test Runner (ephemeral)"
  project      = var.project_id

  depends_on = [google_project_service.apis]

  lifecycle {
    create_before_destroy = false
  }
}

# Minimum permissions: logging, monitoring, self-deletion, Cloud SQL client
resource "google_project_iam_member" "test_runner_roles" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/compute.instanceAdmin.v1",
    "roles/cloudsql.client",
    "roles/secretmanager.secretAccessor",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.test_runner.email}"

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# Cloud SQL — PostgreSQL (smallest tier)
# ============================================================================

resource "google_compute_global_address" "private_ip_range" {
  name          = "milnet-test-db-ip-${local.name_suffix}"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.test_vpc.id

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_service_networking_connection" "private_vpc" {
  network                 = google_compute_network.test_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]

  lifecycle {
    create_before_destroy = false
  }

  depends_on = [google_project_service.apis]
}

resource "google_sql_database_instance" "test_db" {
  name             = "milnet-test-db-${local.name_suffix}"
  database_version = "POSTGRES_15"
  region           = var.region
  project          = var.project_id

  deletion_protection = false

  settings {
    tier              = "db-f1-micro"
    availability_type = "ZONAL"
    disk_size         = 10
    disk_type         = "PD_HDD"
    disk_autoresize   = false

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.test_vpc.id
      enable_private_path_for_google_cloud_services = true
    }

    backup_configuration {
      enabled = false
    }

    database_flags {
      name  = "max_connections"
      value = "50"
    }

    user_labels = local.labels
  }

  depends_on = [google_service_networking_connection.private_vpc]

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_sql_database" "milnet_sso" {
  name     = "milnet_sso"
  instance = google_sql_database_instance.test_db.name
  project  = var.project_id

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_sql_user" "milnet" {
  name     = "milnet"
  instance = google_sql_database_instance.test_db.name
  password = local.db_password
  project  = var.project_id

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# Compute Engine — Spot Test Runner VM
# ============================================================================

resource "google_compute_instance" "test_runner" {
  name         = "milnet-test-runner-${local.name_suffix}"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["milnet-test"]
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
      image = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2204-lts"
      size  = 50
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.test_subnet.id

    access_config {
      # Ephemeral public IP for SSH access
    }
  }

  metadata = {
    startup-script    = file("${path.module}/startup.sh")
    github-repo       = var.github_repo
    github-branch     = var.github_branch
    log-level         = var.log_level
    db-host           = google_sql_database_instance.test_db.private_ip_address
    db-password       = local.db_password
    db-name           = "milnet_sso"
    db-user           = "milnet"
    auto-destroy      = var.auto_destroy_on_failure ? "true" : "false"
    test-status       = "pending"
    test-started-at   = ""
    test-completed-at = ""
    test-exit-code    = ""
    enable-oslogin    = var.developer_mode ? "FALSE" : "TRUE"
  }

  service_account {
    email  = google_service_account.test_runner.email
    scopes = ["cloud-platform"]
  }

  depends_on = [
    google_sql_database.milnet_sso,
    google_sql_user.milnet,
    google_project_iam_member.test_runner_roles,
  ]

  lifecycle {
    create_before_destroy = false
  }
}
