###############################################################################
# Enterprise SSO System — MVP Demo Deployment
#
# Single VM running all services via docker-compose.
# Designed for <10 users/month demo/showcase.
# Estimated cost: ~$15-25/month (e2-medium spot instance).
#
# The system's mTLS, SHARD protocol, FROST threshold signing, and BFT audit
# all still work — they just run on one machine.
###############################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# ---------------------------------------------------------------------------
# Data: current project info
# ---------------------------------------------------------------------------
data "google_project" "current" {
  project_id = var.project_id
}

# ---------------------------------------------------------------------------
# Secret Manager — store db_password (1 secret ≈ free)
# ---------------------------------------------------------------------------
resource "google_secret_manager_secret" "db_password" {
  secret_id = "sso-demo-db-password"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = var.db_password
}

# ---------------------------------------------------------------------------
# Networking — static IP + firewall (default VPC)
# ---------------------------------------------------------------------------
resource "google_compute_address" "sso_demo" {
  name         = "sso-demo-ip"
  address_type = "EXTERNAL"
  region       = var.region
}

resource "google_compute_firewall" "sso_demo" {
  name    = "sso-demo-allow-services"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22", "80", "443", "8080", "9100"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["sso-demo"]
}

# ---------------------------------------------------------------------------
# Persistent disk for PostgreSQL data (survives VM preemptions)
# ---------------------------------------------------------------------------
resource "google_compute_disk" "sso_data" {
  name = "sso-data-disk"
  type = "pd-balanced"
  size = 10
  zone = var.zone
}

# ---------------------------------------------------------------------------
# Compute Engine VM — e2-medium spot instance
# ---------------------------------------------------------------------------
resource "google_compute_instance" "sso_demo" {
  name         = "sso-demo-vm"
  machine_type = "e2-medium"
  zone         = var.zone

  tags = ["sso-demo"]

  scheduling {
    preemptible                 = true
    automatic_restart           = false
    provisioning_model          = "SPOT"
    instance_termination_action = "STOP"
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 30
      type  = "pd-balanced"
    }
  }

  attached_disk {
    source      = google_compute_disk.sso_data.id
    device_name = "sso-data-disk"
    mode        = "READ_WRITE"
  }

  network_interface {
    network = "default"

    access_config {
      nat_ip = google_compute_address.sso_demo.address
    }
  }

  metadata = {
    db-password = var.db_password
    github-repo = var.github_repo
  }

  metadata_startup_script = file("${path.module}/startup.sh")

  service_account {
    scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/secretmanager.access",
    ]
  }

  labels = {
    environment = "demo"
    system      = "enterprise-sso"
    cost-tier   = "minimal"
  }

  allow_stopping_for_update = true
}
