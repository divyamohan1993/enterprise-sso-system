terraform {
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

# Firewall rule to allow HTTP traffic to the SSO server
resource "google_compute_firewall" "allow_http" {
  name    = "milnet-sso-allow-http"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["8080", "22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["milnet-sso"]
}

# Compute Engine VM with Debian 12, PostgreSQL, and the SSO binary
resource "google_compute_instance" "sso_server" {
  name         = "milnet-sso-server"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["milnet-sso"]

  boot_disk {
    initialize_params {
      image = "projects/debian-cloud/global/images/family/debian-12"
      size  = 30
    }
  }

  network_interface {
    network = "default"
    access_config {
      // Ephemeral public IP
    }
  }

  metadata_startup_script = <<-SCRIPT
    #!/bin/bash
    set -e

    # Install PostgreSQL
    apt-get update
    apt-get install -y postgresql postgresql-client

    # Configure PostgreSQL for local connections
    sudo -u postgres psql -c "CREATE USER milnet WITH PASSWORD 'milnet_secure';" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE DATABASE milnet_sso OWNER milnet;" 2>/dev/null || true

    # The admin binary will be deployed separately via SCP or container
    echo "VM ready for MILNET SSO deployment"
  SCRIPT

  service_account {
    scopes = ["cloud-platform"]
  }
}
