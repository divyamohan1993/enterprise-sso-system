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

# Static IP for the SSO server
resource "google_compute_address" "sso_ip" {
  name   = "milnet-sso-ip"
  region = var.region
}

# Firewall: allow HTTP (8080) and SSH (22)
resource "google_compute_firewall" "sso_allow" {
  name    = "milnet-sso-allow"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["8080", "22", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["milnet-sso"]
}

# The SSO server VM
resource "google_compute_instance" "sso_server" {
  name         = "milnet-sso-server"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["milnet-sso"]

  boot_disk {
    initialize_params {
      image = "projects/debian-cloud/global/images/family/debian-12"
      size  = 30
      type  = "pd-ssd"
    }
  }

  network_interface {
    network = "default"
    access_config {
      nat_ip = google_compute_address.sso_ip.address
    }
  }

  metadata = {
    startup-script = file("${path.module}/startup.sh")
  }

  service_account {
    scopes = ["cloud-platform"]
  }

  lifecycle {
    ignore_changes = [metadata["startup-script"]]
  }
}

output "sso_url" {
  value       = "http://${google_compute_address.sso_ip.address}:8080"
  description = "MILNET SSO System URL"
}

output "ssh_command" {
  value       = "gcloud compute ssh ${google_compute_instance.sso_server.name} --zone=${var.zone}"
  description = "SSH into the SSO server"
}
