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

# ── Static IPs ──────────────────────────────────────────────

resource "google_compute_address" "sso_ip" {
  name   = "sso-system-ip"
  region = var.region
}

resource "google_compute_address" "demo_ip" {
  name   = "sso-demo-ip"
  region = var.region
}

# ── Firewall ────────────────────────────────────────────────

resource "google_compute_firewall" "sso_allow_web" {
  name    = "sso-allow-web"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["sso-server"]
}

resource "google_compute_firewall" "sso_allow_ssh" {
  name    = "sso-allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"] # IAP tunnel IP range only
  target_tags   = ["sso-server"]
}

# ── VM 1: SSO System (sso-system.dmj.one) ───────────────────

resource "google_compute_instance" "sso_system" {
  name         = "sso-system"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["sso-server"]

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
    scopes = ["compute-ro", "storage-ro", "logging-write"]
  }

  lifecycle {
    ignore_changes = [metadata["startup-script"]]
  }
}

# ── VM 2: Demo App (sso-system-demo.dmj.one) ────────────────

resource "google_compute_instance" "sso_demo" {
  name         = "sso-demo"
  machine_type = "e2-small"
  zone         = var.zone
  tags         = ["sso-server"]

  boot_disk {
    initialize_params {
      image = "projects/debian-cloud/global/images/family/debian-12"
      size  = 10
    }
  }

  network_interface {
    network = "default"
    access_config {
      nat_ip = google_compute_address.demo_ip.address
    }
  }

  metadata = {
    startup-script = file("${path.module}/demo-startup.sh")
    sso-system-ip  = google_compute_address.sso_ip.address
  }

  service_account {
    scopes = ["compute-ro", "storage-ro", "logging-write"]
  }

  depends_on = [google_compute_instance.sso_system]

  lifecycle {
    ignore_changes = [metadata["startup-script"]]
  }
}

# ── Outputs ──────────────────────────────────────────────────

output "sso_system_url" {
  value       = "https://${google_compute_address.sso_ip.address}"
  description = "SSO System URL (map A record: sso-system.dmj.one)"
}

output "demo_app_url" {
  value       = "https://${google_compute_address.demo_ip.address}"
  description = "Demo App URL (map A record: sso-system-demo.dmj.one)"
}

output "sso_system_ip" {
  value       = google_compute_address.sso_ip.address
  description = "SSO System IP — set DNS A record for sso-system.dmj.one"
}

output "demo_app_ip" {
  value       = google_compute_address.demo_ip.address
  description = "Demo App IP — set DNS A record for sso-system-demo.dmj.one"
}

output "ssh_sso" {
  value       = "gcloud compute ssh sso-system --zone=${var.zone}"
  description = "SSH into SSO server"
}

output "ssh_demo" {
  value       = "gcloud compute ssh sso-demo --zone=${var.zone}"
  description = "SSH into demo server"
}
