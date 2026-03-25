# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — GCP India Compute Module
# ──────────────────────────────────────────────────────────────────────────────
# Compute Engine VMs for 8 MILNET services.
# All VMs in asia-south1 zones (a/b/c) for zone-level HA.
# Spot instances for dev/testing; on-demand for production.
# No external IPs — egress through Cloud NAT only.
# Shielded VMs with vTPM and Integrity Monitoring.
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" { type = string }
variable "primary_region" { type = string }
variable "environment" { type = string }
variable "subnet_id" { type = string }
variable "service_names" {
  type    = list(string)
  default = ["gateway", "orchestrator", "verifier", "ratchet", "audit", "risk", "admin", "opaque"]
}

locals {
  name_prefix = "milnet-india-${var.environment}"
  is_prod     = var.environment == "production"

  # Spread services across 3 zones for availability
  zones = [
    "${var.primary_region}-a",
    "${var.primary_region}-b",
    "${var.primary_region}-c",
  ]

  # Machine type: e2-small for dev, n2d-standard-2 for production (AMD EPYC)
  machine_type = local.is_prod ? "n2d-standard-2" : "e2-small"

  # Zone assignment for each service (round-robin)
  service_zones = {
    for idx, svc in var.service_names :
    svc => local.zones[idx % length(local.zones)]
  }
}

# ── Instance Template ──
# One template per environment; instances created from this template.

resource "google_compute_instance_template" "milnet_service" {
  name_prefix = "${local.name_prefix}-svc-tmpl-"
  project     = var.project_id
  region      = var.primary_region

  machine_type = local.machine_type

  # Spot (preemptible) for dev; standard on-demand for production
  scheduling {
    preemptible        = !local.is_prod
    on_host_maintenance = local.is_prod ? "MIGRATE" : "TERMINATE"
    automatic_restart  = local.is_prod
    provisioning_model = local.is_prod ? "STANDARD" : "SPOT"
  }

  disk {
    source_image = "projects/cos-cloud/global/images/family/cos-stable"
    auto_delete  = true
    boot         = true
    disk_type    = "pd-ssd"
    disk_size_gb = 50

    disk_encryption_key {
      kms_key_self_link = ""  # Set at deployment time from kms module output
    }
  }

  network_interface {
    subnetwork = var.subnet_id
    # No access_config block = no external/public IP
  }

  # Shielded VM: vTPM + integrity monitoring (compatible with MILNET TPM attestation)
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  # Confidential computing (AMD SEV) — encrypts VM memory
  confidential_instance_config {
    enable_confidential_compute = local.is_prod
  }

  service_account {
    # SA email is set per-service via instance-level override; template uses default
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin           = "TRUE"
    block-project-ssh-keys   = "TRUE"
    serial-port-enable       = "FALSE"
    disable-legacy-endpoints = "TRUE"
  }

  tags = ["milnet-service", "no-public-ip"]

  labels = {
    environment    = var.environment
    data_residency = "india"
    managed_by     = "terraform"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ── Per-Service VM Instances ──

resource "google_compute_instance" "milnet_services" {
  for_each = toset(var.service_names)

  name    = "${local.name_prefix}-${each.value}"
  project = var.project_id
  zone    = local.service_zones[each.value]  # asia-south1-a/b/c

  machine_type = local.machine_type

  scheduling {
    preemptible        = !local.is_prod
    on_host_maintenance = local.is_prod ? "MIGRATE" : "TERMINATE"
    automatic_restart  = local.is_prod
    provisioning_model = local.is_prod ? "STANDARD" : "SPOT"
  }

  boot_disk {
    initialize_params {
      image = "projects/cos-cloud/global/images/family/cos-stable"
      size  = 50
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = var.subnet_id
    # No access_config = no public IP
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    milnet-service           = each.value
    enable-oslogin           = "TRUE"
    block-project-ssh-keys   = "TRUE"
    serial-port-enable       = "FALSE"
    disable-legacy-endpoints = "TRUE"
  }

  tags = ["milnet-service", "milnet-${each.value}", "no-public-ip"]

  labels = {
    service        = each.value
    environment    = var.environment
    data_residency = "india"
    managed_by     = "terraform"
  }
}

# ── Outputs ──

output "instance_ids" {
  description = "Map of service name to compute instance ID"
  value       = { for svc, inst in google_compute_instance.milnet_services : svc => inst.id }
}

output "instance_internal_ips" {
  description = "Map of service name to internal IP"
  value       = { for svc, inst in google_compute_instance.milnet_services : svc => inst.network_interface[0].network_ip }
}
