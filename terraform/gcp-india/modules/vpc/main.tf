# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — GCP India VPC Module
# ──────────────────────────────────────────────────────────────────────────────
# Creates a fully private VPC spanning both India regions.
# No public IPs, no IGW equivalent — all outbound through Cloud NAT.
# Private Google Access enabled so VMs can reach GCP APIs without public IPs.
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" { type = string }
variable "primary_region" { type = string }
variable "secondary_region" { type = string }
variable "environment" { type = string }

locals {
  name_prefix = "milnet-india-${var.environment}"
}

# ── VPC ──

resource "google_compute_network" "india_vpc" {
  name                    = "${local.name_prefix}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "MILNET India sovereign VPC — no cross-border traffic"
}

# ── Primary Subnet (asia-south1 / Mumbai) ──

resource "google_compute_subnetwork" "primary" {
  name                     = "${local.name_prefix}-subnet-as1"
  project                  = var.project_id
  region                   = var.primary_region  # asia-south1
  network                  = google_compute_network.india_vpc.id
  ip_cidr_range            = "10.30.0.0/20"
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# ── Secondary Subnet (asia-south2 / Delhi) ──

resource "google_compute_subnetwork" "secondary" {
  name                     = "${local.name_prefix}-subnet-as2"
  project                  = var.project_id
  region                   = var.secondary_region  # asia-south2
  network                  = google_compute_network.india_vpc.id
  ip_cidr_range            = "10.31.0.0/20"
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# ── Cloud NAT (asia-south1) — egress only, no inbound ──

resource "google_compute_router" "nat_router_as1" {
  name    = "${local.name_prefix}-nat-router-as1"
  project = var.project_id
  region  = var.primary_region
  network = google_compute_network.india_vpc.id
}

resource "google_compute_router_nat" "nat_as1" {
  name                               = "${local.name_prefix}-nat-as1"
  project                            = var.project_id
  router                             = google_compute_router.nat_router_as1.name
  region                             = var.primary_region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.primary.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ── Cloud NAT (asia-south2) ──

resource "google_compute_router" "nat_router_as2" {
  name    = "${local.name_prefix}-nat-router-as2"
  project = var.project_id
  region  = var.secondary_region
  network = google_compute_network.india_vpc.id
}

resource "google_compute_router_nat" "nat_as2" {
  name                               = "${local.name_prefix}-nat-as2"
  project                            = var.project_id
  router                             = google_compute_router.nat_router_as2.name
  region                             = var.secondary_region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.secondary.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ── Private IP range for Cloud SQL (RFC 1918) ──

resource "google_compute_global_address" "sql_private_range" {
  name          = "${local.name_prefix}-sql-private-range"
  project       = var.project_id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.india_vpc.id
}

resource "google_service_networking_connection" "sql_private_vpc" {
  network                 = google_compute_network.india_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.sql_private_range.name]
}

# ── Firewall: default-deny ingress ──

resource "google_compute_firewall" "deny_all_ingress" {
  name    = "${local.name_prefix}-deny-all-ingress"
  project = var.project_id
  network = google_compute_network.india_vpc.id

  priority  = 65534
  direction = "INGRESS"

  deny { protocol = "all" }

  source_ranges = ["0.0.0.0/0"]

  description = "Default deny all ingress — override with explicit allow rules"
}

# ── Firewall: allow internal east-west traffic ──

resource "google_compute_firewall" "allow_internal" {
  name    = "${local.name_prefix}-allow-internal"
  project = var.project_id
  network = google_compute_network.india_vpc.id

  priority  = 1000
  direction = "INGRESS"

  allow { protocol = "tcp" }
  allow { protocol = "udp" }
  allow { protocol = "icmp" }

  # Only allow traffic from within India VPC subnets
  source_ranges = ["10.30.0.0/20", "10.31.0.0/20"]

  description = "Allow intra-VPC traffic between India subnets"
}

# ── Firewall: deny egress outside India ──
# Note: GCP does not support geographic-based firewall rules natively;
# org policy + VPC Service Controls enforce India-only data residency.

resource "google_compute_firewall" "deny_all_egress" {
  name    = "${local.name_prefix}-deny-all-egress"
  project = var.project_id
  network = google_compute_network.india_vpc.id

  priority  = 65534
  direction = "EGRESS"

  deny { protocol = "all" }

  destination_ranges = ["0.0.0.0/0"]

  description = "Default deny all egress — explicit allow rules for GCP APIs"
}

resource "google_compute_firewall" "allow_gcp_apis_egress" {
  name    = "${local.name_prefix}-allow-gcp-apis-egress"
  project = var.project_id
  network = google_compute_network.india_vpc.id

  priority  = 1000
  direction = "EGRESS"

  allow { protocol = "tcp"; ports = ["443"] }

  # Google private API ranges (restricted.googleapis.com)
  destination_ranges = ["199.36.153.4/30", "199.36.153.8/30"]

  description = "Allow egress to Google Private Access endpoints only"
}

# ── Outputs ──

output "vpc_id" {
  value = google_compute_network.india_vpc.id
}

output "vpc_self_link" {
  value = google_compute_network.india_vpc.self_link
}

output "primary_subnet_id" {
  value = google_compute_subnetwork.primary.id
}

output "secondary_subnet_id" {
  value = google_compute_subnetwork.secondary.id
}

output "sql_private_vpc_connection" {
  value = google_service_networking_connection.sql_private_vpc.id
}
