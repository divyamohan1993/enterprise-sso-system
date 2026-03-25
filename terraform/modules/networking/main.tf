# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — Networking Module
# ──────────────────────────────────────────────────────────────────────────────
# Creates:
#   - VPC with custom-mode subnetting
#   - Private subnet with secondary ranges for GKE pods/services
#   - Cloud NAT (no public IPs on nodes)
#   - Firewall rules (default-deny ingress, allow only required ports)
#   - Cloud Armor WAF policy
#   - Private IP range for Cloud SQL
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "deployment_suffix" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "pods_cidr" {
  type = string
}

variable "services_cidr" {
  type = string
}

variable "labels" {
  type    = map(string)
  default = {}
}

# ── VPC ──

resource "google_compute_network" "milnet" {
  name                    = "milnet-vpc-${var.deployment_suffix}"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

# ── Primary Subnet ──

resource "google_compute_subnetwork" "milnet_primary" {
  name                     = "milnet-subnet-${var.deployment_suffix}"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.milnet.id
  ip_cidr_range            = var.vpc_cidr
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
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# ── Private IP Range for Cloud SQL ──

resource "google_compute_global_address" "private_ip_range" {
  name          = "milnet-sql-private-${var.deployment_suffix}"
  project       = var.project_id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.milnet.id
}

# ── Cloud Router + NAT ──
# All egress from private nodes goes through Cloud NAT.

resource "google_compute_router" "milnet" {
  name    = "milnet-router-${var.deployment_suffix}"
  project = var.project_id
  region  = var.region
  network = google_compute_network.milnet.id
}

resource "google_compute_router_nat" "milnet" {
  name                               = "milnet-nat-${var.deployment_suffix}"
  project                            = var.project_id
  region                             = var.region
  router                             = google_compute_router.milnet.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ── Firewall Rules ──

# Default deny all ingress
resource "google_compute_firewall" "deny_all_ingress" {
  name    = "milnet-deny-all-ingress-${var.deployment_suffix}"
  project = var.project_id
  network = google_compute_network.milnet.id

  direction = "INGRESS"
  priority  = 65534

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Allow internal communication within the VPC
resource "google_compute_firewall" "allow_internal" {
  name    = "milnet-allow-internal-${var.deployment_suffix}"
  project = var.project_id
  network = google_compute_network.milnet.id

  direction = "INGRESS"
  priority  = 1000

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.vpc_cidr, var.pods_cidr, var.services_cidr]
}

# Allow HTTPS ingress (port 443) from GCP health checks and load balancers
resource "google_compute_firewall" "allow_https_lb" {
  name    = "milnet-allow-https-lb-${var.deployment_suffix}"
  project = var.project_id
  network = google_compute_network.milnet.id

  direction = "INGRESS"
  priority  = 900

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  # GCP health check and LB source ranges
  source_ranges = [
    "35.191.0.0/16",
    "130.211.0.0/22",
    "209.85.152.0/22",
    "209.85.204.0/22",
  ]

  target_tags = ["milnet-sso-node"]
}

# Allow IAP for SSH (for maintenance access through Identity-Aware Proxy)
resource "google_compute_firewall" "allow_iap_ssh" {
  name    = "milnet-allow-iap-ssh-${var.deployment_suffix}"
  project = var.project_id
  network = google_compute_network.milnet.id

  direction = "INGRESS"
  priority  = 950

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # IAP source range
  source_ranges = ["35.235.240.0/20"]

  target_tags = ["milnet-ssh"]
}

# ── Cloud Armor WAF Policy ──

resource "google_compute_security_policy" "milnet_waf" {
  name    = "milnet-waf-${var.deployment_suffix}"
  project = var.project_id

  # Default rule: allow
  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow rule"
  }

  # Block SQL injection
  rule {
    action   = "deny(403)"
    priority = 1000
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }
    description = "Block SQL injection attacks"
  }

  # Block XSS
  rule {
    action   = "deny(403)"
    priority = 1001
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }
    description = "Block XSS attacks"
  }

  # Block known scanners / bad bots
  rule {
    action   = "deny(403)"
    priority = 1002
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('scannerdetection-v33-stable')"
      }
    }
    description = "Block scanner/bot traffic"
  }

  # Rate limiting: >100 requests per minute from a single IP
  rule {
    action   = "rate_based_ban"
    priority = 900
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
      ban_duration_sec = 300
    }
    description = "Rate limit: 100 req/min per IP, 5-min ban on exceed"
  }

  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
    }
  }
}

# ── Outputs ──

output "vpc_id" {
  value = google_compute_network.milnet.id
}

output "vpc_name" {
  value = google_compute_network.milnet.name
}

output "subnet_id" {
  value = google_compute_subnetwork.milnet_primary.id
}

output "subnet_name" {
  value = google_compute_subnetwork.milnet_primary.name
}

output "pods_range_name" {
  value = "pods"
}

output "services_range_name" {
  value = "services"
}

output "private_ip_range_name" {
  value = google_compute_global_address.private_ip_range.name
}

output "waf_policy_id" {
  value = google_compute_security_policy.milnet_waf.id
}
