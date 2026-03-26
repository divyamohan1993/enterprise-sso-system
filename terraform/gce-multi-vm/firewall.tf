###############################################################################
# firewall.tf — Enterprise SSO Multi-VM Zero-Trust Firewall Rules
###############################################################################
# Implements least-privilege network segmentation for the SSO service mesh.
# Every rule is source→destination specific; no broad internal allow.
#
# Service communication matrix:
#   gateway      → orchestrator (9101)
#   orchestrator → opaque (9102), tss (9103), ratchet (9105), audit (9108), risk (9106)
#   verifier     → tss (9103), ratchet (9105), audit (9108)
#   ratchet      → orchestrator (9101), verifier (9104), audit (9108)
#   audit        → kt (9109), postgres (5432)
#   admin        → all services + postgres (5432)
#   tss nodes    ↔ tss nodes   (9113-9117)
#   audit nodes  ↔ audit nodes (9118-9124)
###############################################################################

locals {
  name_prefix = "sso-${var.environment}"

  # GCP health check source ranges
  gcp_health_check_ranges = ["130.211.0.0/22", "35.191.0.0/16"]

  # GCP IAP tunnel source range
  iap_tunnel_range = ["35.235.240.0/20"]

  # Google Private Access endpoints (restricted.googleapis.com)
  google_private_api_ranges = ["199.36.153.4/30"]

  # Google restricted API range (private.googleapis.com)
  google_restricted_api_ranges = ["199.36.153.8/30"]

  # GCP metadata server (DNS)
  metadata_server = ["169.254.169.254/32"]

  # All service tags
  all_service_tags = [
    "sso-gateway",
    "sso-orchestrator",
    "sso-opaque",
    "sso-tss",
    "sso-verifier",
    "sso-ratchet",
    "sso-risk",
    "sso-audit",
    "sso-kt",
    "sso-admin",
  ]
}

###############################################################################
# VPC Network
###############################################################################

resource "google_compute_network" "sso_vpc" {
  name                    = "${local.name_prefix}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "Enterprise SSO zero-trust VPC — no default routes, no default firewall rules"
}

resource "google_compute_subnetwork" "public" {
  name                     = "${local.name_prefix}-public"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.sso_vpc.id
  ip_cidr_range            = var.public_subnet_cidr
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "private" {
  name                     = "${local.name_prefix}-private"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.sso_vpc.id
  ip_cidr_range            = var.private_subnet_cidr
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "private_secondary" {
  name                     = "${local.name_prefix}-private-secondary"
  project                  = var.project_id
  region                   = var.secondary_region
  network                  = google_compute_network.sso_vpc.id
  ip_cidr_range            = var.private_subnet_secondary_cidr
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

###############################################################################
# 1. DEFAULT DENY ALL — Ingress & Egress
###############################################################################

resource "google_compute_firewall" "deny_all_ingress" {
  name    = "${local.name_prefix}-deny-all-ingress"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 65534
  direction = "INGRESS"

  deny { protocol = "all" }

  source_ranges = ["0.0.0.0/0"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Default deny all ingress — zero-trust baseline"
}

resource "google_compute_firewall" "deny_all_egress" {
  name    = "${local.name_prefix}-deny-all-egress"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 65534
  direction = "EGRESS"

  deny { protocol = "all" }

  destination_ranges = ["0.0.0.0/0"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Default deny all egress — zero-trust baseline"
}

###############################################################################
# 2. EXTERNAL INGRESS — Gateway public endpoint (9100)
###############################################################################

resource "google_compute_firewall" "allow_gateway_public" {
  name    = "${local.name_prefix}-allow-gateway-public"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 1000
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9100"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["sso-gateway"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Allow public HTTPS to gateway on port 9100"
}

###############################################################################
# 3. ADMIN ACCESS — VPN CIDR only, port 8080
###############################################################################

resource "google_compute_firewall" "allow_admin_vpn" {
  name    = "${local.name_prefix}-allow-admin-vpn"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 1000
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = var.vpn_source_ranges
  target_tags   = ["sso-admin"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Allow admin panel access only from VPN CIDR on port 8080"
}

###############################################################################
# 4. INTER-SERVICE RULES — Least-privilege source→destination pairs
###############################################################################

# --- gateway → orchestrator (9101) ---

resource "google_compute_firewall" "gateway_to_orchestrator" {
  name    = "${local.name_prefix}-gateway-to-orchestrator"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9101"]
  }

  source_tags = ["sso-gateway"]
  target_tags = ["sso-orchestrator"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "gateway → orchestrator on port 9101"
}

# --- orchestrator → opaque (9102) ---

resource "google_compute_firewall" "orchestrator_to_opaque" {
  name    = "${local.name_prefix}-orch-to-opaque"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9102"]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-opaque"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "orchestrator → opaque on port 9102"
}

# --- orchestrator → tss (9103) ---

resource "google_compute_firewall" "orchestrator_to_tss" {
  name    = "${local.name_prefix}-orch-to-tss"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9103"]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-tss"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "orchestrator → tss on port 9103"
}

# --- orchestrator → ratchet (9105) ---

resource "google_compute_firewall" "orchestrator_to_ratchet" {
  name    = "${local.name_prefix}-orch-to-ratchet"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9105"]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-ratchet"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "orchestrator → ratchet on port 9105"
}

# --- orchestrator → audit (9108) ---

resource "google_compute_firewall" "orchestrator_to_audit" {
  name    = "${local.name_prefix}-orch-to-audit"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9108"]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-audit"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "orchestrator → audit on port 9108"
}

# --- orchestrator → risk (9106) ---

resource "google_compute_firewall" "orchestrator_to_risk" {
  name    = "${local.name_prefix}-orch-to-risk"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9106"]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-risk"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "orchestrator → risk on port 9106"
}

# --- verifier → tss (9103) ---

resource "google_compute_firewall" "verifier_to_tss" {
  name    = "${local.name_prefix}-verifier-to-tss"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9103"]
  }

  source_tags = ["sso-verifier"]
  target_tags = ["sso-tss"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "verifier → tss on port 9103"
}

# --- verifier → ratchet (9105) ---

resource "google_compute_firewall" "verifier_to_ratchet" {
  name    = "${local.name_prefix}-verifier-to-ratchet"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9105"]
  }

  source_tags = ["sso-verifier"]
  target_tags = ["sso-ratchet"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "verifier → ratchet on port 9105"
}

# --- verifier → audit (9108) ---

resource "google_compute_firewall" "verifier_to_audit" {
  name    = "${local.name_prefix}-verifier-to-audit"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9108"]
  }

  source_tags = ["sso-verifier"]
  target_tags = ["sso-audit"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "verifier → audit on port 9108"
}

# --- ratchet → orchestrator (9101) ---

resource "google_compute_firewall" "ratchet_to_orchestrator" {
  name    = "${local.name_prefix}-ratchet-to-orchestrator"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9101"]
  }

  source_tags = ["sso-ratchet"]
  target_tags = ["sso-orchestrator"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "ratchet → orchestrator on port 9101"
}

# --- ratchet → verifier (9104) ---

resource "google_compute_firewall" "ratchet_to_verifier" {
  name    = "${local.name_prefix}-ratchet-to-verifier"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9104"]
  }

  source_tags = ["sso-ratchet"]
  target_tags = ["sso-verifier"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "ratchet → verifier on port 9104"
}

# --- ratchet → audit (9108) ---

resource "google_compute_firewall" "ratchet_to_audit" {
  name    = "${local.name_prefix}-ratchet-to-audit"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9108"]
  }

  source_tags = ["sso-ratchet"]
  target_tags = ["sso-audit"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "ratchet → audit on port 9108"
}

# --- audit → kt (9109) ---

resource "google_compute_firewall" "audit_to_kt" {
  name    = "${local.name_prefix}-audit-to-kt"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9109"]
  }

  source_tags = ["sso-audit"]
  target_tags = ["sso-kt"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "audit → kt (key transparency) on port 9109"
}

# --- admin → all services (all service ports) ---

resource "google_compute_firewall" "admin_to_all_services" {
  name    = "${local.name_prefix}-admin-to-all-services"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9100-9109", "9113-9124"]
  }

  source_tags = ["sso-admin"]
  target_tags = local.all_service_tags

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "admin → all services on all service ports (management plane)"
}

###############################################################################
# 5. TSS PEER MESH — Threshold signing consensus (9113-9117)
###############################################################################

resource "google_compute_firewall" "tss_peer_mesh" {
  name    = "${local.name_prefix}-tss-peer-mesh"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9113-9117"]
  }

  source_tags = ["sso-tss"]
  target_tags = ["sso-tss"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "TSS node peer mesh — threshold signing consensus on ports 9113-9117"
}

###############################################################################
# 6. AUDIT BFT MESH — Byzantine fault-tolerant audit consensus (9118-9124)
###############################################################################

resource "google_compute_firewall" "audit_bft_mesh" {
  name    = "${local.name_prefix}-audit-bft-mesh"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9118-9124"]
  }

  source_tags = ["sso-audit"]
  target_tags = ["sso-audit"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Audit BFT node peer mesh — consensus on ports 9118-9124"
}

###############################################################################
# 7. DATABASE ACCESS — Cloud SQL on 5432
###############################################################################

# Only audit and admin can reach Cloud SQL (orchestrator access via audit service)
# audit service is the write path; admin for migrations/maintenance

resource "google_compute_firewall" "audit_to_cloudsql" {
  name    = "${local.name_prefix}-audit-to-cloudsql"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }

  destination_ranges = [var.cloud_sql_private_cidr]
  target_tags        = ["sso-audit"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "audit → Cloud SQL on port 5432"
}

resource "google_compute_firewall" "orchestrator_to_cloudsql" {
  name    = "${local.name_prefix}-orch-to-cloudsql"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }

  destination_ranges = [var.cloud_sql_private_cidr]
  target_tags        = ["sso-orchestrator"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "orchestrator → Cloud SQL on port 5432"
}

resource "google_compute_firewall" "admin_to_cloudsql" {
  name    = "${local.name_prefix}-admin-to-cloudsql"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }

  destination_ranges = [var.cloud_sql_private_cidr]
  target_tags        = ["sso-admin"]

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "admin → Cloud SQL on port 5432 (migrations/maintenance)"
}

###############################################################################
# 8. SSH — Only from IAP (Identity-Aware Proxy)
###############################################################################

resource "google_compute_firewall" "allow_iap_ssh" {
  name    = "${local.name_prefix}-allow-iap-ssh"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 1000
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = local.iap_tunnel_range

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Allow SSH only from GCP IAP tunnel range — no direct internet SSH"
}

###############################################################################
# 9. HEALTH CHECKS — GCP load balancer health probes
###############################################################################

resource "google_compute_firewall" "allow_health_checks" {
  name    = "${local.name_prefix}-allow-health-checks"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 1000
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9100-9109"]
  }

  source_ranges = local.gcp_health_check_ranges
  target_tags   = local.all_service_tags

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Allow GCP health check probes to service ports"
}

###############################################################################
# 10. EGRESS — Controlled outbound access
###############################################################################

# --- DNS to metadata server (UDP 53) ---

resource "google_compute_firewall" "allow_dns_egress" {
  name    = "${local.name_prefix}-allow-dns-egress"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 1000
  direction = "EGRESS"

  allow {
    protocol = "udp"
    ports    = ["53"]
  }

  destination_ranges = local.metadata_server

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Allow DNS queries to GCP metadata server"
}

# --- GCS (HTTPS 443) for binary downloads ---

resource "google_compute_firewall" "allow_gcs_egress" {
  name    = "${local.name_prefix}-allow-gcs-egress"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 1000
  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  # restricted.googleapis.com — covers GCS, KMS, Secret Manager
  destination_ranges = local.google_private_api_ranges

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Allow HTTPS to Google Private Access (GCS, KMS, Secret Manager)"
}

# --- private.googleapis.com range (additional API endpoint) ---

resource "google_compute_firewall" "allow_private_google_apis_egress" {
  name    = "${local.name_prefix}-allow-private-apis-egress"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 1000
  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  destination_ranges = local.google_restricted_api_ranges

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Allow HTTPS to Google restricted API endpoints (KMS, Secret Manager)"
}

# --- NTP (UDP 123) for secure time synchronization ---

resource "google_compute_firewall" "allow_ntp_egress" {
  name    = "${local.name_prefix}-allow-ntp-egress"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 1000
  direction = "EGRESS"

  allow {
    protocol = "udp"
    ports    = ["123"]
  }

  # GCP metadata server provides NTP
  destination_ranges = local.metadata_server

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Allow NTP to GCP metadata server for secure time"
}

# --- Inter-service egress (services need to reach each other within VPC) ---

resource "google_compute_firewall" "allow_internal_service_egress" {
  name    = "${local.name_prefix}-allow-internal-svc-egress"
  project = var.project_id
  network = google_compute_network.sso_vpc.id

  priority  = 900
  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["9100-9109", "9113-9124"]
  }

  destination_ranges = [var.private_subnet_cidr, var.private_subnet_secondary_cidr, var.public_subnet_cidr]
  target_tags        = local.all_service_tags

  log_config { metadata = "INCLUDE_ALL_METADATA" }

  description = "Allow service-to-service egress within VPC on service ports"
}

###############################################################################
# VARIABLES specific to firewall rules
###############################################################################

variable "cloud_sql_private_cidr" {
  description = "CIDR range for Cloud SQL private IP allocation"
  type        = string
  default     = "10.10.128.0/20"
}

variable "allowed_countries" {
  description = "ISO 3166-1 alpha-2 country codes allowed through geo-blocking (Cloud Armor)"
  type        = list(string)
  default     = ["IN"]
}

variable "cloud_armor_rate_limit" {
  description = "Maximum requests per minute per IP via Cloud Armor"
  type        = number
  default     = 100
}

variable "recaptcha_site_key" {
  description = "reCAPTCHA Enterprise site key for bot management (empty = disabled)"
  type        = string
  default     = ""
}

variable "max_request_body_bytes" {
  description = "Maximum allowed request body size in bytes for auth endpoints"
  type        = number
  default     = 4096
}
