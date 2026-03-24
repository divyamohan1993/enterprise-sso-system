###############################################################################
# MILNET SSO — Production 1K: 1000 logins/sec on GCP
#
# ARCHITECTURE SUMMARY:
#   Compute:   GKE Standard (4 specialized node pools, ~$1,600/mo)
#   Database:  Cloud SQL Enterprise Plus PostgreSQL 16 HA (~$1,200/mo)
#   Cache:     Memorystore Redis Standard HA 4GB (~$140/mo)
#   KMS:       Cloud KMS HSM — batched ops via envelope encryption (~$50/mo)
#   WAF:       Cloud Armor Standard + preconfigured rules (~$600/mo)
#   Network:   Global HTTPS LB + VPC + Cloud NAT (~$170/mo)
#   Secrets:   Secret Manager (~$5/mo)
#   Observe:   Cloud Logging/Monitoring + 2% Trace sampling (~$120/mo)
#   Security:  Binary Auth + VPC Service Controls + Shielded VMs ($0)
#
# ESTIMATED TOTAL: ~$3,900/mo (with 1yr CUD: ~$3,100/mo)
#
# QUANTUM-SAFE DESIGN:
#   All inter-service: SHARD protocol (HMAC-SHA512 + AES-256-GCM over mTLS 1.3)
#   Token signing: FROST 3-of-5 nested under ML-DSA-87 (FIPS 204)
#   Key exchange: X-Wing hybrid KEM (ML-KEM-1024 + X25519)
#   Session keys: HKDF-SHA512 ratcheting (forward secrecy)
#   Audit: ML-DSA-87 signed, SHA3-256 Merkle tree
#
# WHY THIS BEATS OTHER SSO PROVIDERS:
#   - Post-quantum from day one (Okta/Auth0/Azure AD: zero PQ support)
#   - Threshold signing (no single key to steal — unlike every other SSO)
#   - Server-blind passwords (OPAQUE — server never sees plaintext)
#   - Forward-secret sessions (ratcheting — past sessions unrecoverable)
#   - BFT audit log (tamper-proof even with 2 compromised nodes)
#   - DPoP token binding (stolen tokens unusable without client key)
#   - All this for ~$3,900/mo vs Okta Enterprise at $6+/user/mo
###############################################################################

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.40"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "gcs" {
    bucket = "milnet-sso-terraform-state"
    prefix = "production-1k"
  }
}

###############################################################################
# Providers
###############################################################################

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

provider "kubernetes" {
  host                   = "https://${google_container_cluster.primary.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.primary.master_auth[0].cluster_ca_certificate)
}

data "google_client_config" "default" {}
data "google_project" "current" {}

locals {
  cluster_name = "milnet-sso-${var.environment}"
  network_name = "milnet-vpc-${var.environment}"

  labels = {
    project     = "milnet-sso"
    environment = var.environment
    managed_by  = "terraform"
    cost_center = "security-infrastructure"
  }

  # Cost optimization: us-central1 has the cheapest compute + egress
  # E2 machines get automatic 20-30% sustained use discounts
  # N2D for confidential nodes (AMD SEV required)
}

###############################################################################
# Enable Required GCP APIs
###############################################################################

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "cloudkms.googleapis.com",
    "secretmanager.googleapis.com",
    "dns.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "binaryauthorization.googleapis.com",
    "servicenetworking.googleapis.com",
    "certificatemanager.googleapis.com",
    "networksecurity.googleapis.com",
    "cloudtrace.googleapis.com",
  ])

  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

###############################################################################
# VPC Network — Zero-Trust Segmentation
###############################################################################

resource "google_compute_network" "vpc" {
  name                    = local.network_name
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  description             = "MILNET SSO production VPC — zero-trust segmented"

  depends_on = [google_project_service.apis]
}

# GKE nodes subnet — private IPs only
resource "google_compute_subnetwork" "gke" {
  name                     = "${local.network_name}-gke"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = "10.0.0.0/20"
  private_ip_google_access = true
  description              = "GKE nodes — private IPs only, no public exposure"

  secondary_ip_range {
    range_name    = "gke-pods"
    ip_cidr_range = "10.4.0.0/14"
  }

  secondary_ip_range {
    range_name    = "gke-services"
    ip_cidr_range = "10.8.0.0/20"
  }

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.1 # 10% sampling — cost vs visibility balance
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Database/managed services subnet — isolated
resource "google_compute_subnetwork" "db" {
  name                     = "${local.network_name}-db"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = "10.1.0.0/24"
  private_ip_google_access = true
  description              = "Database and managed services — isolated from compute"
}

# Proxy-only subnet for internal load balancers
resource "google_compute_subnetwork" "proxy" {
  name          = "${local.network_name}-proxy"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.vpc.id
  ip_cidr_range = "10.2.0.0/24"
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"
}

###############################################################################
# Cloud Router + NAT — Outbound for private nodes
###############################################################################

resource "google_compute_router" "main" {
  name    = "${local.network_name}-router"
  project = var.project_id
  region  = var.region
  network = google_compute_network.vpc.id

  bgp {
    asn = 64514
  }
}

resource "google_compute_router_nat" "main" {
  name                                = "${local.network_name}-nat"
  project                             = var.project_id
  region                              = var.region
  router                              = google_compute_router.main.name
  nat_ip_allocate_option              = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat  = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  min_ports_per_vm                    = 4096
  max_ports_per_vm                    = 65536
  enable_endpoint_independent_mapping = false

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

###############################################################################
# Private Services Access — Cloud SQL + Memorystore
###############################################################################

resource "google_compute_global_address" "private_services" {
  name          = "${local.network_name}-private-svc"
  project       = var.project_id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]

  depends_on = [google_project_service.apis]
}

###############################################################################
# Firewall Rules — Default Deny + Explicit Allow
###############################################################################

resource "google_compute_firewall" "deny_all_ingress" {
  name     = "${local.network_name}-deny-all"
  project  = var.project_id
  network  = google_compute_network.vpc.id
  priority = 65534

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_internal" {
  name     = "${local.network_name}-allow-internal"
  project  = var.project_id
  network  = google_compute_network.vpc.id
  priority = 1000

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = [
    "10.0.0.0/20", # GKE nodes
    "10.4.0.0/14", # GKE pods
    "10.8.0.0/20", # GKE services
  ]
}

resource "google_compute_firewall" "allow_health_checks" {
  name     = "${local.network_name}-allow-hc"
  project  = var.project_id
  network  = google_compute_network.vpc.id
  priority = 900

  allow {
    protocol = "tcp"
  }

  source_ranges = [
    "35.191.0.0/16",
    "130.211.0.0/22",
  ]

  target_tags = ["gke-node"]
}

resource "google_compute_firewall" "allow_iap_ssh" {
  name     = "${local.network_name}-allow-iap"
  project  = var.project_id
  network  = google_compute_network.vpc.id
  priority = 800

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["gke-node"]
}

resource "google_compute_firewall" "allow_gke_master" {
  name     = "${local.network_name}-allow-master"
  project  = var.project_id
  network  = google_compute_network.vpc.id
  priority = 700

  allow {
    protocol = "tcp"
    ports    = ["443", "8443", "10250", "10255"]
  }

  source_ranges = ["172.16.0.0/28"]
  target_tags   = ["gke-node"]
}

###############################################################################
# GKE Cluster — Standard (Confidential Nodes + Network Policy)
###############################################################################

resource "google_container_cluster" "primary" {
  provider = google-beta

  name                = local.cluster_name
  project             = var.project_id
  location            = var.region
  node_locations      = var.zones
  deletion_protection = true

  # Separately managed node pools
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.vpc.id
  subnetwork = google_compute_subnetwork.gke.id

  ip_allocation_policy {
    cluster_secondary_range_name  = "gke-pods"
    services_secondary_range_name = "gke-services"
  }

  # Private cluster — no public IPs on nodes
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"

    master_global_access_config {
      enabled = true
    }
  }

  master_authorized_networks_config {
    gcp_public_cidrs_access_enabled = false

    cidr_blocks {
      cidr_block   = "10.0.0.0/8"
      display_name = "Internal VPC"
    }
  }

  # Workload Identity — no service account keys
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Calico Network Policy — enforces pod-level zero-trust
  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  addons_config {
    network_policy_config {
      disabled = false
    }
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
    dns_cache_config {
      enabled = true
    }
  }

  # Binary Authorization — only signed images deploy
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  security_posture_config {
    mode               = "BASIC"
    vulnerability_mode = "VULNERABILITY_BASIC"
  }

  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS",
    ]
  }

  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "POD",
      "DEPLOYMENT",
    ]

    managed_prometheus {
      enabled = true
    }
  }

  # Maintenance: Sunday 02:00-06:00 UTC
  maintenance_policy {
    recurring_window {
      start_time = "2024-01-01T02:00:00Z"
      end_time   = "2024-01-01T06:00:00Z"
      recurrence = "FREQ=WEEKLY;BYDAY=SU"
    }
  }

  release_channel {
    channel = "STABLE"
  }

  resource_labels = local.labels

  depends_on = [
    google_project_service.apis,
    google_service_networking_connection.private_services,
  ]
}

###############################################################################
# Node Pool 1: General — Gateway, Admin, Verifier, Risk, KT
# Cost-optimized E2 instances (auto 20-30% sustained use discount)
###############################################################################

resource "google_container_node_pool" "general" {
  name     = "general"
  project  = var.project_id
  location = var.region
  cluster  = google_container_cluster.primary.name

  autoscaling {
    min_node_count = var.gke_general_min_nodes
    max_node_count = var.gke_general_max_nodes
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    max_surge       = 2
    max_unavailable = 1
    strategy        = "SURGE"
  }

  node_config {
    # E2-standard-4: cheapest balanced instance ($0.134/hr)
    # 4 vCPU, 16 GB — handles gateway + admin + verifier + risk + KT
    # Gets automatic 20-30% sustained use discount
    machine_type = "e2-standard-4"
    disk_size_gb = 50
    disk_type    = "pd-balanced" # Cheaper than pd-ssd, sufficient IOPS

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = merge(local.labels, {
      node_pool = "general"
    })

    tags = ["gke-node", "general-pool"]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }
}

###############################################################################
# Node Pool 2: Compute-Heavy — OPAQUE (Argon2id) + Orchestrator
# Higher CPU for password hashing at 1000 req/sec
###############################################################################

resource "google_container_node_pool" "compute" {
  name     = "compute"
  project  = var.project_id
  location = var.region
  cluster  = google_container_cluster.primary.name

  autoscaling {
    min_node_count = var.gke_compute_min_nodes
    max_node_count = var.gke_compute_max_nodes
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 1
    strategy        = "SURGE"
  }

  node_config {
    # T2D-standard-8: AMD EPYC full-core, excellent single-thread perf
    # Critical for Argon2id password hashing + OPAQUE protocol at 1000 req/s
    # $0.0462/vCPU-hr * 8 vCPU = $0.37/hr per node
    machine_type = "t2d-standard-8"
    disk_size_gb = 50
    disk_type    = "pd-balanced"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = merge(local.labels, {
      node_pool = "compute-heavy"
      workload  = "opaque-orchestrator"
    })

    tags = ["gke-node", "compute-pool"]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }
}

###############################################################################
# Node Pool 3: Confidential — TSS FROST Signers
# AMD SEV encrypted memory — key shares never in plaintext RAM
###############################################################################

resource "google_container_node_pool" "confidential" {
  name       = "confidential"
  project    = var.project_id
  location   = var.region
  cluster    = google_container_cluster.primary.name
  node_count = var.tss_signer_count

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0 # Never lose a signer during upgrade
    strategy        = "SURGE"
  }

  node_config {
    # N2D-standard-2: smallest confidential node ($0.084/hr)
    # 2 vCPU, 8 GB — each signer holds 1 FROST share
    # AMD SEV encrypts memory — key shares protected even from hypervisor
    machine_type = "n2d-standard-2"
    disk_size_gb = 50
    disk_type    = "pd-balanced"

    confidential_nodes {
      enabled = true
    }

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = merge(local.labels, {
      node_pool = "confidential"
      workload  = "tss-signer"
    })

    tags = ["gke-node", "confidential-pool"]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }

    # Only TSS signer pods schedule here
    taint {
      key    = "workload"
      value  = "tss-signer"
      effect = "NO_SCHEDULE"
    }
  }
}

###############################################################################
# Node Pool 4: Stateful — Audit BFT + Ratchet
# Persistent storage for audit log, stable node count
###############################################################################

resource "google_container_node_pool" "stateful" {
  name       = "stateful"
  project    = var.project_id
  location   = var.region
  cluster    = google_container_cluster.primary.name
  node_count = var.audit_bft_count

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0 # Never lose a BFT node during upgrade
    strategy        = "SURGE"
  }

  node_config {
    # E2-standard-2: cheapest for stateful workloads ($0.067/hr)
    # 2 vCPU, 8 GB — each runs 1 BFT audit node
    machine_type = "e2-standard-2"
    disk_size_gb = 100      # Audit log storage
    disk_type    = "pd-ssd" # Write-heavy workload needs SSD

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = merge(local.labels, {
      node_pool = "stateful"
      workload  = "audit-bft"
    })

    tags = ["gke-node", "stateful-pool"]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }

    taint {
      key    = "workload"
      value  = "audit-bft"
      effect = "NO_SCHEDULE"
    }
  }
}

###############################################################################
# Cloud SQL — PostgreSQL 16 Enterprise Plus (HA)
# 8 vCPU, 32 GB — handles 500 connections at 1000 req/s
###############################################################################

resource "google_sql_database_instance" "primary" {
  name                = "milnet-db-${var.environment}"
  project             = var.project_id
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true

  settings {
    tier              = var.db_tier
    edition           = "ENTERPRISE_PLUS"
    availability_type = var.db_ha ? "REGIONAL" : "ZONAL"
    disk_size         = 100
    disk_type         = "PD_SSD"
    disk_autoresize   = true

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.vpc.id
      enable_private_path_for_google_cloud_services = true
      require_ssl                                   = true
      ssl_mode                                      = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = 14
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = 7
      hour         = 4
      update_track = "stable"
    }

    insights_config {
      query_insights_enabled  = true
      query_plans_per_minute  = 5
      query_string_length     = 4096
      record_application_tags = true
      record_client_address   = true
    }

    database_flags {
      name  = "max_connections"
      value = "500"
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    database_flags {
      name  = "log_lock_waits"
      value = "on"
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "500"
    }

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }

    # Performance tuning for 1000 req/s
    database_flags {
      name  = "shared_buffers"
      value = "8192" # 8 GB (25% of 32 GB RAM)
    }

    database_flags {
      name  = "effective_cache_size"
      value = "24576" # 24 GB (75% of RAM)
    }

    database_flags {
      name  = "work_mem"
      value = "16384" # 16 MB per operation
    }

    user_labels = local.labels
  }

  depends_on = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "sso" {
  name     = "milnet_sso"
  project  = var.project_id
  instance = google_sql_database_instance.primary.name
}

# IAM-authenticated database user — no password to rotate
resource "google_sql_user" "workload" {
  name     = "milnet-workload@${var.project_id}.iam"
  project  = var.project_id
  instance = google_sql_database_instance.primary.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}

###############################################################################
# Memorystore Redis — Session/Revocation Cache
# Standard HA for zero-downtime failover
###############################################################################

resource "google_redis_instance" "cache" {
  name               = "milnet-redis-${var.environment}"
  project            = var.project_id
  region             = var.region
  tier               = "STANDARD_HA"
  memory_size_gb     = var.redis_memory_gb
  redis_version      = "REDIS_7_2"
  display_name       = "MILNET SSO Session & Revocation Cache"
  authorized_network = google_compute_network.vpc.id
  connect_mode       = "PRIVATE_SERVICE_ACCESS"

  redis_configs = {
    maxmemory-policy       = "allkeys-lru"
    notify-keyspace-events = "Ex" # Expiry notifications for session cleanup
  }

  maintenance_policy {
    weekly_maintenance_window {
      day = "SUNDAY"
      start_time {
        hours   = 3
        minutes = 0
      }
    }
  }

  transit_encryption_mode = "SERVER_AUTHENTICATION"
  auth_enabled            = true

  labels = local.labels

  depends_on = [google_service_networking_connection.private_services]
}

###############################################################################
# Cloud KMS — HSM-Protected Keys (Envelope Encryption)
#
# COST OPTIMIZATION: App does all signing locally using ML-DSA/FROST.
# KMS only wraps/unwraps the master KEK at startup (< 100 ops/day).
# This avoids $7,776/mo in per-operation KMS costs.
###############################################################################

resource "google_kms_key_ring" "sso" {
  name     = "milnet-keyring-${var.environment}"
  project  = var.project_id
  location = var.region

  depends_on = [google_project_service.apis]
}

# Master KEK — wraps all application-level keys
resource "google_kms_crypto_key" "master_kek" {
  name     = "master-kek"
  key_ring = google_kms_key_ring.sso.id
  purpose  = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM" # FIPS 140-3 Level 3
  }

  rotation_period = "7776000s" # 90 days

  labels = merge(local.labels, {
    key_purpose = "master-envelope-encryption"
  })

  lifecycle {
    prevent_destroy = true
  }
}

# Backup wrapping key — disaster recovery
resource "google_kms_crypto_key" "backup_kek" {
  name     = "backup-kek"
  key_ring = google_kms_key_ring.sso.id
  purpose  = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  rotation_period = "15552000s" # 180 days

  labels = merge(local.labels, {
    key_purpose = "backup-envelope-encryption"
  })

  lifecycle {
    prevent_destroy = true
  }
}

###############################################################################
# Secret Manager — All secrets encrypted under KMS HSM
###############################################################################

resource "random_password" "db_password" {
  length  = 80
  special = false # Avoids URL-encoding issues in connection strings
}

resource "google_secret_manager_secret" "db_password" {
  secret_id = "milnet-db-password"
  project   = var.project_id
  labels    = local.labels

  replication {
    auto {
      customer_managed_encryption {
        kms_key_name = google_kms_crypto_key.master_kek.id
      }
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.db_password.result
}

resource "random_password" "master_kek_seed" {
  length  = 64
  special = false
}

resource "google_secret_manager_secret" "master_kek_seed" {
  secret_id = "milnet-master-kek-seed"
  project   = var.project_id
  labels    = local.labels

  replication {
    auto {
      customer_managed_encryption {
        kms_key_name = google_kms_crypto_key.master_kek.id
      }
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "master_kek_seed" {
  secret      = google_secret_manager_secret.master_kek_seed.id
  secret_data = random_password.master_kek_seed.result
}

resource "random_password" "shard_hmac_key" {
  length  = 128
  special = false
}

resource "google_secret_manager_secret" "shard_hmac_key" {
  secret_id = "milnet-shard-hmac-key"
  project   = var.project_id
  labels    = local.labels

  replication {
    auto {
      customer_managed_encryption {
        kms_key_name = google_kms_crypto_key.master_kek.id
      }
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "shard_hmac_key" {
  secret      = google_secret_manager_secret.shard_hmac_key.id
  secret_data = random_password.shard_hmac_key.result
}

###############################################################################
# IAM — Workload Identity (no service account keys)
###############################################################################

resource "google_service_account" "gke_workload" {
  account_id   = "milnet-sso-workload"
  project      = var.project_id
  display_name = "MILNET SSO GKE Workload Identity"
}

# Allow GKE pods to impersonate this service account
resource "google_service_account_iam_binding" "workload_identity" {
  service_account_id = google_service_account.gke_workload.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[milnet-sso/milnet-sso-workload]",
  ]
}

# Minimum privilege: only the permissions the app actually needs
resource "google_project_iam_member" "workload_kms" {
  project = var.project_id
  role    = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member  = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_project_iam_member" "workload_secrets" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_project_iam_member" "workload_sql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_project_iam_member" "workload_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_project_iam_member" "workload_monitoring" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_project_iam_member" "workload_trace" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.gke_workload.email}"
}

###############################################################################
# Cloud Armor — WAF + DDoS Protection
###############################################################################

resource "google_compute_security_policy" "sso" {
  name        = "milnet-sso-armor"
  project     = var.project_id
  description = "MILNET SSO WAF — rate limiting + OWASP protection"

  # Default: allow
  rule {
    action   = "allow"
    priority = 2147483647

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }

  # Rate limiting: 200 req/min per IP (generous for legitimate SSO)
  rule {
    action   = "rate_based_ban"
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
      ban_duration_sec = 300

      rate_limit_threshold {
        count        = 200
        interval_sec = 60
      }
    }
  }

  # Block SQL injection
  rule {
    action   = "deny(403)"
    priority = 2000

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }
  }

  # Block XSS
  rule {
    action   = "deny(403)"
    priority = 2100

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }
  }

  # Block protocol attacks
  rule {
    action   = "deny(403)"
    priority = 2200

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('protocolattack-v33-stable')"
      }
    }
  }

  # Block scanner detection
  rule {
    action   = "deny(403)"
    priority = 2300

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('scannerdetection-v33-stable')"
      }
    }
  }

  # Block remote code execution
  rule {
    action   = "deny(403)"
    priority = 2400

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rce-v33-stable')"
      }
    }
  }

  # Block local file inclusion
  rule {
    action   = "deny(403)"
    priority = 2500

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('lfi-v33-stable')"
      }
    }
  }
}

###############################################################################
# Artifact Registry — Container Images
###############################################################################

resource "google_artifact_registry_repository" "sso" {
  location      = var.artifact_registry_location
  repository_id = "milnet-sso"
  project       = var.project_id
  format        = "DOCKER"
  description   = "MILNET SSO container images"

  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"

    most_recent_versions {
      keep_count = 5
    }
  }

  labels = local.labels

  depends_on = [google_project_service.apis]
}

###############################################################################
# Cloud DNS — Private Zone for Service Discovery
###############################################################################

resource "google_dns_managed_zone" "private" {
  name        = "milnet-sso-private"
  project     = var.project_id
  dns_name    = "sso.internal."
  description = "Private DNS for SSO service discovery"
  visibility  = "private"
  labels      = local.labels

  private_visibility_config {
    networks {
      network_url = google_compute_network.vpc.id
    }
  }
}
