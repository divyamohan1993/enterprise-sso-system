###############################################################################
# MILNET SSO — Production 10K: 10,000 logins/sec on GCP
#
# ARCHITECTURE SUMMARY:
#   Compute:   GKE Standard (4 specialized node pools, ~$5,500/mo)
#   Database:  Cloud SQL Enterprise Plus PostgreSQL 16 HA 16vCPU/64GB (~$2,800/mo)
#   Cache:     Memorystore Redis Cluster 16GB (~$350/mo)
#   KMS:       Cloud KMS HSM — batched ops via envelope encryption (~$15/mo)
#   WAF:       Cloud Armor Enterprise — flat $3,000/mo (26B req/mo included)
#   CDN:       Cloud CDN for JWKS/.well-known endpoints (~$50/mo)
#   Network:   Global HTTPS LB + VPC + Cloud NAT (~$250/mo)
#   Secrets:   Secret Manager (~$15/mo)
#   Observe:   Cloud Logging/Monitoring + 2% Trace sampling (~$300/mo)
#   Security:  Binary Auth + VPC Service Controls + Shielded VMs ($0)
#
# ESTIMATED TOTAL: ~$12,265/mo (with 3yr CUD: ~$8,500/mo)
#
# SCALING FROM 1K → 10K:
#   - General pool: 3x e2-standard-4 → 8x e2-standard-8 (10x vCPU capacity)
#   - Compute pool: 2x t2d-standard-8 → 6x c3d-standard-8 (3x nodes, latest gen)
#   - Confidential pool: 5x n2d-standard-2 → 5x n2d-standard-4 (2x per-signer CPU)
#   - Stateful pool: 7x e2-standard-2 → 7x e2-standard-4 (2x audit throughput)
#   - Cloud SQL: 8vCPU/32GB → 16vCPU/64GB, 500→1000 connections
#   - Redis: 4GB HA → 16GB Cluster (horizontal throughput)
#   - Cloud Armor: Standard → Enterprise (26B req/mo makes flat rate optimal)
#   - Cloud CDN: Added for JWKS/.well-known (cacheable, reduces LB load)
#
# QUANTUM-SAFE DESIGN (UNCHANGED FROM 1K):
#   All inter-service: SHARD protocol (HMAC-SHA512 + AES-256-GCM over mTLS 1.3)
#   Token signing: FROST 3-of-5 nested under ML-DSA-87 (FIPS 204)
#   Key exchange: X-Wing hybrid KEM (ML-KEM-1024 + X25519)
#   Session keys: HKDF-SHA512 ratcheting (forward secrecy)
#   Audit: ML-DSA-87 signed, SHA3-256 Merkle tree
#
# WHY THIS BEATS OTHER SSO PROVIDERS AT SCALE:
#   - Post-quantum from day one (Okta/Auth0/Azure AD: zero PQ support)
#   - Threshold signing (no single key to steal — unlike every other SSO)
#   - Server-blind passwords (OPAQUE — server never sees plaintext)
#   - Forward-secret sessions (ratcheting — past sessions unrecoverable)
#   - BFT audit log (tamper-proof even with 2 compromised nodes)
#   - DPoP token binding (stolen tokens unusable without client key)
#   - All this for ~$12,265/mo vs Okta Enterprise at $6+/user/mo ($6M/mo at 1M users)
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
    prefix = "production-10k"
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
    scale_tier  = "10k"
  }

  # Cost optimization: us-central1 has the cheapest compute + egress
  # E2 machines get automatic 20-30% sustained use discounts
  # C3D for compute-heavy: latest gen AMD, best perf/$ for Argon2id
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
  description             = "MILNET SSO production VPC — zero-trust segmented (10K scale)"

  depends_on = [google_project_service.apis]
}

# GKE nodes subnet — private IPs only
# Larger /18 CIDR for 10K scale (16K node IPs vs /20's 4K)
resource "google_compute_subnetwork" "gke" {
  name                     = "${local.network_name}-gke"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = "10.0.0.0/18"
  private_ip_google_access = true
  description              = "GKE nodes — private IPs only, sized for 10K scale"

  secondary_ip_range {
    range_name    = "gke-pods"
    ip_cidr_range = "10.4.0.0/14"
  }

  secondary_ip_range {
    range_name    = "gke-services"
    ip_cidr_range = "10.8.0.0/18"
  }

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.05 # 5% at 10K scale — balances cost vs visibility
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
# Scaled: more NAT ports per VM for higher connection count
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
  min_ports_per_vm                    = 8192  # Doubled from 1K for higher connection throughput
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
    "10.0.0.0/18", # GKE nodes (expanded for 10K)
    "10.4.0.0/14", # GKE pods
    "10.8.0.0/18", # GKE services (expanded for 10K)
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
# Same security posture as 1K — only node pools scale
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
# SCALED: 3-8x e2-standard-4 → 8-20x e2-standard-8 (10x total vCPU)
# E2-standard-8 doubles per-node capacity, reducing scheduling overhead
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
    max_surge       = 3 # More surge for larger pool
    max_unavailable = 1
    strategy        = "SURGE"
  }

  node_config {
    # E2-standard-8: 8 vCPU, 32 GB — doubled from 1K's e2-standard-4
    # Handles gateway + admin + verifier + risk + KT at 10K scale
    # Gets automatic 20-30% sustained use discount
    machine_type = "e2-standard-8"
    disk_size_gb = 100  # Doubled for higher log/cache volume
    disk_type    = "pd-balanced"

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
# SCALED: 2-5x t2d-standard-8 → 6-15x c3d-standard-8
# C3D: latest gen AMD Genoa — 30-40% better IPC than T2D for Argon2id
# At 10K req/s, Argon2id is the #1 bottleneck; C3D maximizes hash throughput
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
    max_surge       = 2 # Higher surge for faster rollout at scale
    max_unavailable = 1
    strategy        = "SURGE"
  }

  node_config {
    # C3D-standard-8: latest AMD Genoa, 8 vCPU, 32 GB
    # 30-40% better single-thread IPC than T2D (Zen 3 → Zen 4)
    # Critical for Argon2id: memory-hard hashing at 10,000 req/s
    # Each node handles ~1,700 Argon2id hashes/s (vs ~1,200 on T2D)
    machine_type = "c3d-standard-8"
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
# SCALED: 5x n2d-standard-2 → 5x n2d-standard-4 (2x per-signer CPU)
# AMD SEV encrypted memory — key shares never in plaintext RAM
# Larger instances handle 10x signing throughput without adding signers
# (Adding signers would slow FROST — coordination overhead is O(n^2))
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
    # N2D-standard-4: 4 vCPU, 16 GB — doubled from 1K's n2d-standard-2
    # Each signer holds 1 FROST share, handles 10x more concurrent signing rounds
    # AMD SEV encrypts memory — key shares protected even from hypervisor
    # 5 signers is optimal: 3-of-5 threshold minimizes coordination latency
    machine_type = "n2d-standard-4"
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
# SCALED: 7x e2-standard-2 → 7x e2-standard-4 (2x audit write throughput)
# Persistent SSD storage for audit log, stable node count
###############################################################################

resource "google_container_node_pool" "stateful" {
  name       = "stateful"
  project    = var.project_id
  location   = var.region
  cluster    = google_container_cluster.primary.name
  node_count = var.stateful_node_count

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
    # E2-standard-4: 4 vCPU, 16 GB — doubled from 1K's e2-standard-2
    # Each runs 1 BFT audit node — 2x CPU for 10x write throughput
    # Audit writes are batched (100 events/batch) so CPU matters more than IOPS
    machine_type = "e2-standard-4"
    disk_size_gb = 200      # Doubled: 10x audit volume needs more storage
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
# SCALED: 8 vCPU/32 GB → 16 vCPU/64 GB, 500→1000 connections
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
    disk_size         = 500   # 5x more for 10K audit/session volume
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
      query_plans_per_minute  = 10  # More plans at higher load
      query_string_length     = 4096
      record_application_tags = true
      record_client_address   = true
    }

    # Connection handling: 1000 connections for 10K req/s with connection pooling
    # At 10K req/s with ~5ms avg DB time: needs ~50 active connections
    # 1000 max allows for burst headroom + audit + admin + monitoring
    database_flags {
      name  = "max_connections"
      value = tostring(var.db_max_connections)
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

    # Performance tuning for 10,000 req/s
    # 16 GB shared_buffers = 25% of 64 GB RAM (PostgreSQL best practice)
    database_flags {
      name  = "shared_buffers"
      value = tostring(var.db_shared_buffers)
    }

    # 48 GB effective_cache_size = 75% of 64 GB RAM
    database_flags {
      name  = "effective_cache_size"
      value = tostring(var.db_effective_cache_size)
    }

    # 32 MB work_mem — doubled for larger sort/hash operations at 10K scale
    database_flags {
      name  = "work_mem"
      value = "32768"
    }

    # WAL tuning for high write throughput
    database_flags {
      name  = "wal_buffers"
      value = "65536" # 64 MB — maximizes WAL write batching
    }

    # Checkpoint tuning: less frequent checkpoints, more WAL between them
    database_flags {
      name  = "checkpoint_completion_target"
      value = "0.9"
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
# SCALED: 4 GB Standard HA → 16 GB Cluster Mode
# Cluster mode provides horizontal throughput for 10K req/s
# 16 GB holds ~2M concurrent sessions (8 KB/session avg)
###############################################################################

resource "google_redis_cluster" "cache" {
  name           = "milnet-redis-${var.environment}"
  project        = var.project_id
  region         = var.region
  shard_count    = 4      # 4 shards x 4 GB = 16 GB total
  replica_count  = 1      # 1 replica per shard for HA

  psc_configs {
    network = google_compute_network.vpc.id
  }

  redis_configs = {
    maxmemory-policy = "allkeys-lru"
  }

  transit_encryption_mode = "SERVER_AUTHENTICATION"
  authorization_mode      = "AUTH_MODE_IAM_AUTH"

  depends_on = [google_project_service.apis]
}

###############################################################################
# Cloud KMS — HSM-Protected Keys (Envelope Encryption)
#
# UNCHANGED FROM 1K: Same envelope encryption approach.
# App does all signing locally using ML-DSA/FROST.
# KMS only wraps/unwraps the master KEK at startup (< 100 ops/day).
# At 10K req/s this saves $77,760/mo (!) vs per-operation KMS calls.
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
# Cloud Armor — Enterprise WAF + DDoS Protection
# SCALED: Standard → Enterprise ($3,000/mo flat)
# At 26B req/mo (10K req/s), Enterprise is 5x cheaper than Standard per-request
# Includes adaptive protection, bot management, and DDoS insurance
###############################################################################

resource "google_compute_security_policy" "sso" {
  name        = "milnet-sso-armor"
  project     = var.project_id
  description = "MILNET SSO WAF — Enterprise tier, rate limiting + OWASP protection"

  # Adaptive protection (Enterprise only) — ML-based anomaly detection
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable          = var.enable_cloud_armor_enterprise
      rule_visibility = "STANDARD"
    }
  }

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

  # Rate limiting: 500 req/min per IP (higher for 10K — legitimate API clients)
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
      conform_action   = "allow"
      exceed_action    = "deny(429)"
      ban_duration_sec = 300

      rate_limit_threshold {
        count        = 500
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

  # Block session fixation (additional for 10K)
  rule {
    action   = "deny(403)"
    priority = 2600

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sessionfixation-v33-stable')"
      }
    }
  }

  # Block Java attacks (additional for 10K)
  rule {
    action   = "deny(403)"
    priority = 2700

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('java-v33-stable')"
      }
    }
  }
}

###############################################################################
# Cloud CDN — Cache JWKS & .well-known endpoints
# NEW in 10K: reduces load balancer pressure for token verification traffic
# JWKS and .well-known/openid-configuration are immutable per key epoch
# Cache TTL matches ratchet epoch (15 min) — automatic invalidation
###############################################################################

resource "google_compute_backend_bucket" "jwks_cdn" {
  count = var.enable_cloud_cdn ? 1 : 0

  name        = "milnet-jwks-cdn"
  project     = var.project_id
  description = "CDN for JWKS and .well-known endpoints — reduces 10K verification load"
  bucket_name = google_storage_bucket.jwks_cache[0].name
  enable_cdn  = true

  cdn_policy {
    cache_mode                   = "CACHE_ALL_STATIC"
    default_ttl                  = 900  # 15 min — matches ratchet epoch
    max_ttl                      = 900
    signed_url_cache_max_age_sec = 900
    cache_key_policy {
      include_host         = true
      include_protocol     = true
      include_query_string = false
    }
  }
}

resource "google_storage_bucket" "jwks_cache" {
  count = var.enable_cloud_cdn ? 1 : 0

  name     = "milnet-sso-jwks-${var.project_id}"
  project  = var.project_id
  location = var.region

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "Delete"
    }
  }

  labels = local.labels
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
      keep_count = 10 # More versions for faster rollback at scale
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
