###############################################################################
# Enterprise SSO System — Hyper-Scale Terraform Configuration
# Target: 1000+ logins/second on Google Cloud Platform
# Architecture: GKE + Cloud SQL + Memorystore + Cloud KMS (HSM)
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
    prefix = "hyper-scale"
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
  network_name = "milnet-sso-vpc"
  labels = {
    project     = "milnet-sso"
    environment = var.environment
    managed_by  = "terraform"
    cost_center = "security-infrastructure"
  }
}

###############################################################################
# Enable Required APIs
###############################################################################

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "cloudkms.googleapis.com",
    "secretmanager.googleapis.com",
    "privateca.googleapis.com",
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
  ])

  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

###############################################################################
# Networking — VPC, Subnets, Cloud NAT, Firewall
###############################################################################

resource "google_compute_network" "vpc" {
  name                    = local.network_name
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  description             = "VPC for MilNet SSO hyper-scale deployment"

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "gke_subnet" {
  name                     = "${local.network_name}-gke"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = "10.0.0.0/20"
  private_ip_google_access = true
  description              = "GKE nodes subnet — private IPs only"

  secondary_ip_range {
    range_name    = "gke-pods"
    ip_cidr_range = "10.4.0.0/14"
  }

  secondary_ip_range {
    range_name    = "gke-services"
    ip_cidr_range = "10.8.0.0/20"
  }

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "db_subnet" {
  name                     = "${local.network_name}-db"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = "10.1.0.0/24"
  private_ip_google_access = true
  description              = "Database and managed services subnet"
}

resource "google_compute_subnetwork" "proxy_only_subnet" {
  name          = "${local.network_name}-proxy-only"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.vpc.id
  ip_cidr_range = "10.2.0.0/24"
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"
  description   = "Proxy-only subnet for internal load balancers"
}

# Cloud Router for NAT
resource "google_compute_router" "router" {
  name        = "${local.network_name}-router"
  project     = var.project_id
  region      = var.region
  network     = google_compute_network.vpc.id
  description = "Cloud Router for NAT gateway"

  bgp {
    asn = 64514
  }
}

# Cloud NAT — outbound internet for private nodes
resource "google_compute_router_nat" "nat" {
  name                                = "${local.network_name}-nat"
  project                             = var.project_id
  region                              = var.region
  router                              = google_compute_router.router.name
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

# Private services access for Cloud SQL and Memorystore
resource "google_compute_global_address" "private_services" {
  name          = "${local.network_name}-private-services"
  project       = var.project_id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc.id
  description   = "Reserved IP range for private services (Cloud SQL, Memorystore)"
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]

  depends_on = [google_project_service.apis]
}

# Firewall Rules — Module Communication Matrix
resource "google_compute_firewall" "deny_all_ingress" {
  name        = "${local.network_name}-deny-all-ingress"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  priority    = 65534
  direction   = "INGRESS"
  description = "Default deny all ingress traffic"

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_internal" {
  name        = "${local.network_name}-allow-internal"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  priority    = 1000
  direction   = "INGRESS"
  description = "Allow internal communication between GKE pods and services"

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
  name        = "${local.network_name}-allow-health-checks"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  priority    = 900
  direction   = "INGRESS"
  description = "Allow GCP health check probes"

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
  name        = "${local.network_name}-allow-iap-ssh"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  priority    = 800
  direction   = "INGRESS"
  description = "Allow IAP tunnel for SSH access to nodes"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["gke-node"]
}

resource "google_compute_firewall" "allow_gke_master" {
  name        = "${local.network_name}-allow-gke-master"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  priority    = 700
  direction   = "INGRESS"
  description = "Allow GKE master to communicate with nodes on webhook and metrics ports"

  allow {
    protocol = "tcp"
    ports    = ["443", "8443", "10250", "10255"]
  }

  source_ranges = ["172.16.0.0/28"]
  target_tags   = ["gke-node"]
}

# Cloud DNS — Private Zone for Service Discovery
resource "google_dns_managed_zone" "private" {
  name        = "milnet-sso-private"
  project     = var.project_id
  dns_name    = "sso.internal."
  description = "Private DNS zone for SSO service discovery"
  visibility  = "private"
  labels      = local.labels

  private_visibility_config {
    networks {
      network_url = google_compute_network.vpc.id
    }
  }
}

###############################################################################
# GKE Cluster — Standard (Confidential Nodes support)
###############################################################################

resource "google_container_cluster" "primary" {
  provider = google-beta

  name                = local.cluster_name
  project             = var.project_id
  location            = var.region
  node_locations      = var.zones
  deletion_protection = true
  description         = "MilNet SSO hyper-scale GKE cluster for 1000+ logins/sec"

  # Use separately managed node pools
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.vpc.id
  subnetwork = google_compute_subnetwork.gke_subnet.id

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
      display_name = "Internal VPC access"
    }
  }

  # Workload Identity
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Network Policy (Calico)
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

  # Binary Authorization
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  # Security posture
  security_posture_config {
    mode               = "BASIC"
    vulnerability_mode = "VULNERABILITY_BASIC"
  }

  # Logging and monitoring
  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS",
      "APISERVER",
      "SCHEDULER",
      "CONTROLLER_MANAGER",
    ]
  }

  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "APISERVER",
      "SCHEDULER",
      "CONTROLLER_MANAGER",
      "STORAGE",
      "HPA",
      "POD",
      "DAEMONSET",
      "DEPLOYMENT",
      "STATEFULSET",
    ]

    managed_prometheus {
      enabled = true
    }
  }

  # Maintenance window — Sunday 02:00-06:00 UTC
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
# GKE Node Pools
###############################################################################

# Pool 1: General — Gateway, Admin, Verifier, Risk, KT
resource "google_container_node_pool" "general" {
  name     = "general"
  project  = var.project_id
  location = var.region
  cluster  = google_container_cluster.primary.name

  autoscaling {
    min_node_count = 3
    max_node_count = 10
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
    machine_type = "e2-standard-4"
    disk_size_gb = 100
    disk_type    = "pd-ssd"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = merge(local.labels, {
      node_pool = "general"
      workload  = "gateway-admin-verifier-risk-kt"
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

# Pool 2: Compute-Heavy — OPAQUE, Orchestrator
resource "google_container_node_pool" "compute_heavy" {
  name     = "compute-heavy"
  project  = var.project_id
  location = var.region
  cluster  = google_container_cluster.primary.name

  autoscaling {
    min_node_count = 2
    max_node_count = 6
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
    machine_type = "c3-highcpu-22"
    disk_size_gb = 100
    disk_type    = "pd-ssd"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = merge(local.labels, {
      node_pool = "compute-heavy"
      workload  = "opaque-orchestrator"
    })

    tags = ["gke-node", "compute-heavy-pool"]

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

# Pool 3: Confidential — TSS Signers (Confidential Computing)
resource "google_container_node_pool" "confidential" {
  name       = "confidential"
  project    = var.project_id
  location   = var.region
  cluster    = google_container_cluster.primary.name
  node_count = 5

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
    strategy        = "SURGE"
  }

  node_config {
    machine_type = "n2d-standard-4"
    disk_size_gb = 100
    disk_type    = "pd-ssd"

    confidential_nodes {
      enabled = true
    }

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = merge(local.labels, {
      node_pool = "confidential"
      workload  = "tss-signers"
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

    taint {
      key    = "workload"
      value  = "tss-signer"
      effect = "NO_SCHEDULE"
    }
  }
}

# Pool 4: Stateful — Audit BFT
resource "google_container_node_pool" "stateful" {
  name       = "stateful"
  project    = var.project_id
  location   = var.region
  cluster    = google_container_cluster.primary.name
  node_count = 7

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
    strategy        = "SURGE"
  }

  node_config {
    machine_type = "e2-standard-4"
    disk_size_gb = 200
    disk_type    = "pd-ssd"

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
###############################################################################

resource "google_sql_database_instance" "primary" {
  name                = "milnet-sso-db-${var.environment}"
  project             = var.project_id
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true

  settings {
    tier              = "db-custom-4-16384"
    edition           = "ENTERPRISE_PLUS"
    availability_type = "REGIONAL"
    disk_size         = 100
    disk_type         = "PD_SSD"
    disk_autoresize   = true

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.vpc.id
      enable_private_path_for_google_cloud_services = true
      require_ssl                                   = true

      ssl_mode = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = 30
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
      value = "1000"
    }

    database_flags {
      name  = "log_temp_files"
      value = "0"
    }

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
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

resource "google_sql_user" "sso" {
  name     = "sso_app"
  project  = var.project_id
  instance = google_sql_database_instance.primary.name
  password = var.db_password
}

###############################################################################
# Memorystore — Redis (Standard HA, 2GB)
###############################################################################

resource "google_redis_instance" "token_cache" {
  name               = "milnet-sso-redis-${var.environment}"
  project            = var.project_id
  region             = var.region
  tier               = "STANDARD_HA"
  memory_size_gb     = 2
  redis_version      = "REDIS_7_2"
  display_name       = "MilNet SSO Token Revocation Cache"
  authorized_network = google_compute_network.vpc.id
  connect_mode       = "PRIVATE_SERVICE_ACCESS"

  redis_configs = {
    maxmemory-policy       = "allkeys-lru"
    notify-keyspace-events = "Ex"
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
# Cloud KMS — HSM-Protected Keys
###############################################################################

resource "google_kms_key_ring" "sso" {
  name     = "milnet-sso-keyring-${var.environment}"
  project  = var.project_id
  location = var.region

  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "master_kek" {
  name     = "master-kek"
  key_ring = google_kms_key_ring.sso.id
  purpose  = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  rotation_period = "7776000s" # 90 days

  labels = merge(local.labels, {
    key_purpose = "envelope-encryption"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "receipt_signing" {
  name     = "receipt-signing"
  key_ring = google_kms_key_ring.sso.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P384_SHA384"
    protection_level = "HSM"
  }

  labels = merge(local.labels, {
    key_purpose = "opaque-receipt-signing"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "audit_signing" {
  name     = "audit-signing"
  key_ring = google_kms_key_ring.sso.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P384_SHA384"
    protection_level = "HSM"
  }

  labels = merge(local.labels, {
    key_purpose = "audit-log-signing"
  })

  lifecycle {
    prevent_destroy = true
  }
}

###############################################################################
# Secret Manager
###############################################################################

resource "google_secret_manager_secret" "db_password" {
  secret_id = "milnet-sso-db-password"
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
  secret_data = var.db_password
}

resource "random_password" "admin_api_key" {
  length  = 64
  special = true
}

resource "google_secret_manager_secret" "admin_api_key" {
  secret_id = "milnet-sso-admin-api-key"
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

resource "google_secret_manager_secret_version" "admin_api_key" {
  secret      = google_secret_manager_secret.admin_api_key.id
  secret_data = random_password.admin_api_key.result
}

resource "random_password" "receipt_signing_key" {
  length  = 64
  special = false
}

resource "google_secret_manager_secret" "receipt_signing_key" {
  secret_id = "milnet-sso-receipt-signing-key"
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

resource "google_secret_manager_secret_version" "receipt_signing_key" {
  secret      = google_secret_manager_secret.receipt_signing_key.id
  secret_data = random_password.receipt_signing_key.result
}

resource "random_password" "shard_hmac_key" {
  length  = 64
  special = false
}

resource "google_secret_manager_secret" "shard_hmac_key" {
  secret_id = "milnet-sso-shard-hmac-key"
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
# Certificate Authority Service — Private CA for mTLS
###############################################################################

resource "google_privateca_ca_pool" "sso" {
  name     = "milnet-sso-ca-pool"
  project  = var.project_id
  location = var.region
  tier     = "ENTERPRISE"

  publishing_options {
    publish_ca_cert = true
    publish_crl     = true
    encoding_format = "PEM"
  }

  issuance_policy {
    maximum_lifetime = "86400s" # 24 hours — short-lived mTLS certs

    baseline_values {
      key_usage {
        base_key_usage {
          digital_signature = true
          key_encipherment  = true
        }

        extended_key_usage {
          server_auth = true
          client_auth = true
        }
      }

      ca_options {
        is_ca = false
      }
    }
  }

  labels = local.labels

  depends_on = [google_project_service.apis]
}

resource "google_privateca_certificate_authority" "subordinate" {
  pool                     = google_privateca_ca_pool.sso.name
  certificate_authority_id = "milnet-sso-sub-ca"
  project                  = var.project_id
  location                 = var.region
  type                     = "SUBORDINATE"
  deletion_protection      = true

  config {
    subject_config {
      subject {
        organization = "MilNet SSO"
        common_name  = "MilNet SSO Subordinate CA"
      }
    }

    x509_config {
      ca_options {
        is_ca                  = true
        max_issuer_path_length = 0
      }

      key_usage {
        base_key_usage {
          cert_sign = true
          crl_sign  = true
        }

        extended_key_usage {
          server_auth = true
          client_auth = true
        }
      }
    }
  }

  key_spec {
    algorithm = "EC_P384_SHA384"
  }

  lifetime = "315360000s" # 10 years

  labels = local.labels
}

###############################################################################
# IAM — Service Accounts with Minimal Permissions
###############################################################################

# GKE workload service account
resource "google_service_account" "gke_workload" {
  account_id   = "milnet-sso-workload"
  project      = var.project_id
  display_name = "MilNet SSO GKE Workload Identity"
  description  = "Service account for SSO application pods via Workload Identity"
}

resource "google_project_iam_member" "gke_workload_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_project_iam_member" "gke_workload_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_project_iam_member" "gke_workload_trace_agent" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_kms_crypto_key_iam_member" "workload_master_kek" {
  crypto_key_id = google_kms_crypto_key.master_kek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_kms_crypto_key_iam_member" "workload_receipt_signing" {
  crypto_key_id = google_kms_crypto_key.receipt_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_kms_crypto_key_iam_member" "workload_audit_signing" {
  crypto_key_id = google_kms_crypto_key.audit_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_secret_manager_secret_iam_member" "workload_db_password" {
  secret_id = google_secret_manager_secret.db_password.secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_secret_manager_secret_iam_member" "workload_admin_api_key" {
  secret_id = google_secret_manager_secret.admin_api_key.secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_secret_manager_secret_iam_member" "workload_receipt_key" {
  secret_id = google_secret_manager_secret.receipt_signing_key.secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.gke_workload.email}"
}

resource "google_secret_manager_secret_iam_member" "workload_shard_hmac" {
  secret_id = google_secret_manager_secret.shard_hmac_key.secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.gke_workload.email}"
}

# Workload Identity binding
resource "google_service_account_iam_member" "workload_identity_binding" {
  service_account_id = google_service_account.gke_workload.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[milnet-sso/milnet-sso-workload]"
}

# Cloud Build service account
resource "google_service_account" "cloud_build" {
  account_id   = "milnet-sso-cloudbuild"
  project      = var.project_id
  display_name = "MilNet SSO Cloud Build"
  description  = "Service account for CI/CD pipeline"
}

resource "google_project_iam_member" "cloud_build_gke_developer" {
  project = var.project_id
  role    = "roles/container.developer"
  member  = "serviceAccount:${google_service_account.cloud_build.email}"
}

resource "google_project_iam_member" "cloud_build_ar_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.cloud_build.email}"
}

resource "google_project_iam_member" "cloud_build_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.cloud_build.email}"
}

###############################################################################
# Load Balancing — Global HTTPS (Admin) + Internal TCP (Gateway)
###############################################################################

# Global static IP for Admin API
resource "google_compute_global_address" "admin_lb" {
  name        = "milnet-sso-admin-lb-ip"
  project     = var.project_id
  description = "Global static IP for Admin API HTTPS load balancer"
}

# Managed SSL certificate
resource "google_compute_managed_ssl_certificate" "admin" {
  name    = "milnet-sso-admin-cert"
  project = var.project_id

  managed {
    domains = [var.domain]
  }
}

# Cloud Armor security policy
resource "google_compute_security_policy" "admin" {
  name        = "milnet-sso-admin-armor"
  project     = var.project_id
  description = "Cloud Armor policy for Admin API — rate limiting, OWASP, geo-blocking"

  # Default rule — allow
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

  # Rate limiting — 100 requests per minute per IP
  rule {
    action   = "throttle"
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

      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }

      enforce_on_key = "IP"
    }

    description = "Rate limit: 100 req/min per IP"
  }

  # OWASP Top 10 — SQL injection
  rule {
    action   = "deny(403)"
    priority = 2000

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }

    description = "Block SQL injection attempts (OWASP)"
  }

  # OWASP Top 10 — XSS
  rule {
    action   = "deny(403)"
    priority = 2100

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }

    description = "Block XSS attempts (OWASP)"
  }

  # OWASP Top 10 — Remote code execution
  rule {
    action   = "deny(403)"
    priority = 2200

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rce-v33-stable')"
      }
    }

    description = "Block RCE attempts (OWASP)"
  }

  # OWASP Top 10 — Local file inclusion
  rule {
    action   = "deny(403)"
    priority = 2300

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('lfi-v33-stable')"
      }
    }

    description = "Block LFI attempts (OWASP)"
  }

  # OWASP Top 10 — Remote file inclusion
  rule {
    action   = "deny(403)"
    priority = 2400

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rfi-v33-stable')"
      }
    }

    description = "Block RFI attempts (OWASP)"
  }

  # OWASP Top 10 — Scanner detection
  rule {
    action   = "deny(403)"
    priority = 2500

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('scannerdetection-v33-stable')"
      }
    }

    description = "Block scanner/crawler probes (OWASP)"
  }

  # OWASP Top 10 — Protocol attack
  rule {
    action   = "deny(403)"
    priority = 2600

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('protocolattack-v33-stable')"
      }
    }

    description = "Block protocol attacks (OWASP)"
  }

  # OWASP Top 10 — Session fixation
  rule {
    action   = "deny(403)"
    priority = 2700

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sessionfixation-v33-stable')"
      }
    }

    description = "Block session fixation attacks (OWASP)"
  }

  # Geo-blocking — deny high-risk countries
  rule {
    action   = "deny(403)"
    priority = 3000

    match {
      expr {
        expression = "origin.region_code == 'KP' || origin.region_code == 'IR' || origin.region_code == 'SY' || origin.region_code == 'CU'"
      }
    }

    description = "Geo-block sanctioned countries (OFAC)"
  }

  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
    }
  }
}

# Backend service for Admin API (placeholder — actual NEGs created by GKE ingress)
resource "google_compute_health_check" "admin_api" {
  name                = "milnet-sso-admin-health"
  project             = var.project_id
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3
  description         = "Health check for Admin API service"

  http_health_check {
    port         = 8080
    request_path = "/health"
  }
}

# Internal TCP Load Balancer for Gateway (port 9100)
resource "google_compute_address" "gateway_ilb" {
  name         = "milnet-sso-gateway-ilb-ip"
  project      = var.project_id
  region       = var.region
  subnetwork   = google_compute_subnetwork.gke_subnet.id
  address_type = "INTERNAL"
  purpose      = "GCE_ENDPOINT"
  description  = "Internal static IP for Gateway TCP load balancer"
}

resource "google_compute_health_check" "gateway" {
  name                = "milnet-sso-gateway-health"
  project             = var.project_id
  check_interval_sec  = 5
  timeout_sec         = 3
  healthy_threshold   = 2
  unhealthy_threshold = 3
  description         = "Health check for Gateway gRPC service"

  tcp_health_check {
    port = 9100
  }
}

resource "google_compute_region_backend_service" "gateway_ilb" {
  name                  = "milnet-sso-gateway-ilb-backend"
  project               = var.project_id
  region                = var.region
  protocol              = "TCP"
  load_balancing_scheme = "INTERNAL"
  health_checks         = [google_compute_health_check.gateway.id]
  description           = "Internal TCP LB backend for Gateway service"
}

resource "google_compute_forwarding_rule" "gateway_ilb" {
  name                  = "milnet-sso-gateway-ilb"
  project               = var.project_id
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  backend_service       = google_compute_region_backend_service.gateway_ilb.id
  ip_address            = google_compute_address.gateway_ilb.id
  ip_protocol           = "TCP"
  ports                 = ["9100"]
  network               = google_compute_network.vpc.id
  subnetwork            = google_compute_subnetwork.gke_subnet.id
  description           = "Internal forwarding rule for Gateway gRPC on port 9100"

  labels = local.labels
}

###############################################################################
# Observability — Logging, Monitoring, Alerting
###############################################################################

# Log sink to BigQuery for long-term audit storage
resource "google_logging_project_sink" "audit_sink" {
  name                   = "milnet-sso-audit-sink"
  project                = var.project_id
  destination            = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  filter                 = "resource.type=\"k8s_container\" AND resource.labels.namespace_name=\"milnet-sso\""
  unique_writer_identity = true
  description            = "Export SSO namespace logs to Cloud Storage for audit retention"
}

resource "google_storage_bucket" "audit_logs" {
  name                        = "${var.project_id}-milnet-sso-audit-logs"
  project                     = var.project_id
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  force_destroy               = false

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
    condition {
      age = 30
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
    condition {
      age = 90
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
    condition {
      age = 365
    }
  }

  versioning {
    enabled = true
  }

  labels = local.labels
}

resource "google_storage_bucket_iam_member" "audit_sink_writer" {
  bucket = google_storage_bucket.audit_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.audit_sink.writer_identity
}

# Uptime checks
resource "google_monitoring_uptime_check_config" "admin_api" {
  display_name = "MilNet SSO Admin API Health"
  project      = var.project_id
  timeout      = "10s"
  period       = "60s"

  http_check {
    path         = "/health"
    port         = 443
    use_ssl      = true
    validate_ssl = true
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = var.domain
    }
  }
}

# Notification channel (email — update with actual recipients)
resource "google_monitoring_notification_channel" "email" {
  display_name = "MilNet SSO Ops Team"
  project      = var.project_id
  type         = "email"

  labels = {
    email_address = "sso-ops@${replace(var.domain, "sso.", "")}"
  }
}

# Alert: High error rate on Admin API
resource "google_monitoring_alert_policy" "high_error_rate" {
  display_name = "MilNet SSO: High Error Rate (>5%)"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "HTTP 5xx error rate exceeds 5%"

    condition_threshold {
      filter          = "resource.type = \"k8s_container\" AND resource.labels.namespace_name = \"milnet-sso\" AND metric.type = \"logging.googleapis.com/user/http_5xx_count\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.05
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.name]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "The SSO system HTTP 5xx error rate has exceeded 5% for 5 minutes. Check GKE workloads in the milnet-sso namespace for failing pods and review application logs."
    mime_type = "text/markdown"
  }
}

# Alert: High latency on authentication
resource "google_monitoring_alert_policy" "high_latency" {
  display_name = "MilNet SSO: High Auth Latency (>2s p99)"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Authentication p99 latency exceeds 2 seconds"

    condition_threshold {
      filter          = "resource.type = \"k8s_container\" AND resource.labels.namespace_name = \"milnet-sso\" AND metric.type = \"logging.googleapis.com/user/auth_latency_p99\""
      comparison      = "COMPARISON_GT"
      threshold_value = 2000
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_PERCENTILE_99"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.name]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "Authentication p99 latency has exceeded 2 seconds for 5 minutes. Investigate the orchestrator and OPAQUE service pods. Check Cloud SQL and Redis connectivity."
    mime_type = "text/markdown"
  }
}

# Alert: GKE node pool approaching capacity
resource "google_monitoring_alert_policy" "node_pool_capacity" {
  display_name = "MilNet SSO: Node Pool CPU >80%"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "GKE node CPU utilization exceeds 80%"

    condition_threshold {
      filter          = "resource.type = \"k8s_node\" AND resource.labels.cluster_name = \"${local.cluster_name}\" AND metric.type = \"kubernetes.io/node/cpu/allocatable_utilization\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8
      duration        = "600s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.name]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "GKE node CPU utilization has exceeded 80% for 10 minutes. The cluster autoscaler should be adding nodes. If this persists, review node pool max limits and consider increasing them."
    mime_type = "text/markdown"
  }
}

# Alert: Cloud SQL connections approaching limit
resource "google_monitoring_alert_policy" "db_connections" {
  display_name = "MilNet SSO: DB Connections >80%"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Cloud SQL connections exceed 80% of max"

    condition_threshold {
      filter          = "resource.type = \"cloudsql_database\" AND resource.labels.database_id = \"${var.project_id}:${google_sql_database_instance.primary.name}\" AND metric.type = \"cloudsql.googleapis.com/database/postgresql/num_backends\""
      comparison      = "COMPARISON_GT"
      threshold_value = 400
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.name]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "Cloud SQL active connections have exceeded 400 (80% of max_connections=500). Review connection pooling settings in the application and consider scaling the database tier."
    mime_type = "text/markdown"
  }
}

###############################################################################
# Artifact Registry — Docker Repository
###############################################################################

resource "google_artifact_registry_repository" "sso" {
  repository_id = "milnet-sso"
  project       = var.project_id
  location      = var.region
  format        = "DOCKER"
  description   = "Container images for MilNet SSO system"
  mode          = "STANDARD_REPOSITORY"

  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"

    most_recent_versions {
      keep_count = 10
    }
  }

  cleanup_policies {
    id     = "delete-old-untagged"
    action = "DELETE"

    condition {
      tag_state  = "UNTAGGED"
      older_than = "604800s" # 7 days
    }
  }

  docker_config {
    immutable_tags = true
  }

  labels = local.labels

  depends_on = [google_project_service.apis]
}

###############################################################################
# Cloud Build — CI/CD Trigger
###############################################################################

resource "google_cloudbuild_trigger" "main" {
  name        = "milnet-sso-build-deploy"
  project     = var.project_id
  location    = var.region
  description = "Build and deploy MilNet SSO on push to main branch"

  github {
    owner = "divyamohan1993"
    name  = "enterprise-sso-system"

    push {
      branch = "^master$"
    }
  }

  service_account = google_service_account.cloud_build.id

  build {
    step {
      name = "gcr.io/cloud-builders/docker"
      args = [
        "build",
        "-t", "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/gateway:$COMMIT_SHA",
        "-f", "gateway/Dockerfile",
        ".",
      ]
    }

    step {
      name = "gcr.io/cloud-builders/docker"
      args = [
        "build",
        "-t", "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/orchestrator:$COMMIT_SHA",
        "-f", "orchestrator/Dockerfile",
        ".",
      ]
    }

    step {
      name = "gcr.io/cloud-builders/docker"
      args = [
        "build",
        "-t", "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/admin:$COMMIT_SHA",
        "-f", "admin/Dockerfile",
        ".",
      ]
    }

    step {
      name = "gcr.io/cloud-builders/docker"
      args = [
        "build",
        "-t", "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/verifier:$COMMIT_SHA",
        "-f", "verifier/Dockerfile",
        ".",
      ]
    }

    step {
      name = "gcr.io/cloud-builders/docker"
      args = [
        "build",
        "-t", "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/audit:$COMMIT_SHA",
        "-f", "audit/Dockerfile",
        ".",
      ]
    }

    step {
      name = "gcr.io/cloud-builders/docker"
      args = [
        "build",
        "-t", "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/risk:$COMMIT_SHA",
        "-f", "risk/Dockerfile",
        ".",
      ]
    }

    step {
      name = "gcr.io/cloud-builders/docker"
      args = [
        "build",
        "-t", "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/shard:$COMMIT_SHA",
        "-f", "shard/Dockerfile",
        ".",
      ]
    }

    images = [
      "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/gateway:$COMMIT_SHA",
      "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/orchestrator:$COMMIT_SHA",
      "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/admin:$COMMIT_SHA",
      "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/verifier:$COMMIT_SHA",
      "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/audit:$COMMIT_SHA",
      "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/risk:$COMMIT_SHA",
      "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso/shard:$COMMIT_SHA",
    ]

    options {
      machine_type = "E2_HIGHCPU_8"
    }

    timeout = "1800s"
  }

  depends_on = [
    google_project_service.apis,
    google_artifact_registry_repository.sso,
  ]
}

###############################################################################
# Binary Authorization Policy
###############################################################################

resource "google_binary_authorization_policy" "policy" {
  project = var.project_id

  default_admission_rule {
    evaluation_mode  = "ALWAYS_DENY"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
  }

  cluster_admission_rules {
    cluster                 = "${var.region}.${local.cluster_name}"
    evaluation_mode         = "REQUIRE_ATTESTATION"
    enforcement_mode        = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = [google_binary_authorization_attestor.build_attestor.name]
  }

  global_policy_evaluation_mode = "ENABLE"

  depends_on = [google_project_service.apis]
}

resource "google_binary_authorization_attestor" "build_attestor" {
  name    = "milnet-sso-build-attestor"
  project = var.project_id

  attestation_authority_note {
    note_reference = google_container_analysis_note.build_note.name
  }
}

resource "google_container_analysis_note" "build_note" {
  name    = "milnet-sso-build-note"
  project = var.project_id

  attestation_authority {
    hint {
      human_readable_name = "MilNet SSO Build Verification"
    }
  }
}
