# ============================================================================
# MILNET SSO — Cloud Run Services (Simulated Prod for Dev/Test)
# ============================================================================
# Deploys all microservices to Cloud Run with scale-to-zero (spot-like cost).
# Cloud Run does not have a "spot" mode but scale-to-zero with min_instances=0
# achieves the same cost goal — you pay nothing when idle.
# ============================================================================

locals {
  ar_repo   = "${var.region}-docker.pkg.dev/${var.project_id}/milnet-sso-${local.name_suffix}"
  image_tag = var.container_image_tag

  # Service definitions: name -> port
  services = {
    gateway      = { port = 8080, cpu = "1", memory = "512Mi", env = {} }
    orchestrator = { port = 8081, cpu = "1", memory = "512Mi", env = {} }
    opaque       = { port = 8082, cpu = "1", memory = "256Mi", env = {} }
    verifier     = { port = 8084, cpu = "1", memory = "256Mi", env = {} }
    admin        = { port = 8085, cpu = "1", memory = "512Mi", env = {} }
  }
}

# ============================================================================
# Artifact Registry
# ============================================================================

resource "google_artifact_registry_repository" "milnet_sso" {
  location      = var.region
  repository_id = "milnet-sso-${local.name_suffix}"
  format        = "DOCKER"
  project       = var.project_id

  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"
    most_recent_versions {
      keep_count = 3
    }
  }

  depends_on = [google_project_service.apis]

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# Cloud KMS — Master Key Encryption Key
# ============================================================================

resource "google_kms_key_ring" "milnet_sso" {
  name     = "milnet-sso-keyring-${local.name_suffix}"
  location = var.region
  project  = var.project_id

  depends_on = [google_project_service.apis]

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_kms_crypto_key" "master_kek" {
  name     = "master-kek"
  key_ring = google_kms_key_ring.milnet_sso.id
  purpose  = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  rotation_period = "7776000s" # 90 days

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_kms_crypto_key" "signing_key" {
  name     = "token-signing-key"
  key_ring = google_kms_key_ring.milnet_sso.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# Secret Manager — Service Secrets
# ============================================================================

resource "google_secret_manager_secret" "db_password" {
  secret_id = "milnet-db-password-${local.name_suffix}"
  project   = var.project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = local.db_password

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_secret_manager_secret" "hmac_key" {
  secret_id = "milnet-hmac-key-${local.name_suffix}"
  project   = var.project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]

  lifecycle {
    create_before_destroy = false
  }
}

resource "random_password" "hmac_key" {
  length  = 64
  special = false

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_secret_manager_secret_version" "hmac_key" {
  secret      = google_secret_manager_secret.hmac_key.id
  secret_data = random_password.hmac_key.result

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# Cloud Run Service Account
# ============================================================================

resource "google_service_account" "cloud_run" {
  account_id   = "milnet-run-${local.name_suffix}"
  display_name = "MILNET SSO Cloud Run Service Account"
  project      = var.project_id

  depends_on = [google_project_service.apis]

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_project_iam_member" "cloud_run_roles" {
  for_each = toset([
    "roles/cloudsql.client",
    "roles/secretmanager.secretAccessor",
    "roles/cloudkms.cryptoKeyEncrypterDecrypter",
    "roles/cloudkms.signerVerifier",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.cloud_run.email}"

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# Cloud Run — Standard Services (gateway, orchestrator, opaque, verifier, admin)
# ============================================================================

resource "google_cloud_run_v2_service" "services" {
  for_each = local.services

  name     = "milnet-${each.key}-${local.name_suffix}"
  location = var.region
  project  = var.project_id

  ingress = each.key == "gateway" ? "INGRESS_TRAFFIC_ALL" : "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    scaling {
      min_instance_count = var.cloud_run_min_instances
      max_instance_count = var.cloud_run_max_instances
    }

    vpc_access {
      connector = google_vpc_access_connector.connector.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    service_account = google_service_account.cloud_run.email

    containers {
      image = "${local.ar_repo}/${each.key}:${local.image_tag}"

      ports {
        container_port = each.value.port
      }

      resources {
        limits = {
          cpu    = each.value.cpu
          memory = each.value.memory
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      env {
        name  = "RUST_LOG"
        value = var.log_level == "verbose" ? "debug" : "error"
      }

      env {
        name  = "SERVICE_NAME"
        value = each.key
      }

      env {
        name  = "DB_HOST"
        value = google_sql_database_instance.test_db.private_ip_address
      }

      env {
        name  = "DB_NAME"
        value = "milnet_sso"
      }

      env {
        name  = "DB_USER"
        value = "milnet"
      }

      env {
        name = "DB_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.db_password.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "KMS_KEY_RING"
        value = google_kms_key_ring.milnet_sso.name
      }

      env {
        name  = "KMS_MASTER_KEK"
        value = google_kms_crypto_key.master_kek.name
      }

      env {
        name  = "GATEWAY_URL"
        value = "milnet-gateway-${local.name_suffix}"
      }

      env {
        name  = "ORCHESTRATOR_URL"
        value = "milnet-orchestrator-${local.name_suffix}"
      }

      startup_probe {
        http_get {
          path = "/health"
          port = each.value.port
        }
        initial_delay_seconds = 5
        period_seconds        = 10
        failure_threshold     = 3
        timeout_seconds       = 5
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = each.value.port
        }
        period_seconds    = 30
        failure_threshold = 3
        timeout_seconds   = 5
      }
    }

    labels = local.labels
  }

  depends_on = [
    google_project_service.apis,
    google_artifact_registry_repository.milnet_sso,
    google_sql_database_instance.test_db,
    google_project_iam_member.cloud_run_roles,
  ]

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# Cloud Run — TSS Services (multiple replicas for threshold signing)
# ============================================================================

resource "google_cloud_run_v2_service" "tss" {
  count = var.tss_replica_count

  name     = "milnet-tss-${count.index}-${local.name_suffix}"
  location = var.region
  project  = var.project_id

  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    scaling {
      min_instance_count = var.cloud_run_min_instances
      max_instance_count = 1
    }

    vpc_access {
      connector = google_vpc_access_connector.connector.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    service_account = google_service_account.cloud_run.email

    containers {
      image = "${local.ar_repo}/tss:${local.image_tag}"

      ports {
        container_port = 8083
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      env {
        name  = "RUST_LOG"
        value = var.log_level == "verbose" ? "debug" : "error"
      }

      env {
        name  = "SERVICE_NAME"
        value = "tss"
      }

      env {
        name  = "TSS_NODE_ID"
        value = tostring(count.index)
      }

      env {
        name  = "TSS_TOTAL_NODES"
        value = tostring(var.tss_replica_count)
      }

      env {
        name  = "TSS_THRESHOLD"
        value = tostring(floor(var.tss_replica_count / 2) + 1)
      }

      env {
        name  = "DB_HOST"
        value = google_sql_database_instance.test_db.private_ip_address
      }

      env {
        name  = "DB_NAME"
        value = "milnet_sso"
      }

      env {
        name  = "DB_USER"
        value = "milnet"
      }

      env {
        name = "DB_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.db_password.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "KMS_KEY_RING"
        value = google_kms_key_ring.milnet_sso.name
      }

      env {
        name  = "ORCHESTRATOR_URL"
        value = "milnet-orchestrator-${local.name_suffix}"
      }

      startup_probe {
        http_get {
          path = "/health"
          port = 8083
        }
        initial_delay_seconds = 5
        period_seconds        = 10
        failure_threshold     = 3
        timeout_seconds       = 5
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = 8083
        }
        period_seconds    = 30
        failure_threshold = 3
        timeout_seconds   = 5
      }
    }

    labels = merge(local.labels, {
      tss-node-id = tostring(count.index)
    })
  }

  depends_on = [
    google_project_service.apis,
    google_artifact_registry_repository.milnet_sso,
    google_sql_database_instance.test_db,
    google_project_iam_member.cloud_run_roles,
  ]

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# Internal Load Balancer (Serverless NEG for Cloud Run)
# ============================================================================

resource "google_compute_region_network_endpoint_group" "gateway_neg" {
  name                  = "milnet-gateway-neg-${local.name_suffix}"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = google_cloud_run_v2_service.services["gateway"].name
  }

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_compute_region_backend_service" "gateway_backend" {
  name                  = "milnet-gateway-backend-${local.name_suffix}"
  region                = var.region
  protocol              = "HTTP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  timeout_sec           = 30

  backend {
    group          = google_compute_region_network_endpoint_group.gateway_neg.id
    balancing_mode = "UTILIZATION"
  }

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_compute_region_url_map" "gateway_urlmap" {
  name            = "milnet-gateway-urlmap-${local.name_suffix}"
  region          = var.region
  default_service = google_compute_region_backend_service.gateway_backend.id

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_compute_region_target_http_proxy" "gateway_proxy" {
  name    = "milnet-gateway-proxy-${local.name_suffix}"
  region  = var.region
  url_map = google_compute_region_url_map.gateway_urlmap.id

  lifecycle {
    create_before_destroy = false
  }
}

resource "google_compute_forwarding_rule" "gateway_ilb" {
  name                  = "milnet-gateway-ilb-${local.name_suffix}"
  region                = var.region
  load_balancing_scheme = "INTERNAL_MANAGED"
  target                = google_compute_region_target_http_proxy.gateway_proxy.id
  port_range            = "80"
  network               = google_compute_network.test_vpc.id
  subnetwork            = google_compute_subnetwork.test_subnet.id
  ip_protocol           = "TCP"

  depends_on = [google_compute_subnetwork.ilb_proxy_subnet]

  lifecycle {
    create_before_destroy = false
  }
}

# Proxy-only subnet required for internal HTTP(S) load balancer
resource "google_compute_subnetwork" "ilb_proxy_subnet" {
  name          = "milnet-ilb-proxy-${local.name_suffix}"
  ip_cidr_range = "10.10.2.0/24"
  region        = var.region
  network       = google_compute_network.test_vpc.id
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"

  lifecycle {
    create_before_destroy = false
  }
}

# ============================================================================
# IAM — Allow unauthenticated access to gateway (dev/test only)
# ============================================================================

resource "google_cloud_run_v2_service_iam_member" "gateway_public" {
  count = var.developer_mode ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.services["gateway"].name
  role     = "roles/run.invoker"
  member   = "allUsers"

  lifecycle {
    create_before_destroy = false
  }
}
