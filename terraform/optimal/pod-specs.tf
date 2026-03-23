# ============================================================================
# MILNET SSO — Kubernetes Resources (GKE Autopilot)
# ============================================================================
# All 10 services as single-replica Deployments.
# Autopilot bills per-pod — minimal resource requests keep costs low.
# Services communicate via ClusterIP (no internal LB needed).
# ============================================================================

# ── Namespace ────────────────────────────────────────────────────────────────

resource "kubernetes_namespace" "milnet_sso" {
  metadata {
    name = "milnet-sso"

    labels = {
      app                                    = "milnet-sso"
      environment                            = var.environment
      "pod-security.kubernetes.io/enforce"    = "restricted"
      "pod-security.kubernetes.io/audit"      = "restricted"
      "pod-security.kubernetes.io/warn"       = "restricted"
    }
  }

  depends_on = [google_container_cluster.autopilot]
}

# ── Kubernetes Service Account (Workload Identity) ───────────────────────────

resource "kubernetes_service_account" "milnet_sso" {
  metadata {
    name      = "milnet-sso"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    annotations = {
      "iam.gke.io/gcp-service-account" = google_service_account.sso_workload.email
    }
  }
}

# ── ConfigMap — Shared Configuration ─────────────────────────────────────────

resource "kubernetes_config_map" "sso_config" {
  metadata {
    name      = "sso-config"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  data = {
    RUST_LOG              = "info"
    ENVIRONMENT           = var.environment
    ADMIN_PORT            = "8080"
    GATEWAY_PORT          = "8443"
    ORCHESTRATOR_PORT     = "9000"
    OPAQUE_PORT           = "9001"
    TSS_PORT              = "9002"
    VERIFIER_PORT         = "9003"
    RATCHET_PORT          = "9004"
    RISK_PORT             = "9005"
    KT_PORT               = "9006"
    AUDIT_PORT            = "9007"
    DB_HOST               = google_sql_database_instance.postgres.private_ip_address
    DB_PORT               = "5432"
    DB_NAME               = var.db_name
    DB_USER               = var.db_user
    KMS_KEY_RING          = google_kms_key_ring.sso.id
    KMS_SIGNING_KEY       = google_kms_crypto_key.token_signing.id
    KMS_ENCRYPTION_KEY    = google_kms_crypto_key.data_encryption.id
    KMS_TSS_KEY           = google_kms_crypto_key.tss_shares.id
    AUDIT_BFT_REPLICAS    = tostring(var.audit_bft_replicas)
    # Service discovery via ClusterIP DNS
    ORCHESTRATOR_URL      = "http://orchestrator.milnet-sso.svc.cluster.local:9000"
    OPAQUE_URL            = "http://opaque.milnet-sso.svc.cluster.local:9001"
    TSS_URL               = "http://tss.milnet-sso.svc.cluster.local:9002"
    VERIFIER_URL          = "http://verifier.milnet-sso.svc.cluster.local:9003"
    RATCHET_URL           = "http://ratchet.milnet-sso.svc.cluster.local:9004"
    RISK_URL              = "http://risk.milnet-sso.svc.cluster.local:9005"
    KT_URL                = "http://kt.milnet-sso.svc.cluster.local:9006"
    AUDIT_URL             = "http://audit.milnet-sso.svc.cluster.local:9007"
  }
}

# ── Secret — Database URL ────────────────────────────────────────────────────

resource "kubernetes_secret" "db_credentials" {
  metadata {
    name      = "db-credentials"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  data = {
    DATABASE_URL = "postgres://${var.db_user}:${var.db_password}@${google_sql_database_instance.postgres.private_ip_address}:5432/${var.db_name}"
    DB_PASSWORD  = var.db_password
  }

  type = "Opaque"
}

# ============================================================================
# Service Deployment Template (locals for DRY)
# ============================================================================

locals {
  # Service definitions: name => {port, cpu, memory, replicas, command}
  services = {
    gateway = {
      port     = 8443
      cpu      = "250m"
      memory   = "256Mi"
      replicas = 1
      command  = ["/usr/local/bin/gateway"]
    }
    admin = {
      port     = 8080
      cpu      = "500m"
      memory   = "512Mi"
      replicas = 1
      command  = ["/usr/local/bin/admin"]
    }
    orchestrator = {
      port     = 9000
      cpu      = "500m"
      memory   = "512Mi"
      replicas = 1
      command  = ["/usr/local/bin/orchestrator"]
    }
    opaque = {
      port     = 9001
      cpu      = "1000m"
      memory   = "512Mi"
      replicas = 1
      command  = ["/usr/local/bin/opaque"]
    }
    tss = {
      port     = 9002
      cpu      = "1000m"
      memory   = "512Mi"
      replicas = 1
      command  = ["/usr/local/bin/tss"]
    }
    verifier = {
      port     = 9003
      cpu      = "250m"
      memory   = "256Mi"
      replicas = 1
      command  = ["/usr/local/bin/verifier"]
    }
    ratchet = {
      port     = 9004
      cpu      = "250m"
      memory   = "256Mi"
      replicas = 1
      command  = ["/usr/local/bin/ratchet"]
    }
    risk = {
      port     = 9005
      cpu      = "250m"
      memory   = "256Mi"
      replicas = 1
      command  = ["/usr/local/bin/risk"]
    }
    kt = {
      port     = 9006
      cpu      = "250m"
      memory   = "256Mi"
      replicas = 1
      command  = ["/usr/local/bin/kt"]
    }
  }
}

# ============================================================================
# Deployments — All Non-Audit Services (single replica each)
# ============================================================================

resource "kubernetes_deployment" "services" {
  for_each = local.services

  metadata {
    name      = each.key
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      app       = each.key
      component = "milnet-sso"
    }
  }

  spec {
    replicas = each.value.replicas

    selector {
      match_labels = {
        app = each.key
      }
    }

    template {
      metadata {
        labels = {
          app       = each.key
          component = "milnet-sso"
        }
      }

      spec {
        service_account_name            = kubernetes_service_account.milnet_sso.metadata[0].name
        automount_service_account_token = true

        security_context {
          run_as_non_root = true
          run_as_user     = 65534
          run_as_group    = 65534
          fs_group        = 65534

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name    = each.key
          image   = "${local.ar_repo}/sso:${local.image_tag}"
          command = each.value.command

          port {
            container_port = each.value.port
            protocol       = "TCP"
          }

          env_from {
            config_map_ref {
              name = kubernetes_config_map.sso_config.metadata[0].name
            }
          }

          env {
            name = "DATABASE_URL"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.db_credentials.metadata[0].name
                key  = "DATABASE_URL"
              }
            }
          }

          resources {
            requests = {
              cpu               = each.value.cpu
              memory            = each.value.memory
              "ephemeral-storage" = "100Mi"
            }
            limits = {
              cpu               = each.value.cpu == "1000m" ? "2000m" : "1000m"
              memory            = each.value.memory == "512Mi" ? "1Gi" : "512Mi"
              "ephemeral-storage" = "500Mi"
            }
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            run_as_non_root            = true
            run_as_user                = 65534

            capabilities {
              drop = ["ALL"]
            }

            seccomp_profile {
              type = "RuntimeDefault"
            }
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = each.value.port
            }
            initial_delay_seconds = 15
            period_seconds        = 30
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = each.value.port
            }
            initial_delay_seconds = 5
            period_seconds        = 10
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }

        volume {
          name = "tmp"
          empty_dir {
            size_limit = "100Mi"
          }
        }
      }
    }
  }

  depends_on = [google_container_cluster.autopilot]
}

# ============================================================================
# Audit BFT — 3 replicas (f=1 tolerance), cost-optimized from 7
# ============================================================================

resource "kubernetes_deployment" "audit" {
  metadata {
    name      = "audit"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      app       = "audit"
      component = "milnet-sso"
    }
  }

  spec {
    replicas = var.audit_bft_replicas

    selector {
      match_labels = {
        app = "audit"
      }
    }

    template {
      metadata {
        labels = {
          app       = "audit"
          component = "milnet-sso"
        }
      }

      spec {
        service_account_name            = kubernetes_service_account.milnet_sso.metadata[0].name
        automount_service_account_token = true

        security_context {
          run_as_non_root = true
          run_as_user     = 65534
          run_as_group    = 65534
          fs_group        = 65534

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        # Anti-affinity: spread audit pods across nodes for BFT
        affinity {
          pod_anti_affinity {
            preferred_during_scheduling_ignored_during_execution {
              weight = 100

              pod_affinity_term {
                label_selector {
                  match_labels = {
                    app = "audit"
                  }
                }
                topology_key = "kubernetes.io/hostname"
              }
            }
          }
        }

        container {
          name    = "audit"
          image   = "${local.ar_repo}/sso:${local.image_tag}"
          command = ["/usr/local/bin/audit"]

          port {
            container_port = 9007
            protocol       = "TCP"
          }

          env_from {
            config_map_ref {
              name = kubernetes_config_map.sso_config.metadata[0].name
            }
          }

          env {
            name = "DATABASE_URL"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.db_credentials.metadata[0].name
                key  = "DATABASE_URL"
              }
            }
          }

          env {
            name  = "AUDIT_NODE_ID"
            value_from {
              field_ref {
                field_path = "metadata.name"
              }
            }
          }

          resources {
            requests = {
              cpu               = "250m"
              memory            = "256Mi"
              "ephemeral-storage" = "100Mi"
            }
            limits = {
              cpu               = "1000m"
              memory            = "512Mi"
              "ephemeral-storage" = "500Mi"
            }
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            run_as_non_root            = true
            run_as_user                = 65534

            capabilities {
              drop = ["ALL"]
            }

            seccomp_profile {
              type = "RuntimeDefault"
            }
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 9007
            }
            initial_delay_seconds = 15
            period_seconds        = 30
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 9007
            }
            initial_delay_seconds = 5
            period_seconds        = 10
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }

          volume_mount {
            name       = "audit-data"
            mount_path = "/data/audit"
          }
        }

        volume {
          name = "tmp"
          empty_dir {
            size_limit = "100Mi"
          }
        }

        volume {
          name = "audit-data"
          empty_dir {
            size_limit = "1Gi"
          }
        }
      }
    }
  }

  depends_on = [google_container_cluster.autopilot]
}

# ============================================================================
# ClusterIP Services — Internal communication
# ============================================================================

resource "kubernetes_service" "services" {
  for_each = merge(local.services, {
    audit = {
      port     = 9007
      cpu      = "250m"
      memory   = "256Mi"
      replicas = var.audit_bft_replicas
      command  = ["/usr/local/bin/audit"]
    }
  })

  metadata {
    name      = each.key
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      app       = each.key
      component = "milnet-sso"
    }
  }

  spec {
    selector = {
      app = each.key
    }

    port {
      name        = "http"
      port        = each.value.port
      target_port = each.value.port
      protocol    = "TCP"
    }

    type = "ClusterIP"
  }
}

# ============================================================================
# Ingress — Admin API exposed via GKE Ingress (creates GCLB automatically)
# ============================================================================

resource "kubernetes_ingress_v1" "admin" {
  metadata {
    name      = "admin-ingress"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    annotations = {
      "kubernetes.io/ingress.class"                 = "gce"
      "kubernetes.io/ingress.global-static-ip-name" = google_compute_global_address.admin_lb.name
      "networking.gke.io/managed-certificates"      = "admin-cert"
      "networking.gke.io/v1beta1.FrontendConfig"    = "admin-frontend-config"
    }
  }

  spec {
    default_backend {
      service {
        name = "admin"

        port {
          number = 8080
        }
      }
    }

    rule {
      host = var.domain

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = "admin"

              port {
                number = 8080
              }
            }
          }
        }

        path {
          path      = "/api/"
          path_type = "Prefix"

          backend {
            service {
              name = "admin"

              port {
                number = 8080
              }
            }
          }
        }
      }
    }
  }

  depends_on = [kubernetes_service.services]
}

# GKE Managed Certificate resource
resource "kubernetes_manifest" "managed_cert" {
  manifest = {
    apiVersion = "networking.gke.io/v1"
    kind       = "ManagedCertificate"

    metadata = {
      name      = "admin-cert"
      namespace = "milnet-sso"
    }

    spec = {
      domains = [var.domain]
    }
  }

  depends_on = [kubernetes_namespace.milnet_sso]
}

# Frontend config to attach Cloud Armor policy and enforce HTTPS
resource "kubernetes_manifest" "frontend_config" {
  manifest = {
    apiVersion = "networking.gke.io/v1beta1"
    kind       = "FrontendConfig"

    metadata = {
      name      = "admin-frontend-config"
      namespace = "milnet-sso"
    }

    spec = {
      sslPolicy = ""
      redirectToHttps = {
        enabled          = true
        responseCodeName = "MOVED_PERMANENTLY_DEFAULT"
      }
    }
  }

  depends_on = [kubernetes_namespace.milnet_sso]
}

# ============================================================================
# Network Policies — Deny All + Allow Specific
# ============================================================================

# Default deny all ingress and egress
resource "kubernetes_network_policy" "deny_all" {
  metadata {
    name      = "deny-all"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {}

    policy_types = ["Ingress", "Egress"]
  }
}

# Allow DNS resolution (kube-dns)
resource "kubernetes_network_policy" "allow_dns" {
  metadata {
    name      = "allow-dns"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {}

    policy_types = ["Egress"]

    egress {
      ports {
        port     = "53"
        protocol = "UDP"
      }
      ports {
        port     = "53"
        protocol = "TCP"
      }
    }
  }
}

# Gateway: accept external ingress, talk to orchestrator
resource "kubernetes_network_policy" "gateway" {
  metadata {
    name      = "allow-gateway"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        app = "gateway"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      ports {
        port     = "8443"
        protocol = "TCP"
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            app = "orchestrator"
          }
        }
      }
      ports {
        port     = "9000"
        protocol = "TCP"
      }
    }
  }
}

# Admin: accept external ingress (from LB), talk to DB and all internal services
resource "kubernetes_network_policy" "admin" {
  metadata {
    name      = "allow-admin"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        app = "admin"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      ports {
        port     = "8080"
        protocol = "TCP"
      }
    }

    # Allow egress to all services in namespace + DB
    egress {
      to {
        pod_selector {}
      }
    }

    egress {
      ports {
        port     = "5432"
        protocol = "TCP"
      }
    }

    # Allow egress to Google APIs (KMS, Secret Manager)
    egress {
      ports {
        port     = "443"
        protocol = "TCP"
      }
    }
  }
}

# Orchestrator: accept from gateway/admin, talk to all crypto services
resource "kubernetes_network_policy" "orchestrator" {
  metadata {
    name      = "allow-orchestrator"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        app = "orchestrator"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "gateway"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "admin"
          }
        }
      }

      ports {
        port     = "9000"
        protocol = "TCP"
      }
    }

    egress {
      to {
        pod_selector {}
      }
    }

    egress {
      ports {
        port     = "5432"
        protocol = "TCP"
      }
    }

    egress {
      ports {
        port     = "443"
        protocol = "TCP"
      }
    }
  }
}

# Crypto services (OPAQUE, TSS, Verifier, Ratchet, Risk, KT): accept from orchestrator only
resource "kubernetes_network_policy" "crypto_services" {
  for_each = toset(["opaque", "tss", "verifier", "ratchet", "risk", "kt"])

  metadata {
    name      = "allow-${each.key}"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        app = each.key
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "orchestrator"
          }
        }
      }

      ports {
        port     = tostring(local.services[each.key].port)
        protocol = "TCP"
      }
    }

    # Allow egress to DB
    egress {
      ports {
        port     = "5432"
        protocol = "TCP"
      }
    }

    # Allow egress to Google APIs (KMS)
    egress {
      ports {
        port     = "443"
        protocol = "TCP"
      }
    }

    # Allow egress to audit
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "audit"
          }
        }
      }
      ports {
        port     = "9007"
        protocol = "TCP"
      }
    }
  }
}

# Audit: accept from all services in namespace, talk to DB
resource "kubernetes_network_policy" "audit" {
  metadata {
    name      = "allow-audit"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        app = "audit"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            component = "milnet-sso"
          }
        }
      }

      ports {
        port     = "9007"
        protocol = "TCP"
      }
    }

    # Audit BFT peer communication
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "audit"
          }
        }
      }
      ports {
        port     = "9007"
        protocol = "TCP"
      }
    }

    # DB access
    egress {
      ports {
        port     = "5432"
        protocol = "TCP"
      }
    }

    # Google APIs (Logging, KMS)
    egress {
      ports {
        port     = "443"
        protocol = "TCP"
      }
    }
  }
}
