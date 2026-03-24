###############################################################################
# GKE Workloads — Kubernetes Resources via Terraform
# Namespace, Network Policies, Resource Quotas, Pod Security
###############################################################################

###############################################################################
# Namespace
###############################################################################

resource "kubernetes_namespace" "milnet_sso" {
  metadata {
    name = "milnet-sso"

    labels = {
      "app.kubernetes.io/part-of"          = "milnet-sso"
      "app.kubernetes.io/managed-by"       = "terraform"
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }

    annotations = {
      "meta.helm.sh/release-namespace" = "milnet-sso"
    }
  }

  depends_on = [
    google_container_cluster.primary,
    google_container_node_pool.general,
    google_container_node_pool.compute_heavy,
    google_container_node_pool.confidential,
    google_container_node_pool.stateful,
  ]
}

###############################################################################
# Kubernetes Service Account — Workload Identity
###############################################################################

resource "kubernetes_service_account" "workload" {
  metadata {
    name      = "milnet-sso-workload"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
    }

    annotations = {
      "iam.gke.io/gcp-service-account" = google_service_account.gke_workload.email
    }
  }
}

###############################################################################
# Network Policies — Module Communication Matrix
###############################################################################

# Default deny all ingress and egress in the namespace
resource "kubernetes_network_policy" "default_deny" {
  metadata {
    name      = "default-deny-all"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "default-deny"
    }
  }

  spec {
    pod_selector {}

    policy_types = ["Ingress", "Egress"]
  }
}

# Allow DNS resolution for all pods (required for service discovery)
resource "kubernetes_network_policy" "allow_dns" {
  metadata {
    name      = "allow-dns"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "allow-dns"
    }
  }

  spec {
    pod_selector {}

    policy_types = ["Egress"]

    egress {
      ports {
        port     = 53
        protocol = "UDP"
      }
      ports {
        port     = 53
        protocol = "TCP"
      }
    }
  }
}

# Gateway: accepts external ingress, can only talk to orchestrator
resource "kubernetes_network_policy" "gateway" {
  metadata {
    name      = "gateway-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "gateway"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "gateway"
      }
    }

    policy_types = ["Ingress", "Egress"]

    # Accept traffic from load balancer / external
    ingress {
      ports {
        port     = 9100
        protocol = "TCP"
      }
    }

    # Can only send to orchestrator
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "orchestrator"
          }
        }
      }

      ports {
        port     = 9200
        protocol = "TCP"
      }
    }
  }
}

# Orchestrator: receives from gateway, can talk to opaque, tss, risk, ratchet
resource "kubernetes_network_policy" "orchestrator" {
  metadata {
    name      = "orchestrator-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "orchestrator"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "orchestrator"
      }
    }

    policy_types = ["Ingress", "Egress"]

    # Accept from gateway
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "gateway"
          }
        }
      }

      ports {
        port     = 9200
        protocol = "TCP"
      }
    }

    # Can talk to opaque
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "opaque"
          }
        }
      }

      ports {
        port     = 9300
        protocol = "TCP"
      }
    }

    # Can talk to tss-coordinator
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "tss-coordinator"
          }
        }
      }

      ports {
        port     = 9400
        protocol = "TCP"
      }
    }

    # Can talk to risk
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "risk"
          }
        }
      }

      ports {
        port     = 9500
        protocol = "TCP"
      }
    }

    # Can talk to ratchet (key transport)
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "ratchet"
          }
        }
      }

      ports {
        port     = 9600
        protocol = "TCP"
      }
    }
  }
}

# TSS Coordinator: receives from orchestrator, can talk to tss-signers
resource "kubernetes_network_policy" "tss_coordinator" {
  metadata {
    name      = "tss-coordinator-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "tss-coordinator"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "tss-coordinator"
      }
    }

    policy_types = ["Ingress", "Egress"]

    # Accept from orchestrator
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "orchestrator"
          }
        }
      }

      ports {
        port     = 9400
        protocol = "TCP"
      }
    }

    # Accept from verifier
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "verifier"
          }
        }
      }

      ports {
        port     = 9400
        protocol = "TCP"
      }
    }

    # Can talk to tss-signers
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "tss-signer"
          }
        }
      }

      ports {
        port     = 9401
        protocol = "TCP"
      }
    }
  }
}

# TSS Signers: receive from coordinator and each other
resource "kubernetes_network_policy" "tss_signer" {
  metadata {
    name      = "tss-signer-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "tss-signer"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "tss-signer"
      }
    }

    policy_types = ["Ingress", "Egress"]

    # Accept from tss-coordinator
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "tss-coordinator"
          }
        }
      }

      ports {
        port     = 9401
        protocol = "TCP"
      }
    }

    # Accept from other tss-signers (peer-to-peer for threshold protocol)
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "tss-signer"
          }
        }
      }

      ports {
        port     = 9401
        protocol = "TCP"
      }
    }

    # Can talk to other tss-signers
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "tss-signer"
          }
        }
      }

      ports {
        port     = 9401
        protocol = "TCP"
      }
    }

    # Can talk to tss-coordinator
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "tss-coordinator"
          }
        }
      }

      ports {
        port     = 9400
        protocol = "TCP"
      }
    }
  }
}

# OPAQUE: receives from orchestrator only
resource "kubernetes_network_policy" "opaque" {
  metadata {
    name      = "opaque-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "opaque"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "opaque"
      }
    }

    policy_types = ["Ingress", "Egress"]

    # Accept from orchestrator
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "orchestrator"
          }
        }
      }

      ports {
        port     = 9300
        protocol = "TCP"
      }
    }

    # Egress to Cloud SQL (database)
    egress {
      to {
        ip_block {
          cidr = "10.1.0.0/24"
        }
      }

      ports {
        port     = 5432
        protocol = "TCP"
      }
    }
  }
}

# Risk Engine: receives from orchestrator only
resource "kubernetes_network_policy" "risk" {
  metadata {
    name      = "risk-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "risk"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "risk"
      }
    }

    policy_types = ["Ingress", "Egress"]

    # Accept from orchestrator
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "orchestrator"
          }
        }
      }

      ports {
        port     = 9500
        protocol = "TCP"
      }
    }

    # Egress to Redis (token cache / risk data)
    egress {
      to {
        ip_block {
          cidr = "10.1.0.0/24"
        }
      }

      ports {
        port     = 6379
        protocol = "TCP"
      }
    }
  }
}

# Ratchet (Key Transport): receives from orchestrator and verifier
resource "kubernetes_network_policy" "ratchet" {
  metadata {
    name      = "ratchet-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "ratchet"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "ratchet"
      }
    }

    policy_types = ["Ingress", "Egress"]

    # Accept from orchestrator
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "orchestrator"
          }
        }
      }

      ports {
        port     = 9600
        protocol = "TCP"
      }
    }

    # Accept from verifier
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "verifier"
          }
        }
      }

      ports {
        port     = 9600
        protocol = "TCP"
      }
    }
  }
}

# Verifier: receives external verification requests, talks to ratchet and tss
resource "kubernetes_network_policy" "verifier" {
  metadata {
    name      = "verifier-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "verifier"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "verifier"
      }
    }

    policy_types = ["Ingress", "Egress"]

    # Accept external verification requests
    ingress {
      ports {
        port     = 9700
        protocol = "TCP"
      }
    }

    # Can talk to ratchet
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "ratchet"
          }
        }
      }

      ports {
        port     = 9600
        protocol = "TCP"
      }
    }

    # Can talk to tss-coordinator
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "tss-coordinator"
          }
        }
      }

      ports {
        port     = 9400
        protocol = "TCP"
      }
    }
  }
}

# Admin API: accepts external HTTPS, talks to database
resource "kubernetes_network_policy" "admin" {
  metadata {
    name      = "admin-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "admin"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "admin"
      }
    }

    policy_types = ["Ingress", "Egress"]

    # Accept from HTTPS load balancer
    ingress {
      ports {
        port     = 8080
        protocol = "TCP"
      }
    }

    # Egress to Cloud SQL
    egress {
      to {
        ip_block {
          cidr = "10.1.0.0/24"
        }
      }

      ports {
        port     = 5432
        protocol = "TCP"
      }
    }

    # Egress to Redis
    egress {
      to {
        ip_block {
          cidr = "10.1.0.0/24"
        }
      }

      ports {
        port     = 6379
        protocol = "TCP"
      }
    }
  }
}

# Audit: receives from all services, sends to KT (ratchet)
resource "kubernetes_network_policy" "audit" {
  metadata {
    name      = "audit-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "audit"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "audit"
      }
    }

    policy_types = ["Ingress", "Egress"]

    # Accept audit events from all SSO services
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/part-of" = "milnet-sso"
          }
        }
      }

      ports {
        port     = 9800
        protocol = "TCP"
      }
    }

    # Can send to ratchet (KT — key transport for audit key rotation)
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "ratchet"
          }
        }
      }

      ports {
        port     = 9600
        protocol = "TCP"
      }
    }

    # Egress to Cloud SQL (audit persistence)
    egress {
      to {
        ip_block {
          cidr = "10.1.0.0/24"
        }
      }

      ports {
        port     = 5432
        protocol = "TCP"
      }
    }
  }
}

# Allow all pods to send audit events to audit service
resource "kubernetes_network_policy" "allow_audit_egress" {
  metadata {
    name      = "allow-audit-egress"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
      "policy"                       = "allow-audit-egress"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/part-of" = "milnet-sso"
      }
    }

    policy_types = ["Egress"]

    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "audit"
          }
        }
      }

      ports {
        port     = 9800
        protocol = "TCP"
      }
    }
  }
}

###############################################################################
# Resource Quotas
###############################################################################

resource "kubernetes_resource_quota" "milnet_sso" {
  metadata {
    name      = "milnet-sso-quota"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  spec {
    hard = {
      "requests.cpu"           = "120"
      "requests.memory"        = "256Gi"
      "limits.cpu"             = "200"
      "limits.memory"          = "512Gi"
      "pods"                   = "500"
      "services"               = "50"
      "secrets"                = "100"
      "configmaps"             = "100"
      "persistentvolumeclaims" = "50"
    }
  }
}

###############################################################################
# Limit Ranges — Pod Defaults and Caps
###############################################################################

resource "kubernetes_limit_range" "milnet_sso" {
  metadata {
    name      = "milnet-sso-limits"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of"    = "milnet-sso"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  spec {
    limit {
      type = "Container"

      default = {
        cpu    = "500m"
        memory = "512Mi"
      }

      default_request = {
        cpu    = "100m"
        memory = "128Mi"
      }

      max = {
        cpu    = "8"
        memory = "16Gi"
      }

      min = {
        cpu    = "50m"
        memory = "64Mi"
      }
    }

    limit {
      type = "Pod"

      max = {
        cpu    = "16"
        memory = "32Gi"
      }
    }
  }
}
