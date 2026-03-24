###############################################################################
# MILNET SSO — GKE Workloads (Namespace, Network Policies, Quotas)
# Enforces zero-trust pod-to-pod communication matrix
###############################################################################

###############################################################################
# Namespace — Pod Security Standards: Restricted
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
  }

  depends_on = [
    google_container_cluster.primary,
    google_container_node_pool.general,
    google_container_node_pool.compute,
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
# Network Policies — Zero-Trust Module Communication Matrix
#
# QUANTUM-SAFE ENFORCEMENT:
# All inter-pod traffic uses SHARD protocol which provides:
#   1. HMAC-SHA512 message authentication (quantum-resistant MAC)
#   2. AES-256-GCM payload encryption (quantum-resistant symmetric)
#   3. mTLS 1.3 transport (X25519 + ML-KEM-1024 via X-Wing at app layer)
#   4. Monotonic sequence counters (replay protection)
#   5. ±2s timestamp validation (freshness)
#
# Network policies are defense-in-depth — even if an attacker bypasses
# Calico, SHARD authentication rejects unauthorized senders (C11).
###############################################################################

# Default deny all — explicit allow required for every connection
resource "kubernetes_network_policy" "default_deny" {
  metadata {
    name      = "default-deny-all"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

# DNS resolution for all pods
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

# All pods → audit (every module sends audit events)
resource "kubernetes_network_policy" "allow_audit_egress" {
  metadata {
    name      = "allow-audit-egress"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
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
        port     = 9108
        protocol = "TCP"
      }
    }
  }
}

# Gateway: LB ingress → orchestrator only
resource "kubernetes_network_policy" "gateway" {
  metadata {
    name      = "gateway-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "gateway"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      ports {
        port     = 9100
        protocol = "TCP"
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "orchestrator"
          }
        }
      }
      ports {
        port     = 9101
        protocol = "TCP"
      }
    }
  }
}

# Orchestrator: gateway → opaque, tss, risk, ratchet, kt
resource "kubernetes_network_policy" "orchestrator" {
  metadata {
    name      = "orchestrator-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "orchestrator"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "gateway"
          }
        }
      }
      ports {
        port     = 9101
        protocol = "TCP"
      }
    }

    # OPAQUE
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "opaque"
          }
        }
      }
      ports {
        port     = 9102
        protocol = "TCP"
      }
    }

    # TSS
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "tss"
          }
        }
      }
      ports {
        port     = 9103
        protocol = "TCP"
      }
    }

    # Risk
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "risk"
          }
        }
      }
      ports {
        port     = 9106
        protocol = "TCP"
      }
    }

    # Ratchet
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "ratchet"
          }
        }
      }
      ports {
        port     = 9105
        protocol = "TCP"
      }
    }

    # KT
    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "kt"
          }
        }
      }
      ports {
        port     = 9107
        protocol = "TCP"
      }
    }
  }
}

# OPAQUE: orchestrator only → Cloud SQL
resource "kubernetes_network_policy" "opaque" {
  metadata {
    name      = "opaque-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "opaque"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "orchestrator"
          }
        }
      }
      ports {
        port     = 9102
        protocol = "TCP"
      }
    }

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

# TSS: orchestrator + verifier → peer signers
resource "kubernetes_network_policy" "tss" {
  metadata {
    name      = "tss-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "tss"
      }
    }

    policy_types = ["Ingress", "Egress"]

    # From orchestrator
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "orchestrator"
          }
        }
      }
      ports {
        port     = 9103
        protocol = "TCP"
      }
    }

    # From verifier
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "verifier"
          }
        }
      }
      ports {
        port     = 9103
        protocol = "TCP"
      }
    }

    # Peer-to-peer FROST signing
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "tss"
          }
        }
      }
      ports {
        port     = 9103
        protocol = "TCP"
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "tss"
          }
        }
      }
      ports {
        port     = 9103
        protocol = "TCP"
      }
    }
  }
}

# Verifier: external verification → ratchet, tss
resource "kubernetes_network_policy" "verifier" {
  metadata {
    name      = "verifier-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "verifier"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      ports {
        port     = 9104
        protocol = "TCP"
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "ratchet"
          }
        }
      }
      ports {
        port     = 9105
        protocol = "TCP"
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "tss"
          }
        }
      }
      ports {
        port     = 9103
        protocol = "TCP"
      }
    }
  }
}

# Risk: orchestrator only → Redis
resource "kubernetes_network_policy" "risk" {
  metadata {
    name      = "risk-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "risk"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "orchestrator"
          }
        }
      }
      ports {
        port     = 9106
        protocol = "TCP"
      }
    }

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

# Ratchet: orchestrator + verifier
resource "kubernetes_network_policy" "ratchet" {
  metadata {
    name      = "ratchet-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "ratchet"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "orchestrator"
          }
        }
      }
      ports {
        port     = 9105
        protocol = "TCP"
      }
    }

    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "verifier"
          }
        }
      }
      ports {
        port     = 9105
        protocol = "TCP"
      }
    }
  }
}

# KT: orchestrator → Cloud SQL
resource "kubernetes_network_policy" "kt" {
  metadata {
    name      = "kt-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "kt"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "orchestrator"
          }
        }
      }
      ports {
        port     = 9107
        protocol = "TCP"
      }
    }

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

# Admin: external HTTPS → Cloud SQL + Redis
resource "kubernetes_network_policy" "admin" {
  metadata {
    name      = "admin-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "admin"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      ports {
        port     = 8080
        protocol = "TCP"
      }
    }

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

# Audit: all SSO pods → Cloud SQL
resource "kubernetes_network_policy" "audit" {
  metadata {
    name      = "audit-policy"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "audit"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/part-of" = "milnet-sso"
          }
        }
      }
      ports {
        port     = 9108
        protocol = "TCP"
      }
    }

    # Peer BFT replication
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "audit"
          }
        }
      }
      ports {
        port     = 9108
        protocol = "TCP"
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "audit"
          }
        }
      }
      ports {
        port     = 9108
        protocol = "TCP"
      }
    }

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

###############################################################################
# Resource Quotas — Prevent runaway resource consumption
###############################################################################

resource "kubernetes_resource_quota" "milnet_sso" {
  metadata {
    name      = "milnet-sso-quota"
    namespace = kubernetes_namespace.milnet_sso.metadata[0].name
  }

  spec {
    hard = {
      "requests.cpu"           = "80"
      "requests.memory"        = "160Gi"
      "limits.cpu"             = "120"
      "limits.memory"          = "256Gi"
      "pods"                   = "200"
      "services"               = "30"
      "secrets"                = "50"
      "configmaps"             = "50"
      "persistentvolumeclaims" = "20"
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
        cpu    = "4"
        memory = "8Gi"
      }

      min = {
        cpu    = "50m"
        memory = "64Mi"
      }
    }
  }
}
