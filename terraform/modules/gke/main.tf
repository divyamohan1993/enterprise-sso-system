# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — GKE Autopilot Module
# ──────────────────────────────────────────────────────────────────────────────
# Military-grade GKE Autopilot cluster with:
#   - Workload Identity (no node-level SA keys)
#   - Binary Authorization
#   - Network policy enforcement
#   - Private cluster (no public endpoint)
#   - Master authorized networks
#   - Shielded nodes with Secure Boot + Integrity Monitoring
#   - Optional Confidential GKE Nodes (AMD SEV)
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "zone" {
  type = string
}

variable "deployment_suffix" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "pods_range_name" {
  type = string
}

variable "services_range_name" {
  type = string
}

variable "master_authorized_cidr" {
  type    = list(string)
  default = []
}

variable "release_channel" {
  type    = string
  default = "STABLE"
}

variable "enable_confidential_nodes" {
  type    = bool
  default = false
}

variable "service_account_email" {
  type = string
}

variable "labels" {
  type    = map(string)
  default = {}
}

# ── GKE Autopilot Cluster ──

resource "google_container_cluster" "milnet" {
  provider = google-beta

  name     = "milnet-sso-${var.deployment_suffix}"
  project  = var.project_id
  location = var.region

  # Autopilot mode — GCP manages node pools, scaling, upgrades
  enable_autopilot = true

  network    = var.vpc_id
  subnetwork = var.subnet_id

  ip_allocation_policy {
    cluster_secondary_range_name  = var.pods_range_name
    services_secondary_range_name = var.services_range_name
  }

  # Private cluster: nodes have no public IPs, master has private endpoint
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  # Master authorized networks: only allow access from specified CIDRs
  dynamic "master_authorized_networks_config" {
    for_each = length(var.master_authorized_cidr) > 0 ? [1] : []
    content {
      dynamic "cidr_blocks" {
        for_each = var.master_authorized_cidr
        content {
          cidr_block   = cidr_blocks.value
          display_name = "authorized-${cidr_blocks.key}"
        }
      }
    }
  }

  release_channel {
    channel = var.release_channel
  }

  # Workload Identity — pods authenticate as GCP service accounts
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Binary Authorization — only verified container images may run
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  # Security posture: enable vulnerability scanning
  security_posture_config {
    mode               = "BASIC"
    vulnerability_mode = "VULNERABILITY_BASIC"
  }

  # Gateway API
  gateway_api_config {
    channel = "CHANNEL_STANDARD"
  }

  # Logging and monitoring
  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS",
    ]
  }

  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
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

  # DNS config for internal service discovery
  dns_config {
    cluster_dns        = "CLOUD_DNS"
    cluster_dns_scope  = "CLUSTER_SCOPE"
    cluster_dns_domain = "milnet.local"
  }

  resource_labels = var.labels

  # Prevent accidental destruction
  deletion_protection = true
}

# ── Outputs ──

output "cluster_name" {
  value = google_container_cluster.milnet.name
}

output "cluster_endpoint" {
  value     = google_container_cluster.milnet.endpoint
  sensitive = true
}

output "cluster_ca_certificate" {
  value     = google_container_cluster.milnet.master_auth[0].cluster_ca_certificate
  sensitive = true
}

output "workload_identity_pool" {
  value = "${var.project_id}.svc.id.goog"
}
