# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — IAM Module
# ──────────────────────────────────────────────────────────────────────────────
# Creates:
#   - Per-service GCP service accounts with minimal permissions
#   - GKE node pool service account (stripped of default SA powers)
#   - Workload Identity bindings (K8s SA -> GCP SA)
#   - KMS access for services that need encryption/decryption
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" {
  type = string
}

variable "deployment_suffix" {
  type = string
}

variable "service_names" {
  type = list(string)
}

variable "kms_keyring_id" {
  type = string
}

variable "labels" {
  type    = map(string)
  default = {}
}

locals {
  # Services that require KMS encrypt/decrypt access
  kms_services = toset(["orchestrator", "gateway", "verifier", "crypto", "opaque", "tss"])

  # Services that need Secret Manager access
  secret_services = toset(var.service_names)

  # Services that need Cloud SQL access
  db_services = toset(["gateway", "orchestrator", "verifier", "audit", "admin", "risk", "opaque", "kt"])

  # Kubernetes namespace for Workload Identity bindings
  k8s_namespace = "milnet-sso"
}

# ── GKE Node Pool Service Account ──
# Minimal permissions — no default SA, no project-wide access.

resource "google_service_account" "gke_node" {
  account_id   = "milnet-gke-node-${var.deployment_suffix}"
  display_name = "MILNET SSO GKE Node SA"
  project      = var.project_id
}

# Minimal roles for GKE node SA
resource "google_project_iam_member" "gke_node_roles" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/stackdriver.resourceMetadata.writer",
    "roles/artifactregistry.reader",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.gke_node.email}"
}

# ── Per-Service Service Accounts ──

resource "google_service_account" "services" {
  for_each = toset(var.service_names)

  account_id   = "milnet-${each.value}-${var.deployment_suffix}"
  display_name = "MILNET SSO ${each.value} service"
  project      = var.project_id
}

# ── Workload Identity Bindings ──
# Maps K8s service accounts to GCP service accounts so pods can authenticate
# to GCP services without exported keys.

resource "google_service_account_iam_member" "workload_identity" {
  for_each = toset(var.service_names)

  service_account_id = google_service_account.services[each.value].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${local.k8s_namespace}/${each.value}]"
}

# ── KMS Access (encrypt/decrypt) ──

resource "google_kms_key_ring_iam_member" "kms_access" {
  for_each = local.kms_services

  key_ring_id = var.kms_keyring_id
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member      = "serviceAccount:${google_service_account.services[each.value].email}"
}

# ── Secret Manager Access ──

resource "google_project_iam_member" "secret_accessor" {
  for_each = local.secret_services

  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.services[each.value].email}"
}

# ── Cloud SQL Client Access ──

resource "google_project_iam_member" "cloudsql_client" {
  for_each = local.db_services

  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.services[each.value].email}"
}

# ── Audit service: BigQuery write access for log analysis ──

resource "google_project_iam_member" "audit_bq_writer" {
  project = var.project_id
  role    = "roles/bigquery.dataEditor"
  member  = "serviceAccount:${google_service_account.services["audit"].email}"
}

# ── Admin service: additional monitoring access ──

resource "google_project_iam_member" "admin_monitoring" {
  project = var.project_id
  role    = "roles/monitoring.viewer"
  member  = "serviceAccount:${google_service_account.services["admin"].email}"
}

# ── Outputs ──

output "gke_node_sa_email" {
  value = google_service_account.gke_node.email
}

output "service_account_emails" {
  value = { for k, v in google_service_account.services : k => v.email }
}
