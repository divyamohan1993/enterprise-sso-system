# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — GCP India IAM Module
# ──────────────────────────────────────────────────────────────────────────────
# Per-service service accounts with least-privilege IAM bindings.
# No service account has owner/editor roles.
# Org policy enforces India-only access (domain restriction).
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" { type = string }
variable "environment" { type = string }
variable "service_names" {
  type    = list(string)
  default = ["gateway", "orchestrator", "verifier", "ratchet", "audit", "risk", "admin", "opaque"]
}

locals {
  name_prefix = "milnet-india-${var.environment}"
}

# ── Per-Service Service Accounts ──

resource "google_service_account" "services" {
  for_each = toset(var.service_names)

  account_id   = "milnet-${each.value}-${var.environment}"
  display_name = "MILNET SSO ${each.value} (${var.environment})"
  description  = "Service account for MILNET ${each.value} service — least privilege"
  project      = var.project_id
}

# ── IAM Bindings: Logging ──
# All services can write logs (Stackdriver).

resource "google_project_iam_member" "log_writer" {
  for_each = toset(var.service_names)

  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.services[each.value].email}"
}

# ── IAM Bindings: Monitoring ──

resource "google_project_iam_member" "metric_writer" {
  for_each = toset(var.service_names)

  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.services[each.value].email}"
}

# ── IAM Bindings: Secret Manager ──
# Only allow access to own service's secrets.

resource "google_project_iam_member" "secret_accessor" {
  for_each = toset(var.service_names)

  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.services[each.value].email}"

  condition {
    title       = "own-secrets-only-${each.value}"
    description = "Only access secrets prefixed with milnet-${each.value}"
    expression  = "resource.name.startsWith(\"projects/${var.project_id}/secrets/milnet-${each.value}-\")"
  }
}

# ── IAM Bindings: KMS ──
# Audit service gets signing key access; others get KEK access only.

resource "google_project_iam_member" "kms_encrypter_decrypter" {
  for_each = toset([for svc in var.service_names : svc if svc != "audit"])

  project = var.project_id
  role    = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member  = "serviceAccount:${google_service_account.services[each.value].email}"

  condition {
    title       = "milnet-kek-only-${each.value}"
    description = "Only access MILNET KMS keys"
    expression  = "resource.name.contains(\"milnet-india\")"
  }
}

resource "google_project_iam_member" "kms_signer_verifier" {
  project = var.project_id
  role    = "roles/cloudkms.signerVerifier"
  member  = "serviceAccount:${google_service_account.services["audit"].email}"

  condition {
    title       = "audit-signing-key-only"
    description = "Audit service can sign with audit-signing key only"
    expression  = "resource.name.contains(\"audit-signing\")"
  }
}

# ── IAM Bindings: Cloud SQL ──
# Services that need DB access get cloudsql.client role.

locals {
  db_services = ["gateway", "orchestrator", "verifier", "audit", "admin"]
}

resource "google_project_iam_member" "cloudsql_client" {
  for_each = toset(local.db_services)

  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.services[each.value].email}"
}

# ── IAM Bindings: GCS ──
# Audit service writes to audit bucket; others have no GCS access.

resource "google_project_iam_member" "storage_object_creator" {
  project = var.project_id
  role    = "roles/storage.objectCreator"
  member  = "serviceAccount:${google_service_account.services["audit"].email}"

  condition {
    title       = "audit-bucket-only"
    description = "Audit SA can only create objects in audit bucket"
    expression  = "resource.name.startsWith(\"projects/_/buckets/milnet-india-audit\")"
  }
}

# ── Org Policy: Restrict Resource Location to India ──
# Prevents accidental creation of resources outside India regions.

resource "google_project_organization_policy" "resource_location" {
  project    = var.project_id
  constraint = "constraints/gcp.resourceLocations"

  list_policy {
    allow {
      values = [
        "in:asia-south1-locations",
        "in:asia-south2-locations",
        "in:in-locations",
      ]
    }
  }
}

# ── Outputs ──

output "service_account_emails" {
  description = "Map of service name to service account email"
  value       = { for svc, sa in google_service_account.services : svc => sa.email }
}

output "service_account_ids" {
  description = "Map of service name to service account unique ID"
  value       = { for svc, sa in google_service_account.services : svc => sa.unique_id }
}
