# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — Cloud KMS Module
# ──────────────────────────────────────────────────────────────────────────────
# Manages the KMS keyring and crypto keys for:
#   - Master KEK (Key Encryption Key) with automatic 90-day rotation
#   - Database encryption key (CMEK for Cloud SQL)
#   - Envelope encryption key for Secret Manager payloads
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "deployment_suffix" {
  type = string
}

variable "rotation_period" {
  description = "Automatic key rotation period (e.g. 7776000s = 90 days)"
  type        = string
  default     = "7776000s"
}

variable "protection_level" {
  description = "HSM or SOFTWARE"
  type        = string
  default     = "HSM"
}

variable "labels" {
  type    = map(string)
  default = {}
}

# ── Keyring ──

resource "google_kms_key_ring" "milnet" {
  name     = "milnet-sso-keyring-${var.deployment_suffix}"
  location = var.region
  project  = var.project_id
}

# ── Master KEK ──
# Used for envelope encryption of all sensitive data at rest.  Rotated every
# 90 days automatically.  HSM-backed by default (CNSA 2.0 compliance).

resource "google_kms_crypto_key" "master_kek" {
  name            = "milnet-master-kek-${var.deployment_suffix}"
  key_ring        = google_kms_key_ring.milnet.id
  rotation_period = var.rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.protection_level
  }

  labels = var.labels

  lifecycle {
    prevent_destroy = true
  }
}

# ── Database Encryption Key (CMEK for Cloud SQL) ──

resource "google_kms_crypto_key" "db_encryption" {
  name            = "milnet-db-cmek-${var.deployment_suffix}"
  key_ring        = google_kms_key_ring.milnet.id
  rotation_period = var.rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.protection_level
  }

  labels = var.labels

  lifecycle {
    prevent_destroy = true
  }
}

# ── Signing Key (for audit log integrity) ──

resource "google_kms_crypto_key" "audit_signing" {
  name     = "milnet-audit-sign-${var.deployment_suffix}"
  key_ring = google_kms_key_ring.milnet.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P384_SHA384"
    protection_level = var.protection_level
  }

  labels = var.labels

  lifecycle {
    prevent_destroy = true
  }
}

# ── IAM: Allow Cloud SQL service agent to use the DB CMEK ──

data "google_project" "current" {
  project_id = var.project_id
}

resource "google_kms_crypto_key_iam_member" "cloudsql_cmek" {
  crypto_key_id = google_kms_crypto_key.db_encryption.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloud-sql.iam.gserviceaccount.com"
}

# ── Outputs ──

output "keyring_id" {
  value = google_kms_key_ring.milnet.id
}

output "keyring_name" {
  value = google_kms_key_ring.milnet.name
}

output "master_kek_crypto_key_id" {
  value = google_kms_crypto_key.master_kek.id
}

output "db_encryption_key_id" {
  value = google_kms_crypto_key.db_encryption.id
}

output "audit_signing_key_id" {
  value = google_kms_crypto_key.audit_signing.id
}
