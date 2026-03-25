# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — GCP India KMS Module
# ──────────────────────────────────────────────────────────────────────────────
# Cloud KMS keyring anchored to asia-south1.
# Keys never leave India — keyring location enforces this at the API level.
#
# Keys:
#   master-kek     — symmetric ENCRYPT_DECRYPT, HSM, 90-day rotation
#   db-cmek        — symmetric ENCRYPT_DECRYPT, HSM, 90-day rotation (Cloud SQL)
#   audit-signing  — asymmetric ASYMMETRIC_SIGN, HSM, no rotation (key versioning)
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" { type = string }
variable "region" { type = string }
variable "environment" { type = string }

locals {
  name_prefix     = "milnet-india-${var.environment}"
  rotation_period = "7776000s" # 90 days in seconds
}

# ── Keyring (anchored to asia-south1) ──

resource "google_kms_key_ring" "india" {
  name     = "${local.name_prefix}-keyring"
  location = var.region  # asia-south1 — keys never leave India
  project  = var.project_id
}

# ── Master KEK ──
# Envelope encryption of all application secrets and sensitive data.

resource "google_kms_crypto_key" "master_kek" {
  name            = "${local.name_prefix}-master-kek"
  key_ring        = google_kms_key_ring.india.id
  rotation_period = local.rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ── Database CMEK (Customer-Managed Encryption Key for Cloud SQL) ──

resource "google_kms_crypto_key" "db_cmek" {
  name            = "${local.name_prefix}-db-cmek"
  key_ring        = google_kms_key_ring.india.id
  rotation_period = local.rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ── Audit Log Signing Key ──
# ECDSA P-384 for tamper-evident audit log signatures.

resource "google_kms_crypto_key" "audit_signing" {
  name     = "${local.name_prefix}-audit-signing"
  key_ring = google_kms_key_ring.india.id
  purpose  = "ASYMMETRIC_SIGN"

  # No automatic rotation — signing keys are versioned manually.
  # Previous versions are kept for signature verification.

  version_template {
    algorithm        = "EC_SIGN_P384_SHA384"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ── GCS CMEK ──

resource "google_kms_crypto_key" "gcs_cmek" {
  name            = "${local.name_prefix}-gcs-cmek"
  key_ring        = google_kms_key_ring.india.id
  rotation_period = local.rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ── IAM: Cloud SQL service agent can use db-cmek ──

data "google_project" "current" {
  project_id = var.project_id
}

resource "google_kms_crypto_key_iam_member" "cloudsql_cmek" {
  crypto_key_id = google_kms_crypto_key.db_cmek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloud-sql.iam.gserviceaccount.com"
}

resource "google_kms_crypto_key_iam_member" "gcs_cmek" {
  crypto_key_id = google_kms_crypto_key.gcs_cmek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@gs-project-accounts.iam.gserviceaccount.com"
}

# ── Outputs ──

output "keyring_id" {
  value = google_kms_key_ring.india.id
}

output "keyring_name" {
  value = google_kms_key_ring.india.name
}

output "master_kek_id" {
  value = google_kms_crypto_key.master_kek.id
}

output "db_cmek_key_id" {
  value = google_kms_crypto_key.db_cmek.id
}

output "audit_signing_key_id" {
  value = google_kms_crypto_key.audit_signing.id
}

output "gcs_cmek_key_id" {
  value = google_kms_crypto_key.gcs_cmek.id
}
