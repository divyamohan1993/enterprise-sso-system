# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — GCP India GCS Module
# ──────────────────────────────────────────────────────────────────────────────
# GCS buckets with India dual-region (IN) for data residency.
# CMEK encryption, versioning, and lifecycle rules.
#
# Buckets:
#   audit-logs  — immutable audit log storage (WORM-style)
#   backups     — encrypted database and config backups
#   artifacts   — binary/container artifacts for deployment
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" { type = string }
variable "environment" { type = string }
variable "kms_key_id" {
  description = "KMS crypto key ID for CMEK encryption"
  type        = string
}

locals {
  name_prefix = "milnet-india-${var.environment}"
  # IN = India dual-region (Mumbai + Delhi). Data never leaves India.
  location    = "IN"
}

# ── Audit Logs Bucket ──
# Immutable audit trail. Object versioning + locked retention policy.

resource "google_storage_bucket" "audit_logs" {
  name          = "${local.name_prefix}-audit-logs"
  project       = var.project_id
  location      = local.location  # IN = India dual-region
  storage_class = "STANDARD"

  # CMEK encryption — HSM-backed key
  encryption {
    default_kms_key_name = var.kms_key_id
  }

  versioning {
    enabled = true
  }

  # Retention policy: audit logs must be kept for 7 years (2555 days)
  retention_policy {
    is_locked        = var.environment == "production"
    retention_period = 220752000  # 7 years in seconds
  }

  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = 1095
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }

  labels = {
    environment    = var.environment
    data_residency = "india"
    data_type      = "audit-logs"
    managed_by     = "terraform"
  }
}

# ── Backup Bucket ──
# Database and configuration backups.

resource "google_storage_bucket" "backups" {
  name          = "${local.name_prefix}-backups"
  project       = var.project_id
  location      = local.location  # IN = India dual-region
  storage_class = "STANDARD"

  encryption {
    default_kms_key_name = var.kms_key_id
  }

  versioning {
    enabled = true
  }

  uniform_bucket_level_access = true

  # Transition to Nearline after 30 days
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  # Delete backups after 365 days
  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type = "Delete"
    }
  }

  # Delete non-current versions after 90 days
  lifecycle_rule {
    condition {
      num_newer_versions = 3
      age                = 90
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    environment    = var.environment
    data_residency = "india"
    data_type      = "backups"
    managed_by     = "terraform"
  }
}

# ── Artifacts Bucket ──
# Binary and deployment artifacts.

resource "google_storage_bucket" "artifacts" {
  name          = "${local.name_prefix}-artifacts"
  project       = var.project_id
  location      = local.location  # IN = India dual-region
  storage_class = "STANDARD"

  encryption {
    default_kms_key_name = var.kms_key_id
  }

  versioning {
    enabled = true
  }

  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 180
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  labels = {
    environment    = var.environment
    data_residency = "india"
    data_type      = "artifacts"
    managed_by     = "terraform"
  }
}

# ── Block Public Access ──

resource "google_storage_bucket_iam_binding" "audit_deny_public" {
  bucket = google_storage_bucket.audit_logs.name
  role   = "roles/storage.objectViewer"
  members = []  # Explicitly empty — no public read access
}

# ── Outputs ──

output "audit_bucket_name" {
  value = google_storage_bucket.audit_logs.name
}

output "audit_bucket_url" {
  value = google_storage_bucket.audit_logs.url
}

output "backup_bucket_name" {
  value = google_storage_bucket.backups.name
}

output "artifacts_bucket_name" {
  value = google_storage_bucket.artifacts.name
}
