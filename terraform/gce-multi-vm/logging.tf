###############################################################################
# logging.tf — Enterprise SSO Multi-VM GCE: Log Sinks, Metrics & Audit Export
###############################################################################

# ---------- Variables ----------

variable "audit_retention_years" {
  description = "Number of years to retain audit logs in Cloud Storage"
  type        = number
  default     = 7
}

variable "log_storage_location" {
  description = "GCS bucket location for audit log archive"
  type        = string
  default     = "asia-south1"
}

###############################################################################
# Long-Term Audit Log Archive — GCS Bucket (7-year retention)
###############################################################################

resource "google_storage_bucket" "audit_archive" {
  name          = "${var.project_id}-sso-audit-archive"
  project       = var.project_id
  location      = var.log_storage_location
  storage_class = "COLDLINE"
  force_destroy = false

  uniform_bucket_level_access = true

  retention_policy {
    is_locked        = true
    retention_period = var.audit_retention_years * 365 * 24 * 3600 # 7 years in seconds
  }

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 365 # Move to archive after 1 year
    }
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
  }

  labels = merge(var.labels, {
    purpose    = "audit-archive"
    compliance = "7-year-retention"
  })
}

# Log sink: route all audit-relevant logs to GCS
resource "google_logging_project_sink" "audit_to_gcs" {
  name        = "sso-audit-to-gcs"
  project     = var.project_id
  destination = "storage.googleapis.com/${google_storage_bucket.audit_archive.name}"

  filter = <<-EOT
    resource.type="gce_instance"
    AND metadata.userLabels.system="enterprise-sso"
    AND (
      jsonPayload.event_type=~"^(authentication|authorization|key_rotation|session_|admin_action|privilege_|duress|tamper|config_change)"
      OR logName=~"projects/${var.project_id}/logs/cloudaudit.googleapis.com"
    )
  EOT

  unique_writer_identity = true
}

# Grant the log sink service account write access to the bucket
resource "google_storage_bucket_iam_member" "audit_sink_writer" {
  bucket = google_storage_bucket.audit_archive.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.audit_to_gcs.writer_identity
}

###############################################################################
# Log-Based Metrics: Security Events
###############################################################################

resource "google_logging_metric" "duress_detected" {
  name    = "sso-gce-duress-detected"
  project = var.project_id
  filter  = "resource.type=\"gce_instance\" AND jsonPayload.event_type=\"duress_detected\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "SSO GCE Duress Detections"
    labels {
      key         = "service"
      value_type  = "STRING"
      description = "Service that detected duress"
    }
  }

  label_extractors = {
    "service" = "EXTRACT(jsonPayload.source_service)"
  }
}

resource "google_logging_metric" "tamper_detected" {
  name    = "sso-gce-tamper-detected"
  project = var.project_id
  filter  = "resource.type=\"gce_instance\" AND jsonPayload.event_type=\"tamper_detected\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "SSO GCE Tamper Detections"
    labels {
      key         = "service"
      value_type  = "STRING"
      description = "Service that detected tampering"
    }
    labels {
      key         = "component"
      value_type  = "STRING"
      description = "Component affected (binary, config, key)"
    }
  }

  label_extractors = {
    "service"   = "EXTRACT(jsonPayload.source_service)"
    "component" = "EXTRACT(jsonPayload.tamper_component)"
  }
}

resource "google_logging_metric" "auth_failures_by_user" {
  name    = "sso-gce-auth-failures-by-pattern"
  project = var.project_id
  filter  = "resource.type=\"gce_instance\" AND jsonPayload.event_type=\"authentication_failure\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "SSO GCE Auth Failures by Username Pattern"
    labels {
      key         = "username_pattern"
      value_type  = "STRING"
      description = "Hashed/masked username pattern (never raw usernames)"
    }
  }

  label_extractors = {
    "username_pattern" = "EXTRACT(jsonPayload.username_hash_prefix)"
  }
}

resource "google_logging_metric" "privilege_escalation_attempt" {
  name    = "sso-gce-privilege-escalation"
  project = var.project_id
  filter  = "resource.type=\"gce_instance\" AND jsonPayload.event_type=\"privilege_escalation_attempt\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "SSO GCE Privilege Escalation Attempts"
    labels {
      key         = "target_role"
      value_type  = "STRING"
      description = "Target privilege role attempted"
    }
    labels {
      key         = "source_service"
      value_type  = "STRING"
      description = "Service where attempt originated"
    }
  }

  label_extractors = {
    "target_role"    = "EXTRACT(jsonPayload.target_role)"
    "source_service" = "EXTRACT(jsonPayload.source_service)"
  }
}

###############################################################################
# Log Exclusion Filters — Prevent Sensitive Data from Being Logged
###############################################################################

resource "google_logging_project_exclusion" "exclude_sensitive_payloads" {
  name        = "sso-exclude-sensitive-payloads"
  project     = var.project_id
  description = "Exclude log entries containing raw credentials, tokens, or key material"

  filter = <<-EOT
    resource.type="gce_instance"
    AND metadata.userLabels.system="enterprise-sso"
    AND (
      jsonPayload.password=~".+"
      OR jsonPayload.token=~".+"
      OR jsonPayload.secret=~".+"
      OR jsonPayload.private_key=~".+"
      OR jsonPayload.session_key=~".+"
      OR jsonPayload.opaque_registration=~".+"
    )
  EOT
}

resource "google_logging_project_exclusion" "exclude_healthcheck_noise" {
  name        = "sso-exclude-healthcheck-noise"
  project     = var.project_id
  description = "Exclude high-volume health check log entries to reduce cost"

  filter = <<-EOT
    resource.type="gce_instance"
    AND metadata.userLabels.system="enterprise-sso"
    AND httpRequest.requestUrl=~"^/healthz"
    AND httpRequest.status=200
  EOT
}

resource "google_logging_project_exclusion" "exclude_debug_logs" {
  name        = "sso-exclude-debug-in-prod"
  project     = var.project_id
  description = "Exclude DEBUG-level logs in production to reduce volume"

  filter = <<-EOT
    resource.type="gce_instance"
    AND metadata.userLabels.system="enterprise-sso"
    AND severity="DEBUG"
  EOT
}

###############################################################################
# Audit Log Export — BigQuery for Forensic Analysis
###############################################################################

resource "google_bigquery_dataset" "forensic_audit" {
  dataset_id  = "sso_forensic_audit"
  project     = var.project_id
  location    = var.log_storage_location
  description = "Enterprise SSO audit logs for forensic analysis and compliance reporting"

  default_table_expiration_ms     = null # Never expire — compliance requirement
  default_partition_expiration_ms = null

  access {
    role          = "OWNER"
    special_group = "projectOwners"
  }

  access {
    role          = "WRITER"
    special_group = "projectWriters"
  }

  # Restrict reader access — security-sensitive dataset
  access {
    role          = "READER"
    special_group = "projectReaders"
  }

  labels = merge(var.labels, {
    purpose    = "forensic-audit"
    compliance = "restricted"
  })
}

resource "google_logging_project_sink" "audit_to_bigquery" {
  name        = "sso-audit-to-bigquery"
  project     = var.project_id
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.forensic_audit.dataset_id}"

  filter = <<-EOT
    resource.type="gce_instance"
    AND metadata.userLabels.system="enterprise-sso"
    AND (
      jsonPayload.event_type=~"^(authentication|authorization|key_rotation|session_|admin_action|privilege_|duress|tamper|config_change|tss_signing|audit_)"
      OR logName=~"projects/${var.project_id}/logs/cloudaudit.googleapis.com"
    )
  EOT

  unique_writer_identity = true

  bigquery_options {
    use_partitioned_tables = true
  }
}

# Grant the BigQuery sink writer access
resource "google_bigquery_dataset_iam_member" "audit_bq_writer" {
  dataset_id = google_bigquery_dataset.forensic_audit.dataset_id
  project    = var.project_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.audit_to_bigquery.writer_identity
}

# Also export GCP Admin Activity audit logs
resource "google_logging_project_sink" "admin_activity_to_bigquery" {
  name        = "sso-admin-activity-to-bigquery"
  project     = var.project_id
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.forensic_audit.dataset_id}"

  filter = <<-EOT
    logName="projects/${var.project_id}/logs/cloudaudit.googleapis.com%2Factivity"
    OR logName="projects/${var.project_id}/logs/cloudaudit.googleapis.com%2Fdata_access"
  EOT

  unique_writer_identity = true

  bigquery_options {
    use_partitioned_tables = true
  }
}

resource "google_bigquery_dataset_iam_member" "admin_activity_bq_writer" {
  dataset_id = google_bigquery_dataset.forensic_audit.dataset_id
  project    = var.project_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.admin_activity_to_bigquery.writer_identity
}
