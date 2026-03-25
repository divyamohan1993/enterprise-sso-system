# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — Cloud Monitoring Module
# ──────────────────────────────────────────────────────────────────────────────
# Creates:
#   - Alert policies for critical security events
#   - Uptime checks for the SSO gateway
#   - Cloud Monitoring dashboards
#   - Log-based metrics for security forensics
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" {
  type = string
}

variable "deployment_suffix" {
  type = string
}

variable "alert_notification_channels" {
  type    = list(string)
  default = []
}

variable "uptime_check_host" {
  type    = string
  default = ""
}

variable "labels" {
  type    = map(string)
  default = {}
}

# ── Log-Based Metrics ──

resource "google_logging_metric" "auth_failures" {
  name    = "milnet-auth-failures-${var.deployment_suffix}"
  project = var.project_id
  filter  = "jsonPayload.severity=\"MEDIUM\" AND jsonPayload.source_module=\"authentication\" AND jsonPayload.details.outcome=\"failure\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "MILNET SSO Authentication Failures"
  }
}

resource "google_logging_metric" "duress_detections" {
  name    = "milnet-duress-detections-${var.deployment_suffix}"
  project = var.project_id
  filter  = "jsonPayload.event_type=\"duress\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "MILNET SSO Duress Detections"
  }
}

resource "google_logging_metric" "tamper_detections" {
  name    = "milnet-tamper-detections-${var.deployment_suffix}"
  project = var.project_id
  filter  = "jsonPayload.event_type=\"tamper_detected\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "MILNET SSO Tamper Detections"
  }
}

resource "google_logging_metric" "entropy_failures" {
  name    = "milnet-entropy-failures-${var.deployment_suffix}"
  project = var.project_id
  filter  = "jsonPayload.event_type=\"entropy_quality_failure\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "MILNET SSO Entropy Quality Failures"
  }
}

resource "google_logging_metric" "certificate_errors" {
  name    = "milnet-certificate-errors-${var.deployment_suffix}"
  project = var.project_id
  filter  = "jsonPayload.event_type=\"certificate_validation_failed\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "MILNET SSO Certificate Validation Errors"
  }
}

# ── Alert Policies ──

resource "google_monitoring_alert_policy" "auth_failure_spike" {
  display_name = "MILNET SSO: Auth Failures > 10/min"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Auth failure rate exceeds threshold"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/milnet-auth-failures-${var.deployment_suffix}\" AND resource.type=\"k8s_container\""
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      duration        = "60s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = var.alert_notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "Authentication failures exceeded 10/min. Check for brute force attacks. Runbook: https://milnet-docs/runbook/auth-failure-spike"
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

resource "google_monitoring_alert_policy" "duress_alert" {
  display_name = "MILNET SSO: Duress Detection [CRITICAL]"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Duress signal detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/milnet-duress-detections-${var.deployment_suffix}\" AND resource.type=\"k8s_container\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = var.alert_notification_channels

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content   = "CRITICAL: Duress PIN activated. A user may be under coercion. Immediate response required. Runbook: https://milnet-docs/runbook/duress-response"
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

resource "google_monitoring_alert_policy" "tamper_alert" {
  display_name = "MILNET SSO: Tamper Detection [CRITICAL]"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Tamper signal detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/milnet-tamper-detections-${var.deployment_suffix}\" AND resource.type=\"k8s_container\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = var.alert_notification_channels

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content   = "CRITICAL: Tamper detection triggered. System integrity may be compromised. Runbook: https://milnet-docs/runbook/tamper-response"
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

resource "google_monitoring_alert_policy" "entropy_failure_alert" {
  display_name = "MILNET SSO: Entropy Quality Failure [CRITICAL]"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Entropy quality check failed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/milnet-entropy-failures-${var.deployment_suffix}\" AND resource.type=\"k8s_container\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = var.alert_notification_channels

  documentation {
    content   = "CRITICAL: Entropy source failure. Cryptographic operations may be weakened. Runbook: https://milnet-docs/runbook/entropy-failure"
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

resource "google_monitoring_alert_policy" "cert_error_alert" {
  display_name = "MILNET SSO: Certificate Validation Errors"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Certificate validation failures"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/milnet-certificate-errors-${var.deployment_suffix}\" AND resource.type=\"k8s_container\""
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = var.alert_notification_channels

  documentation {
    content   = "Certificate validation errors exceeding threshold. Possible mTLS misconfiguration or MITM attempt. Runbook: https://milnet-docs/runbook/cert-errors"
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

# ── Uptime Check ──

resource "google_monitoring_uptime_check_config" "gateway" {
  count = var.uptime_check_host != "" ? 1 : 0

  display_name = "MILNET SSO Gateway Health"
  project      = var.project_id
  timeout      = "10s"
  period       = "60s"

  http_check {
    path         = "/healthz"
    port         = 443
    use_ssl      = true
    validate_ssl = true
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = var.uptime_check_host
    }
  }
}

# ── Log Sink to BigQuery for Forensics ──

resource "google_bigquery_dataset" "security_logs" {
  dataset_id  = "milnet_security_logs_${var.deployment_suffix}"
  project     = var.project_id
  location    = "asia-south1"
  description = "MILNET SSO security event logs for forensic analysis"

  default_table_expiration_ms = 31536000000 # 365 days

  labels = var.labels
}

resource "google_logging_project_sink" "security_to_bq" {
  name        = "milnet-security-bq-${var.deployment_suffix}"
  project     = var.project_id
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.security_logs.dataset_id}"

  filter = "jsonPayload.source_module=~\"authentication|authorization|integrity|key_management|session|availability|access_control|configuration\""

  unique_writer_identity = true

  bigquery_options {
    use_partitioned_tables = true
  }
}

# Grant the log sink writer access to the BigQuery dataset
resource "google_bigquery_dataset_iam_member" "log_writer" {
  dataset_id = google_bigquery_dataset.security_logs.dataset_id
  project    = var.project_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.security_to_bq.writer_identity
}

# ── Dashboard ──

resource "google_monitoring_dashboard" "milnet_overview" {
  project = var.project_id
  dashboard_json = jsonencode({
    displayName = "MILNET SSO Security Overview"
    mosaicLayout = {
      tiles = [
        {
          width  = 6
          height = 4
          widget = {
            title = "Authentication Failures (1h)"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"logging.googleapis.com/user/milnet-auth-failures-${var.deployment_suffix}\""
                    aggregation = {
                      alignmentPeriod  = "60s"
                      perSeriesAligner = "ALIGN_RATE"
                    }
                  }
                }
              }]
            }
          }
        },
        {
          xPos   = 6
          width  = 6
          height = 4
          widget = {
            title = "Duress & Tamper Events"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"logging.googleapis.com/user/milnet-duress-detections-${var.deployment_suffix}\""
                      aggregation = {
                        alignmentPeriod  = "60s"
                        perSeriesAligner = "ALIGN_COUNT"
                      }
                    }
                  }
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"logging.googleapis.com/user/milnet-tamper-detections-${var.deployment_suffix}\""
                      aggregation = {
                        alignmentPeriod  = "60s"
                        perSeriesAligner = "ALIGN_COUNT"
                      }
                    }
                  }
                },
              ]
            }
          }
        },
        {
          yPos   = 4
          width  = 6
          height = 4
          widget = {
            title = "Entropy & Certificate Errors"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"logging.googleapis.com/user/milnet-entropy-failures-${var.deployment_suffix}\""
                      aggregation = {
                        alignmentPeriod  = "60s"
                        perSeriesAligner = "ALIGN_COUNT"
                      }
                    }
                  }
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"logging.googleapis.com/user/milnet-certificate-errors-${var.deployment_suffix}\""
                      aggregation = {
                        alignmentPeriod  = "60s"
                        perSeriesAligner = "ALIGN_COUNT"
                      }
                    }
                  }
                },
              ]
            }
          }
        },
      ]
    }
  })
}
