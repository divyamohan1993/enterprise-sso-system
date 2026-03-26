###############################################################################
# monitoring.tf — Enterprise SSO Multi-VM GCE: Monitoring, Alerting & Dashboard
###############################################################################

# ---------- Variables for monitoring configuration ----------

variable "alert_email" {
  description = "Email address for alert notifications"
  type        = string
  default     = "soc-alerts@enterprise-sso.internal"
}

variable "pagerduty_service_key" {
  description = "PagerDuty integration service key for incident routing"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_pagerduty" {
  description = "Enable PagerDuty notification channel"
  type        = bool
  default     = false
}

variable "gateway_lb_ip_for_uptime" {
  description = "External IP of the gateway LB for uptime checks (set after first apply)"
  type        = string
  default     = ""
}

variable "cloud_sql_max_connections" {
  description = "Max connections configured on Cloud SQL instance"
  type        = number
  default     = 500
}

# ---------- Notification Channels ----------

resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Enterprise SSO SOC Email"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }

  user_labels = var.labels
}

resource "google_monitoring_notification_channel" "pagerduty" {
  count = var.enable_pagerduty ? 1 : 0

  project      = var.project_id
  display_name = "Enterprise SSO PagerDuty"
  type         = "pagerduty"

  labels = {
    service_key = var.pagerduty_service_key
  }

  user_labels = var.labels
}

locals {
  notification_channels = concat(
    [google_monitoring_notification_channel.email.name],
    var.enable_pagerduty ? [google_monitoring_notification_channel.pagerduty[0].name] : []
  )
}

###############################################################################
# Uptime Checks
###############################################################################

# Gateway — External TCP check on port 9100
resource "google_monitoring_uptime_check_config" "gateway_tcp" {
  project      = var.project_id
  display_name = "SSO Gateway TCP (port 9100)"
  timeout      = "10s"
  period       = "60s"

  tcp_check {
    port = 9100
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = var.gateway_lb_ip_for_uptime != "" ? var.gateway_lb_ip_for_uptime : google_compute_global_address.gateway_lb.address
    }
  }

  content_matchers {}
}

# Admin — Internal HTTPS check on port 8080
resource "google_monitoring_uptime_check_config" "admin_https" {
  project      = var.project_id
  display_name = "SSO Admin HTTPS (port 8080)"
  timeout      = "10s"
  period       = "60s"

  http_check {
    path         = "/healthz"
    port         = 8080
    use_ssl      = true
    validate_ssl = false # Internal cert, not publicly trusted
  }

  resource_group {
    resource_type = "INSTANCE"
    group_id      = google_compute_region_instance_group_manager.admin.instance_group
  }
}

###############################################################################
# Alert Policy: Service Down (VM not responding > 30s) — CRITICAL
###############################################################################

resource "google_monitoring_alert_policy" "service_down" {
  project      = var.project_id
  display_name = "SSO: Service Down [CRITICAL]"
  combiner     = "OR"
  severity     = "CRITICAL"

  conditions {
    display_name = "Uptime check failing for > 30s"
    condition_threshold {
      filter          = "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND resource.type=\"uptime_url\""
      comparison      = "COMPARISON_LT"
      threshold_value = 1
      duration        = "30s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_NEXT_OLDER"
        cross_series_reducer = "REDUCE_COUNT_FALSE"
        group_by_fields      = ["resource.label.host"]
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "CRITICAL: A service VM has stopped responding for > 30 seconds. Immediate investigation required.\n\nRunbook: `./incident-response.sh status` then `./incident-response.sh snapshot <vm-name>`"
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

###############################################################################
# Alert Policy: CPU > 80% sustained 5 min — WARNING (auto-scale trigger)
###############################################################################

resource "google_monitoring_alert_policy" "high_cpu" {
  project      = var.project_id
  display_name = "SSO: CPU > 80% for 5 min [WARNING]"
  combiner     = "OR"
  severity     = "WARNING"

  conditions {
    display_name = "CPU utilization > 80% sustained"
    condition_threshold {
      filter          = "metric.type=\"compute.googleapis.com/instance/cpu/utilization\" AND resource.type=\"gce_instance\" AND metadata.user_labels.system=\"enterprise-sso\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "WARNING: CPU utilization > 80% sustained for 5 minutes. Auto-scaler should be adjusting. If this persists, check autoscaler health and consider manual scaling.\n\nRunbook: Check `gcloud compute instance-groups managed list-instances`"
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

###############################################################################
# Alert Policy: Memory > 90% — CRITICAL
###############################################################################

resource "google_monitoring_alert_policy" "high_memory" {
  project      = var.project_id
  display_name = "SSO: Memory > 90% [CRITICAL]"
  combiner     = "OR"
  severity     = "CRITICAL"

  conditions {
    display_name = "Memory utilization > 90%"
    condition_threshold {
      filter          = "metric.type=\"agent.googleapis.com/memory/percent_used\" AND resource.type=\"gce_instance\" AND metadata.user_labels.system=\"enterprise-sso\" AND metric.labels.state=\"used\""
      comparison      = "COMPARISON_GT"
      threshold_value = 90
      duration        = "120s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "CRITICAL: Memory utilization > 90%. Risk of OOM kills. Investigate memory leaks or scale out.\n\nRunbook: SSH to instance, check `free -m`, `top -o %MEM`, service restart if needed."
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

###############################################################################
# Alert Policy: Disk > 80% — WARNING
###############################################################################

resource "google_monitoring_alert_policy" "high_disk" {
  project      = var.project_id
  display_name = "SSO: Disk > 80% [WARNING]"
  combiner     = "OR"
  severity     = "WARNING"

  conditions {
    display_name = "Disk utilization > 80%"
    condition_threshold {
      filter          = "metric.type=\"agent.googleapis.com/disk/percent_used\" AND resource.type=\"gce_instance\" AND metadata.user_labels.system=\"enterprise-sso\""
      comparison      = "COMPARISON_GT"
      threshold_value = 80
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.notification_channels

  alert_strategy {
    auto_close = "3600s"
  }

  documentation {
    content   = "WARNING: Disk usage > 80%. Clean up old logs/snapshots or expand disk.\n\nRunbook: `du -sh /var/log/*`, rotate logs, check audit log accumulation."
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

###############################################################################
# Alert Policy: Auth failure rate > 50/min — CRITICAL (brute force)
###############################################################################

resource "google_monitoring_alert_policy" "brute_force" {
  project      = var.project_id
  display_name = "SSO: Auth Failures > 50/min — Brute Force [CRITICAL]"
  combiner     = "OR"
  severity     = "CRITICAL"

  conditions {
    display_name = "Auth failure rate > 50/min"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/sso-gce-auth-failures\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      duration        = "60s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.notification_channels

  alert_strategy {
    auto_close = "3600s"
  }

  documentation {
    content   = "CRITICAL: Authentication failure rate exceeds 50/min — likely brute force attack.\n\nImmediate actions:\n1. `./incident-response.sh status` to identify source\n2. Block offending IPs via WAF\n3. Consider `./incident-response.sh freeze` if attack is sophisticated"
    mime_type = "text/markdown"
  }

  user_labels = var.labels

  depends_on = [google_logging_metric.auth_failures]
}

###############################################################################
# Alert Policy: Network ingress > 100MB/s on gateway — WARNING (DDoS)
###############################################################################

resource "google_monitoring_alert_policy" "ddos_ingress" {
  project      = var.project_id
  display_name = "SSO: Gateway Ingress > 100MB/s — DDoS [WARNING]"
  combiner     = "OR"
  severity     = "WARNING"

  conditions {
    display_name = "Network ingress > 100 MB/s on gateway"
    condition_threshold {
      filter          = "metric.type=\"compute.googleapis.com/instance/network/received_bytes_count\" AND resource.type=\"gce_instance\" AND metadata.user_labels.service=\"gateway\""
      comparison      = "COMPARISON_GT"
      threshold_value = 104857600 # 100 MB/s in bytes
      duration        = "60s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "WARNING: Gateway network ingress > 100 MB/s. Potential DDoS.\n\nActions:\n1. Enable Cloud Armor rate limiting\n2. Check `gcloud compute firewall-rules list` for emergency blocks\n3. Scale gateway replicas if legitimate traffic"
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

###############################################################################
# Alert Policy: TSS node down (any of 5) — CRITICAL (threshold at risk)
###############################################################################

resource "google_monitoring_alert_policy" "tss_node_down" {
  project      = var.project_id
  display_name = "SSO: TSS Node Down — Threshold At Risk [CRITICAL]"
  combiner     = "OR"
  severity     = "CRITICAL"

  conditions {
    display_name = "TSS node not sending heartbeat"
    condition_absent {
      filter   = "metric.type=\"compute.googleapis.com/instance/cpu/utilization\" AND resource.type=\"gce_instance\" AND metadata.user_labels.service=\"tss\""
      duration = "120s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_COUNT"
        group_by_fields      = ["resource.label.instance_id"]
      }
    }
  }

  notification_channels = local.notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "CRITICAL: A TSS node is down. With ${var.tss_threshold}-of-${var.tss_node_count} threshold, losing nodes jeopardizes signing capability.\n\nActions:\n1. `./incident-response.sh status`\n2. Check specific TSS node health\n3. If compromised: `./incident-response.sh isolate tss-<N>`"
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

###############################################################################
# Alert Policy: Audit BFT quorum at risk (< 5 of 7 up) — CRITICAL
###############################################################################

resource "google_monitoring_alert_policy" "audit_quorum_risk" {
  project      = var.project_id
  display_name = "SSO: Audit BFT Quorum At Risk [CRITICAL]"
  combiner     = "OR"
  severity     = "CRITICAL"

  conditions {
    display_name = "Fewer than ${var.audit_quorum} audit nodes responding"
    condition_threshold {
      filter          = "metric.type=\"compute.googleapis.com/instance/uptime\" AND resource.type=\"gce_instance\" AND metadata.user_labels.service=\"audit\""
      comparison      = "COMPARISON_LT"
      threshold_value = var.audit_quorum
      duration        = "120s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_COUNT"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "CRITICAL: Audit BFT quorum at risk. Fewer than ${var.audit_quorum} of ${var.audit_node_count} audit nodes are healthy. Audit logging integrity is compromised.\n\nActions:\n1. `./incident-response.sh status`\n2. Check audit node logs for crash loops\n3. Restore failed nodes or replace them"
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

###############################################################################
# Alert Policy: Cloud SQL connections > 80% of max — WARNING
###############################################################################

resource "google_monitoring_alert_policy" "cloudsql_connections" {
  project      = var.project_id
  display_name = "SSO: Cloud SQL Connections > 80% [WARNING]"
  combiner     = "OR"
  severity     = "WARNING"

  conditions {
    display_name = "Cloud SQL connections > 80% of max"
    condition_threshold {
      filter          = "metric.type=\"cloudsql.googleapis.com/database/network/connections\" AND resource.type=\"cloudsql_database\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.cloud_sql_max_connections * 0.8
      duration        = "120s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "WARNING: Cloud SQL connections nearing max (${var.cloud_sql_max_connections}). Connection pool exhaustion imminent.\n\nActions:\n1. Check for connection leaks in service logs\n2. Restart offending service pods\n3. Consider scaling Cloud SQL tier"
    mime_type = "text/markdown"
  }

  user_labels = var.labels
}

###############################################################################
# Alert Policy: Error rate > 5% on any service — CRITICAL
###############################################################################

resource "google_monitoring_alert_policy" "high_error_rate" {
  project      = var.project_id
  display_name = "SSO: Error Rate > 5% [CRITICAL]"
  combiner     = "OR"
  severity     = "CRITICAL"

  conditions {
    display_name = "Error rate > 5% on service"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/sso-gce-error-rate\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      duration        = "120s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = local.notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "CRITICAL: Error rate exceeds 5% on a service. User-facing impact likely.\n\nActions:\n1. Identify affected service from alert labels\n2. Check service logs: `gcloud logging read 'resource.labels.instance_id=\"INSTANCE\"'`\n3. Consider rolling restart or rollback"
    mime_type = "text/markdown"
  }

  user_labels = var.labels

  depends_on = [google_logging_metric.error_rate]
}

###############################################################################
# Log-Based Metrics (referenced by alert policies above)
###############################################################################

resource "google_logging_metric" "auth_failures" {
  name    = "sso-gce-auth-failures"
  project = var.project_id
  filter  = "resource.type=\"gce_instance\" AND jsonPayload.event_type=\"authentication_failure\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "SSO GCE Authentication Failures"
  }
}

resource "google_logging_metric" "error_rate" {
  name    = "sso-gce-error-rate"
  project = var.project_id
  filter  = "resource.type=\"gce_instance\" AND severity>=\"ERROR\" AND metadata.userLabels.system=\"enterprise-sso\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "SSO GCE Error Rate"
  }
}

###############################################################################
# Dashboard
###############################################################################

resource "google_monitoring_dashboard" "sso_operations" {
  project = var.project_id
  dashboard_json = jsonencode({
    displayName = "Enterprise SSO Operations Dashboard"
    mosaicLayout = {
      columns = 12
      tiles = [
        # ── Row 1: Auth Metrics ──
        {
          width  = 4
          height = 4
          widget = {
            title = "Auth Success Rate"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"logging.googleapis.com/user/sso-gce-auth-success\" AND resource.type=\"gce_instance\""
                    aggregation = {
                      alignmentPeriod  = "60s"
                      perSeriesAligner = "ALIGN_RATE"
                    }
                  }
                }
                plotType = "LINE"
              }]
            }
          }
        },
        {
          xPos   = 4
          width  = 4
          height = 4
          widget = {
            title = "Auth Failure Rate"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"logging.googleapis.com/user/sso-gce-auth-failures\" AND resource.type=\"gce_instance\""
                    aggregation = {
                      alignmentPeriod  = "60s"
                      perSeriesAligner = "ALIGN_RATE"
                    }
                  }
                }
                plotType = "LINE"
              }]
            }
          }
        },
        {
          xPos   = 8
          width  = 4
          height = 4
          widget = {
            title = "Active Sessions"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"logging.googleapis.com/user/sso-gce-active-sessions\" AND resource.type=\"gce_instance\""
                  aggregation = {
                    alignmentPeriod    = "60s"
                    perSeriesAligner   = "ALIGN_MEAN"
                    crossSeriesReducer = "REDUCE_SUM"
                  }
                }
              }
            }
          }
        },

        # ── Row 2: Latency ──
        {
          yPos   = 4
          width  = 6
          height = 4
          widget = {
            title = "Service Latency (p50, p95, p99)"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"logging.googleapis.com/user/sso-gce-request-latency\" AND resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_50"
                        crossSeriesReducer = "REDUCE_MEAN"
                        groupByFields      = ["metadata.user_labels.service"]
                      }
                    }
                  }
                  plotType = "LINE"
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"logging.googleapis.com/user/sso-gce-request-latency\" AND resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_95"
                        crossSeriesReducer = "REDUCE_MEAN"
                        groupByFields      = ["metadata.user_labels.service"]
                      }
                    }
                  }
                  plotType = "LINE"
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"logging.googleapis.com/user/sso-gce-request-latency\" AND resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_99"
                        crossSeriesReducer = "REDUCE_MEAN"
                        groupByFields      = ["metadata.user_labels.service"]
                      }
                    }
                  }
                  plotType = "LINE"
                },
              ]
            }
          }
        },
        {
          xPos   = 6
          yPos   = 4
          width  = 6
          height = 4
          widget = {
            title = "TSS Signing Operations/sec"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"logging.googleapis.com/user/sso-gce-tss-signing-ops\" AND resource.type=\"gce_instance\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_RATE"
                      crossSeriesReducer = "REDUCE_SUM"
                    }
                  }
                }
                plotType = "LINE"
              }]
            }
          }
        },

        # ── Row 3: Resource Utilization ──
        {
          yPos   = 8
          width  = 4
          height = 4
          widget = {
            title = "CPU by Service Group"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"compute.googleapis.com/instance/cpu/utilization\" AND resource.type=\"gce_instance\" AND metadata.user_labels.system=\"enterprise-sso\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_MEAN"
                      crossSeriesReducer = "REDUCE_MEAN"
                      groupByFields      = ["metadata.user_labels.service"]
                    }
                  }
                }
                plotType = "LINE"
              }]
            }
          }
        },
        {
          xPos   = 4
          yPos   = 8
          width  = 4
          height = 4
          widget = {
            title = "Memory by Service Group"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"agent.googleapis.com/memory/percent_used\" AND resource.type=\"gce_instance\" AND metadata.user_labels.system=\"enterprise-sso\" AND metric.labels.state=\"used\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_MEAN"
                      crossSeriesReducer = "REDUCE_MEAN"
                      groupByFields      = ["metadata.user_labels.service"]
                    }
                  }
                }
                plotType = "LINE"
              }]
            }
          }
        },
        {
          xPos   = 8
          yPos   = 8
          width  = 4
          height = 4
          widget = {
            title = "Rate Limiter Hits"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"logging.googleapis.com/user/sso-gce-rate-limiter-hits\" AND resource.type=\"gce_instance\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_RATE"
                      crossSeriesReducer = "REDUCE_SUM"
                      groupByFields      = ["metadata.user_labels.service"]
                    }
                  }
                }
                plotType = "STACKED_BAR"
              }]
            }
          }
        },
      ]
    }
  })
}

###############################################################################
# Supporting log-based metrics for dashboard widgets
###############################################################################

resource "google_logging_metric" "auth_success" {
  name    = "sso-gce-auth-success"
  project = var.project_id
  filter  = "resource.type=\"gce_instance\" AND jsonPayload.event_type=\"authentication_success\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "SSO GCE Authentication Successes"
  }
}

resource "google_logging_metric" "active_sessions" {
  name    = "sso-gce-active-sessions"
  project = var.project_id
  filter  = "resource.type=\"gce_instance\" AND jsonPayload.metric=\"active_sessions\""

  metric_descriptor {
    metric_kind  = "GAUGE"
    value_type   = "INT64"
    unit         = "1"
    display_name = "SSO GCE Active Sessions"
  }

  value_extractor = "EXTRACT(jsonPayload.value)"
}

resource "google_logging_metric" "request_latency" {
  name    = "sso-gce-request-latency"
  project = var.project_id
  filter  = "resource.type=\"gce_instance\" AND jsonPayload.metric=\"request_latency_ms\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "DISTRIBUTION"
    unit         = "ms"
    display_name = "SSO GCE Request Latency"
  }

  value_extractor = "EXTRACT(jsonPayload.value)"

  bucket_options {
    explicit_buckets {
      bounds = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]
    }
  }
}

resource "google_logging_metric" "tss_signing_ops" {
  name    = "sso-gce-tss-signing-ops"
  project = var.project_id
  filter  = "resource.type=\"gce_instance\" AND jsonPayload.event_type=\"tss_signing_complete\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "SSO GCE TSS Signing Operations"
  }
}

resource "google_logging_metric" "rate_limiter_hits" {
  name    = "sso-gce-rate-limiter-hits"
  project = var.project_id
  filter  = "resource.type=\"gce_instance\" AND jsonPayload.event_type=\"rate_limited\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "SSO GCE Rate Limiter Hits"
  }
}
