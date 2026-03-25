# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — GCP India Cloud SQL Module
# ──────────────────────────────────────────────────────────────────────────────
# PostgreSQL 15 with:
#   - Primary instance in asia-south1 (Mumbai)
#   - Read replica in asia-south2 (Delhi)
#   - CMEK encryption (HSM-backed KMS key)
#   - Private IP only (no public IP)
#   - Automated backups retained 30 days
#   - Point-in-time recovery enabled
# ──────────────────────────────────────────────────────────────────────────────

variable "project_id" { type = string }
variable "primary_region" { type = string }
variable "secondary_region" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "kms_key_id" { type = string }

locals {
  name_prefix = "milnet-india-${var.environment}"
  db_version  = "POSTGRES_15"

  # Tier: db-g1-small for dev/staging, db-n1-standard-2 for production
  db_tier = var.environment == "production" ? "db-n1-standard-2" : "db-g1-small"
}

# ── Primary Instance (asia-south1 / Mumbai) ──

resource "google_sql_database_instance" "primary" {
  name             = "${local.name_prefix}-pg15-primary"
  project          = var.project_id
  region           = var.primary_region  # asia-south1
  database_version = local.db_version

  # CMEK — Cloud SQL data encrypted with HSM-backed KMS key
  encryption_key_name = var.kms_key_id

  deletion_protection = var.environment == "production"

  settings {
    tier              = local.db_tier
    availability_type = var.environment == "production" ? "REGIONAL" : "ZONAL"
    disk_type         = "PD_SSD"
    disk_size         = 100

    # Private IP only — no public endpoint
    ip_configuration {
      ipv4_enabled                                  = false  # No public IP
      private_network                               = var.vpc_id
      enable_private_path_for_google_cloud_services = true
      require_ssl                                   = true
    }

    backup_configuration {
      enabled                        = true
      start_time                     = "02:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 30
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = 7  # Sunday
      hour         = 2  # 02:00 UTC
      update_track = "stable"
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }
    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
    database_flags {
      name  = "log_lock_waits"
      value = "on"
    }
    database_flags {
      name  = "log_min_duration_statement"
      value = "1000"  # Log queries taking > 1s
    }
    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }
    database_flags {
      name  = "password_encryption"
      value = "scram-sha-256"
    }

    insights_config {
      query_insights_enabled  = true
      query_string_length     = 1024
      record_application_tags = true
      record_client_address   = false  # Privacy: don't log client IPs
    }

    user_labels = {
      environment    = var.environment
      data_residency = "india"
      region         = var.primary_region
    }
  }
}

# ── Read Replica (asia-south2 / Delhi) ──
# Provides low-latency reads from Delhi and serves as a warm standby.

resource "google_sql_database_instance" "replica" {
  name                 = "${local.name_prefix}-pg15-replica-as2"
  project              = var.project_id
  region               = var.secondary_region  # asia-south2
  database_version     = local.db_version
  master_instance_name = google_sql_database_instance.primary.name

  # Replica inherits CMEK from primary
  encryption_key_name = var.kms_key_id

  deletion_protection = false

  replica_configuration {
    failover_target = false
  }

  settings {
    tier              = local.db_tier
    availability_type = "ZONAL"
    disk_type         = "PD_SSD"
    disk_size         = 100

    ip_configuration {
      ipv4_enabled    = false  # No public IP
      private_network = var.vpc_id
      require_ssl     = true
    }

    user_labels = {
      environment    = var.environment
      data_residency = "india"
      region         = var.secondary_region
      role           = "read-replica"
    }
  }

  depends_on = [google_sql_database_instance.primary]
}

# ── Outputs ──

output "connection_name" {
  description = "Cloud SQL primary instance connection name"
  value       = google_sql_database_instance.primary.connection_name
}

output "private_ip" {
  description = "Private IP of the primary instance"
  value       = google_sql_database_instance.primary.private_ip_address
  sensitive   = true
}

output "replica_connection_name" {
  description = "Cloud SQL replica instance connection name"
  value       = google_sql_database_instance.replica.connection_name
}

output "instance_name" {
  value = google_sql_database_instance.primary.name
}
