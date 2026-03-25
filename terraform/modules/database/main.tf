# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — Cloud SQL PostgreSQL Module
# ──────────────────────────────────────────────────────────────────────────────
# Military-grade PostgreSQL 15 with:
#   - Private IP only (no public endpoint)
#   - SSL enforcement
#   - Automated backups with point-in-time recovery
#   - CMEK encryption via Cloud KMS
#   - Audit logging via pgaudit
#   - Per-service database users
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

variable "tier" {
  type    = string
  default = "db-f1-micro"
}

variable "availability_type" {
  type    = string
  default = "ZONAL"
}

variable "backup_retention_days" {
  type    = number
  default = 7
}

variable "maintenance_window_day" {
  type    = number
  default = 7
}

variable "maintenance_window_hour" {
  type    = number
  default = 2
}

variable "vpc_network_id" {
  type = string
}

variable "private_ip_range_name" {
  type = string
}

variable "service_names" {
  type = list(string)
}

variable "kms_crypto_key_id" {
  description = "Cloud KMS key ID for CMEK encryption of the database"
  type        = string
}

variable "labels" {
  type    = map(string)
  default = {}
}

# ── Private Service Connection ──
# Required for Cloud SQL to get a private IP in the VPC.

resource "google_service_networking_connection" "private_vpc" {
  network                 = var.vpc_network_id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [var.private_ip_range_name]
}

# ── Cloud SQL Instance ──

resource "google_sql_database_instance" "milnet" {
  name                = "milnet-sso-db-${var.deployment_suffix}"
  project             = var.project_id
  region              = var.region
  database_version    = "POSTGRES_15"
  deletion_protection = true

  encryption_key_name = var.kms_crypto_key_id

  settings {
    tier              = var.tier
    availability_type = var.availability_type
    disk_autoresize   = true
    disk_size         = 10
    disk_type         = "PD_SSD"

    user_labels = var.labels

    ip_configuration {
      ipv4_enabled    = false
      private_network = var.vpc_network_id

      ssl_mode = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
      transaction_log_retention_days = var.backup_retention_days

      backup_retention_settings {
        retained_backups = var.backup_retention_days
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = var.maintenance_window_day
      hour         = var.maintenance_window_hour
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
      name  = "log_temp_files"
      value = "0"
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "1000"
    }

    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }

    database_flags {
      name  = "pgaudit.log"
      value = "all"
    }

    insights_config {
      query_insights_enabled  = true
      record_application_tags = true
      record_client_address   = true
    }
  }

  depends_on = [google_service_networking_connection.private_vpc]
}

# ── Primary database ──

resource "google_sql_database" "milnet_sso" {
  name     = "milnet_sso"
  instance = google_sql_database_instance.milnet.name
  project  = var.project_id
}

# ── Per-service database users ──
# Each microservice gets its own DB user with a random password stored in
# Secret Manager (created by the secrets module).

resource "random_password" "db_passwords" {
  for_each = toset(var.service_names)

  length  = 32
  special = false
}

resource "google_sql_user" "service_users" {
  for_each = toset(var.service_names)

  name     = "milnet_${each.value}"
  instance = google_sql_database_instance.milnet.name
  project  = var.project_id
  password = random_password.db_passwords[each.value].result
}

# ── Outputs ──

output "instance_name" {
  value = google_sql_database_instance.milnet.name
}

output "connection_name" {
  value = google_sql_database_instance.milnet.connection_name
}

output "private_ip" {
  value     = google_sql_database_instance.milnet.private_ip_address
  sensitive = true
}

output "database_name" {
  value = google_sql_database.milnet_sso.name
}

output "service_user_passwords" {
  description = "Map of service name to generated DB password"
  value       = { for k, v in random_password.db_passwords : k => v.result }
  sensitive   = true
}
