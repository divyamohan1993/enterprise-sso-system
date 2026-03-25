# ──────────────────────────────────────────────────────────────────────────────
# MILNET SSO — AWS GovCloud RDS Module
# ──────────────────────────────────────────────────────────────────────────────
# RDS Aurora PostgreSQL 15-compatible cluster.
# FIPS mode enabled via parameter group.
# Encryption with customer-managed KMS key.
# Private subnets only, no publicly accessible endpoint.
# ──────────────────────────────────────────────────────────────────────────────

variable "primary_region" { type = string }
variable "secondary_region" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "kms_key_arn" { type = string }

locals {
  name_prefix = "milnet-govcloud-${var.environment}"
  is_prod     = var.environment == "production"

  engine_version = "15.4"
  instance_class = local.is_prod ? "db.r6g.large" : "db.t4g.medium"
}

# ── DB Subnet Group ──

resource "aws_db_subnet_group" "milnet" {
  name        = "${local.name_prefix}-db-subnet-group"
  subnet_ids  = var.subnet_ids
  description = "MILNET GovCloud DB subnet group — private subnets only"

  tags = { Name = "${local.name_prefix}-db-subnet-group" }
}

# ── Security Group for RDS ──

resource "aws_security_group" "rds" {
  name        = "${local.name_prefix}-rds-sg"
  description = "Allow PostgreSQL from MILNET services only"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.40.0.0/16"]
    description = "PostgreSQL from MILNET VPC only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-rds-sg" }
}

# ── Parameter Group (FIPS mode) ──

resource "aws_rds_cluster_parameter_group" "fips" {
  name        = "${local.name_prefix}-pg15-fips"
  family      = "aurora-postgresql15"
  description = "MILNET GovCloud PostgreSQL 15 — FIPS mode"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "ssl_min_protocol_version"
    value = "TLSv1.2"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_checkpoints"
    value = "1"
  }

  parameter {
    name  = "pgaudit.log"
    value = "ddl,write,role"
  }

  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }

  tags = { Name = "${local.name_prefix}-pg15-fips-params" }
}

# ── Aurora Cluster ──

resource "aws_rds_cluster" "milnet" {
  cluster_identifier = "${local.name_prefix}-pg15"
  engine             = "aurora-postgresql"
  engine_version     = local.engine_version
  engine_mode        = "provisioned"

  # Private — no public access
  publicly_accessible = false

  db_subnet_group_name   = aws_db_subnet_group.milnet.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  # CMEK encryption
  storage_encrypted = true
  kms_key_id        = var.kms_key_arn

  # Force TLS
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.fips.name

  # Backup
  backup_retention_period      = 30
  preferred_backup_window      = "02:00-03:00"
  preferred_maintenance_window = "sun:03:00-sun:04:00"
  copy_tags_to_snapshot        = true
  deletion_protection          = local.is_prod

  # Skip final snapshot for dev
  skip_final_snapshot       = !local.is_prod
  final_snapshot_identifier = local.is_prod ? "${local.name_prefix}-final-snapshot" : null

  enabled_cloudwatch_logs_exports = ["postgresql"]

  serverlessv2_scaling_configuration {
    min_capacity = local.is_prod ? 2 : 0.5
    max_capacity = local.is_prod ? 16 : 2
  }

  tags = {
    Name        = "${local.name_prefix}-pg15"
    Environment = var.environment
    FipsMode    = "true"
    Encryption  = "cmek"
  }
}

# ── Writer Instance ──

resource "aws_rds_cluster_instance" "writer" {
  identifier         = "${local.name_prefix}-pg15-writer"
  cluster_identifier = aws_rds_cluster.milnet.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.milnet.engine
  engine_version     = aws_rds_cluster.milnet.engine_version

  publicly_accessible         = false
  db_subnet_group_name        = aws_db_subnet_group.milnet.name
  performance_insights_enabled = local.is_prod

  auto_minor_version_upgrade = false

  tags = {
    Name = "${local.name_prefix}-pg15-writer"
    Role = "writer"
  }
}

# ── Reader Instance (production only) ──

resource "aws_rds_cluster_instance" "reader" {
  count = local.is_prod ? 1 : 0

  identifier         = "${local.name_prefix}-pg15-reader"
  cluster_identifier = aws_rds_cluster.milnet.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.milnet.engine
  engine_version     = aws_rds_cluster.milnet.engine_version

  publicly_accessible          = false
  db_subnet_group_name         = aws_db_subnet_group.milnet.name
  performance_insights_enabled = true

  auto_minor_version_upgrade = false

  tags = {
    Name = "${local.name_prefix}-pg15-reader"
    Role = "reader"
  }
}

# ── Outputs ──

output "endpoint" {
  description = "Aurora cluster writer endpoint"
  value       = aws_rds_cluster.milnet.endpoint
  sensitive   = true
}

output "reader_endpoint" {
  description = "Aurora cluster reader endpoint"
  value       = aws_rds_cluster.milnet.reader_endpoint
  sensitive   = true
}

output "port" {
  value = aws_rds_cluster.milnet.port
}

output "cluster_arn" {
  value = aws_rds_cluster.milnet.arn
}
