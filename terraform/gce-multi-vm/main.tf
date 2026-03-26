###############################################################################
# main.tf — Enterprise SSO Multi-VM GCE Deployment
#
# Deploys 10 microservices across isolated VMs with:
#   - TSS on 5 separate VMs across 5 zones (threshold signing)
#   - Audit BFT on 7 separate VMs across zones (5-of-7 quorum)
#   - Gateway behind global TCP LB with auto-scaling MIG
#   - Admin behind internal HTTPS LB with auto-scaling MIG
#   - Verifier auto-scaling MIG
#   - HA pairs for orchestrator, opaque, ratchet
#   - Single VMs for risk, kt
#   - Cloud SQL PostgreSQL with HA failover
#   - VPC with private subnets, strict firewall rules
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  backend "gcs" {
    bucket = "enterprise-sso-tfstate"
    prefix = "gce-multi-vm"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# Random suffix for globally-unique resource names
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix = random_id.suffix.hex
  common_labels = merge(var.labels, {
    environment = var.environment
  })

  # Zone distribution for TSS (5 nodes across 5 zones)
  tss_zones = concat(var.zones, var.secondary_zones) # 5 zones total

  # Zone distribution for Audit BFT (7 nodes across available zones, round-robin)
  all_zones   = concat(var.zones, var.secondary_zones)
  audit_zones = [for i in range(var.audit_node_count) : local.all_zones[i % length(local.all_zones)]]

  # Service ports
  ports = {
    gateway      = 9100
    admin        = 8080
    orchestrator = 9101
    opaque       = 9102
    tss          = 9103
    verifier     = 9104
    ratchet      = 9105
    risk         = 9106
    audit        = 9108
    kt           = 9109
  }
}

###############################################################################
# 1. VPC NETWORK
###############################################################################

resource "google_compute_network" "sso_vpc" {
  name                    = "sso-vpc-${local.suffix}"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  project                 = var.project_id
}

# Public subnet — gateway only
resource "google_compute_subnetwork" "public" {
  name                     = "sso-public-${local.suffix}"
  ip_cidr_range            = var.public_subnet_cidr
  region                   = var.region
  network                  = google_compute_network.sso_vpc.id
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Private subnet — all internal services (primary region)
resource "google_compute_subnetwork" "private" {
  name                     = "sso-private-${local.suffix}"
  ip_cidr_range            = var.private_subnet_cidr
  region                   = var.region
  network                  = google_compute_network.sso_vpc.id
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Private subnet — secondary region (for cross-region TSS/audit nodes)
resource "google_compute_subnetwork" "private_secondary" {
  name                     = "sso-private-secondary-${local.suffix}"
  ip_cidr_range            = var.private_subnet_secondary_cidr
  region                   = var.secondary_region
  network                  = google_compute_network.sso_vpc.id
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Cloud NAT for private instances to pull binaries from GCS
resource "google_compute_router" "nat_router" {
  name    = "sso-nat-router-${local.suffix}"
  network = google_compute_network.sso_vpc.id
  region  = var.region
}

resource "google_compute_router_nat" "nat" {
  name                               = "sso-nat-${local.suffix}"
  router                             = google_compute_router.nat_router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_compute_router" "nat_router_secondary" {
  name    = "sso-nat-router-sec-${local.suffix}"
  network = google_compute_network.sso_vpc.id
  region  = var.secondary_region
}

resource "google_compute_router_nat" "nat_secondary" {
  name                               = "sso-nat-sec-${local.suffix}"
  router                             = google_compute_router.nat_router_secondary.name
  region                             = var.secondary_region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Private Services Access for Cloud SQL
resource "google_compute_global_address" "private_ip_range" {
  name          = "sso-private-ip-${local.suffix}"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.sso_vpc.id
}

resource "google_service_networking_connection" "private_vpc" {
  network                 = google_compute_network.sso_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]
}

###############################################################################
# 2. SERVICE ACCOUNTS (minimal IAM per service)
###############################################################################

resource "google_service_account" "gateway" {
  account_id   = "sso-gateway-${local.suffix}"
  display_name = "SSO Gateway Service"
}

resource "google_service_account" "admin" {
  account_id   = "sso-admin-${local.suffix}"
  display_name = "SSO Admin API Service"
}

resource "google_service_account" "orchestrator" {
  account_id   = "sso-orchestrator-${local.suffix}"
  display_name = "SSO Orchestrator Service"
}

resource "google_service_account" "opaque" {
  account_id   = "sso-opaque-${local.suffix}"
  display_name = "SSO OPAQUE Auth Service"
}

resource "google_service_account" "tss" {
  account_id   = "sso-tss-${local.suffix}"
  display_name = "SSO Threshold Signing Service"
}

resource "google_service_account" "verifier" {
  account_id   = "sso-verifier-${local.suffix}"
  display_name = "SSO Token Verifier Service"
}

resource "google_service_account" "ratchet" {
  account_id   = "sso-ratchet-${local.suffix}"
  display_name = "SSO Session Ratchet Service"
}

resource "google_service_account" "risk" {
  account_id   = "sso-risk-${local.suffix}"
  display_name = "SSO Risk Scoring Service"
}

resource "google_service_account" "audit" {
  account_id   = "sso-audit-${local.suffix}"
  display_name = "SSO Audit BFT Service"
}

resource "google_service_account" "kt" {
  account_id   = "sso-kt-${local.suffix}"
  display_name = "SSO Key Transparency Service"
}

# IAM: all services can read binaries from GCS
locals {
  all_service_accounts = [
    google_service_account.gateway.email,
    google_service_account.admin.email,
    google_service_account.orchestrator.email,
    google_service_account.opaque.email,
    google_service_account.tss.email,
    google_service_account.verifier.email,
    google_service_account.ratchet.email,
    google_service_account.risk.email,
    google_service_account.audit.email,
    google_service_account.kt.email,
  ]
}

resource "google_storage_bucket_iam_member" "binary_reader" {
  for_each = toset(local.all_service_accounts)
  bucket   = var.binary_bucket
  role     = "roles/storage.objectViewer"
  member   = "serviceAccount:${each.value}"
}

# Service-specific IAM
resource "google_project_iam_member" "gateway_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}

resource "google_project_iam_member" "gateway_monitoring" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}

# Audit needs write to Cloud Storage for tamper-evident logs
resource "google_project_iam_member" "audit_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.audit.email}"
}

# Admin needs Cloud SQL client access
resource "google_project_iam_member" "admin_sql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.admin.email}"
}

# Orchestrator needs Cloud SQL client access
resource "google_project_iam_member" "orchestrator_sql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.orchestrator.email}"
}

# All services get log writer and metric writer
resource "google_project_iam_member" "service_logging" {
  for_each = toset(local.all_service_accounts)
  project  = var.project_id
  role     = "roles/logging.logWriter"
  member   = "serviceAccount:${each.value}"
}

resource "google_project_iam_member" "service_monitoring" {
  for_each = toset(local.all_service_accounts)
  project  = var.project_id
  role     = "roles/monitoring.metricWriter"
  member   = "serviceAccount:${each.value}"
}

###############################################################################
# 3. FIREWALL RULES
###############################################################################

# Deny all ingress by default (implicit in GCP, but explicit for clarity)
resource "google_compute_firewall" "deny_all_ingress" {
  name      = "sso-deny-all-ingress-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 65534

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

# Allow health checks from GCP LB ranges
resource "google_compute_firewall" "allow_health_checks" {
  name      = "sso-allow-health-checks-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 100

  allow {
    protocol = "tcp"
    ports    = [for _, p in local.ports : tostring(p)]
  }

  source_ranges = [
    "35.191.0.0/16",  # GCP health check
    "130.211.0.0/22", # GCP health check
  ]

  target_tags = ["sso-service"]
}

# Gateway: external traffic on port 9100
resource "google_compute_firewall" "gateway_external" {
  name      = "sso-gateway-external-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 200

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.gateway)]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["sso-gateway"]
}

# Admin: internal/VPN access only on port 8080
resource "google_compute_firewall" "admin_internal" {
  name      = "sso-admin-internal-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 300

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.admin)]
  }

  source_ranges = concat(
    [var.private_subnet_cidr, var.public_subnet_cidr, var.private_subnet_secondary_cidr],
    var.vpn_source_ranges,
  )

  target_tags = ["sso-admin"]
}

# Inter-service: gateway -> orchestrator
resource "google_compute_firewall" "gateway_to_orchestrator" {
  name      = "sso-gw-to-orch-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.orchestrator)]
  }

  source_tags = ["sso-gateway"]
  target_tags = ["sso-orchestrator"]
}

# Inter-service: gateway -> verifier (token verification)
resource "google_compute_firewall" "gateway_to_verifier" {
  name      = "sso-gw-to-verifier-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.verifier)]
  }

  source_tags = ["sso-gateway"]
  target_tags = ["sso-verifier"]
}

# Inter-service: orchestrator -> opaque
resource "google_compute_firewall" "orchestrator_to_opaque" {
  name      = "sso-orch-to-opaque-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.opaque)]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-opaque"]
}

# Inter-service: orchestrator -> tss
resource "google_compute_firewall" "orchestrator_to_tss" {
  name      = "sso-orch-to-tss-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.tss)]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-tss"]
}

# Inter-service: orchestrator -> ratchet
resource "google_compute_firewall" "orchestrator_to_ratchet" {
  name      = "sso-orch-to-ratchet-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.ratchet)]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-ratchet"]
}

# Inter-service: orchestrator -> risk
resource "google_compute_firewall" "orchestrator_to_risk" {
  name      = "sso-orch-to-risk-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.risk)]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-risk"]
}

# Inter-service: orchestrator -> verifier
resource "google_compute_firewall" "orchestrator_to_verifier" {
  name      = "sso-orch-to-verifier-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.verifier)]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-verifier"]
}

# Inter-service: orchestrator -> audit
resource "google_compute_firewall" "orchestrator_to_audit" {
  name      = "sso-orch-to-audit-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.audit)]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-audit"]
}

# Inter-service: orchestrator -> kt
resource "google_compute_firewall" "orchestrator_to_kt" {
  name      = "sso-orch-to-kt-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.kt)]
  }

  source_tags = ["sso-orchestrator"]
  target_tags = ["sso-kt"]
}

# TSS inter-node communication (peer-to-peer for threshold protocol)
resource "google_compute_firewall" "tss_peer" {
  name      = "sso-tss-peer-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.tss)]
  }

  source_tags = ["sso-tss"]
  target_tags = ["sso-tss"]
}

# Audit BFT inter-node communication (BFT consensus protocol)
resource "google_compute_firewall" "audit_peer" {
  name      = "sso-audit-peer-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.audit)]
  }

  source_tags = ["sso-audit"]
  target_tags = ["sso-audit"]
}

# Admin -> orchestrator (management)
resource "google_compute_firewall" "admin_to_orchestrator" {
  name      = "sso-admin-to-orch-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.orchestrator)]
  }

  source_tags = ["sso-admin"]
  target_tags = ["sso-orchestrator"]
}

# Admin -> audit (log retrieval)
resource "google_compute_firewall" "admin_to_audit" {
  name      = "sso-admin-to-audit-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 400

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ports.audit)]
  }

  source_tags = ["sso-admin"]
  target_tags = ["sso-audit"]
}

# IAP SSH tunnel access (for ops debugging)
resource "google_compute_firewall" "iap_ssh" {
  name      = "sso-iap-ssh-${local.suffix}"
  network   = google_compute_network.sso_vpc.id
  direction = "INGRESS"
  priority  = 500

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.ssh_source_ranges
  target_tags   = ["sso-service"]
}

###############################################################################
# 4. STARTUP SCRIPT TEMPLATE
###############################################################################

locals {
  # Base startup script — parameterized per service
  startup_script_template = <<-'SCRIPT'
    #!/bin/bash
    set -euo pipefail

    SERVICE_NAME="__SERVICE_NAME__"
    SERVICE_PORT="__SERVICE_PORT__"
    BINARY_BUCKET="__BINARY_BUCKET__"
    BINARY_VERSION="__BINARY_VERSION__"
    EXTRA_ENV="__EXTRA_ENV__"

    # Harden the OS
    echo "* hard nofile 65536" >> /etc/security/limits.conf
    echo "* soft nofile 65536" >> /etc/security/limits.conf
    sysctl -w net.core.somaxconn=65535
    sysctl -w net.ipv4.tcp_max_syn_backlog=65535
    sysctl -w net.ipv4.ip_forward=0
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.default.accept_redirects=0
    sysctl -w net.ipv4.conf.all.accept_redirects=0

    # Install monitoring agent
    curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
    bash add-google-cloud-ops-agent-repo.sh --also-install || true

    # Create service user
    useradd -r -s /usr/sbin/nologin "sso-${SERVICE_NAME}" || true

    # Download binary from GCS
    mkdir -p /opt/sso/bin /opt/sso/config /var/log/sso
    gsutil cp "gs://${BINARY_BUCKET}/${BINARY_VERSION}/${SERVICE_NAME}" /opt/sso/bin/${SERVICE_NAME}
    chmod 755 /opt/sso/bin/${SERVICE_NAME}
    chown -R "sso-${SERVICE_NAME}:sso-${SERVICE_NAME}" /opt/sso /var/log/sso

    # Fetch instance metadata for peer discovery
    INSTANCE_NAME=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/name)
    INSTANCE_ZONE=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone | awk -F/ '{print $NF}')
    INTERNAL_IP=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip)

    # Write env file
    cat > /opt/sso/config/${SERVICE_NAME}.env <<EOF
    SSO_SERVICE_NAME=${SERVICE_NAME}
    SSO_SERVICE_PORT=${SERVICE_PORT}
    SSO_INSTANCE_NAME=${INSTANCE_NAME}
    SSO_INSTANCE_ZONE=${INSTANCE_ZONE}
    SSO_BIND_ADDRESS=0.0.0.0:${SERVICE_PORT}
    SSO_INTERNAL_IP=${INTERNAL_IP}
    SSO_LOG_DIR=/var/log/sso
    SSO_LOG_LEVEL=info
    ${EXTRA_ENV}
    EOF

    # Create systemd unit
    cat > /etc/systemd/system/sso-${SERVICE_NAME}.service <<EOF
    [Unit]
    Description=SSO ${SERVICE_NAME} service
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    User=sso-${SERVICE_NAME}
    Group=sso-${SERVICE_NAME}
    EnvironmentFile=/opt/sso/config/${SERVICE_NAME}.env
    ExecStart=/opt/sso/bin/${SERVICE_NAME}
    Restart=always
    RestartSec=5
    LimitNOFILE=65536
    StandardOutput=journal
    StandardError=journal
    ProtectSystem=strict
    ProtectHome=true
    NoNewPrivileges=true
    ReadWritePaths=/var/log/sso

    [Install]
    WantedBy=multi-user.target
    EOF

    systemctl daemon-reload
    systemctl enable sso-${SERVICE_NAME}
    systemctl start sso-${SERVICE_NAME}

    echo "SSO ${SERVICE_NAME} started on port ${SERVICE_PORT}"
  SCRIPT
}

# Helper to generate per-service startup scripts
locals {
  startup_scripts = {
    for svc, port in local.ports : svc => replace(
      replace(
        replace(
          replace(
            replace(local.startup_script_template,
            "__SERVICE_NAME__", svc),
          "__SERVICE_PORT__", tostring(port)),
        "__BINARY_BUCKET__", var.binary_bucket),
      "__BINARY_VERSION__", var.binary_version),
    "__EXTRA_ENV__", "")
  }
}

###############################################################################
# 5. INSTANCE TEMPLATES (for auto-scaling services)
###############################################################################

# ----- Gateway instance template -----
resource "google_compute_instance_template" "gateway" {
  name_prefix  = "sso-gateway-"
  machine_type = var.machine_type_gateway
  region       = var.region
  tags         = ["sso-service", "sso-gateway"]
  labels       = merge(local.common_labels, { service = "gateway" })

  disk {
    source_image = "debian-cloud/debian-12"
    auto_delete  = true
    boot         = true
    disk_size_gb = 20
    disk_type    = "pd-balanced"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.public.id
    # Gateway gets external IP via LB, not directly on instance
  }

  metadata = {
    startup-script = local.startup_scripts["gateway"]
    service-name   = "gateway"
    service-port   = tostring(local.ports.gateway)
  }

  service_account {
    email  = google_service_account.gateway.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ----- Admin instance template -----
resource "google_compute_instance_template" "admin" {
  name_prefix  = "sso-admin-"
  machine_type = var.machine_type_admin
  region       = var.region
  tags         = ["sso-service", "sso-admin"]
  labels       = merge(local.common_labels, { service = "admin" })

  disk {
    source_image = "debian-cloud/debian-12"
    auto_delete  = true
    boot         = true
    disk_size_gb = 20
    disk_type    = "pd-balanced"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }

  metadata = {
    startup-script = local.startup_scripts["admin"]
    service-name   = "admin"
    service-port   = tostring(local.ports.admin)
  }

  service_account {
    email  = google_service_account.admin.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ----- Verifier instance template -----
resource "google_compute_instance_template" "verifier" {
  name_prefix  = "sso-verifier-"
  machine_type = var.machine_type_verifier
  region       = var.region
  tags         = ["sso-service", "sso-verifier"]
  labels       = merge(local.common_labels, { service = "verifier" })

  disk {
    source_image = "debian-cloud/debian-12"
    auto_delete  = true
    boot         = true
    disk_size_gb = 20
    disk_type    = "pd-balanced"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }

  metadata = {
    startup-script = local.startup_scripts["verifier"]
    service-name   = "verifier"
    service-port   = tostring(local.ports.verifier)
  }

  service_account {
    email  = google_service_account.verifier.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  lifecycle {
    create_before_destroy = true
  }
}

###############################################################################
# 6. MANAGED INSTANCE GROUPS + AUTOSCALERS
###############################################################################

# ----- Gateway MIG (regional, multi-zone) -----
resource "google_compute_region_instance_group_manager" "gateway" {
  name               = "sso-gateway-mig-${local.suffix}"
  base_instance_name = "sso-gateway"
  region             = var.region

  version {
    instance_template = google_compute_instance_template.gateway.id
  }

  named_port {
    name = "gateway"
    port = local.ports.gateway
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.gateway.id
    initial_delay_sec = 120
  }

  update_policy {
    type                           = "PROACTIVE"
    minimal_action                 = "REPLACE"
    most_disruptive_allowed_action = "REPLACE"
    max_surge_fixed                = 2
    max_unavailable_fixed          = 0
  }
}

resource "google_compute_region_autoscaler" "gateway" {
  name   = "sso-gateway-autoscaler-${local.suffix}"
  region = var.region
  target = google_compute_region_instance_group_manager.gateway.id

  autoscaling_policy {
    min_replicas    = var.gateway_min_replicas
    max_replicas    = var.gateway_max_replicas
    cooldown_period = 90

    cpu_utilization {
      target = var.autoscaler_cpu_target
    }
  }
}

# ----- Admin MIG (regional) -----
resource "google_compute_region_instance_group_manager" "admin" {
  name               = "sso-admin-mig-${local.suffix}"
  base_instance_name = "sso-admin"
  region             = var.region

  version {
    instance_template = google_compute_instance_template.admin.id
  }

  named_port {
    name = "admin"
    port = local.ports.admin
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.admin.id
    initial_delay_sec = 120
  }

  update_policy {
    type                           = "PROACTIVE"
    minimal_action                 = "REPLACE"
    most_disruptive_allowed_action = "REPLACE"
    max_surge_fixed                = 1
    max_unavailable_fixed          = 0
  }
}

resource "google_compute_region_autoscaler" "admin" {
  name   = "sso-admin-autoscaler-${local.suffix}"
  region = var.region
  target = google_compute_region_instance_group_manager.admin.id

  autoscaling_policy {
    min_replicas    = var.admin_min_replicas
    max_replicas    = var.admin_max_replicas
    cooldown_period = 90

    cpu_utilization {
      target = var.autoscaler_cpu_target
    }
  }
}

# ----- Verifier MIG (regional) -----
resource "google_compute_region_instance_group_manager" "verifier" {
  name               = "sso-verifier-mig-${local.suffix}"
  base_instance_name = "sso-verifier"
  region             = var.region

  version {
    instance_template = google_compute_instance_template.verifier.id
  }

  named_port {
    name = "verifier"
    port = local.ports.verifier
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.verifier.id
    initial_delay_sec = 120
  }

  update_policy {
    type                           = "PROACTIVE"
    minimal_action                 = "REPLACE"
    most_disruptive_allowed_action = "REPLACE"
    max_surge_fixed                = 2
    max_unavailable_fixed          = 0
  }
}

resource "google_compute_region_autoscaler" "verifier" {
  name   = "sso-verifier-autoscaler-${local.suffix}"
  region = var.region
  target = google_compute_region_instance_group_manager.verifier.id

  autoscaling_policy {
    min_replicas    = var.verifier_min_replicas
    max_replicas    = var.verifier_max_replicas
    cooldown_period = 90

    cpu_utilization {
      target = var.autoscaler_cpu_target
    }
  }
}

###############################################################################
# 7. HEALTH CHECKS
###############################################################################

resource "google_compute_health_check" "gateway" {
  name                = "sso-gateway-hc-${local.suffix}"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  tcp_health_check {
    port = local.ports.gateway
  }
}

resource "google_compute_health_check" "admin" {
  name                = "sso-admin-hc-${local.suffix}"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  tcp_health_check {
    port = local.ports.admin
  }
}

resource "google_compute_health_check" "verifier" {
  name                = "sso-verifier-hc-${local.suffix}"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  tcp_health_check {
    port = local.ports.verifier
  }
}

###############################################################################
# 8. GLOBAL TCP LOAD BALANCER — GATEWAY
###############################################################################

resource "google_compute_global_address" "gateway_lb" {
  name = "sso-gateway-lb-ip-${local.suffix}"
}

resource "google_compute_backend_service" "gateway" {
  name                  = "sso-gateway-backend-${local.suffix}"
  protocol              = "TCP"
  port_name             = "gateway"
  timeout_sec           = 30
  load_balancing_scheme = "EXTERNAL"
  health_checks         = [google_compute_health_check.gateway.id]

  backend {
    group           = google_compute_region_instance_group_manager.gateway.instance_group
    balancing_mode  = "UTILIZATION"
    max_utilization = 0.8
  }

  connection_draining_timeout_sec = 30

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_target_tcp_proxy" "gateway" {
  name            = "sso-gateway-tcp-proxy-${local.suffix}"
  backend_service = google_compute_backend_service.gateway.id
}

resource "google_compute_global_forwarding_rule" "gateway" {
  name                  = "sso-gateway-fwd-${local.suffix}"
  ip_address            = google_compute_global_address.gateway_lb.address
  ip_protocol           = "TCP"
  port_range            = tostring(local.ports.gateway)
  target                = google_compute_target_tcp_proxy.gateway.id
  load_balancing_scheme = "EXTERNAL"
}

###############################################################################
# 9. INTERNAL HTTPS LOAD BALANCER — ADMIN
###############################################################################

resource "google_compute_address" "admin_ilb" {
  name         = "sso-admin-ilb-ip-${local.suffix}"
  subnetwork   = google_compute_subnetwork.private.id
  address_type = "INTERNAL"
  region       = var.region
}

resource "google_compute_region_health_check" "admin_ilb" {
  name                = "sso-admin-ilb-hc-${local.suffix}"
  region              = var.region
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  tcp_health_check {
    port = local.ports.admin
  }
}

resource "google_compute_region_backend_service" "admin" {
  name                  = "sso-admin-ilb-backend-${local.suffix}"
  region                = var.region
  protocol              = "TCP"
  load_balancing_scheme = "INTERNAL"
  health_checks         = [google_compute_region_health_check.admin_ilb.id]

  backend {
    group           = google_compute_region_instance_group_manager.admin.instance_group
    balancing_mode  = "CONNECTION"
    max_connections = 1000
  }

  connection_draining_timeout_sec = 30
}

resource "google_compute_forwarding_rule" "admin_ilb" {
  name                  = "sso-admin-ilb-fwd-${local.suffix}"
  region                = var.region
  ip_address            = google_compute_address.admin_ilb.address
  ip_protocol           = "TCP"
  ports                 = [tostring(local.ports.admin)]
  load_balancing_scheme = "INTERNAL"
  backend_service       = google_compute_region_backend_service.admin.id
  subnetwork            = google_compute_subnetwork.private.id
}

###############################################################################
# 10. TSS NODES — 5 SEPARATE VMs IN DIFFERENT ZONES
###############################################################################

resource "google_compute_instance" "tss" {
  for_each = { for i in range(var.tss_node_count) : "tss-${i}" => {
    index = i
    zone  = local.tss_zones[i]
    # Primary region nodes use primary subnet, secondary region nodes use secondary subnet
    subnet = i < length(var.zones) ? google_compute_subnetwork.private.id : google_compute_subnetwork.private_secondary.id
  } }

  name         = "sso-tss-${each.value.index}-${local.suffix}"
  machine_type = var.machine_type_default
  zone         = each.value.zone
  tags         = ["sso-service", "sso-tss"]
  labels       = merge(local.common_labels, { service = "tss", node_index = tostring(each.value.index) })

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = each.value.subnet
    # No external IP — private only
  }

  metadata = {
    startup-script = replace(
      local.startup_scripts["tss"],
      "SSO_LOG_LEVEL=info",
      join("\n", [
        "SSO_LOG_LEVEL=info",
        "SSO_TSS_NODE_INDEX=${each.value.index}",
        "SSO_TSS_NODE_COUNT=${var.tss_node_count}",
        "SSO_TSS_THRESHOLD=${var.tss_threshold}",
        "SSO_TSS_PEERS=${join(",", [for j in range(var.tss_node_count) : "sso-tss-${j}-${local.suffix}:${local.ports.tss}" if j != each.value.index])}",
      ])
    )
    service-name = "tss"
    service-port = tostring(local.ports.tss)
    node-index   = tostring(each.value.index)
  }

  service_account {
    email  = google_service_account.tss.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  allow_stopping_for_update = true
}

###############################################################################
# 11. AUDIT BFT NODES — 7 SEPARATE VMs ACROSS ZONES
###############################################################################

resource "google_compute_instance" "audit" {
  for_each = { for i in range(var.audit_node_count) : "audit-${i}" => {
    index = i
    zone  = local.audit_zones[i]
    subnet = (
      contains(var.zones, local.audit_zones[i])
      ? google_compute_subnetwork.private.id
      : google_compute_subnetwork.private_secondary.id
    )
  } }

  name         = "sso-audit-${each.value.index}-${local.suffix}"
  machine_type = var.machine_type_default
  zone         = each.value.zone
  tags         = ["sso-service", "sso-audit"]
  labels       = merge(local.common_labels, { service = "audit", node_index = tostring(each.value.index) })

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 50 # Larger disk for audit log storage
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = each.value.subnet
  }

  metadata = {
    startup-script = replace(
      local.startup_scripts["audit"],
      "SSO_LOG_LEVEL=info",
      join("\n", [
        "SSO_LOG_LEVEL=info",
        "SSO_AUDIT_NODE_INDEX=${each.value.index}",
        "SSO_AUDIT_NODE_COUNT=${var.audit_node_count}",
        "SSO_AUDIT_QUORUM=${var.audit_quorum}",
        "SSO_AUDIT_PEERS=${join(",", [for j in range(var.audit_node_count) : "sso-audit-${j}-${local.suffix}:${local.ports.audit}" if j != each.value.index])}",
      ])
    )
    service-name = "audit"
    service-port = tostring(local.ports.audit)
    node-index   = tostring(each.value.index)
  }

  service_account {
    email  = google_service_account.audit.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  allow_stopping_for_update = true
}

###############################################################################
# 12. HA PAIR — ORCHESTRATOR (2 VMs in different zones)
###############################################################################

resource "google_compute_instance" "orchestrator" {
  count = 2

  name         = "sso-orchestrator-${count.index}-${local.suffix}"
  machine_type = var.machine_type_default
  zone         = var.zones[count.index]
  tags         = ["sso-service", "sso-orchestrator"]
  labels       = merge(local.common_labels, { service = "orchestrator", ha_index = tostring(count.index) })

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }

  metadata = {
    startup-script = replace(
      local.startup_scripts["orchestrator"],
      "SSO_LOG_LEVEL=info",
      join("\n", [
        "SSO_LOG_LEVEL=info",
        "SSO_HA_INDEX=${count.index}",
        "SSO_HA_PEER=sso-orchestrator-${1 - count.index}-${local.suffix}:${local.ports.orchestrator}",
        "SSO_OPAQUE_ENDPOINTS=${join(",", [for i in range(2) : "sso-opaque-${i}-${local.suffix}:${local.ports.opaque}"])}",
        "SSO_TSS_ENDPOINTS=${join(",", [for i in range(var.tss_node_count) : "sso-tss-${i}-${local.suffix}:${local.ports.tss}"])}",
        "SSO_RATCHET_ENDPOINTS=${join(",", [for i in range(2) : "sso-ratchet-${i}-${local.suffix}:${local.ports.ratchet}"])}",
        "SSO_RISK_ENDPOINT=sso-risk-0-${local.suffix}:${local.ports.risk}",
        "SSO_AUDIT_ENDPOINTS=${join(",", [for i in range(var.audit_node_count) : "sso-audit-${i}-${local.suffix}:${local.ports.audit}"])}",
        "SSO_KT_ENDPOINT=sso-kt-0-${local.suffix}:${local.ports.kt}",
        "SSO_DB_HOST=${google_sql_database_instance.primary.private_ip_address}",
        "SSO_DB_NAME=${var.db_name}",
      ])
    )
    service-name = "orchestrator"
    service-port = tostring(local.ports.orchestrator)
  }

  service_account {
    email  = google_service_account.orchestrator.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  allow_stopping_for_update = true
}

###############################################################################
# 13. HA PAIR — OPAQUE (2 VMs in different zones)
###############################################################################

resource "google_compute_instance" "opaque" {
  count = 2

  name         = "sso-opaque-${count.index}-${local.suffix}"
  machine_type = var.machine_type_default
  zone         = var.zones[count.index]
  tags         = ["sso-service", "sso-opaque"]
  labels       = merge(local.common_labels, { service = "opaque", ha_index = tostring(count.index) })

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }

  metadata = {
    startup-script = replace(
      local.startup_scripts["opaque"],
      "SSO_LOG_LEVEL=info",
      join("\n", [
        "SSO_LOG_LEVEL=info",
        "SSO_HA_INDEX=${count.index}",
        "SSO_HA_PEER=sso-opaque-${1 - count.index}-${local.suffix}:${local.ports.opaque}",
        "SSO_DB_HOST=${google_sql_database_instance.primary.private_ip_address}",
        "SSO_DB_NAME=${var.db_name}",
      ])
    )
    service-name = "opaque"
    service-port = tostring(local.ports.opaque)
  }

  service_account {
    email  = google_service_account.opaque.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  allow_stopping_for_update = true
}

###############################################################################
# 14. HA PAIR — RATCHET (2 VMs in different zones)
###############################################################################

resource "google_compute_instance" "ratchet" {
  count = 2

  name         = "sso-ratchet-${count.index}-${local.suffix}"
  machine_type = var.machine_type_default
  zone         = var.zones[count.index]
  tags         = ["sso-service", "sso-ratchet"]
  labels       = merge(local.common_labels, { service = "ratchet", ha_index = tostring(count.index) })

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }

  metadata = {
    startup-script = replace(
      local.startup_scripts["ratchet"],
      "SSO_LOG_LEVEL=info",
      join("\n", [
        "SSO_LOG_LEVEL=info",
        "SSO_HA_INDEX=${count.index}",
        "SSO_HA_PEER=sso-ratchet-${1 - count.index}-${local.suffix}:${local.ports.ratchet}",
      ])
    )
    service-name = "ratchet"
    service-port = tostring(local.ports.ratchet)
  }

  service_account {
    email  = google_service_account.ratchet.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  allow_stopping_for_update = true
}

###############################################################################
# 15. SINGLE VM — RISK
###############################################################################

resource "google_compute_instance" "risk" {
  name         = "sso-risk-0-${local.suffix}"
  machine_type = var.machine_type_small
  zone         = var.zones[0]
  tags         = ["sso-service", "sso-risk"]
  labels       = merge(local.common_labels, { service = "risk" })

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }

  metadata = {
    startup-script = local.startup_scripts["risk"]
    service-name   = "risk"
    service-port   = tostring(local.ports.risk)
  }

  service_account {
    email  = google_service_account.risk.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  allow_stopping_for_update = true
}

###############################################################################
# 16. SINGLE VM — KEY TRANSPARENCY
###############################################################################

resource "google_compute_instance" "kt" {
  name         = "sso-kt-0-${local.suffix}"
  machine_type = var.machine_type_small
  zone         = var.zones[1]
  tags         = ["sso-service", "sso-kt"]
  labels       = merge(local.common_labels, { service = "kt" })

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }

  metadata = {
    startup-script = local.startup_scripts["kt"]
    service-name   = "kt"
    service-port   = tostring(local.ports.kt)
  }

  service_account {
    email  = google_service_account.kt.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  allow_stopping_for_update = true
}

###############################################################################
# 17. CLOUD SQL POSTGRESQL — HA WITH FAILOVER REPLICA
###############################################################################

resource "google_sql_database_instance" "primary" {
  name                = "sso-db-primary-${local.suffix}"
  database_version    = "POSTGRES_16"
  region              = var.region
  deletion_protection = true

  depends_on = [google_service_networking_connection.private_vpc]

  settings {
    tier              = var.db_tier
    availability_type = "REGIONAL" # Automatic HA failover
    disk_size         = var.db_disk_size_gb
    disk_type         = "PD_SSD"
    disk_autoresize   = true

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.sso_vpc.id
      enable_private_path_for_google_cloud_services = true
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "02:00" # 2 AM IST window
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = 30
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = 7 # Sunday
      hour         = 3
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
      value = "1000" # Log queries > 1s
    }

    database_flags {
      name  = "max_connections"
      value = "200"
    }

    user_labels = local.common_labels

    insights_config {
      query_insights_enabled  = true
      query_plans_per_minute  = 5
      query_string_length     = 1024
      record_application_tags = true
      record_client_address   = true
    }
  }
}

resource "google_sql_database_instance" "replica" {
  name                 = "sso-db-replica-${local.suffix}"
  master_instance_name = google_sql_database_instance.primary.name
  database_version     = "POSTGRES_16"
  region               = var.region
  deletion_protection  = true

  replica_configuration {
    failover_target = true
  }

  settings {
    tier            = var.db_tier
    disk_size       = var.db_disk_size_gb
    disk_type       = "PD_SSD"
    disk_autoresize = true

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.sso_vpc.id
      enable_private_path_for_google_cloud_services = true
    }

    user_labels = merge(local.common_labels, { role = "replica" })
  }
}

resource "google_sql_database" "sso" {
  name     = var.db_name
  instance = google_sql_database_instance.primary.name
}

resource "google_sql_user" "sso_admin" {
  name     = var.db_user
  instance = google_sql_database_instance.primary.name
  password = var.db_password
}

###############################################################################
# 18. CLOUD DNS — INTERNAL SERVICE DISCOVERY
###############################################################################

resource "google_dns_managed_zone" "internal" {
  name        = "sso-internal-${local.suffix}"
  dns_name    = "sso.internal."
  description = "Internal DNS for SSO service discovery"
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.sso_vpc.id
    }
  }
}

# DNS records for singleton/HA services
resource "google_dns_record_set" "orchestrator" {
  name         = "orchestrator.sso.internal."
  type         = "A"
  ttl          = 30
  managed_zone = google_dns_managed_zone.internal.name
  rrdatas      = [for i in google_compute_instance.orchestrator : i.network_interface[0].network_ip]
}

resource "google_dns_record_set" "opaque" {
  name         = "opaque.sso.internal."
  type         = "A"
  ttl          = 30
  managed_zone = google_dns_managed_zone.internal.name
  rrdatas      = [for i in google_compute_instance.opaque : i.network_interface[0].network_ip]
}

resource "google_dns_record_set" "ratchet" {
  name         = "ratchet.sso.internal."
  type         = "A"
  ttl          = 30
  managed_zone = google_dns_managed_zone.internal.name
  rrdatas      = [for i in google_compute_instance.ratchet : i.network_interface[0].network_ip]
}

resource "google_dns_record_set" "risk" {
  name         = "risk.sso.internal."
  type         = "A"
  ttl          = 60
  managed_zone = google_dns_managed_zone.internal.name
  rrdatas      = [google_compute_instance.risk.network_interface[0].network_ip]
}

resource "google_dns_record_set" "kt" {
  name         = "kt.sso.internal."
  type         = "A"
  ttl          = 60
  managed_zone = google_dns_managed_zone.internal.name
  rrdatas      = [google_compute_instance.kt.network_interface[0].network_ip]
}

resource "google_dns_record_set" "tss" {
  for_each     = google_compute_instance.tss
  name         = "${each.key}.sso.internal."
  type         = "A"
  ttl          = 30
  managed_zone = google_dns_managed_zone.internal.name
  rrdatas      = [each.value.network_interface[0].network_ip]
}

resource "google_dns_record_set" "audit" {
  for_each     = google_compute_instance.audit
  name         = "${each.key}.sso.internal."
  type         = "A"
  ttl          = 30
  managed_zone = google_dns_managed_zone.internal.name
  rrdatas      = [each.value.network_interface[0].network_ip]
}

resource "google_dns_record_set" "admin_ilb" {
  name         = "admin.sso.internal."
  type         = "A"
  ttl          = 30
  managed_zone = google_dns_managed_zone.internal.name
  rrdatas      = [google_compute_address.admin_ilb.address]
}

resource "google_dns_record_set" "db" {
  name         = "db.sso.internal."
  type         = "A"
  ttl          = 60
  managed_zone = google_dns_managed_zone.internal.name
  rrdatas      = [google_sql_database_instance.primary.private_ip_address]
}
