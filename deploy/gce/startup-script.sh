#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — GCE VM Startup Script
# ==============================================================================
# Generic VM startup script passed via instance metadata. Each VM has its
# SERVICE_NAME set in metadata; this script bootstraps the correct binary.
#
# What it does:
#   1. Reads SERVICE_NAME + CONFIG from instance metadata
#   2. Downloads the binary from GCS (version from BINARY_VERSION metadata)
#   3. Creates milnet user/group (uid/gid 1000)
#   4. Sets up /var/lib/milnet/{service}/ with 0700 perms
#   5. Writes /etc/milnet/{service}.env from metadata
#   6. Creates and enables a systemd unit
#   7. Installs and configures Cloud Logging ops-agent
#   8. Hardens the VM (sysctl, core dumps, ptrace)
#   9. Starts the service
#
# Expected instance metadata keys:
#   SERVICE_NAME     — e.g. "gateway", "orchestrator", "tss"
#   BINARY_BUCKET    — e.g. "milnet-sso-binaries-lmsforshantithakur"
#   BINARY_VERSION   — e.g. "v20260326-120000" or "latest"
#   SERVICE_ENV      — newline-separated KEY=VALUE pairs for the .env file
#   SERVICE_PORT     — port the service listens on (for health checks)
#   SERVICE_INSTANCE — (optional) instance number for multi-instance services (tss)
# ==============================================================================

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# ── Helpers ──────────────────────────────────────────────────────────────────

log_info()  { echo "[STARTUP] INFO:  $(date -Iseconds) $*"; }
log_error() { echo "[STARTUP] ERROR: $(date -Iseconds) $*" >&2; }
die()       { log_error "$@"; exit 1; }

# Fetch a metadata attribute from the instance metadata server.
metadata() {
    local key="$1"
    curl -sf \
        -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/${key}" \
        2>/dev/null
}

# Fetch project-level metadata.
project_metadata() {
    local key="$1"
    curl -sf \
        -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/project/attributes/${key}" \
        2>/dev/null
}

# ── Step 1: Read metadata ────────────────────────────────────────────────────

log_info "Reading instance metadata ..."

SERVICE_NAME=$(metadata "SERVICE_NAME") \
    || die "Missing required metadata key: SERVICE_NAME"

BINARY_BUCKET=$(metadata "BINARY_BUCKET") \
    || die "Missing required metadata key: BINARY_BUCKET"

BINARY_VERSION=$(metadata "BINARY_VERSION" || echo "latest")
SERVICE_ENV=$(metadata "SERVICE_ENV" || echo "")
SERVICE_PORT=$(metadata "SERVICE_PORT" || echo "")
SERVICE_INSTANCE=$(metadata "SERVICE_INSTANCE" || echo "")

# Resolve "latest" to actual version tag.
if [[ "${BINARY_VERSION}" == "latest" ]]; then
    log_info "Resolving LATEST version from GCS ..."
    BINARY_VERSION=$(gsutil cat "gs://${BINARY_BUCKET}/LATEST" 2>/dev/null) \
        || die "Could not read LATEST pointer from gs://${BINARY_BUCKET}/LATEST"
fi

# Construct the unit name: milnet-tss@1 for tss instances, milnet-gateway otherwise.
if [[ -n "${SERVICE_INSTANCE}" ]]; then
    UNIT_NAME="milnet-${SERVICE_NAME}@${SERVICE_INSTANCE}"
    BINARY_NAME="${SERVICE_NAME}"
else
    UNIT_NAME="milnet-${SERVICE_NAME}"
    BINARY_NAME="${SERVICE_NAME}"
fi

log_info "Service: ${SERVICE_NAME} (unit: ${UNIT_NAME})"
log_info "Binary version: ${BINARY_VERSION}"
log_info "Binary bucket: ${BINARY_BUCKET}"

# ── Step 2: Download binary from GCS ─────────────────────────────────────────

BIN_DIR="/opt/milnet/bin"
mkdir -p "${BIN_DIR}"

BINARY_PATH="${BIN_DIR}/${BINARY_NAME}"
GCS_PATH="gs://${BINARY_BUCKET}/${BINARY_VERSION}/${BINARY_NAME}"

log_info "Downloading ${GCS_PATH} ..."
gsutil cp "${GCS_PATH}" "${BINARY_PATH}"
chmod 0555 "${BINARY_PATH}"

# Verify the download using the SHA256 manifest.
log_info "Verifying binary integrity ..."
EXPECTED_SHA=$(gsutil cat "gs://${BINARY_BUCKET}/${BINARY_VERSION}/SHA256SUMS" \
    | grep "  ${BINARY_NAME}$" | awk '{print $1}')

if [[ -n "${EXPECTED_SHA}" ]]; then
    ACTUAL_SHA=$(sha256sum "${BINARY_PATH}" | awk '{print $1}')
    if [[ "${EXPECTED_SHA}" != "${ACTUAL_SHA}" ]]; then
        die "SHA-256 mismatch for ${BINARY_NAME}: expected=${EXPECTED_SHA} actual=${ACTUAL_SHA}"
    fi
    log_info "Binary integrity verified (SHA-256: ${ACTUAL_SHA:0:16}...)"
else
    log_info "WARNING: No SHA256 manifest entry found for ${BINARY_NAME}, skipping verification."
fi

# ── Step 3: Create milnet user and group ─────────────────────────────────────

log_info "Creating milnet user/group ..."

if ! getent group milnet >/dev/null 2>&1; then
    groupadd --gid 1000 milnet
fi

if ! id -u milnet >/dev/null 2>&1; then
    useradd \
        --uid 1000 \
        --gid 1000 \
        --system \
        --shell /usr/sbin/nologin \
        --home-dir /var/lib/milnet \
        --no-create-home \
        milnet
fi

# ── Step 4: Set up data directory ────────────────────────────────────────────

DATA_DIR="/var/lib/milnet/${SERVICE_NAME}"
CONF_DIR="/etc/milnet"

log_info "Creating data directory: ${DATA_DIR}"
mkdir -p "${DATA_DIR}"
chown milnet:milnet "${DATA_DIR}"
chmod 0700 "${DATA_DIR}"

mkdir -p "${CONF_DIR}"
chmod 0755 "${CONF_DIR}"

# ── Step 5: Write environment file from metadata ────────────────────────────

ENV_FILE="${CONF_DIR}/${SERVICE_NAME}.env"

log_info "Writing environment file: ${ENV_FILE}"

cat > "${ENV_FILE}" <<ENVEOF
# Auto-generated by MILNET GCE startup script
# Service: ${SERVICE_NAME}
# Version: ${BINARY_VERSION}
# Generated: $(date -Iseconds)

MILNET_DATA_DIR=${DATA_DIR}
RUST_LOG=info
ENVEOF

# Append service-specific env vars from metadata.
if [[ -n "${SERVICE_ENV}" ]]; then
    echo "" >> "${ENV_FILE}"
    echo "# Service-specific configuration from instance metadata" >> "${ENV_FILE}"
    echo "${SERVICE_ENV}" >> "${ENV_FILE}"
fi

chown root:milnet "${ENV_FILE}"
chmod 0640 "${ENV_FILE}"

# ── Step 6: Create systemd service unit ──────────────────────────────────────

UNIT_FILE="/etc/systemd/system/${UNIT_NAME}.service"

log_info "Creating systemd unit: ${UNIT_FILE}"

cat > "${UNIT_FILE}" <<UNITEOF
# Auto-generated by MILNET GCE startup script — do not edit manually.
[Unit]
Description=MILNET SSO - ${SERVICE_NAME}
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=milnet
Group=milnet

ExecStart=${BINARY_PATH}
Restart=on-failure
RestartSec=5
WatchdogSec=60

# ── Filesystem hardening ──
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_DIR}
PrivateTmp=yes
PrivateDevices=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectHostname=yes
ProtectClock=yes

# ── Process hardening ──
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
ProtectProc=invisible
ProcSubset=pid

# ── Resource limits ──
MemoryMax=512M
TasksMax=64
LimitNOFILE=65536
LimitMEMLOCK=infinity

# ── Security context ──
SecureBits=noroot
UMask=0077

# ── Environment ──
EnvironmentFile=${ENV_FILE}

# ── Logging ──
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${UNIT_NAME}

[Install]
WantedBy=multi-user.target
UNITEOF

# ── Step 7: Enable and start the service ─────────────────────────────────────

log_info "Enabling and starting ${UNIT_NAME} ..."
systemctl daemon-reload
systemctl enable "${UNIT_NAME}.service"
systemctl start "${UNIT_NAME}.service"

# ── Step 8: Install and configure Cloud Logging ops-agent ────────────────────

log_info "Setting up Cloud Logging via ops-agent ..."

if ! command -v google_cloud_ops_agent_engine &>/dev/null; then
    curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
    bash add-google-cloud-ops-agent-repo.sh --also-install
    rm -f add-google-cloud-ops-agent-repo.sh
fi

# Configure ops-agent to pick up MILNET journal logs.
OPSAGENT_CONF="/etc/google-cloud-ops-agent/config.yaml"
mkdir -p "$(dirname "${OPSAGENT_CONF}")"

cat > "${OPSAGENT_CONF}" <<'OPSEOF'
# MILNET SSO — Cloud Ops Agent configuration
logging:
  receivers:
    milnet_journal:
      type: systemd_journald
      units:
        - milnet-gateway
        - milnet-orchestrator
        - milnet-opaque
        - milnet-tss@1
        - milnet-tss@2
        - milnet-tss@3
        - milnet-tss@4
        - milnet-tss@5
        - milnet-verifier
        - milnet-ratchet
        - milnet-audit
        - milnet-admin
    syslog:
      type: files
      include_paths:
        - /var/log/syslog
  service:
    pipelines:
      milnet_pipeline:
        receivers:
          - milnet_journal
      default_pipeline:
        receivers:
          - syslog
metrics:
  receivers:
    hostmetrics:
      type: hostmetrics
      collection_interval: 30s
  service:
    pipelines:
      default_pipeline:
        receivers:
          - hostmetrics
OPSEOF

systemctl restart google-cloud-ops-agent || log_info "WARNING: ops-agent restart failed (non-fatal)"

# ── Step 9: Harden the VM ────────────────────────────────────────────────────

log_info "Applying VM hardening ..."

# --- Disable core dumps ---
cat > /etc/security/limits.d/99-milnet-nocore.conf <<'LIMEOF'
# MILNET: Disable core dumps to prevent cryptographic key leakage.
*               hard    core            0
*               soft    core            0
LIMEOF

# Also via sysctl for processes that bypass limits.
cat > /etc/sysctl.d/99-milnet-hardening.conf <<'SYSEOF'
# ==============================================================================
# MILNET SSO — Kernel Hardening (GCE)
# ==============================================================================

# --- Core dumps ---
# Disable core dumps globally. Core dumps can contain cryptographic keys,
# session tokens, and other sensitive material from process memory.
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false

# --- Ptrace restriction ---
# Restrict ptrace to parent-child relationships only (YAMA scope 1).
# Prevents one compromised service from attaching to another.
kernel.yama.ptrace_scope = 1

# --- ASLR ---
# Full address-space layout randomization (brk, mmap, stack, VDSO).
kernel.randomize_va_space = 2

# --- Kernel pointer hiding ---
# Hide kernel pointers in /proc from unprivileged users.
kernel.kptr_restrict = 2

# --- dmesg restriction ---
# Only root can read kernel log (prevents information disclosure).
kernel.dmesg_restrict = 1

# --- Symlink/hardlink protection ---
# Prevent symlink/hardlink attacks in world-writable sticky directories.
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# --- Network hardening ---
# Disable IP forwarding (VMs are endpoints, not routers).
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Ignore ICMP redirects (prevent MITM route injection).
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Ignore source-routed packets.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Enable SYN cookies (SYN flood protection).
net.ipv4.tcp_syncookies = 1

# Log martian packets (aids forensic analysis).
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP echo broadcasts (Smurf attack mitigation).
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses.
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering (anti-spoofing).
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- TCP hardening ---
# Reduce TIME_WAIT for faster connection recycling under load.
net.ipv4.tcp_fin_timeout = 15
# Enable TCP keepalive with aggressive timeouts to detect dead peers.
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3

# --- Memory ---
# Restrict unprivileged BPF (prevent BPF-based exfiltration).
kernel.unprivileged_bpf_disabled = 1
# Restrict userfaultfd to root only.
vm.unprivileged_userfaultfd = 0
SYSEOF

sysctl --system >/dev/null 2>&1

# --- Disable unnecessary services ---
for svc in apport whoopsie snapd; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        systemctl stop "${svc}" 2>/dev/null || true
        systemctl disable "${svc}" 2>/dev/null || true
        log_info "Disabled unnecessary service: ${svc}"
    fi
done

# ── Done ─────────────────────────────────────────────────────────────────────

log_info "==========================================="
log_info "Startup complete for ${SERVICE_NAME}"
log_info "  Binary  : ${BINARY_PATH}"
log_info "  Version : ${BINARY_VERSION}"
log_info "  Data dir: ${DATA_DIR}"
log_info "  Env file: ${ENV_FILE}"
log_info "  Unit    : ${UNIT_NAME}"
log_info "==========================================="
