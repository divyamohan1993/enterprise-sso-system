#!/usr/bin/env bash
# MILNET SSO System — VM Provisioning Script
#
# Provisions a minimum-5-VM deployment with the MILNET SSO system.
# Installs the Rust toolchain, copies the pre-built binary, sets up systemd
# services, configures MILNET_CLUSTER_PEERS, and starts all services.
#
# Usage:
#   ./provision.sh VM1_IP VM2_IP VM3_IP VM4_IP VM5_IP [VM6_IP ...]
#
# Prerequisites:
#   - SSH key-based access to all VMs (as root or sudo-capable user)
#   - Pre-built release binary at ../target/release/ or BINARY_DIR env var
#   - Environment files populated in ./env/

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY_DIR="${BINARY_DIR:-$PROJECT_ROOT/target/release}"
ENV_DIR="$SCRIPT_DIR/env"
SYSTEMD_DIR="$SCRIPT_DIR"
SSH_USER="${SSH_USER:-root}"
SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=accept-new -o ConnectTimeout=10}"
INSTALL_DIR="/opt/milnet/bin"
CONFIG_DIR="/etc/milnet"
DATA_DIR="/var/lib/milnet"
MILNET_USER="milnet"

# Service binaries (all compiled from the same workspace)
SERVICES=(gateway orchestrator opaque tss verifier ratchet risk audit kt admin)

# ── Argument validation ────────────────────────────────────────────────────────

if [ "$#" -lt 5 ]; then
    echo "ERROR: Minimum 5 VMs required for MILNET deployment."
    echo ""
    echo "Reason: FROST 3-of-5 threshold signing requires 5 separate hosts."
    echo "  - Raft consensus needs 3-node quorum across distinct VMs"
    echo "  - OPAQUE 2-of-3 shares must reside on separate hosts"
    echo "  - BFT audit (f=2) needs processes across multiple failure domains"
    echo ""
    echo "Usage: $0 VM1_IP VM2_IP VM3_IP VM4_IP VM5_IP [VM6_IP ...]"
    exit 1
fi

VM1="$1"  # gateway + admin
VM2="$2"  # auth-primary: orchestrator, opaque-1, tss-coordinator
VM3="$3"  # auth-replica-1: orchestrator, opaque-2, tss-signer-1, tss-signer-2
VM4="$4"  # auth-replica-2: orchestrator, opaque-3, tss-signer-3, tss-signer-4
VM5="$5"  # verification: verifier, ratchet, risk, audit, kt, tss-signer-5

ALL_VMS=("$@")

echo "================================================================"
echo "MILNET SSO System — VM Provisioning"
echo "================================================================"
echo "VM-1 (gateway+admin):      $VM1"
echo "VM-2 (auth-primary):       $VM2"
echo "VM-3 (auth-replica-1):     $VM3"
echo "VM-4 (auth-replica-2):     $VM4"
echo "VM-5 (verification+audit): $VM5"
for i in $(seq 5 $((${#ALL_VMS[@]} - 1))); do
    echo "VM-$((i+1)) (additional):       ${ALL_VMS[$i]}"
done
echo "================================================================"

# ── Helper functions ───────────────────────────────────────────────────────────

ssh_cmd() {
    local host="$1"
    shift
    ssh $SSH_OPTS "$SSH_USER@$host" "$@"
}

scp_cmd() {
    scp $SSH_OPTS "$@"
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

check_binary() {
    local svc="$1"
    local binary_path="$BINARY_DIR/$svc"
    if [ ! -f "$binary_path" ]; then
        echo "ERROR: Binary not found: $binary_path"
        echo "Build first: cargo build --release --bin $svc"
        exit 1
    fi
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────

log "Running pre-flight checks..."

# Verify all binaries exist
for svc in "${SERVICES[@]}"; do
    check_binary "$svc"
done
log "All ${#SERVICES[@]} service binaries found in $BINARY_DIR"

# Verify SSH connectivity to all VMs
for vm in "${ALL_VMS[@]}"; do
    if ! ssh_cmd "$vm" "true" 2>/dev/null; then
        echo "ERROR: Cannot SSH to $vm. Ensure SSH key access is configured."
        exit 1
    fi
done
log "SSH connectivity verified for all ${#ALL_VMS[@]} VMs"

# ── Phase 1: Install prerequisites on all VMs ─────────────────────────────────

install_prerequisites() {
    local vm="$1"
    log "[$vm] Installing prerequisites..."

    ssh_cmd "$vm" bash -s << 'REMOTE_SCRIPT'
set -euo pipefail

# Create milnet system user (no login shell, no home directory in /home)
if ! id milnet &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin milnet
fi

# Create directory structure
mkdir -p /opt/milnet/bin
mkdir -p /etc/milnet/env
mkdir -p /etc/milnet/tls
mkdir -p /var/lib/milnet/audit
mkdir -p /var/lib/milnet/kt
mkdir -p /var/lib/milnet/tss_nonce_state
mkdir -p /var/log/milnet

# Set ownership
chown -R milnet:milnet /var/lib/milnet
chown -R milnet:milnet /var/log/milnet
chown -R root:milnet /etc/milnet
chmod 750 /etc/milnet/env
chmod 750 /etc/milnet/tls

# Install Rust toolchain (for future local builds if needed)
if ! command -v rustup &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.88.0
fi

# Ensure necessary system packages
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq libssl-dev pkg-config ca-certificates
elif command -v dnf &>/dev/null; then
    dnf install -y openssl-devel pkg-config ca-certificates
fi

# Configure kernel parameters for crypto workloads
cat > /etc/sysctl.d/99-milnet.conf << 'SYSCTL'
# Allow mlock for key material protection
vm.max_map_count = 262144
# TCP hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
# Disable core dumps (key material protection)
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
SYSCTL
sysctl --system -q

# Set mlock limits for milnet user
cat > /etc/security/limits.d/milnet.conf << 'LIMITS'
milnet soft memlock unlimited
milnet hard memlock unlimited
milnet soft nofile 65536
milnet hard nofile 65536
LIMITS

echo "Prerequisites installed successfully"
REMOTE_SCRIPT
}

for vm in "${ALL_VMS[@]}"; do
    install_prerequisites "$vm" &
done
wait
log "Prerequisites installed on all VMs"

# ── Phase 1b: Configure nftables firewall on all VMs ─────────────────────────

configure_firewall() {
    local vm="$1"
    local ROLE="$2"

    log "[$vm] Configuring nftables firewall (role: $ROLE)..."

    ssh_cmd "$vm" bash -s "$ROLE" << 'FIREWALL_SCRIPT'
set -euo pipefail
ROLE="$1"

log_info() { echo "[FIREWALL] $*"; }

log_info "Configuring nftables firewall..."

apt-get install -y nftables >/dev/null 2>&1 || yum install -y nftables >/dev/null 2>&1

cat > /etc/nftables.conf << 'NFTEOF'
#!/usr/sbin/nft -f
flush ruleset

table inet milnet_filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established/related connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Allow SSH for management (restrict to bastion IP in production)
        tcp dport 22 accept

        # Allow ICMP for health checks
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Service-specific rules added per role below
        include "/etc/nftables.d/*.nft"

        # Log and drop everything else
        log prefix "MILNET_DROP: " drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
NFTEOF

mkdir -p /etc/nftables.d

# Role-specific rules
case "${ROLE}" in
    gateway)
        echo 'tcp dport 9100 accept comment "MILNET Gateway TLS"' > /etc/nftables.d/service.nft
        echo 'tcp dport 10100 accept comment "MILNET Gateway Health"' >> /etc/nftables.d/service.nft
        ;;
    admin)
        echo 'tcp dport 8080 ip saddr 127.0.0.1 accept comment "MILNET Admin localhost only"' > /etc/nftables.d/service.nft
        ;;
    *)
        # Inter-service SHARD ports (9001-9020)
        echo 'tcp dport 9001-9020 accept comment "MILNET SHARD inter-service"' > /etc/nftables.d/service.nft
        ;;
esac

systemctl enable nftables
nft -f /etc/nftables.conf
log_info "Firewall configured with default-deny policy"
FIREWALL_SCRIPT
}

# VM1 runs gateway + admin; gateway needs external access, admin is localhost-only
configure_firewall "$VM1" "gateway" &
configure_firewall "$VM2" "shard" &
configure_firewall "$VM3" "shard" &
configure_firewall "$VM4" "shard" &
configure_firewall "$VM5" "shard" &
wait
log "Firewall configured on all VMs"

# ── Phase 2: Copy binaries to all VMs ─────────────────────────────────────────

copy_binaries() {
    local vm="$1"
    shift
    local services=("$@")

    log "[$vm] Copying binaries: ${services[*]}"
    for svc in "${services[@]}"; do
        scp_cmd "$BINARY_DIR/$svc" "$SSH_USER@$vm:$INSTALL_DIR/$svc"
        ssh_cmd "$vm" "chmod 755 $INSTALL_DIR/$svc && chown root:milnet $INSTALL_DIR/$svc"
    done
}

# Copy only the binaries each VM needs
copy_binaries "$VM1" gateway admin &
copy_binaries "$VM2" orchestrator opaque tss &
copy_binaries "$VM3" orchestrator opaque tss &
copy_binaries "$VM4" orchestrator opaque tss &
copy_binaries "$VM5" verifier ratchet risk audit kt tss &
wait
log "Binaries deployed to all VMs"

# ── Phase 3: Deploy environment files ─────────────────────────────────────────

generate_cluster_peers() {
    # Orchestrator Raft peers: all 3 orchestrator VMs on port 9090
    echo "${VM2}:9090,${VM3}:9090,${VM4}:9090"
}

generate_tss_coordinator_peers() {
    echo "${VM2}:9190,${VM3}:9190,${VM4}:9190"
}

generate_tss_signer_addrs() {
    echo "${VM3}:9110,${VM3}:9111,${VM4}:9112,${VM4}:9113,${VM5}:9114"
}

deploy_env_files() {
    local vm="$1"
    local vm_role="$2"

    log "[$vm] Deploying environment files for role: $vm_role"

    CLUSTER_PEERS=$(generate_cluster_peers)
    TSS_COORD_PEERS=$(generate_tss_coordinator_peers)
    TSS_SIGNER_ADDRS=$(generate_tss_signer_addrs)

    case "$vm_role" in
        gateway)
            ssh_cmd "$vm" "cat > /etc/milnet/env/gateway.env" << EOF
# MILNET Gateway — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_PQ_TLS_ONLY=1
MILNET_FIPS_MODE=1
GATEWAY_BIND_ADDR=0.0.0.0:9100
MILNET_GATEWAY_CERT_PATH=/etc/milnet/tls/gateway.crt
MILNET_GATEWAY_KEY_PATH=/etc/milnet/tls/gateway.key
MILNET_GATEWAY_KEY_PINS=REPLACE_WITH_KEY_PINS
MILNET_ORCHESTRATOR_ENDPOINTS=${VM2}:9101,${VM3}:9101,${VM4}:9101
MILNET_RATE_LIMIT_PER_IP=100
MILNET_RATE_LIMIT_PER_USER=50
MILNET_RATE_LIMIT_WINDOW_SECS=60
MILNET_RATE_LIMIT_BURST=20
MILNET_RATE_LIMIT_REDIS_URL=REPLACE_WITH_REDIS_URL
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
MILNET_SIEM_WEBHOOK_URL=REPLACE_WITH_SIEM_URL
MILNET_SIEM_AUTH_TOKEN=REPLACE_WITH_SIEM_TOKEN
MILNET_SIEM_ENABLED=true
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/admin.env" << EOF
# MILNET Admin — Environment Configuration
MILNET_PRODUCTION=1
MILNET_DEPLOYMENT_ID=REPLACE_WITH_DEPLOYMENT_ID
ADMIN_BIND_ADDR=127.0.0.1:8080
DATABASE_URL=REPLACE_WITH_DATABASE_URL
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ;;
        auth-primary)
            ssh_cmd "$vm" "cat > /etc/milnet/env/orchestrator.env" << EOF
# MILNET Orchestrator — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_PQ_TLS_ONLY=1
MILNET_FIPS_MODE=1
ORCH_LISTEN_ADDR=0.0.0.0:9101
MILNET_NODE_ID=orchestrator-0
MILNET_SERVICE_TYPE=orchestrator
MILNET_SERVICE_ADDR=${vm}:9101
MILNET_RAFT_ADDR=${vm}:9090
MILNET_CLUSTER_PEERS=${CLUSTER_PEERS}
OPAQUE_ADDR=${VM2}:9102
TSS_ADDR=${VM2}:9103
VERIFIER_ADDR=${VM5}:9104
RATCHET_ADDR=${VM5}:9105
RISK_ADDR=${VM5}:9106
AUDIT_ADDR=${VM5}:9108
KT_ADDR=${VM5}:9109
DATABASE_URL=REPLACE_WITH_DATABASE_URL
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
MILNET_HSM_BACKEND=REPLACE_WITH_HSM_BACKEND
MILNET_SIEM_WEBHOOK_URL=REPLACE_WITH_SIEM_URL
MILNET_SIEM_AUTH_TOKEN=REPLACE_WITH_SIEM_TOKEN
MILNET_SIEM_ENABLED=true
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/opaque.env" << EOF
# MILNET OPAQUE (Server 1) — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
MILNET_OPAQUE_ADDR=0.0.0.0:9102
MILNET_OPAQUE_MODE=threshold
MILNET_OPAQUE_SERVER_ID=1
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/tss-coordinator.env" << EOF
# MILNET TSS Coordinator — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
MILNET_TSS_ROLE=coordinator
MILNET_TSS_MODE=distributed
TSS_ADDR=0.0.0.0:9103
MILNET_NODE_ID=tss-coordinator-0
MILNET_SERVICE_TYPE=tss-coordinator
MILNET_RAFT_ADDR=${vm}:9190
MILNET_CLUSTER_PEERS=${TSS_COORD_PEERS}
MILNET_TSS_SIGNER_ADDRS=${TSS_SIGNER_ADDRS}
MILNET_TSS_PUBLIC_KEY_PACKAGE=REPLACE_WITH_PUBLIC_KEY_PACKAGE
MILNET_TSS_THRESHOLD=3
MILNET_TSS_SIGNING_TIMEOUT_SECS=10
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ;;
        auth-replica-1)
            ssh_cmd "$vm" "cat > /etc/milnet/env/orchestrator.env" << EOF
# MILNET Orchestrator (Replica 1) — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_PQ_TLS_ONLY=1
MILNET_FIPS_MODE=1
ORCH_LISTEN_ADDR=0.0.0.0:9101
MILNET_NODE_ID=orchestrator-1
MILNET_SERVICE_TYPE=orchestrator
MILNET_SERVICE_ADDR=${vm}:9101
MILNET_RAFT_ADDR=${vm}:9090
MILNET_CLUSTER_PEERS=${CLUSTER_PEERS}
OPAQUE_ADDR=${VM2}:9102
TSS_ADDR=${VM2}:9103
VERIFIER_ADDR=${VM5}:9104
RATCHET_ADDR=${VM5}:9105
RISK_ADDR=${VM5}:9106
AUDIT_ADDR=${VM5}:9108
KT_ADDR=${VM5}:9109
DATABASE_URL=REPLACE_WITH_DATABASE_URL
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
MILNET_HSM_BACKEND=REPLACE_WITH_HSM_BACKEND
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/opaque.env" << EOF
# MILNET OPAQUE (Server 2) — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
MILNET_OPAQUE_ADDR=0.0.0.0:9102
MILNET_OPAQUE_MODE=threshold
MILNET_OPAQUE_SERVER_ID=2
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/tss-signer-1.env" << EOF
# MILNET TSS Signer 1 — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
MILNET_TSS_ROLE=signer
MILNET_TSS_SIGNER_ADDR=0.0.0.0:9110
MILNET_TSS_SHARE_SEALED=REPLACE_WITH_SIGNER_1_SEALED_SHARE
MILNET_TSS_NONCE_STATE_PATH=/var/lib/milnet/tss_nonce_state/signer-1
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/tss-signer-2.env" << EOF
# MILNET TSS Signer 2 — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
MILNET_TSS_ROLE=signer
MILNET_TSS_SIGNER_ADDR=0.0.0.0:9111
MILNET_TSS_SHARE_SEALED=REPLACE_WITH_SIGNER_2_SEALED_SHARE
MILNET_TSS_NONCE_STATE_PATH=/var/lib/milnet/tss_nonce_state/signer-2
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ;;
        auth-replica-2)
            ssh_cmd "$vm" "cat > /etc/milnet/env/orchestrator.env" << EOF
# MILNET Orchestrator (Replica 2) — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_PQ_TLS_ONLY=1
MILNET_FIPS_MODE=1
ORCH_LISTEN_ADDR=0.0.0.0:9101
MILNET_NODE_ID=orchestrator-2
MILNET_SERVICE_TYPE=orchestrator
MILNET_SERVICE_ADDR=${vm}:9101
MILNET_RAFT_ADDR=${vm}:9090
MILNET_CLUSTER_PEERS=${CLUSTER_PEERS}
OPAQUE_ADDR=${VM2}:9102
TSS_ADDR=${VM2}:9103
VERIFIER_ADDR=${VM5}:9104
RATCHET_ADDR=${VM5}:9105
RISK_ADDR=${VM5}:9106
AUDIT_ADDR=${VM5}:9108
KT_ADDR=${VM5}:9109
DATABASE_URL=REPLACE_WITH_DATABASE_URL
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
MILNET_HSM_BACKEND=REPLACE_WITH_HSM_BACKEND
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/opaque.env" << EOF
# MILNET OPAQUE (Server 3) — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
MILNET_OPAQUE_ADDR=0.0.0.0:9102
MILNET_OPAQUE_MODE=threshold
MILNET_OPAQUE_SERVER_ID=3
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/tss-signer-3.env" << EOF
# MILNET TSS Signer 3 — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
MILNET_TSS_ROLE=signer
MILNET_TSS_SIGNER_ADDR=0.0.0.0:9112
MILNET_TSS_SHARE_SEALED=REPLACE_WITH_SIGNER_3_SEALED_SHARE
MILNET_TSS_NONCE_STATE_PATH=/var/lib/milnet/tss_nonce_state/signer-3
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/tss-signer-4.env" << EOF
# MILNET TSS Signer 4 — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
MILNET_TSS_ROLE=signer
MILNET_TSS_SIGNER_ADDR=0.0.0.0:9113
MILNET_TSS_SHARE_SEALED=REPLACE_WITH_SIGNER_4_SEALED_SHARE
MILNET_TSS_NONCE_STATE_PATH=/var/lib/milnet/tss_nonce_state/signer-4
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ;;
        verification)
            ssh_cmd "$vm" "cat > /etc/milnet/env/verifier.env" << EOF
# MILNET Verifier — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
VERIFIER_ADDR=0.0.0.0:9104
RATCHET_ADDR=127.0.0.1:9105
MILNET_GROUP_VERIFYING_KEY=REPLACE_WITH_GROUP_VERIFYING_KEY
MILNET_PQ_VERIFYING_KEY=REPLACE_WITH_PQ_VERIFYING_KEY
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/ratchet.env" << EOF
# MILNET Ratchet — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
RATCHET_ADDR=0.0.0.0:9105
DATABASE_URL=REPLACE_WITH_DATABASE_URL
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/risk.env" << EOF
# MILNET Risk — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
RISK_ADDR=0.0.0.0:9106
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/audit.env" << EOF
# MILNET Audit — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
AUDIT_ADDR=0.0.0.0:9108
AUDIT_DATA_DIR=/var/lib/milnet/audit
KT_ADDR=127.0.0.1:9109
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/kt.env" << EOF
# MILNET Key Transparency — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
KT_ADDR=0.0.0.0:9109
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ssh_cmd "$vm" "cat > /etc/milnet/env/tss-signer-5.env" << EOF
# MILNET TSS Signer 5 — Environment Configuration
MILNET_PRODUCTION=1
MILNET_MILITARY_DEPLOYMENT=1
MILNET_FIPS_MODE=1
MILNET_TSS_ROLE=signer
MILNET_TSS_SIGNER_ADDR=0.0.0.0:9114
MILNET_TSS_SHARE_SEALED=REPLACE_WITH_SIGNER_5_SEALED_SHARE
MILNET_TSS_NONCE_STATE_PATH=/var/lib/milnet/tss_nonce_state/signer-5
MILNET_MASTER_KEK=REPLACE_WITH_MASTER_KEK
RUST_LOG=info,milnet=debug
EOF
            ;;
    esac

    # Lock down env file permissions (contain secrets)
    ssh_cmd "$vm" "chmod 640 /etc/milnet/env/*.env && chown root:milnet /etc/milnet/env/*.env"
}

deploy_env_files "$VM1" "gateway"
deploy_env_files "$VM2" "auth-primary"
deploy_env_files "$VM3" "auth-replica-1"
deploy_env_files "$VM4" "auth-replica-2"
deploy_env_files "$VM5" "verification"
log "Environment files deployed to all VMs"

# ── Phase 4: Deploy systemd unit files ─────────────────────────────────────────

deploy_systemd_units() {
    local vm="$1"
    shift
    local units=("$@")

    log "[$vm] Deploying systemd units: ${units[*]}"
    for unit in "${units[@]}"; do
        local unit_file="$SYSTEMD_DIR/$unit"
        if [ ! -f "$unit_file" ]; then
            echo "WARNING: Unit file not found: $unit_file — skipping"
            continue
        fi
        scp_cmd "$unit_file" "$SSH_USER@$vm:/etc/systemd/system/$unit"
    done

    ssh_cmd "$vm" "systemctl daemon-reload"
}

deploy_systemd_units "$VM1" \
    milnet-gateway.service \
    milnet-admin.service &

deploy_systemd_units "$VM2" \
    milnet-orchestrator.service \
    milnet-opaque.service \
    milnet-tss-coordinator.service &

deploy_systemd_units "$VM3" \
    milnet-orchestrator.service \
    milnet-opaque.service \
    "milnet-tss-signer@.service" &

deploy_systemd_units "$VM4" \
    milnet-orchestrator.service \
    milnet-opaque.service \
    "milnet-tss-signer@.service" &

deploy_systemd_units "$VM5" \
    milnet-verifier.service \
    milnet-ratchet.service \
    milnet-risk.service \
    milnet-audit.service \
    milnet-kt.service \
    "milnet-tss-signer@.service" &

wait
log "Systemd units deployed to all VMs"

# ── Phase 5: Enable and start services ─────────────────────────────────────────

start_services() {
    local vm="$1"
    shift
    local services=("$@")

    log "[$vm] Starting services: ${services[*]}"
    for svc in "${services[@]}"; do
        ssh_cmd "$vm" "systemctl enable --now $svc" || {
            echo "WARNING: Failed to start $svc on $vm"
        }
    done
}

# Start in dependency order: infrastructure first, then auth services, then dependents

log "Phase 5a: Starting gateway + admin on VM-1..."
start_services "$VM1" milnet-gateway.service milnet-admin.service

log "Phase 5b: Starting auth-primary services on VM-2..."
start_services "$VM2" milnet-orchestrator.service milnet-opaque.service milnet-tss-coordinator.service

log "Phase 5c: Starting auth-replica services on VM-3 and VM-4..."
start_services "$VM3" milnet-orchestrator.service milnet-opaque.service \
    "milnet-tss-signer@1.service" "milnet-tss-signer@2.service" &
start_services "$VM4" milnet-orchestrator.service milnet-opaque.service \
    "milnet-tss-signer@3.service" "milnet-tss-signer@4.service" &
wait

log "Phase 5d: Starting verification + audit services on VM-5..."
start_services "$VM5" milnet-verifier.service milnet-ratchet.service \
    milnet-risk.service milnet-audit.service milnet-kt.service \
    "milnet-tss-signer@5.service"

# ── Phase 6: Health verification ───────────────────────────────────────────────

log "Verifying service health across all VMs..."

check_health() {
    local vm="$1"
    local port="$2"
    local svc="$3"

    if ssh_cmd "$vm" "timeout 5 bash -c 'echo > /dev/tcp/127.0.0.1/$port'" 2>/dev/null; then
        echo "  [OK]   $svc on $vm:$port"
    else
        echo "  [FAIL] $svc on $vm:$port"
    fi
}

echo ""
echo "=== Health Check Results ==="
check_health "$VM1" 10100 "gateway"
check_health "$VM1" 9080  "admin"
check_health "$VM2" 10101 "orchestrator-0"
check_health "$VM2" 10102 "opaque-1"
check_health "$VM2" 10103 "tss-coordinator"
check_health "$VM3" 10101 "orchestrator-1"
check_health "$VM3" 10102 "opaque-2"
check_health "$VM3" 10110 "tss-signer-1"
check_health "$VM3" 10111 "tss-signer-2"
check_health "$VM4" 10101 "orchestrator-2"
check_health "$VM4" 10102 "opaque-3"
check_health "$VM4" 10112 "tss-signer-3"
check_health "$VM4" 10113 "tss-signer-4"
check_health "$VM5" 10104 "verifier"
check_health "$VM5" 10105 "ratchet"
check_health "$VM5" 10106 "risk"
check_health "$VM5" 10108 "audit"
check_health "$VM5" 10109 "kt"
check_health "$VM5" 10114 "tss-signer-5"
echo "==========================="
echo ""

log "MILNET SSO deployment complete."
log "Gateway endpoint: https://${VM1}:9100"
