#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Bare-Metal Installation Script
# ==============================================================================
# Complete installation of the MILNET SSO system on a bare-metal Linux host.
# Replaces Docker/Kubernetes entirely with systemd, nftables, and kernel
# hardening.
#
# What this script does:
#   1. Creates milnet group and per-service system users
#   2. Creates directory structure (/opt/milnet, /var/lib/milnet, /etc/milnet)
#   3. Installs binaries with strict permissions (root:milnet, 0555)
#   4. Installs systemd service units
#   5. Installs nftables firewall rules
#   6. Applies sysctl kernel hardening
#   7. Installs logrotate configuration
#   8. Installs security scripts (TPM, attestation)
#   9. Enables and starts services in dependency order
#  10. Runs initial health checks
#
# Prerequisites:
#   - Root access
#   - PostgreSQL 15+ installed and running
#   - MILNET binaries built and available in $BIN_SOURCE
#   - nftables installed (replaces iptables)
#   - tpm2-tools installed (optional, for TPM attestation)
#
# Usage:
#   sudo ./install.sh [--bin-dir /path/to/binaries] [--skip-start] [--skip-firewall]
# ==============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Where compiled MILNET binaries are located.
BIN_SOURCE="${BIN_SOURCE:-${SCRIPT_DIR}/../../target/release}"

# Installation paths.
readonly INSTALL_PREFIX="/opt/milnet"
readonly BIN_DIR="${INSTALL_PREFIX}/bin"
readonly SECURITY_DIR="${INSTALL_PREFIX}/security"
readonly DATA_DIR="/var/lib/milnet"
readonly CONF_DIR="/etc/milnet"
readonly SYSTEMD_DIR="/etc/systemd/system"
readonly NFTABLES_DIR="/etc/nftables.d"
readonly SYSCTL_DIR="/etc/sysctl.d"
readonly LOGROTATE_DIR="/etc/logrotate.d"

# Services (order matters for startup).
readonly -a SERVICES=(audit opaque ratchet verifier orchestrator gateway admin)
readonly -a ALL_USERS=(gateway orchestrator opaque tss verifier ratchet audit admin)
readonly GROUP_NAME="milnet"

# Flags.
SKIP_START=false
SKIP_FIREWALL=false

# Cloud provider integration.
# Valid values: none, gcp, aws, onprem
CLOUD_PROVIDER="${CLOUD_PROVIDER:-none}"

# Compliance regime.
# Valid values: none, fedramp-high, il4, il5, meitygov, itar
COMPLIANCE_REGIME="${COMPLIANCE_REGIME:-none}"

# ── Helpers ──────────────────────────────────────────────────────────────────

log_info()  { echo "[MILNET_INSTALL] INFO:  $*"; }
log_warn()  { echo "[MILNET_INSTALL] WARN:  $*" >&2; }
log_error() { echo "[MILNET_INSTALL] ERROR: $*" >&2; }

die() { log_error "$@"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)."
    fi
}

# ── Parse arguments ─────────────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --bin-dir)
                BIN_SOURCE="$2"
                shift 2
                ;;
            --skip-start)
                SKIP_START=true
                shift
                ;;
            --skip-firewall)
                SKIP_FIREWALL=true
                shift
                ;;
            --cloud-provider)
                CLOUD_PROVIDER="$2"
                shift 2
                ;;
            --cloud-provider=*)
                CLOUD_PROVIDER="${1#--cloud-provider=}"
                shift
                ;;
            --compliance-regime)
                COMPLIANCE_REGIME="$2"
                shift 2
                ;;
            --compliance-regime=*)
                COMPLIANCE_REGIME="${1#--compliance-regime=}"
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [--bin-dir /path/to/binaries] [--skip-start] [--skip-firewall]"
                echo "          [--cloud-provider none|gcp|aws|onprem]"
                echo "          [--compliance-regime none|fedramp-high|il4|il5|meitygov|itar]"
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    # Validate cloud provider
    case "$CLOUD_PROVIDER" in
        none|gcp|aws|onprem) ;;
        *) die "Invalid --cloud-provider: $CLOUD_PROVIDER. Must be none, gcp, aws, or onprem." ;;
    esac

    # Validate compliance regime
    case "$COMPLIANCE_REGIME" in
        none|fedramp-high|il4|il5|meitygov|itar) ;;
        *) die "Invalid --compliance-regime: $COMPLIANCE_REGIME. Must be none, fedramp-high, il4, il5, meitygov, or itar." ;;
    esac
}

# ── Step 1: Create group and users ──────────────────────────────────────────

create_users() {
    log_info "Creating milnet group and service users..."

    # Create the shared milnet group if it does not exist.
    if ! getent group "$GROUP_NAME" &>/dev/null; then
        groupadd --system "$GROUP_NAME"
        log_info "Created group: ${GROUP_NAME}"
    else
        log_info "Group ${GROUP_NAME} already exists."
    fi

    # Create per-service users. Each service runs as its own user for
    # privilege separation. If one service is compromised, it cannot
    # access another service's data directory or memory.
    for svc in "${ALL_USERS[@]}"; do
        local username="milnet-${svc}"
        if ! id "$username" &>/dev/null; then
            useradd \
                --system \
                --gid "$GROUP_NAME" \
                --home-dir "/var/lib/milnet/${svc}" \
                --no-create-home \
                --shell /usr/sbin/nologin \
                --comment "MILNET SSO ${svc} service" \
                "$username"
            log_info "Created user: ${username}"
        else
            log_info "User ${username} already exists."
        fi
    done
}

# ── Step 2: Create directory structure ──────────────────────────────────────

create_directories() {
    log_info "Creating directory structure..."

    # /opt/milnet/bin — read-only binaries.
    mkdir -p "$BIN_DIR"

    # /opt/milnet/security — security scripts and attestation data.
    mkdir -p "$SECURITY_DIR"

    # /etc/milnet — environment files (secrets).
    mkdir -p "$CONF_DIR"

    # /var/lib/milnet/<service> — per-service data directories.
    for svc in "${ALL_USERS[@]}"; do
        mkdir -p "${DATA_DIR}/${svc}"
    done

    # TSS per-node directories.
    for i in 1 2 3 4 5; do
        mkdir -p "${DATA_DIR}/tss/node-${i}"
    done

    # Alerts directory for SIEM integration.
    mkdir -p "${DATA_DIR}/alerts"

    # TPM sealed data directory.
    mkdir -p "${DATA_DIR}/tpm"

    # nftables drop-in directory.
    mkdir -p "$NFTABLES_DIR"
}

# ── Step 3: Set permissions ─────────────────────────────────────────────────

set_permissions() {
    log_info "Setting directory permissions..."

    # /opt/milnet — owned by root, readable by milnet group.
    chown -R root:"$GROUP_NAME" "$INSTALL_PREFIX"
    chmod 0755 "$INSTALL_PREFIX"
    chmod 0755 "$BIN_DIR"
    chmod 0750 "$SECURITY_DIR"

    # /etc/milnet — owned by root, group-readable for secrets.
    chown root:root "$CONF_DIR"
    chmod 0750 "$CONF_DIR"

    # /var/lib/milnet — per-service ownership.
    chown root:"$GROUP_NAME" "$DATA_DIR"
    chmod 0750 "$DATA_DIR"

    for svc in "${ALL_USERS[@]}"; do
        chown "milnet-${svc}":"$GROUP_NAME" "${DATA_DIR}/${svc}"
        chmod 0700 "${DATA_DIR}/${svc}"
    done

    # TSS node directories — owned by milnet-tss.
    for i in 1 2 3 4 5; do
        chown milnet-tss:"$GROUP_NAME" "${DATA_DIR}/tss/node-${i}"
        chmod 0700 "${DATA_DIR}/tss/node-${i}"
    done

    # Alerts directory — writable by audit service.
    chown milnet-audit:"$GROUP_NAME" "${DATA_DIR}/alerts"
    chmod 0700 "${DATA_DIR}/alerts"

    # TPM directory — root only.
    chown root:root "${DATA_DIR}/tpm"
    chmod 0700 "${DATA_DIR}/tpm"
}

# ── Step 4: Install binaries ───────────────────────────────────────────────

install_binaries() {
    log_info "Installing MILNET binaries from ${BIN_SOURCE}..."

    local -a all_bins=(gateway orchestrator opaque tss verifier ratchet audit admin)

    for bin in "${all_bins[@]}"; do
        local src="${BIN_SOURCE}/${bin}"
        local dst="${BIN_DIR}/${bin}"

        if [[ ! -f "$src" ]]; then
            log_warn "Binary not found: ${src} (skipping — build first with 'cargo build --release')"
            continue
        fi

        # Atomic install: copy to temp, set perms, then rename.
        # This prevents a window where the binary exists but has wrong perms.
        cp "$src" "${dst}.new"
        chown root:"$GROUP_NAME" "${dst}.new"
        chmod 0555 "${dst}.new"
        mv -f "${dst}.new" "$dst"
        log_info "Installed: ${dst}"
    done
}

# ── Step 5: Install environment files ──────────────────────────────────────

install_env_files() {
    log_info "Installing environment files to ${CONF_DIR}..."

    local env_src="${SCRIPT_DIR}/env"

    # Install base env files for each service.
    for envfile in "${env_src}"/*.env; do
        local basename
        basename=$(basename "$envfile")
        local dst="${CONF_DIR}/${basename}"

        # Do not overwrite existing env files (they may contain secrets).
        if [[ -f "$dst" ]]; then
            log_warn "Environment file ${dst} already exists — not overwriting."
            log_warn "Merge changes manually from ${envfile}."
            continue
        fi

        cp "$envfile" "$dst"
        chown root:root "$dst"
        chmod 0640 "$dst"

        # Set group ownership to the specific service user for readability.
        # Extract service name from filename (e.g., gateway.env -> milnet-gateway).
        local svc_name="${basename%.env}"
        # Handle tss-node-N files.
        if [[ "$svc_name" == tss-node-* ]]; then
            chown root:milnet-tss "$dst"
        elif [[ "$svc_name" == "tss" ]]; then
            chown root:milnet-tss "$dst"
        else
            local username="milnet-${svc_name}"
            if id "$username" &>/dev/null; then
                chown root:"$username" "$dst"
            fi
        fi

        log_info "Installed: ${dst}"
    done
}

# ── Step 6: Install systemd units ──────────────────────────────────────────

install_systemd_units() {
    log_info "Installing systemd service units..."

    local unit_src="${SCRIPT_DIR}/systemd"

    for unit in "${unit_src}"/*.service "${unit_src}"/*.target; do
        [[ -f "$unit" ]] || continue
        local basename
        basename=$(basename "$unit")
        cp "$unit" "${SYSTEMD_DIR}/${basename}"
        chmod 0644 "${SYSTEMD_DIR}/${basename}"
        log_info "Installed: ${SYSTEMD_DIR}/${basename}"
    done

    # Reload systemd to pick up new units.
    systemctl daemon-reload
    log_info "systemd daemon reloaded."
}

# ── Step 7: Install nftables rules ─────────────────────────────────────────

install_firewall() {
    if [[ "$SKIP_FIREWALL" == "true" ]]; then
        log_warn "Skipping firewall installation (--skip-firewall)."
        return
    fi

    log_info "Installing nftables firewall rules..."

    if ! command -v nft &>/dev/null; then
        log_warn "nftables not installed. Install with: apt install nftables"
        log_warn "Skipping firewall installation."
        return
    fi

    cp "${SCRIPT_DIR}/nftables/milnet.nft" "${NFTABLES_DIR}/milnet.nft"
    chmod 0644 "${NFTABLES_DIR}/milnet.nft"

    # Validate rules before applying.
    if nft -c -f "${NFTABLES_DIR}/milnet.nft"; then
        log_info "nftables rules validated successfully."
        nft -f "${NFTABLES_DIR}/milnet.nft"
        log_info "nftables rules applied."
    else
        log_error "nftables rules failed validation! Rules NOT applied."
        log_error "Fix the rules in ${NFTABLES_DIR}/milnet.nft and re-run."
        return 1
    fi

    # Ensure nftables service is enabled for persistence across reboots.
    # The main nftables.conf should include /etc/nftables.d/*.nft.
    if systemctl is-enabled nftables &>/dev/null; then
        log_info "nftables service is already enabled."
    else
        systemctl enable nftables 2>/dev/null || \
            log_warn "Could not enable nftables service. Ensure rules persist across reboots."
    fi
}

# ── Step 8: Apply sysctl hardening ─────────────────────────────────────────

install_sysctl() {
    log_info "Installing sysctl kernel hardening..."

    cp "${SCRIPT_DIR}/sysctl/99-milnet-hardening.conf" "${SYSCTL_DIR}/99-milnet-hardening.conf"
    chmod 0644 "${SYSCTL_DIR}/99-milnet-hardening.conf"

    # Apply immediately.
    if sysctl --system &>/dev/null; then
        log_info "sysctl settings applied."
    else
        log_warn "Some sysctl settings may have failed to apply (check dmesg)."
    fi
}

# ── Step 9: Install security scripts ──────────────────────────────────────

install_security_scripts() {
    log_info "Installing security scripts..."

    local sec_src="${SCRIPT_DIR}/security"

    for script in "${sec_src}"/*.sh; do
        [[ -f "$script" ]] || continue
        local basename
        basename=$(basename "$script")
        cp "$script" "${SECURITY_DIR}/${basename}"
        chmod 0750 "${SECURITY_DIR}/${basename}"
        chown root:"$GROUP_NAME" "${SECURITY_DIR}/${basename}"
        log_info "Installed: ${SECURITY_DIR}/${basename}"
    done

    # Install expected PCRs config (non-executable).
    if [[ -f "${sec_src}/expected-pcrs.conf" ]]; then
        cp "${sec_src}/expected-pcrs.conf" "${SECURITY_DIR}/expected-pcrs.conf"
        chmod 0600 "${SECURITY_DIR}/expected-pcrs.conf"
        chown root:root "${SECURITY_DIR}/expected-pcrs.conf"
        log_info "Installed: ${SECURITY_DIR}/expected-pcrs.conf"
    fi

    # Install cloud HSM init script.
    if [[ -f "${sec_src}/cloud-hsm-init.sh" ]]; then
        cp "${sec_src}/cloud-hsm-init.sh" "${SECURITY_DIR}/cloud-hsm-init.sh"
        chmod 0750 "${SECURITY_DIR}/cloud-hsm-init.sh"
        chown root:root "${SECURITY_DIR}/cloud-hsm-init.sh"
        log_info "Installed: ${SECURITY_DIR}/cloud-hsm-init.sh"
    fi
}

# ── Cloud HSM Initialization ─────────────────────────────────────────────────
# Run cloud-hsm-init.sh for the selected cloud provider.
# Only called when --cloud-provider is not 'none'.

init_cloud_hsm() {
    if [[ "$CLOUD_PROVIDER" == "none" ]]; then
        log_info "No cloud provider specified — skipping Cloud HSM initialization."
        return
    fi

    log_info "Initializing Cloud HSM for provider: $CLOUD_PROVIDER"

    local hsm_init_script="${SECURITY_DIR}/cloud-hsm-init.sh"
    if [[ ! -x "$hsm_init_script" ]]; then
        log_warn "Cloud HSM init script not found at ${hsm_init_script}. Skipping."
        return
    fi

    local hsm_env_args=()

    case "$CLOUD_PROVIDER" in
        gcp)
            # Pass compliance-specific region defaults
            if [[ "$COMPLIANCE_REGIME" == "meitygov" ]]; then
                hsm_env_args+=(REGION="${REGION:-asia-south1}")
            fi
            ;;
        aws)
            # GovCloud FIPS regions for FedRAMP/IL compliance
            if [[ "$COMPLIANCE_REGIME" == "fedramp-high" || \
                  "$COMPLIANCE_REGIME" == "il4" || \
                  "$COMPLIANCE_REGIME" == "il5" || \
                  "$COMPLIANCE_REGIME" == "itar" ]]; then
                hsm_env_args+=(REGION="${REGION:-us-gov-west-1}")
            fi
            ;;
        onprem)
            # On-prem has no region concept
            ;;
    esac

    env "${hsm_env_args[@]}" \
        ENV="${ENVIRONMENT:-production}" \
        "$hsm_init_script" \
        --provider="$CLOUD_PROVIDER" \
        || log_warn "Cloud HSM initialization exited with non-zero status. Review output above."

    log_info "Cloud HSM initialization step complete."
}

# ── Step 10: Install logrotate ─────────────────────────────────────────────

install_logrotate() {
    log_info "Installing logrotate configuration..."

    if [[ -f "${SCRIPT_DIR}/logrotate/milnet" ]]; then
        cp "${SCRIPT_DIR}/logrotate/milnet" "${LOGROTATE_DIR}/milnet"
        chmod 0644 "${LOGROTATE_DIR}/milnet"
        log_info "Installed: ${LOGROTATE_DIR}/milnet"
    else
        # Generate inline if the file does not exist in the source tree.
        cat > "${LOGROTATE_DIR}/milnet" <<'LOGROTATE'
# MILNET SSO — Log Rotation Configuration
# Rotates journal-exported logs and audit data files.

/var/lib/milnet/audit/*.log
/var/lib/milnet/alerts/*.log
{
    daily
    rotate 365
    compress
    delaycompress
    missingok
    notifempty
    create 0640 milnet-audit milnet
    sharedscripts
    postrotate
        systemctl kill --signal=HUP milnet-audit.service 2>/dev/null || true
    endscript
}

/var/lib/milnet/gateway/*.log
/var/lib/milnet/orchestrator/*.log
/var/lib/milnet/opaque/*.log
/var/lib/milnet/verifier/*.log
/var/lib/milnet/ratchet/*.log
/var/lib/milnet/admin/*.log
{
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root milnet
    sharedscripts
}
LOGROTATE
        log_info "Generated: ${LOGROTATE_DIR}/milnet"
    fi
}

# ── Step 11: Enable and start services ─────────────────────────────────────

enable_and_start() {
    if [[ "$SKIP_START" == "true" ]]; then
        log_warn "Skipping service start (--skip-start)."
        log_info "Enable manually with: systemctl enable --now milnet.target"
        return
    fi

    log_info "Enabling and starting MILNET services..."

    # Enable the target (pulls in all services).
    systemctl enable milnet.target

    # Enable individual services.
    systemctl enable milnet-pre.service
    systemctl enable milnet-postgres.service

    for svc in "${SERVICES[@]}"; do
        systemctl enable "milnet-${svc}.service"
    done

    # Enable TSS template instances.
    for i in 1 2 3 4 5; do
        systemctl enable "milnet-tss@${i}.service"
    done

    # Start the target (cascades to all services).
    log_info "Starting milnet.target..."
    if systemctl start milnet.target; then
        log_info "All MILNET services started."
    else
        log_error "Some services failed to start. Check: journalctl -u 'milnet-*' --since '5 minutes ago'"
    fi
}

# ── Step 12: Run health checks ─────────────────────────────────────────────

run_health_checks() {
    if [[ "$SKIP_START" == "true" ]]; then
        return
    fi

    log_info "Running initial health checks..."

    # Give services a moment to initialize.
    sleep 3

    local health_script="${SCRIPT_DIR}/health-check.sh"
    if [[ -x "$health_script" ]]; then
        "$health_script" || log_warn "Some health checks failed. Review output above."
    else
        log_warn "Health check script not found at ${health_script}."
    fi
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    echo "============================================================"
    echo "  MILNET SSO — Bare-Metal Installation"
    echo "============================================================"
    echo ""

    check_root
    parse_args "$@"

    log_info "Cloud provider : ${CLOUD_PROVIDER}"
    log_info "Compliance     : ${COMPLIANCE_REGIME}"

    create_users
    create_directories
    set_permissions
    install_binaries
    install_env_files
    install_systemd_units
    install_firewall
    install_sysctl
    install_security_scripts
    install_logrotate
    init_cloud_hsm
    enable_and_start
    run_health_checks

    echo ""
    echo "============================================================"
    echo "  MILNET SSO installation complete."
    echo ""
    echo "  Next steps:"
    echo "    1. Edit /etc/milnet/*.env with real database passwords"
    echo "    2. Provision TPM baselines: ${SECURITY_DIR}/vtpm-attest.sh --provision"
    echo "    3. Generate binary manifest: ${SECURITY_DIR}/binary-attest.sh --generate"
    echo "    4. Verify health: ${SCRIPT_DIR}/health-check.sh"
    echo "    5. Configure PostgreSQL pg_hba.conf for milnet users"
    echo ""
    echo "  Management:"
    echo "    systemctl status milnet.target     # Overall status"
    echo "    journalctl -u milnet-gateway -f    # Follow gateway logs"
    echo "    systemctl restart milnet.target     # Restart all"
    echo "============================================================"
}

main "$@"
