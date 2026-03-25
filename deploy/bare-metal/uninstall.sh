#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Bare-Metal Uninstallation Script
# ==============================================================================
# Cleanly removes all MILNET SSO components from the system:
#   - Stops and disables all MILNET systemd services
#   - Removes systemd unit files
#   - Removes nftables rules
#   - Removes sysctl hardening (optional)
#   - Removes binaries and security scripts
#   - Optionally removes data directories and users
#
# Usage:
#   sudo ./uninstall.sh [--purge]
#     --purge: Also remove data directories (/var/lib/milnet) and users.
#              Without --purge, data and users are preserved for potential
#              reinstallation.
# ==============================================================================

set -euo pipefail

readonly INSTALL_PREFIX="/opt/milnet"
readonly DATA_DIR="/var/lib/milnet"
readonly CONF_DIR="/etc/milnet"
readonly SYSTEMD_DIR="/etc/systemd/system"
readonly NFTABLES_DIR="/etc/nftables.d"
readonly SYSCTL_DIR="/etc/sysctl.d"
readonly LOGROTATE_DIR="/etc/logrotate.d"

readonly -a ALL_USERS=(gateway orchestrator opaque tss verifier ratchet audit admin)
readonly GROUP_NAME="milnet"

PURGE=false

log_info()  { echo "[MILNET_UNINSTALL] INFO:  $*"; }
log_warn()  { echo "[MILNET_UNINSTALL] WARN:  $*" >&2; }
log_error() { echo "[MILNET_UNINSTALL] ERROR: $*" >&2; }

die() { log_error "$@"; exit 1; }

check_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root."
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --purge)
                PURGE=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [--purge]"
                echo "  --purge: Also remove data, configs, and users"
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done
}

# ── Step 1: Stop and disable services ──────────────────────────────────────

stop_services() {
    log_info "Stopping all MILNET services..."

    # Stop the target (cascades to all PartOf services).
    systemctl stop milnet.target 2>/dev/null || true

    # Stop TSS instances explicitly.
    for i in 1 2 3 4 5; do
        systemctl stop "milnet-tss@${i}.service" 2>/dev/null || true
        systemctl disable "milnet-tss@${i}.service" 2>/dev/null || true
    done

    # Stop and disable individual services.
    for svc in "${ALL_USERS[@]}"; do
        systemctl stop "milnet-${svc}.service" 2>/dev/null || true
        systemctl disable "milnet-${svc}.service" 2>/dev/null || true
    done

    systemctl stop milnet-pre.service 2>/dev/null || true
    systemctl disable milnet-pre.service 2>/dev/null || true

    systemctl stop milnet-postgres.service 2>/dev/null || true
    systemctl disable milnet-postgres.service 2>/dev/null || true

    systemctl disable milnet.target 2>/dev/null || true

    log_info "All MILNET services stopped and disabled."
}

# ── Step 2: Remove systemd units ──────────────────────────────────────────

remove_systemd_units() {
    log_info "Removing systemd unit files..."

    rm -f "${SYSTEMD_DIR}"/milnet-*.service
    rm -f "${SYSTEMD_DIR}"/milnet-*.target
    rm -f "${SYSTEMD_DIR}"/milnet.target

    systemctl daemon-reload
    log_info "systemd daemon reloaded."
}

# ── Step 3: Remove nftables rules ─────────────────────────────────────────

remove_firewall() {
    log_info "Removing nftables rules..."

    # Delete the MILNET table from active ruleset.
    if command -v nft &>/dev/null; then
        nft delete table inet milnet 2>/dev/null || true
    fi

    rm -f "${NFTABLES_DIR}/milnet.nft"
    log_info "Firewall rules removed."
}

# ── Step 4: Remove sysctl hardening ───────────────────────────────────────

remove_sysctl() {
    log_info "Removing sysctl hardening..."
    rm -f "${SYSCTL_DIR}/99-milnet-hardening.conf"

    # Re-apply remaining sysctl configs to revert MILNET settings.
    sysctl --system &>/dev/null || true
    log_info "sysctl settings reverted."
}

# ── Step 5: Remove logrotate ──────────────────────────────────────────────

remove_logrotate() {
    log_info "Removing logrotate configuration..."
    rm -f "${LOGROTATE_DIR}/milnet"
}

# ── Step 6: Remove installation files ─────────────────────────────────────

remove_install_files() {
    log_info "Removing MILNET installation directory..."
    rm -rf "$INSTALL_PREFIX"
    log_info "Removed: ${INSTALL_PREFIX}"
}

# ── Step 7: Remove config and data (purge only) ──────────────────────────

purge_data() {
    if [[ "$PURGE" != "true" ]]; then
        log_info "Preserving data directories and users (use --purge to remove)."
        log_info "  Data: ${DATA_DIR}"
        log_info "  Config: ${CONF_DIR}"
        return
    fi

    log_warn "PURGING all MILNET data and configuration..."

    # Remove configuration (contains secrets).
    if [[ -d "$CONF_DIR" ]]; then
        # Securely erase env files that may contain database passwords.
        find "$CONF_DIR" -name "*.env" -exec shred -fuz {} \; 2>/dev/null || true
        rm -rf "$CONF_DIR"
        log_info "Removed: ${CONF_DIR}"
    fi

    # Remove data directories.
    if [[ -d "$DATA_DIR" ]]; then
        # Securely erase key material in TPM directory.
        find "${DATA_DIR}/tpm" -type f -exec shred -fuz {} \; 2>/dev/null || true
        rm -rf "$DATA_DIR"
        log_info "Removed: ${DATA_DIR}"
    fi
}

# ── Step 8: Remove users (purge only) ────────────────────────────────────

purge_users() {
    if [[ "$PURGE" != "true" ]]; then
        return
    fi

    log_info "Removing MILNET system users..."

    for svc in "${ALL_USERS[@]}"; do
        local username="milnet-${svc}"
        if id "$username" &>/dev/null; then
            userdel "$username" 2>/dev/null || log_warn "Could not delete user: ${username}"
            log_info "Removed user: ${username}"
        fi
    done

    if getent group "$GROUP_NAME" &>/dev/null; then
        groupdel "$GROUP_NAME" 2>/dev/null || log_warn "Could not delete group: ${GROUP_NAME}"
        log_info "Removed group: ${GROUP_NAME}"
    fi
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    echo "============================================================"
    echo "  MILNET SSO — Bare-Metal Uninstallation"
    if [[ "$PURGE" == "true" ]]; then
        echo "  MODE: PURGE (removes ALL data, configs, and users)"
    else
        echo "  MODE: Standard (preserves data and users)"
    fi
    echo "============================================================"
    echo ""

    check_root
    parse_args "$@"

    stop_services
    remove_systemd_units
    remove_firewall
    remove_sysctl
    remove_logrotate
    remove_install_files
    purge_data
    purge_users

    echo ""
    echo "============================================================"
    echo "  MILNET SSO uninstallation complete."
    if [[ "$PURGE" != "true" ]]; then
        echo "  Data preserved at: ${DATA_DIR}"
        echo "  Config preserved at: ${CONF_DIR}"
        echo "  Run with --purge to remove everything."
    fi
    echo "============================================================"
}

main "$@"
