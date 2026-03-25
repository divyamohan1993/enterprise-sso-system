#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Binary Update / Deploy Script
# ==============================================================================
# Pushes new binary versions to a running MILNET installation with:
#   1. Binary attestation (SHA-512 verification against signed manifest)
#   2. Graceful service stop
#   3. Atomic binary replacement (rename, not copy)
#   4. Service restart
#   5. Health check validation
#   6. Automatic rollback if health checks fail
#
# This script is designed for ZERO-downtime updates when used with a
# load balancer (drain gateway, update, re-add). On a single host,
# there is a brief window during service restart.
#
# Usage:
#   sudo ./deploy.sh --bin-dir /path/to/new/binaries [--manifest /path/to/manifest]
#   sudo ./deploy.sh --rollback  # Restore previous binaries from backup
# ==============================================================================

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BIN_DIR="/opt/milnet/bin"
readonly BACKUP_DIR="/opt/milnet/bin.prev"
readonly SECURITY_DIR="/opt/milnet/security"
readonly MANIFEST_DEFAULT="${SECURITY_DIR}/binary-manifest.sha512"
readonly HEALTH_CHECK="${SCRIPT_DIR}/health-check.sh"

# All MILNET binaries.
readonly -a MILNET_BINARIES=(gateway orchestrator opaque tss verifier ratchet audit admin)

# Services in stop order (reverse dependency).
readonly -a STOP_ORDER=(admin gateway orchestrator verifier ratchet opaque audit)

# TSS instances.
readonly -a TSS_INSTANCES=(1 2 3 4 5)

# Configuration.
NEW_BIN_DIR=""
MANIFEST=""
ROLLBACK=false
HEALTH_TIMEOUT=30
HEALTH_RETRIES=3

log_info()  { echo "[MILNET_DEPLOY] INFO:  $*"; }
log_warn()  { echo "[MILNET_DEPLOY] WARN:  $*" >&2; }
log_error() { echo "[MILNET_DEPLOY] ERROR: $*" >&2; }

die() { log_error "$@"; exit 1; }

check_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root."
}

# ── Parse arguments ─────────────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --bin-dir)
                NEW_BIN_DIR="$2"
                shift 2
                ;;
            --manifest)
                MANIFEST="$2"
                shift 2
                ;;
            --rollback)
                ROLLBACK=true
                shift
                ;;
            --health-timeout)
                HEALTH_TIMEOUT="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 --bin-dir /path/to/binaries [--manifest /path/to/manifest]"
                echo "       $0 --rollback"
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    if [[ "$ROLLBACK" == "false" ]] && [[ -z "$NEW_BIN_DIR" ]]; then
        die "Either --bin-dir or --rollback is required."
    fi

    MANIFEST="${MANIFEST:-$MANIFEST_DEFAULT}"
}

# ── Step 1: Verify new binaries ────────────────────────────────────────────

verify_new_binaries() {
    log_info "Verifying new binaries in ${NEW_BIN_DIR}..."

    local missing=0
    for bin in "${MILNET_BINARIES[@]}"; do
        local path="${NEW_BIN_DIR}/${bin}"
        if [[ ! -f "$path" ]]; then
            log_error "Missing binary: ${path}"
            ((missing++))
        elif [[ ! -x "$path" ]]; then
            log_error "Binary not executable: ${path}"
            ((missing++))
        fi
    done

    [[ $missing -eq 0 ]] || die "${missing} binary(ies) missing or not executable."

    # Verify SHA-512 hashes against manifest if available.
    if [[ -f "$MANIFEST" ]]; then
        log_info "Verifying binary hashes against manifest..."
        local hash_failures=0

        for bin in "${MILNET_BINARIES[@]}"; do
            local path="${NEW_BIN_DIR}/${bin}"
            local current_hash
            current_hash=$(sha512sum "$path" | awk '{print $1}')

            local expected_hash
            expected_hash=$(grep -P "\s+.*/${bin}\$|\s+${bin}\$" "$MANIFEST" 2>/dev/null | awk '{print $1}')

            if [[ -z "$expected_hash" ]]; then
                log_warn "Binary ${bin} not in manifest (new binary?)."
                continue
            fi

            if [[ "$current_hash" != "$expected_hash" ]]; then
                log_error "Hash mismatch for ${bin}!"
                log_error "  Expected: ${expected_hash}"
                log_error "  Got:      ${current_hash}"
                ((hash_failures++))
            fi
        done

        if [[ $hash_failures -gt 0 ]]; then
            die "${hash_failures} binary(ies) failed hash verification. Aborting deploy."
        fi

        log_info "All binary hashes match manifest."
    else
        log_warn "No manifest found at ${MANIFEST} — skipping hash verification."
    fi
}

# ── Step 2: Create backup of current binaries ──────────────────────────────

backup_current_binaries() {
    log_info "Backing up current binaries to ${BACKUP_DIR}..."

    # Remove previous backup.
    rm -rf "$BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"

    for bin in "${MILNET_BINARIES[@]}"; do
        local src="${BIN_DIR}/${bin}"
        if [[ -f "$src" ]]; then
            cp -a "$src" "${BACKUP_DIR}/${bin}"
        fi
    done

    log_info "Backup complete."
}

# ── Step 3: Graceful stop ──────────────────────────────────────────────────

stop_services() {
    log_info "Stopping MILNET services gracefully..."

    # Stop services in dependency-safe order.
    for svc in "${STOP_ORDER[@]}"; do
        log_info "  Stopping milnet-${svc}..."
        systemctl stop "milnet-${svc}.service" 2>/dev/null || true
    done

    # Stop TSS instances.
    for i in "${TSS_INSTANCES[@]}"; do
        systemctl stop "milnet-tss@${i}.service" 2>/dev/null || true
    done

    log_info "All services stopped."
}

# ── Step 4: Atomic binary replacement ──────────────────────────────────────

replace_binaries() {
    local source_dir="$1"
    log_info "Replacing binaries atomically from ${source_dir}..."

    for bin in "${MILNET_BINARIES[@]}"; do
        local src="${source_dir}/${bin}"
        local dst="${BIN_DIR}/${bin}"

        if [[ ! -f "$src" ]]; then
            log_warn "Binary ${bin} not found in source — keeping existing."
            continue
        fi

        # Atomic replacement: copy to .new, set perms, rename over old.
        cp "$src" "${dst}.new"
        chown root:milnet "${dst}.new"
        chmod 0555 "${dst}.new"
        mv -f "${dst}.new" "$dst"
    done

    log_info "All binaries replaced."
}

# ── Step 5: Restart services ──────────────────────────────────────────────

start_services() {
    log_info "Starting MILNET services..."
    systemctl start milnet.target

    # Wait for services to initialize.
    log_info "Waiting ${HEALTH_TIMEOUT}s for services to initialize..."
    sleep "$HEALTH_TIMEOUT"
}

# ── Step 6: Health check ──────────────────────────────────────────────────

run_health_check() {
    log_info "Running health checks..."

    for attempt in $(seq 1 "$HEALTH_RETRIES"); do
        if [[ -x "$HEALTH_CHECK" ]]; then
            if "$HEALTH_CHECK" --quiet; then
                log_info "Health check passed (attempt ${attempt}/${HEALTH_RETRIES})."
                return 0
            fi
        else
            # Fallback: check if all services are active.
            local all_ok=true
            for svc in "${MILNET_BINARIES[@]}"; do
                if [[ "$svc" == "tss" ]]; then
                    for i in "${TSS_INSTANCES[@]}"; do
                        if ! systemctl is-active "milnet-tss@${i}.service" &>/dev/null; then
                            all_ok=false
                            break
                        fi
                    done
                else
                    if ! systemctl is-active "milnet-${svc}.service" &>/dev/null; then
                        all_ok=false
                        break
                    fi
                fi
            done

            if [[ "$all_ok" == "true" ]]; then
                log_info "All services active (attempt ${attempt}/${HEALTH_RETRIES})."
                return 0
            fi
        fi

        log_warn "Health check failed (attempt ${attempt}/${HEALTH_RETRIES}). Retrying in 5s..."
        sleep 5
    done

    log_error "Health check failed after ${HEALTH_RETRIES} attempts."
    return 1
}

# ── Step 7: Rollback ─────────────────────────────────────────────────────

rollback() {
    log_warn "ROLLING BACK to previous binaries..."

    if [[ ! -d "$BACKUP_DIR" ]]; then
        die "No backup found at ${BACKUP_DIR}. Cannot rollback."
    fi

    stop_services
    replace_binaries "$BACKUP_DIR"
    start_services

    if run_health_check; then
        log_info "Rollback successful. Previous version restored."
    else
        log_error "ROLLBACK ALSO FAILED. Manual intervention required."
        log_error "Check: journalctl -u 'milnet-*' --since '10 minutes ago'"
        exit 2
    fi
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    echo "============================================================"
    echo "  MILNET SSO — Binary Deploy"
    echo "============================================================"
    echo ""

    check_root
    parse_args "$@"

    # Rollback mode.
    if [[ "$ROLLBACK" == "true" ]]; then
        rollback
        exit 0
    fi

    # Normal deploy flow.
    verify_new_binaries
    backup_current_binaries
    stop_services
    replace_binaries "$NEW_BIN_DIR"
    start_services

    if run_health_check; then
        log_info "Deploy successful."

        # Update binary attestation manifest.
        if [[ -x "${SECURITY_DIR}/binary-attest.sh" ]]; then
            log_info "Regenerating binary attestation manifest..."
            "${SECURITY_DIR}/binary-attest.sh" --generate || true
        fi
    else
        log_error "Deploy health check FAILED. Initiating rollback..."
        rollback
        exit 1
    fi

    echo ""
    echo "============================================================"
    echo "  Deploy complete. All services healthy."
    echo "============================================================"
}

main "$@"
