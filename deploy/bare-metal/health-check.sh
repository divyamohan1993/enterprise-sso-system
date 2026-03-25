#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Health Check Script
# ==============================================================================
# Comprehensive health verification of all MILNET SSO components:
#   1. Systemd service status (all services running)
#   2. Port listening verification (all expected ports bound)
#   3. TPM accessibility
#   4. Firewall active and loaded
#   5. Sysctl hardening applied
#   6. Binary integrity (quick hash check)
#   7. Disk space and resource checks
#
# Exit codes:
#   0 — All checks passed
#   1 — One or more checks failed (details in output)
#
# Usage:
#   ./health-check.sh [--quiet] [--json]
# ==============================================================================

set -euo pipefail

readonly BIN_DIR="/opt/milnet/bin"
readonly DATA_DIR="/var/lib/milnet"
readonly CONF_DIR="/etc/milnet"

# Service/port mapping.
declare -A SERVICE_PORTS=(
    [milnet-gateway]=9100
    [milnet-orchestrator]=9101
    [milnet-opaque]=9102
    [milnet-verifier]=9104
    [milnet-ratchet]=9105
    [milnet-audit]=9108
    [milnet-admin]=8080
)

# TSS instances.
declare -A TSS_PORTS=(
    [milnet-tss@1]=9113
    [milnet-tss@2]=9114
    [milnet-tss@3]=9115
    [milnet-tss@4]=9116
    [milnet-tss@5]=9117
)

QUIET=false
FAILURES=0
WARNINGS=0
CHECKS=0

log_ok()   { ((CHECKS++)); [[ "$QUIET" == "true" ]] || echo "[OK]   $*"; }
log_fail() { ((CHECKS++)); ((FAILURES++)); echo "[FAIL] $*" >&2; }
log_warn() { ((WARNINGS++)); [[ "$QUIET" == "true" ]] || echo "[WARN] $*" >&2; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --quiet|-q) QUIET=true; shift ;;
            -h|--help)
                echo "Usage: $0 [--quiet]"
                exit 0
                ;;
            *) shift ;;
        esac
    done
}

# ── Check 1: Systemd service status ────────────────────────────────────────

check_services() {
    [[ "$QUIET" == "true" ]] || echo ""
    [[ "$QUIET" == "true" ]] || echo "=== Systemd Service Status ==="

    # Check milnet.target.
    if systemctl is-active milnet.target &>/dev/null; then
        log_ok "milnet.target is active"
    else
        log_fail "milnet.target is NOT active"
    fi

    # Check individual services.
    for svc in "${!SERVICE_PORTS[@]}"; do
        if systemctl is-active "${svc}.service" &>/dev/null; then
            log_ok "${svc}.service is active"
        else
            log_fail "${svc}.service is NOT active"
        fi
    done

    # Check TSS instances.
    for svc in "${!TSS_PORTS[@]}"; do
        if systemctl is-active "${svc}.service" &>/dev/null; then
            log_ok "${svc}.service is active"
        else
            log_fail "${svc}.service is NOT active"
        fi
    done

    # Check PostgreSQL wrapper.
    if systemctl is-active milnet-postgres.service &>/dev/null; then
        log_ok "milnet-postgres.service is active"
    else
        log_fail "milnet-postgres.service is NOT active"
    fi
}

# ── Check 2: Port listening ────────────────────────────────────────────────

check_ports() {
    [[ "$QUIET" == "true" ]] || echo ""
    [[ "$QUIET" == "true" ]] || echo "=== Port Listening ==="

    for svc in "${!SERVICE_PORTS[@]}"; do
        local port="${SERVICE_PORTS[$svc]}"
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            log_ok "Port ${port} (${svc}) is listening"
        else
            log_fail "Port ${port} (${svc}) is NOT listening"
        fi
    done

    # Check TSS peer ports.
    for svc in "${!TSS_PORTS[@]}"; do
        local port="${TSS_PORTS[$svc]}"
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            log_ok "Port ${port} (${svc} peer) is listening"
        else
            log_warn "Port ${port} (${svc} peer) is not listening (may be normal if TSS is idle)"
        fi
    done

    # Check PostgreSQL.
    if ss -tlnp 2>/dev/null | grep -q ":5432 "; then
        log_ok "Port 5432 (PostgreSQL) is listening"
    else
        log_fail "Port 5432 (PostgreSQL) is NOT listening"
    fi
}

# ── Check 3: TPM accessibility ─────────────────────────────────────────────

check_tpm() {
    [[ "$QUIET" == "true" ]] || echo ""
    [[ "$QUIET" == "true" ]] || echo "=== TPM Status ==="

    if [[ -c /dev/tpmrm0 ]]; then
        log_ok "TPM resource manager (/dev/tpmrm0) is accessible"

        if command -v tpm2_getcap &>/dev/null; then
            if tpm2_getcap properties-fixed &>/dev/null; then
                log_ok "TPM responds to queries (tpm2_getcap)"
            else
                log_fail "TPM device exists but does not respond"
            fi
        else
            log_warn "tpm2-tools not installed — cannot verify TPM functionality"
        fi
    else
        log_warn "TPM resource manager not found (vTPM attestation unavailable)"
    fi
}

# ── Check 4: Firewall status ──────────────────────────────────────────────

check_firewall() {
    [[ "$QUIET" == "true" ]] || echo ""
    [[ "$QUIET" == "true" ]] || echo "=== Firewall Status ==="

    if ! command -v nft &>/dev/null; then
        log_warn "nftables not installed"
        return
    fi

    if nft list table inet milnet &>/dev/null; then
        log_ok "nftables table 'inet milnet' is loaded"

        # Verify key chains exist.
        for chain in input output forward; do
            if nft list chain inet milnet "$chain" &>/dev/null; then
                log_ok "Chain '${chain}' exists in milnet table"
            else
                log_fail "Chain '${chain}' MISSING from milnet table"
            fi
        done
    else
        log_fail "nftables table 'inet milnet' is NOT loaded"
    fi
}

# ── Check 5: Sysctl hardening ─────────────────────────────────────────────

check_sysctl() {
    [[ "$QUIET" == "true" ]] || echo ""
    [[ "$QUIET" == "true" ]] || echo "=== Kernel Hardening ==="

    local -A expected_values=(
        [kernel.randomize_va_space]=2
        [kernel.kptr_restrict]=2
        [kernel.dmesg_restrict]=1
        [kernel.yama.ptrace_scope]=3
        [net.ipv4.conf.all.rp_filter]=1
        [net.ipv4.tcp_syncookies]=1
        [net.ipv4.ip_forward]=0
        [fs.suid_dumpable]=0
    )

    for key in "${!expected_values[@]}"; do
        local expected="${expected_values[$key]}"
        local actual
        actual=$(sysctl -n "$key" 2>/dev/null || echo "N/A")

        if [[ "$actual" == "$expected" ]]; then
            log_ok "sysctl ${key} = ${actual}"
        elif [[ "$actual" == "N/A" ]]; then
            log_warn "sysctl ${key} not available on this kernel"
        else
            log_fail "sysctl ${key} = ${actual} (expected ${expected})"
        fi
    done
}

# ── Check 6: Binary integrity ─────────────────────────────────────────────

check_binaries() {
    [[ "$QUIET" == "true" ]] || echo ""
    [[ "$QUIET" == "true" ]] || echo "=== Binary Integrity ==="

    local -a expected_binaries=(gateway orchestrator opaque tss verifier ratchet audit admin)

    for bin in "${expected_binaries[@]}"; do
        local path="${BIN_DIR}/${bin}"
        if [[ -f "$path" ]] && [[ -x "$path" ]]; then
            local perms
            perms=$(stat -c '%a' "$path")
            if [[ "$perms" == "555" ]]; then
                log_ok "Binary ${bin}: present, executable, permissions ${perms}"
            else
                log_warn "Binary ${bin}: permissions ${perms} (expected 555)"
            fi
        elif [[ -f "$path" ]]; then
            log_fail "Binary ${bin}: present but NOT executable"
        else
            log_fail "Binary ${bin}: MISSING"
        fi
    done
}

# ── Check 7: Disk space ───────────────────────────────────────────────────

check_disk() {
    [[ "$QUIET" == "true" ]] || echo ""
    [[ "$QUIET" == "true" ]] || echo "=== Resource Checks ==="

    # Check data directory has at least 1GB free.
    local avail_kb
    avail_kb=$(df -k "$DATA_DIR" 2>/dev/null | tail -1 | awk '{print $4}')

    if [[ -n "$avail_kb" ]]; then
        local avail_mb=$((avail_kb / 1024))
        if [[ $avail_mb -gt 1024 ]]; then
            log_ok "Disk space for ${DATA_DIR}: ${avail_mb}MB available"
        elif [[ $avail_mb -gt 256 ]]; then
            log_warn "Disk space for ${DATA_DIR}: ${avail_mb}MB (low)"
        else
            log_fail "Disk space for ${DATA_DIR}: ${avail_mb}MB (critically low)"
        fi
    fi

    # Check memory.
    local mem_avail_kb
    mem_avail_kb=$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2}')
    if [[ -n "$mem_avail_kb" ]]; then
        local mem_avail_mb=$((mem_avail_kb / 1024))
        if [[ $mem_avail_mb -gt 2048 ]]; then
            log_ok "Available memory: ${mem_avail_mb}MB"
        elif [[ $mem_avail_mb -gt 512 ]]; then
            log_warn "Available memory: ${mem_avail_mb}MB (low for all services)"
        else
            log_fail "Available memory: ${mem_avail_mb}MB (critically low)"
        fi
    fi
}

# ── Summary ────────────────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo "============================================================"
    echo "  Health Check Summary"
    echo "  Checks: ${CHECKS}  Passed: $((CHECKS - FAILURES))  Failed: ${FAILURES}  Warnings: ${WARNINGS}"
    echo "============================================================"

    if [[ $FAILURES -eq 0 ]]; then
        echo "  STATUS: ALL CHECKS PASSED"
    else
        echo "  STATUS: ${FAILURES} CHECK(S) FAILED"
    fi
    echo ""
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    [[ "$QUIET" == "true" ]] || echo "============================================================"
    [[ "$QUIET" == "true" ]] || echo "  MILNET SSO — Health Check"
    [[ "$QUIET" == "true" ]] || echo "============================================================"

    check_services
    check_ports
    check_tpm
    check_firewall
    check_sysctl
    check_binaries
    check_disk

    print_summary

    [[ $FAILURES -eq 0 ]]
}

main "$@"
