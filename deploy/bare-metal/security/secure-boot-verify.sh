#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Secure Boot Verification
# ==============================================================================
# Verifies that Secure Boot is enabled and the boot chain has not been
# tampered with. This is a pre-flight check that runs before any MILNET
# service starts.
#
# If Secure Boot is disabled or UEFI variables indicate tampering, this
# script exits non-zero, preventing the entire MILNET stack from starting.
#
# Rationale: Without Secure Boot, an attacker with physical or remote root
# access could insert a bootkit that captures all cryptographic keys before
# the OS even starts. Secure Boot ensures only signed bootloaders and
# kernels execute.
# ==============================================================================

set -euo pipefail

readonly SCRIPT_NAME="secure-boot-verify"
readonly LOG_TAG="MILNET_PREFLIGHT"

log_info()  { echo "[${LOG_TAG}] [${SCRIPT_NAME}] INFO:  $*"; }
log_warn()  { echo "[${LOG_TAG}] [${SCRIPT_NAME}] WARN:  $*" >&2; }
log_error() { echo "[${LOG_TAG}] [${SCRIPT_NAME}] ERROR: $*" >&2; }

# ── Check 1: Secure Boot status via EFI variables ───────────────────────────

check_secure_boot() {
    local sb_var="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

    # Check if EFI is available at all (vs. legacy BIOS).
    if [[ ! -d /sys/firmware/efi ]]; then
        log_warn "System booted in legacy BIOS mode — Secure Boot not available."
        log_warn "MILNET strongly recommends UEFI with Secure Boot enabled."
        log_warn "Continuing with degraded security posture (configurable via MILNET_REQUIRE_SECUREBOOT)."
        if [[ "${MILNET_REQUIRE_SECUREBOOT:-true}" == "true" ]]; then
            log_error "MILNET_REQUIRE_SECUREBOOT=true but system has no UEFI. Aborting."
            return 1
        fi
        return 0
    fi

    # Read Secure Boot state. The variable is a 5-byte blob:
    # bytes 0-3: attributes, byte 4: value (1=enabled, 0=disabled).
    if [[ -f "$sb_var" ]]; then
        local sb_value
        sb_value=$(od -An -t u1 -j 4 -N 1 "$sb_var" 2>/dev/null | tr -d ' ')

        if [[ "$sb_value" == "1" ]]; then
            log_info "Secure Boot is ENABLED."
        else
            log_error "Secure Boot is DISABLED (value=${sb_value})."
            log_error "An attacker could insert unsigned bootloaders or kernel modules."
            if [[ "${MILNET_REQUIRE_SECUREBOOT:-true}" == "true" ]]; then
                return 1
            fi
            log_warn "Continuing with Secure Boot disabled (MILNET_REQUIRE_SECUREBOOT=false)."
        fi
    else
        log_warn "SecureBoot EFI variable not found at ${sb_var}."
        log_warn "This may indicate a firmware bug or that efivarfs is not mounted."
        if [[ "${MILNET_REQUIRE_SECUREBOOT:-true}" == "true" ]]; then
            log_error "Cannot verify Secure Boot state. Aborting."
            return 1
        fi
    fi
}

# ── Check 2: Setup Mode (should NOT be in setup mode) ──────────────────────

check_setup_mode() {
    local sm_var="/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"

    if [[ ! -f "$sm_var" ]]; then
        log_info "SetupMode variable not found (expected on some firmware)."
        return 0
    fi

    local sm_value
    sm_value=$(od -An -t u1 -j 4 -N 1 "$sm_var" 2>/dev/null | tr -d ' ')

    if [[ "$sm_value" == "1" ]]; then
        log_error "UEFI is in SETUP MODE — Secure Boot keys can be modified!"
        log_error "An attacker could enroll their own keys and sign malicious bootloaders."
        return 1
    fi

    log_info "UEFI Setup Mode is DISABLED (keys are locked)."
}

# ── Check 3: Verify kernel lockdown mode ────────────────────────────────────

check_kernel_lockdown() {
    local lockdown="/sys/kernel/security/lockdown"

    if [[ ! -f "$lockdown" ]]; then
        log_warn "Kernel lockdown not available (requires CONFIG_SECURITY_LOCKDOWN_LSM)."
        return 0
    fi

    local mode
    mode=$(cat "$lockdown")

    if echo "$mode" | grep -q '\[integrity\]\|confidentiality'; then
        log_info "Kernel lockdown mode: ${mode}"
    elif echo "$mode" | grep -q '\[none\]'; then
        log_warn "Kernel lockdown is DISABLED. Consider enabling 'integrity' mode."
        log_warn "Without lockdown, root can modify kernel memory and bypass Secure Boot."
    else
        log_info "Kernel lockdown mode: ${mode}"
    fi
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    log_info "=== Secure Boot Verification ==="

    check_secure_boot
    check_setup_mode
    check_kernel_lockdown

    log_info "=== Secure Boot verification passed ==="
}

main "$@"
