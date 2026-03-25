#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — vTPM Attestation
# ==============================================================================
# Reads TPM Platform Configuration Registers (PCRs) and verifies them
# against expected baseline values established during initial provisioning.
#
# PCRs measured:
#   PCR 0  — UEFI firmware code (BIOS/UEFI)
#   PCR 2  — Option ROM code (PCI device firmware)
#   PCR 4  — Master Boot Record / boot loader code
#   PCR 7  — Secure Boot policy (db, dbx, KEK, PK variables)
#
# If any PCR deviates from baseline, the boot chain has been modified.
# This could indicate:
#   - Firmware update (benign — re-provision baselines)
#   - Bootkit installation (malicious — investigate immediately)
#   - GRUB/bootloader replacement (requires re-provisioning)
#
# Dependencies: tpm2-tools package
# ==============================================================================

set -euo pipefail

readonly SCRIPT_NAME="vtpm-attest"
readonly LOG_TAG="MILNET_PREFLIGHT"
readonly EXPECTED_PCRS="/opt/milnet/security/expected-pcrs.conf"
readonly TPM_DEVICE="/dev/tpmrm0"

# PCRs to verify. These cover the firmware-to-bootloader chain.
readonly -a PCRS_TO_CHECK=(0 2 4 7)

log_info()  { echo "[${LOG_TAG}] [${SCRIPT_NAME}] INFO:  $*"; }
log_warn()  { echo "[${LOG_TAG}] [${SCRIPT_NAME}] WARN:  $*" >&2; }
log_error() { echo "[${LOG_TAG}] [${SCRIPT_NAME}] ERROR: $*" >&2; }

# ── Check TPM availability ──────────────────────────────────────────────────

check_tpm_available() {
    if [[ ! -c "$TPM_DEVICE" ]]; then
        log_warn "TPM resource manager device not found at ${TPM_DEVICE}."

        # Check for the raw TPM device.
        if [[ -c /dev/tpm0 ]]; then
            log_warn "/dev/tpm0 exists but /dev/tpmrm0 does not."
            log_warn "Ensure tpm2-abrmd or the kernel resource manager is running."
        fi

        if [[ "${MILNET_REQUIRE_TPM:-true}" == "true" ]]; then
            log_error "MILNET_REQUIRE_TPM=true but no TPM device available. Aborting."
            return 1
        fi

        log_warn "Continuing without TPM attestation (MILNET_REQUIRE_TPM=false)."
        return 2  # Signal to skip remaining checks.
    fi

    # Verify tpm2-tools is installed.
    if ! command -v tpm2_pcrread &>/dev/null; then
        log_error "tpm2-tools is not installed. Cannot read PCR values."
        log_error "Install with: apt install tpm2-tools (Debian) or dnf install tpm2-tools (RHEL)."
        return 1
    fi

    log_info "TPM device found at ${TPM_DEVICE}."
}

# ── Read current PCR values ─────────────────────────────────────────────────

read_pcr_values() {
    local pcr_list
    pcr_list=$(printf "%s," "${PCRS_TO_CHECK[@]}")
    pcr_list="${pcr_list%,}"  # Remove trailing comma.

    # Read PCR values using SHA-256 bank (preferred) with SHA-1 fallback.
    if tpm2_pcrread "sha256:${pcr_list}" 2>/dev/null; then
        PCR_BANK="sha256"
    elif tpm2_pcrread "sha1:${pcr_list}" 2>/dev/null; then
        PCR_BANK="sha1"
        log_warn "Using SHA-1 PCR bank (SHA-256 not available). SHA-1 is deprecated."
    else
        log_error "Failed to read PCR values from TPM."
        return 1
    fi

    log_info "Using PCR bank: ${PCR_BANK}"
}

# ── Verify PCR values against baseline ──────────────────────────────────────

verify_pcrs() {
    if [[ ! -f "$EXPECTED_PCRS" ]]; then
        log_warn "Expected PCR baseline file not found at ${EXPECTED_PCRS}."
        log_warn "Run '/opt/milnet/security/vtpm-attest.sh --provision' to create baseline."
        log_warn "Skipping PCR verification (first boot?)."
        return 0
    fi

    local failures=0

    for pcr in "${PCRS_TO_CHECK[@]}"; do
        # Read current PCR value.
        local current
        current=$(tpm2_pcrread "${PCR_BANK}:${pcr}" 2>/dev/null | \
                  grep -oP '0x[0-9A-Fa-f]+' | head -1)

        # Read expected value from baseline file.
        local expected
        expected=$(grep -P "^PCR_${pcr}=" "$EXPECTED_PCRS" 2>/dev/null | \
                   cut -d'=' -f2 | tr -d ' "'"'"'')

        if [[ -z "$expected" ]]; then
            log_warn "No baseline for PCR ${pcr} in ${EXPECTED_PCRS}. Skipping."
            continue
        fi

        if [[ -z "$current" ]]; then
            log_error "Failed to read current value for PCR ${pcr}."
            ((failures++))
            continue
        fi

        # Normalize hex to lowercase for comparison.
        current=$(echo "$current" | tr '[:upper:]' '[:lower:]')
        expected=$(echo "$expected" | tr '[:upper:]' '[:lower:]')

        if [[ "$current" == "$expected" ]]; then
            log_info "PCR ${pcr}: OK (matches baseline)"
        else
            log_error "PCR ${pcr}: MISMATCH!"
            log_error "  Expected: ${expected}"
            log_error "  Current:  ${current}"
            log_error "  This indicates the boot chain has been modified."
            ((failures++))
        fi
    done

    if [[ $failures -gt 0 ]]; then
        log_error "${failures} PCR(s) deviated from baseline. Boot chain integrity FAILED."
        log_error "If this is due to a legitimate firmware/bootloader update, re-provision:"
        log_error "  /opt/milnet/security/vtpm-attest.sh --provision"
        return 1
    fi

    log_info "All PCR values match baseline."
}

# ── Provisioning mode ───────────────────────────────────────────────────────

provision_baselines() {
    log_info "=== PCR Baseline Provisioning Mode ==="
    log_warn "This will overwrite existing PCR baselines in ${EXPECTED_PCRS}."
    log_warn "Only run this on a KNOWN-GOOD system during initial setup."

    local pcr_list
    pcr_list=$(printf "%s," "${PCRS_TO_CHECK[@]}")
    pcr_list="${pcr_list%,}"

    # Determine available bank.
    if tpm2_pcrread "sha256:${pcr_list}" &>/dev/null; then
        PCR_BANK="sha256"
    else
        PCR_BANK="sha1"
    fi

    # Write baseline file.
    {
        echo "# MILNET SSO — Expected PCR Baseline Values"
        echo "# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "# Host: $(hostname -f 2>/dev/null || hostname)"
        echo "# PCR Bank: ${PCR_BANK}"
        echo "# WARNING: Re-provision after any firmware or bootloader update."
        echo ""
    } > "$EXPECTED_PCRS"

    for pcr in "${PCRS_TO_CHECK[@]}"; do
        local value
        value=$(tpm2_pcrread "${PCR_BANK}:${pcr}" 2>/dev/null | \
                grep -oP '0x[0-9A-Fa-f]+' | head -1)
        echo "PCR_${pcr}=${value}" >> "$EXPECTED_PCRS"
        log_info "Recorded PCR ${pcr} = ${value}"
    done

    chmod 0600 "$EXPECTED_PCRS"
    chown root:root "$EXPECTED_PCRS"
    log_info "Baseline written to ${EXPECTED_PCRS}."
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    log_info "=== vTPM Attestation ==="

    # Provisioning mode.
    if [[ "${1:-}" == "--provision" ]]; then
        check_tpm_available || return $?
        provision_baselines
        return 0
    fi

    # Normal verification mode.
    local tpm_status
    check_tpm_available
    tpm_status=$?

    if [[ $tpm_status -eq 2 ]]; then
        # TPM not required and not available — skip gracefully.
        return 0
    elif [[ $tpm_status -ne 0 ]]; then
        return 1
    fi

    read_pcr_values
    verify_pcrs

    log_info "=== vTPM attestation passed ==="
}

main "$@"
