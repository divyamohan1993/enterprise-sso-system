#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — TPM Key Sealing
# ==============================================================================
# Seals the master Key Encryption Key (KEK) to TPM PCR values. The sealed
# blob can only be unsealed when the PCR values match the sealing-time
# values, ensuring the KEK is only available when the system has booted
# with the expected firmware, bootloader, and Secure Boot policy.
#
# This provides hardware-bound key protection:
#   - KEK cannot be extracted from a powered-off disk
#   - KEK cannot be unsealed after boot chain modification
#   - KEK cannot be moved to a different machine
#
# Usage:
#   seal-keys.sh <kek-file>
#     Reads the KEK from <kek-file>, seals it to TPM PCRs 0,2,4,7,
#     and writes the sealed blob to /var/lib/milnet/tpm/sealed-kek.blob.
#     The original KEK file should be securely erased after sealing.
#
# Dependencies: tpm2-tools
# ==============================================================================

set -euo pipefail

readonly SCRIPT_NAME="seal-keys"
readonly LOG_TAG="MILNET_TPM"
readonly TPM_DIR="/var/lib/milnet/tpm"
readonly SEALED_BLOB="${TPM_DIR}/sealed-kek.blob"
readonly SEALED_POLICY="${TPM_DIR}/sealed-kek.policy"
readonly TPM_CONTEXT="${TPM_DIR}/primary.ctx"

# PCRs to bind the seal operation to.
# Changing any of these PCRs makes the sealed blob unrecoverable.
readonly PCR_LIST="sha256:0,2,4,7"

log_info()  { echo "[${LOG_TAG}] [${SCRIPT_NAME}] INFO:  $*"; }
log_error() { echo "[${LOG_TAG}] [${SCRIPT_NAME}] ERROR: $*" >&2; }

# ── Validate inputs ─────────────────────────────────────────────────────────

validate_inputs() {
    local kek_file="${1:-}"

    if [[ -z "$kek_file" ]]; then
        log_error "Usage: seal-keys.sh <kek-file>"
        log_error "  <kek-file>: Path to the plaintext KEK to seal."
        return 1
    fi

    if [[ ! -f "$kek_file" ]]; then
        log_error "KEK file not found: ${kek_file}"
        return 1
    fi

    # Sanity check: KEK should be 32 or 64 bytes (AES-256 or two keys).
    local kek_size
    kek_size=$(stat -c '%s' "$kek_file")
    if [[ $kek_size -lt 16 ]] || [[ $kek_size -gt 128 ]]; then
        log_error "KEK file size is ${kek_size} bytes (expected 16-128)."
        log_error "This does not look like a valid key file."
        return 1
    fi

    if ! command -v tpm2_createprimary &>/dev/null; then
        log_error "tpm2-tools is not installed."
        return 1
    fi

    if [[ ! -c /dev/tpmrm0 ]]; then
        log_error "TPM resource manager device not found at /dev/tpmrm0."
        return 1
    fi
}

# ── Create TPM directory structure ──────────────────────────────────────────

prepare_tpm_dir() {
    mkdir -p "$TPM_DIR"
    chmod 0700 "$TPM_DIR"
    chown root:root "$TPM_DIR"
}

# ── Seal KEK to TPM ────────────────────────────────────────────────────────

seal_kek() {
    local kek_file="$1"

    log_info "Creating TPM primary key under owner hierarchy..."
    tpm2_createprimary \
        -C o \
        -g sha256 \
        -G aes256cfb \
        -c "$TPM_CONTEXT" \
        2>/dev/null

    log_info "Creating PCR policy for seal (PCRs: ${PCR_LIST})..."
    tpm2_startauthsession -S /tmp/milnet-session.ctx 2>/dev/null
    tpm2_policypcr \
        -S /tmp/milnet-session.ctx \
        -l "$PCR_LIST" \
        -L "$SEALED_POLICY" \
        2>/dev/null
    tpm2_flushcontext /tmp/milnet-session.ctx 2>/dev/null
    rm -f /tmp/milnet-session.ctx

    log_info "Sealing KEK to TPM with PCR policy..."
    tpm2_create \
        -C "$TPM_CONTEXT" \
        -i "$kek_file" \
        -u "${SEALED_BLOB}.pub" \
        -r "${SEALED_BLOB}.priv" \
        -L "$SEALED_POLICY" \
        2>/dev/null

    log_info "Loading sealed object into TPM..."
    tpm2_load \
        -C "$TPM_CONTEXT" \
        -u "${SEALED_BLOB}.pub" \
        -r "${SEALED_BLOB}.priv" \
        -c "$SEALED_BLOB" \
        2>/dev/null

    # Set permissions on sealed blob files.
    chmod 0600 "${SEALED_BLOB}" "${SEALED_BLOB}.pub" "${SEALED_BLOB}.priv" "$SEALED_POLICY"
    chown root:root "${SEALED_BLOB}" "${SEALED_BLOB}.pub" "${SEALED_BLOB}.priv" "$SEALED_POLICY"

    # Clean up the primary context (not needed after loading).
    rm -f "$TPM_CONTEXT"

    log_info "KEK sealed successfully."
    log_info "Sealed blob: ${SEALED_BLOB}"
    log_info "Policy:      ${SEALED_POLICY}"
    log_info ""
    log_info "IMPORTANT: Securely erase the plaintext KEK file now:"
    log_info "  shred -vfz -n 3 ${kek_file}"
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    log_info "=== MILNET TPM Key Sealing ==="

    validate_inputs "$@"
    prepare_tpm_dir
    seal_kek "$1"

    log_info "=== Key sealing complete ==="
}

main "$@"
