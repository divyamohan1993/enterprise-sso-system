#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — TPM Key Unsealing
# ==============================================================================
# Unseals the master KEK from the TPM. This operation ONLY succeeds when
# the current PCR values match those at sealing time. If the boot chain
# has been modified (firmware update, bootkit, bootloader change), the
# unseal operation fails and the KEK remains inaccessible.
#
# Usage:
#   unseal-keys.sh [output-file]
#     Unseals the KEK and writes it to output-file (default: stdout).
#     In production, pipe directly to the service that needs it:
#       unseal-keys.sh | milnet-orchestrator --kek-from-stdin
#
# Dependencies: tpm2-tools
# ==============================================================================

set -euo pipefail

readonly SCRIPT_NAME="unseal-keys"
readonly LOG_TAG="MILNET_TPM"
readonly TPM_DIR="/var/lib/milnet/tpm"
readonly SEALED_BLOB="${TPM_DIR}/sealed-kek.blob"
readonly SEALED_POLICY="${TPM_DIR}/sealed-kek.policy"
readonly TPM_CONTEXT="${TPM_DIR}/primary.ctx"
readonly PCR_LIST="sha256:0,2,4,7"

log_info()  { echo "[${LOG_TAG}] [${SCRIPT_NAME}] INFO:  $*" >&2; }
log_error() { echo "[${LOG_TAG}] [${SCRIPT_NAME}] ERROR: $*" >&2; }

# ── Validate prerequisites ──────────────────────────────────────────────────

validate() {
    if [[ ! -c /dev/tpmrm0 ]]; then
        log_error "TPM resource manager device not found at /dev/tpmrm0."
        return 1
    fi

    if ! command -v tpm2_unseal &>/dev/null; then
        log_error "tpm2-tools is not installed."
        return 1
    fi

    for f in "${SEALED_BLOB}.pub" "${SEALED_BLOB}.priv" "$SEALED_POLICY"; do
        if [[ ! -f "$f" ]]; then
            log_error "Required sealed blob component not found: ${f}"
            log_error "Has the KEK been sealed? Run seal-keys.sh first."
            return 1
        fi
    done
}

# ── Unseal KEK ──────────────────────────────────────────────────────────────

unseal_kek() {
    local output="${1:-/dev/stdout}"

    log_info "Recreating TPM primary key..."
    tpm2_createprimary \
        -C o \
        -g sha256 \
        -G aes256cfb \
        -c "$TPM_CONTEXT" \
        2>/dev/null

    log_info "Loading sealed object..."
    local loaded_ctx="/tmp/milnet-loaded.ctx"
    tpm2_load \
        -C "$TPM_CONTEXT" \
        -u "${SEALED_BLOB}.pub" \
        -r "${SEALED_BLOB}.priv" \
        -c "$loaded_ctx" \
        2>/dev/null

    log_info "Starting policy session for PCR verification..."
    tpm2_startauthsession \
        --policy-session \
        -S /tmp/milnet-policy-session.ctx \
        2>/dev/null

    tpm2_policypcr \
        -S /tmp/milnet-policy-session.ctx \
        -l "$PCR_LIST" \
        2>/dev/null

    log_info "Unsealing KEK (will fail if boot chain has changed)..."
    if tpm2_unseal \
        -c "$loaded_ctx" \
        -p "session:/tmp/milnet-policy-session.ctx" \
        -o "$output" \
        2>/dev/null; then
        log_info "KEK unsealed successfully."
    else
        log_error "TPM UNSEAL FAILED!"
        log_error "This means the current PCR values do not match the sealing-time values."
        log_error "Possible causes:"
        log_error "  1. Firmware was updated (re-seal after verifying the update)"
        log_error "  2. Bootloader was modified (investigate for tampering)"
        log_error "  3. Secure Boot policy changed (check UEFI settings)"
        log_error "  4. Bootkit or rootkit has been installed (INCIDENT RESPONSE REQUIRED)"
        log_error ""
        log_error "The master KEK is INACCESSIBLE until the boot chain is restored"
        log_error "to its original state, or the KEK is re-sealed to new PCR values"
        log_error "using a backup of the plaintext KEK."

        # Clean up session.
        tpm2_flushcontext /tmp/milnet-policy-session.ctx 2>/dev/null || true
        rm -f "$loaded_ctx" "$TPM_CONTEXT" /tmp/milnet-policy-session.ctx
        return 1
    fi

    # Clean up temporary files.
    tpm2_flushcontext /tmp/milnet-policy-session.ctx 2>/dev/null || true
    rm -f "$loaded_ctx" "$TPM_CONTEXT" /tmp/milnet-policy-session.ctx
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    log_info "=== MILNET TPM Key Unsealing ==="

    validate
    unseal_kek "${1:-/dev/stdout}"

    log_info "=== Key unsealing complete ==="
}

main "$@"
