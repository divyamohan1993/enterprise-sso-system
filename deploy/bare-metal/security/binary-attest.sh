#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Binary Attestation
# ==============================================================================
# Computes SHA-512 hashes of all MILNET service binaries and compares them
# against a signed manifest. Detects:
#   - Replaced binaries (supply chain attack)
#   - Modified binaries (runtime tampering)
#   - Missing binaries (incomplete deployment)
#
# The manifest is signed with an Ed25519 key; the public key is embedded
# in this script (or read from /opt/milnet/security/manifest-pubkey.pem).
#
# Dependencies: coreutils (sha512sum), openssl (signature verification)
# ==============================================================================

set -euo pipefail

readonly SCRIPT_NAME="binary-attest"
readonly LOG_TAG="MILNET_PREFLIGHT"
readonly BIN_DIR="/opt/milnet/bin"
readonly MANIFEST="/opt/milnet/security/binary-manifest.sha512"
readonly MANIFEST_SIG="/opt/milnet/security/binary-manifest.sha512.sig"
readonly PUBKEY="/opt/milnet/security/manifest-pubkey.pem"

# All expected MILNET binaries.
readonly -a MILNET_BINARIES=(
    gateway
    orchestrator
    opaque
    tss
    verifier
    ratchet
    audit
    admin
)

log_info()  { echo "[${LOG_TAG}] [${SCRIPT_NAME}] INFO:  $*"; }
log_warn()  { echo "[${LOG_TAG}] [${SCRIPT_NAME}] WARN:  $*" >&2; }
log_error() { echo "[${LOG_TAG}] [${SCRIPT_NAME}] ERROR: $*" >&2; }

# ── Check all binaries exist ────────────────────────────────────────────────

check_binaries_exist() {
    local missing=0

    for bin in "${MILNET_BINARIES[@]}"; do
        local path="${BIN_DIR}/${bin}"
        if [[ ! -f "$path" ]]; then
            log_error "Missing binary: ${path}"
            ((missing++))
        elif [[ ! -x "$path" ]]; then
            log_error "Binary not executable: ${path}"
            ((missing++))
        fi
    done

    if [[ $missing -gt 0 ]]; then
        log_error "${missing} binary(ies) missing or not executable."
        return 1
    fi

    log_info "All ${#MILNET_BINARIES[@]} binaries present and executable."
}

# ── Check binary permissions ────────────────────────────────────────────────

check_binary_permissions() {
    local issues=0

    for bin in "${MILNET_BINARIES[@]}"; do
        local path="${BIN_DIR}/${bin}"
        local perms owner group

        perms=$(stat -c '%a' "$path" 2>/dev/null)
        owner=$(stat -c '%U' "$path" 2>/dev/null)
        group=$(stat -c '%G' "$path" 2>/dev/null)

        # Binaries should be 0555 (r-xr-xr-x) owned by root:milnet.
        # No write permission for anyone.
        if [[ "$perms" != "555" ]]; then
            log_warn "Binary ${bin} has permissions ${perms} (expected 555)."
            ((issues++))
        fi

        if [[ "$owner" != "root" ]]; then
            log_warn "Binary ${bin} owned by ${owner} (expected root)."
            ((issues++))
        fi

        if [[ "$group" != "milnet" ]]; then
            log_warn "Binary ${bin} group is ${group} (expected milnet)."
            # Not a failure — just a warning.
        fi
    done

    if [[ $issues -gt 0 ]]; then
        log_warn "${issues} permission issue(s) found. Review binary ownership."
    fi
}

# ── Verify manifest signature ───────────────────────────────────────────────

verify_manifest_signature() {
    if [[ ! -f "$MANIFEST" ]]; then
        log_warn "Binary manifest not found at ${MANIFEST}."
        log_warn "Run '/opt/milnet/security/binary-attest.sh --generate' to create one."
        log_warn "Skipping hash verification (first deployment?)."
        return 2  # Signal to skip hash check.
    fi

    if [[ ! -f "$MANIFEST_SIG" ]]; then
        log_warn "Manifest signature not found at ${MANIFEST_SIG}."
        log_warn "Manifest exists but is unsigned — cannot verify authenticity."
        if [[ "${MILNET_REQUIRE_SIGNED_MANIFEST:-false}" == "true" ]]; then
            log_error "MILNET_REQUIRE_SIGNED_MANIFEST=true but no signature found. Aborting."
            return 1
        fi
        return 0
    fi

    if [[ ! -f "$PUBKEY" ]]; then
        log_error "Manifest public key not found at ${PUBKEY}."
        log_error "Cannot verify manifest signature without the public key."
        return 1
    fi

    # Verify the Ed25519 signature on the manifest.
    if openssl pkeyutl -verify \
        -pubin -inkey "$PUBKEY" \
        -sigfile "$MANIFEST_SIG" \
        -in "$MANIFEST" \
        -rawin 2>/dev/null; then
        log_info "Manifest signature verified (authentic)."
    else
        log_error "Manifest signature INVALID! The manifest may have been tampered with."
        return 1
    fi
}

# ── Verify binary hashes against manifest ───────────────────────────────────

verify_binary_hashes() {
    if [[ ! -f "$MANIFEST" ]]; then
        return 0  # Already warned in signature check.
    fi

    local failures=0

    for bin in "${MILNET_BINARIES[@]}"; do
        local path="${BIN_DIR}/${bin}"

        # Compute current SHA-512.
        local current_hash
        current_hash=$(sha512sum "$path" | awk '{print $1}')

        # Look up expected hash in manifest.
        local expected_hash
        expected_hash=$(grep -P "\s+${bin}\$" "$MANIFEST" 2>/dev/null | awk '{print $1}')

        if [[ -z "$expected_hash" ]]; then
            log_warn "Binary ${bin} not found in manifest. New binary?"
            continue
        fi

        if [[ "$current_hash" == "$expected_hash" ]]; then
            log_info "Binary ${bin}: OK (SHA-512 matches)"
        else
            log_error "Binary ${bin}: HASH MISMATCH!"
            log_error "  Expected: ${expected_hash}"
            log_error "  Current:  ${current_hash}"
            log_error "  The binary has been modified since the manifest was generated."
            ((failures++))
        fi
    done

    if [[ $failures -gt 0 ]]; then
        log_error "${failures} binary(ies) failed hash verification."
        return 1
    fi

    log_info "All binary hashes match manifest."
}

# ── Generate manifest ───────────────────────────────────────────────────────

generate_manifest() {
    log_info "=== Generating Binary Manifest ==="
    log_warn "Only run this with KNOWN-GOOD binaries from a trusted build."

    mkdir -p "$(dirname "$MANIFEST")"

    {
        echo "# MILNET SSO — Binary Attestation Manifest (SHA-512)"
        echo "# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "# Host: $(hostname -f 2>/dev/null || hostname)"
        echo "#"
    } > "$MANIFEST"

    for bin in "${MILNET_BINARIES[@]}"; do
        local path="${BIN_DIR}/${bin}"
        if [[ -f "$path" ]]; then
            sha512sum "$path" >> "$MANIFEST"
            log_info "Recorded: ${bin}"
        else
            log_warn "Binary not found: ${path} (skipping)"
        fi
    done

    chmod 0644 "$MANIFEST"
    chown root:root "$MANIFEST"

    log_info "Manifest written to ${MANIFEST}."
    log_info "Sign it with: openssl pkeyutl -sign -inkey <privkey> -out ${MANIFEST_SIG} -rawin -in ${MANIFEST}"
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    log_info "=== Binary Attestation ==="

    # Manifest generation mode.
    if [[ "${1:-}" == "--generate" ]]; then
        check_binaries_exist
        generate_manifest
        return 0
    fi

    check_binaries_exist
    check_binary_permissions

    local sig_status
    verify_manifest_signature
    sig_status=$?

    if [[ $sig_status -ne 2 ]]; then
        verify_binary_hashes
    fi

    log_info "=== Binary attestation passed ==="
}

main "$@"
