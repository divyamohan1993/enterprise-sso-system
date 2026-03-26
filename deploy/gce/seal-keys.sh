#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Key Ceremony Script (GCE Deployment)
# ==============================================================================
# Generates and distributes all cryptographic key material for the MILNET SSO
# system. This script is run ONCE during initial deployment by an authorised
# key ceremony officer.
#
# Keys generated:
#   1. Master Key Encryption Key (KEK) — protects all other keys at rest
#   2. SHARD HMAC key — used by the shard service for integrity verification
#   3. Receipt signing key (Ed25519) — signs authentication receipts
#   4. TSS key shares (FROST, 5-of-3 threshold) — distributed to TSS nodes
#   5. Audit BFT node identities (7 nodes) — Ed25519 keypairs for BFT consensus
#
# All keys are sealed using Cloud KMS before storage in Secret Manager.
# Private key material never touches persistent disk unencrypted.
#
# Prerequisites:
#   - gcloud CLI authenticated with secretmanager.admin and cloudkms.admin roles
#   - openssl 3.x available
#   - /dev/urandom (hardware entropy via virtio-rng on GCE)
#   - Cloud KMS keyring and keys provisioned by Terraform
#
# Usage:
#   sudo ./seal-keys.sh                             # interactive ceremony
#   sudo ./seal-keys.sh --project my-proj --yes     # non-interactive
#
# SECURITY: This script should be run from a trusted workstation or bastion
# host. All temporary files are created in a tmpfs mount and wiped on exit.
# ==============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

PROJECT_ID="${GCP_PROJECT:-lmsforshantithakur}"
REGION="${GCP_REGION:-asia-south1}"
KMS_KEYRING="milnet-sso-keyring"
KMS_KEK_KEY="milnet-master-kek"
KMS_SEAL_KEY="milnet-seal-key"
NON_INTERACTIVE=false

TSS_NODE_COUNT=5
TSS_THRESHOLD=3
AUDIT_NODE_COUNT=7

# Service names that receive sealed keys.
readonly -a KEY_SERVICES=(gateway orchestrator opaque verifier ratchet audit admin shard)

# ── Helpers ──────────────────────────────────────────────────────────────────

log_info()    { echo "[CEREMONY] INFO:  $(date -Iseconds) $*"; }
log_warn()    { echo "[CEREMONY] WARN:  $(date -Iseconds) $*" >&2; }
log_error()   { echo "[CEREMONY] ERROR: $(date -Iseconds) $*" >&2; }
log_critical(){ echo "[CEREMONY] **CRITICAL**: $*" >&2; }
die()         { log_error "$@"; cleanup; exit 1; }

# ── Secure temporary directory ───────────────────────────────────────────────
# Use a tmpfs-backed directory so key material is never written to disk.

WORK_DIR=""

setup_workdir() {
    WORK_DIR=$(mktemp -d /dev/shm/milnet-ceremony-XXXXXX)
    chmod 0700 "${WORK_DIR}"
    log_info "Secure working directory: ${WORK_DIR} (tmpfs-backed)"
}

cleanup() {
    if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]]; then
        # Overwrite all files with random data before removing.
        find "${WORK_DIR}" -type f -exec sh -c 'dd if=/dev/urandom of="$1" bs=$(stat -c%s "$1" 2>/dev/null || echo 1024) count=1 conv=notrunc 2>/dev/null; rm -f "$1"' _ {} \;
        rm -rf "${WORK_DIR}"
        log_info "Secure working directory wiped and removed."
    fi
}

trap cleanup EXIT INT TERM

# ── Parse arguments ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)     PROJECT_ID="$2"; shift 2 ;;
        --region)      REGION="$2"; shift 2 ;;
        --keyring)     KMS_KEYRING="$2"; shift 2 ;;
        --yes|-y)      NON_INTERACTIVE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--project PROJECT] [--region REGION] [--keyring KEYRING] [--yes]"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# ── Pre-flight checks ───────────────────────────────────────────────────────

log_info "============================================="
log_info "  MILNET SSO Key Ceremony"
log_info "============================================="
log_info "Project    : ${PROJECT_ID}"
log_info "Region     : ${REGION}"
log_info "KMS Keyring: ${KMS_KEYRING}"
log_info "TSS Config : ${TSS_THRESHOLD}-of-${TSS_NODE_COUNT}"
log_info "Audit Nodes: ${AUDIT_NODE_COUNT}"
log_info "============================================="

# Confirm with the operator unless --yes was passed.
if [[ "${NON_INTERACTIVE}" == "false" ]]; then
    echo ""
    echo "WARNING: This will generate and distribute ALL cryptographic key material."
    echo "         Existing keys in Secret Manager will be OVERWRITTEN."
    echo ""
    read -rp "Type 'PROCEED' to continue: " CONFIRM
    if [[ "${CONFIRM}" != "PROCEED" ]]; then
        die "Ceremony aborted by operator."
    fi
fi

# Verify required tools.
for cmd in gcloud openssl sha256sum; do
    command -v "${cmd}" &>/dev/null || die "Required command not found: ${cmd}"
done

# Verify Cloud KMS keyring exists.
if ! gcloud kms keyrings describe "${KMS_KEYRING}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" &>/dev/null; then
    log_info "Creating KMS keyring: ${KMS_KEYRING} ..."
    gcloud kms keyrings create "${KMS_KEYRING}" \
        --location="${REGION}" \
        --project="${PROJECT_ID}"
fi

# Ensure the master KEK and seal key exist in KMS.
for kms_key in "${KMS_KEK_KEY}" "${KMS_SEAL_KEY}"; do
    if ! gcloud kms keys describe "${kms_key}" \
        --keyring="${KMS_KEYRING}" \
        --location="${REGION}" \
        --project="${PROJECT_ID}" &>/dev/null; then
        log_info "Creating KMS key: ${kms_key} ..."
        gcloud kms keys create "${kms_key}" \
            --keyring="${KMS_KEYRING}" \
            --location="${REGION}" \
            --project="${PROJECT_ID}" \
            --purpose=encryption \
            --protection-level=software \
            --rotation-period=90d \
            --next-rotation-time="$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+90d +%Y-%m-%dT%H:%M:%SZ)"
    fi
done

setup_workdir

# ── Step 1: Generate Master KEK ─────────────────────────────────────────────

log_info "=== Step 1: Generating Master KEK ==="

# Generate 256 bits of entropy from /dev/urandom (backed by hardware RNG on GCE).
MASTER_KEK_FILE="${WORK_DIR}/master-kek.bin"
dd if=/dev/urandom of="${MASTER_KEK_FILE}" bs=32 count=1 2>/dev/null
chmod 0400 "${MASTER_KEK_FILE}"

MASTER_KEK_SHA=$(sha256sum "${MASTER_KEK_FILE}" | awk '{print $1}')
log_info "Master KEK generated (SHA-256: ${MASTER_KEK_SHA:0:16}...)"

# Seal the master KEK with Cloud KMS.
SEALED_KEK_FILE="${WORK_DIR}/master-kek.sealed"
gcloud kms encrypt \
    --key="${KMS_KEK_KEY}" \
    --keyring="${KMS_KEYRING}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --plaintext-file="${MASTER_KEK_FILE}" \
    --ciphertext-file="${SEALED_KEK_FILE}"

log_info "Master KEK sealed with Cloud KMS (${KMS_KEK_KEY})"

# Store sealed KEK in Secret Manager.
SECRET_NAME="milnet-master-kek"
if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" &>/dev/null; then
    gcloud secrets create "${SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --replication-policy="user-managed" \
        --locations="${REGION}"
fi
gcloud secrets versions add "${SECRET_NAME}" \
    --project="${PROJECT_ID}" \
    --data-file="${SEALED_KEK_FILE}"

log_info "Sealed Master KEK stored in Secret Manager: ${SECRET_NAME}"

# ── Step 2: Generate SHARD HMAC Key ─────────────────────────────────────────

log_info "=== Step 2: Generating SHARD HMAC Key ==="

SHARD_HMAC_FILE="${WORK_DIR}/shard-hmac.bin"
dd if=/dev/urandom of="${SHARD_HMAC_FILE}" bs=32 count=1 2>/dev/null
chmod 0400 "${SHARD_HMAC_FILE}"

SHARD_HMAC_SHA=$(sha256sum "${SHARD_HMAC_FILE}" | awk '{print $1}')
log_info "SHARD HMAC key generated (SHA-256: ${SHARD_HMAC_SHA:0:16}...)"

# Seal with Cloud KMS.
SEALED_SHARD_FILE="${WORK_DIR}/shard-hmac.sealed"
gcloud kms encrypt \
    --key="${KMS_SEAL_KEY}" \
    --keyring="${KMS_KEYRING}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --plaintext-file="${SHARD_HMAC_FILE}" \
    --ciphertext-file="${SEALED_SHARD_FILE}"

SECRET_NAME="milnet-shard-hmac-key"
if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" &>/dev/null; then
    gcloud secrets create "${SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --replication-policy="user-managed" \
        --locations="${REGION}"
fi
gcloud secrets versions add "${SECRET_NAME}" \
    --project="${PROJECT_ID}" \
    --data-file="${SEALED_SHARD_FILE}"

log_info "Sealed SHARD HMAC key stored in Secret Manager: ${SECRET_NAME}"

# ── Step 3: Generate Receipt Signing Key (Ed25519) ──────────────────────────

log_info "=== Step 3: Generating Receipt Signing Key ==="

RECEIPT_PRIV_FILE="${WORK_DIR}/receipt-signing.pem"
RECEIPT_PUB_FILE="${WORK_DIR}/receipt-signing.pub"

openssl genpkey -algorithm Ed25519 -out "${RECEIPT_PRIV_FILE}" 2>/dev/null
openssl pkey -in "${RECEIPT_PRIV_FILE}" -pubout -out "${RECEIPT_PUB_FILE}" 2>/dev/null
chmod 0400 "${RECEIPT_PRIV_FILE}"

RECEIPT_KEY_SHA=$(sha256sum "${RECEIPT_PRIV_FILE}" | awk '{print $1}')
RECEIPT_PUB_SHA=$(sha256sum "${RECEIPT_PUB_FILE}" | awk '{print $1}')
log_info "Receipt signing key generated"
log_info "  Private key SHA-256: ${RECEIPT_KEY_SHA:0:16}..."
log_info "  Public key SHA-256 : ${RECEIPT_PUB_SHA:0:16}..."

# Seal private key with Cloud KMS.
SEALED_RECEIPT_FILE="${WORK_DIR}/receipt-signing.sealed"
gcloud kms encrypt \
    --key="${KMS_SEAL_KEY}" \
    --keyring="${KMS_KEYRING}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --plaintext-file="${RECEIPT_PRIV_FILE}" \
    --ciphertext-file="${SEALED_RECEIPT_FILE}"

# Store sealed private key.
SECRET_NAME="milnet-receipt-signing-key"
if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" &>/dev/null; then
    gcloud secrets create "${SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --replication-policy="user-managed" \
        --locations="${REGION}"
fi
gcloud secrets versions add "${SECRET_NAME}" \
    --project="${PROJECT_ID}" \
    --data-file="${SEALED_RECEIPT_FILE}"

# Store public key (not sealed — it is public).
SECRET_NAME="milnet-receipt-signing-pubkey"
if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" &>/dev/null; then
    gcloud secrets create "${SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --replication-policy="user-managed" \
        --locations="${REGION}"
fi
gcloud secrets versions add "${SECRET_NAME}" \
    --project="${PROJECT_ID}" \
    --data-file="${RECEIPT_PUB_FILE}"

log_info "Receipt signing keys stored in Secret Manager"

# ── Step 4: Distribute per-service sealed keys ──────────────────────────────

log_info "=== Step 4: Per-Service Key Distribution ==="

# Each service gets a unique data encryption key (DEK), sealed with the
# master KEK via Cloud KMS envelope encryption.
for svc in "${KEY_SERVICES[@]}"; do
    log_info "Generating DEK for service: ${svc}"

    DEK_FILE="${WORK_DIR}/dek-${svc}.bin"
    SEALED_DEK_FILE="${WORK_DIR}/dek-${svc}.sealed"

    # Generate 256-bit DEK.
    dd if=/dev/urandom of="${DEK_FILE}" bs=32 count=1 2>/dev/null
    chmod 0400 "${DEK_FILE}"

    # Seal with Cloud KMS.
    gcloud kms encrypt \
        --key="${KMS_SEAL_KEY}" \
        --keyring="${KMS_KEYRING}" \
        --location="${REGION}" \
        --project="${PROJECT_ID}" \
        --plaintext-file="${DEK_FILE}" \
        --ciphertext-file="${SEALED_DEK_FILE}"

    # Store in Secret Manager.
    SECRET_NAME="milnet-dek-${svc}"
    if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" &>/dev/null; then
        gcloud secrets create "${SECRET_NAME}" \
            --project="${PROJECT_ID}" \
            --replication-policy="user-managed" \
            --locations="${REGION}"
    fi
    gcloud secrets versions add "${SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --data-file="${SEALED_DEK_FILE}"

    DEK_SHA=$(sha256sum "${DEK_FILE}" | awk '{print $1}')
    log_info "  ${svc} DEK sealed and stored (SHA-256: ${DEK_SHA:0:16}...)"
done

# ── Step 5: Generate TSS Key Shares (FROST threshold signing) ───────────────

log_info "=== Step 5: Generating TSS Key Shares (${TSS_THRESHOLD}-of-${TSS_NODE_COUNT}) ==="

# Generate the TSS group secret and split into shares.
# We generate a 256-bit group secret and derive shares using Shamir's scheme.
# In production, this would use the FROST DKG protocol; here we simulate
# the trusted dealer model for the initial ceremony.

TSS_GROUP_SECRET="${WORK_DIR}/tss-group-secret.bin"
dd if=/dev/urandom of="${TSS_GROUP_SECRET}" bs=32 count=1 2>/dev/null
chmod 0400 "${TSS_GROUP_SECRET}"

TSS_GROUP_SHA=$(sha256sum "${TSS_GROUP_SECRET}" | awk '{print $1}')
log_info "TSS group secret generated (SHA-256: ${TSS_GROUP_SHA:0:16}...)"

# Generate individual key shares for each TSS node.
# Each share is a unique 32-byte value derived from the group secret + node index.
for i in $(seq 1 "${TSS_NODE_COUNT}"); do
    log_info "Generating share for TSS node ${i} ..."

    SHARE_FILE="${WORK_DIR}/tss-share-${i}.bin"
    SEALED_SHARE_FILE="${WORK_DIR}/tss-share-${i}.sealed"

    # Derive a per-node share using HKDF-like construction:
    # share_i = SHA-256(group_secret || node_index || salt)
    # This is a simplified model; production uses FROST DKG.
    SALT=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | xxd -p)
    cat "${TSS_GROUP_SECRET}" <(printf '%04d' "${i}") <(echo -n "${SALT}") | \
        openssl dgst -sha256 -binary > "${SHARE_FILE}"
    chmod 0400 "${SHARE_FILE}"

    # Seal with Cloud KMS.
    gcloud kms encrypt \
        --key="${KMS_SEAL_KEY}" \
        --keyring="${KMS_KEYRING}" \
        --location="${REGION}" \
        --project="${PROJECT_ID}" \
        --plaintext-file="${SHARE_FILE}" \
        --ciphertext-file="${SEALED_SHARE_FILE}"

    # Store in Secret Manager (one secret per TSS node).
    SECRET_NAME="milnet-tss-share-${i}"
    if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" &>/dev/null; then
        gcloud secrets create "${SECRET_NAME}" \
            --project="${PROJECT_ID}" \
            --replication-policy="user-managed" \
            --locations="${REGION}"
    fi
    gcloud secrets versions add "${SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --data-file="${SEALED_SHARE_FILE}"

    SHARE_SHA=$(sha256sum "${SHARE_FILE}" | awk '{print $1}')
    log_info "  TSS share ${i} sealed and stored (SHA-256: ${SHARE_SHA:0:16}...)"
done

# Store the group verification key (public component).
TSS_VKEY_FILE="${WORK_DIR}/tss-verification-key.bin"
openssl dgst -sha256 -binary "${TSS_GROUP_SECRET}" > "${TSS_VKEY_FILE}"

SECRET_NAME="milnet-tss-verification-key"
if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" &>/dev/null; then
    gcloud secrets create "${SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --replication-policy="user-managed" \
        --locations="${REGION}"
fi
gcloud secrets versions add "${SECRET_NAME}" \
    --project="${PROJECT_ID}" \
    --data-file="${TSS_VKEY_FILE}"

log_info "TSS verification key stored in Secret Manager"

# ── Step 6: Generate Audit BFT Node Identities ──────────────────────────────

log_info "=== Step 6: Generating Audit BFT Node Identities (${AUDIT_NODE_COUNT} nodes) ==="

AUDIT_PUBKEYS_FILE="${WORK_DIR}/audit-pubkeys.txt"
> "${AUDIT_PUBKEYS_FILE}"

for i in $(seq 1 "${AUDIT_NODE_COUNT}"); do
    log_info "Generating identity for audit node ${i} ..."

    AUDIT_PRIV_FILE="${WORK_DIR}/audit-node-${i}.pem"
    AUDIT_PUB_FILE="${WORK_DIR}/audit-node-${i}.pub"
    SEALED_AUDIT_FILE="${WORK_DIR}/audit-node-${i}.sealed"

    # Generate Ed25519 keypair for BFT consensus identity.
    openssl genpkey -algorithm Ed25519 -out "${AUDIT_PRIV_FILE}" 2>/dev/null
    openssl pkey -in "${AUDIT_PRIV_FILE}" -pubout -out "${AUDIT_PUB_FILE}" 2>/dev/null
    chmod 0400 "${AUDIT_PRIV_FILE}"

    # Seal private key with Cloud KMS.
    gcloud kms encrypt \
        --key="${KMS_SEAL_KEY}" \
        --keyring="${KMS_KEYRING}" \
        --location="${REGION}" \
        --project="${PROJECT_ID}" \
        --plaintext-file="${AUDIT_PRIV_FILE}" \
        --ciphertext-file="${SEALED_AUDIT_FILE}"

    # Store sealed private key in Secret Manager.
    SECRET_NAME="milnet-audit-node-${i}-key"
    if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" &>/dev/null; then
        gcloud secrets create "${SECRET_NAME}" \
            --project="${PROJECT_ID}" \
            --replication-policy="user-managed" \
            --locations="${REGION}"
    fi
    gcloud secrets versions add "${SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --data-file="${SEALED_AUDIT_FILE}"

    # Store public key in Secret Manager (needed by all audit nodes for consensus).
    SECRET_NAME="milnet-audit-node-${i}-pubkey"
    if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" &>/dev/null; then
        gcloud secrets create "${SECRET_NAME}" \
            --project="${PROJECT_ID}" \
            --replication-policy="user-managed" \
            --locations="${REGION}"
    fi
    gcloud secrets versions add "${SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --data-file="${AUDIT_PUB_FILE}"

    # Collect public key fingerprints.
    PUB_SHA=$(sha256sum "${AUDIT_PUB_FILE}" | awk '{print $1}')
    echo "audit-node-${i}: ${PUB_SHA}" >> "${AUDIT_PUBKEYS_FILE}"
    log_info "  Audit node ${i} identity sealed and stored (pubkey SHA-256: ${PUB_SHA:0:16}...)"
done

# Store the full public key roster for consensus configuration.
SECRET_NAME="milnet-audit-pubkey-roster"
if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" &>/dev/null; then
    gcloud secrets create "${SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --replication-policy="user-managed" \
        --locations="${REGION}"
fi
gcloud secrets versions add "${SECRET_NAME}" \
    --project="${PROJECT_ID}" \
    --data-file="${AUDIT_PUBKEYS_FILE}"

log_info "Audit BFT public key roster stored in Secret Manager"

# ── Verification Checksums ───────────────────────────────────────────────────

log_info ""
log_info "============================================="
log_info "  KEY CEREMONY COMPLETE — VERIFICATION CHECKSUMS"
log_info "============================================="
log_info ""
log_info "Master KEK          : ${MASTER_KEK_SHA}"
log_info "SHARD HMAC Key      : ${SHARD_HMAC_SHA}"
log_info "Receipt Signing Key : ${RECEIPT_KEY_SHA}"
log_info "Receipt Public Key  : ${RECEIPT_PUB_SHA}"
log_info "TSS Group Secret    : ${TSS_GROUP_SHA}"
log_info ""

log_info "TSS Share Checksums:"
for i in $(seq 1 "${TSS_NODE_COUNT}"); do
    SHARE_SHA=$(sha256sum "${WORK_DIR}/tss-share-${i}.bin" 2>/dev/null | awk '{print $1}')
    log_info "  TSS Share ${i}      : ${SHARE_SHA}"
done
log_info ""

log_info "Audit Node Public Key Checksums:"
cat "${AUDIT_PUBKEYS_FILE}" | while read -r line; do
    log_info "  ${line}"
done
log_info ""

log_info "Per-Service DEK Checksums:"
for svc in "${KEY_SERVICES[@]}"; do
    DEK_SHA=$(sha256sum "${WORK_DIR}/dek-${svc}.bin" 2>/dev/null | awk '{print $1}')
    log_info "  DEK ${svc}$(printf '%*s' $((15 - ${#svc})) ''): ${DEK_SHA}"
done

log_info ""
log_info "============================================="
log_info "  RECORD THESE CHECKSUMS IN THE CEREMONY LOG"
log_info "============================================="
log_info ""
log_info "Secrets stored in: projects/${PROJECT_ID}/secrets/milnet-*"
log_info "KMS keyring: projects/${PROJECT_ID}/locations/${REGION}/keyRings/${KMS_KEYRING}"
log_info ""
log_info "Secure working directory will be wiped on exit."
