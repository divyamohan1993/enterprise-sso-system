#!/usr/bin/env bash
# =============================================================================
# MILNET SSO - Quantum-Safe Key Ceremony
#
# Runs in the controller's WSL2. Produces all cryptographic material the fleet
# needs, written as plain files into the output directory for the Fleet
# Commander to pick up and distribute inside per-node payloads.
#
# Usage:
#   key-ceremony.sh <out-dir> <bin-dir> <repo-dir> <node-ip-1> <node-ip-2> ...
#
# Produces in <out-dir>:
#   ca.crt ca.key                 - internal Certificate Authority
#   <ip-with-dashes>.crt/.key     - per-node mTLS identity (SAN = node IP),
#                                   usable as BOTH server and client cert
#   master_kek.hex                - 32-byte master Key Encryption Key (64 hex)
#   shard_hmac.hex receipt_signing.hex audit_hmac.hex
#   session_enc.hex ratchet_seed.hex kt_hmac.hex   - HKDF/HMAC sub-keys
#   tss_share_1..5.b64            - FROST 3-of-5 sealed signer shares (if the
#                                   tss binary exposes a keygen CLI; otherwise
#                                   left empty and signers run DKG on startup)
#   tss_public_key.b64            - FROST group public key package
#   group_verifying_key.hex pq_verifying_key.hex
#   key_pins.txt deployment_id.txt db_password.txt
# =============================================================================
set -euo pipefail

OUT="${1:?out-dir required}"
BIN="${2:?bin-dir required}"
REPO="${3:?repo-dir required}"
shift 3
NODE_IPS=("$@")
[ "${#NODE_IPS[@]}" -ge 1 ] || { echo "FATAL: no node IPs given" >&2; exit 1; }

log() { echo "[key-ceremony] $*"; }
mkdir -p "$OUT"
chmod 700 "$OUT"

# --- ensure tools ------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
if ! command -v openssl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq openssl python3 >/dev/null 2>&1 || true
fi

# --- 1. Internal CA ----------------------------------------------------------
log "Generating internal Certificate Authority..."
openssl ecparam -genkey -name prime256v1 -out "$OUT/ca.key" 2>/dev/null
openssl req -new -x509 -key "$OUT/ca.key" -out "$OUT/ca.crt" -days 365 \
    -subj "/C=IN/O=MILNET/OU=SSO/CN=MILNET Internal Root CA" 2>/dev/null
chmod 600 "$OUT/ca.key"

# --- 2. Per-node mTLS certificates (SAN = node IP, server+client) -----------
log "Issuing per-node mTLS certificates for ${#NODE_IPS[@]} node(s)..."
SERIAL=1
for ip in "${NODE_IPS[@]}"; do
    safe="${ip//./-}"
    openssl ecparam -genkey -name prime256v1 -out "$OUT/$safe.key" 2>/dev/null
    openssl req -new -key "$OUT/$safe.key" -out "$OUT/$safe.csr" \
        -subj "/C=IN/O=MILNET/OU=SSO/CN=milnet-node-$safe" 2>/dev/null
    cat > "$OUT/$safe.ext" <<EXT
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=IP:$ip,DNS:milnet-node-$safe,IP:127.0.0.1
EXT
    openssl x509 -req -in "$OUT/$safe.csr" \
        -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -set_serial "$SERIAL" \
        -out "$OUT/$safe.crt" -days 365 -extfile "$OUT/$safe.ext" 2>/dev/null
    chmod 600 "$OUT/$safe.key"
    rm -f "$OUT/$safe.csr" "$OUT/$safe.ext"
    SERIAL=$((SERIAL+1))
done
log "mTLS certificates issued (server+client EKU, SAN-pinned to each node IP)."

# --- 3. Master KEK + derived sub-keys ---------------------------------------
log "Generating master KEK and deriving sub-keys (HMAC-SHA512)..."
openssl rand -hex 32 > "$OUT/master_kek.hex"
MASTER_KEK="$(cat "$OUT/master_kek.hex")"

derive() {  # derive <label> <outfile>
    printf '%s' "$1" | \
        openssl dgst -sha512 -mac HMAC -macopt "hexkey:${MASTER_KEK}" -hex 2>/dev/null | \
        awk '{print $NF}' | cut -c1-64 > "$OUT/$2"
}
derive "milnet-shard-hmac-v1"     shard_hmac.hex
derive "milnet-receipt-signing-v1" receipt_signing.hex
derive "milnet-audit-hmac-v1"     audit_hmac.hex
derive "milnet-session-enc-v1"    session_enc.hex
derive "milnet-ratchet-seed-v1"   ratchet_seed.hex
derive "milnet-kt-hmac-v1"        kt_hmac.hex

# --- 4. FROST 3-of-5 threshold signing key + ML-DSA-87 verifying key --------
log "Generating FROST 3-of-5 threshold signing key material..."
: > "$OUT/tss_public_key.b64"
: > "$OUT/group_verifying_key.hex"
: > "$OUT/pq_verifying_key.hex"
for i in 1 2 3 4 5; do : > "$OUT/tss_share_$i.b64"; : > "$OUT/tss_signer_$i.id"; done

# The keygen runs the codebase's own production Pedersen DKG
# (crypto::threshold::dkg_distributed) and share sealing via the
# tss/examples/fleet_keygen.rs helper, so the sealed shares, group public key
# and PQ verifying key are byte-for-byte what the deployed services expect.
# MILNET_MASTER_KEK must be exported so the sealed shares match the signers'.
FROST_DONE=0
if command -v cargo >/dev/null 2>&1 || [ -x "$HOME/.cargo/bin/cargo" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
    export MILNET_MASTER_KEK MILNET_ALLOW_SINGLE_KEK=1 MILNET_TESTING_SINGLE_KEK_ACK=1
    log "Running FROST DKG ceremony (cargo example fleet_keygen)..."
    if ( cd "$REPO" && cargo run --release --quiet --example fleet_keygen -p tss -- "$OUT" ) \
            >>"$OUT/keygen.log" 2>&1; then
        FROST_DONE=1
        log "FROST 3-of-5 + ML-DSA-87 key material generated."
    else
        log "WARNING: fleet_keygen example failed - see $OUT/keygen.log"
    fi
fi
if [ "$FROST_DONE" -eq 0 ]; then
    log "NOTE: offline FROST keygen unavailable. The TSS coordinator/signer and"
    log "      verifier services require this material; without it those nodes"
    log "      stay down until the FROST ceremony is supplied. Re-run after"
    log "      'cargo build --release' succeeds on the controller."
fi

# --- 5. Gateway key pins -----------------------------------------------------
# SHA-256 SPKI pin of the CA - the gateway pins the chain it will accept.
log "Computing gateway key pins..."
PIN="$(openssl x509 -in "$OUT/ca.crt" -pubkey -noout 2>/dev/null | \
       openssl pkey -pubin -outform der 2>/dev/null | \
       openssl dgst -sha256 -binary 2>/dev/null | openssl enc -base64)"
echo "sha256//${PIN}" > "$OUT/key_pins.txt"

# --- 6. Deployment identity + DB credential ---------------------------------
if command -v uuidgen >/dev/null 2>&1; then uuidgen > "$OUT/deployment_id.txt"
else python3 -c 'import uuid;print(uuid.uuid4())' > "$OUT/deployment_id.txt"; fi
openssl rand -hex 24 > "$OUT/db_password.txt"

# --- 7. Lock down ------------------------------------------------------------
chmod 600 "$OUT"/*.key "$OUT"/*.hex "$OUT"/*.b64 "$OUT"/db_password.txt 2>/dev/null || true
log "Key ceremony complete. Material written to: $OUT"
exit 0
