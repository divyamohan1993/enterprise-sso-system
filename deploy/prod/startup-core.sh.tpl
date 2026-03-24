#!/bin/bash
# ============================================================================
# MILNET Core VM Startup — opaque (:9102), admin (:8080), verifier (:9104),
#                           ratchet (:9105), audit (:9108)
# Has: DATABASE_URL (via Cloud SQL Auth Proxy), Cloud KMS access
# ============================================================================
set -euo pipefail
exec > /var/log/milnet-startup.log 2>&1
echo "=== MILNET Core startup at $(date -u) ==="

# ── Generate unique SHARD HMAC key (64 bytes from /dev/urandom) ──
SHARD_HMAC_KEY=$(head -c 64 /dev/urandom | base64 -w0)
echo "Generated unique SHARD HMAC key for core VM"

# ── Create milnet user (non-root) ──
useradd -r -s /bin/false -m milnet 2>/dev/null || true

# ── Install Docker (COS has Docker pre-installed) ──
if ! command -v docker &>/dev/null; then
  echo "Installing Docker..."
  apt-get update -qq && apt-get install -y -qq docker.io
  systemctl enable docker && systemctl start docker
fi

# ── Wait for Docker ──
for i in $(seq 1 30); do
  docker info &>/dev/null && break
  echo "Waiting for Docker... ($i/30)"
  sleep 2
done

# ── Authenticate to Artifact Registry ──
echo "Authenticating to Artifact Registry..."
gcloud auth configure-docker ${project_id}-docker.pkg.dev,asia-south1-docker.pkg.dev --quiet 2>/dev/null || true

# ── Pull ONLY core service images ──
echo "Pulling core service images..."
docker pull ${ar_registry}/opaque:latest || echo "WARN: opaque pull failed"
docker pull ${ar_registry}/admin:latest || echo "WARN: admin pull failed"
docker pull ${ar_registry}/verifier:latest || echo "WARN: verifier pull failed"
docker pull ${ar_registry}/ratchet:latest || echo "WARN: ratchet pull failed"
docker pull ${ar_registry}/audit:latest || echo "WARN: audit pull failed"

# ── Start Cloud SQL Auth Proxy (private IP, sidecar) ──
echo "Starting Cloud SQL Auth Proxy..."
docker pull gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.14.1 || true
docker run -d \
  --name cloud-sql-proxy \
  --restart unless-stopped \
  -p 5432:5432 \
  gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.14.1 \
  --private-ip \
  --address 0.0.0.0 \
  --port 5432 \
  ${sql_connection}

# Wait for proxy to be ready
echo "Waiting for Cloud SQL Auth Proxy..."
for i in $(seq 1 30); do
  nc -z 127.0.0.1 5432 2>/dev/null && break
  echo "Waiting for SQL proxy... ($i/30)"
  sleep 2
done

# Fetch DB password from Secret Manager at runtime (NEVER in metadata/env/disk)
echo "Fetching DB password from Secret Manager..."
ACCESS_TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | \
  python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
DB_PASSWORD=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/${project_id}/secrets/milnet-db-password/versions/latest:access" | \
  python3 -c 'import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)["payload"]["data"]).decode())')
unset ACCESS_TOKEN  # Don't leave token in environment
echo "DB password fetched from Secret Manager (length: $${#DB_PASSWORD})"

# Database URL via local proxy (SSL enforced by Cloud SQL side)
DATABASE_URL="postgresql://${db_user}:$${DB_PASSWORD}@127.0.0.1:5432/${db_name}"

# ── Create isolated Docker network ──
docker network create milnet-internal 2>/dev/null || true

# ── Start OPAQUE service (:9102) ──
echo "Starting opaque on :9102..."
docker run -d \
  --name milnet-opaque \
  --restart unless-stopped \
  --network milnet-internal \
  --user 1000:1000 \
  -p 9102:9102 \
  -e RUST_LOG=info \
  -e BIND_ADDR=0.0.0.0:9102 \
  -e DATABASE_URL="$DATABASE_URL" \
  -e KMS_KEYRING="${kms_keyring}" \
  -e SHARD_HMAC_KEY="$SHARD_HMAC_KEY" \
  ${ar_registry}/opaque:latest

# ── Start Admin service (:8080) ──
echo "Starting admin on :8080..."
docker run -d \
  --name milnet-admin \
  --restart unless-stopped \
  --network milnet-internal \
  --user 1000:1000 \
  -p 8080:8080 \
  -e RUST_LOG=info \
  -e BIND_ADDR=0.0.0.0:8080 \
  -e DATABASE_URL="$DATABASE_URL" \
  -e KMS_KEYRING="${kms_keyring}" \
  -e SHARD_HMAC_KEY="$SHARD_HMAC_KEY" \
  ${ar_registry}/admin:latest

# ── Start Verifier service (:9104) ──
echo "Starting verifier on :9104..."
docker run -d \
  --name milnet-verifier \
  --restart unless-stopped \
  --network milnet-internal \
  --user 1000:1000 \
  -p 9104:9104 \
  -e RUST_LOG=info \
  -e BIND_ADDR=0.0.0.0:9104 \
  -e DATABASE_URL="$DATABASE_URL" \
  -e KMS_KEYRING="${kms_keyring}" \
  -e SHARD_HMAC_KEY="$SHARD_HMAC_KEY" \
  ${ar_registry}/verifier:latest

# ── Start Ratchet service (:9105) ──
echo "Starting ratchet on :9105..."
docker run -d \
  --name milnet-ratchet \
  --restart unless-stopped \
  --network milnet-internal \
  --user 1000:1000 \
  -p 9105:9105 \
  -e RUST_LOG=info \
  -e BIND_ADDR=0.0.0.0:9105 \
  -e DATABASE_URL="$DATABASE_URL" \
  -e KMS_KEYRING="${kms_keyring}" \
  -e SHARD_HMAC_KEY="$SHARD_HMAC_KEY" \
  ${ar_registry}/ratchet:latest

# ── Start Audit service (:9108) ──
echo "Starting audit on :9108..."
docker run -d \
  --name milnet-audit \
  --restart unless-stopped \
  --network milnet-internal \
  --user 1000:1000 \
  -p 9108:9108 \
  -e RUST_LOG=info \
  -e BIND_ADDR=0.0.0.0:9108 \
  -e DATABASE_URL="$DATABASE_URL" \
  -e KMS_KEYRING="${kms_keyring}" \
  -e SHARD_HMAC_KEY="$SHARD_HMAC_KEY" \
  ${ar_registry}/audit:latest

echo "=== MILNET Core startup complete at $(date -u) ==="
echo "Services: opaque(:9102) admin(:8080) verifier(:9104) ratchet(:9105) audit(:9108)"
