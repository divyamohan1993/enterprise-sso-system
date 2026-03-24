#!/bin/bash
# ============================================================================
# MILNET Gateway VM Startup — gateway (:9100) + orchestrator (:9101)
# ZERO database credentials, ZERO KMS access, ZERO signing keys
# ============================================================================
set -euo pipefail
exec > /var/log/milnet-startup.log 2>&1
echo "=== MILNET Gateway startup at $(date -u) ==="

# ── Generate unique SHARD HMAC key (64 bytes from /dev/urandom) ──
SHARD_HMAC_KEY=$(head -c 64 /dev/urandom | base64 -w0)
echo "Generated unique SHARD HMAC key for gateway VM"

# ── Create milnet user (non-root) ──
if ! id milnet &>/dev/null; then
    useradd -r -s /bin/false -m milnet
fi

# ── Install Docker (COS has Docker pre-installed) ──
if ! command -v docker &>/dev/null; then
  echo "Installing Docker..."
  apt-get update -qq && apt-get install -y -qq docker.io
  systemctl enable docker && systemctl start docker
fi

# ── Wait for Docker ──
docker_ready=false
for i in $(seq 1 30); do
  if docker info &>/dev/null; then
    docker_ready=true
    break
  fi
  echo "Waiting for Docker... ($i/30)"
  sleep 2
done
if [ "$docker_ready" = false ]; then
  echo "ERROR: Docker failed to start after 60 seconds" >&2
  exit 1
fi

# ── Authenticate to Artifact Registry ──
echo "Authenticating to Artifact Registry..."
if ! gcloud auth configure-docker ${project_id}-docker.pkg.dev,asia-south1-docker.pkg.dev --quiet 2>&1; then
  echo "WARNING: Artifact Registry auth may have failed" >&2
fi

# ── Pull ONLY gateway images (least privilege) ──
echo "Pulling gateway images..."
docker pull ${ar_registry}/gateway:latest || echo "WARN: gateway pull failed, may already be cached"
docker pull ${ar_registry}/orchestrator:latest || echo "WARN: orchestrator pull failed, may already be cached"

# ── Create isolated Docker network ──
docker network create milnet-internal 2>/dev/null || true

# Common security flags for all containers
SECURITY_OPTS="--security-opt no-new-privileges:true --cap-drop ALL --read-only --tmpfs /tmp"

# ── Start Gateway (:9100) ──
echo "Starting gateway on :9100..."
docker run -d \
  --name milnet-gateway \
  --restart unless-stopped \
  --network milnet-internal \
  --user 1000:1000 \
  $SECURITY_OPTS \
  -p 9100:9100 \
  -e RUST_LOG=info \
  -e BIND_ADDR=0.0.0.0:9100 \
  -e ORCHESTRATOR_URL=http://127.0.0.1:9101 \
  -e SHARD_HMAC_KEY="$SHARD_HMAC_KEY" \
  -e POW_DIFFICULTY=20 \
  -e RATE_LIMIT_RPS=100 \
  --memory 256m \
  --cpus 0.5 \
  ${ar_registry}/gateway:latest

# ── Start Orchestrator (:9101) ──
echo "Starting orchestrator on :9101..."
docker run -d \
  --name milnet-orchestrator \
  --restart unless-stopped \
  --network milnet-internal \
  --user 1000:1000 \
  $SECURITY_OPTS \
  -p 127.0.0.1:9101:9101 \
  -e RUST_LOG=info \
  -e BIND_ADDR=0.0.0.0:9101 \
  -e GATEWAY_URL=http://127.0.0.1:9100 \
  -e OPAQUE_URL=http://${core_ip}:9102 \
  -e TSS_0_URL=http://${tss_ip}:9103 \
  -e TSS_1_URL=http://${tss_ip}:9113 \
  -e TSS_2_URL=http://${tss_ip}:9123 \
  -e VERIFIER_URL=http://${core_ip}:9104 \
  -e RATCHET_URL=http://${core_ip}:9105 \
  -e AUDIT_URL=http://${core_ip}:9108 \
  -e ADMIN_URL=http://${core_ip}:8080 \
  -e SHARD_HMAC_KEY="$SHARD_HMAC_KEY" \
  --memory 256m \
  --cpus 0.5 \
  ${ar_registry}/orchestrator:latest

unset SHARD_HMAC_KEY

echo "=== MILNET Gateway startup complete at $(date -u) ==="
echo "Services: gateway(:9100) orchestrator(:9101)"
