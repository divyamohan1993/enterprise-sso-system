#!/bin/bash
# ============================================================================
# MILNET TSS VM Startup — tss-0 (:9103), tss-1 (:9113), tss-2 (:9123)
# ZERO database access, ZERO KMS access — only FROST threshold shares
# ============================================================================
set -euo pipefail
exec > /var/log/milnet-startup.log 2>&1
echo "=== MILNET TSS startup at $(date -u) ==="

# ── Generate unique SHARD HMAC key (64 bytes from /dev/urandom) ──
SHARD_HMAC_KEY=$(head -c 64 /dev/urandom | base64 -w0)
echo "Generated unique SHARD HMAC key for TSS VM"

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

# ── Pull ONLY TSS image (all 3 nodes use same image, different config) ──
echo "Pulling TSS image..."
docker pull ${ar_registry}/tss:latest || echo "WARN: tss pull failed"

# ── Create isolated Docker network ──
docker network create milnet-internal 2>/dev/null || true

# ── Generate unique FROST share keys per node ──
TSS_0_SHARE_KEY=$(head -c 32 /dev/urandom | base64 -w0)
TSS_1_SHARE_KEY=$(head -c 32 /dev/urandom | base64 -w0)
TSS_2_SHARE_KEY=$(head -c 32 /dev/urandom | base64 -w0)

# ── Start TSS Node 0 (:9103) ──
echo "Starting tss-0 on :9103..."
docker run -d \
  --name milnet-tss-0 \
  --restart unless-stopped \
  --network milnet-internal \
  --user 1000:1000 \
  -p 9103:9103 \
  -e RUST_LOG=info \
  -e BIND_ADDR=0.0.0.0:9103 \
  -e NODE_ID=0 \
  -e THRESHOLD=2 \
  -e NUM_NODES=3 \
  -e PEER_1_URL=http://127.0.0.1:9113 \
  -e PEER_2_URL=http://127.0.0.1:9123 \
  -e SHARD_HMAC_KEY="$SHARD_HMAC_KEY" \
  -e TSS_SHARE_KEY="$TSS_0_SHARE_KEY" \
  ${ar_registry}/tss:latest

# ── Start TSS Node 1 (:9113) ──
echo "Starting tss-1 on :9113..."
docker run -d \
  --name milnet-tss-1 \
  --restart unless-stopped \
  --network milnet-internal \
  --user 1000:1000 \
  -p 9113:9113 \
  -e RUST_LOG=info \
  -e BIND_ADDR=0.0.0.0:9113 \
  -e NODE_ID=1 \
  -e THRESHOLD=2 \
  -e NUM_NODES=3 \
  -e PEER_0_URL=http://127.0.0.1:9103 \
  -e PEER_2_URL=http://127.0.0.1:9123 \
  -e SHARD_HMAC_KEY="$SHARD_HMAC_KEY" \
  -e TSS_SHARE_KEY="$TSS_1_SHARE_KEY" \
  ${ar_registry}/tss:latest

# ── Start TSS Node 2 (:9123) ──
echo "Starting tss-2 on :9123..."
docker run -d \
  --name milnet-tss-2 \
  --restart unless-stopped \
  --network milnet-internal \
  --user 1000:1000 \
  -p 9123:9123 \
  -e RUST_LOG=info \
  -e BIND_ADDR=0.0.0.0:9123 \
  -e NODE_ID=2 \
  -e THRESHOLD=2 \
  -e NUM_NODES=3 \
  -e PEER_0_URL=http://127.0.0.1:9103 \
  -e PEER_1_URL=http://127.0.0.1:9113 \
  -e SHARD_HMAC_KEY="$SHARD_HMAC_KEY" \
  -e TSS_SHARE_KEY="$TSS_2_SHARE_KEY" \
  ${ar_registry}/tss:latest

echo "=== MILNET TSS startup complete at $(date -u) ==="
echo "Services: tss-0(:9103) tss-1(:9113) tss-2(:9123)"
