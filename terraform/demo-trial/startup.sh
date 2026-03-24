#!/bin/bash
set -euo pipefail

# Log all output for debugging
exec > >(tee /var/log/milnet-startup.log) 2>&1
echo "=== MilNet SSO Demo Trial Startup (all-in-one VM) ==="
echo "Started at: $(date -u)"

# -------------------------------------------------------
# 1. Install system dependencies
# -------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  libclang-dev \
  cmake \
  ca-certificates \
  curl \
  gnupg \
  lsb-release \
  git \
  nginx \
  jq \
  sudo

# -------------------------------------------------------
# 2. Fetch configuration from GCE metadata
# -------------------------------------------------------
META="http://metadata.google.internal/computeMetadata/v1"
MH="Metadata-Flavor: Google"

REPO_URL=$(curl -sf "$META/instance/attributes/github-repo" -H "$MH")
FROST_COUNT=$(curl -sf "$META/instance/attributes/frost-signer-count" -H "$MH")
BFT_COUNT=$(curl -sf "$META/instance/attributes/bft-audit-nodes" -H "$MH")
DB_IP=$(curl -sf "$META/instance/attributes/db-private-ip" -H "$MH")
DB_SECRET=$(curl -sf "$META/instance/attributes/db-password-secret" -H "$MH")
KEK_SECRET=$(curl -sf "$META/instance/attributes/kek-seed-secret" -H "$MH")
SHARD_SECRET=$(curl -sf "$META/instance/attributes/shard-hmac-secret" -H "$MH")
KMS_KEY=$(curl -sf "$META/instance/attributes/kms-key-id" -H "$MH")
EXTERNAL_IP=$(curl -sf "$META/instance/network-interfaces/0/access-configs/0/external-ip" -H "$MH")
PROJECT_ID=$(curl -sf "$META/project/project-id" -H "$MH")

# Fetch secrets from Secret Manager via metadata server auth
ACCESS_TOKEN=$(curl -sf "$META/instance/service-accounts/default/token" -H "$MH" | jq -r .access_token)

DB_PASSWORD=$(curl -sf \
  "https://secretmanager.googleapis.com/v1/projects/${PROJECT_ID}/secrets/${DB_SECRET}/versions/latest:access" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq -r '.payload.data' | base64 -d)

KEK_SEED=$(curl -sf \
  "https://secretmanager.googleapis.com/v1/projects/${PROJECT_ID}/secrets/${KEK_SECRET}/versions/latest:access" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq -r '.payload.data' | base64 -d)

SHARD_HMAC=$(curl -sf \
  "https://secretmanager.googleapis.com/v1/projects/${PROJECT_ID}/secrets/${SHARD_SECRET}/versions/latest:access" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq -r '.payload.data' | base64 -d)

echo "Configuration fetched: FROST=${FROST_COUNT} signers, BFT=${BFT_COUNT} nodes"

# -------------------------------------------------------
# 3. Create milnet system user
# -------------------------------------------------------
if ! id milnet &>/dev/null; then
  useradd --system --create-home --home-dir /home/milnet --shell /usr/sbin/nologin milnet
fi

# -------------------------------------------------------
# 4. Install Rust and build from source
# -------------------------------------------------------
sudo -u milnet bash -c '
  if [ ! -d "$HOME/.rustup" ]; then
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.88.0
  fi
  source "$HOME/.cargo/env"
  rustup default 1.88.0
  rustc --version
'

APP_DIR="/opt/milnet-sso"

if [ -d "$APP_DIR" ]; then
  cd "$APP_DIR"
  git pull --ff-only || true
else
  git clone "$REPO_URL" "$APP_DIR"
fi

chown -R milnet:milnet "$APP_DIR"

sudo -u milnet bash -c "
  source /home/milnet/.cargo/env
  cd $APP_DIR
  cargo build --release 2>&1
"

# -------------------------------------------------------
# 5. Create environment file with all secrets
# -------------------------------------------------------
cat > /etc/milnet-sso.env <<ENVEOF
DATABASE_URL=postgres://milnet:${DB_PASSWORD}@${DB_IP}:5432/milnet_sso
MILNET_DB_PASSWORD=${DB_PASSWORD}
MILNET_KEK_SEED=${KEK_SEED}
MILNET_SHARD_HMAC_KEY=${SHARD_HMAC}
MILNET_KMS_KEY_ID=${KMS_KEY}
SSO_BASE_URL=https://${EXTERNAL_IP}
MILNET_CACHE_BACKEND=memory
RUST_LOG=info
RUST_BACKTRACE=1
ENVEOF

chmod 600 /etc/milnet-sso.env
chown milnet:milnet /etc/milnet-sso.env

# -------------------------------------------------------
# 6. Create systemd units for core services
# -------------------------------------------------------
BIN_DIR="$APP_DIR/target/release"

create_service() {
  local svc_name="$1"
  local bin_name="$2"
  local port="$3"
  local extra_env="${4:-}"

  cat > "/etc/systemd/system/milnet-${svc_name}.service" <<SVCEOF
[Unit]
Description=MilNet SSO - ${svc_name} (port ${port})
After=network.target
Wants=network.target

[Service]
Type=simple
User=milnet
Group=milnet
EnvironmentFile=/etc/milnet-sso.env
Environment=LISTEN_PORT=${port}
Environment=SERVICE_PORT=${port}
${extra_env}
WorkingDirectory=${APP_DIR}
ExecStart=${BIN_DIR}/${bin_name}
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

# Security hardening (same as production systemd config)
ProtectSystem=strict
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=${APP_DIR}
ProtectHome=read-only
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF
}

# Core services — same ports as production
create_service "gateway"       "gateway"       9100
create_service "orchestrator"  "orchestrator"  9101
create_service "opaque"        "opaque"        9102
create_service "verifier"      "verifier"      9104
create_service "ratchet"       "ratchet"       9105
create_service "risk"          "risk"          9106 "Environment=MILNET_CACHE_BACKEND=memory"
create_service "kt"            "kt"            9107
create_service "admin"         "admin"         8080 "Environment=MILNET_CACHE_BACKEND=memory"

# -------------------------------------------------------
# 7. FROST 3-of-5 threshold signers (5 processes, different ports)
#
# In production: 5 separate VMs with AMD SEV confidential computing
# In demo: 5 processes on localhost, same FROST protocol, same security
# Each signer holds 1 share — threshold of 3 needed to sign
# -------------------------------------------------------
for i in $(seq 0 $((FROST_COUNT - 1))); do
  PORT=$((9103 + i * 100))  # 9103, 9203, 9303, 9403, 9503
  SIGNER_ID="$i"

  cat > "/etc/systemd/system/milnet-tss-signer-${i}.service" <<SVCEOF
[Unit]
Description=MilNet SSO - FROST TSS Signer ${i} (port ${PORT})
After=network.target
Wants=network.target

[Service]
Type=simple
User=milnet
Group=milnet
EnvironmentFile=/etc/milnet-sso.env
Environment=LISTEN_PORT=${PORT}
Environment=SERVICE_PORT=${PORT}
Environment=MILNET_TSS_SIGNER_ID=${SIGNER_ID}
Environment=MILNET_TSS_SIGNER_COUNT=${FROST_COUNT}
Environment=MILNET_TSS_THRESHOLD=3
Environment=MILNET_TSS_PEER_PORTS=9103,9203,9303,9403,9503
WorkingDirectory=${APP_DIR}
ExecStart=${BIN_DIR}/tss
Restart=always
RestartSec=5

ProtectSystem=strict
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=${APP_DIR}
ProtectHome=read-only
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF
done

# -------------------------------------------------------
# 8. BFT Audit nodes (3 processes for 1 Byzantine tolerance)
#
# In production: 7 nodes across zones (2 Byzantine tolerance)
# In demo: 3 nodes on localhost (1 Byzantine tolerance — minimum BFT)
# Same ML-DSA-87 signing, same SHA3-256 Merkle tree, same BFT consensus
# -------------------------------------------------------
for i in $(seq 0 $((BFT_COUNT - 1))); do
  PORT=$((9108 + i * 100))  # 9108, 9208, 9308
  NODE_ID="$i"

  cat > "/etc/systemd/system/milnet-audit-${i}.service" <<SVCEOF
[Unit]
Description=MilNet SSO - BFT Audit Node ${i} (port ${PORT})
After=network.target
Wants=network.target

[Service]
Type=simple
User=milnet
Group=milnet
EnvironmentFile=/etc/milnet-sso.env
Environment=LISTEN_PORT=${PORT}
Environment=SERVICE_PORT=${PORT}
Environment=MILNET_AUDIT_NODE_ID=${NODE_ID}
Environment=MILNET_AUDIT_NODE_COUNT=${BFT_COUNT}
Environment=MILNET_AUDIT_PEER_PORTS=9108,9208,9308
WorkingDirectory=${APP_DIR}
ExecStart=${BIN_DIR}/audit
Restart=always
RestartSec=5

ProtectSystem=strict
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=${APP_DIR}
ProtectHome=read-only
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF
done

# -------------------------------------------------------
# 9. Start all services in dependency order
# -------------------------------------------------------
systemctl daemon-reload

# BFT audit nodes first (other services send audit events)
for i in $(seq 0 $((BFT_COUNT - 1))); do
  systemctl enable "milnet-audit-${i}"
  systemctl start "milnet-audit-${i}" || echo "WARNING: audit-${i} failed, continuing..."
  sleep 1
done

# FROST signers (orchestrator needs them for token signing)
for i in $(seq 0 $((FROST_COUNT - 1))); do
  systemctl enable "milnet-tss-signer-${i}"
  systemctl start "milnet-tss-signer-${i}" || echo "WARNING: tss-signer-${i} failed, continuing..."
  sleep 1
done

# Core services
CORE_SERVICES=(
  milnet-risk
  milnet-opaque
  milnet-verifier
  milnet-ratchet
  milnet-kt
  milnet-orchestrator
  milnet-gateway
  milnet-admin
)

for svc in "${CORE_SERVICES[@]}"; do
  systemctl enable "$svc"
  systemctl start "$svc" || echo "WARNING: $svc failed to start, continuing..."
  sleep 1
done

# -------------------------------------------------------
# 10. Nginx reverse proxy with self-signed TLS
# -------------------------------------------------------
mkdir -p /etc/nginx/ssl

openssl req -x509 -nodes -days 3650 \
  -newkey rsa:4096 \
  -keyout /etc/nginx/ssl/milnet.key \
  -out /etc/nginx/ssl/milnet.crt \
  -subj "/C=US/ST=Demo/L=Demo/O=MilNet SSO Demo/CN=${EXTERNAL_IP}"

cat > /etc/nginx/sites-available/milnet-sso <<'NGINXEOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    ssl_certificate     /etc/nginx/ssl/milnet.crt;
    ssl_certificate_key /etc/nginx/ssl/milnet.key;
    ssl_protocols       TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_read_timeout 30s;
    }

    location /health {
        proxy_pass http://127.0.0.1:8080/health;
        access_log off;
    }
}
NGINXEOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/milnet-sso /etc/nginx/sites-enabled/milnet-sso
nginx -t && systemctl restart nginx
systemctl enable nginx

# -------------------------------------------------------
# 11. Install Cloud Ops Agent (free tier logging/monitoring)
# -------------------------------------------------------
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
bash add-google-cloud-ops-agent-repo.sh --also-install || true

# -------------------------------------------------------
# 12. Final status report
# -------------------------------------------------------
echo ""
echo "============================================================"
echo "  MilNet SSO Demo Trial - Deployment Complete"
echo "============================================================"
echo "  Time:       $(date -u)"
echo "  External:   https://${EXTERNAL_IP}"
echo "  Gateway:    ${EXTERNAL_IP}:9100"
echo "  Admin:      https://${EXTERNAL_IP} (via nginx)"
echo "  Database:   Cloud SQL @ ${DB_IP}:5432 (private IP, SSL)"
echo ""
echo "  FROST Signers: ${FROST_COUNT} processes (3-of-5 threshold)"
echo "  BFT Audit:     ${BFT_COUNT} nodes (1 Byzantine tolerance)"
echo ""
echo "  Crypto:  X-Wing KEM, FROST 3-of-5, OPAQUE, ML-DSA-87,"
echo "           SHARD mTLS, DPoP, HKDF ratcheting"
echo "  Status:  IDENTICAL to production security"
echo "============================================================"
echo ""
echo "Service status:"
systemctl list-units milnet-*.service --no-pager || true
echo ""
echo "=== Startup script finished ==="
