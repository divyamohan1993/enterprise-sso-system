#!/bin/bash
set -euo pipefail

# Log all output for debugging
exec > >(tee /var/log/milnet-startup.log) 2>&1
echo "=== MilNet SSO Demo Startup Script (bare-metal, no Docker) ==="
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
  sudo

# -------------------------------------------------------
# 2. Install PostgreSQL 16
# -------------------------------------------------------
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/keyrings/postgresql.gpg
echo "deb [signed-by=/etc/apt/keyrings/postgresql.gpg] http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
  > /etc/apt/sources.list.d/pgdg.list

apt-get update -y
apt-get install -y postgresql-16

systemctl enable postgresql
systemctl start postgresql

# -------------------------------------------------------
# 3. Format and mount the data disk for PostgreSQL
# -------------------------------------------------------
DATA_DISK="/dev/disk/by-id/google-sso-data-disk"
MOUNT_POINT="/mnt/sso-data"

if ! blkid "$DATA_DISK"; then
  mkfs.ext4 -F "$DATA_DISK"
fi

mkdir -p "$MOUNT_POINT"
mount -o discard,defaults "$DATA_DISK" "$MOUNT_POINT" || true

# Persist mount across reboots
if ! grep -q "$MOUNT_POINT" /etc/fstab; then
  echo "$DATA_DISK $MOUNT_POINT ext4 discard,defaults,nofail 0 2" >> /etc/fstab
fi

mkdir -p "$MOUNT_POINT/pgdata"
chown postgres:postgres "$MOUNT_POINT/pgdata"

# -------------------------------------------------------
# 4. Create milnet system user
# -------------------------------------------------------
if ! id milnet &>/dev/null; then
  useradd --system --create-home --home-dir /home/milnet --shell /usr/sbin/nologin milnet
fi

# -------------------------------------------------------
# 5. Install Rust 1.88 via rustup for milnet user
# -------------------------------------------------------
sudo -u milnet bash -c '
  if [ ! -d "$HOME/.rustup" ]; then
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.88.0
  fi
  source "$HOME/.cargo/env"
  rustup default 1.88.0
  rustc --version
'

# -------------------------------------------------------
# 6. Fetch configuration from GCE metadata
# -------------------------------------------------------
DB_PASSWORD=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/db-password" \
  -H "Metadata-Flavor: Google" || echo "fallback-demo-password")

REPO_URL=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/github-repo" \
  -H "Metadata-Flavor: Google" || echo "https://github.com/divyamohan1993/enterprise-sso-system.git")

EXTERNAL_IP=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" \
  -H "Metadata-Flavor: Google" || echo "127.0.0.1")

# -------------------------------------------------------
# 7. Clone the repository and build
# -------------------------------------------------------
APP_DIR="/opt/milnet-sso"

if [ -d "$APP_DIR" ]; then
  cd "$APP_DIR"
  git pull --ff-only || true
else
  git clone "$REPO_URL" "$APP_DIR"
fi

chown -R milnet:milnet "$APP_DIR"

# Build all binaries as the milnet user
sudo -u milnet bash -c "
  source /home/milnet/.cargo/env
  cd $APP_DIR
  cargo build --release 2>&1
"

# -------------------------------------------------------
# 8. Set up PostgreSQL database
# -------------------------------------------------------
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='milnet'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE USER milnet WITH PASSWORD '${DB_PASSWORD}';"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='milnet_sso'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE milnet_sso OWNER milnet;"

sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE milnet_sso TO milnet;"

# Run schema migrations if they exist
if [ -d "$APP_DIR/migrations" ]; then
  sudo -u milnet bash -c "
    source /home/milnet/.cargo/env
    cd $APP_DIR
    export DATABASE_URL='postgres://milnet:${DB_PASSWORD}@127.0.0.1:5432/milnet_sso'
    cargo run --release --bin audit -- --migrate 2>/dev/null || true
  "
fi

# -------------------------------------------------------
# 9. Create environment file for services
# -------------------------------------------------------
cat > /etc/milnet-sso.env <<ENVEOF
DATABASE_URL=postgres://milnet:${DB_PASSWORD}@127.0.0.1:5432/milnet_sso
MILNET_DB_PASSWORD=${DB_PASSWORD}
SSO_BASE_URL=https://${EXTERNAL_IP}
RUST_LOG=info
RUST_BACKTRACE=1
ENVEOF

chmod 600 /etc/milnet-sso.env
chown milnet:milnet /etc/milnet-sso.env

# -------------------------------------------------------
# 10. Create systemd unit files for each service
# -------------------------------------------------------
BIN_DIR="$APP_DIR/target/release"

create_service() {
  local svc_name="$1"
  local bin_name="$2"
  local port="$3"
  local extra_args="${4:-}"

  cat > "/etc/systemd/system/milnet-${svc_name}.service" <<SVCEOF
[Unit]
Description=MilNet SSO - ${svc_name} service (port ${port})
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=milnet
Group=milnet
EnvironmentFile=/etc/milnet-sso.env
Environment=LISTEN_PORT=${port}
Environment=SERVICE_PORT=${port}
WorkingDirectory=${APP_DIR}
ExecStart=${BIN_DIR}/${bin_name} ${extra_args}
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

# Security hardening
ProtectSystem=strict
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=${APP_DIR} /mnt/sso-data
ProtectHome=read-only

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF
}

create_service "gateway"       "gateway"       9100
create_service "orchestrator"  "orchestrator"  9101
create_service "opaque"        "opaque"        9102
create_service "tss"           "tss"           9103
create_service "verifier"      "verifier"      9104
create_service "ratchet"       "ratchet"       9105
create_service "risk"          "risk"          9106
create_service "kt"            "kt"            9107
create_service "audit"         "audit"         9108
create_service "admin"         "admin"         8080

# -------------------------------------------------------
# 11. Enable and start all services in dependency order
# -------------------------------------------------------
systemctl daemon-reload

# Start infrastructure-layer services first
SERVICES=(
  milnet-audit
  milnet-risk
  milnet-opaque
  milnet-tss
  milnet-verifier
  milnet-ratchet
  milnet-kt
  milnet-orchestrator
  milnet-gateway
  milnet-admin
)

for svc in "${SERVICES[@]}"; do
  systemctl enable "$svc"
  systemctl start "$svc" || echo "WARNING: $svc failed to start, continuing..."
  sleep 1
done

# -------------------------------------------------------
# 12. Set up nginx reverse proxy with self-signed TLS cert
# -------------------------------------------------------
mkdir -p /etc/nginx/ssl

openssl req -x509 -nodes -days 3650 \
  -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/milnet.key \
  -out /etc/nginx/ssl/milnet.crt \
  -subj "/C=US/ST=Demo/L=Demo/O=MilNet SSO/CN=${EXTERNAL_IP}"

cat > /etc/nginx/sites-available/milnet-sso <<'NGINXEOF'
# HTTP -> HTTPS redirect
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

# HTTPS reverse proxy to admin panel (port 8080)
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    ssl_certificate     /etc/nginx/ssl/milnet.crt;
    ssl_certificate_key /etc/nginx/ssl/milnet.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_read_timeout 30s;
    }

    # Health check endpoint
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
# 13. Install the Cloud Logging agent (free tier)
# -------------------------------------------------------
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
bash add-google-cloud-ops-agent-repo.sh --also-install || true

# -------------------------------------------------------
# 14. Final status report
# -------------------------------------------------------
echo ""
echo "=== MilNet SSO Demo — Deployment Summary ==="
echo "Completed at: $(date -u)"
echo "External IP: ${EXTERNAL_IP}"
echo "Admin panel: https://${EXTERNAL_IP}"
echo "Gateway:     ${EXTERNAL_IP}:9100"
echo ""
echo "Service status:"
systemctl list-units milnet-*.service --no-pager || true
echo ""
echo "=== Startup script finished ==="
