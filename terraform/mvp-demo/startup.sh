#!/bin/bash
set -euo pipefail

# Log all output for debugging
exec > >(tee /var/log/sso-startup.log) 2>&1
echo "=== SSO Demo Startup Script ==="
echo "Started at: $(date -u)"

# -------------------------------------------------------
# 1. Install Docker CE
# -------------------------------------------------------
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release git

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable docker
systemctl start docker

# -------------------------------------------------------
# 2. Format and mount the data disk for PostgreSQL
# -------------------------------------------------------
DATA_DISK="/dev/disk/by-id/google-sso-data-disk"
MOUNT_POINT="/mnt/sso-data"

if ! blkid "$DATA_DISK"; then
  mkfs.ext4 -F "$DATA_DISK"
fi

mkdir -p "$MOUNT_POINT"
mount -o discard,defaults "$DATA_DISK" "$MOUNT_POINT"

# Persist mount across reboots
if ! grep -q "$MOUNT_POINT" /etc/fstab; then
  echo "$DATA_DISK $MOUNT_POINT ext4 discard,defaults,nofail 0 2" >> /etc/fstab
fi

mkdir -p "$MOUNT_POINT/pgdata"
chmod 777 "$MOUNT_POINT/pgdata"

# -------------------------------------------------------
# 3. Fetch the database password from Secret Manager
# -------------------------------------------------------
DB_PASSWORD=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/db-password" \
  -H "Metadata-Flavor: Google" || echo "fallback-demo-password")

# -------------------------------------------------------
# 4. Clone the repository
# -------------------------------------------------------
REPO_URL=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/github-repo" \
  -H "Metadata-Flavor: Google" || echo "https://github.com/divyamohan1993/enterprise-sso-system.git")

APP_DIR="/opt/enterprise-sso-system"

if [ -d "$APP_DIR" ]; then
  cd "$APP_DIR"
  git pull --ff-only || true
else
  git clone "$REPO_URL" "$APP_DIR"
  cd "$APP_DIR"
fi

# -------------------------------------------------------
# 5. Write the .env file for docker-compose
# -------------------------------------------------------
cat > "$APP_DIR/.env" <<ENVEOF
MILNET_DB_PASSWORD=${DB_PASSWORD}
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
SSO_BASE_URL=http://$(curl -s http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip -H "Metadata-Flavor: Google"):8080
ENVEOF

# -------------------------------------------------------
# 6. Override docker-compose to use the data disk for pgdata
# -------------------------------------------------------
cat > "$APP_DIR/docker-compose.override.yml" <<'OVERRIDEEOF'
version: '3.8'

services:
  postgres:
    volumes:
      - /mnt/sso-data/pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
    driver_opts:
      type: none
      device: /mnt/sso-data/pgdata
      o: bind
OVERRIDEEOF

# -------------------------------------------------------
# 7. Build and start all services
# -------------------------------------------------------
cd "$APP_DIR"
docker compose build --no-cache
docker compose up -d

# -------------------------------------------------------
# 8. Set up automatic restart on boot via systemd
# -------------------------------------------------------
cat > /etc/systemd/system/sso-demo.service <<SVCEOF
[Unit]
Description=Enterprise SSO Demo (docker-compose)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable sso-demo.service

# -------------------------------------------------------
# 9. Install the Cloud Logging agent (free tier)
# -------------------------------------------------------
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
bash add-google-cloud-ops-agent-repo.sh --also-install || true

echo "=== SSO Demo startup complete at $(date -u) ==="
