#!/bin/bash
set -euo pipefail

LOG_FILE="/var/log/milnet-sso-setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== MILNET SSO Setup Started: $(date) ==="

# Skip if already set up
if systemctl is-active --quiet milnet-sso; then
    echo "MILNET SSO already running, skipping setup"
    exit 0
fi

# 1. Install dependencies
echo ">>> Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq git curl build-essential pkg-config libssl-dev postgresql postgresql-client

# 2. Install Rust
echo ">>> Installing Rust..."
if ! command -v rustup &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
export HOME="/root"
source "$HOME/.cargo/env"
rustup default stable

# 3. Setup PostgreSQL
echo ">>> Setting up PostgreSQL..."
# Read password from instance metadata; fall back to environment variable
MILNET_DB_PASSWORD=$(curl -s -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/attributes/milnet-db-password 2>/dev/null \
    || echo "${MILNET_DB_PASSWORD:-}")
if [ -z "$MILNET_DB_PASSWORD" ]; then
    echo "ERROR: MILNET_DB_PASSWORD not set in instance metadata or environment"
    exit 1
fi
export MILNET_DB_PASSWORD
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='milnet'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER milnet WITH PASSWORD '${MILNET_DB_PASSWORD}';"
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='milnet_sso'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE milnet_sso OWNER milnet;"

# 4. Clone repository
echo ">>> Cloning repository..."
REPO_DIR="/opt/milnet-sso"
if [ -d "$REPO_DIR" ]; then
    cd "$REPO_DIR" && git pull origin master
else
    git clone https://github.com/divyamohan1993/enterprise-sso-system.git "$REPO_DIR"
fi
cd "$REPO_DIR"

# 5. Build
echo ">>> Building MILNET SSO (this takes ~10 minutes)..."
cargo build --release -p admin 2>&1 | tail -5

# 6. Install binary
echo ">>> Installing binary..."
cp target/release/admin /usr/local/bin/admin
chmod +x /usr/local/bin/admin

# 7. Copy frontend
mkdir -p /usr/local/share/milnet-sso/frontend
cp -r frontend/* /usr/local/share/milnet-sso/frontend/ 2>/dev/null || true

# 8. Create systemd service
echo ">>> Creating systemd service..."
cat > /etc/systemd/system/milnet-sso.service << 'SYSTEMD'
[Unit]
Description=MILNET SSO Admin Server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
ExecStart=/usr/local/bin/admin
WorkingDirectory=/usr/local/share/milnet-sso
Environment=ADMIN_PORT=8080
Environment=DATABASE_URL=postgres://milnet:${MILNET_DB_PASSWORD}@localhost/milnet_sso
Environment=RUST_LOG=info
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMD

# 9. Start service
echo ">>> Starting MILNET SSO service..."
systemctl daemon-reload
systemctl enable milnet-sso
systemctl start milnet-sso

# 10. Auto-update cron DISABLED by default
# WARNING: Automatic git pull + cargo build + systemctl restart is a security risk.
# An attacker who compromises the Git repo could deploy arbitrary code.
# Enable only if you have signed commits, branch protection, and a verified CI pipeline.
# To enable, uncomment the cron entry below and review the update script carefully.
echo ">>> Auto-update cron is DISABLED for security (see comments in startup.sh)..."
mkdir -p /opt/milnet-sso/scripts
cat > /etc/cron.d/milnet-sso-update << 'CRON'
# DISABLED: Automatic updates from GitHub are a security risk without commit signature verification.
# Uncomment only after configuring GPG signature verification in the update script.
# */15 * * * * root /opt/milnet-sso/scripts/auto-update.sh >> /var/log/milnet-sso-update.log 2>&1
CRON

# Create the auto-update script (not active until cron is enabled)
cat > /opt/milnet-sso/scripts/auto-update.sh << 'UPDATE'
#!/bin/bash
set -euo pipefail
cd /opt/milnet-sso

# SECURITY WARNING: This script does git pull && cargo build && systemctl restart
# without verifying commit signatures. An attacker who gains push access to the
# repository could deploy arbitrary code. Before enabling:
# 1. Enforce signed commits on the repository
# 2. Add GPG signature verification below (git verify-commit)
# 3. Restrict branch protection rules on master

# Fetch latest
git fetch origin master --quiet

# Check if there are new commits
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/master)

if [ "$LOCAL" = "$REMOTE" ]; then
    echo "$(date): No updates available"
    exit 0
fi

# TODO: Verify commit signatures before proceeding
# if ! git verify-commit origin/master 2>/dev/null; then
#     echo "$(date): ERROR — commit signature verification failed, aborting update"
#     exit 1
# fi

echo "$(date): New commits detected. Updating..."
git pull origin master --quiet

# Rebuild
source /root/.cargo/env
cargo build --release -p admin 2>&1 | tail -3

# Install and restart
cp target/release/admin /usr/local/bin/admin
cp -r frontend/* /usr/local/share/milnet-sso/frontend/ 2>/dev/null || true
systemctl restart milnet-sso

echo "$(date): Update complete. New version: $(git rev-parse --short HEAD)"
UPDATE

chmod +x /opt/milnet-sso/scripts/auto-update.sh

# 11. Wait and verify
sleep 3
if curl -s http://localhost:8080/api/health | grep -q "ok"; then
    echo "=== MILNET SSO DEPLOYED SUCCESSFULLY ==="
    echo "URL: http://$(curl -s ifconfig.me):8080"
    echo "Health: $(curl -s http://localhost:8080/api/health)"
else
    echo "=== DEPLOYMENT FAILED - Check logs: journalctl -u milnet-sso ==="
    exit 1
fi
