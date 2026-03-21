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
source "$HOME/.cargo/env"
rustup default stable

# 3. Setup PostgreSQL
echo ">>> Setting up PostgreSQL..."
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='milnet'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER milnet WITH PASSWORD 'milnet_secure_2026';"
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
Environment=DATABASE_URL=postgres://milnet:milnet_secure_2026@localhost/milnet_sso
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

# 10. Wait and verify
sleep 3
if curl -s http://localhost:8080/api/health | grep -q "ok"; then
    echo "=== MILNET SSO DEPLOYED SUCCESSFULLY ==="
    echo "URL: http://$(curl -s ifconfig.me):8080"
    echo "Health: $(curl -s http://localhost:8080/api/health)"
else
    echo "=== DEPLOYMENT FAILED - Check logs: journalctl -u milnet-sso ==="
    exit 1
fi
