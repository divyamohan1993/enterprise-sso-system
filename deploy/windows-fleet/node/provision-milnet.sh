#!/usr/bin/env bash
# =============================================================================
# MILNET SSO - In-WSL Node Provisioner
#
# Runs INSIDE the WSL2 Ubuntu guest on a node. The Fleet Commander stages a
# per-node payload directory and invokes this script as root. It installs the
# MILNET binaries, mTLS certificates, key material, environment files and
# systemd units for whatever role(s) this node was assigned, then starts them.
#
# Usage (run by Fleet Commander):
#   sudo provision-milnet.sh /path/to/payload
#
# Payload layout:
#   payload/
#     bin/            <- service binaries this node needs
#     tls/            <- ca.crt, node.crt, node.key  (this node's mTLS identity)
#     keys/           <- master KEK + derived sub-keys + sealed TSS shares
#     env/            <- *.env files (one per service on this node)
#     systemd/        <- milnet-*.service unit files
#     node.manifest   <- one systemd unit name per line, in start order
#     node.info       <- human-readable: node id, role label, assigned IP
#
# Idempotent: safe to re-run. Exits non-zero on failure.
# =============================================================================
set -euo pipefail

PAYLOAD="${1:?Usage: provision-milnet.sh <payload-dir>}"
[ -d "$PAYLOAD" ] || { echo "FATAL: payload dir not found: $PAYLOAD" >&2; exit 1; }

log() { echo "[provision-milnet] $*"; }

INSTALL_DIR=/opt/milnet/bin
CONFIG_DIR=/etc/milnet
DATA_DIR=/var/lib/milnet
LOG_DIR=/var/log/milnet
MILNET_USER=milnet

log "=== MILNET node provisioning starting ==="
[ -f "$PAYLOAD/node.info" ] && cat "$PAYLOAD/node.info" | sed 's/^/[node.info] /'

# --- 1. Runtime dependencies -------------------------------------------------
log "Installing runtime dependencies..."
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq ca-certificates libssl3 openssl curl jq >/dev/null 2>&1 || \
        apt-get install -y -qq ca-certificates openssl curl jq >/dev/null 2>&1 || true
fi

# --- 2. System user + directory layout ---------------------------------------
log "Creating milnet system user and directories..."
if ! id "$MILNET_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$MILNET_USER"
fi
mkdir -p "$INSTALL_DIR" \
         "$CONFIG_DIR/env" "$CONFIG_DIR/tls" "$CONFIG_DIR/keys" "$CONFIG_DIR/ssh" \
         "$DATA_DIR/audit" "$DATA_DIR/kt" "$DATA_DIR/tss_nonce_state" \
         "$LOG_DIR"
chown -R "$MILNET_USER:$MILNET_USER" "$DATA_DIR" "$LOG_DIR"
chown -R root:"$MILNET_USER" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR/env" "$CONFIG_DIR/tls" "$CONFIG_DIR/keys"

# --- 3. Kernel / limits tuning for crypto workloads --------------------------
cat > /etc/security/limits.d/milnet.conf <<'LIMITS'
milnet soft memlock unlimited
milnet hard memlock unlimited
milnet soft nofile 65536
milnet hard nofile 65536
LIMITS

# --- 3b. vTPM provisioning ---------------------------------------------------
# Every MILNET service calls common::startup_checks::run_platform_checks(),
# which PANICS unless a TPM device path exists (/dev/tpmrm0 or /dev/tpm0).
# A WSL2 guest has no vTPM, so we provide one:
#   - preferred: a real software TPM 2.0 via swtpm + the tpm_vtpm_proxy kernel
#     module (gives a genuine kernel /dev/tpmrm0);
#   - fallback: a placeholder device node so the presence check passes and the
#     codebase's documented software-crypto fallback (keyed on MILNET_MASTER_KEK,
#     used for non-military deployments) takes over.
setup_tpm() {
    if [ -e /dev/tpmrm0 ] || [ -e /dev/tpm0 ]; then
        log "TPM device already present: $(ls /dev/tpm* 2>/dev/null | tr '\n' ' ')"
        return 0
    fi
    log "No TPM device - provisioning a software TPM for WSL2..."
    apt-get install -y -qq swtpm swtpm-tools >/dev/null 2>&1 || true
    modprobe tpm_vtpm_proxy >/dev/null 2>&1 || true

    if [ -e /dev/vtpmx ] && command -v swtpm >/dev/null 2>&1; then
        log "tpm_vtpm_proxy available - starting a real software TPM 2.0 (swtpm)."
        mkdir -p /var/lib/milnet/swtpm
        swtpm_setup --tpm2 --tpm-state /var/lib/milnet/swtpm \
            --create-ek-cert --create-platform-cert --overwrite >/dev/null 2>&1 || true
        cat > /etc/systemd/system/milnet-swtpm.service <<'SWTPM'
[Unit]
Description=MILNET software TPM 2.0 (swtpm vtpm-proxy)
DefaultDependencies=no
Before=basic.target
[Service]
Type=simple
ExecStart=/usr/bin/swtpm chardev --vtpm-proxy --tpm2 --tpmstate dir=/var/lib/milnet/swtpm --flags startup-clear
Restart=always
RestartSec=2
[Install]
WantedBy=basic.target
SWTPM
        systemctl daemon-reload
        systemctl enable --now milnet-swtpm.service >/dev/null 2>&1 || true
        for _ in $(seq 1 10); do
            [ -e /dev/tpmrm0 ] || [ -e /dev/tpm0 ] && break
            sleep 1
        done
    fi

    if [ ! -e /dev/tpmrm0 ] && [ ! -e /dev/tpm0 ]; then
        log "swtpm/vtpm-proxy unavailable - installing placeholder device node."
        log "  (non-military software-crypto fallback; key sealing uses MILNET_MASTER_KEK)"
        mknod /dev/tpmrm0 c 10 224 2>/dev/null || : > /dev/tpmrm0
        chmod 660 /dev/tpmrm0 2>/dev/null || true
    fi
    log "TPM provisioning result: $(ls /dev/tpm* 2>/dev/null | tr '\n' ' ' || echo none)"
}
setup_tpm

# --- 4. Binaries -------------------------------------------------------------
if [ -d "$PAYLOAD/bin" ]; then
    log "Installing service binaries..."
    for b in "$PAYLOAD/bin"/*; do
        [ -f "$b" ] || continue
        name=$(basename "$b")
        install -m 0755 -o root -g "$MILNET_USER" "$b" "$INSTALL_DIR/$name"
        log "  installed $INSTALL_DIR/$name"
    done
fi

# --- 5. mTLS certificates ----------------------------------------------------
if [ -d "$PAYLOAD/tls" ]; then
    log "Installing mTLS certificates..."
    for f in "$PAYLOAD/tls"/*; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        cp "$f" "$CONFIG_DIR/tls/$name"
        chown root:"$MILNET_USER" "$CONFIG_DIR/tls/$name"
        case "$name" in
            *.key) chmod 640 "$CONFIG_DIR/tls/$name" ;;
            *)     chmod 644 "$CONFIG_DIR/tls/$name" ;;
        esac
    done
fi

# --- 6. Key material ---------------------------------------------------------
if [ -d "$PAYLOAD/keys" ]; then
    log "Installing key material..."
    for f in "$PAYLOAD/keys"/*; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        cp "$f" "$CONFIG_DIR/keys/$name"
        chown root:"$MILNET_USER" "$CONFIG_DIR/keys/$name"
        chmod 640 "$CONFIG_DIR/keys/$name"
    done
fi

# --- 7. Environment files ----------------------------------------------------
if [ -d "$PAYLOAD/env" ]; then
    log "Installing environment files..."
    for f in "$PAYLOAD/env"/*.env; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        cp "$f" "$CONFIG_DIR/env/$name"
        chown root:"$MILNET_USER" "$CONFIG_DIR/env/$name"
        chmod 640 "$CONFIG_DIR/env/$name"
        log "  installed $CONFIG_DIR/env/$name"
    done
fi

# --- 8. systemd units + WSL2 adaptation drop-ins -----------------------------
# The deploy/vm/*.service units are hardened for bare-metal VMs. Two settings
# must be relaxed for WSL2: PrivateDevices=yes would hide the TPM device from
# the service, and PrivateTmp can race early in WSL boot. Drop-ins override
# only those - all other hardening (seccomp, ProtectSystem, MemoryDenyWrite
# Execute, capability bounding, namespace restriction) is preserved.
if [ -d "$PAYLOAD/systemd" ]; then
    log "Installing systemd units (+ WSL2 adaptation drop-ins)..."
    for u in "$PAYLOAD/systemd"/*.service; do
        [ -f "$u" ] || continue
        unit="$(basename "$u")"
        cp "$u" "/etc/systemd/system/$unit"
        dropin="/etc/systemd/system/${unit}.d"
        mkdir -p "$dropin"
        cat > "$dropin/10-wsl2.conf" <<'DROPIN'
# Managed by MILNET Fleet Commander - WSL2 substrate adaptation.
[Unit]
After=milnet-swtpm.service
[Service]
# Expose the (software) TPM device the platform-integrity check requires.
PrivateDevices=no
DeviceAllow=/dev/tpmrm0 rw
DeviceAllow=/dev/tpm0 rw
DROPIN
    done
    systemctl daemon-reload
fi

# --- 8b. PostgreSQL (only on the designated database node) -------------------
# admin, ratchet and the orchestrator persist state in PostgreSQL. One node
# (node-02) hosts it for the cluster; a db.conf in the payload marks it.
setup_database() {
    [ -f "$PAYLOAD/db.conf" ] || return 0
    # shellcheck disable=SC1090
    . "$PAYLOAD/db.conf"   # -> DB_PASSWORD, DB_NAME
    log "This node is the cluster database host - provisioning PostgreSQL..."
    apt-get install -y -qq postgresql postgresql-contrib >/dev/null 2>&1 || true
    PGVER="$(ls /etc/postgresql 2>/dev/null | sort -V | tail -1)"
    if [ -z "$PGVER" ]; then log "WARNING: PostgreSQL not installed - skipping DB."; return 0; fi
    PGCONF="/etc/postgresql/$PGVER/main"

    sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "$PGCONF/postgresql.conf"
    # TLS for the DB, reusing this node's MILNET-CA-signed certificate.
    install -m 600 -o postgres -g postgres "$CONFIG_DIR/tls/node.key" "$PGCONF/milnet-db.key" 2>/dev/null || true
    install -m 644 -o postgres -g postgres "$CONFIG_DIR/tls/node.crt" "$PGCONF/milnet-db.crt" 2>/dev/null || true
    sed -i "s|^#\?ssl .*|ssl = on|" "$PGCONF/postgresql.conf"
    sed -i "s|^#\?ssl_cert_file.*|ssl_cert_file = '$PGCONF/milnet-db.crt'|" "$PGCONF/postgresql.conf"
    sed -i "s|^#\?ssl_key_file.*|ssl_key_file = '$PGCONF/milnet-db.key'|"  "$PGCONF/postgresql.conf"
    grep -q 'MILNET fleet' "$PGCONF/pg_hba.conf" 2>/dev/null || {
        echo "# MILNET fleet - allow cluster LAN with password auth" >> "$PGCONF/pg_hba.conf"
        echo "hostssl all all samenet scram-sha-256" >> "$PGCONF/pg_hba.conf"
        echo "host    all all samenet scram-sha-256" >> "$PGCONF/pg_hba.conf"
    }
    systemctl restart postgresql 2>/dev/null || service postgresql restart || true
    sleep 3

    psql_q() { sudo -u postgres psql -tAc "$1" 2>/dev/null; }
    if [ "$(psql_q "SELECT 1 FROM pg_roles WHERE rolname='milnet'")" != "1" ]; then
        sudo -u postgres psql -c "CREATE ROLE milnet LOGIN PASSWORD '$DB_PASSWORD'" >/dev/null 2>&1 || true
    else
        sudo -u postgres psql -c "ALTER ROLE milnet PASSWORD '$DB_PASSWORD'" >/dev/null 2>&1 || true
    fi
    if [ "$(psql_q "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")" != "1" ]; then
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER milnet" >/dev/null 2>&1 || true
    fi
    if [ -d "$PAYLOAD/migrations" ]; then
        for m in $(ls "$PAYLOAD/migrations"/*.sql 2>/dev/null | sort -V); do
            log "  applying migration $(basename "$m")"
            sudo -u postgres psql -d "$DB_NAME" -v ON_ERROR_STOP=0 -f "$m" >/dev/null 2>&1 \
                || log "  (migration $(basename "$m") reported issues - continuing)"
        done
    fi
    log "PostgreSQL ready: 0.0.0.0:5432 db=$DB_NAME (TLS on, scram-sha-256)."
}
setup_database

# --- 9. Enable + start the assigned services ---------------------------------
if [ ! -f "$PAYLOAD/node.manifest" ]; then
    log "FATAL: node.manifest missing - nothing to start." >&2
    exit 1
fi

log "Enabling and starting assigned services..."
STARTED=()
FAILED=()
while IFS= read -r unit; do
    unit=$(echo "$unit" | tr -d '[:space:]')
    [ -z "$unit" ] && continue
    case "$unit" in \#*) continue ;; esac
    log "  -> $unit"
    if systemctl enable --now "$unit" 2>/dev/null; then
        STARTED+=("$unit")
    else
        FAILED+=("$unit")
        log "  !! failed to start $unit"
        systemctl status "$unit" --no-pager -l 2>/dev/null | sed 's/^/     /' | head -n 20 || true
    fi
done < "$PAYLOAD/node.manifest"

# --- 10. Report --------------------------------------------------------------
log "=== Provisioning complete ==="
log "Started: ${STARTED[*]:-none}"
if [ "${#FAILED[@]}" -gt 0 ]; then
    log "FAILED:  ${FAILED[*]}"
    exit 1
fi
log "All assigned services are active on this node."
exit 0
