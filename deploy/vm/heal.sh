#!/usr/bin/env bash
# MILNET SSO System — Binary Healing Script
#
# Replaces a potentially corrupted binary on a target VM, restarts the service,
# and verifies the health check passes after restart.
#
# Usage:
#   ./heal.sh TARGET_IP SERVICE_NAME
#
# Examples:
#   ./heal.sh 10.0.0.2 orchestrator
#   ./heal.sh 10.0.0.3 tss-signer@2     # template instance
#   ./heal.sh 10.0.0.5 audit
#
# The script computes a SHA-256 hash of the local binary before and after
# transfer to ensure integrity. Exits non-zero if healing fails.

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY_DIR="${BINARY_DIR:-$PROJECT_ROOT/target/release}"
SSH_USER="${SSH_USER:-root}"
SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=accept-new -o ConnectTimeout=10}"
INSTALL_DIR="/opt/milnet/bin"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-30}"

# ── Argument validation ────────────────────────────────────────────────────────

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 TARGET_IP SERVICE_NAME"
    echo ""
    echo "SERVICE_NAME is one of:"
    echo "  gateway, orchestrator, opaque, tss, verifier,"
    echo "  ratchet, risk, audit, kt, admin"
    echo ""
    echo "For TSS signer template instances, use:"
    echo "  tss-signer@N  (e.g., tss-signer@1)"
    exit 1
fi

TARGET_IP="$1"
SERVICE_INPUT="$2"

# ── Resolve service name and systemd unit ──────────────────────────────────────

# Map service input to binary name and systemd unit name
if [[ "$SERVICE_INPUT" == tss-signer@* ]]; then
    BINARY_NAME="tss"
    SYSTEMD_UNIT="milnet-${SERVICE_INPUT}.service"
elif [[ "$SERVICE_INPUT" == tss-coordinator ]]; then
    BINARY_NAME="tss"
    SYSTEMD_UNIT="milnet-tss-coordinator.service"
else
    BINARY_NAME="$SERVICE_INPUT"
    SYSTEMD_UNIT="milnet-${SERVICE_INPUT}.service"
fi

LOCAL_BINARY="$BINARY_DIR/$BINARY_NAME"

# ── Helper functions ───────────────────────────────────────────────────────────

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

ssh_cmd() {
    ssh $SSH_OPTS "$SSH_USER@$TARGET_IP" "$@"
}

scp_cmd() {
    scp $SSH_OPTS "$@"
}

die() {
    log "FATAL: $*"
    exit 1
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────

[ -f "$LOCAL_BINARY" ] || die "Local binary not found: $LOCAL_BINARY (build with: cargo build --release --bin $BINARY_NAME)"

ssh_cmd "true" 2>/dev/null || die "Cannot SSH to $TARGET_IP"

log "Healing $SERVICE_INPUT on $TARGET_IP"
log "  Binary: $LOCAL_BINARY"
log "  Systemd unit: $SYSTEMD_UNIT"

# ── Step 1: Compute local binary hash ─────────────────────────────────────────

LOCAL_HASH=$(sha256sum "$LOCAL_BINARY" | awk '{print $1}')
log "Local binary SHA-256: $LOCAL_HASH"

# ── Step 2: Check remote binary hash (if present) ─────────────────────────────

REMOTE_BINARY="$INSTALL_DIR/$BINARY_NAME"
REMOTE_HASH=$(ssh_cmd "sha256sum $REMOTE_BINARY 2>/dev/null | awk '{print \$1}'" || echo "MISSING")

if [ "$REMOTE_HASH" = "$LOCAL_HASH" ]; then
    log "Remote binary already matches local binary. Skipping copy."
    COPY_NEEDED=false
else
    if [ "$REMOTE_HASH" = "MISSING" ]; then
        log "Remote binary not found — will deploy fresh copy."
    else
        log "Remote binary SHA-256: $REMOTE_HASH (MISMATCH — will replace)"
    fi
    COPY_NEEDED=true
fi

# ── Step 3: Stop the service ──────────────────────────────────────────────────

log "Stopping $SYSTEMD_UNIT..."
ssh_cmd "systemctl stop $SYSTEMD_UNIT 2>/dev/null" || log "  (unit was not running)"

# ── Step 4: Copy binary if needed ─────────────────────────────────────────────

if [ "$COPY_NEEDED" = true ]; then
    log "Copying binary to $TARGET_IP:$REMOTE_BINARY..."
    scp_cmd "$LOCAL_BINARY" "$SSH_USER@$TARGET_IP:$REMOTE_BINARY"
    ssh_cmd "chmod 755 $REMOTE_BINARY && chown root:milnet $REMOTE_BINARY"

    # Verify transfer integrity
    VERIFY_HASH=$(ssh_cmd "sha256sum $REMOTE_BINARY | awk '{print \$1}'")
    if [ "$VERIFY_HASH" != "$LOCAL_HASH" ]; then
        die "Binary hash mismatch after transfer! Expected $LOCAL_HASH, got $VERIFY_HASH"
    fi
    log "Transfer verified — SHA-256 matches."
fi

# ── Step 5: Restart the service ───────────────────────────────────────────────

log "Starting $SYSTEMD_UNIT..."
ssh_cmd "systemctl start $SYSTEMD_UNIT"

# ── Step 6: Verify health check ───────────────────────────────────────────────

log "Waiting up to ${HEALTH_TIMEOUT}s for health check..."

# Determine the health port from the service's environment file
# Convention: health port = service port + 1000
HEALTH_PORT=""
case "$SERVICE_INPUT" in
    gateway)          HEALTH_PORT=10100 ;;
    orchestrator)     HEALTH_PORT=10101 ;;
    opaque)           HEALTH_PORT=10102 ;;
    tss-coordinator)  HEALTH_PORT=10103 ;;
    verifier)         HEALTH_PORT=10104 ;;
    ratchet)          HEALTH_PORT=10105 ;;
    risk)             HEALTH_PORT=10106 ;;
    audit)            HEALTH_PORT=10108 ;;
    kt)               HEALTH_PORT=10109 ;;
    admin)            HEALTH_PORT=9080  ;;
    tss-signer@1)     HEALTH_PORT=10110 ;;
    tss-signer@2)     HEALTH_PORT=10111 ;;
    tss-signer@3)     HEALTH_PORT=10112 ;;
    tss-signer@4)     HEALTH_PORT=10113 ;;
    tss-signer@5)     HEALTH_PORT=10114 ;;
    *)
        log "WARNING: Unknown service — cannot determine health port. Skipping health check."
        log "Heal complete (health check skipped)."
        exit 0
        ;;
esac

ELAPSED=0
INTERVAL=2
while [ "$ELAPSED" -lt "$HEALTH_TIMEOUT" ]; do
    if ssh_cmd "timeout 3 bash -c 'echo > /dev/tcp/127.0.0.1/$HEALTH_PORT'" 2>/dev/null; then
        log "Health check PASSED on port $HEALTH_PORT after ${ELAPSED}s"
        log "Heal complete for $SERVICE_INPUT on $TARGET_IP"
        exit 0
    fi
    sleep "$INTERVAL"
    ELAPSED=$((ELAPSED + INTERVAL))
done

die "Health check FAILED — $SYSTEMD_UNIT did not become healthy within ${HEALTH_TIMEOUT}s. Check: ssh $SSH_USER@$TARGET_IP journalctl -u $SYSTEMD_UNIT --no-pager -n 50"
