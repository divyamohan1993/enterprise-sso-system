#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Deployment Entrypoint
# ==============================================================================
# Starts PostgreSQL as the postgres user, then runs the admin service as the
# unprivileged milnet user.
#
# Security: This script runs as root only to start PostgreSQL; it immediately
# drops privileges to the milnet user for the application process.
# ==============================================================================

set -euo pipefail

echo "=== MILNET SSO Deployment Entrypoint ==="

# ── Start PostgreSQL ──────────────────────────────────────────────────────────
if command -v pg_isready >/dev/null 2>&1; then
    echo "[entrypoint] Starting PostgreSQL..."

    # Initialize the database cluster if not already done
    PG_DATA="/var/lib/postgresql/15/main"
    if [ ! -d "$PG_DATA" ] || [ ! -f "$PG_DATA/PG_VERSION" ]; then
        echo "[entrypoint] Initializing PostgreSQL data directory..."
        su - postgres -c "/usr/lib/postgresql/15/bin/initdb -D $PG_DATA"
    fi

    # Start PostgreSQL as the postgres user
    su - postgres -c "/usr/lib/postgresql/15/bin/pg_ctl start -D $PG_DATA -l /var/log/postgresql/postgresql.log -w"

    # Wait for PostgreSQL to be ready
    for i in $(seq 1 30); do
        if su - postgres -c "pg_isready -q" 2>/dev/null; then
            echo "[entrypoint] PostgreSQL is ready."
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo "[entrypoint] ERROR: PostgreSQL failed to start within 30 seconds."
            exit 1
        fi
        sleep 1
    done

    # Create the milnet database if it doesn't exist
    su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname = 'milnet'\" | grep -q 1" || \
        su - postgres -c "createdb milnet"

    # Set DATABASE_URL if not already provided
    export DATABASE_URL="${DATABASE_URL:-postgresql://postgres@localhost/milnet}"
else
    echo "[entrypoint] PostgreSQL not found; using external DATABASE_URL."
    if [ -z "${DATABASE_URL:-}" ]; then
        echo "[entrypoint] ERROR: DATABASE_URL is required when PostgreSQL is not installed."
        exit 1
    fi
fi

# ── Start the Admin Service ───────────────────────────────────────────────────
echo "[entrypoint] Starting admin service on port ${ADMIN_PORT:-8080}..."
echo "[entrypoint] Log level: ${RUST_LOG:-info}"

# Drop privileges to milnet user for the application process
exec su - milnet -s /bin/bash -c "
    export DATABASE_URL='${DATABASE_URL}'
    export ADMIN_PORT='${ADMIN_PORT:-8080}'
    export RUST_LOG='${RUST_LOG:-info}'
    export DEVELOPER_MODE='${DEVELOPER_MODE:-false}'
    exec /usr/local/bin/admin
"
