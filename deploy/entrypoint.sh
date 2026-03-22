#!/bin/bash
set -e

# Start PostgreSQL
PG_VERSION=$(ls /usr/lib/postgresql/)
export PATH="/usr/lib/postgresql/$PG_VERSION/bin:$PATH"
PGDATA="/var/lib/postgresql/$PG_VERSION/main"

# Initialize DB if needed
if [ ! -f "$PGDATA/PG_VERSION" ]; then
    su - postgres -c "initdb -D $PGDATA" 2>/dev/null || true
fi

# Start PostgreSQL
su - postgres -c "pg_ctlcluster $PG_VERSION main start" 2>/dev/null || \
    pg_ctlcluster "$PG_VERSION" main start 2>/dev/null || \
    su - postgres -c "/usr/lib/postgresql/$PG_VERSION/bin/pg_ctl -D $PGDATA -l /var/log/postgresql/postgresql.log start"

# Wait for PostgreSQL to be ready
for i in $(seq 1 30); do
    if su - postgres -c "pg_isready" 2>/dev/null; then
        break
    fi
    sleep 1
done

# Create user and database
su - postgres -c "psql -c \"CREATE USER milnet WITH PASSWORD '${MILNET_DB_PASSWORD}';\"" 2>/dev/null || true
su - postgres -c "psql -c \"CREATE DATABASE milnet_sso OWNER milnet;\"" 2>/dev/null || true

# Start the admin server as non-root milnet user
# cd to /opt so ServeDir::new("frontend") resolves to /opt/frontend/
cd /opt
exec su -s /bin/bash milnet -c "/usr/local/bin/admin"
