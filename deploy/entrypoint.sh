#!/bin/bash
set -euo pipefail

# Start PostgreSQL
PG_VERSION=$(ls /usr/lib/postgresql/)
export PATH="/usr/lib/postgresql/$PG_VERSION/bin:$PATH"
PGDATA="/var/lib/postgresql/$PG_VERSION/main"

# Initialize DB if needed
if [ ! -f "$PGDATA/PG_VERSION" ]; then
    if ! su - postgres -c "initdb -D $PGDATA" 2>&1; then
        echo "ERROR: Failed to initialize PostgreSQL database" >&2
        exit 1
    fi
fi

# Start PostgreSQL
if ! su - postgres -c "pg_ctlcluster $PG_VERSION main start" 2>&1; then
    if ! pg_ctlcluster "$PG_VERSION" main start 2>&1; then
        if ! su - postgres -c "/usr/lib/postgresql/$PG_VERSION/bin/pg_ctl -D $PGDATA -l /var/log/postgresql/postgresql.log start" 2>&1; then
            echo "ERROR: Failed to start PostgreSQL" >&2
            exit 1
        fi
    fi
fi

# Wait for PostgreSQL to be ready
pg_ready=false
for i in $(seq 1 30); do
    if su - postgres -c "pg_isready" 2>/dev/null; then
        pg_ready=true
        break
    fi
    sleep 1
done
if [ "$pg_ready" = false ]; then
    echo "ERROR: PostgreSQL failed to become ready after 30 seconds" >&2
    exit 1
fi

# Create user and database using temp SQL file to avoid password in process listing
SQL_TMPFILE=$(mktemp /tmp/milnet-init-XXXXXX.sql)
chmod 600 "$SQL_TMPFILE"
cat > "$SQL_TMPFILE" <<EOSQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'milnet') THEN
        CREATE USER milnet WITH PASSWORD '${MILNET_DB_PASSWORD}';
    END IF;
END
\$\$;

SELECT 'CREATE DATABASE milnet_sso OWNER milnet'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'milnet_sso')\gexec
EOSQL

if ! su - postgres -c "psql -f $SQL_TMPFILE" 2>&1; then
    echo "WARNING: Database initialization may have partially failed" >&2
fi
rm -f "$SQL_TMPFILE"

# Clear the password from the environment before exec-ing the application
unset MILNET_DB_PASSWORD

# Start the admin server as non-root milnet user
# cd to /opt so ServeDir::new("frontend") resolves to /opt/frontend/
cd /opt
exec su -s /bin/bash milnet -c "/usr/local/bin/admin"
