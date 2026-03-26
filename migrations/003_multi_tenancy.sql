-- Migration 003: Multi-tenancy enforcement
-- Adds tenant_id to all data tables, creates the tenants table,
-- and enables Row-Level Security (RLS) scoped by tenant_id.
--
-- This migration is idempotent — safe to re-run.

BEGIN;

-- =========================================================================
-- 1. Tenants table (matches common::multi_tenancy::Tenant struct)
-- =========================================================================

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id       UUID PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(255) UNIQUE NOT NULL,
    status          VARCHAR(50)  NOT NULL DEFAULT 'Active'
                    CHECK (status IN ('Active', 'Suspended', 'Decommissioning', 'Decommissioned')),
    created_at      BIGINT       NOT NULL,
    compliance_regime VARCHAR(50) NOT NULL DEFAULT 'Commercial'
                    CHECK (compliance_regime IN ('UsDod', 'IndianGovt', 'Commercial', 'Dual')),
    data_residency_region VARCHAR(100) NOT NULL DEFAULT '',
    max_users       BIGINT       NOT NULL DEFAULT 1000,
    max_devices     BIGINT       NOT NULL DEFAULT 5000,
    feature_flags   TEXT         NOT NULL DEFAULT '[]',
    encryption_key_id TEXT       NOT NULL DEFAULT '',

    -- Per-tenant rate limiting
    rate_limit_rps          INTEGER NOT NULL DEFAULT 1000,
    rate_limit_burst        INTEGER NOT NULL DEFAULT 2000,

    -- Per-tenant policy configuration
    session_timeout_secs    BIGINT  NOT NULL DEFAULT 3600,
    max_sessions_per_user   INTEGER NOT NULL DEFAULT 5,
    password_min_length     INTEGER NOT NULL DEFAULT 12,
    mfa_required            BOOLEAN NOT NULL DEFAULT true,
    allowed_auth_methods    TEXT    NOT NULL DEFAULT '["opaque","fido","cac"]'
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants (slug);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants (status);

-- =========================================================================
-- 2. Add tenant_id column to all data tables
-- =========================================================================

-- A default tenant UUID for existing rows during migration.
-- In production, run a data-backfill job to assign proper tenant IDs.
-- Using a well-known UUID so it can be identified and cleaned up.
DO $$ BEGIN
    -- users
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE users ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
    END IF;

    -- devices
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'devices' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE devices ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
    END IF;

    -- sessions
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'sessions' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE sessions ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
    END IF;

    -- audit_log
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_log' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE audit_log ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
    END IF;

    -- portals
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'portals' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE portals ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
    END IF;

    -- fido_credentials
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'fido_credentials' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE fido_credentials ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
    END IF;

    -- authorization_codes
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'authorization_codes' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE authorization_codes ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
    END IF;

    -- oauth_codes
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'oauth_codes' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE oauth_codes ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
    END IF;

    -- revoked_tokens
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'revoked_tokens' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE revoked_tokens ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
    END IF;

    -- recovery_codes
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'recovery_codes' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE recovery_codes ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
    END IF;
END $$;

-- =========================================================================
-- 3. Indexes on tenant_id for all tables
-- =========================================================================

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_devices_tenant_id ON devices (tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id ON sessions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id ON audit_log (tenant_id);
CREATE INDEX IF NOT EXISTS idx_portals_tenant_id ON portals (tenant_id);
CREATE INDEX IF NOT EXISTS idx_fido_credentials_tenant_id ON fido_credentials (tenant_id);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_tenant_id ON authorization_codes (tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_tenant_id ON oauth_codes (tenant_id);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_tenant_id ON revoked_tokens (tenant_id);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_tenant_id ON recovery_codes (tenant_id);

-- Composite indexes for common query patterns (tenant + lookup key)
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_username ON users (tenant_id, username);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_user ON sessions (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_fido_credentials_tenant_user ON fido_credentials (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_tenant_user ON recovery_codes (tenant_id, user_id) WHERE NOT is_used;
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_timestamp ON audit_log (tenant_id, timestamp);

-- =========================================================================
-- 4. Row-Level Security (RLS) policies scoped by tenant_id
-- =========================================================================
-- RLS is enforced via a session variable `app.current_tenant_id` that the
-- application sets on each connection/transaction via:
--   SET LOCAL app.current_tenant_id = '<uuid>';
--
-- The policies below ensure that even if application code has a bug,
-- PostgreSQL itself will prevent cross-tenant data access.

-- Helper: get the current tenant_id from session config
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID AS $$
BEGIN
    RETURN current_setting('app.current_tenant_id', true)::UUID;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- Macro-like DO block to enable RLS and create policies for each table.
-- Each table gets: SELECT, INSERT, UPDATE, DELETE policies scoped to tenant_id.

-- users
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_select_users ON users;
DROP POLICY IF EXISTS tenant_isolation_insert_users ON users;
DROP POLICY IF EXISTS tenant_isolation_update_users ON users;
DROP POLICY IF EXISTS tenant_isolation_delete_users ON users;
CREATE POLICY tenant_isolation_select_users ON users FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_insert_users ON users FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_update_users ON users FOR UPDATE USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_delete_users ON users FOR DELETE USING (tenant_id = current_tenant_id());

-- devices
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_select_devices ON devices;
DROP POLICY IF EXISTS tenant_isolation_insert_devices ON devices;
DROP POLICY IF EXISTS tenant_isolation_update_devices ON devices;
DROP POLICY IF EXISTS tenant_isolation_delete_devices ON devices;
CREATE POLICY tenant_isolation_select_devices ON devices FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_insert_devices ON devices FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_update_devices ON devices FOR UPDATE USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_delete_devices ON devices FOR DELETE USING (tenant_id = current_tenant_id());

-- sessions
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_select_sessions ON sessions;
DROP POLICY IF EXISTS tenant_isolation_insert_sessions ON sessions;
DROP POLICY IF EXISTS tenant_isolation_update_sessions ON sessions;
DROP POLICY IF EXISTS tenant_isolation_delete_sessions ON sessions;
CREATE POLICY tenant_isolation_select_sessions ON sessions FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_insert_sessions ON sessions FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_update_sessions ON sessions FOR UPDATE USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_delete_sessions ON sessions FOR DELETE USING (tenant_id = current_tenant_id());

-- audit_log
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_select_audit_log ON audit_log;
DROP POLICY IF EXISTS tenant_isolation_insert_audit_log ON audit_log;
DROP POLICY IF EXISTS tenant_isolation_update_audit_log ON audit_log;
DROP POLICY IF EXISTS tenant_isolation_delete_audit_log ON audit_log;
CREATE POLICY tenant_isolation_select_audit_log ON audit_log FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_insert_audit_log ON audit_log FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_update_audit_log ON audit_log FOR UPDATE USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_delete_audit_log ON audit_log FOR DELETE USING (tenant_id = current_tenant_id());

-- portals
ALTER TABLE portals ENABLE ROW LEVEL SECURITY;
ALTER TABLE portals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_select_portals ON portals;
DROP POLICY IF EXISTS tenant_isolation_insert_portals ON portals;
DROP POLICY IF EXISTS tenant_isolation_update_portals ON portals;
DROP POLICY IF EXISTS tenant_isolation_delete_portals ON portals;
CREATE POLICY tenant_isolation_select_portals ON portals FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_insert_portals ON portals FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_update_portals ON portals FOR UPDATE USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_delete_portals ON portals FOR DELETE USING (tenant_id = current_tenant_id());

-- fido_credentials
ALTER TABLE fido_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE fido_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_select_fido_credentials ON fido_credentials;
DROP POLICY IF EXISTS tenant_isolation_insert_fido_credentials ON fido_credentials;
DROP POLICY IF EXISTS tenant_isolation_update_fido_credentials ON fido_credentials;
DROP POLICY IF EXISTS tenant_isolation_delete_fido_credentials ON fido_credentials;
CREATE POLICY tenant_isolation_select_fido_credentials ON fido_credentials FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_insert_fido_credentials ON fido_credentials FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_update_fido_credentials ON fido_credentials FOR UPDATE USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_delete_fido_credentials ON fido_credentials FOR DELETE USING (tenant_id = current_tenant_id());

-- authorization_codes
ALTER TABLE authorization_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_codes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_select_authorization_codes ON authorization_codes;
DROP POLICY IF EXISTS tenant_isolation_insert_authorization_codes ON authorization_codes;
DROP POLICY IF EXISTS tenant_isolation_update_authorization_codes ON authorization_codes;
DROP POLICY IF EXISTS tenant_isolation_delete_authorization_codes ON authorization_codes;
CREATE POLICY tenant_isolation_select_authorization_codes ON authorization_codes FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_insert_authorization_codes ON authorization_codes FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_update_authorization_codes ON authorization_codes FOR UPDATE USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_delete_authorization_codes ON authorization_codes FOR DELETE USING (tenant_id = current_tenant_id());

-- oauth_codes
ALTER TABLE oauth_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_codes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_select_oauth_codes ON oauth_codes;
DROP POLICY IF EXISTS tenant_isolation_insert_oauth_codes ON oauth_codes;
DROP POLICY IF EXISTS tenant_isolation_update_oauth_codes ON oauth_codes;
DROP POLICY IF EXISTS tenant_isolation_delete_oauth_codes ON oauth_codes;
CREATE POLICY tenant_isolation_select_oauth_codes ON oauth_codes FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_insert_oauth_codes ON oauth_codes FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_update_oauth_codes ON oauth_codes FOR UPDATE USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_delete_oauth_codes ON oauth_codes FOR DELETE USING (tenant_id = current_tenant_id());

-- revoked_tokens
ALTER TABLE revoked_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE revoked_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_select_revoked_tokens ON revoked_tokens;
DROP POLICY IF EXISTS tenant_isolation_insert_revoked_tokens ON revoked_tokens;
DROP POLICY IF EXISTS tenant_isolation_update_revoked_tokens ON revoked_tokens;
DROP POLICY IF EXISTS tenant_isolation_delete_revoked_tokens ON revoked_tokens;
CREATE POLICY tenant_isolation_select_revoked_tokens ON revoked_tokens FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_insert_revoked_tokens ON revoked_tokens FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_update_revoked_tokens ON revoked_tokens FOR UPDATE USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_delete_revoked_tokens ON revoked_tokens FOR DELETE USING (tenant_id = current_tenant_id());

-- recovery_codes
ALTER TABLE recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_codes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_select_recovery_codes ON recovery_codes;
DROP POLICY IF EXISTS tenant_isolation_insert_recovery_codes ON recovery_codes;
DROP POLICY IF EXISTS tenant_isolation_update_recovery_codes ON recovery_codes;
DROP POLICY IF EXISTS tenant_isolation_delete_recovery_codes ON recovery_codes;
CREATE POLICY tenant_isolation_select_recovery_codes ON recovery_codes FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_insert_recovery_codes ON recovery_codes FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_update_recovery_codes ON recovery_codes FOR UPDATE USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_isolation_delete_recovery_codes ON recovery_codes FOR DELETE USING (tenant_id = current_tenant_id());

-- =========================================================================
-- 5. Foreign key constraints: tenant_id references tenants(tenant_id)
-- =========================================================================
-- Note: We add these as deferred constraints so bulk migration can insert
-- the default tenant row first, then backfill.

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_users_tenant' AND table_name = 'users'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT fk_users_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) DEFERRABLE INITIALLY DEFERRED;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_devices_tenant' AND table_name = 'devices'
    ) THEN
        ALTER TABLE devices ADD CONSTRAINT fk_devices_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) DEFERRABLE INITIALLY DEFERRED;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_sessions_tenant' AND table_name = 'sessions'
    ) THEN
        ALTER TABLE sessions ADD CONSTRAINT fk_sessions_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) DEFERRABLE INITIALLY DEFERRED;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_audit_log_tenant' AND table_name = 'audit_log'
    ) THEN
        ALTER TABLE audit_log ADD CONSTRAINT fk_audit_log_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) DEFERRABLE INITIALLY DEFERRED;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_portals_tenant' AND table_name = 'portals'
    ) THEN
        ALTER TABLE portals ADD CONSTRAINT fk_portals_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) DEFERRABLE INITIALLY DEFERRED;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_fido_credentials_tenant' AND table_name = 'fido_credentials'
    ) THEN
        ALTER TABLE fido_credentials ADD CONSTRAINT fk_fido_credentials_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) DEFERRABLE INITIALLY DEFERRED;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_authorization_codes_tenant' AND table_name = 'authorization_codes'
    ) THEN
        ALTER TABLE authorization_codes ADD CONSTRAINT fk_authorization_codes_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) DEFERRABLE INITIALLY DEFERRED;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_oauth_codes_tenant' AND table_name = 'oauth_codes'
    ) THEN
        ALTER TABLE oauth_codes ADD CONSTRAINT fk_oauth_codes_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) DEFERRABLE INITIALLY DEFERRED;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_revoked_tokens_tenant' AND table_name = 'revoked_tokens'
    ) THEN
        ALTER TABLE revoked_tokens ADD CONSTRAINT fk_revoked_tokens_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) DEFERRABLE INITIALLY DEFERRED;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_recovery_codes_tenant' AND table_name = 'recovery_codes'
    ) THEN
        ALTER TABLE recovery_codes ADD CONSTRAINT fk_recovery_codes_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) DEFERRABLE INITIALLY DEFERRED;
    END IF;
END $$;

-- =========================================================================
-- 6. Insert the default migration tenant (for pre-existing rows)
-- =========================================================================

INSERT INTO tenants (tenant_id, name, slug, status, created_at, compliance_regime, data_residency_region, max_users, max_devices, encryption_key_id)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'Default Migration Tenant',
    'default-migration',
    'Active',
    EXTRACT(EPOCH FROM NOW())::BIGINT,
    'Commercial',
    'us-central1',
    10000,
    50000,
    ''
) ON CONFLICT (tenant_id) DO NOTHING;

COMMIT;
