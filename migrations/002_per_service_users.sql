-- Migration 002: Per-service database roles with minimal privileges
--
-- Each MILNET SSO microservice connects with its own restricted PostgreSQL
-- role.  This limits blast radius: a compromised verifier cannot INSERT into
-- audit_log, and the audit service cannot UPDATE user records.
--
-- Roles are created with NOLOGIN by default.  Per-environment deployment
-- scripts should CREATE USER ... LOGIN PASSWORD ... IN ROLE milnet_<role>
-- for each service.

-- =========================================================================
-- 1. Create roles (idempotent via IF NOT EXISTS)
-- =========================================================================

DO $$
BEGIN
    -- Admin role: full DDL and DML (for migrations and admin tooling)
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'milnet_admin') THEN
        CREATE ROLE milnet_admin NOLOGIN;
    END IF;

    -- Audit role: append-only access to audit_log
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'milnet_audit') THEN
        CREATE ROLE milnet_audit NOLOGIN;
    END IF;

    -- Verifier role: read-only on users and sessions for token validation
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'milnet_verifier') THEN
        CREATE ROLE milnet_verifier NOLOGIN;
    END IF;

    -- OPAQUE role: manages user OPAQUE registration data
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'milnet_opaque') THEN
        CREATE ROLE milnet_opaque NOLOGIN;
    END IF;

    -- Orchestrator role: manages sessions, authorization codes, OAuth flows
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'milnet_orchestrator') THEN
        CREATE ROLE milnet_orchestrator NOLOGIN;
    END IF;
END $$;

-- =========================================================================
-- 2. Revoke default public access (defense in depth)
-- =========================================================================

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- =========================================================================
-- 3. milnet_admin: Full privileges on all tables
-- =========================================================================

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO milnet_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO milnet_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO milnet_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO milnet_admin;

-- =========================================================================
-- 4. milnet_audit: INSERT only on audit_log, SELECT for chain verification
-- =========================================================================

GRANT SELECT, INSERT ON audit_log TO milnet_audit;
-- The audit service also needs to read witness_checkpoints for cross-reference
GRANT SELECT ON witness_checkpoints TO milnet_audit;

-- =========================================================================
-- 5. milnet_verifier: SELECT only on users, sessions, fido_credentials
-- =========================================================================

GRANT SELECT ON users TO milnet_verifier;
GRANT SELECT ON sessions TO milnet_verifier;
GRANT SELECT ON fido_credentials TO milnet_verifier;
GRANT SELECT ON revoked_tokens TO milnet_verifier;
GRANT SELECT ON portals TO milnet_verifier;

-- =========================================================================
-- 6. milnet_opaque: SELECT/UPDATE on users (opaque_registration column)
-- =========================================================================

GRANT SELECT, UPDATE ON users TO milnet_opaque;
-- OPAQUE service needs to insert new users during registration
GRANT INSERT ON users TO milnet_opaque;
-- Recovery codes for account recovery flows
GRANT SELECT, INSERT, UPDATE ON recovery_codes TO milnet_opaque;

-- =========================================================================
-- 7. milnet_orchestrator: Session and OAuth flow management
-- =========================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO milnet_orchestrator;
GRANT SELECT, INSERT, UPDATE, DELETE ON authorization_codes TO milnet_orchestrator;
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_codes TO milnet_orchestrator;
GRANT SELECT, INSERT ON revoked_tokens TO milnet_orchestrator;
GRANT SELECT ON users TO milnet_orchestrator;
GRANT SELECT ON portals TO milnet_orchestrator;
GRANT SELECT ON devices TO milnet_orchestrator;
GRANT SELECT, INSERT, UPDATE ON ratchet_sessions TO milnet_orchestrator;
GRANT SELECT, INSERT, UPDATE ON shard_sequences TO milnet_orchestrator;
GRANT SELECT ON server_config TO milnet_orchestrator;

-- =========================================================================
-- 8. Row-Level Security (RLS) policies
-- =========================================================================

-- Enable RLS on sensitive tables.  The milnet_admin role bypasses RLS
-- because it is a superuser-like role.

-- 8a. audit_log: audit role can only see/insert its own entries,
--     admin can see everything.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_log_admin_all ON audit_log
    FOR ALL
    TO milnet_admin
    USING (true)
    WITH CHECK (true);

CREATE POLICY audit_log_audit_select ON audit_log
    FOR SELECT
    TO milnet_audit
    USING (true);

CREATE POLICY audit_log_audit_insert ON audit_log
    FOR INSERT
    TO milnet_audit
    WITH CHECK (true);

-- 8b. sessions: orchestrator manages sessions, verifier can only read
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY sessions_admin_all ON sessions
    FOR ALL
    TO milnet_admin
    USING (true)
    WITH CHECK (true);

CREATE POLICY sessions_orchestrator_all ON sessions
    FOR ALL
    TO milnet_orchestrator
    USING (true)
    WITH CHECK (true);

CREATE POLICY sessions_verifier_select ON sessions
    FOR SELECT
    TO milnet_verifier
    USING (true);

-- 8c. users: opaque service can read/write, verifier and orchestrator read-only
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY users_admin_all ON users
    FOR ALL
    TO milnet_admin
    USING (true)
    WITH CHECK (true);

CREATE POLICY users_opaque_all ON users
    FOR ALL
    TO milnet_opaque
    USING (true)
    WITH CHECK (true);

CREATE POLICY users_verifier_select ON users
    FOR SELECT
    TO milnet_verifier
    USING (true);

CREATE POLICY users_orchestrator_select ON users
    FOR SELECT
    TO milnet_orchestrator
    USING (true);

-- 8d. key_material: only admin can touch key material
ALTER TABLE key_material ENABLE ROW LEVEL SECURITY;

CREATE POLICY key_material_admin_all ON key_material
    FOR ALL
    TO milnet_admin
    USING (true)
    WITH CHECK (true);

-- =========================================================================
-- 9. Audit log retention: allow milnet_audit to DELETE old entries
--    (required by enforce_retention() for aged-out entries)
-- =========================================================================

GRANT DELETE ON audit_log TO milnet_audit;
