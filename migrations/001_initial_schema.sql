-- Migration 001: Initial schema for MILNET SSO system
--
-- Creates all base tables required by the SSO system.
-- This migration must run BEFORE 002_per_service_users.sql and
-- 003_multi_tenancy.sql, which depend on these tables existing.
--
-- All tables use CREATE TABLE IF NOT EXISTS for idempotency.

BEGIN;

-- =========================================================================
-- 1. Tenants table (must exist first for FK constraints)
-- =========================================================================

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id               UUID PRIMARY KEY,
    name                    VARCHAR(255) NOT NULL,
    slug                    VARCHAR(255) UNIQUE NOT NULL,
    status                  VARCHAR(50)  NOT NULL DEFAULT 'Active',
    created_at              BIGINT       NOT NULL,
    compliance_regime       VARCHAR(50)  NOT NULL DEFAULT 'Commercial',
    data_residency_region   VARCHAR(100) NOT NULL DEFAULT '',
    max_users               BIGINT       NOT NULL DEFAULT 1000,
    max_devices             BIGINT       NOT NULL DEFAULT 5000,
    feature_flags           TEXT         NOT NULL DEFAULT '[]',
    encryption_key_id       TEXT         NOT NULL DEFAULT '',
    rate_limit_rps          INTEGER      NOT NULL DEFAULT 1000,
    rate_limit_burst        INTEGER      NOT NULL DEFAULT 2000,
    session_timeout_secs    BIGINT       NOT NULL DEFAULT 3600,
    max_sessions_per_user   INTEGER      NOT NULL DEFAULT 5,
    password_min_length     INTEGER      NOT NULL DEFAULT 12,
    mfa_required            BOOLEAN      NOT NULL DEFAULT true,
    allowed_auth_methods    TEXT         NOT NULL DEFAULT '["opaque","fido","cac"]'
);

-- Insert default migration tenant for pre-existing data
INSERT INTO tenants (tenant_id, name, slug, status, created_at)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'Default Migration Tenant',
    'default-migration',
    'Active',
    EXTRACT(EPOCH FROM NOW())::BIGINT
) ON CONFLICT (tenant_id) DO NOTHING;

-- =========================================================================
-- 2. Users table — core identity store
-- =========================================================================

CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(tenant_id),
    username            VARCHAR(255) NOT NULL,
    opaque_registration BYTEA,
    tier                INTEGER NOT NULL DEFAULT 2,
    created_at          BIGINT NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    duress_pin_hash     BYTEA,
    email               VARCHAR(255),
    auth_provider       VARCHAR(50) NOT NULL DEFAULT 'opaque',
    email_encrypted     BYTEA,
    email_hash          BYTEA
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
    ON users (email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_email_hash_unique
    ON users (email_hash) WHERE email_hash IS NOT NULL;

-- =========================================================================
-- 3. Devices table — enrolled device attestations
-- =========================================================================

CREATE TABLE IF NOT EXISTS devices (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(tenant_id),
    tier                INTEGER NOT NULL,
    attestation_hash    BYTEA,
    enrolled_by         UUID,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    created_at          BIGINT NOT NULL
);

-- =========================================================================
-- 4. Portals table — registered service providers / relying parties
-- =========================================================================

CREATE TABLE IF NOT EXISTS portals (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(tenant_id),
    name                VARCHAR(255) NOT NULL,
    callback_url        TEXT NOT NULL,
    client_id           VARCHAR(255),
    client_secret       BYTEA,
    required_tier       INTEGER NOT NULL DEFAULT 2,
    required_scope      INTEGER NOT NULL DEFAULT 0,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    created_at          BIGINT NOT NULL
);

-- =========================================================================
-- 5. Audit log — append-only tamper-evident log with hash chain
-- =========================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(tenant_id),
    event_type          VARCHAR(100) NOT NULL,
    user_ids            TEXT NOT NULL DEFAULT '[]',
    timestamp           BIGINT NOT NULL,
    prev_hash           BYTEA,
    signature           BYTEA,
    data                TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
    ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type
    ON audit_log (event_type);

-- =========================================================================
-- 6. Sessions table — active authenticated sessions
-- =========================================================================

CREATE TABLE IF NOT EXISTS sessions (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(tenant_id),
    user_id             UUID NOT NULL,
    ratchet_epoch       BIGINT NOT NULL DEFAULT 0,
    created_at          BIGINT NOT NULL,
    expires_at          BIGINT NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions (expires_at);

-- =========================================================================
-- 7. Ratchet sessions — forward-secret session key ratchet state
-- =========================================================================

CREATE TABLE IF NOT EXISTS ratchet_sessions (
    session_id          UUID PRIMARY KEY,
    current_epoch       BIGINT NOT NULL,
    chain_key_encrypted BYTEA NOT NULL,
    client_entropy      BYTEA,
    server_entropy      BYTEA,
    created_at          BIGINT NOT NULL,
    last_advanced_at    BIGINT NOT NULL
);

-- =========================================================================
-- 8. Authorization codes — OAuth 2.0 / OIDC authorization code grants
-- =========================================================================

CREATE TABLE IF NOT EXISTS authorization_codes (
    code                VARCHAR(255) PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(tenant_id),
    client_id           VARCHAR(255) NOT NULL,
    redirect_uri        TEXT NOT NULL,
    user_id             UUID NOT NULL,
    code_challenge      VARCHAR(255),
    tier                INTEGER NOT NULL,
    nonce               VARCHAR(255),
    created_at          BIGINT NOT NULL,
    consumed            BOOLEAN DEFAULT FALSE
);

-- =========================================================================
-- 9. Revoked tokens — token revocation list with TTL-based cleanup
-- =========================================================================

CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_hash          BYTEA PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(tenant_id),
    revoked_at          BIGINT NOT NULL,
    expires_at          BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at
    ON revoked_tokens (expires_at);

-- =========================================================================
-- 10. OAuth codes — secondary OAuth code table for extended flows
-- =========================================================================

CREATE TABLE IF NOT EXISTS oauth_codes (
    code                VARCHAR(255) PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(tenant_id),
    client_id           VARCHAR(255) NOT NULL,
    user_id             UUID NOT NULL,
    redirect_uri        TEXT NOT NULL,
    scope               TEXT,
    code_challenge      TEXT,
    nonce               TEXT,
    expires_at          BIGINT NOT NULL
);

-- =========================================================================
-- 11. Server config — encrypted server-side configuration values
-- =========================================================================

CREATE TABLE IF NOT EXISTS server_config (
    key                 VARCHAR(255) PRIMARY KEY,
    value               BYTEA NOT NULL,
    created_at          BIGINT NOT NULL
);

-- =========================================================================
-- 12. FIDO credentials — WebAuthn / FIDO2 credential store
-- =========================================================================

CREATE TABLE IF NOT EXISTS fido_credentials (
    credential_id       BYTEA PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(tenant_id),
    user_id             UUID NOT NULL,
    public_key          BYTEA NOT NULL,
    sign_count          INTEGER NOT NULL DEFAULT 0,
    authenticator_type  VARCHAR(50) NOT NULL,
    created_at          BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fido_credentials_user_id
    ON fido_credentials (user_id);

-- =========================================================================
-- 13. Key material — encrypted key storage (envelope encryption)
-- =========================================================================

CREATE TABLE IF NOT EXISTS key_material (
    key_name            VARCHAR(255) PRIMARY KEY,
    key_bytes           BYTEA NOT NULL,
    created_at          BIGINT NOT NULL,
    rotated_at          BIGINT
);

-- =========================================================================
-- 14. SHARD sequences — inter-service message sequence tracking
-- =========================================================================

CREATE TABLE IF NOT EXISTS shard_sequences (
    module_pair         VARCHAR(100) PRIMARY KEY,
    sequence            BIGINT NOT NULL DEFAULT 0
);

-- =========================================================================
-- 15. Witness checkpoints — transparency log witness co-signatures
-- =========================================================================

CREATE TABLE IF NOT EXISTS witness_checkpoints (
    sequence            BIGINT PRIMARY KEY,
    audit_root          BYTEA NOT NULL,
    kt_root             BYTEA NOT NULL,
    timestamp           BIGINT NOT NULL,
    signature           BYTEA NOT NULL
);

-- =========================================================================
-- 16. Recovery codes — account recovery backup codes
-- =========================================================================

CREATE TABLE IF NOT EXISTS recovery_codes (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(tenant_id),
    user_id             UUID NOT NULL REFERENCES users(id),
    code_hash           BYTEA NOT NULL,
    code_salt           BYTEA NOT NULL,
    is_used             BOOLEAN NOT NULL DEFAULT false,
    used_at             BIGINT,
    created_at          BIGINT NOT NULL,
    expires_at          BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recovery_codes_user
    ON recovery_codes (user_id) WHERE NOT is_used;

COMMIT;
