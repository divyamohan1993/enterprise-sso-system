//! PostgreSQL persistence layer for the SSO system.
//! Uses sqlx with async PostgreSQL driver.
//! Hardened with statement timeouts, connection pool limits, and health checks.

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Default statement timeout in seconds.
const DEFAULT_STATEMENT_TIMEOUT_SECS: u64 = 30;

/// Default connection acquisition timeout in seconds.
const DEFAULT_ACQUIRE_TIMEOUT_SECS: u64 = 10;

/// Minimum warm connections in the pool.
const MIN_CONNECTIONS: u32 = 2;

/// Maximum connection lifetime (30 minutes).
const MAX_LIFETIME_SECS: u64 = 1800;

/// Idle connection timeout (5 minutes).
const IDLE_TIMEOUT_SECS: u64 = 300;

/// Read the statement timeout from `MILNET_DB_STATEMENT_TIMEOUT_SECS` or use the default.
fn statement_timeout_secs() -> u64 {
    std::env::var("MILNET_DB_STATEMENT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_STATEMENT_TIMEOUT_SECS)
}

/// Validate that `user_ids` is a JSON array of valid UUIDs.
///
/// Returns the parsed UUIDs on success, or a descriptive error message.
pub fn validate_user_ids(ids: &str) -> Result<Vec<uuid::Uuid>, String> {
    let parsed: Vec<String> = serde_json::from_str(ids)
        .map_err(|e| format!("user_ids is not a valid JSON array: {e}"))?;

    let mut uuids = Vec::with_capacity(parsed.len());
    for s in &parsed {
        let u = uuid::Uuid::parse_str(s)
            .map_err(|e| format!("invalid UUID '{}' in user_ids: {e}", s))?;
        uuids.push(u);
    }
    Ok(uuids)
}

/// Initialize the PostgreSQL connection pool with hardened settings.
pub async fn init_database(database_url: &str) -> PgPool {
    let timeout_secs = statement_timeout_secs();

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .min_connections(MIN_CONNECTIONS)
        .acquire_timeout(Duration::from_secs(DEFAULT_ACQUIRE_TIMEOUT_SECS))
        .max_lifetime(Duration::from_secs(MAX_LIFETIME_SECS))
        .idle_timeout(Duration::from_secs(IDLE_TIMEOUT_SECS))
        .test_before_acquire(true)
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                let query = format!("SET statement_timeout = '{}s'", timeout_secs);
                sqlx::Executor::execute(&mut *conn, query.as_str())
                    .await
                    .map_err(|e| {
                        tracing::error!("failed to set statement_timeout: {e}");
                        e
                    })?;

                // Enable audit logging for security compliance.
                // Use .ok() since these may fail if PG doesn't grant SET permission.
                let _ = sqlx::Executor::execute(&mut *conn, "SET log_statement = 'mod'").await.ok();
                let _ = sqlx::Executor::execute(&mut *conn, "SET log_connections = 'on'").await.ok();
                let _ = sqlx::Executor::execute(&mut *conn, "SET log_disconnections = 'on'").await.ok();

                Ok(())
            })
        })
        .connect(database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    // Run migrations
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            opaque_registration BYTEA,
            tier INTEGER NOT NULL DEFAULT 2,
            created_at BIGINT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT true
        )
    "#).execute(&pool).await.expect("Failed to create users table");

    // Migration: add tier column to existing users tables that lack it
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS tier INTEGER NOT NULL DEFAULT 2")
        .execute(&pool)
        .await;

    // Migration: add duress_pin_hash column for duress PIN system
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS duress_pin_hash BYTEA")
        .execute(&pool)
        .await;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS devices (
            id UUID PRIMARY KEY,
            tier INTEGER NOT NULL,
            attestation_hash BYTEA,
            enrolled_by UUID,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create devices table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS portals (
            id UUID PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            callback_url TEXT NOT NULL,
            client_id VARCHAR(255) UNIQUE,
            client_secret BYTEA,
            required_tier INTEGER NOT NULL DEFAULT 2,
            required_scope INTEGER NOT NULL DEFAULT 0,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create portals table");

    // Migration: convert client_secret from VARCHAR to BYTEA for envelope encryption.
    // ALTER TYPE with USING handles existing plaintext values by casting to bytes.
    let _ = sqlx::query(
        "ALTER TABLE portals ALTER COLUMN client_secret TYPE BYTEA USING client_secret::BYTEA"
    ).execute(&pool).await;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS audit_log (
            id UUID PRIMARY KEY,
            event_type VARCHAR(100) NOT NULL,
            user_ids TEXT NOT NULL,
            timestamp BIGINT NOT NULL,
            prev_hash BYTEA,
            signature BYTEA,
            data TEXT
        )
    "#).execute(&pool).await.expect("Failed to create audit_log table");

    // Migration: make user_ids NOT NULL with default empty JSON array for existing rows
    let _ = sqlx::query(
        "UPDATE audit_log SET user_ids = '[]' WHERE user_ids IS NULL"
    ).execute(&pool).await;
    let _ = sqlx::query(
        "ALTER TABLE audit_log ALTER COLUMN user_ids SET NOT NULL"
    ).execute(&pool).await;
    let _ = sqlx::query(
        "ALTER TABLE audit_log ALTER COLUMN user_ids SET DEFAULT '[]'"
    ).execute(&pool).await;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS sessions (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL,
            ratchet_epoch BIGINT NOT NULL DEFAULT 0,
            created_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT true
        )
    "#).execute(&pool).await.expect("Failed to create sessions table");


    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS ratchet_sessions (
            session_id UUID PRIMARY KEY,
            current_epoch BIGINT NOT NULL,
            chain_key_encrypted BYTEA NOT NULL,
            client_entropy BYTEA,
            server_entropy BYTEA,
            created_at BIGINT NOT NULL,
            last_advanced_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create ratchet_sessions table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS authorization_codes (
            code VARCHAR(255) PRIMARY KEY,
            client_id VARCHAR(255) NOT NULL,
            redirect_uri TEXT NOT NULL,
            user_id UUID NOT NULL,
            code_challenge VARCHAR(255),
            tier INTEGER NOT NULL,
            nonce VARCHAR(255),
            created_at BIGINT NOT NULL,
            consumed BOOLEAN DEFAULT FALSE
        )
    "#).execute(&pool).await.expect("Failed to create authorization_codes table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            token_hash BYTEA PRIMARY KEY,
            revoked_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create revoked_tokens table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS oauth_codes (
            code VARCHAR(255) PRIMARY KEY,
            client_id VARCHAR(255) NOT NULL,
            user_id UUID NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT,
            code_challenge TEXT,
            nonce TEXT,
            expires_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create oauth_codes table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS server_config (
            key VARCHAR(255) PRIMARY KEY,
            value BYTEA NOT NULL,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create server_config table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS fido_credentials (
            credential_id BYTEA PRIMARY KEY,
            user_id UUID NOT NULL,
            public_key BYTEA NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            authenticator_type VARCHAR(50) NOT NULL,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create fido_credentials table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS key_material (
            key_name VARCHAR(255) PRIMARY KEY,
            key_bytes BYTEA NOT NULL,
            created_at BIGINT NOT NULL,
            rotated_at BIGINT
        )
    "#).execute(&pool).await.expect("Failed to create key_material table");

    // Migration: add email and auth_provider columns for Google OAuth
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255)")
        .execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(50) NOT NULL DEFAULT 'opaque'")
        .execute(&pool).await;
    let _ = sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (email) WHERE email IS NOT NULL")
        .execute(&pool).await;

    // Migration: add encrypted email column for PII protection at rest
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_encrypted BYTEA")
        .execute(&pool).await;
    // Migration: add email_hash column for lookups without decrypting
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_hash BYTEA")
        .execute(&pool).await;
    let _ = sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS users_email_hash_unique ON users (email_hash) WHERE email_hash IS NOT NULL")
        .execute(&pool).await;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS shard_sequences (
            module_pair VARCHAR(100) PRIMARY KEY,
            sequence BIGINT NOT NULL DEFAULT 0
        )
    "#).execute(&pool).await.expect("Failed to create shard_sequences table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS witness_checkpoints (
            sequence BIGINT PRIMARY KEY,
            audit_root BYTEA NOT NULL,
            kt_root BYTEA NOT NULL,
            timestamp BIGINT NOT NULL,
            signature BYTEA NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create witness_checkpoints table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS recovery_codes (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id),
            code_hash BYTEA NOT NULL,
            code_salt BYTEA NOT NULL,
            is_used BOOLEAN NOT NULL DEFAULT false,
            used_at BIGINT,
            created_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create recovery_codes table");

    sqlx::query(r#"
        CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes (user_id) WHERE NOT is_used
    "#).execute(&pool).await.expect("Failed to create recovery_codes index");

    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_user_ids_valid_array() {
        let ids = r#"["550e8400-e29b-41d4-a716-446655440000","6ba7b810-9dad-11d1-80b4-00c04fd430c8"]"#;
        let result = validate_user_ids(ids).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn validate_user_ids_empty_array() {
        let result = validate_user_ids("[]").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn validate_user_ids_not_json() {
        assert!(validate_user_ids("not-json").is_err());
    }

    #[test]
    fn validate_user_ids_not_array() {
        assert!(validate_user_ids(r#"{"a": 1}"#).is_err());
    }

    #[test]
    fn validate_user_ids_invalid_uuid() {
        assert!(validate_user_ids(r#"["not-a-uuid"]"#).is_err());
    }

    #[test]
    fn validate_user_ids_mixed_valid_invalid() {
        let ids = r#"["550e8400-e29b-41d4-a716-446655440000","garbage"]"#;
        assert!(validate_user_ids(ids).is_err());
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL — set DATABASE_URL"]
    async fn test_db_init_creates_tables() {
        let url = std::env::var("DATABASE_URL").unwrap();
        let pool = init_database(&url).await;
        // Verify tables exist by querying the information_schema
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('users', 'devices', 'portals', 'audit_log', 'sessions', 'oauth_codes', 'fido_credentials')"
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, 7);
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL — set DATABASE_URL"]
    async fn test_db_insert_and_query_user() {
        let url = std::env::var("DATABASE_URL").unwrap();
        let pool = init_database(&url).await;
        let user_id = uuid::Uuid::new_v4();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query("INSERT INTO users (id, username, opaque_registration, created_at) VALUES ($1, $2, $3, $4)")
            .bind(user_id)
            .bind("alice")
            .bind(&[0u8; 32] as &[u8])
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();

        let row: (uuid::Uuid, String) = sqlx::query_as(
            "SELECT id, username FROM users WHERE username = $1"
        )
        .bind("alice")
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(row.0, user_id);
        assert_eq!(row.1, "alice");

        // Clean up
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
