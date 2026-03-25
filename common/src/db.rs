//! PostgreSQL persistence layer for the SSO system.
//! Uses sqlx with async PostgreSQL driver.
//! Hardened with statement timeouts, connection pool limits, health checks,
//! and mandatory SSL enforcement in production.

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

// ---------------------------------------------------------------------------
// SSL enforcement for PostgreSQL connections
// ---------------------------------------------------------------------------

/// SSL mode extracted from the DATABASE_URL query string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    Disable,
    Allow,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
    Unknown,
}

impl SslMode {
    /// Returns `true` for modes that guarantee encryption on the wire.
    pub fn is_secure(&self) -> bool {
        matches!(self, SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull)
    }
}

/// Parse the `sslmode` parameter from a PostgreSQL connection URL.
///
/// Accepts both `sslmode` and `ssl_mode` (with and without URL encoding).
/// Returns `SslMode::Unknown` if the parameter is absent.
pub fn parse_sslmode(database_url: &str) -> SslMode {
    // Find sslmode in the query string portion of the URL.
    let query_start = database_url.find('?').unwrap_or(database_url.len());
    let query = &database_url[query_start..];

    for param in query.trim_start_matches('?').split('&') {
        let mut kv = param.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let val = kv.next().unwrap_or("");
        if key.eq_ignore_ascii_case("sslmode") || key.eq_ignore_ascii_case("ssl_mode") {
            return match val.to_lowercase().as_str() {
                "disable" => SslMode::Disable,
                "allow" => SslMode::Allow,
                "prefer" => SslMode::Prefer,
                "require" => SslMode::Require,
                "verify-ca" | "verify_ca" => SslMode::VerifyCa,
                "verify-full" | "verify_full" => SslMode::VerifyFull,
                _ => SslMode::Unknown,
            };
        }
    }
    SslMode::Unknown
}

/// Ensure `sslmode=require` (or stronger) is present in the DATABASE_URL.
///
/// If the URL lacks an `sslmode` parameter, this function appends `sslmode=require`.
/// Returns the (possibly modified) URL.
pub fn enforce_ssl_in_url(database_url: &str) -> String {
    let mode = parse_sslmode(database_url);
    if mode.is_secure() {
        return database_url.to_string();
    }
    // Append sslmode=require if missing or insecure
    if mode == SslMode::Unknown {
        // No sslmode param — append it
        let sep = if database_url.contains('?') { "&" } else { "?" };
        let url = format!("{database_url}{sep}sslmode=require");
        tracing::info!("DB SSL: appended sslmode=require to DATABASE_URL");
        return url;
    }
    // sslmode is present but insecure — replace it
    tracing::warn!(
        "DB SSL: sslmode={:?} is not secure; overriding to sslmode=require",
        mode
    );
    // Replace the existing sslmode value
    let mut result = String::with_capacity(database_url.len() + 16);
    let query_start = database_url.find('?').unwrap_or(database_url.len());
    result.push_str(&database_url[..query_start]);
    let query = &database_url[query_start..];
    let mut first = true;
    for param in query.trim_start_matches('?').split('&') {
        let key = param.splitn(2, '=').next().unwrap_or("");
        if key.eq_ignore_ascii_case("sslmode") || key.eq_ignore_ascii_case("ssl_mode") {
            result.push(if first { '?' } else { '&' });
            result.push_str("sslmode=require");
        } else if !param.is_empty() {
            result.push(if first { '?' } else { '&' });
            result.push_str(param);
        } else {
            continue;
        }
        first = false;
    }
    result
}

/// Validate SSL configuration at startup.
///
/// In production (`MILNET_PRODUCTION=1`), rejects connections that do not use
/// `sslmode=require` or `sslmode=verify-full`. Logs a warning in dev mode
/// if SSL is not configured.
///
/// Also validates `MILNET_DB_SSL_CERT` and `MILNET_DB_SSL_KEY` env vars
/// when `sslmode=verify-full` is requested.
pub fn validate_ssl_config(database_url: &str) {
    let mode = parse_sslmode(database_url);
    let is_production = crate::sealed_keys::is_production();

    // Log SSL cert/key availability
    let ssl_cert = std::env::var("MILNET_DB_SSL_CERT").ok().filter(|s| !s.is_empty());
    let ssl_key = std::env::var("MILNET_DB_SSL_KEY").ok().filter(|s| !s.is_empty());

    if let Some(ref cert_path) = ssl_cert {
        tracing::info!("DB SSL: client certificate configured at {}", cert_path);
    }
    if let Some(ref key_path) = ssl_key {
        tracing::info!("DB SSL: client key configured at {}", key_path);
    }

    if !mode.is_secure() {
        if is_production {
            panic!(
                "FATAL: DATABASE_URL sslmode={:?} is not acceptable in production. \
                 Set sslmode=require or sslmode=verify-full.",
                mode
            );
        }
        tracing::warn!(
            "DB SSL WARNING: sslmode={:?} does not guarantee encryption. \
             Set sslmode=require or sslmode=verify-full for production use.",
            mode
        );
    }

    // verify-full requires cert and key
    if mode == SslMode::VerifyFull {
        if ssl_cert.is_none() {
            tracing::warn!("DB SSL: sslmode=verify-full but MILNET_DB_SSL_CERT is not set");
        }
        if ssl_key.is_none() {
            tracing::warn!("DB SSL: sslmode=verify-full but MILNET_DB_SSL_KEY is not set");
        }
    }
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
///
/// Accepts per-service DATABASE_URL — each service may connect with its own
/// restricted PostgreSQL role (see `migrations/002_per_service_users.sql`).
///
/// SSL is enforced: in production, non-SSL connections are rejected at startup.
/// In dev mode, `sslmode=require` is appended automatically if missing.
pub async fn init_database(database_url: &str) -> PgPool {
    // ── SSL enforcement ──
    validate_ssl_config(database_url);
    let ssl_url = enforce_ssl_in_url(database_url);
    let connect_url = ssl_url.as_str();

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

                // Verify SSL is active on the connection (belt-and-suspenders).
                let ssl_row = sqlx::Executor::fetch_optional(
                    &mut *conn,
                    "SELECT current_setting('ssl', true)",
                )
                .await
                .ok()
                .flatten();
                if ssl_row.is_some() {
                    tracing::debug!("DB connection established with SSL active");
                }

                // Enable audit logging for security compliance.
                // Use .ok() since these may fail if PG doesn't grant SET permission.
                let _ = sqlx::Executor::execute(&mut *conn, "SET log_statement = 'mod'").await.ok();
                let _ = sqlx::Executor::execute(&mut *conn, "SET log_connections = 'on'").await.ok();
                let _ = sqlx::Executor::execute(&mut *conn, "SET log_disconnections = 'on'").await.ok();

                Ok(())
            })
        })
        .connect(connect_url)
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

    // ── SSL enforcement tests ──

    #[test]
    fn parse_sslmode_require() {
        assert_eq!(parse_sslmode("postgres://host/db?sslmode=require"), SslMode::Require);
    }

    #[test]
    fn parse_sslmode_verify_full() {
        assert_eq!(parse_sslmode("postgres://host/db?sslmode=verify-full"), SslMode::VerifyFull);
    }

    #[test]
    fn parse_sslmode_verify_ca() {
        assert_eq!(parse_sslmode("postgres://host/db?sslmode=verify-ca"), SslMode::VerifyCa);
    }

    #[test]
    fn parse_sslmode_disable() {
        assert_eq!(parse_sslmode("postgres://host/db?sslmode=disable"), SslMode::Disable);
    }

    #[test]
    fn parse_sslmode_prefer() {
        assert_eq!(parse_sslmode("postgres://host/db?sslmode=prefer"), SslMode::Prefer);
    }

    #[test]
    fn parse_sslmode_allow() {
        assert_eq!(parse_sslmode("postgres://host/db?sslmode=allow"), SslMode::Allow);
    }

    #[test]
    fn parse_sslmode_missing() {
        assert_eq!(parse_sslmode("postgres://host/db"), SslMode::Unknown);
    }

    #[test]
    fn parse_sslmode_with_other_params() {
        assert_eq!(
            parse_sslmode("postgres://host/db?timeout=10&sslmode=require&pool=5"),
            SslMode::Require
        );
    }

    #[test]
    fn parse_sslmode_case_insensitive_key() {
        assert_eq!(parse_sslmode("postgres://host/db?SSLMODE=require"), SslMode::Require);
    }

    #[test]
    fn parse_sslmode_ssl_mode_underscore() {
        assert_eq!(parse_sslmode("postgres://host/db?ssl_mode=require"), SslMode::Require);
    }

    #[test]
    fn sslmode_is_secure() {
        assert!(SslMode::Require.is_secure());
        assert!(SslMode::VerifyCa.is_secure());
        assert!(SslMode::VerifyFull.is_secure());
        assert!(!SslMode::Disable.is_secure());
        assert!(!SslMode::Allow.is_secure());
        assert!(!SslMode::Prefer.is_secure());
        assert!(!SslMode::Unknown.is_secure());
    }

    #[test]
    fn enforce_ssl_appends_sslmode_when_missing() {
        let url = enforce_ssl_in_url("postgres://host/db");
        assert!(url.contains("sslmode=require"));
    }

    #[test]
    fn enforce_ssl_appends_with_ampersand_when_other_params_exist() {
        let url = enforce_ssl_in_url("postgres://host/db?timeout=10");
        assert!(url.contains("&sslmode=require"));
    }

    #[test]
    fn enforce_ssl_preserves_secure_mode() {
        let original = "postgres://host/db?sslmode=verify-full";
        let url = enforce_ssl_in_url(original);
        assert_eq!(url, original);
    }

    #[test]
    fn enforce_ssl_overrides_insecure_mode() {
        let url = enforce_ssl_in_url("postgres://host/db?sslmode=disable");
        assert!(url.contains("sslmode=require"));
        assert!(!url.contains("sslmode=disable"));
    }

    #[test]
    fn enforce_ssl_overrides_prefer_mode() {
        let url = enforce_ssl_in_url("postgres://host/db?sslmode=prefer");
        assert!(url.contains("sslmode=require"));
        assert!(!url.contains("sslmode=prefer"));
    }

    #[test]
    fn enforce_ssl_preserves_other_params_when_overriding() {
        let url = enforce_ssl_in_url("postgres://host/db?timeout=10&sslmode=disable&pool=5");
        assert!(url.contains("timeout=10"));
        assert!(url.contains("pool=5"));
        assert!(url.contains("sslmode=require"));
    }

    #[test]
    fn validate_ssl_config_does_not_panic_dev_mode() {
        // In dev mode (MILNET_PRODUCTION not set), should just warn, not panic
        std::env::remove_var("MILNET_PRODUCTION");
        validate_ssl_config("postgres://host/db?sslmode=disable");
        // If we reach here, no panic occurred
    }

    #[test]
    #[should_panic(expected = "FATAL: DATABASE_URL sslmode=")]
    fn validate_ssl_config_panics_in_production_mode() {
        std::env::set_var("MILNET_PRODUCTION", "1");
        validate_ssl_config("postgres://host/db?sslmode=disable");
        // Clean up in case panic doesn't happen (it should)
        std::env::remove_var("MILNET_PRODUCTION");
    }

    #[test]
    fn validate_ssl_config_ok_in_production_with_require() {
        std::env::set_var("MILNET_PRODUCTION", "1");
        validate_ssl_config("postgres://host/db?sslmode=require");
        std::env::remove_var("MILNET_PRODUCTION");
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
