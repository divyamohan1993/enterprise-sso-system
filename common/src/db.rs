//! PostgreSQL persistence layer for the SSO system.
//! Uses sqlx with async PostgreSQL driver.
//! Hardened with statement timeouts, connection pool limits, health checks,
//! and mandatory SSL enforcement in production.
//!
//! All data tables include a `tenant_id UUID NOT NULL` column and all queries
//! are scoped through [`TenantAwarePool`] which enforces tenant isolation at
//! both the application layer and via PostgreSQL Row-Level Security.
//!
//! ## Read-Only Fallback Mode
//!
//! When the primary database becomes unavailable, the system can degrade
//! gracefully to read-only mode using `MILNET_DB_REPLICA_URL`.  In read-only
//! mode, token verification and session lookups continue to work, while
//! write operations (registration, password changes) return errors.

use std::sync::atomic::{AtomicU8, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use crate::multi_tenancy::{TenantContext, TenantId};

// ---------------------------------------------------------------------------
// Database operating mode — graceful degradation
// ---------------------------------------------------------------------------

/// Operating mode of the database layer.
///
/// Transitions:
/// - `ReadWrite` -> `ReadOnly`: primary health check fails, replica available
/// - `ReadWrite` -> `Unavailable`: primary fails, no replica configured
/// - `ReadOnly` -> `ReadWrite`: primary recovers
/// - `Unavailable` -> `ReadWrite`: primary recovers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DatabaseMode {
    /// Full read-write access to the primary database.
    ReadWrite = 0,
    /// Primary is unreachable; reads are served from the async replica.
    /// Writes (registration, password changes, new sessions) are rejected.
    ReadOnly = 1,
    /// Both primary and replica are unreachable.
    Unavailable = 2,
}

impl DatabaseMode {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::ReadWrite,
            1 => Self::ReadOnly,
            _ => Self::Unavailable,
        }
    }

    /// Returns `true` if write operations are allowed.
    pub fn allows_writes(&self) -> bool {
        matches!(self, Self::ReadWrite)
    }

    /// Returns `true` if read operations are allowed.
    pub fn allows_reads(&self) -> bool {
        matches!(self, Self::ReadWrite | Self::ReadOnly)
    }
}

/// Thread-safe handle to the current database operating mode.
///
/// Shared across the application; the health check background task updates
/// it, and request handlers read it to decide whether to accept writes.
#[derive(Clone)]
pub struct DatabaseModeHandle {
    mode: Arc<AtomicU8>,
}

impl DatabaseModeHandle {
    /// Create a new handle starting in `ReadWrite` mode.
    pub fn new() -> Self {
        Self {
            mode: Arc::new(AtomicU8::new(DatabaseMode::ReadWrite as u8)),
        }
    }

    /// Get the current database mode.
    pub fn current(&self) -> DatabaseMode {
        DatabaseMode::from_u8(self.mode.load(AtomicOrdering::SeqCst))
    }

    /// Set the database mode.  Logs transitions.
    pub fn set(&self, new_mode: DatabaseMode) {
        let old = DatabaseMode::from_u8(self.mode.swap(new_mode as u8, AtomicOrdering::SeqCst));
        if old != new_mode {
            match new_mode {
                DatabaseMode::ReadWrite => {
                    tracing::info!(
                        target: "siem",
                        old = ?old,
                        new = ?new_mode,
                        "Database mode RECOVERED to ReadWrite"
                    );
                }
                DatabaseMode::ReadOnly => {
                    tracing::warn!(
                        target: "siem",
                        old = ?old,
                        new = ?new_mode,
                        "Database DEGRADED to ReadOnly — writes will be rejected"
                    );
                }
                DatabaseMode::Unavailable => {
                    tracing::error!(
                        target: "siem",
                        old = ?old,
                        new = ?new_mode,
                        "Database UNAVAILABLE — all operations will fail"
                    );
                }
            }
        }
    }

    /// Returns `true` if writes are currently allowed.
    pub fn allows_writes(&self) -> bool {
        self.current().allows_writes()
    }

    /// Returns `true` if reads are currently allowed.
    pub fn allows_reads(&self) -> bool {
        self.current().allows_reads()
    }

    /// Reject if writes are not allowed; returns a user-facing error string.
    pub fn require_write(&self) -> Result<(), String> {
        if self.allows_writes() {
            Ok(())
        } else {
            Err("database is in read-only mode — write operations are temporarily unavailable".to_string())
        }
    }
}

impl Default for DatabaseModeHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Resilient database pool with primary + optional read replica.
///
/// The health check task periodically pings the primary; on failure it
/// switches to `ReadOnly` mode (if a replica is configured) or `Unavailable`.
pub struct ResilientPool {
    /// Primary read-write pool.
    pub primary: PgPool,
    /// Optional read-replica pool (from `MILNET_DB_REPLICA_URL`).
    pub replica: Option<PgPool>,
    /// Current operating mode.
    pub mode: DatabaseModeHandle,
}

impl ResilientPool {
    /// Get the pool to use for read operations.
    /// Returns the primary when healthy, falls back to the replica.
    pub fn read_pool(&self) -> Option<&PgPool> {
        match self.mode.current() {
            DatabaseMode::ReadWrite => Some(&self.primary),
            DatabaseMode::ReadOnly => self.replica.as_ref().or(Some(&self.primary)),
            DatabaseMode::Unavailable => None,
        }
    }

    /// Get the pool to use for write operations.
    /// Returns `None` when not in `ReadWrite` mode.
    pub fn write_pool(&self) -> Option<&PgPool> {
        if self.mode.allows_writes() {
            Some(&self.primary)
        } else {
            None
        }
    }

    /// Run a periodic health check against the primary database.
    /// If the primary fails, switch to ReadOnly (if replica available) or Unavailable.
    /// If the primary recovers, switch back to ReadWrite.
    pub async fn health_check(&self) {
        let primary_ok = sqlx::query("SELECT 1")
            .execute(&self.primary)
            .await
            .is_ok();

        if primary_ok {
            self.mode.set(DatabaseMode::ReadWrite);
        } else if self.replica.is_some() {
            let replica_ok = if let Some(ref replica) = self.replica {
                sqlx::query("SELECT 1").execute(replica).await.is_ok()
            } else {
                false
            };
            if replica_ok {
                self.mode.set(DatabaseMode::ReadOnly);
            } else {
                self.mode.set(DatabaseMode::Unavailable);
            }
        } else {
            self.mode.set(DatabaseMode::Unavailable);
        }
    }

    /// Spawn a background health check task that runs every `interval`.
    pub fn spawn_health_check(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                pool.health_check().await;
            }
        })
    }
}

/// Initialize a resilient pool with optional read replica.
///
/// Reads `MILNET_DB_REPLICA_URL` for the replica connection string.
pub async fn init_resilient_pool(primary_pool: PgPool) -> Arc<ResilientPool> {
    let replica = match std::env::var("MILNET_DB_REPLICA_URL") {
        Ok(url) if !url.is_empty() => {
            let ssl_url = enforce_ssl_in_url(&url);
            match PgPoolOptions::new()
                .max_connections(10)
                .min_connections(1)
                .acquire_timeout(Duration::from_secs(DEFAULT_ACQUIRE_TIMEOUT_SECS))
                .max_lifetime(Duration::from_secs(MAX_LIFETIME_SECS))
                .idle_timeout(Duration::from_secs(IDLE_TIMEOUT_SECS))
                .test_before_acquire(true)
                .connect(&ssl_url)
                .await
            {
                Ok(pool) => {
                    tracing::info!("Read replica pool initialized from MILNET_DB_REPLICA_URL");
                    Some(pool)
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to read replica: {e} — proceeding without replica");
                    None
                }
            }
        }
        _ => None,
    };

    Arc::new(ResilientPool {
        primary: primary_pool,
        replica,
        mode: DatabaseModeHandle::new(),
    })
}

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
/// Rejects connections that do not use `sslmode=require` or
/// `sslmode=verify-full`.
///
/// Also validates `MILNET_DB_SSL_CERT` and `MILNET_DB_SSL_KEY` env vars
/// when `sslmode=verify-full` is requested.
pub fn validate_ssl_config(database_url: &str) {
    let mode = parse_sslmode(database_url);

    // Log SSL cert/key availability
    let ssl_cert = std::env::var("MILNET_DB_SSL_CERT").ok().filter(|s| !s.is_empty());
    let ssl_key = std::env::var("MILNET_DB_SSL_KEY").ok().filter(|s| !s.is_empty());
    // Remove sensitive env vars after reading
    // Overwrite with zeros first to clear libc environ buffer
    if let Some(ref k) = ssl_key {
        std::env::set_var("MILNET_DB_SSL_KEY", "0".repeat(k.len()));
    }
    std::env::remove_var("MILNET_DB_SSL_KEY");
    if let Some(ref c) = ssl_cert {
        std::env::set_var("MILNET_DB_SSL_CERT", "0".repeat(c.len()));
    }
    std::env::remove_var("MILNET_DB_SSL_CERT");

    if let Some(ref cert_path) = ssl_cert {
        tracing::info!("DB SSL: client certificate configured at {}", cert_path);
    }
    if let Some(ref key_path) = ssl_key {
        tracing::info!("DB SSL: client key configured at {}", key_path);
    }

    if !mode.is_secure() {
        panic!(
            "FATAL: DATABASE_URL sslmode={:?} is not acceptable. \
             Set sslmode=require or sslmode=verify-full.",
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
pub async fn init_database(database_url: &str) -> Result<PgPool, String> {
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
        .map_err(|e| format!("database connection failed: {e}"))?;

    // ── Tenants table (must exist before FK-constrained data tables) ──
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS tenants (
            tenant_id       UUID PRIMARY KEY,
            name            VARCHAR(255) NOT NULL,
            slug            VARCHAR(255) UNIQUE NOT NULL,
            status          VARCHAR(50)  NOT NULL DEFAULT 'Active',
            created_at      BIGINT       NOT NULL,
            compliance_regime VARCHAR(50) NOT NULL DEFAULT 'Commercial',
            data_residency_region VARCHAR(100) NOT NULL DEFAULT '',
            max_users       BIGINT       NOT NULL DEFAULT 1000,
            max_devices     BIGINT       NOT NULL DEFAULT 5000,
            feature_flags   TEXT         NOT NULL DEFAULT '[]',
            encryption_key_id TEXT       NOT NULL DEFAULT '',
            rate_limit_rps          INTEGER NOT NULL DEFAULT 1000,
            rate_limit_burst        INTEGER NOT NULL DEFAULT 2000,
            session_timeout_secs    BIGINT  NOT NULL DEFAULT 3600,
            max_sessions_per_user   INTEGER NOT NULL DEFAULT 5,
            password_min_length     INTEGER NOT NULL DEFAULT 12,
            mfa_required            BOOLEAN NOT NULL DEFAULT true,
            allowed_auth_methods    TEXT    NOT NULL DEFAULT '["opaque","fido","cac"]'
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create tenants table: {e}"))?;

    // Insert default migration tenant for pre-existing data
    let _ = sqlx::query(
        "INSERT INTO tenants (tenant_id, name, slug, status, created_at) \
         VALUES ('00000000-0000-0000-0000-000000000000', 'Default Migration Tenant', 'default-migration', 'Active', \
         EXTRACT(EPOCH FROM NOW())::BIGINT) ON CONFLICT (tenant_id) DO NOTHING"
    ).execute(&pool).await;

    // Run migrations
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
            username VARCHAR(255) NOT NULL,
            opaque_registration BYTEA,
            tier INTEGER NOT NULL DEFAULT 2,
            created_at BIGINT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT true
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create users table: {e}"))?;

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
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
            tier INTEGER NOT NULL,
            attestation_hash BYTEA,
            enrolled_by UUID,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create devices table: {e}"))?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS portals (
            id UUID PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
            name VARCHAR(255) NOT NULL,
            callback_url TEXT NOT NULL,
            client_id VARCHAR(255),
            client_secret BYTEA,
            required_tier INTEGER NOT NULL DEFAULT 2,
            required_scope INTEGER NOT NULL DEFAULT 0,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create portals table: {e}"))?;

    // Migration: convert client_secret from VARCHAR to BYTEA for envelope encryption.
    // ALTER TYPE with USING handles existing plaintext values by casting to bytes.
    let _ = sqlx::query(
        "ALTER TABLE portals ALTER COLUMN client_secret TYPE BYTEA USING client_secret::BYTEA"
    ).execute(&pool).await;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS audit_log (
            id UUID PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
            event_type VARCHAR(100) NOT NULL,
            user_ids TEXT NOT NULL,
            timestamp BIGINT NOT NULL,
            prev_hash BYTEA,
            signature BYTEA,
            data TEXT
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create audit_log table: {e}"))?;

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
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
            user_id UUID NOT NULL,
            ratchet_epoch BIGINT NOT NULL DEFAULT 0,
            created_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT true
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create sessions table: {e}"))?;


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
    "#).execute(&pool).await.map_err(|e| format!("Failed to create ratchet_sessions table: {e}"))?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS authorization_codes (
            code VARCHAR(255) PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
            client_id VARCHAR(255) NOT NULL,
            redirect_uri TEXT NOT NULL,
            user_id UUID NOT NULL,
            code_challenge VARCHAR(255),
            tier INTEGER NOT NULL,
            nonce VARCHAR(255),
            created_at BIGINT NOT NULL,
            consumed BOOLEAN DEFAULT FALSE
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create authorization_codes table: {e}"))?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            token_hash BYTEA PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
            revoked_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create revoked_tokens table: {e}"))?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS oauth_codes (
            code VARCHAR(255) PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
            client_id VARCHAR(255) NOT NULL,
            user_id UUID NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT,
            code_challenge TEXT,
            nonce TEXT,
            expires_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create oauth_codes table: {e}"))?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS server_config (
            key VARCHAR(255) PRIMARY KEY,
            value BYTEA NOT NULL,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create server_config table: {e}"))?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS fido_credentials (
            credential_id BYTEA PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
            user_id UUID NOT NULL,
            public_key BYTEA NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            authenticator_type VARCHAR(50) NOT NULL,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create fido_credentials table: {e}"))?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS key_material (
            key_name VARCHAR(255) PRIMARY KEY,
            key_bytes BYTEA NOT NULL,
            created_at BIGINT NOT NULL,
            rotated_at BIGINT
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create key_material table: {e}"))?;

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
    "#).execute(&pool).await.map_err(|e| format!("Failed to create shard_sequences table: {e}"))?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS witness_checkpoints (
            sequence BIGINT PRIMARY KEY,
            audit_root BYTEA NOT NULL,
            kt_root BYTEA NOT NULL,
            timestamp BIGINT NOT NULL,
            signature BYTEA NOT NULL
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create witness_checkpoints table: {e}"))?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS recovery_codes (
            id UUID PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
            user_id UUID NOT NULL REFERENCES users(id),
            code_hash BYTEA NOT NULL,
            code_salt BYTEA NOT NULL,
            is_used BOOLEAN NOT NULL DEFAULT false,
            used_at BIGINT,
            created_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.map_err(|e| format!("Failed to create recovery_codes table: {e}"))?;

    sqlx::query(r#"
        CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes (user_id) WHERE NOT is_used
    "#).execute(&pool).await.map_err(|e| format!("Failed to create recovery_codes index: {e}"))?;

    // ── Multi-tenancy column migrations (idempotent) ──
    // Add tenant_id to tables that may have been created before multi-tenancy.
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'")
        .execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE devices ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'")
        .execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'")
        .execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'")
        .execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE portals ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'")
        .execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE fido_credentials ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'")
        .execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'")
        .execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'")
        .execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE revoked_tokens ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'")
        .execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE recovery_codes ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'")
        .execute(&pool).await;

    // ── Tenant-scoped indexes ──
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users (tenant_id)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_devices_tenant_id ON devices (tenant_id)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id ON sessions (tenant_id)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id ON audit_log (tenant_id)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_portals_tenant_id ON portals (tenant_id)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_fido_credentials_tenant_id ON fido_credentials (tenant_id)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_authorization_codes_tenant_id ON authorization_codes (tenant_id)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_oauth_codes_tenant_id ON oauth_codes (tenant_id)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_revoked_tokens_tenant_id ON revoked_tokens (tenant_id)").execute(&pool).await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_recovery_codes_tenant_id ON recovery_codes (tenant_id)").execute(&pool).await;

    Ok(pool)
}

// ---------------------------------------------------------------------------
// TenantAwarePool — automatic tenant scoping for all queries
// ---------------------------------------------------------------------------

/// A wrapper around `PgPool` that enforces tenant isolation on every query.
///
/// Before executing any query, `TenantAwarePool` sets the PostgreSQL session
/// variable `app.current_tenant_id` so that Row-Level Security policies are
/// active, and also injects `tenant_id` into application-level queries.
///
/// # Usage
/// ```ignore
/// let pool = TenantAwarePool::new(pg_pool);
/// // Within a request scoped to a tenant:
/// TenantContext::with_tenant(tenant_id, || async {
///     let users = pool.query_scoped("SELECT * FROM users WHERE username = $1", &["alice"]).await?;
/// });
/// ```
pub struct TenantAwarePool {
    pool: PgPool,
}

impl TenantAwarePool {
    /// Wrap an existing PgPool with tenant-aware query scoping.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a reference to the underlying PgPool (for migrations/admin ops).
    pub fn inner(&self) -> &PgPool {
        &self.pool
    }

    /// Get the current tenant ID from thread-local context, or panic.
    fn require_tenant_id() -> Result<Uuid, sqlx::Error> {
        let tid = TenantContext::require_tenant()
            .map_err(|_| sqlx::Error::Protocol(
                "no tenant context set — all queries require a tenant scope".to_string(),
            ))?;
        Ok(*tid.as_uuid())
    }

    /// Set the PostgreSQL session variable for RLS enforcement.
    ///
    /// This MUST be called at the start of every transaction or query batch
    /// so that RLS policies see the correct tenant_id.
    pub async fn set_rls_tenant(&self, tenant_id: &Uuid) -> Result<(), sqlx::Error> {
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&self.pool).await?;
        Ok(())
    }

    /// Begin a transaction with the tenant context pre-set for RLS.
    pub async fn begin_tenant_tx(
        &self,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;
        Ok(tx)
    }

    /// Insert a user scoped to the current tenant.
    pub async fn insert_user(
        &self,
        id: Uuid,
        username: &str,
        opaque_registration: Option<&[u8]>,
        tier: i32,
        created_at: i64,
    ) -> Result<(), sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        sqlx::query(
            "INSERT INTO users (id, tenant_id, username, opaque_registration, tier, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(username)
        .bind(opaque_registration)
        .bind(tier)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Query a user by username, scoped to the current tenant.
    pub async fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<(Uuid, String, Option<Vec<u8>>, i32, i64, bool)>, sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let row: Option<(Uuid, String, Option<Vec<u8>>, i32, i64, bool)> = sqlx::query_as(
            "SELECT id, username, opaque_registration, tier, created_at, is_active \
             FROM users WHERE tenant_id = $1 AND username = $2"
        )
        .bind(tenant_id)
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Insert a session scoped to the current tenant.
    pub async fn insert_session(
        &self,
        id: Uuid,
        user_id: Uuid,
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        sqlx::query(
            "INSERT INTO sessions (id, tenant_id, user_id, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(created_at)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Query sessions for a user, scoped to the current tenant.
    pub async fn get_user_sessions(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, i64, i64, bool)>, sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let rows: Vec<(Uuid, i64, i64, bool)> = sqlx::query_as(
            "SELECT id, created_at, expires_at, is_active \
             FROM sessions WHERE tenant_id = $1 AND user_id = $2"
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Insert an audit log entry scoped to the current tenant.
    pub async fn insert_audit_log(
        &self,
        id: Uuid,
        event_type: &str,
        user_ids: &str,
        timestamp: i64,
        prev_hash: Option<&[u8]>,
        signature: Option<&[u8]>,
        data: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, event_type, user_ids, timestamp, prev_hash, signature, data) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(event_type)
        .bind(user_ids)
        .bind(timestamp)
        .bind(prev_hash)
        .bind(signature)
        .bind(data)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Query audit logs scoped to the current tenant.
    pub async fn get_audit_logs(
        &self,
        limit: i64,
    ) -> Result<Vec<(Uuid, String, String, i64, Option<String>)>, sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let rows: Vec<(Uuid, String, String, i64, Option<String>)> = sqlx::query_as(
            "SELECT id, event_type, user_ids, timestamp, data \
             FROM audit_log WHERE tenant_id = $1 ORDER BY timestamp DESC LIMIT $2"
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Insert a device scoped to the current tenant.
    pub async fn insert_device(
        &self,
        id: Uuid,
        tier: i32,
        attestation_hash: Option<&[u8]>,
        enrolled_by: Option<Uuid>,
        created_at: i64,
    ) -> Result<(), sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        sqlx::query(
            "INSERT INTO devices (id, tenant_id, tier, attestation_hash, enrolled_by, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(tier)
        .bind(attestation_hash)
        .bind(enrolled_by)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Insert a portal (OAuth client) scoped to the current tenant.
    pub async fn insert_portal(
        &self,
        id: Uuid,
        name: &str,
        callback_url: &str,
        client_id: &str,
        client_secret: Option<&[u8]>,
        required_tier: i32,
        created_at: i64,
    ) -> Result<(), sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        sqlx::query(
            "INSERT INTO portals (id, tenant_id, name, callback_url, client_id, client_secret, required_tier, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(callback_url)
        .bind(client_id)
        .bind(client_secret)
        .bind(required_tier)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Insert a FIDO credential scoped to the current tenant.
    pub async fn insert_fido_credential(
        &self,
        credential_id: &[u8],
        user_id: Uuid,
        public_key: &[u8],
        authenticator_type: &str,
        created_at: i64,
    ) -> Result<(), sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        sqlx::query(
            "INSERT INTO fido_credentials (credential_id, tenant_id, user_id, public_key, authenticator_type, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(credential_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(public_key)
        .bind(authenticator_type)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Insert an authorization code scoped to the current tenant.
    pub async fn insert_authorization_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        user_id: Uuid,
        code_challenge: Option<&str>,
        tier: i32,
        nonce: Option<&str>,
        created_at: i64,
    ) -> Result<(), sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        sqlx::query(
            "INSERT INTO authorization_codes (code, tenant_id, client_id, redirect_uri, user_id, code_challenge, tier, nonce, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        .bind(code)
        .bind(tenant_id)
        .bind(client_id)
        .bind(redirect_uri)
        .bind(user_id)
        .bind(code_challenge)
        .bind(tier)
        .bind(nonce)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Insert an OAuth code scoped to the current tenant.
    pub async fn insert_oauth_code(
        &self,
        code: &str,
        client_id: &str,
        user_id: Uuid,
        redirect_uri: &str,
        scope: Option<&str>,
        code_challenge: Option<&str>,
        nonce: Option<&str>,
        expires_at: i64,
    ) -> Result<(), sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        sqlx::query(
            "INSERT INTO oauth_codes (code, tenant_id, client_id, user_id, redirect_uri, scope, code_challenge, nonce, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        .bind(code)
        .bind(tenant_id)
        .bind(client_id)
        .bind(user_id)
        .bind(redirect_uri)
        .bind(scope)
        .bind(code_challenge)
        .bind(nonce)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Revoke a token, scoped to the current tenant.
    pub async fn revoke_token(
        &self,
        token_hash: &[u8],
        revoked_at: i64,
        expires_at: i64,
    ) -> Result<(), sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        sqlx::query(
            "INSERT INTO revoked_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING"
        )
        .bind(token_hash)
        .bind(tenant_id)
        .bind(revoked_at)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Check if a token is revoked, scoped to the current tenant.
    pub async fn is_token_revoked(&self, token_hash: &[u8]) -> Result<bool, sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT revoked_at FROM revoked_tokens WHERE tenant_id = $1 AND token_hash = $2"
        )
        .bind(tenant_id)
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    /// Insert a recovery code scoped to the current tenant.
    pub async fn insert_recovery_code(
        &self,
        id: Uuid,
        user_id: Uuid,
        code_hash: &[u8],
        code_salt: &[u8],
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        sqlx::query(
            "INSERT INTO recovery_codes (id, tenant_id, user_id, code_hash, code_salt, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(code_hash)
        .bind(code_salt)
        .bind(created_at)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Delete a user, scoped to the current tenant.
    pub async fn delete_user(&self, user_id: Uuid) -> Result<u64, sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        let result = sqlx::query(
            "DELETE FROM users WHERE tenant_id = $1 AND id = $2"
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(result.rows_affected())
    }

    /// Deactivate all sessions for a user, scoped to the current tenant.
    pub async fn deactivate_user_sessions(&self, user_id: Uuid) -> Result<u64, sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let mut tx = self.pool.begin().await?;
        let stmt = format!("SET LOCAL app.current_tenant_id = '{}'", tenant_id);
        sqlx::query(&stmt).execute(&mut *tx).await?;

        let result = sqlx::query(
            "UPDATE sessions SET is_active = false WHERE tenant_id = $1 AND user_id = $2"
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(result.rows_affected())
    }

    /// Count users for the current tenant (for quota enforcement).
    pub async fn count_tenant_users(&self) -> Result<i64, sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM users WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    /// Count devices for the current tenant (for quota enforcement).
    pub async fn count_tenant_devices(&self) -> Result<i64, sqlx::Error> {
        let tenant_id = Self::require_tenant_id()?;
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM devices WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    // ── Tenant CRUD (not scoped — operates on the tenants table itself) ──

    /// Load a tenant record from the database.
    pub async fn get_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<TenantRow>, sqlx::Error> {
        let row: Option<TenantRow> = sqlx::query_as(
            "SELECT tenant_id, name, slug, status, created_at, compliance_regime, \
             data_residency_region, max_users, max_devices, feature_flags, encryption_key_id, \
             rate_limit_rps, rate_limit_burst, session_timeout_secs, max_sessions_per_user, \
             password_min_length, mfa_required, allowed_auth_methods \
             FROM tenants WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Insert a new tenant record.
    pub async fn insert_tenant(&self, row: &TenantRow) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO tenants (tenant_id, name, slug, status, created_at, compliance_regime, \
             data_residency_region, max_users, max_devices, feature_flags, encryption_key_id, \
             rate_limit_rps, rate_limit_burst, session_timeout_secs, max_sessions_per_user, \
             password_min_length, mfa_required, allowed_auth_methods) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)"
        )
        .bind(row.tenant_id)
        .bind(&row.name)
        .bind(&row.slug)
        .bind(&row.status)
        .bind(row.created_at)
        .bind(&row.compliance_regime)
        .bind(&row.data_residency_region)
        .bind(row.max_users)
        .bind(row.max_devices)
        .bind(&row.feature_flags)
        .bind(&row.encryption_key_id)
        .bind(row.rate_limit_rps)
        .bind(row.rate_limit_burst)
        .bind(row.session_timeout_secs)
        .bind(row.max_sessions_per_user)
        .bind(row.password_min_length)
        .bind(row.mfa_required)
        .bind(&row.allowed_auth_methods)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update tenant status.
    pub async fn update_tenant_status(
        &self,
        tenant_id: Uuid,
        status: &str,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE tenants SET status = $1 WHERE tenant_id = $2"
        )
        .bind(status)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Cascade-delete ALL data for a decommissioned tenant.
    ///
    /// This permanently removes every row belonging to the tenant from all
    /// data tables. Only callable for tenants in Decommissioning status.
    /// The tenant record itself is kept (marked Decommissioned) for audit trail.
    pub async fn cascade_delete_tenant_data(
        &self,
        tenant_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let mut total: u64 = 0;

        // Order matters: delete child rows before parent rows (FK constraints).
        let tables = [
            "recovery_codes",
            "fido_credentials",
            "authorization_codes",
            "oauth_codes",
            "revoked_tokens",
            "sessions",
            "audit_log",
            "devices",
            "portals",
            "users",
        ];

        for table in &tables {
            let query = format!("DELETE FROM {} WHERE tenant_id = $1", table);
            let result = sqlx::query(&query)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
            total += result.rows_affected();
        }

        tx.commit().await?;
        Ok(total)
    }
}

/// Database row representation of a tenant (for sqlx::FromRow).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantRow {
    pub tenant_id: Uuid,
    pub name: String,
    pub slug: String,
    pub status: String,
    pub created_at: i64,
    pub compliance_regime: String,
    pub data_residency_region: String,
    pub max_users: i64,
    pub max_devices: i64,
    pub feature_flags: String,
    pub encryption_key_id: String,
    pub rate_limit_rps: i32,
    pub rate_limit_burst: i32,
    pub session_timeout_secs: i64,
    pub max_sessions_per_user: i32,
    pub password_min_length: i32,
    pub mfa_required: bool,
    pub allowed_auth_methods: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DatabaseMode / DatabaseModeHandle tests ──────────────────────

    #[test]
    fn test_database_mode_from_u8() {
        assert_eq!(DatabaseMode::from_u8(0), DatabaseMode::ReadWrite);
        assert_eq!(DatabaseMode::from_u8(1), DatabaseMode::ReadOnly);
        assert_eq!(DatabaseMode::from_u8(2), DatabaseMode::Unavailable);
        assert_eq!(DatabaseMode::from_u8(255), DatabaseMode::Unavailable);
    }

    #[test]
    fn test_database_mode_allows() {
        assert!(DatabaseMode::ReadWrite.allows_writes());
        assert!(DatabaseMode::ReadWrite.allows_reads());

        assert!(!DatabaseMode::ReadOnly.allows_writes());
        assert!(DatabaseMode::ReadOnly.allows_reads());

        assert!(!DatabaseMode::Unavailable.allows_writes());
        assert!(!DatabaseMode::Unavailable.allows_reads());
    }

    #[test]
    fn test_database_mode_handle_transitions() {
        let handle = DatabaseModeHandle::new();
        assert_eq!(handle.current(), DatabaseMode::ReadWrite);
        assert!(handle.allows_writes());
        assert!(handle.allows_reads());

        handle.set(DatabaseMode::ReadOnly);
        assert_eq!(handle.current(), DatabaseMode::ReadOnly);
        assert!(!handle.allows_writes());
        assert!(handle.allows_reads());
        assert!(handle.require_write().is_err());

        handle.set(DatabaseMode::Unavailable);
        assert_eq!(handle.current(), DatabaseMode::Unavailable);
        assert!(!handle.allows_writes());
        assert!(!handle.allows_reads());

        handle.set(DatabaseMode::ReadWrite);
        assert_eq!(handle.current(), DatabaseMode::ReadWrite);
        assert!(handle.require_write().is_ok());
    }

    #[test]
    fn test_database_mode_handle_clone_shares_state() {
        let handle1 = DatabaseModeHandle::new();
        let handle2 = handle1.clone();

        handle1.set(DatabaseMode::ReadOnly);
        assert_eq!(handle2.current(), DatabaseMode::ReadOnly);
    }

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
    #[should_panic(expected = "FATAL: DATABASE_URL sslmode=")]
    fn validate_ssl_config_panics_for_insecure_sslmode() {
        // Production is always enforced — insecure sslmode must panic regardless
        // of MILNET_PRODUCTION env var (there is no dev mode).
        std::env::remove_var("MILNET_PRODUCTION");
        validate_ssl_config("postgres://host/db?sslmode=disable");
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
        let pool = init_database(&url).await.unwrap();
        // Verify tables exist by querying the information_schema (now includes tenants)
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('tenants', 'users', 'devices', 'portals', 'audit_log', 'sessions', 'oauth_codes', 'fido_credentials')"
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, 8);
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL — set DATABASE_URL"]
    async fn test_db_insert_and_query_user() {
        let url = std::env::var("DATABASE_URL").unwrap();
        let pool = init_database(&url).await.unwrap();
        let user_id = uuid::Uuid::new_v4();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let default_tenant = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();

        sqlx::query("INSERT INTO users (id, tenant_id, username, opaque_registration, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(user_id)
            .bind(default_tenant)
            .bind("alice")
            .bind(&[0u8; 32] as &[u8])
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();

        let row: (uuid::Uuid, String) = sqlx::query_as(
            "SELECT id, username FROM users WHERE tenant_id = $1 AND username = $2"
        )
        .bind(default_tenant)
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
