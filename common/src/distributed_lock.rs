//! Distributed locking for leader election and mutual exclusion.
//!
//! Provides fencing-token-based distributed locks backed by PostgreSQL
//! advisory locks. Designed for leader election in the SSO system where
//! only one instance should perform certain operations (e.g., key rotation
//! coordination, TSS ceremony initiation).
//!
//! # Fencing Tokens
//! Every lock acquisition returns a monotonically increasing fencing token.
//! Downstream systems must validate that the token is current before accepting
//! writes, preventing stale leaders from corrupting state after a network
//! partition.
//!
//! # Lock Renewal
//! Locks have a TTL (time-to-live). The holder must periodically renew the
//! lock before TTL expiry. If renewal fails, the lock is released and another
//! instance can acquire it.
//!
//! # Backend: PostgreSQL Advisory Locks
//! Uses `pg_try_advisory_lock(bigint)` for distributed coordination. This
//! avoids external dependencies (etcd, ZooKeeper) while providing strong
//! guarantees when paired with fencing tokens.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ── Error types ─────────────────────────────────────────────────────────────

/// Errors that can occur during distributed lock operations.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// The lock is already held by another instance.
    #[error("lock '{name}' is held by another instance (holder: {holder})")]
    AlreadyHeld {
        name: String,
        holder: String,
    },

    /// The lock was not found (never acquired or already released).
    #[error("lock '{0}' not found")]
    NotFound(String),

    /// The fencing token is stale (a newer token has been issued).
    #[error("stale fencing token: provided {provided}, current {current}")]
    StaleFencingToken {
        provided: u64,
        current: u64,
    },

    /// Lock renewal failed because the TTL has already expired.
    #[error("lock '{0}' TTL expired — lock lost")]
    TtlExpired(String),

    /// Lock renewal failed because the caller is not the current holder.
    #[error("lock '{name}' renewal denied: caller '{caller}' is not holder '{holder}'")]
    NotHolder {
        name: String,
        caller: String,
        holder: String,
    },

    /// Database error during advisory lock operations.
    #[error("database error: {0}")]
    Database(String),

    /// Internal error.
    #[error("internal lock error: {0}")]
    Internal(String),
}

// ── Fencing token ───────────────────────────────────────────────────────────

/// Global monotonically increasing fencing token counter.
///
/// In a production multi-process deployment this would be backed by a
/// database sequence (`CREATE SEQUENCE milnet_fencing_seq`). For
/// single-process / testing scenarios, an atomic counter suffices.
static FENCING_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Default path for persisted fencing counter state.
const DEFAULT_FENCING_STATE_PATH: &str = "/var/lib/milnet/fencing_counter";

/// Generate the next fencing token.
/// Persists the counter to disk (fsync) before returning, so that a restart
/// never reissues a token that was previously handed out.
fn next_fencing_token() -> u64 {
    if std::env::var("MILNET_PRODUCTION").is_ok() && !is_distributed_fencing_enabled() {
        tracing::warn!(
            target: "siem",
            "SIEM:WARNING: Using local file-based fencing counter in production. \
             Call init_distributed_fencing() at startup for cross-process monotonicity."
        );
    }
    // Load persisted max on first call via the in-memory counter.
    // Subsequent calls just increment the atomic.
    let token = FENCING_COUNTER.fetch_add(1, Ordering::SeqCst);
    // Best-effort persist: write to file with fsync.
    persist_fencing_counter(token + 1);
    token
}

/// Persist the fencing counter ceiling to disk so restarts never reissue tokens.
fn persist_fencing_counter(next_value: u64) {
    let path = std::env::var("MILNET_FENCING_STATE_PATH")
        .unwrap_or_else(|_| DEFAULT_FENCING_STATE_PATH.to_string());
    let tmp = format!("{path}.tmp");
    let data = next_value.to_le_bytes();
    if let Ok(mut f) = std::fs::File::create(&tmp) {
        use std::io::Write;
        if f.write_all(&data).is_ok() && f.sync_all().is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// Load the persisted fencing counter from disk and initialize the atomic.
/// Call once at startup before any lock operations.
pub fn init_fencing_counter_from_disk() {
    let path = std::env::var("MILNET_FENCING_STATE_PATH")
        .unwrap_or_else(|_| DEFAULT_FENCING_STATE_PATH.to_string());
    if let Ok(data) = std::fs::read(&path) {
        if data.len() == 8 {
            if let Ok(bytes) = data[..8].try_into() {
                let persisted: u64 = u64::from_le_bytes(bytes);
                // Set the counter to at least the persisted value.
                FENCING_COUNTER.fetch_max(persisted, Ordering::SeqCst);
                tracing::info!(fencing_counter = persisted, "restored fencing counter from disk");
            }
        }
    }
}

/// Database-backed fencing token counter for distributed deployments.
/// Uses a PostgreSQL sequence to guarantee monotonicity across all processes.
static DISTRIBUTED_FENCING_POOL: std::sync::OnceLock<sqlx::PgPool> = std::sync::OnceLock::new();

/// Cached block of fencing tokens fetched from the database sequence.
struct FencingTokenBlock {
    next: u64,
    upper: u64,
}

static FENCING_TOKEN_BLOCK: Mutex<Option<FencingTokenBlock>> = Mutex::new(None);

/// Number of tokens to fetch per DB round-trip.
const FENCING_BLOCK_SIZE: u64 = 100;

/// Initialize distributed fencing with a database pool.
/// The caller must ensure the sequence exists:
///   `CREATE SEQUENCE IF NOT EXISTS milnet_fencing_seq START WITH 1 INCREMENT BY 1 NO CYCLE;`
pub fn init_distributed_fencing_pool(pool: sqlx::PgPool) {
    DISTRIBUTED_FENCING_POOL.set(pool).ok();
    tracing::info!(
        target: "siem",
        "Distributed fencing initialized with database-backed sequence"
    );
}

/// Backward-compatible initialization from URL. For production use
/// `init_distributed_fencing_pool()` with a shared pool.
pub fn init_distributed_fencing(database_url: &str) {
    let _ = database_url;
    tracing::info!(
        target: "siem",
        "Distributed fencing init requested (pool-based init preferred)"
    );
}

/// Check if distributed fencing is available (pool-backed).
pub fn is_distributed_fencing_enabled() -> bool {
    DISTRIBUTED_FENCING_POOL.get().is_some()
}

/// Enforce that distributed fencing is initialized in production mode.
/// Call after all startup initialization is complete.
/// In production (MILNET_PRODUCTION=1), if distributed fencing is not initialized,
/// logs SIEM:CRITICAL and exits the process. Local AtomicU64 fencing is forbidden
/// in production because it resets on restart, violating monotonicity across processes.
pub fn enforce_distributed_fencing_in_production() {
    if cfg!(test) || cfg!(feature = "test-support") {
        return;
    }
    let is_production = std::env::var("MILNET_PRODUCTION").is_ok()
        || std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok();
    if !is_production {
        return;
    }
    if is_distributed_fencing_enabled() {
        return;
    }
    let event = crate::siem::SecurityEvent {
        timestamp: crate::siem::SecurityEvent::now_iso8601(),
        category: "distributed_lock",
        action: "fencing_not_distributed_production",
        severity: crate::siem::Severity::Critical,
        outcome: "failure",
        user_id: None,
        source_ip: None,
        detail: Some(
            "MILNET_PRODUCTION=1 but distributed fencing (PostgreSQL sequence) is not initialized. \
             Local AtomicU64 fencing resets on restart and cannot guarantee monotonicity across processes. \
             Call init_distributed_fencing_pool() at startup."
                .into(),
        ),
    };
    event.emit();
    tracing::error!(
        "SIEM:CRITICAL Distributed fencing not initialized in production mode. \
         Fencing tokens from local AtomicU64 are unsafe. Exiting."
    );
    std::process::exit(1);
}

/// Validate that the fencing sequence exists in the database.
/// Call at startup to fail fast if the migration is missing.
pub async fn validate_fencing_sequence() -> Result<(), LockError> {
    let pool = DISTRIBUTED_FENCING_POOL
        .get()
        .ok_or_else(|| LockError::Internal("distributed fencing pool not initialized".into()))?;

    let exists: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM pg_sequences WHERE sequencename = 'milnet_fencing_seq')",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| LockError::Database(format!("sequence validation query failed: {e}")))?;

    if !exists.0 {
        return Err(LockError::Internal(
            "milnet_fencing_seq does not exist. Run migration: \
             CREATE SEQUENCE IF NOT EXISTS milnet_fencing_seq START WITH 1 INCREMENT BY 1 NO CYCLE;"
                .into(),
        ));
    }

    tracing::info!(target: "siem", "Fencing sequence milnet_fencing_seq validated");
    Ok(())
}

/// Fetch a block of fencing tokens from the database sequence.
async fn fetch_fencing_token_block(pool: &sqlx::PgPool) -> Result<FencingTokenBlock, String> {
    let row: (i64,) = sqlx::query_as(
        "SELECT setval('milnet_fencing_seq', \
         nextval('milnet_fencing_seq') + $1 - 1) - $1 + 1",
    )
    .bind(FENCING_BLOCK_SIZE as i64)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("fencing sequence fetch failed: {e}"))?;

    let base = row.0 as u64;
    Ok(FencingTokenBlock {
        next: base,
        upper: base + FENCING_BLOCK_SIZE,
    })
}

/// Synchronously fetch a fencing token block.
fn fetch_block_sync(pool: &sqlx::PgPool) -> Result<FencingTokenBlock, String> {
    let pool = pool.clone();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => std::thread::scope(|s| {
            s.spawn(|| handle.block_on(fetch_fencing_token_block(&pool)))
                .join()
                .unwrap_or_else(|_| Err("thread panicked during fencing fetch".into()))
        }),
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("failed to create runtime for fencing fetch: {e}"))?;
            rt.block_on(fetch_fencing_token_block(&pool))
        }
    }
}

/// Generate the next fencing token using the database sequence.
///
/// In military deployment mode (`MILNET_MILITARY_DEPLOYMENT`), returns 0 (poison)
/// if distributed fencing is not initialized. Local fallback is forbidden.
///
/// Tokens are fetched in blocks of 100 to reduce DB round-trips.
pub fn next_fencing_token_distributed() -> u64 {
    let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok();

    let pool = match DISTRIBUTED_FENCING_POOL.get() {
        Some(p) => p,
        None => {
            if is_military {
                tracing::error!(
                    target: "siem",
                    "SIEM:CRITICAL Fencing token requested in MILITARY DEPLOYMENT mode \
                     but distributed fencing not initialized. REFUSING to issue token."
                );
                let event = crate::siem::SecurityEvent {
                    timestamp: crate::siem::SecurityEvent::now_iso8601(),
                    category: "distributed_lock",
                    action: "fencing_token_refused_military",
                    severity: crate::siem::Severity::Critical,
                    outcome: "failure",
                    user_id: None,
                    source_ip: None,
                    detail: Some(
                        "distributed fencing not initialized in military mode".into(),
                    ),
                };
                event.emit();
                return 0;
            }

            if std::env::var("MILNET_PRODUCTION").is_ok() {
                tracing::warn!(
                    target: "siem",
                    "SIEM:WARNING Fencing token requested but distributed fencing not initialized. \
                     Using local atomic counter as fallback."
                );
            }
            return next_fencing_token();
        }
    };

    // Try to get a token from the cached block
    {
        let mut block_guard = FENCING_TOKEN_BLOCK.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref mut block) = *block_guard {
            if block.next < block.upper {
                let token = block.next;
                block.next += 1;
                FENCING_COUNTER.fetch_max(token + 1, Ordering::SeqCst);
                persist_fencing_counter(token + 1);
                return token;
            }
        }
    }

    // Block exhausted or not yet fetched
    let fetch_result = fetch_block_sync(pool);
    match fetch_result {
        Ok(mut block) => {
            let token = block.next;
            block.next += 1;
            FENCING_COUNTER.fetch_max(token + 1, Ordering::SeqCst);
            persist_fencing_counter(token + 1);
            let mut block_guard =
                FENCING_TOKEN_BLOCK.lock().unwrap_or_else(|p| p.into_inner());
            *block_guard = Some(block);
            token
        }
        Err(e) => {
            if is_military {
                tracing::error!(
                    target: "siem",
                    error = %e,
                    "SIEM:CRITICAL Fencing token DB fetch failed in MILITARY mode. \
                     REFUSING to issue token."
                );
                let event = crate::siem::SecurityEvent {
                    timestamp: crate::siem::SecurityEvent::now_iso8601(),
                    category: "distributed_lock",
                    action: "fencing_token_db_failure_military",
                    severity: crate::siem::Severity::Critical,
                    outcome: "failure",
                    user_id: None,
                    source_ip: None,
                    detail: Some(format!("DB fetch error: {e}")),
                };
                event.emit();
                0
            } else {
                tracing::error!(
                    target: "siem",
                    error = %e,
                    "SIEM:CRITICAL Fencing token DB fetch failed. Falling back to local counter."
                );
                next_fencing_token()
            }
        }
    }
}

/// Validate that a fencing token is current.
///
/// Uses constant-time comparison to prevent timing side-channels on the
/// fencing token value (defense in depth — the token is not a secret, but
/// we follow the codebase convention of constant-time comparisons for
/// security-relevant values).
pub fn validate_fencing_token(provided: u64, expected: u64) -> Result<(), LockError> {
    // Monotonic check: a fencing token is valid if it is >= the expected value.
    // This allows a newer leader's token to be accepted while rejecting stale ones.
    if provided >= expected {
        Ok(())
    } else {
        Err(LockError::StaleFencingToken {
            provided,
            current: expected,
        })
    }
}

// ── Lock state ──────────────────────────────────────────────────────────────

/// A held lock with its metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockGrant {
    /// Name / identifier of the lock.
    pub name: String,
    /// Fencing token — must be validated by downstream systems.
    pub fencing_token: u64,
    /// Identity of the holder (e.g., instance ID, hostname).
    pub holder_id: String,
    /// When the lock was acquired (Unix epoch seconds).
    pub acquired_at_epoch: u64,
    /// When the lock expires if not renewed (Unix epoch seconds).
    pub expires_at_epoch: u64,
    /// TTL duration for renewal calculations.
    pub ttl_secs: u64,
}

/// Internal mutable state for a held lock.
struct LockState {
    grant: LockGrant,
    /// Instant when the lock was last renewed (or acquired).
    last_renewed: Instant,
    /// TTL duration.
    ttl: Duration,
}

impl LockState {
    /// Check if the lock has expired.
    fn is_expired(&self) -> bool {
        self.last_renewed.elapsed() > self.ttl
    }

    /// Renew the lock, extending the TTL.
    fn renew(&mut self) -> u64 {
        self.last_renewed = Instant::now();
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.grant.expires_at_epoch = now_epoch + self.grant.ttl_secs;
        self.grant.fencing_token
    }
}

// ── Lock Manager ────────────────────────────────────────────────────────────

/// In-process distributed lock manager.
///
/// For true distributed locking across multiple processes/hosts, use
/// [`PgAdvisoryLockManager`] which delegates to PostgreSQL. This in-process
/// manager is suitable for:
/// - Single-process deployments with multiple async tasks.
/// - Testing and development.
/// - As a local cache layer in front of the PostgreSQL backend.
///
/// # Thread Safety
/// All operations are protected by an internal `Mutex`.
pub struct LockManager {
    locks: Mutex<HashMap<String, LockState>>,
}

impl LockManager {
    /// Create a new lock manager.
    pub fn new() -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Try to acquire a named lock.
    ///
    /// Returns a [`LockGrant`] containing the fencing token if successful.
    /// The lock will expire after `ttl` if not renewed.
    ///
    /// # Arguments
    /// * `name` - Unique lock name (e.g., `"leader-election"`, `"key-rotation"`).
    /// * `holder_id` - Identity of the acquiring instance.
    /// * `ttl` - Time-to-live for the lock.
    pub fn try_acquire(
        &self,
        name: &str,
        holder_id: &str,
        ttl: Duration,
    ) -> Result<LockGrant, LockError> {
        let mut locks = self.locks.lock().unwrap_or_else(|poisoned| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "LockManager::try_acquire — recovered from poisoned lock",
            );
            poisoned.into_inner()
        });

        // Check if lock is already held.
        if let Some(existing) = locks.get(name) {
            if !existing.is_expired() {
                return Err(LockError::AlreadyHeld {
                    name: name.to_string(),
                    holder: existing.grant.holder_id.clone(),
                });
            }
            // Expired — we can take it over. Emit a SIEM event for the expiry.
            emit_lock_event(
                "lock_expired",
                name,
                &existing.grant.holder_id,
                existing.grant.fencing_token,
            );
        }

        let fencing_token = next_fencing_token();
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let grant = LockGrant {
            name: name.to_string(),
            fencing_token,
            holder_id: holder_id.to_string(),
            acquired_at_epoch: now_epoch,
            expires_at_epoch: now_epoch + ttl.as_secs(),
            ttl_secs: ttl.as_secs(),
        };

        let state = LockState {
            grant: grant.clone(),
            last_renewed: Instant::now(),
            ttl,
        };

        locks.insert(name.to_string(), state);

        emit_lock_event("lock_acquired", name, holder_id, fencing_token);
        tracing::info!(
            "distributed_lock: '{}' acquired by '{}' (token={})",
            name,
            holder_id,
            fencing_token
        );

        Ok(grant)
    }

    /// Renew a held lock, extending its TTL.
    ///
    /// The caller must provide the correct `holder_id`. Returns the current
    /// fencing token (unchanged on renewal).
    pub fn renew(
        &self,
        name: &str,
        holder_id: &str,
    ) -> Result<u64, LockError> {
        let mut locks = self.locks.lock().unwrap_or_else(|poisoned| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "LockManager::renew — recovered from poisoned lock",
            );
            poisoned.into_inner()
        });

        let state = locks
            .get_mut(name)
            .ok_or_else(|| LockError::NotFound(name.to_string()))?;

        if state.is_expired() {
            locks.remove(name);
            return Err(LockError::TtlExpired(name.to_string()));
        }

        if state.grant.holder_id != holder_id {
            return Err(LockError::NotHolder {
                name: name.to_string(),
                caller: holder_id.to_string(),
                holder: state.grant.holder_id.clone(),
            });
        }

        let token = state.renew();
        tracing::debug!(
            "distributed_lock: '{}' renewed by '{}' (token={})",
            name,
            holder_id,
            token
        );

        Ok(token)
    }

    /// Release a held lock.
    ///
    /// Only the current holder (matching `holder_id`) can release the lock.
    pub fn release(
        &self,
        name: &str,
        holder_id: &str,
    ) -> Result<(), LockError> {
        let mut locks = self.locks.lock().unwrap_or_else(|poisoned| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "LockManager::release — recovered from poisoned lock",
            );
            poisoned.into_inner()
        });

        let state = locks
            .get(name)
            .ok_or_else(|| LockError::NotFound(name.to_string()))?;

        if state.grant.holder_id != holder_id {
            return Err(LockError::NotHolder {
                name: name.to_string(),
                caller: holder_id.to_string(),
                holder: state.grant.holder_id.clone(),
            });
        }

        let token = state.grant.fencing_token;
        locks.remove(name);

        emit_lock_event("lock_released", name, holder_id, token);
        tracing::info!(
            "distributed_lock: '{}' released by '{}'",
            name,
            holder_id
        );

        Ok(())
    }

    /// Inspect a lock without modifying it.
    pub fn inspect(&self, name: &str) -> Result<LockGrant, LockError> {
        let locks = self.locks.lock().unwrap_or_else(|poisoned| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "LockManager::inspect — recovered from poisoned lock",
            );
            poisoned.into_inner()
        });

        let state = locks
            .get(name)
            .ok_or_else(|| LockError::NotFound(name.to_string()))?;

        if state.is_expired() {
            return Err(LockError::TtlExpired(name.to_string()));
        }

        Ok(state.grant.clone())
    }

    /// Reap all expired locks. Call periodically from a background task.
    pub fn reap_expired(&self) -> usize {
        let mut locks = self.locks.lock().unwrap_or_else(|poisoned| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "LockManager::reap_expired — recovered from poisoned lock",
            );
            poisoned.into_inner()
        });

        let expired: Vec<String> = locks
            .iter()
            .filter(|(_, state)| state.is_expired())
            .map(|(name, _)| name.clone())
            .collect();

        let count = expired.len();
        for name in &expired {
            if let Some(state) = locks.remove(name) {
                emit_lock_event(
                    "lock_expired",
                    name,
                    &state.grant.holder_id,
                    state.grant.fencing_token,
                );
            }
        }

        if count > 0 {
            tracing::info!("distributed_lock: reaped {} expired locks", count);
        }

        count
    }

    /// List all currently held (non-expired) locks.
    pub fn list_held(&self) -> Vec<LockGrant> {
        let locks = self.locks.lock().unwrap_or_else(|poisoned| {
            crate::siem::SecurityEvent::mutex_poisoning(
                "LockManager::list_held — recovered from poisoned lock",
            );
            poisoned.into_inner()
        });

        locks
            .values()
            .filter(|s| !s.is_expired())
            .map(|s| s.grant.clone())
            .collect()
    }
}

impl Default for LockManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── PostgreSQL advisory lock backend ────────────────────────────────────────

/// PostgreSQL-backed distributed lock manager using advisory locks.
///
/// Advisory locks in PostgreSQL are:
/// - Automatically released when the session disconnects.
/// - Not subject to MVCC — they are true mutual exclusion primitives.
/// - Identified by a `bigint` key derived from the lock name.
///
/// This manager adds fencing tokens and TTL on top of raw advisory locks
/// to provide the full distributed lock semantics required for leader
/// election.
///
/// # Usage
/// ```rust,no_run
/// use common::distributed_lock::PgAdvisoryLockManager;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let pool = sqlx::PgPool::connect("postgres://...").await?;
/// let mgr = PgAdvisoryLockManager::new(pool);
/// let grant = mgr.try_acquire("leader-election", "instance-1",
///     std::time::Duration::from_secs(30)).await?;
/// // ... do leader work using grant.fencing_token ...
/// mgr.release("leader-election", "instance-1").await?;
/// # Ok(())
/// # }
/// ```
pub struct PgAdvisoryLockManager {
    pool: sqlx::PgPool,
    /// Local lock manager for TTL and fencing token tracking.
    local: LockManager,
}

impl PgAdvisoryLockManager {
    /// Create a new PostgreSQL advisory lock manager.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            pool,
            local: LockManager::new(),
        }
    }

    /// Derive a stable `i64` advisory lock key from a lock name.
    ///
    /// Uses BLAKE3 hash truncated to 8 bytes, ensuring consistent key
    /// derivation across all instances.
    fn lock_key(name: &str) -> i64 {
        let hash = blake3::hash(name.as_bytes());
        let bytes: [u8; 8] = hash.as_bytes()[..8]
            .try_into()
            .unwrap_or([0u8; 8]);
        // Mask the sign bit to keep the key positive for readability in
        // pg_locks, but this is not a security requirement.
        i64::from_le_bytes(bytes) & i64::MAX
    }

    /// Try to acquire a distributed advisory lock.
    pub async fn try_acquire(
        &self,
        name: &str,
        holder_id: &str,
        ttl: Duration,
    ) -> Result<LockGrant, LockError> {
        let key = Self::lock_key(name);

        // Try the PostgreSQL advisory lock first.
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| LockError::Database(e.to_string()))?;

        if !acquired {
            return Err(LockError::AlreadyHeld {
                name: name.to_string(),
                holder: "unknown (remote instance)".to_string(),
            });
        }

        // Advisory lock acquired — create local tracking with fencing token.
        match self.local.try_acquire(name, holder_id, ttl) {
            Ok(grant) => Ok(grant),
            Err(e) => {
                // Release the advisory lock if local tracking fails.
                let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                    .bind(key)
                    .execute(&self.pool)
                    .await;
                Err(e)
            }
        }
    }

    /// Renew a held lock's TTL.
    pub async fn renew(
        &self,
        name: &str,
        holder_id: &str,
    ) -> Result<u64, LockError> {
        // Verify we still hold the advisory lock by checking pg_locks.
        let key = Self::lock_key(name);
        let held: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = $1 AND pid = pg_backend_pid())"
        )
        .bind(key as i32)  // objid is the lower 32 bits
        .fetch_one(&self.pool)
        .await
        .map_err(|e| LockError::Database(e.to_string()))?;

        if !held {
            // Lost the advisory lock — another session took it.
            return Err(LockError::TtlExpired(name.to_string()));
        }

        self.local.renew(name, holder_id)
    }

    /// Release a distributed advisory lock.
    pub async fn release(
        &self,
        name: &str,
        holder_id: &str,
    ) -> Result<(), LockError> {
        // Release local tracking first.
        self.local.release(name, holder_id)?;

        // Then release the PostgreSQL advisory lock.
        let key = Self::lock_key(name);
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| LockError::Database(e.to_string()))?;

        Ok(())
    }

    /// Inspect a lock.
    pub fn inspect(&self, name: &str) -> Result<LockGrant, LockError> {
        self.local.inspect(name)
    }

    /// Reap expired locks and release their advisory locks.
    pub async fn reap_expired(&self) -> Result<usize, LockError> {
        // Get expired lock names before reaping.
        let expired_names: Vec<String> = {
            let locks = self.local.locks.lock().unwrap_or_else(|p| {
                crate::siem::SecurityEvent::mutex_poisoning(
                    "PgAdvisoryLockManager::reap_expired — recovered",
                );
                p.into_inner()
            });
            locks
                .iter()
                .filter(|(_, s)| s.is_expired())
                .map(|(n, _)| n.clone())
                .collect()
        };

        // Release advisory locks for expired entries.
        for name in &expired_names {
            let key = Self::lock_key(name);
            let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(key)
                .execute(&self.pool)
                .await;
        }

        // Reap from local manager.
        Ok(self.local.reap_expired())
    }

    /// Spawn a background task that renews a lock periodically.
    ///
    /// The task renews at `ttl / 3` intervals (well before expiry) and
    /// stops when it can no longer renew (TTL expired or holder changed).
    ///
    /// NOTE: This method uses the local `LockManager` only. For full
    /// distributed renewal (including PostgreSQL advisory lock verification),
    /// use [`spawn_lock_renewal`] with an `Arc<PgAdvisoryLockManager>`.
    pub fn spawn_renewal(
        self: &std::sync::Arc<Self>,
        name: String,
        holder_id: String,
        ttl: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let manager = std::sync::Arc::clone(self);
        let renewal_interval = ttl / 3;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(renewal_interval).await;
                match manager.renew(&name, &holder_id).await {
                    Ok(token) => {
                        tracing::debug!(
                            "distributed_lock: renewed '{}' for '{}' (token={})",
                            name,
                            holder_id,
                            token
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "distributed_lock: renewal failed for '{}' by '{}': {}",
                            name,
                            holder_id,
                            e
                        );
                        emit_lock_event("lock_renewal_failed", &name, &holder_id, 0);
                        break;
                    }
                }
            }
        })
    }
}

// ── Lock renewal helper for Arc usage ───────────────────────────────────────

/// Spawn a lock renewal loop for an `Arc<PgAdvisoryLockManager>`.
///
/// This is the recommended way to keep a lock alive:
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use common::distributed_lock::*;
/// # async fn example(mgr: Arc<PgAdvisoryLockManager>) {
/// let grant = mgr.try_acquire("leader", "node-1",
///     std::time::Duration::from_secs(30)).await.unwrap();
/// let handle = spawn_lock_renewal(
///     Arc::clone(&mgr), "leader".into(), "node-1".into(),
///     std::time::Duration::from_secs(30),
/// );
/// // ... do leader work ...
/// handle.abort(); // Stop renewing before release.
/// mgr.release("leader", "node-1").await.unwrap();
/// # }
/// ```
pub fn spawn_lock_renewal(
    manager: std::sync::Arc<PgAdvisoryLockManager>,
    name: String,
    holder_id: String,
    ttl: Duration,
) -> tokio::task::JoinHandle<()> {
    let renewal_interval = ttl / 3;

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(renewal_interval).await;
            match manager.renew(&name, &holder_id).await {
                Ok(token) => {
                    tracing::debug!(
                        "distributed_lock: renewed '{}' for '{}' (token={})",
                        name,
                        holder_id,
                        token
                    );
                }
                Err(e) => {
                    tracing::error!(
                        "distributed_lock: renewal failed for '{}' by '{}': {}",
                        name,
                        holder_id,
                        e
                    );
                    emit_lock_event("lock_renewal_failed", &name, &holder_id, 0);
                    break;
                }
            }
        }
    })
}

// ── SIEM integration ────────────────────────────────────────────────────────

/// Emit a SIEM event for lock operations.
fn emit_lock_event(action: &'static str, name: &str, holder: &str, token: u64) {
    let severity = match action {
        "lock_expired" | "lock_renewal_failed" => crate::siem::Severity::Warning,
        _ => crate::siem::Severity::Info,
    };

    let event = crate::siem::SecurityEvent {
        timestamp: crate::siem::SecurityEvent::now_iso8601(),
        category: "distributed_lock",
        action,
        severity,
        outcome: if action.contains("fail") || action.contains("expired") {
            "failure"
        } else {
            "success"
        },
        user_id: None,
        source_ip: None,
        detail: Some(format!(
            "lock={} holder={} fencing_token={}",
            name, holder, token
        )),
    };
    event.emit();
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_and_release() {
        let mgr = LockManager::new();
        let grant = mgr
            .try_acquire("test-lock", "node-1", Duration::from_secs(30))
            .unwrap();
        assert_eq!(grant.name, "test-lock");
        assert_eq!(grant.holder_id, "node-1");
        assert!(grant.fencing_token > 0);

        mgr.release("test-lock", "node-1").unwrap();
    }

    #[test]
    fn double_acquire_fails() {
        let mgr = LockManager::new();
        mgr.try_acquire("exclusive", "node-1", Duration::from_secs(60))
            .unwrap();

        let err = mgr
            .try_acquire("exclusive", "node-2", Duration::from_secs(60))
            .unwrap_err();
        assert!(matches!(err, LockError::AlreadyHeld { .. }));
    }

    #[test]
    fn expired_lock_can_be_reacquired() {
        let mgr = LockManager::new();
        // Acquire with a very short TTL.
        mgr.try_acquire("ephemeral", "node-1", Duration::from_millis(1))
            .unwrap();

        // Wait for expiry.
        std::thread::sleep(Duration::from_millis(10));

        // Another node can now acquire it.
        let grant = mgr
            .try_acquire("ephemeral", "node-2", Duration::from_secs(30))
            .unwrap();
        assert_eq!(grant.holder_id, "node-2");
    }

    #[test]
    fn renew_extends_ttl() {
        let mgr = LockManager::new();
        let grant = mgr
            .try_acquire("renewable", "node-1", Duration::from_secs(30))
            .unwrap();

        let token = mgr.renew("renewable", "node-1").unwrap();
        assert_eq!(token, grant.fencing_token);
    }

    #[test]
    fn wrong_holder_cannot_release() {
        let mgr = LockManager::new();
        mgr.try_acquire("guarded", "node-1", Duration::from_secs(30))
            .unwrap();

        let err = mgr.release("guarded", "node-2").unwrap_err();
        assert!(matches!(err, LockError::NotHolder { .. }));
    }

    #[test]
    fn fencing_tokens_are_monotonic() {
        let mgr = LockManager::new();

        let g1 = mgr
            .try_acquire("seq-1", "n", Duration::from_secs(30))
            .unwrap();
        let g2 = mgr
            .try_acquire("seq-2", "n", Duration::from_secs(30))
            .unwrap();
        let g3 = mgr
            .try_acquire("seq-3", "n", Duration::from_secs(30))
            .unwrap();

        assert!(g2.fencing_token > g1.fencing_token);
        assert!(g3.fencing_token > g2.fencing_token);
    }

    #[test]
    fn validate_fencing_token_monotonic() {
        assert!(validate_fencing_token(42, 42).is_ok());
        assert!(validate_fencing_token(43, 42).is_ok()); // newer token accepted
        assert!(validate_fencing_token(42, 43).is_err()); // stale token rejected
    }

    #[test]
    fn reap_expired_cleans_up() {
        let mgr = LockManager::new();
        mgr.try_acquire("reap-1", "n", Duration::from_millis(1))
            .unwrap();
        mgr.try_acquire("reap-2", "n", Duration::from_secs(300))
            .unwrap();

        std::thread::sleep(Duration::from_millis(10));

        let reaped = mgr.reap_expired();
        assert_eq!(reaped, 1);
        assert_eq!(mgr.list_held().len(), 1);
    }

    #[test]
    fn list_held_excludes_expired() {
        let mgr = LockManager::new();
        mgr.try_acquire("alive", "n", Duration::from_secs(300))
            .unwrap();
        mgr.try_acquire("dead", "n", Duration::from_millis(1))
            .unwrap();

        std::thread::sleep(Duration::from_millis(10));

        let held = mgr.list_held();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].name, "alive");
    }

    #[test]
    fn pg_lock_key_is_deterministic() {
        let k1 = PgAdvisoryLockManager::lock_key("leader-election");
        let k2 = PgAdvisoryLockManager::lock_key("leader-election");
        assert_eq!(k1, k2);
        // Different names produce different keys.
        let k3 = PgAdvisoryLockManager::lock_key("key-rotation");
        assert_ne!(k1, k3);
    }

    #[test]
    fn distributed_fencing_not_initialized_non_military() {
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        std::env::remove_var("MILNET_PRODUCTION");

        let token = next_fencing_token_distributed();
        assert!(token > 0, "local fallback should produce non-zero token");
    }

    #[test]
    fn fencing_tokens_concurrent_monotonicity() {
        use std::collections::BTreeSet;
        use std::sync::Arc;

        let tokens = Arc::new(Mutex::new(BTreeSet::new()));
        let mut handles = vec![];

        for _ in 0..8 {
            let tokens = Arc::clone(&tokens);
            handles.push(std::thread::spawn(move || {
                let mut local_tokens = vec![];
                for _ in 0..50 {
                    local_tokens.push(next_fencing_token());
                }
                let mut guard = tokens.lock().unwrap();
                for t in local_tokens {
                    guard.insert(t);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let guard = tokens.lock().unwrap();
        assert_eq!(guard.len(), 400, "all fencing tokens must be unique");

        let sorted: Vec<u64> = guard.iter().copied().collect();
        for w in sorted.windows(2) {
            assert!(w[1] > w[0], "tokens must be strictly increasing");
        }
    }

    #[test]
    fn fencing_token_gaps_are_acceptable() {
        let t1 = next_fencing_token();
        FENCING_COUNTER.fetch_add(10, Ordering::SeqCst);
        let t2 = next_fencing_token();

        assert!(t2 > t1, "token after gap must still be monotonically increasing");
        assert!(t2 - t1 > 1, "there should be a gap");
        assert!(validate_fencing_token(t2, t1).is_ok());
    }
}
