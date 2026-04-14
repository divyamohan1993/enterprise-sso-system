//! Concurrent session tracking — enforces max_concurrent_sessions_per_user.
#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// F17: ratchet chain_key encryption with per-session AAD
// ---------------------------------------------------------------------------

/// F17: build the AAD used when persisting a ratchet chain_key. The
/// 64-byte AAD is `user_id || session_id` (each 32 bytes via blake3), which
/// cryptographically binds the ciphertext to a single (user, session) pair
/// and blocks cross-session replay even if two sessions share a chain_key
/// at some point in their lifecycle.
pub fn chain_key_aad(user_id: &uuid::Uuid, session_id: &uuid::Uuid) -> [u8; 64] {
    let mut aad = [0u8; 64];
    // user_id is 16 bytes — expand to 32 via blake3 so both halves are
    // indistinguishable from random. Same for session_id.
    let u = blake3::hash(user_id.as_bytes());
    let s = blake3::hash(session_id.as_bytes());
    aad[..32].copy_from_slice(u.as_bytes());
    aad[32..].copy_from_slice(s.as_bytes());
    aad
}

/// F17: encrypt a ratchet chain_key with AES-256-GCM using the per-session AAD.
/// Ciphertext layout: `nonce (12 bytes) || aes_gcm_ct_and_tag`.
pub fn seal_chain_key(
    master_kek: &[u8; 32],
    chain_key: &[u8],
    user_id: &uuid::Uuid,
    session_id: &uuid::Uuid,
) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
    let aad = chain_key_aad(user_id, session_id);
    let cipher = Aes256Gcm::new_from_slice(master_kek)
        .map_err(|e| format!("F17 seal chain_key init: {e}"))?;
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("F17 seal chain_key rng: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: chain_key, aad: &aad })
        .map_err(|_| "F17 seal chain_key encrypt failed".to_string())?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// F17: decrypt a persisted chain_key ciphertext, enforcing the same AAD.
/// A mismatched (user, session) MUST fail — this blocks cross-session replay.
pub fn open_chain_key(
    master_kek: &[u8; 32],
    ciphertext: &[u8],
    user_id: &uuid::Uuid,
    session_id: &uuid::Uuid,
) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
    if ciphertext.len() < 12 + 16 {
        return Err("F17 chain_key ciphertext too short".into());
    }
    let aad = chain_key_aad(user_id, session_id);
    let cipher = Aes256Gcm::new_from_slice(master_kek)
        .map_err(|e| format!("F17 open chain_key init: {e}"))?;
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    cipher
        .decrypt(nonce, Payload { msg: &ciphertext[12..], aad: &aad })
        .map_err(|_| "F17 chain_key AAD mismatch — cross-session replay blocked".to_string())
}

use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// Session metadata with timestamps for both creation and last activity.
struct SessionEntry {
    session_id: Uuid,
    created_at: i64,
    last_activity: i64,
}

/// Tracks active sessions per user to enforce concurrency limits.
pub struct SessionTracker {
    /// Maps user_id -> set of active session IDs with their creation timestamps.
    active: Mutex<HashMap<Uuid, Vec<SessionEntry>>>,
    /// Maximum concurrent sessions per user.
    max_per_user: u32,
}

impl SessionTracker {
    /// Maximum idle time before session eviction (30 minutes).
    const IDLE_TIMEOUT_SECS: i64 = 1800;

    /// Create a new session tracker with the given per-user limit.
    pub fn new(max_per_user: u32) -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
            max_per_user,
        }
    }

    /// Try to register a new session. Returns Ok(()) if within limits,
    /// Err with message if the user has too many active sessions.
    // SECURITY: The mutex MUST be held continuously from the length check through
    // the push to prevent TOCTOU race conditions on session limits.
    pub fn register_session(&self, user_id: Uuid, session_id: Uuid, now: i64) -> Result<(), String> {
        let mut active = self.active.lock().unwrap_or_else(|e| {
            tracing::error!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SessionTracker mutex poisoned — recovering with inner data. \
                 A thread panicked while holding this lock."
            );
            e.into_inner()
        });
        let sessions = active.entry(user_id).or_default();

        // Evict sessions older than 8 hours (max session lifetime)
        const MAX_SESSION_AGE_SECS: i64 = 28800;
        let len_before = sessions.len();
        sessions.retain(|entry| {
            now - entry.created_at < MAX_SESSION_AGE_SECS && now - entry.last_activity < Self::IDLE_TIMEOUT_SECS
        });
        let evicted_age = len_before - sessions.len();
        for _ in 0..evicted_age {
            crate::siem::SecurityEvent::session_expired(&user_id.to_string());
        }

        if sessions.len() >= self.max_per_user as usize {
            crate::siem::SecurityEvent::session_revoked(
                &user_id.to_string(),
                "concurrent session limit exceeded",
            );
            return Err(format!(
                "session limit exceeded: max {} concurrent sessions per user",
                self.max_per_user
            ));
        }

        sessions.push(SessionEntry { session_id, created_at: now, last_activity: now });
        // Defense-in-depth: verify limit was not violated despite mutex protection
        assert!(
            sessions.len() <= self.max_per_user as usize + 1,
            "session limit invariant violated: {} sessions for user {}",
            sessions.len(), user_id
        );
        crate::siem::SecurityEvent::session_created(
            &user_id.to_string(),
            "internal",
        );
        Ok(())
    }

    /// Remove a session (on logout or expiry).
    pub fn remove_session(&self, user_id: &Uuid, session_id: &Uuid) {
        let mut active = self.active.lock().unwrap_or_else(|e| {
            tracing::error!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SessionTracker mutex poisoned — recovering with inner data. \
                 A thread panicked while holding this lock."
            );
            e.into_inner()
        });
        if let Some(sessions) = active.get_mut(user_id) {
            sessions.retain(|entry| &entry.session_id != session_id);
            if sessions.is_empty() {
                active.remove(user_id);
            }
        }
    }

    /// Get number of active sessions for a user.
    pub fn active_count(&self, user_id: &Uuid) -> usize {
        let active = self.active.lock().unwrap_or_else(|e| {
            tracing::error!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SessionTracker mutex poisoned — recovering with inner data. \
                 A thread panicked while holding this lock."
            );
            e.into_inner()
        });
        active.get(user_id).map_or(0, |s| s.len())
    }

    /// Check if a session has exceeded the idle timeout without being touched.
    /// Returns true if the session is idle (last activity > 30 minutes ago) or unknown.
    pub fn is_session_idle(&self, user_id: &Uuid, session_id: &Uuid, now: i64) -> bool {
        let active = self.active.lock().unwrap_or_else(|e| {
            tracing::warn!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SIEM:WARNING mutex poisoned in session_limits::is_session_idle - recovering"
            );
            e.into_inner()
        });
        if let Some(sessions) = active.get(user_id) {
            for entry in sessions {
                if &entry.session_id == session_id {
                    return (now - entry.last_activity) > Self::IDLE_TIMEOUT_SECS;
                }
            }
        }
        true // Unknown session = expired
    }

    /// Update the last-activity timestamp for a session (call on each API request).
    pub fn touch_session(&self, user_id: &Uuid, session_id: &Uuid, now: i64) {
        let mut active = self.active.lock().unwrap_or_else(|e| {
            tracing::warn!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SIEM:WARNING mutex poisoned in session_limits::touch_session - recovering"
            );
            e.into_inner()
        });
        if let Some(sessions) = active.get_mut(user_id) {
            for entry in sessions.iter_mut() {
                if &entry.session_id == session_id {
                    entry.last_activity = now;
                    return;
                }
            }
        }
    }

    /// Returns the total number of active sessions across all users.
    pub fn total_active_count(&self) -> usize {
        let active = self.active.lock().unwrap_or_else(|e| {
            tracing::warn!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SIEM:WARNING mutex poisoned in session_limits::total_active_count - recovering"
            );
            e.into_inner()
        });
        active.values().map(|v| v.len()).sum()
    }

    /// Remove all sessions for a user. Used for account deletion (GDPR Article 17).
    pub fn remove_all_sessions(&self, user_id: &Uuid) {
        let mut active = self.active.lock().unwrap_or_else(|e| {
            tracing::warn!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SIEM:WARNING mutex poisoned in session_limits::remove_all_sessions - recovering"
            );
            e.into_inner()
        });
        active.remove(user_id);
    }

    /// Persist all active sessions to a JSONL file for crash recovery.
    /// Called periodically or on graceful shutdown.
    pub fn persist_to_file(&self, path: &std::path::Path) -> Result<(), String> {
        let active = self.active.lock().unwrap_or_else(|e| {
            tracing::warn!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SIEM:WARNING mutex poisoned in session_limits::persist_to_file - recovering"
            );
            e.into_inner()
        });
        let file = std::fs::File::create(path)
            .map_err(|e| format!("failed to create session file: {e}"))?;
        let mut writer = std::io::BufWriter::new(file);

        for (user_id, sessions) in active.iter() {
            for entry in sessions {
                let record = serde_json::json!({
                    "user_id": user_id.to_string(),
                    "session_id": entry.session_id.to_string(),
                    "created_at": entry.created_at,
                    "last_activity": entry.last_activity,
                });
                if let Err(e) = serde_json::to_writer(&mut writer, &record) {
                    tracing::warn!("Failed to persist session entry: {e}");
                }
                use std::io::Write;
                let _ = writer.write_all(b"\n");
            }
        }
        Ok(())
    }

    /// Load sessions from a persistence file on startup.
    pub fn load_from_file(&self, path: &std::path::Path, now: i64) -> usize {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return 0,
        };
        let reader = std::io::BufReader::new(file);
        let mut loaded = 0usize;

        use std::io::BufRead;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            if let Ok(record) = serde_json::from_str::<serde_json::Value>(&line) {
                let user_id = record["user_id"].as_str()
                    .and_then(|s| uuid::Uuid::parse_str(s).ok());
                let session_id = record["session_id"].as_str()
                    .and_then(|s| uuid::Uuid::parse_str(s).ok());
                let created_at = record["created_at"].as_i64().unwrap_or(0);
                let last_activity = record["last_activity"].as_i64().unwrap_or(0);

                if let (Some(uid), Some(sid)) = (user_id, session_id) {
                    // Only load sessions that haven't expired
                    if now - created_at < 28800 && now - last_activity < 1800 {
                        let _ = self.register_session(uid, sid, created_at);
                        loaded += 1;
                    }
                }
            }
        }
        loaded
    }

    /// Remove sessions that have been inactive for longer than `timeout_secs`.
    /// Returns the number of sessions removed.
    pub fn cleanup_inactive(&self, now: i64, timeout_secs: i64) -> usize {
        let mut active = self.active.lock().unwrap_or_else(|e| {
            tracing::error!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SessionTracker mutex poisoned — recovering with inner data. \
                 A thread panicked while holding this lock."
            );
            e.into_inner()
        });
        let mut removed = 0usize;
        active.retain(|_user_id, sessions| {
            let before = sessions.len();
            sessions.retain(|entry| now - entry.last_activity < timeout_secs);
            removed += before - sessions.len();
            !sessions.is_empty()
        });
        removed
    }
}

// ---------------------------------------------------------------------------
// DistributedSessionTracker — PostgreSQL-backed with in-memory L1 cache
// ---------------------------------------------------------------------------

/// PostgreSQL-backed session tracker with in-memory L1 cache for fast lookups.
///
/// Session records are written through to a `active_sessions` table on every
/// mutation. The in-memory `SessionTracker` is the L1 cache for hot-path reads.
/// Periodic cleanup removes expired sessions from both cache and database.
pub struct DistributedSessionTracker {
    /// In-memory L1 cache for fast lookups.
    cache: SessionTracker,
    /// PostgreSQL connection pool for durable storage.
    pool: sqlx::PgPool,
}

impl DistributedSessionTracker {
    /// Create a new distributed tracker and ensure the backing table exists.
    pub async fn new(pool: sqlx::PgPool, max_per_user: u32) -> Result<Self, String> {
        // Ensure the active_sessions table exists (idempotent DDL).
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS active_sessions (
                session_id  UUID PRIMARY KEY,
                user_id     UUID NOT NULL,
                created_at  BIGINT NOT NULL,
                last_activity BIGINT NOT NULL,
                expires_at  BIGINT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .map_err(|e| format!("create active_sessions table: {e}"))?;

        if let Err(e) = sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_active_sessions_user \
             ON active_sessions (user_id)",
        )
        .execute(&pool)
        .await
        {
            tracing::debug!("CREATE INDEX idx_active_sessions_user (may already exist): {e}");
        }

        if let Err(e) = sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_active_sessions_expires \
             ON active_sessions (expires_at)",
        )
        .execute(&pool)
        .await
        {
            tracing::debug!("CREATE INDEX idx_active_sessions_expires (may already exist): {e}");
        }

        let tracker = Self {
            cache: SessionTracker::new(max_per_user),
            pool,
        };

        // Hydrate L1 cache from database.
        tracker.load_from_db().await?;

        Ok(tracker)
    }

    /// Load active sessions from database into the in-memory cache.
    async fn load_from_db(&self) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let rows: Vec<(Uuid, Uuid, i64, i64)> = sqlx::query_as(
            "SELECT session_id, user_id, created_at, last_activity \
             FROM active_sessions WHERE expires_at > $1",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("load active_sessions: {e}"))?;

        let mut loaded = 0usize;
        for (session_id, user_id, created_at, _last_activity) in rows {
            // Use created_at as the `now` parameter to preserve original timestamp.
            let _ = self.cache.register_session(user_id, session_id, created_at);
            loaded += 1;
        }

        tracing::info!(loaded, "DistributedSessionTracker: hydrated L1 cache from DB");
        Ok(())
    }

    /// Register a new session: write-through to DB, then update L1 cache.
    ///
    /// On login: INSERT a session record and check the per-user count.
    pub async fn register_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        now: i64,
    ) -> Result<(), String> {
        // Check L1 cache limit first (fast reject).
        self.cache.register_session(user_id, session_id, now)?;

        // Write through to database.
        let max_session_age_secs: i64 = 28800;
        let expires_at = now + max_session_age_secs;

        sqlx::query(
            "INSERT INTO active_sessions (session_id, user_id, created_at, last_activity, expires_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (session_id) DO UPDATE SET last_activity = $4",
        )
        .bind(session_id)
        .bind(user_id)
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            // Rollback L1 cache on DB failure.
            self.cache.remove_session(&user_id, &session_id);
            format!("persist session to DB: {e}")
        })?;

        Ok(())
    }

    /// Remove a session on logout or expiry: delete from DB, then update L1 cache.
    pub async fn remove_session(&self, user_id: &Uuid, session_id: &Uuid) -> Result<(), String> {
        self.cache.remove_session(user_id, session_id);

        sqlx::query("DELETE FROM active_sessions WHERE session_id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("delete session from DB: {e}"))?;

        Ok(())
    }

    /// Touch a session (update last_activity).
    pub async fn touch_session(
        &self,
        user_id: &Uuid,
        session_id: &Uuid,
        now: i64,
    ) -> Result<(), String> {
        self.cache.touch_session(user_id, session_id, now);

        sqlx::query("UPDATE active_sessions SET last_activity = $1 WHERE session_id = $2")
            .bind(now)
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("touch session in DB: {e}"))?;

        Ok(())
    }

    /// Get the number of active sessions for a user (from L1 cache).
    pub fn active_count(&self, user_id: &Uuid) -> usize {
        self.cache.active_count(user_id)
    }

    /// Get total active session count across all users (from L1 cache).
    pub fn total_active_count(&self) -> usize {
        self.cache.total_active_count()
    }

    /// Periodic cleanup: remove expired sessions from both DB and L1 cache.
    /// Returns the number of sessions removed.
    pub async fn cleanup_expired(&self, now: i64) -> Result<usize, String> {
        // Clean up the L1 cache.
        let cache_removed = self
            .cache
            .cleanup_inactive(now, SessionTracker::IDLE_TIMEOUT_SECS);

        // Clean up the database.
        let db_result = sqlx::query("DELETE FROM active_sessions WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("cleanup expired sessions: {e}"))?;

        let db_removed = db_result.rows_affected() as usize;

        if db_removed > 0 || cache_removed > 0 {
            tracing::info!(
                cache_removed,
                db_removed,
                "DistributedSessionTracker: cleaned up expired sessions"
            );
        }

        Ok(cache_removed.max(db_removed))
    }

    /// Spawn a background cleanup task that runs every `interval`.
    pub fn spawn_cleanup_task(
        pool: sqlx::PgPool,
        max_per_user: u32,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Create a minimal tracker just for cleanup (shares the same DB table).
            let tracker = match DistributedSessionTracker::new(pool, max_per_user).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("Failed to create cleanup tracker: {e}");
                    return;
                }
            };

            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                if let Err(e) = tracker.cleanup_expired(now).await {
                    tracing::warn!("Session cleanup error: {e}");
                }
            }
        })
    }

    /// Access the underlying in-memory cache for read-only checks.
    pub fn cache(&self) -> &SessionTracker {
        &self.cache
    }
}

// ---------------------------------------------------------------------------
// Session Invalidation on Privilege Change
// ---------------------------------------------------------------------------

/// Reason for session invalidation. Logged to SIEM for audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionInvalidationReason {
    /// User changed their password.
    PasswordChanged,
    /// User's role was changed.
    RoleChanged,
    /// User received elevated permissions.
    PermissionEscalation,
    /// Security incident detected.
    SecurityIncident,
    /// Administrative action.
    AdminAction,
}

impl SessionInvalidationReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::PasswordChanged => "password_changed",
            Self::RoleChanged => "role_changed",
            Self::PermissionEscalation => "permission_escalation",
            Self::SecurityIncident => "security_incident",
            Self::AdminAction => "admin_action",
        }
    }
}

impl SessionTracker {
    /// Invalidate ALL sessions for a user due to a privilege or security event.
    /// Distinct from `remove_all_sessions` (GDPR deletion) -- this logs the reason.
    pub fn invalidate_sessions_for_user(
        &self,
        user_id: &Uuid,
        reason: SessionInvalidationReason,
    ) -> usize {
        let mut active = self.active.lock().unwrap_or_else(|e| {
            tracing::error!(
                target: "siem",
                category = "security",
                action = "mutex_poisoning_recovered",
                "SessionTracker mutex poisoned in invalidate_sessions_for_user - recovering"
            );
            e.into_inner()
        });
        let count = active
            .get(user_id)
            .map(|sessions| sessions.len())
            .unwrap_or(0);
        active.remove(user_id);

        if count > 0 {
            crate::siem::SecurityEvent::session_revoked(
                &user_id.to_string(),
                &format!("privilege_change:{}", reason.as_str()),
            );
            tracing::info!(
                target: "siem",
                user_id = %user_id,
                reason = reason.as_str(),
                sessions_invalidated = count,
                "SIEM:INFO All sessions invalidated for user due to privilege change"
            );
        }

        count
    }

    /// Hook called when a user's privileges change.
    pub fn on_privilege_change(
        &self,
        user_id: &Uuid,
        reason: SessionInvalidationReason,
    ) -> usize {
        self.invalidate_sessions_for_user(user_id, reason)
    }
}

impl DistributedSessionTracker {
    /// F6: On logout, walk the refresh token family and mark every token in
    /// the family as revoked. Creates the `refresh_token_family` table if it
    /// does not exist (migration 010 is the canonical DDL; this is safety net).
    pub async fn revoke_refresh_family_on_logout(
        &self,
        user_id: &Uuid,
        family_id: &Uuid,
    ) -> Result<u64, String> {
        // Defensive DDL — normally provided by migration 010.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS refresh_token_family (\
                token_id UUID PRIMARY KEY,\
                family_id UUID NOT NULL,\
                user_id UUID NOT NULL,\
                issued_at BIGINT NOT NULL,\
                expires_at BIGINT NOT NULL,\
                revoked BOOLEAN NOT NULL DEFAULT FALSE\
             )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| format!("ensure refresh_token_family table: {e}"))?;

        let result = sqlx::query(
            "UPDATE refresh_token_family SET revoked = TRUE \
             WHERE family_id = $1 AND user_id = $2 AND revoked = FALSE",
        )
        .bind(family_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("revoke refresh family: {e}"))?;

        tracing::info!(
            target: "siem",
            %user_id,
            %family_id,
            rows = result.rows_affected(),
            "SIEM:INFO F6 refresh token family revoked on logout"
        );
        Ok(result.rows_affected())
    }

    /// F6: Rotate (invalidate) the current session ID for `user_id` and
    /// replace it with a freshly issued one. Returns the new session UUID.
    /// The old session is removed both from the L1 cache and the DB.
    pub async fn rotate_session_id(
        &self,
        user_id: &Uuid,
        old_session_id: &Uuid,
        now: i64,
    ) -> Result<Uuid, String> {
        self.remove_session(user_id, old_session_id).await?;
        let new_session_id = Uuid::new_v4();
        self.register_session(*user_id, new_session_id, now).await?;
        tracing::info!(
            target: "siem",
            %user_id,
            old = %old_session_id,
            new = %new_session_id,
            "SIEM:INFO F6 session rotated"
        );
        Ok(new_session_id)
    }

    /// Invalidate all sessions for a user across cache and database.
    pub async fn invalidate_sessions_for_user(
        &self,
        user_id: &Uuid,
        reason: SessionInvalidationReason,
    ) -> Result<usize, String> {
        let cache_count = self.cache.invalidate_sessions_for_user(user_id, reason);

        let db_result = sqlx::query("DELETE FROM active_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("invalidate sessions in DB: {e}"))?;

        let db_count = db_result.rows_affected() as usize;
        let total = cache_count.max(db_count);

        tracing::info!(
            target: "siem",
            user_id = %user_id,
            reason = reason.as_str(),
            cache_invalidated = cache_count,
            db_invalidated = db_count,
            "SIEM:INFO DistributedSessionTracker: sessions invalidated on privilege change"
        );

        Ok(total)
    }

    /// Hook for privilege change events.
    pub async fn on_privilege_change(
        &self,
        user_id: &Uuid,
        reason: SessionInvalidationReason,
    ) -> Result<usize, String> {
        self.invalidate_sessions_for_user(user_id, reason).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_touch_session_updates_timestamp() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        tracker.register_session(user, session, 1000).unwrap();

        tracker.touch_session(&user, &session, 2000);
        // Session should not be cleaned up if touched recently
        let removed = tracker.cleanup_inactive(2500, 1000);
        assert_eq!(removed, 0);
        assert_eq!(tracker.active_count(&user), 1);
    }

    #[test]
    fn test_touch_session_noop_for_unknown() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        tracker.touch_session(&user, &session, 1000);
        // No panic, no-op for unknown session
    }

    #[test]
    fn test_cleanup_inactive_removes_old_sessions() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        tracker.register_session(user, s1, 1000).unwrap();
        tracker.register_session(user, s2, 2000).unwrap();

        // At time 2500, with timeout 1000: s1 (age 1500) should be removed, s2 (age 500) stays
        let removed = tracker.cleanup_inactive(2500, 1000);
        assert_eq!(removed, 1);
        assert_eq!(tracker.active_count(&user), 1);
    }

    #[test]
    fn test_cleanup_inactive_removes_all_expired() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        let s1 = Uuid::new_v4();
        tracker.register_session(user, s1, 1000).unwrap();

        let removed = tracker.cleanup_inactive(5000, 1000);
        assert_eq!(removed, 1);
        assert_eq!(tracker.active_count(&user), 0);
    }

    #[test]
    fn test_cleanup_inactive_returns_zero_when_none_expired() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        let s1 = Uuid::new_v4();
        tracker.register_session(user, s1, 1000).unwrap();

        let removed = tracker.cleanup_inactive(1500, 1000);
        assert_eq!(removed, 0);
        assert_eq!(tracker.active_count(&user), 1);
    }

    #[test]
    fn test_invalidate_sessions_for_user_removes_all() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        tracker.register_session(user, Uuid::new_v4(), 1000).unwrap();
        tracker.register_session(user, Uuid::new_v4(), 1000).unwrap();
        tracker.register_session(user, Uuid::new_v4(), 1000).unwrap();
        assert_eq!(tracker.active_count(&user), 3);

        let invalidated = tracker.invalidate_sessions_for_user(
            &user,
            SessionInvalidationReason::PasswordChanged,
        );
        assert_eq!(invalidated, 3);
        assert_eq!(tracker.active_count(&user), 0);
    }

    #[test]
    fn test_invalidate_does_not_affect_other_users() {
        let tracker = SessionTracker::new(5);
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        tracker.register_session(user_a, Uuid::new_v4(), 1000).unwrap();
        tracker.register_session(user_b, Uuid::new_v4(), 1000).unwrap();

        tracker.invalidate_sessions_for_user(
            &user_a,
            SessionInvalidationReason::RoleChanged,
        );
        assert_eq!(tracker.active_count(&user_a), 0);
        assert_eq!(tracker.active_count(&user_b), 1);
    }

    #[test]
    fn test_on_privilege_change_hook() {
        let tracker = SessionTracker::new(5);
        let user = Uuid::new_v4();
        tracker.register_session(user, Uuid::new_v4(), 1000).unwrap();

        let count = tracker.on_privilege_change(
            &user,
            SessionInvalidationReason::SecurityIncident,
        );
        assert_eq!(count, 1);
        assert_eq!(tracker.active_count(&user), 0);
    }

    #[test]
    fn test_invalidate_nonexistent_user() {
        let tracker = SessionTracker::new(5);
        let count = tracker.invalidate_sessions_for_user(
            &Uuid::new_v4(),
            SessionInvalidationReason::AdminAction,
        );
        assert_eq!(count, 0);
    }
}
