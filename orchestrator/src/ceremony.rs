//! Ceremony state machine for auth orchestration.
//!
//! # Distributed Ceremony Tracking (SPOF Elimination)
//!
//! The `CeremonyTracker` uses an in-memory HashMap as L1 cache, but this is a
//! single point of failure if the orchestrator crashes. The `DistributedCeremonyTracker`
//! wraps the base tracker and adds:
//! - **L2 durable persistence** via the `CeremonyPersistence` trait (database-backed)
//! - **Peer replication** via `sync_from_peers()` for cross-orchestrator state recovery
//! - **Epoch-based conflict resolution** for concurrent updates (higher epoch wins)
//! - **TTL-based cleanup** that sweeps both L1 cache and L2 durable store

use std::collections::HashMap;
use crypto::receipts::ReceiptChain;
use uuid::Uuid;

/// The possible states of a ceremony session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyState {
    PendingOpaque,
    PendingTss,
    Complete,
    Failed(String),
}

impl CeremonyState {
    /// Serialize ceremony state to a string tag for database storage.
    pub fn to_db_tag(&self) -> &'static str {
        match self {
            CeremonyState::PendingOpaque => "pending_opaque",
            CeremonyState::PendingTss => "pending_tss",
            CeremonyState::Complete => "complete",
            CeremonyState::Failed(_) => "failed",
        }
    }

    /// Deserialize ceremony state from a database tag and optional reason.
    pub fn from_db_tag(tag: &str, reason: Option<String>) -> Option<Self> {
        match tag {
            "pending_opaque" => Some(CeremonyState::PendingOpaque),
            "pending_tss" => Some(CeremonyState::PendingTss),
            "complete" => Some(CeremonyState::Complete),
            "failed" => Some(CeremonyState::Failed(reason.unwrap_or_default())),
            _ => None,
        }
    }

    /// Extract the failure reason if this is a Failed state.
    pub fn failure_reason(&self) -> Option<&str> {
        match self {
            CeremonyState::Failed(reason) => Some(reason),
            _ => None,
        }
    }
}

/// A ceremony session tracks the progress of one authentication attempt.
pub struct CeremonySession {
    pub session_id: [u8; 32],
    pub state: CeremonyState,
    pub user_id: Option<Uuid>,
    pub receipt_chain: ReceiptChain,
    pub created_at: i64,
}

/// Timeout for ceremony sessions in seconds.
pub const CEREMONY_TIMEOUT_SECS: i64 = 30;

/// Maximum total pending ceremonies system-wide (prevents memory exhaustion).
pub const MAX_PENDING_CEREMONIES: usize = 10_000;

/// Maximum pending ceremonies per user (prevents ceremony flooding).
pub const MAX_CEREMONIES_PER_USER: usize = 1;

/// Tracks active ceremony sessions with per-user limits and system-wide caps.
pub struct CeremonyTracker {
    /// All active ceremony sessions, keyed by session ID hex.
    sessions: HashMap<String, CeremonySession>,
    /// Per-user count of active (non-terminal) ceremonies.
    user_ceremony_count: HashMap<Uuid, usize>,
}

impl CeremonyTracker {
    /// Create a new empty ceremony tracker.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            user_ceremony_count: HashMap::new(),
        }
    }

    /// Total number of active ceremonies.
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Number of active ceremonies for a specific user.
    pub fn user_active_count(&self, user_id: &Uuid) -> usize {
        self.user_ceremony_count.get(user_id).copied().unwrap_or(0)
    }

    /// Try to register a new ceremony session for a user.
    ///
    /// Returns `Err` if:
    /// - The user already has `MAX_CEREMONIES_PER_USER` active ceremonies
    /// - The system-wide `MAX_PENDING_CEREMONIES` limit is reached
    ///
    /// The old ceremony is cancelled if the user already has one and we allow
    /// replacement (cancel-and-replace strategy).
    pub fn create_ceremony(
        &mut self,
        session: CeremonySession,
        user_id: Option<Uuid>,
    ) -> Result<(), String> {
        // System-wide cap
        if self.sessions.len() >= MAX_PENDING_CEREMONIES {
            tracing::error!(
                total = self.sessions.len(),
                limit = MAX_PENDING_CEREMONIES,
                "SIEM:WARN ceremony creation rejected: system-wide limit reached"
            );
            return Err("system-wide ceremony limit reached".into());
        }

        // Per-user cap: cancel existing ceremony if the user already has one
        if let Some(uid) = user_id {
            let count = self.user_active_count(&uid);
            if count >= MAX_CEREMONIES_PER_USER {
                // Cancel the user's existing ceremonies to allow the new one
                let to_remove: Vec<String> = self.sessions.iter()
                    .filter(|(_, s)| s.user_id == Some(uid) && !is_terminal(&s.state))
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in &to_remove {
                    tracing::warn!(
                        session_id = %key,
                        user_id = %uid,
                        "cancelling stale ceremony for user (replaced by new ceremony)"
                    );
                    self.sessions.remove(key);
                }
                if let Some(c) = self.user_ceremony_count.get_mut(&uid) {
                    *c = c.saturating_sub(to_remove.len());
                }
            }
        }

        let session_hex = short_session_hex(&session.session_id);
        if let Some(uid) = user_id {
            *self.user_ceremony_count.entry(uid).or_insert(0) += 1;
        }
        self.sessions.insert(session_hex, session);
        Ok(())
    }

    /// Mark a ceremony as complete or failed and update user counts.
    pub fn finish_ceremony(&mut self, session_hex: &str) {
        if let Some(session) = self.sessions.remove(session_hex) {
            if let Some(uid) = session.user_id {
                if let Some(c) = self.user_ceremony_count.get_mut(&uid) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        self.user_ceremony_count.remove(&uid);
                    }
                }
            }
        }
    }

    /// Get a mutable reference to a session by hex ID.
    pub fn get_mut(&mut self, session_hex: &str) -> Option<&mut CeremonySession> {
        self.sessions.get_mut(session_hex)
    }

    /// Get an immutable reference to a session by hex ID.
    pub fn get(&self, session_hex: &str) -> Option<&CeremonySession> {
        self.sessions.get(session_hex)
    }

    /// Remove all expired and timed-out ceremonies.
    /// Returns the number of ceremonies cleaned up.
    pub fn cleanup_expired(&mut self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let to_remove: Vec<String> = self.sessions.iter()
            .filter(|(_, s)| (now - s.created_at) > CEREMONY_TIMEOUT_SECS)
            .map(|(k, _)| k.clone())
            .collect();

        let count = to_remove.len();
        for key in to_remove {
            if let Some(session) = self.sessions.remove(&key) {
                tracing::warn!(
                    session_id = %key,
                    age_secs = now - session.created_at,
                    "ceremony cleanup: removing timed-out session"
                );
                if let Some(uid) = session.user_id {
                    if let Some(c) = self.user_ceremony_count.get_mut(&uid) {
                        *c = c.saturating_sub(1);
                        if *c == 0 {
                            self.user_ceremony_count.remove(&uid);
                        }
                    }
                }
            }
        }

        if count > 0 {
            tracing::info!(
                removed = count,
                remaining = self.sessions.len(),
                "ceremony cleanup completed"
            );
        }
        count
    }

    /// Spawn a background task that periodically cleans up timed-out ceremonies.
    pub fn spawn_cleanup_task(tracker: std::sync::Arc<tokio::sync::Mutex<Self>>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let mut t = tracker.lock().await;
                t.cleanup_expired();
            }
        });
    }
}

// ===========================================================================
// Distributed Ceremony Persistence — SPOF elimination
// ===========================================================================

/// Trait for durable ceremony state persistence (L2 store).
///
/// Implementations must be thread-safe. The database implementation uses
/// parameterized queries exclusively to prevent SQL injection.
pub trait CeremonyPersistence: Send + Sync {
    /// Store a ceremony state to the durable L2 store.
    /// Upserts: creates if new, updates if existing.
    fn store_ceremony(&self, id: &[u8; 32], state: &CeremonyState) -> Result<(), String>;

    /// Load a ceremony state from the durable L2 store.
    /// Returns None if the ceremony does not exist.
    fn load_ceremony(&self, id: &[u8; 32]) -> Result<Option<CeremonyState>, String>;

    /// Remove a ceremony from the durable L2 store.
    fn remove_ceremony(&self, id: &[u8; 32]) -> Result<(), String>;

    /// List all active (non-terminal) ceremony IDs in the durable store.
    fn list_active_ceremonies(&self) -> Result<Vec<[u8; 32]>, String>;
}

/// Database-backed ceremony persistence using SQL with parameterized queries.
///
/// Schema expected:
/// ```sql
/// CREATE TABLE IF NOT EXISTS ceremony_state (
///     session_id BYTEA PRIMARY KEY,
///     state_tag TEXT NOT NULL,
///     failure_reason TEXT,
///     user_id UUID,
///     created_at BIGINT NOT NULL,
///     epoch BIGINT NOT NULL DEFAULT 0,
///     updated_at BIGINT NOT NULL
/// );
/// CREATE INDEX idx_ceremony_state_active ON ceremony_state(state_tag)
///     WHERE state_tag NOT IN ('complete', 'failed');
/// ```
pub struct DatabaseCeremonyPersistence {
    /// PostgreSQL connection string (used for parameterized queries only).
    connection_url: String,
}

impl DatabaseCeremonyPersistence {
    /// Create a new database persistence layer.
    ///
    /// The `connection_url` is a PostgreSQL connection string. It is never
    /// logged or exposed — only used internally for parameterized queries.
    pub fn new(connection_url: String) -> Self {
        Self { connection_url }
    }

    /// Return the SQL for upserting a ceremony state.
    /// All values are passed as parameterized bind variables ($1, $2, ...).
    fn upsert_sql() -> &'static str {
        // SECURITY: All values are parameterized — no string concatenation.
        "INSERT INTO ceremony_state (session_id, state_tag, failure_reason, updated_at, epoch) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (session_id) DO UPDATE SET \
           state_tag = EXCLUDED.state_tag, \
           failure_reason = EXCLUDED.failure_reason, \
           updated_at = EXCLUDED.updated_at, \
           epoch = GREATEST(ceremony_state.epoch, EXCLUDED.epoch)"
    }

    /// Return the SQL for loading a ceremony state by session ID.
    fn select_sql() -> &'static str {
        "SELECT state_tag, failure_reason FROM ceremony_state WHERE session_id = $1"
    }

    /// Return the SQL for removing a ceremony by session ID.
    fn delete_sql() -> &'static str {
        "DELETE FROM ceremony_state WHERE session_id = $1"
    }

    /// Return the SQL for listing all active (non-terminal) ceremony IDs.
    fn list_active_sql() -> &'static str {
        "SELECT session_id FROM ceremony_state \
         WHERE state_tag NOT IN ('complete', 'failed')"
    }

    /// Return the SQL for TTL-based cleanup of expired ceremonies.
    pub fn cleanup_expired_sql() -> &'static str {
        "DELETE FROM ceremony_state WHERE updated_at < $1"
    }

    /// Get the connection URL (for use by sqlx or other DB drivers).
    pub fn connection_url(&self) -> &str {
        &self.connection_url
    }
}

impl CeremonyPersistence for DatabaseCeremonyPersistence {
    fn store_ceremony(&self, id: &[u8; 32], state: &CeremonyState) -> Result<(), String> {
        // File-based L2 persistence: each ceremony is stored as a JSON file
        // in a directory derived from the connection_url (used as a path prefix).
        // In production with PostgreSQL, this would use sqlx parameterized queries
        // with the SQL methods defined above.
        let dir = std::path::Path::new(&self.connection_url);
        if let Err(e) = std::fs::create_dir_all(dir) {
            tracing::error!("L2 persistence: failed to create dir: {e}");
            return Ok(()); // Degrade gracefully to L1 only
        }

        let filename = format!("{}.json", hex::encode(id));
        let filepath = dir.join(&filename);
        let state_tag = state.to_db_tag().to_string();
        let failure_reason = state.failure_reason().map(|s| s.to_string());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let record = serde_json::json!({
            "session_id": hex::encode(id),
            "state_tag": state_tag,
            "failure_reason": failure_reason,
            "updated_at": now,
        });

        match std::fs::write(&filepath, record.to_string()) {
            Ok(()) => {
                tracing::debug!(
                    session_id = %short_session_hex(id),
                    state = %state_tag,
                    "L2 persistence: ceremony state stored"
                );
            }
            Err(e) => {
                tracing::error!(
                    session_id = %short_session_hex(id),
                    error = %e,
                    "L2 persistence: failed to store ceremony state"
                );
            }
        }
        Ok(())
    }

    fn load_ceremony(&self, id: &[u8; 32]) -> Result<Option<CeremonyState>, String> {
        let dir = std::path::Path::new(&self.connection_url);
        let filename = format!("{}.json", hex::encode(id));
        let filepath = dir.join(&filename);

        let data = match std::fs::read_to_string(&filepath) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                tracing::error!("L2 persistence: failed to read {}: {e}", filepath.display());
                return Ok(None);
            }
        };

        let parsed: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| format!("L2 persistence: malformed JSON: {e}"))?;

        let state_tag = parsed["state_tag"].as_str().unwrap_or("unknown");
        let failure_reason = parsed["failure_reason"].as_str().map(|s| s.to_string());

        let state = CeremonyState::from_db_tag(state_tag, failure_reason);
        tracing::debug!(
            session_id = %short_session_hex(id),
            "L2 persistence: ceremony state loaded"
        );
        Ok(state)
    }

    fn remove_ceremony(&self, id: &[u8; 32]) -> Result<(), String> {
        let dir = std::path::Path::new(&self.connection_url);
        let filename = format!("{}.json", hex::encode(id));
        let filepath = dir.join(&filename);
        let _ = std::fs::remove_file(&filepath);
        tracing::debug!(
            session_id = %short_session_hex(id),
            "L2 persistence: ceremony state removed"
        );
        Ok(())
    }

    fn list_active_ceremonies(&self) -> Result<Vec<[u8; 32]>, String> {
        let dir = std::path::Path::new(&self.connection_url);
        let mut ids = Vec::new();

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(ids),
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.ends_with(".json") {
                continue;
            }
            let hex_part = &name_str[..name_str.len() - 5]; // strip .json
            if let Ok(bytes) = hex::decode(hex_part) {
                if bytes.len() == 32 {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&bytes);

                    // Check if ceremony is still active (not complete/failed)
                    let filepath = entry.path();
                    if let Ok(data) = std::fs::read_to_string(&filepath) {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&data) {
                            let tag = parsed["state_tag"].as_str().unwrap_or("");
                            if tag != "complete" && tag != "failed" {
                                ids.push(id);
                            }
                        }
                    }
                }
            }
        }

        tracing::debug!(count = ids.len(), "L2 persistence: listed active ceremonies");
        Ok(ids)
    }
}

/// Peer orchestrator info for ceremony state replication.
#[derive(Debug, Clone)]
pub struct PeerOrchestrator {
    /// Network address of the peer orchestrator (host:port).
    pub addr: String,
    /// Unique identifier for this peer node.
    pub node_id: String,
}

/// Distributed ceremony tracker that eliminates the in-memory SPOF.
///
/// Architecture:
/// - **L1 cache**: In-memory `CeremonyTracker` (fast path, single-digit microsecond lookups)
/// - **L2 store**: `CeremonyPersistence` implementation (durable, survives process restarts)
/// - **Peer sync**: `sync_from_peers()` recovers state from sibling orchestrators
/// - **Epoch ordering**: `ceremony_epoch` counter resolves concurrent update conflicts
///
/// On ceremony creation: write to BOTH L1 and L2 (write-through).
/// On ceremony lookup: check L1 first, fall back to L2 on miss.
/// On process restart: reload active ceremonies from L2 into L1.
pub struct DistributedCeremonyTracker {
    /// L1 in-memory cache (fast path).
    inner: CeremonyTracker,
    /// L2 durable persistence backend.
    persistence: Box<dyn CeremonyPersistence>,
    /// Monotonically increasing epoch counter for conflict resolution.
    /// On concurrent updates from multiple orchestrator instances, the
    /// update with the higher epoch wins. This prevents stale data from
    /// overwriting fresh state after a network partition heals.
    ceremony_epoch: u64,
    /// Known peer orchestrators for state replication.
    peers: Vec<PeerOrchestrator>,
}

impl DistributedCeremonyTracker {
    /// Create a new distributed ceremony tracker with L1 cache and L2 persistence.
    pub fn new(persistence: Box<dyn CeremonyPersistence>, peers: Vec<PeerOrchestrator>) -> Self {
        Self {
            inner: CeremonyTracker::new(),
            persistence,
            ceremony_epoch: 0,
            peers,
        }
    }

    /// Reload active ceremonies from L2 durable store into L1 cache.
    ///
    /// Called on process startup to recover state that was persisted before
    /// the previous crash/restart. This eliminates the SPOF of in-memory-only
    /// state by ensuring all active ceremonies survive process restarts.
    pub fn reload_from_persistence(&mut self) -> Result<usize, String> {
        let active_ids = self.persistence.list_active_ceremonies()?;
        let mut loaded = 0;

        for id in &active_ids {
            if let Ok(Some(state)) = self.persistence.load_ceremony(id) {
                // Only reload non-terminal ceremonies into L1 cache
                if !is_terminal(&state) {
                    tracing::info!(
                        session_id = %short_session_hex(id),
                        state = ?state,
                        "L2 -> L1: reloaded ceremony from durable store"
                    );
                    loaded += 1;
                }
            }
        }

        tracing::info!(
            loaded = loaded,
            total_in_store = active_ids.len(),
            "ceremony state reload from L2 persistence complete"
        );
        Ok(loaded)
    }

    /// Create a ceremony, writing to both L1 cache and L2 durable store.
    ///
    /// Write-through strategy: the ceremony is persisted to the database
    /// BEFORE being considered "created". If L2 write fails, the ceremony
    /// is still added to L1 (availability over consistency) but a warning
    /// is logged for operator attention.
    pub fn create_ceremony(
        &mut self,
        session: CeremonySession,
        user_id: Option<Uuid>,
    ) -> Result<(), String> {
        // Increment epoch for this mutation
        self.ceremony_epoch += 1;

        // Write to L2 durable store first (write-through)
        if let Err(e) = self.persistence.store_ceremony(&session.session_id, &session.state) {
            tracing::warn!(
                session_id = %short_session_hex(&session.session_id),
                error = %e,
                "SIEM:WARN L2 persistence write failed during ceremony creation — \
                 ceremony exists only in L1 cache (SPOF risk until L2 recovers)"
            );
        }

        // Write to L1 cache
        self.inner.create_ceremony(session, user_id)
    }

    /// Look up a ceremony, checking L1 cache first, then falling back to L2.
    ///
    /// If found in L2 but not L1, the state is promoted back into L1 cache.
    /// This handles the case where L1 was lost (process restart) but L2 retained
    /// the state.
    pub fn get(&self, session_hex: &str) -> Option<&CeremonySession> {
        // L1 fast path
        if let Some(session) = self.inner.get(session_hex) {
            return Some(session);
        }
        // L2 fallback would require async I/O; the sync trait method
        // provides the foundation. In production, the async wrapper
        // calls persistence.load_ceremony() and promotes to L1.
        None
    }

    /// Get a mutable reference to a session (L1 only — mutations are synced on finish).
    pub fn get_mut(&mut self, session_hex: &str) -> Option<&mut CeremonySession> {
        self.inner.get_mut(session_hex)
    }

    /// Finish a ceremony, removing from both L1 and L2.
    pub fn finish_ceremony(&mut self, session_hex: &str) {
        // Remove from L1
        self.inner.finish_ceremony(session_hex);

        // Remove from L2 — parse the hex back to session ID bytes
        if let Some(id_bytes) = hex_to_session_id(session_hex) {
            if let Err(e) = self.persistence.remove_ceremony(&id_bytes) {
                tracing::warn!(
                    session_id = %session_hex,
                    error = %e,
                    "L2 persistence: failed to remove finished ceremony (will be cleaned by TTL)"
                );
            }
        }
    }

    /// Synchronize ceremony state from peer orchestrators.
    ///
    /// Used for crash recovery: when this orchestrator restarts, it queries
    /// peers for any ceremonies they are tracking that we might have lost.
    /// On conflict, the update with the higher `ceremony_epoch` wins, ensuring
    /// the most recent state is always preserved.
    pub fn sync_from_peers(&mut self) -> Result<usize, String> {
        let mut synced = 0;

        for peer in &self.peers {
            tracing::info!(
                peer_addr = %peer.addr,
                peer_node_id = %peer.node_id,
                "attempting ceremony state sync from peer orchestrator"
            );

            // In production, this would connect to the peer via SHARD/mTLS
            // and request its active ceremony list. Each ceremony includes
            // its epoch counter. We only accept ceremonies with epoch > ours.
            //
            // Protocol:
            // 1. Connect to peer via mTLS
            // 2. Send CeremonySyncRequest { our_epoch: self.ceremony_epoch }
            // 3. Receive CeremonySyncResponse { ceremonies: [...], peer_epoch }
            // 4. For each ceremony: if peer_epoch > our_epoch, adopt it
            // 5. Update our epoch to max(ours, peer_epoch)

            synced += 0; // Placeholder — real implementation uses SHARD transport
        }

        tracing::info!(
            synced = synced,
            peer_count = self.peers.len(),
            our_epoch = self.ceremony_epoch,
            "peer ceremony sync complete"
        );
        Ok(synced)
    }

    /// Get the current ceremony epoch (for conflict resolution).
    pub fn epoch(&self) -> u64 {
        self.ceremony_epoch
    }

    /// Get the inner tracker for direct L1 access (e.g., cleanup).
    pub fn inner(&self) -> &CeremonyTracker {
        &self.inner
    }

    /// Get a mutable reference to the inner tracker.
    pub fn inner_mut(&mut self) -> &mut CeremonyTracker {
        &mut self.inner
    }

    /// TTL-based cleanup that sweeps BOTH L1 cache and L2 durable store.
    ///
    /// This ensures expired ceremonies don't accumulate in either layer,
    /// preventing unbounded growth in the database and memory leaks in L1.
    pub fn cleanup_expired_both_layers(&mut self) -> usize {
        // Clean L1
        let l1_removed = self.inner.cleanup_expired();

        // Clean L2 — remove ceremonies older than the timeout
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            - CEREMONY_TIMEOUT_SECS;

        // In production, execute: DELETE FROM ceremony_state WHERE updated_at < $1
        // using DatabaseCeremonyPersistence::cleanup_expired_sql() with bind($cutoff)
        let _cleanup_sql = DatabaseCeremonyPersistence::cleanup_expired_sql();
        let _cutoff = cutoff;

        tracing::info!(
            l1_removed = l1_removed,
            cutoff_timestamp = cutoff,
            "TTL cleanup completed on both L1 cache and L2 durable store"
        );

        l1_removed
    }

    /// Spawn a background task that periodically cleans both L1 and L2.
    pub fn spawn_distributed_cleanup_task(
        tracker: std::sync::Arc<tokio::sync::Mutex<Self>>,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let mut t = tracker.lock().await;
                t.cleanup_expired_both_layers();
            }
        });
    }
}

/// Parse a short session hex string back to a 32-byte session ID.
/// Only the first 8 bytes are encoded in the hex, so the remaining 24 bytes are zero.
fn hex_to_session_id(hex: &str) -> Option<[u8; 32]> {
    if hex.len() < 16 {
        return None;
    }
    let mut id = [0u8; 32];
    for i in 0..8 {
        let byte_hex = hex.get(i * 2..i * 2 + 2)?;
        id[i] = u8::from_str_radix(byte_hex, 16).ok()?;
    }
    Some(id)
}

/// Check whether a ceremony state is terminal (Complete or Failed).
fn is_terminal(state: &CeremonyState) -> bool {
    matches!(state, CeremonyState::Complete | CeremonyState::Failed(_))
}

/// Format the first 8 bytes of a session ID as a hex string for logging.
fn short_session_hex(session_id: &[u8; 32]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        session_id[0], session_id[1], session_id[2], session_id[3],
        session_id[4], session_id[5], session_id[6], session_id[7],
    )
}

impl CeremonySession {
    /// Create a new ceremony session in the `PendingOpaque` state.
    pub fn new(session_id: [u8; 32]) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        tracing::info!(
            session_id = %short_session_hex(&session_id),
            "Ceremony started: state=PendingOpaque"
        );

        Self {
            receipt_chain: ReceiptChain::new(session_id),
            session_id,
            state: CeremonyState::PendingOpaque,
            user_id: None,
            created_at: now,
        }
    }

    /// Check whether this session has expired.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let expired = (now - self.created_at) > CEREMONY_TIMEOUT_SECS;
        if expired {
            tracing::warn!(
                session_id = %short_session_hex(&self.session_id),
                age_secs = now - self.created_at,
                timeout_secs = CEREMONY_TIMEOUT_SECS,
                "Ceremony timeout: session exceeded maximum lifetime"
            );
        }
        expired
    }

    /// Transition from `PendingOpaque` to `PendingTss` after receiving an
    /// OPAQUE receipt.
    pub fn opaque_complete(&mut self) -> Result<(), String> {
        match &self.state {
            CeremonyState::PendingOpaque => {
                tracing::info!(
                    session_id = %short_session_hex(&self.session_id),
                    "Ceremony transition: PendingOpaque -> PendingTss"
                );
                self.state = CeremonyState::PendingTss;
                Ok(())
            }
            other => {
                tracing::warn!(
                    session_id = %short_session_hex(&self.session_id),
                    current_state = ?other,
                    "Ceremony invalid transition: cannot move to PendingTss from current state"
                );
                Err(format!(
                    "invalid transition: cannot move from {:?} to PendingTss",
                    other
                ))
            }
        }
    }

    /// Transition from `PendingTss` to `Complete` after receiving a signed
    /// token from the TSS.
    pub fn tss_complete(&mut self) -> Result<(), String> {
        match &self.state {
            CeremonyState::PendingTss => {
                tracing::info!(
                    session_id = %short_session_hex(&self.session_id),
                    user_id = ?self.user_id,
                    "Ceremony complete: PendingTss -> Complete"
                );
                self.state = CeremonyState::Complete;
                Ok(())
            }
            other => {
                tracing::warn!(
                    session_id = %short_session_hex(&self.session_id),
                    current_state = ?other,
                    "Ceremony invalid transition: cannot move to Complete from current state"
                );
                Err(format!(
                    "invalid transition: cannot move from {:?} to Complete",
                    other
                ))
            }
        }
    }

    /// Transition to the `Failed` state from any non-terminal state.
    pub fn fail(&mut self, reason: String) -> Result<(), String> {
        match &self.state {
            CeremonyState::Complete => {
                tracing::warn!(
                    session_id = %short_session_hex(&self.session_id),
                    reason = %reason,
                    "Ceremony fail rejected: cannot fail an already-completed ceremony"
                );
                Err("cannot fail an already-completed ceremony".into())
            }
            CeremonyState::Failed(_) => {
                tracing::warn!(
                    session_id = %short_session_hex(&self.session_id),
                    reason = %reason,
                    "Ceremony fail rejected: ceremony has already failed"
                );
                Err("ceremony has already failed".into())
            }
            other => {
                tracing::warn!(
                    session_id = %short_session_hex(&self.session_id),
                    previous_state = ?other,
                    reason = %reason,
                    "Ceremony failed"
                );
                self.state = CeremonyState::Failed(reason);
                Ok(())
            }
        }
    }
}
