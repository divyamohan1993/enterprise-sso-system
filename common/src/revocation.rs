//! Token revocation list — bounded in-memory store with TTL-based cleanup.
//!
//! Provides O(1) revocation checks that run *before* expensive signature
//! verification, enabling fast rejection of compromised tokens.
//!
//! Two layers are provided:
//! - [`RevocationList`]: the inner data structure (not thread-safe).
//! - [`SharedRevocationList`]: an `Arc<RwLock<...>>` wrapper for concurrent use,
//!   with built-in lazy cleanup that triggers at most once per 60 seconds.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of entries in the revocation list.
/// Bounded to prevent memory exhaustion from a flood of revocation commands.
const MAX_ENTRIES: usize = 100_000;

/// Maximum token lifetime in microseconds (8 hours).
/// Entries older than this are eligible for cleanup since the corresponding
/// tokens would have expired naturally.
const MAX_TOKEN_LIFETIME_US: i64 = 8 * 60 * 60 * 1_000_000;

/// Minimum interval between lazy cleanups, in microseconds (60 seconds).
const LAZY_CLEANUP_INTERVAL_US: i64 = 60 * 1_000_000;

/// A revocation command sent over the SHARD protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationCommand {
    /// The token_id of the token to revoke.
    pub token_id: [u8; 16],
    /// Optional reason for audit trail.
    pub reason: RevocationReason,
}

/// Why a token was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Administrative revocation (e.g., user deprovisioned).
    Administrative,
    /// Token suspected compromised.
    Compromised,
    /// User-initiated logout / session termination.
    UserLogout,
    /// Duress signal detected.
    Duress,
}

/// In-memory revocation list with bounded capacity and TTL cleanup.
///
/// Uses a `HashSet` for O(1) membership checks and a parallel `HashMap` to
/// track revocation timestamps for TTL-based expiry.
pub struct RevocationList {
    /// Set of revoked token_ids for O(1) membership lookup.
    revoked_ids: HashSet<[u8; 16]>,
    /// Maps token_id -> revocation timestamp (microseconds since UNIX epoch).
    revocation_times: HashMap<[u8; 16], i64>,
}

impl RevocationList {
    /// Create a new empty revocation list.
    pub fn new() -> Self {
        Self {
            revoked_ids: HashSet::new(),
            revocation_times: HashMap::new(),
        }
    }

    /// Returns the current timestamp in microseconds since UNIX epoch.
    fn now_us() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64
    }

    /// Revoke a token by its unique identifier.
    ///
    /// Returns `true` if the token was newly revoked, `false` if it was
    /// already in the revocation list or the list is at capacity (after cleanup).
    pub fn revoke(&mut self, token_id: [u8; 16]) -> bool {
        // If already revoked, no-op
        if self.revoked_ids.contains(&token_id) {
            return false;
        }

        // If at capacity, attempt cleanup first
        if self.revoked_ids.len() >= MAX_ENTRIES {
            self.cleanup();
        }

        // If still at capacity after cleanup, reject to prevent unbounded growth
        if self.revoked_ids.len() >= MAX_ENTRIES {
            return false;
        }

        let now = Self::now_us();
        self.revoked_ids.insert(token_id);
        self.revocation_times.insert(token_id, now);
        true
    }

    /// Check if a token has been revoked.
    ///
    /// This is an O(1) HashSet lookup designed to run before expensive
    /// cryptographic signature verification.
    pub fn is_revoked(&self, token_id: &[u8; 16]) -> bool {
        self.revoked_ids.contains(token_id)
    }

    /// Remove entries older than the maximum token lifetime (8 hours).
    ///
    /// Tokens older than MAX_TOKEN_LIFETIME_US would have expired naturally,
    /// so their revocation entries are no longer needed.
    pub fn cleanup(&mut self) {
        let cutoff = Self::now_us() - MAX_TOKEN_LIFETIME_US;
        self.cleanup_expired_cutoff(cutoff);
    }

    /// Remove entries whose revocation timestamp is older than `max_token_lifetime_secs`
    /// seconds ago.
    ///
    /// This allows callers to specify a custom lifetime rather than using the
    /// default 8-hour window.
    pub fn cleanup_expired(&mut self, max_token_lifetime_secs: i64) {
        let cutoff = Self::now_us() - (max_token_lifetime_secs * 1_000_000);
        self.cleanup_expired_cutoff(cutoff);
    }

    /// Internal: remove all entries with revocation timestamp <= cutoff (microseconds).
    fn cleanup_expired_cutoff(&mut self, cutoff: i64) {
        self.revocation_times.retain(|token_id, &mut ts| {
            if ts <= cutoff {
                self.revoked_ids.remove(token_id);
                false
            } else {
                true
            }
        });
    }

    /// Number of entries currently in the revocation list.
    pub fn revoked_count(&self) -> usize {
        self.revoked_ids.len()
    }

    /// Number of entries currently in the revocation list (alias for backward compat).
    pub fn len(&self) -> usize {
        self.revoked_ids.len()
    }

    /// Whether the revocation list is empty.
    pub fn is_empty(&self) -> bool {
        self.revoked_ids.is_empty()
    }
}

impl Default for RevocationList {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Thread-safe wrapper with lazy cleanup
// ---------------------------------------------------------------------------

/// Thread-safe revocation list with lazy cleanup.
///
/// Wraps a `RevocationList` in `Arc<RwLock<...>>` for safe concurrent access
/// across async tasks. Includes a lazy cleanup mechanism that automatically
/// purges expired entries during verification if more than 60 seconds have
/// elapsed since the last cleanup.
pub struct SharedRevocationList {
    inner: Arc<RwLock<RevocationList>>,
    /// Timestamp (microseconds) of last cleanup, protected by its own lock
    /// to allow read-path lazy cleanup without write-locking the main list
    /// unless cleanup is actually needed.
    last_cleanup: Arc<RwLock<i64>>,
}

impl SharedRevocationList {
    /// Create a new shared revocation list.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RevocationList::new())),
            last_cleanup: Arc::new(RwLock::new(0)),
        }
    }

    /// Revoke a token. Returns `true` if newly revoked.
    pub fn revoke(&self, token_id: [u8; 16]) -> bool {
        let mut list = self.inner.write().unwrap();
        list.revoke(token_id)
    }

    /// Check if a token has been revoked (O(1) lookup).
    pub fn is_revoked(&self, token_id: &[u8; 16]) -> bool {
        let list = self.inner.read().unwrap();
        list.is_revoked(token_id)
    }

    /// Remove entries older than `max_token_lifetime_secs`.
    pub fn cleanup_expired(&self, max_token_lifetime_secs: i64) {
        let mut list = self.inner.write().unwrap();
        list.cleanup_expired(max_token_lifetime_secs);
        // Update last cleanup timestamp
        if let Ok(mut ts) = self.last_cleanup.write() {
            *ts = RevocationList::now_us();
        }
    }

    /// Number of currently revoked tokens.
    pub fn revoked_count(&self) -> usize {
        let list = self.inner.read().unwrap();
        list.revoked_count()
    }

    /// Perform lazy cleanup if more than 60 seconds have elapsed since last cleanup.
    ///
    /// This is designed to be called from the verification hot path. It only
    /// acquires the write lock when cleanup is actually needed.
    pub fn maybe_lazy_cleanup(&self, max_token_lifetime_secs: i64) {
        let now = RevocationList::now_us();
        let needs_cleanup = {
            let last = self.last_cleanup.read().unwrap();
            (now - *last) >= LAZY_CLEANUP_INTERVAL_US
        };
        if needs_cleanup {
            self.cleanup_expired(max_token_lifetime_secs);
        }
    }

    /// Run the default cleanup (8-hour window).
    pub fn cleanup(&self) {
        let mut list = self.inner.write().unwrap();
        list.cleanup();
        if let Ok(mut ts) = self.last_cleanup.write() {
            *ts = RevocationList::now_us();
        }
    }

    /// Number of entries (alias for backward compat).
    pub fn len(&self) -> usize {
        self.revoked_count()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.revoked_count() == 0
    }
}

impl Default for SharedRevocationList {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SharedRevocationList {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            last_cleanup: Arc::clone(&self.last_cleanup),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_and_check() {
        let mut rl = RevocationList::new();
        let id = [0xAB; 16];

        assert!(!rl.is_revoked(&id));
        assert!(rl.revoke(id));
        assert!(rl.is_revoked(&id));
        // Double revoke returns false
        assert!(!rl.revoke(id));
        assert_eq!(rl.len(), 1);
        assert_eq!(rl.revoked_count(), 1);
    }

    #[test]
    fn cleanup_removes_old_entries() {
        let mut rl = RevocationList::new();
        let id = [0x01; 16];

        // Insert with an artificially old timestamp
        let old_ts = RevocationList::now_us() - MAX_TOKEN_LIFETIME_US - 1_000_000;
        rl.revoked_ids.insert(id);
        rl.revocation_times.insert(id, old_ts);
        assert!(rl.is_revoked(&id));

        rl.cleanup();
        assert!(!rl.is_revoked(&id));
        assert!(rl.is_empty());
    }

    #[test]
    fn cleanup_keeps_recent_entries() {
        let mut rl = RevocationList::new();
        let id = [0x02; 16];

        rl.revoke(id);
        rl.cleanup();
        assert!(rl.is_revoked(&id));
    }

    #[test]
    fn cleanup_expired_custom_lifetime() {
        let mut rl = RevocationList::new();
        let id = [0x03; 16];

        // Insert with a timestamp 120 seconds ago
        let old_ts = RevocationList::now_us() - 120 * 1_000_000;
        rl.revoked_ids.insert(id);
        rl.revocation_times.insert(id, old_ts);
        assert!(rl.is_revoked(&id));

        // Cleanup with 60-second lifetime should remove it
        rl.cleanup_expired(60);
        assert!(!rl.is_revoked(&id));
    }

    #[test]
    fn cleanup_expired_keeps_recent() {
        let mut rl = RevocationList::new();
        let id = [0x04; 16];

        rl.revoke(id);
        // Cleanup with 3600-second lifetime should keep recently added entry
        rl.cleanup_expired(3600);
        assert!(rl.is_revoked(&id));
    }

    #[test]
    fn bounded_capacity() {
        let mut rl = RevocationList::new();

        // Fill to capacity with entries that have recent timestamps
        // (so cleanup won't remove them)
        for i in 0..MAX_ENTRIES {
            let mut id = [0u8; 16];
            let bytes = (i as u128).to_le_bytes();
            id.copy_from_slice(&bytes);
            rl.revoke(id);
        }

        assert_eq!(rl.len(), MAX_ENTRIES);

        // Next insertion should fail (entries are recent, cleanup won't help)
        let overflow_id = [0xFF; 16];
        assert!(!rl.revoke(overflow_id));
        assert!(!rl.is_revoked(&overflow_id));
    }

    #[test]
    fn shared_revocation_list_basic() {
        let srl = SharedRevocationList::new();
        let id = [0xCD; 16];

        assert!(!srl.is_revoked(&id));
        assert!(srl.revoke(id));
        assert!(srl.is_revoked(&id));
        assert!(!srl.revoke(id)); // duplicate
        assert_eq!(srl.revoked_count(), 1);
        assert_eq!(srl.len(), 1);
    }

    #[test]
    fn shared_revocation_list_cleanup_expired() {
        let srl = SharedRevocationList::new();
        let id = [0xEF; 16];

        // Insert with an artificially old timestamp via inner list
        {
            let mut list = srl.inner.write().unwrap();
            let old_ts = RevocationList::now_us() - 200 * 1_000_000;
            list.revoked_ids.insert(id);
            list.revocation_times.insert(id, old_ts);
        }
        assert!(srl.is_revoked(&id));

        srl.cleanup_expired(60); // 60-second lifetime
        assert!(!srl.is_revoked(&id));
        assert_eq!(srl.revoked_count(), 0);
    }

    #[test]
    fn shared_clone_shares_state() {
        let srl = SharedRevocationList::new();
        let clone = srl.clone();
        let id = [0xAA; 16];

        srl.revoke(id);
        assert!(clone.is_revoked(&id));
    }
}
