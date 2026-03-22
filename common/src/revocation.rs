//! Token revocation list — bounded in-memory store with TTL-based cleanup.
//!
//! Provides O(1) revocation checks that run *before* expensive signature
//! verification, enabling fast rejection of compromised tokens.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of entries in the revocation list.
/// Bounded to prevent memory exhaustion from a flood of revocation commands.
const MAX_ENTRIES: usize = 100_000;

/// Maximum token lifetime in microseconds (8 hours).
/// Entries older than this are eligible for cleanup since the corresponding
/// tokens would have expired naturally.
const MAX_TOKEN_LIFETIME_US: i64 = 8 * 60 * 60 * 1_000_000;

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
pub struct RevocationList {
    /// Maps token_id -> revocation timestamp (microseconds since UNIX epoch).
    entries: HashMap<[u8; 16], i64>,
}

impl RevocationList {
    /// Create a new empty revocation list.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
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
        if self.entries.contains_key(&token_id) {
            return false;
        }

        // If at capacity, attempt cleanup first
        if self.entries.len() >= MAX_ENTRIES {
            self.cleanup();
        }

        // If still at capacity after cleanup, reject to prevent unbounded growth
        if self.entries.len() >= MAX_ENTRIES {
            return false;
        }

        self.entries.insert(token_id, Self::now_us());
        true
    }

    /// Check if a token has been revoked.
    ///
    /// This is an O(1) HashMap lookup designed to run before expensive
    /// cryptographic signature verification.
    pub fn is_revoked(&self, token_id: &[u8; 16]) -> bool {
        self.entries.contains_key(token_id)
    }

    /// Remove entries older than the maximum token lifetime (8 hours).
    ///
    /// Tokens older than MAX_TOKEN_LIFETIME_US would have expired naturally,
    /// so their revocation entries are no longer needed.
    pub fn cleanup(&mut self) {
        let cutoff = Self::now_us() - MAX_TOKEN_LIFETIME_US;
        self.entries.retain(|_, &mut ts| ts > cutoff);
    }

    /// Number of entries currently in the revocation list.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the revocation list is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for RevocationList {
    fn default() -> Self {
        Self::new()
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
    }

    #[test]
    fn cleanup_removes_old_entries() {
        let mut rl = RevocationList::new();
        let id = [0x01; 16];

        // Insert with an artificially old timestamp
        let old_ts = RevocationList::now_us() - MAX_TOKEN_LIFETIME_US - 1_000_000;
        rl.entries.insert(id, old_ts);
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
}
