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
use std::path::PathBuf;
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

/// Default persistence path in production.
const DEFAULT_PERSISTENCE_PATH: &str = "/var/lib/milnet/revocations.dat";

/// Line count threshold that triggers file compaction.
const COMPACTION_THRESHOLD: usize = 10_000;

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
    /// Optional path to the append-only persistence file.
    persistence_path: Option<PathBuf>,
}

impl RevocationList {
    /// Create a new empty revocation list.
    ///
    /// In production (`MILNET_PRODUCTION=1`), persistence is mandatory and
    /// defaults to `/var/lib/milnet/revocations.dat`. The constructor will
    /// panic if it cannot establish a persistence path in production mode.
    pub fn new() -> Self {
        let is_production = std::env::var("MILNET_PRODUCTION")
            .map(|v| v == "1")
            .unwrap_or(false);

        let persistence_path = if is_production {
            Some(PathBuf::from(DEFAULT_PERSISTENCE_PATH))
        } else {
            None
        };

        let mut this = Self {
            revoked_ids: HashSet::new(),
            revocation_times: HashMap::new(),
            persistence_path,
        };
        this.load_from_file();
        this
    }

    /// Create a new revocation list with an explicit persistence path.
    ///
    /// Loads any previously persisted (non-expired) entries from the file.
    pub fn with_persistence(path: PathBuf) -> Self {
        let mut this = Self {
            revoked_ids: HashSet::new(),
            revocation_times: HashMap::new(),
            persistence_path: Some(path),
        };
        this.load_from_file();
        this
    }

    /// Returns the current timestamp in microseconds since UNIX epoch.
    fn now_us() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64
    }

    // ------------------------------------------------------------------
    // Persistence helpers
    // ------------------------------------------------------------------

    /// Compute HMAC-SHA512 over revocation data for integrity verification.
    /// The HMAC key is derived from the master KEK via HKDF-SHA512, preventing
    /// forgery by anyone who merely reads the source code.
    fn compute_revocation_hmac(data: &[u8]) -> [u8; 64] {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        use hkdf::Hkdf;
        type HmacSha512 = Hmac<Sha512>;
        // Derive HMAC key from master KEK — not a hardcoded string
        let master_kek = crate::sealed_keys::cached_master_kek();
        let hk = Hkdf::<Sha512>::new(Some(b"MILNET-REVOCATION-INTEGRITY-v2"), master_kek);
        let mut derived_key = [0u8; 64];
        if let Err(e) = hk.expand(b"revocation-file-hmac", &mut derived_key) {
            tracing::error!("FATAL: HKDF-SHA512 expand failed for revocation HMAC key: {e}");
            std::process::exit(1);
        }
        let mut mac = HmacSha512::new_from_slice(&derived_key).unwrap_or_else(|e| {
            tracing::error!("FATAL: HMAC-SHA512 key init failed for revocation integrity: {e}");
            std::process::exit(1);
        });
        // Zeroize derived key after creating MAC
        use zeroize::Zeroize;
        derived_key.zeroize();
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&result);
        out
    }

    /// Securely erase a file by overwriting its contents with random data before removal.
    fn secure_erase_file(path: &std::path::Path) -> Result<(), String> {
        use std::io::Write;
        if let Ok(metadata) = std::fs::metadata(path) {
            let size = metadata.len() as usize;
            if size > 0 {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map_err(|e| format!("secure erase open: {e}"))?;
                let mut zeros = vec![0u8; size.min(4096)];
                getrandom::getrandom(&mut zeros).ok(); // random overwrite
                let mut written = 0;
                while written < size {
                    let chunk = zeros.len().min(size - written);
                    file.write_all(&zeros[..chunk]).map_err(|e| format!("secure erase: {e}"))?;
                    written += chunk;
                }
                file.sync_all().map_err(|e| format!("secure erase sync: {e}"))?;
            }
        }
        Ok(())
    }

    /// Rewrite the persistence file with the given content and append an HMAC line.
    fn write_with_hmac(path: &std::path::Path, content: &[u8]) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("write_with_hmac open: {e}"))?;
        file.write_all(content)
            .map_err(|e| format!("write_with_hmac write: {e}"))?;
        let hmac = Self::compute_revocation_hmac(content);
        writeln!(file, "HMAC:{}", hex::encode(hmac))
            .map_err(|e| format!("write_with_hmac hmac: {e}"))?;
        file.flush().map_err(|e| format!("write_with_hmac flush: {e}"))?;
        Ok(())
    }

    /// Append a single revocation entry to the persistence file.
    fn persist_revocation(&self, token_id: &[u8; 16], expires_at: i64) -> Result<(), String> {
        if let Some(ref path) = self.persistence_path {
            // Read existing data lines (strip old HMAC if present), append new entry, rewrite with HMAC
            let existing = std::fs::read_to_string(path).unwrap_or_default();
            let mut data_lines = String::new();
            for line in existing.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with("HMAC:") {
                    continue;
                }
                data_lines.push_str(line);
                data_lines.push('\n');
            }
            data_lines.push_str(&format!("{},{}\n", hex::encode(token_id), expires_at));
            Self::write_with_hmac(path, data_lines.as_bytes())?;
        }
        Ok(())
    }

    /// Load non-expired entries from the persistence file on startup.
    ///
    /// Verifies HMAC-SHA512 integrity before trusting file contents.
    fn load_from_file(&mut self) {
        let path = match self.persistence_path {
            Some(ref p) => p.clone(),
            None => return,
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return, // File doesn't exist yet — first run
        };

        // Separate data lines from HMAC line
        let mut data_lines = String::new();
        let mut stored_hmac_hex: Option<String> = None;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(hmac_str) = trimmed.strip_prefix("HMAC:") {
                stored_hmac_hex = Some(hmac_str.to_string());
            } else {
                data_lines.push_str(line);
                data_lines.push('\n');
            }
        }

        // Verify HMAC integrity if an HMAC line is present
        if let Some(ref hmac_hex) = stored_hmac_hex {
            let stored_hmac = match hex::decode(hmac_hex) {
                Ok(b) if b.len() == 64 => b,
                _ => {
                    tracing::error!(
                        target: "siem",
                        event = "revocation_integrity_failure",
                        severity = 10,
                        "CRITICAL: Revocation file HMAC is malformed — possible tampering. \
                         Refusing to load revocation data from {:?}",
                        path,
                    );
                    return;
                }
            };
            let computed_hmac = Self::compute_revocation_hmac(data_lines.as_bytes());
            // Constant-time comparison to prevent timing attacks
            use subtle::ConstantTimeEq;
            if stored_hmac.ct_eq(&computed_hmac).unwrap_u8() != 1 {
                tracing::error!(
                    target: "siem",
                    event = "revocation_integrity_failure",
                    severity = 10,
                    "CRITICAL: Revocation file HMAC verification FAILED — data has been \
                     tampered with. Refusing to load revocation data from {:?}",
                    path,
                );
                return;
            }
        }

        let now = Self::now_us();
        for line in data_lines.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(2, ',').collect();
            if parts.len() != 2 {
                continue;
            }
            let token_bytes = match hex::decode(parts[0]) {
                Ok(b) if b.len() == 16 => b,
                _ => continue,
            };
            let expires_at: i64 = match parts[1].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Skip expired entries
            if expires_at <= now {
                continue;
            }
            let mut id = [0u8; 16];
            id.copy_from_slice(&token_bytes);
            // Derive the original revocation timestamp from expires_at
            let revoked_at = expires_at - MAX_TOKEN_LIFETIME_US;
            self.revoked_ids.insert(id);
            self.revocation_times.insert(id, revoked_at);
        }
    }

    /// Compact the persistence file by rewriting it with only non-expired entries.
    ///
    /// The compacted file is written to a temp file with HMAC integrity, then the
    /// old file is securely erased before the temp file is renamed into place.
    fn maybe_compact(&self) {
        let path = match self.persistence_path {
            Some(ref p) => p.clone(),
            None => return,
        };
        // Count lines in the current file
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        let line_count = content.lines().count();
        if line_count < COMPACTION_THRESHOLD {
            return;
        }
        // Rewrite with only current in-memory entries (which are already pruned of expired)
        let tmp_path = path.with_extension("dat.tmp");
        let result = (|| -> Result<(), String> {
            // Build data content
            let mut data = String::new();
            for (id, &revoked_at) in &self.revocation_times {
                let expires_at = revoked_at + MAX_TOKEN_LIFETIME_US;
                data.push_str(&format!("{},{}\n", hex::encode(id), expires_at));
            }
            // Write temp file with HMAC integrity
            Self::write_with_hmac(&tmp_path, data.as_bytes())?;
            // Securely erase old revocation file before replacement
            Self::secure_erase_file(&path)?;
            std::fs::rename(&tmp_path, &path)
                .map_err(|e| format!("compaction rename failed: {e}"))?;
            Ok(())
        })();
        if let Err(e) = result {
            tracing::warn!(target: "siem", "Revocation file compaction failed: {e}");
        }
    }

    /// 90% capacity threshold for SIEM alerting.
    const CAPACITY_WARN_THRESHOLD: usize = MAX_ENTRIES * 90 / 100;

    /// Revoke a token by its unique identifier.
    ///
    /// Returns `true` if the token was newly revoked, `false` if it was
    /// already in the revocation list or the list is at capacity (after cleanup
    /// and eviction of the oldest entries).
    pub fn revoke(&mut self, token_id: [u8; 16]) -> bool {
        // If already revoked, no-op
        if self.revoked_ids.contains(&token_id) {
            return false;
        }

        // If at capacity, attempt cleanup first
        if self.revoked_ids.len() >= MAX_ENTRIES {
            self.cleanup();
        }

        // If still at capacity after cleanup, evict the oldest entries to make room
        if self.revoked_ids.len() >= MAX_ENTRIES {
            self.evict_oldest(MAX_ENTRIES / 10); // Evict 10% of entries
        }

        let now = Self::now_us();
        let expires_at = now + MAX_TOKEN_LIFETIME_US;

        // Persist before updating in-memory state for crash safety
        if let Err(e) = self.persist_revocation(&token_id, expires_at) {
            tracing::error!(target: "siem", "Failed to persist revocation: {e}");
        }

        self.revoked_ids.insert(token_id);
        self.revocation_times.insert(token_id, now);

        // Periodic compaction when persistence file grows too large
        self.maybe_compact();

        // Emit SIEM alert when crossing the 90% capacity threshold
        if self.revoked_ids.len() == Self::CAPACITY_WARN_THRESHOLD {
            tracing::error!(
                target: "siem",
                category = "security",
                action = "revocation_list_near_capacity",
                count = self.revoked_ids.len(),
                max = MAX_ENTRIES,
                "Revocation list at 90% capacity ({}/{})",
                self.revoked_ids.len(),
                MAX_ENTRIES,
            );
        }

        true
    }

    /// Evict the `count` oldest entries from the revocation list.
    fn evict_oldest(&mut self, count: usize) {
        // SIEM CRITICAL: capacity-based eviction may indicate a revocation flooding attack
        tracing::error!(
            target: "siem",
            event = "revocation_capacity_critical",
            severity = 9,
            "Revocation list at capacity ({} entries) — evicting oldest 10%. \
             Possible revocation flooding attack.",
            self.revoked_ids.len()
        );

        let mut entries: Vec<([u8; 16], i64)> = self.revocation_times.iter()
            .map(|(id, ts)| (*id, *ts))
            .collect();
        entries.sort_by_key(|(_id, ts)| *ts);

        for (id, _ts) in entries.into_iter().take(count) {
            self.revoked_ids.remove(&id);
            self.revocation_times.remove(&id);
        }
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
        Self {
            revoked_ids: HashSet::new(),
            revocation_times: HashMap::new(),
            persistence_path: None,
        }
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

    /// Create a new shared revocation list with an explicit persistence path.
    pub fn with_persistence(path: PathBuf) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RevocationList::with_persistence(path))),
            last_cleanup: Arc::new(RwLock::new(0)),
        }
    }

    /// Revoke a token. Returns `true` if newly revoked.
    pub fn revoke(&self, token_id: [u8; 16]) -> bool {
        let mut list = crate::sync::siem_write(&self.inner, "revocation::revoke");
        list.revoke(token_id)
    }

    /// Check if a token has been revoked (O(1) lookup).
    pub fn is_revoked(&self, token_id: &[u8; 16]) -> bool {
        let list = crate::sync::siem_read(&self.inner, "revocation::is_revoked");
        list.is_revoked(token_id)
    }

    /// Remove entries older than `max_token_lifetime_secs`.
    pub fn cleanup_expired(&self, max_token_lifetime_secs: i64) {
        let mut list = crate::sync::siem_write(&self.inner, "revocation::cleanup_expired");
        list.cleanup_expired(max_token_lifetime_secs);
        // Update last cleanup timestamp
        if let Ok(mut ts) = self.last_cleanup.write() {
            *ts = RevocationList::now_us();
        }
    }

    /// Number of currently revoked tokens.
    pub fn revoked_count(&self) -> usize {
        let list = crate::sync::siem_read(&self.inner, "revocation::revoked_count");
        list.revoked_count()
    }

    /// Perform lazy cleanup if more than 60 seconds have elapsed since last cleanup.
    ///
    /// This is designed to be called from the verification hot path. It only
    /// acquires the write lock when cleanup is actually needed.
    pub fn maybe_lazy_cleanup(&self, max_token_lifetime_secs: i64) {
        let now = RevocationList::now_us();
        let needs_cleanup = {
            let last = crate::sync::siem_read(&self.last_cleanup, "revocation::maybe_lazy_cleanup");
            (now - *last) >= LAZY_CLEANUP_INTERVAL_US
        };
        if needs_cleanup {
            self.cleanup_expired(max_token_lifetime_secs);
        }
    }

    /// Run the default cleanup (8-hour window).
    pub fn cleanup(&self) {
        let mut list = crate::sync::siem_write(&self.inner, "revocation::cleanup");
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

        // Next insertion evicts the oldest 10% and succeeds
        let overflow_id = [0xFF; 16];
        assert!(rl.revoke(overflow_id));
        assert!(rl.is_revoked(&overflow_id));
        // After eviction of 10% + adding 1, size should be 90% + 1
        assert_eq!(rl.len(), MAX_ENTRIES - MAX_ENTRIES / 10 + 1);
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

    #[test]
    fn persistence_roundtrip() {
        let dir = std::env::temp_dir().join(format!("revocation_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("revocations.dat");
        let _ = std::fs::remove_file(&path); // clean slate

        let id1 = [0x10; 16];
        let id2 = [0x20; 16];

        // Revoke two tokens with persistence
        {
            let mut rl = RevocationList::with_persistence(path.clone());
            assert!(rl.revoke(id1));
            assert!(rl.revoke(id2));
            assert_eq!(rl.len(), 2);
        }

        // Simulate restart: create a new list from the same file
        {
            let rl = RevocationList::with_persistence(path.clone());
            assert!(rl.is_revoked(&id1), "id1 should survive restart");
            assert!(rl.is_revoked(&id2), "id2 should survive restart");
            assert_eq!(rl.len(), 2);
        }

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn persistence_filters_expired_on_load() {
        let dir = std::env::temp_dir().join(format!("revocation_expired_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("revocations.dat");
        let _ = std::fs::remove_file(&path);

        let id_valid = [0x30; 16];
        let id_expired = [0x40; 16];

        // Write a file with one valid and one expired entry
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path).unwrap();
            let now = RevocationList::now_us();
            let future_expires = now + MAX_TOKEN_LIFETIME_US;
            let past_expires = now - 1_000_000; // already expired
            writeln!(f, "{},{}", hex::encode(id_valid), future_expires).unwrap();
            writeln!(f, "{},{}", hex::encode(id_expired), past_expires).unwrap();
        }

        let rl = RevocationList::with_persistence(path.clone());
        assert!(rl.is_revoked(&id_valid), "valid entry should be loaded");
        assert!(!rl.is_revoked(&id_expired), "expired entry should be skipped");
        assert_eq!(rl.len(), 1);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn shared_persistence_roundtrip() {
        let dir = std::env::temp_dir().join(format!("shared_persist_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("revocations.dat");
        let _ = std::fs::remove_file(&path);

        let id = [0x50; 16];

        {
            let srl = SharedRevocationList::with_persistence(path.clone());
            assert!(srl.revoke(id));
        }

        {
            let srl = SharedRevocationList::with_persistence(path.clone());
            assert!(srl.is_revoked(&id), "should survive restart via SharedRevocationList");
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}

/// Database-backed revocation list that maintains O(1) in-memory lookups
/// while persisting all revocations to PostgreSQL for durability.
pub struct PersistentRevocationList {
    memory: SharedRevocationList,
    pool: sqlx::PgPool,
}

impl PersistentRevocationList {
    pub async fn new(pool: sqlx::PgPool) -> Result<Self, String> {
        let memory = SharedRevocationList::new();
        let prl = Self { memory, pool };
        prl.load_from_db().await?;
        Ok(prl)
    }
    async fn load_from_db(&self) -> Result<(), String> {
        let now = RevocationList::now_us();
        let rows: Vec<(Vec<u8>, i64)> = sqlx::query_as("SELECT token_hash, revoked_at FROM revoked_tokens WHERE expires_at > $1")
            .bind(now).fetch_all(&self.pool).await.map_err(|e| format!("load revocations: {e}"))?;
        let mut list = self.memory.inner.write().unwrap();
        for (th, ra) in rows { if th.len() == 16 { let mut id = [0u8; 16]; id.copy_from_slice(&th); list.revoked_ids.insert(id); list.revocation_times.insert(id, ra); } }
        Ok(())
    }
    pub async fn revoke(&self, token_id: [u8; 16]) -> Result<bool, String> {
        if self.memory.is_revoked(&token_id) { return Ok(false); }
        let now = RevocationList::now_us();
        let expires_at = now + MAX_TOKEN_LIFETIME_US;
        sqlx::query("INSERT INTO revoked_tokens (token_hash, revoked_at, expires_at) VALUES ($1, $2, $3) ON CONFLICT (token_hash) DO NOTHING")
            .bind(&token_id[..]).bind(now).bind(expires_at).execute(&self.pool).await.map_err(|e| format!("persist revocation: {e}"))?;
        Ok(self.memory.revoke(token_id))
    }
    pub fn is_revoked(&self, token_id: &[u8; 16]) -> bool { self.memory.is_revoked(token_id) }
    pub async fn cleanup_expired(&self, max_token_lifetime_secs: i64) -> Result<(), String> {
        let cutoff = RevocationList::now_us() - (max_token_lifetime_secs * 1_000_000);
        sqlx::query("DELETE FROM revoked_tokens WHERE revoked_at <= $1").bind(cutoff).execute(&self.pool).await.map_err(|e| format!("cleanup: {e}"))?;
        self.memory.cleanup_expired(max_token_lifetime_secs); Ok(())
    }
    pub async fn cleanup(&self) -> Result<(), String> {
        let now = RevocationList::now_us();
        sqlx::query("DELETE FROM revoked_tokens WHERE expires_at <= $1").bind(now).execute(&self.pool).await.map_err(|e| format!("cleanup: {e}"))?;
        self.memory.cleanup(); Ok(())
    }
    pub fn revoked_count(&self) -> usize { self.memory.revoked_count() }
    pub fn len(&self) -> usize { self.memory.len() }
    pub fn is_empty(&self) -> bool { self.memory.is_empty() }
    pub fn shared(&self) -> &SharedRevocationList { &self.memory }
}
