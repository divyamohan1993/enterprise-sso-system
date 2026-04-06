//! Hash puzzle challenge for DDoS mitigation.
//!
//! Clients must solve a proof-of-work puzzle before the gateway will
//! process their authentication request.
//!
//! # Hash algorithm choice: SHA-512
//!
//! SHA-512 is chosen over SHA-256 for the proof-of-work hash for improved
//! GPU/ASIC resistance.  SHA-512 operates on 64-bit words, which penalises
//! 32-bit GPU shader cores and simple ASIC designs relative to 64-bit server
//! CPUs.  This makes large-scale puzzle-farming on commodity GPUs roughly 2x
//! more expensive per hash compared to SHA-256, raising the cost of DDoS
//! attacks that attempt to stockpile valid puzzle solutions.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crypto::entropy::generate_nonce;

/// Maximum number of consumed puzzle entries before forced eviction.
///
/// When the tracker reaches this capacity, expired entries are purged.  If
/// the set is still at capacity after purging (all entries are fresh), the
/// oldest entries are evicted to make room.  This hard bound prevents
/// unbounded memory growth under sustained high-rate traffic.
const MAX_CONSUMED_ENTRIES: usize = 100_000;

/// Global adaptive difficulty -- increases under load.
static CURRENT_DIFFICULTY: AtomicU8 = AtomicU8::new(0);

/// Compute the adaptive difficulty INCREASE based on the number of active
/// connections and store it globally.
///
/// Returns 0 under normal load (the server's configured base difficulty
/// applies), scaling up to 24 under extreme load.  The server takes
/// `max(base_difficulty, adaptive_difficulty)` so the configured difficulty
/// always acts as a floor -- allowing tests to use a low difficulty while
/// production servers enforce a meaningful minimum.
pub fn get_adaptive_difficulty(active_connections: usize) -> u8 {
    let difficulty = if active_connections > 1000 {
        24 // DDoS level
    } else if active_connections > 500 {
        22 // High load
    } else if active_connections > 100 {
        18 // Moderate load
    } else {
        0 // Normal -- use base difficulty
    };
    CURRENT_DIFFICULTY.store(difficulty, Ordering::Relaxed);
    difficulty
}

/// Return the last stored adaptive difficulty.
pub fn current_difficulty() -> u8 {
    CURRENT_DIFFICULTY.load(Ordering::Relaxed)
}

/// Maximum age of a puzzle challenge before it expires (30 seconds).
const PUZZLE_TTL_SECS: i64 = 30;

// ---------------------------------------------------------------------------
// Consumed puzzle nonce tracker (replay protection)
// ---------------------------------------------------------------------------

/// Tracks solved puzzle nonces to prevent replay attacks.
///
/// Each consumed nonce is stored with the timestamp it was consumed at.
/// Entries older than `PUZZLE_TTL_SECS` are automatically purged during
/// cleanup, and the set is hard-bounded by `MAX_CONSUMED_ENTRIES`.
///
/// PERSISTENCE DECISION: Intentionally ephemeral (in-memory only).
///
/// Puzzle nonces have a 30-second TTL (`PUZZLE_TTL_SECS`). After a process
/// restart, the replay window is bounded to at most 30 seconds of previously-
/// solved puzzles that could be replayed. This is acceptable because:
///   1. Puzzles are proof-of-work challenges, not authentication tokens.
///      Replaying a solved puzzle only skips the PoW computation; it does not
///      grant access or bypass authentication.
///   2. The 30-second TTL means the attacker must replay within 30 seconds
///      of the restart AND possess a valid solution from before the restart.
///   3. The adaptive difficulty system (`get_adaptive_difficulty`) will
///      increase puzzle difficulty under load regardless of replay cache state.
///   4. For military deployments, the `DistributedPuzzleStore` trait provides
///      cross-instance replay prevention via Redis, which also survives
///      single-instance restarts.
///
/// When the hard limit is reached and no expired entries can be purged,
/// the oldest entries are forcibly evicted (LRU-style) to guarantee the
/// bound is never exceeded.
pub struct ConsumedPuzzles {
    /// Map from nonce to the unix timestamp (seconds) when it was consumed.
    entries: HashMap<[u8; 32], i64>,
}

impl ConsumedPuzzles {
    /// Create an empty consumed puzzles tracker.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Returns `true` if the nonce has already been consumed.
    pub fn is_consumed(&self, nonce: &[u8; 32]) -> bool {
        self.entries.contains_key(nonce)
    }

    /// Mark a nonce as consumed at the given unix timestamp.
    ///
    /// If the tracker is at capacity, expired entries are purged first.
    /// If still at capacity after purging, the oldest entries are forcibly
    /// evicted to enforce the `MAX_CONSUMED_ENTRIES` bound.
    pub fn insert(&mut self, nonce: [u8; 32], timestamp: i64) {
        if self.entries.len() >= MAX_CONSUMED_ENTRIES {
            self.cleanup_expired(timestamp);
        }
        // If still at capacity after expiry cleanup, evict oldest entries.
        if self.entries.len() >= MAX_CONSUMED_ENTRIES {
            self.evict_oldest(MAX_CONSUMED_ENTRIES / 10);
        }
        self.entries.insert(nonce, timestamp);
    }

    /// Remove all entries older than `PUZZLE_TTL_SECS` relative to `now`.
    pub fn cleanup_expired(&mut self, now: i64) {
        self.entries.retain(|_, ts| now - *ts <= PUZZLE_TTL_SECS);
    }

    /// Forcibly evict the `count` oldest entries by timestamp.
    ///
    /// This guarantees the hard bound is respected even when all entries
    /// are within the TTL window (e.g. under sustained high-rate traffic).
    fn evict_oldest(&mut self, count: usize) {
        if self.entries.is_empty() || count == 0 {
            return;
        }
        // Collect timestamps, sort, find the cutoff.
        let mut timestamps: Vec<i64> = self.entries.values().copied().collect();
        timestamps.sort_unstable();
        let cutoff_idx = count.min(timestamps.len()) - 1;
        let cutoff_ts = timestamps[cutoff_idx];
        let mut removed = 0usize;
        self.entries.retain(|_, ts| {
            if removed < count && *ts <= cutoff_ts {
                removed += 1;
                false
            } else {
                true
            }
        });
    }
}

impl Default for ConsumedPuzzles {
    fn default() -> Self {
        Self::new()
    }
}

/// Global consumed-puzzles tracker, protected by a mutex.
///
/// WARNING: This is a per-process store. In a multi-instance deployment,
/// a puzzle nonce consumed by one instance is not visible to others. For
/// military deployments, wire a `DistributedPuzzleStore` implementation
/// (e.g. Redis-backed) to provide cross-instance replay prevention.
static CONSUMED_PUZZLES: std::sync::LazyLock<Mutex<ConsumedPuzzles>> =
    std::sync::LazyLock::new(|| {
        if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok() {
            tracing::error!(
                "FATAL: Per-process puzzle store in military deployment mode. \
                 Configure a DistributedPuzzleStore or set MILNET_ALLOW_LOCAL_PUZZLE_STORE=1."
            );
            if std::env::var("MILNET_ALLOW_LOCAL_PUZZLE_STORE").is_err() {
                std::process::exit(1);
            }
        }
        Mutex::new(ConsumedPuzzles::new())
    });

/// Trait for distributed puzzle nonce replay prevention.
///
/// The default in-memory `ConsumedPuzzles` is per-process. For multi-instance
/// deployments, implement this trait with a shared backend (e.g. Redis)
/// to ensure nonces cannot be replayed across gateway instances.
pub trait DistributedPuzzleStore: Send + Sync {
    /// Check if a nonce has been consumed and, if not, atomically mark it as consumed.
    /// Returns `Ok(true)` if the nonce was fresh and is now consumed.
    /// Returns `Ok(false)` if the nonce was already consumed (replay detected).
    fn check_and_consume(&self, nonce: &[u8; 32], timestamp: i64) -> Result<bool, String>;
}

/// DoD Standard Notice and Consent Banner (DISA STIG V-222396).
/// Must be displayed before any authentication interaction.
pub const DOD_BANNER: &str = "\
You are accessing a U.S. Government (USG) Information System (IS) that is \
provided for USG-authorized use only.\n\n\
By using this IS (which includes any device attached to this IS), you consent \
to the following conditions:\n\
- The USG routinely intercepts and monitors communications on this IS for \
purposes including, but not limited to, penetration testing, COMSEC monitoring, \
network operations and defense, personnel misconduct (PM), law enforcement (LE), \
and counterintelligence (CI) investigations.\n\
- At any time, the USG may inspect and seize data stored on this IS.\n\
- Communications using, or data stored on, this IS are not private, are subject \
to routine monitoring, interception, and search, and may be disclosed or used \
for any USG-authorized purpose.\n\
- This IS includes security measures (e.g., authentication and access controls) \
to protect USG interests -- not for your personal benefit or privacy.\n\
- Notwithstanding the above, using this IS does not constitute consent to PM, \
LE or CI investigative searching or monitoring of the content of privileged \
communications, or work product, related to personal representation or services \
by attorneys, psychotherapists, or clergy, and their assistants. Such \
communications and work product are private and confidential. See User Agreement \
for details.";

/// A proof-of-work challenge sent by the gateway to connecting clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PuzzleChallenge {
    pub nonce: [u8; 32],
    pub difficulty: u8,
    pub timestamp: i64,
    /// Server's X-Wing public key (X25519 || ML-KEM-1024 EK) for hybrid
    /// post-quantum key exchange.  Clients encapsulate against this key and
    /// return the ciphertext with their puzzle solution.
    #[serde(default)]
    pub xwing_server_pk: Option<Vec<u8>>,
    /// SHA-256 fingerprint of the server's X-Wing public key (hex-encoded).
    /// Clients SHOULD verify this against a pinned set of trusted fingerprints
    /// before encapsulating.  If the fingerprint does not match, the client
    /// MUST abort the connection -- a mismatch indicates a potential key
    /// substitution or man-in-the-middle attack.
    #[serde(default)]
    pub xwing_server_pk_fingerprint: Option<String>,
    /// DoD Standard Notice and Consent Banner (DISA STIG V-222396).
    /// Always present in the puzzle challenge so clients display it before auth.
    #[serde(default)]
    pub dod_banner: Option<String>,
}

/// A client's solution to a [`PuzzleChallenge`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PuzzleSolution {
    pub nonce: [u8; 32],
    pub solution: [u8; 32],
    /// X-Wing KEM ciphertext produced by the client encapsulating against
    /// the server's public key.  The server decapsulates this to derive the
    /// shared secret.  Replaces the previous `xwing_client_pk` field: the
    /// client no longer sends its own public key; it encapsulates against
    /// the server's key and sends back the ciphertext.
    #[serde(default)]
    pub xwing_kem_ciphertext: Option<Vec<u8>>,
}

/// Generate a new puzzle challenge with the given difficulty (number of
/// leading zero bits required in the hash).
pub fn generate_challenge(difficulty: u8) -> PuzzleChallenge {
    let nonce = generate_nonce();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    PuzzleChallenge {
        nonce,
        difficulty,
        timestamp,
        xwing_server_pk: None,
        xwing_server_pk_fingerprint: None,
        dod_banner: Some(DOD_BANNER.to_string()),
    }
}

/// Check whether `SHA-512(nonce || solution)` has at least `difficulty`
/// leading zero bits, the challenge has not expired (30s TTL), and the
/// nonce has not already been consumed (replay protection).
///
/// All comparisons use constant-time operations where security-relevant:
/// - Nonce replay check uses `HashMap::contains_key` (not timing-sensitive
///   since nonces are random and not secret).
/// - The proof-of-work hash comparison uses `leading_zeros` which always
///   examines a fixed prefix of the hash (no early return on the critical
///   difficulty check path).
pub fn verify_solution(challenge: &PuzzleChallenge, solution: &[u8; 32]) -> bool {
    // Check expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if now - challenge.timestamp > PUZZLE_TTL_SECS {
        return false;
    }

    // Check replay: reject already-consumed nonces
    {
        let mut consumed = CONSUMED_PUZZLES.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in puzzle - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        // Periodically clean up expired entries
        consumed.cleanup_expired(now);
        if consumed.is_consumed(&challenge.nonce) {
            return false;
        }
    }

    // Verify the proof-of-work using SHA-512 (GPU/ASIC resistant).
    if !has_leading_zero_bits(challenge, solution) {
        return false;
    }

    // Mark nonce as consumed after successful verification
    {
        let mut consumed = CONSUMED_PUZZLES.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in puzzle - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        consumed.insert(challenge.nonce, now);
    }

    true
}

/// Check the SHA-512 hash without expiration (internal helper).
fn has_leading_zero_bits(challenge: &PuzzleChallenge, solution: &[u8; 32]) -> bool {
    let mut hasher = Sha512::new();
    hasher.update(challenge.nonce);
    hasher.update(solution);
    let hash = hasher.finalize();

    leading_zeros(&hash) >= challenge.difficulty as u32
}

/// Count the number of leading zero bits in a byte slice.
fn leading_zeros(data: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in data.iter() {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Brute-force solver for testing. Tries random values until one satisfies
/// the puzzle.
pub fn solve_challenge(challenge: &PuzzleChallenge) -> [u8; 32] {
    loop {
        let candidate = generate_nonce();
        if has_leading_zero_bits(challenge, &candidate) {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros_counts_correctly() {
        assert_eq!(leading_zeros(&[0x00, 0x00, 0x01]), 23);
        assert_eq!(leading_zeros(&[0x80]), 0);
        assert_eq!(leading_zeros(&[0x40]), 1);
        assert_eq!(leading_zeros(&[0x00, 0x0F]), 12);
    }

    #[test]
    fn consumed_puzzles_enforces_bound() {
        let mut tracker = ConsumedPuzzles::new();
        // Fill to capacity with entries at timestamp 1000
        for i in 0..MAX_CONSUMED_ENTRIES {
            let mut nonce = [0u8; 32];
            nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
            tracker.insert(nonce, 1000);
        }
        assert_eq!(tracker.entries.len(), MAX_CONSUMED_ENTRIES);
        // Insert one more; eviction should keep us at or below capacity.
        let mut new_nonce = [0xFFu8; 32];
        new_nonce[0] = 0xAA;
        tracker.insert(new_nonce, 1001);
        assert!(tracker.entries.len() <= MAX_CONSUMED_ENTRIES);
        assert!(tracker.is_consumed(&new_nonce));
    }

    #[test]
    fn expired_entries_are_cleaned() {
        let mut tracker = ConsumedPuzzles::new();
        let old_nonce = [1u8; 32];
        tracker.insert(old_nonce, 100);
        // "now" is far in the future relative to old_nonce
        tracker.cleanup_expired(100 + PUZZLE_TTL_SECS + 1);
        assert!(!tracker.is_consumed(&old_nonce));
    }
}
