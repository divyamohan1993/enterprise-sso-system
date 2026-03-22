//! Hash puzzle challenge for DDoS mitigation.
//!
//! Clients must solve a proof-of-work puzzle before the gateway will
//! process their authentication request.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crypto::entropy::generate_nonce;

/// Maximum number of consumed puzzle entries before forced cleanup.
const MAX_CONSUMED_ENTRIES: usize = 100_000;

/// Global adaptive difficulty -- increases under load.
static CURRENT_DIFFICULTY: AtomicU8 = AtomicU8::new(8);

/// Compute the appropriate puzzle difficulty based on the number of active
/// connections and store it globally.
pub fn get_adaptive_difficulty(active_connections: usize) -> u8 {
    let difficulty = if active_connections > 1000 {
        20 // DDoS level
    } else if active_connections > 500 {
        16 // High load
    } else if active_connections > 100 {
        12 // Moderate load
    } else {
        8 // Normal
    };
    CURRENT_DIFFICULTY.store(difficulty, Ordering::Relaxed);
    difficulty
}

/// Return the last stored adaptive difficulty.
pub fn current_difficulty() -> u8 {
    CURRENT_DIFFICULTY.load(Ordering::Relaxed)
}

/// Maximum age of a puzzle challenge before it expires (10 seconds).
const PUZZLE_TTL_SECS: i64 = 10;

// ---------------------------------------------------------------------------
// Consumed puzzle nonce tracker (replay protection)
// ---------------------------------------------------------------------------

/// Tracks solved puzzle nonces to prevent replay attacks.
///
/// Each consumed nonce is stored with the timestamp it was consumed at.
/// Entries older than `PUZZLE_TTL_SECS` are automatically purged during
/// cleanup, and the set is bounded by `MAX_CONSUMED_ENTRIES`.
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
    pub fn insert(&mut self, nonce: [u8; 32], timestamp: i64) {
        // Enforce size bound: if at capacity, run cleanup first.
        if self.entries.len() >= MAX_CONSUMED_ENTRIES {
            self.cleanup_expired(timestamp);
        }
        self.entries.insert(nonce, timestamp);
    }

    /// Remove all entries older than `PUZZLE_TTL_SECS` relative to `now`.
    pub fn cleanup_expired(&mut self, now: i64) {
        self.entries.retain(|_, ts| now - *ts <= PUZZLE_TTL_SECS);
    }
}

impl Default for ConsumedPuzzles {
    fn default() -> Self {
        Self::new()
    }
}

/// Global consumed-puzzles tracker, protected by a mutex.
static CONSUMED_PUZZLES: std::sync::LazyLock<Mutex<ConsumedPuzzles>> =
    std::sync::LazyLock::new(|| Mutex::new(ConsumedPuzzles::new()));

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
}

/// A client's solution to a [`PuzzleChallenge`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PuzzleSolution {
    pub nonce: [u8; 32],
    pub solution: [u8; 32],
    /// Client's X-Wing public key.  The server encapsulates against this key
    /// and sends the resulting ciphertext back so both sides share a secret.
    #[serde(default)]
    pub xwing_client_pk: Option<Vec<u8>>,
}

/// Generate a new puzzle challenge with the given difficulty (number of
/// leading zero bits required in the hash).
pub fn generate_challenge(difficulty: u8) -> PuzzleChallenge {
    let nonce = generate_nonce();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64;
    PuzzleChallenge {
        nonce,
        difficulty,
        timestamp,
        xwing_server_pk: None,
    }
}

/// Check whether `SHA-256(nonce || solution)` has at least `difficulty`
/// leading zero bits, the challenge has not expired (10s TTL), and the
/// nonce has not already been consumed (replay protection).
pub fn verify_solution(challenge: &PuzzleChallenge, solution: &[u8; 32]) -> bool {
    // Check expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64;
    if now - challenge.timestamp > PUZZLE_TTL_SECS {
        return false;
    }

    // Check replay: reject already-consumed nonces
    {
        let mut consumed = CONSUMED_PUZZLES.lock().unwrap_or_else(|e| e.into_inner());
        // Periodically clean up expired entries
        consumed.cleanup_expired(now);
        if consumed.is_consumed(&challenge.nonce) {
            return false;
        }
    }

    // Verify the proof-of-work
    if !has_leading_zero_bits(challenge, solution) {
        return false;
    }

    // Mark nonce as consumed after successful verification
    {
        let mut consumed = CONSUMED_PUZZLES.lock().unwrap_or_else(|e| e.into_inner());
        consumed.insert(challenge.nonce, now);
    }

    true
}

/// Check the hash without expiration (internal helper).
fn has_leading_zero_bits(challenge: &PuzzleChallenge, solution: &[u8; 32]) -> bool {
    let mut hasher = Sha256::new();
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
}
