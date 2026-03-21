//! Hash puzzle challenge for DDoS mitigation.
//!
//! Clients must solve a proof-of-work puzzle before the gateway will
//! process their authentication request.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use milnet_crypto::entropy::generate_nonce;

/// Maximum age of a puzzle challenge before it expires (10 seconds).
const PUZZLE_TTL_SECS: i64 = 10;

/// A proof-of-work challenge sent by the gateway to connecting clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PuzzleChallenge {
    pub nonce: [u8; 32],
    pub difficulty: u8,
    pub timestamp: i64,
}

/// A client's solution to a [`PuzzleChallenge`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PuzzleSolution {
    pub nonce: [u8; 32],
    pub solution: [u8; 32],
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
    }
}

/// Check whether `SHA-256(nonce || solution)` has at least `difficulty`
/// leading zero bits, and the challenge has not expired (10s TTL).
pub fn verify_solution(challenge: &PuzzleChallenge, solution: &[u8; 32]) -> bool {
    // Check expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64;
    if now - challenge.timestamp > PUZZLE_TTL_SECS {
        return false;
    }

    has_leading_zero_bits(challenge, solution)
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
