//! Recovery code generation, hashing, and verification.
//!
//! Recovery codes are 128-bit random values displayed as XXXX-XXXX-XXXX-XXXX format.
//! They are hashed with HMAC-SHA512 + per-code salt before storage.
//! The plaintext code is shown to the user ONCE and never stored.

use sha2::Sha512;
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;

type HmacSha512 = Hmac<Sha512>;

const RECOVERY_CODE_BYTES: usize = 16; // 128 bits
const RECOVERY_CODE_SALT_BYTES: usize = 32;
const RECOVERY_CODE_TTL_SECS: i64 = 365 * 24 * 3600; // 1 year
const MAX_CODES_PER_USER: usize = 8;

/// Generate a batch of recovery codes for a user.
/// Returns Vec of (display_string, salt, hash) tuples.
/// The display_string must be shown to the user and then discarded.
pub fn generate_recovery_codes(count: usize) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let count = count.min(MAX_CODES_PER_USER);
    (0..count).map(|_| {
        let mut code_bytes = [0u8; RECOVERY_CODE_BYTES];
        getrandom::getrandom(&mut code_bytes).expect("getrandom failed");

        let display = format_code(&code_bytes);
        let salt = generate_salt();
        let hash = hash_code(&code_bytes, &salt);

        // Zeroize the raw bytes (display string will be returned and shown once)
        use zeroize::Zeroize;
        code_bytes.zeroize();

        (display, salt, hash)
    }).collect()
}

/// Format 16 bytes as XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX (hex, uppercase)
fn format_code(bytes: &[u8; 16]) -> String {
    let hex = hex::encode(bytes).to_uppercase();
    format!("{}-{}-{}-{}", &hex[0..8], &hex[8..16], &hex[16..24], &hex[24..32])
}

/// Parse a display code back to bytes
pub fn parse_code(display: &str) -> Result<[u8; 16], String> {
    let clean: String = display.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 32 {
        return Err("invalid recovery code format".into());
    }
    let bytes = hex::decode(&clean).map_err(|e| format!("invalid hex: {e}"))?;
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Generate a random salt for code hashing
fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; RECOVERY_CODE_SALT_BYTES];
    getrandom::getrandom(&mut salt).expect("getrandom failed");
    salt
}

/// Hash a recovery code with HMAC-SHA512(salt, code)
fn hash_code(code: &[u8; 16], salt: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha512::new_from_slice(salt).expect("HMAC key length valid");
    mac.update(crate::domain::RECOVERY_CODE); // Domain separation
    mac.update(code);
    mac.finalize().into_bytes().to_vec()
}

/// Verify a recovery code against a stored hash+salt using constant-time comparison
pub fn verify_code(code: &[u8; 16], salt: &[u8], expected_hash: &[u8]) -> bool {
    let computed = hash_code(code, salt);
    computed.ct_eq(expected_hash).into()
}

/// TTL for recovery codes
pub fn recovery_code_ttl_secs() -> i64 {
    RECOVERY_CODE_TTL_SECS
}

/// Maximum codes per user
pub fn max_codes_per_user() -> usize {
    MAX_CODES_PER_USER
}

// ---------------------------------------------------------------------------
// Recovery rate limiter
// ---------------------------------------------------------------------------

/// Rate limiter for recovery code attempts: max 3 attempts per 15-minute window.
pub struct RecoveryRateLimiter {
    attempts: std::collections::HashMap<uuid::Uuid, (u32, i64)>, // (count, window_start)
}

impl RecoveryRateLimiter {
    /// Window duration in seconds (15 minutes).
    const WINDOW_SECS: i64 = 15 * 60;
    /// Maximum attempts per window.
    const MAX_ATTEMPTS: u32 = 3;

    pub fn new() -> Self {
        Self {
            attempts: std::collections::HashMap::new(),
        }
    }

    /// Check if the user is allowed to attempt recovery, and record the attempt.
    /// Returns `Ok(())` if allowed, `Err` if rate limited.
    pub fn check_and_record(&mut self, user_id: uuid::Uuid, now: i64) -> Result<(), &'static str> {
        let entry = self.attempts.entry(user_id).or_insert((0, now));

        // Reset window if expired
        if now - entry.1 >= Self::WINDOW_SECS {
            *entry = (0, now);
        }

        if entry.0 >= Self::MAX_ATTEMPTS {
            return Err("recovery rate limit exceeded: max 3 attempts per 15 minutes");
        }

        entry.0 += 1;
        Ok(())
    }

    /// Reset the rate limiter for a specific user (e.g., after successful recovery).
    pub fn reset(&mut self, user_id: &uuid::Uuid) {
        self.attempts.remove(user_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify() {
        let codes = generate_recovery_codes(3);
        assert_eq!(codes.len(), 3);
        for (display, salt, hash) in &codes {
            // Display format: XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
            assert_eq!(display.len(), 35); // 32 hex + 3 dashes
            assert!(display.contains('-'));

            // Parse back and verify
            let parsed = parse_code(display).unwrap();
            assert!(verify_code(&parsed, salt, hash));
        }
    }

    #[test]
    fn test_wrong_code_rejected() {
        let codes = generate_recovery_codes(1);
        let (_display, salt, hash) = &codes[0];
        let wrong = [0xFFu8; 16];
        assert!(!verify_code(&wrong, salt, hash));
    }

    #[test]
    fn test_wrong_salt_rejected() {
        let codes = generate_recovery_codes(1);
        let (display, _salt, hash) = &codes[0];
        let parsed = parse_code(display).unwrap();
        let wrong_salt = vec![0u8; 32];
        assert!(!verify_code(&parsed, &wrong_salt, hash));
    }

    #[test]
    fn test_max_codes_capped() {
        let codes = generate_recovery_codes(100);
        assert_eq!(codes.len(), MAX_CODES_PER_USER);
    }

    #[test]
    fn test_parse_with_dashes() {
        let codes = generate_recovery_codes(1);
        let (display, salt, hash) = &codes[0];
        let parsed = parse_code(display).unwrap();
        assert!(verify_code(&parsed, salt, hash));
    }

    #[test]
    fn test_codes_are_unique() {
        let codes = generate_recovery_codes(8);
        let displays: Vec<&str> = codes.iter().map(|(d, _, _)| d.as_str()).collect();
        for i in 0..displays.len() {
            for j in (i+1)..displays.len() {
                assert_ne!(displays[i], displays[j]);
            }
        }
    }

    // ── RecoveryRateLimiter tests ──

    #[test]
    fn test_rate_limiter_allows_up_to_3() {
        let mut limiter = RecoveryRateLimiter::new();
        let user = uuid::Uuid::new_v4();
        let now = 1000;
        assert!(limiter.check_and_record(user, now).is_ok());
        assert!(limiter.check_and_record(user, now + 1).is_ok());
        assert!(limiter.check_and_record(user, now + 2).is_ok());
        // 4th should fail
        assert!(limiter.check_and_record(user, now + 3).is_err());
    }

    #[test]
    fn test_rate_limiter_resets_after_window() {
        let mut limiter = RecoveryRateLimiter::new();
        let user = uuid::Uuid::new_v4();
        let now = 1000;
        assert!(limiter.check_and_record(user, now).is_ok());
        assert!(limiter.check_and_record(user, now).is_ok());
        assert!(limiter.check_and_record(user, now).is_ok());
        assert!(limiter.check_and_record(user, now).is_err());

        // After 15 minutes, window resets
        let later = now + 15 * 60;
        assert!(limiter.check_and_record(user, later).is_ok());
    }

    #[test]
    fn test_rate_limiter_reset_user() {
        let mut limiter = RecoveryRateLimiter::new();
        let user = uuid::Uuid::new_v4();
        let now = 1000;
        assert!(limiter.check_and_record(user, now).is_ok());
        assert!(limiter.check_and_record(user, now).is_ok());
        assert!(limiter.check_and_record(user, now).is_ok());
        assert!(limiter.check_and_record(user, now).is_err());

        limiter.reset(&user);
        assert!(limiter.check_and_record(user, now).is_ok());
    }

    #[test]
    fn test_rate_limiter_independent_users() {
        let mut limiter = RecoveryRateLimiter::new();
        let user1 = uuid::Uuid::new_v4();
        let user2 = uuid::Uuid::new_v4();
        let now = 1000;
        // Exhaust user1
        for _ in 0..3 {
            assert!(limiter.check_and_record(user1, now).is_ok());
        }
        assert!(limiter.check_and_record(user1, now).is_err());
        // user2 should still be allowed
        assert!(limiter.check_and_record(user2, now).is_ok());
    }
}
