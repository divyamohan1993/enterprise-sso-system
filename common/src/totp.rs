//! TOTP (Time-based One-Time Password) implementation per RFC 6238.
//!
//! Uses HMAC-SHA1 as mandated by interoperability requirements (most authenticator
//! apps only support SHA1). This is a CNSA 2.0 exception for TOTP compatibility.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::collections::HashMap;
use std::sync::Mutex;

type HmacSha1 = Hmac<Sha1>;

/// Global TOTP used-code cache — prevents replay within a time window.
/// Per RFC 6238 Section 5.2: "The verifier MUST NOT accept the second attempt."
/// Keyed by (user_secret_fingerprint, code, time_step) to prevent cross-user collisions.
/// Entries are evicted after 2 minutes (4 time steps) to bound memory.
static TOTP_USED_CODES: std::sync::OnceLock<Mutex<TotpUsedCodeCache>> = std::sync::OnceLock::new();

struct TotpUsedCodeCache {
    /// Maps (secret_fingerprint_u64, time_step, code) -> true
    used: HashMap<(u64, u64, u32), bool>,
    last_cleanup: u64,
}

impl TotpUsedCodeCache {
    fn new() -> Self {
        Self { used: HashMap::new(), last_cleanup: 0 }
    }

    fn is_used(&mut self, secret_fp: u64, time: u64, code: u32) -> bool {
        let step = time / TIME_STEP;
        // Cleanup old entries every 60 seconds
        if time > self.last_cleanup + 60 {
            self.used.retain(|&(_, s, _), _| s + 4 >= step);
            self.last_cleanup = time;
        }
        self.used.contains_key(&(secret_fp, step, code))
    }

    fn mark_used(&mut self, secret_fp: u64, time: u64, code: u32) {
        let step = time / TIME_STEP;
        self.used.insert((secret_fp, step, code), true);
    }
}

fn totp_used_cache() -> &'static Mutex<TotpUsedCodeCache> {
    TOTP_USED_CODES.get_or_init(|| Mutex::new(TotpUsedCodeCache::new()))
}

/// Compute a fast fingerprint of the TOTP secret for cache keying.
/// Not cryptographic — just for HashMap key differentiation.
fn secret_fingerprint(secret: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    secret.hash(&mut hasher);
    hasher.finish()
}

/// Time step in seconds (RFC 6238 default).
const TIME_STEP: u64 = 30;

/// Number of TOTP digits.
const TOTP_DIGITS: u32 = 6;

/// Generate a 32-byte random secret for TOTP enrollment.
///
/// Returns a `Zeroizing<[u8; 32]>` — the secret is automatically erased
/// from memory when dropped, preventing post-use forensic recovery.
pub fn generate_secret() -> zeroize::Zeroizing<[u8; 32]> {
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::getrandom(secret.as_mut()).expect("getrandom failed");
    secret
}

/// Generate a 6-digit TOTP code for the given secret and unix timestamp.
///
/// Implements HOTP (RFC 4226) with time-based counter per RFC 6238.
/// Uses dynamic truncation to extract a 6-digit code from the HMAC-SHA1 result.
pub fn generate_totp(secret: &[u8], time: u64) -> String {
    let counter = time / TIME_STEP;
    let counter_bytes = counter.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC-SHA1 accepts any key length");
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation per RFC 4226 Section 5.4
    let offset = (result[19] & 0x0F) as usize;
    let binary = ((result[offset] as u32 & 0x7F) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let otp = binary % 10u32.pow(TOTP_DIGITS);
    format!("{:0width$}", otp, width = TOTP_DIGITS as usize)
}

/// Verify a TOTP code against the given secret and time, checking ± window steps.
///
/// Uses constant-time comparison to prevent timing side-channels on the code value.
/// Per RFC 6238 Section 5.2, each code can only be used once — replay within the
/// same time step is rejected via a global used-code cache.
pub fn verify_totp(secret: &[u8], code: &str, time: u64, window: u32) -> bool {
    use subtle::ConstantTimeEq;

    // Enforce maximum window to prevent callers from degrading security
    let window = window.min(2);

    let code_num: u32 = match code.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    let fp = secret_fingerprint(secret);

    // Check if this exact code was already used for this secret in this time step
    if let Ok(mut cache) = totp_used_cache().lock() {
        if cache.is_used(fp, time, code_num) {
            return false; // RFC 6238 §5.2: reject second attempt
        }
    }

    let mut result = 0u8;
    for i in 0..=(window * 2) {
        let check_time = if i <= window {
            time.wrapping_sub((window as u64 - i as u64) * TIME_STEP)
        } else {
            time + (i as u64 - window as u64) * TIME_STEP
        };
        let expected = generate_totp(secret, check_time);
        // Accumulate match results in constant time
        result |= code.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8();
    }

    if result == 1 {
        // Mark this code as used so it cannot be replayed
        if let Ok(mut cache) = totp_used_cache().lock() {
            cache.mark_used(fp, time, code_num);
        }
        true
    } else {
        false
    }
}

/// Build an otpauth:// URI for QR code generation.
pub fn secret_to_otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    let encoded_secret = encode_base32(secret);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        issuer, account, encoded_secret, issuer
    )
}

/// RFC 4648 Base32 encoding (no padding).
pub fn encode_base32(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }
    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B test vector: SHA1, secret = "12345678901234567890", time = 59.
    /// Expected TOTP: 287082
    #[test]
    fn test_rfc6238_test_vector_time_59() {
        let secret = b"12345678901234567890";
        let code = generate_totp(secret, 59);
        assert_eq!(code, "287082", "RFC 6238 test vector at time=59 failed");
    }

    /// RFC 6238 Appendix B: time = 1111111109
    /// Expected TOTP: 081804
    #[test]
    fn test_rfc6238_test_vector_time_1111111109() {
        let secret = b"12345678901234567890";
        let code = generate_totp(secret, 1111111109);
        assert_eq!(code, "081804");
    }

    /// RFC 6238 Appendix B: time = 1234567890
    /// Expected TOTP: 005924
    #[test]
    fn test_rfc6238_test_vector_time_1234567890() {
        let secret = b"12345678901234567890";
        let code = generate_totp(secret, 1234567890);
        assert_eq!(code, "005924");
    }

    #[test]
    fn test_verify_totp_exact() {
        let secret = b"12345678901234567890";
        assert!(verify_totp(secret, "287082", 59, 0));
    }

    #[test]
    fn test_verify_totp_with_window() {
        let secret = b"12345678901234567890";
        // Code for time=59 (step 1), verify at time=89 (step 2) with window=1
        assert!(verify_totp(secret, "287082", 89, 1));
    }

    #[test]
    fn test_verify_totp_wrong_code() {
        let secret = b"12345678901234567890";
        assert!(!verify_totp(secret, "000000", 59, 1));
    }

    #[test]
    fn test_generate_secret_is_random() {
        let s1 = generate_secret();
        let s2 = generate_secret();
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn test_encode_base32() {
        // Known test: "Hello!" -> "JBSWY3DPEE"
        // Actually let's use a simpler known vector
        assert_eq!(encode_base32(b""), "");
        assert_eq!(encode_base32(b"f"), "MY");
        assert_eq!(encode_base32(b"fo"), "MZXQ");
        assert_eq!(encode_base32(b"foo"), "MZXW6");
        assert_eq!(encode_base32(b"foob"), "MZXW6YQ");
        assert_eq!(encode_base32(b"fooba"), "MZXW6YTB");
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn test_otpauth_uri() {
        let secret = b"12345678901234567890";
        let uri = secret_to_otpauth_uri(secret, "MILNET", "user@example.com");
        assert!(uri.starts_with("otpauth://totp/MILNET:user@example.com?"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    // ── TOTP replay prevention tests (RFC 6238 §5.2) ───────────────────

    #[test]
    fn test_totp_replay_prevention() {
        // Use a unique secret so the cache doesn't interfere with other tests
        let mut secret = [0u8; 20];
        getrandom::getrandom(&mut secret).unwrap();
        let time = 1_700_000_000u64; // fixed timestamp
        let code = generate_totp(&secret, time);

        // First use should succeed
        assert!(verify_totp(&secret, &code, time, 0), "first use should succeed");
        // Second use of the same code in the same time step MUST fail
        assert!(!verify_totp(&secret, &code, time, 0), "replay MUST be rejected (RFC 6238 §5.2)");
    }

    #[test]
    fn test_totp_window_capped_at_2() {
        // Even if caller passes window=10, it should be capped at 2
        let secret = b"12345678901234567890";
        // Code for time=59 (step 1), try to verify at a time far away with window=10
        // Window is capped at 2, so this should NOT match step 1 from step 10+
        let code = generate_totp(secret, 59);
        // At step 10 (time=300), window=2 covers steps 8-12, not step 1
        assert!(!verify_totp(secret, &code, 300, 10));
    }

    #[test]
    fn test_totp_different_secrets_independent_replay() {
        let mut s1 = [0u8; 20];
        let mut s2 = [0u8; 20];
        getrandom::getrandom(&mut s1).unwrap();
        getrandom::getrandom(&mut s2).unwrap();
        let time = 1_700_001_000u64;

        let code1 = generate_totp(&s1, time);
        let code2 = generate_totp(&s2, time);

        // Using code1 for s1 should not affect s2
        assert!(verify_totp(&s1, &code1, time, 0));
        if code1 == code2 {
            // Same code, different secret — each has its own replay tracking
            assert!(verify_totp(&s2, &code2, time, 0));
        }
    }
}
