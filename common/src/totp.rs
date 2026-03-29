//! TOTP (Time-based One-Time Password) implementation per RFC 6238.
//!
//! Supports SHA-1 (legacy), SHA-256 (recommended), and SHA-512 (CNSA 2.0).
//! New enrollments default to SHA-256 via `MILNET_TOTP_ALGORITHM` env var.
//! SHA-1 is retained for backward compatibility with existing enrollments
//! but logs a deprecation warning on every verification.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::sync::Mutex;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// TOTP hash algorithm selection per RFC 6238.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    /// SHA-1 — legacy, for existing enrollments only. Deprecated.
    Sha1,
    /// SHA-256 — recommended for new enrollments.
    Sha256,
    /// SHA-512 — CNSA 2.0 compliant.
    Sha512,
}

impl TotpAlgorithm {
    /// Parse from string (case-insensitive). Returns None for unrecognized values.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sha1" | "sha-1" => Some(Self::Sha1),
            "sha256" | "sha-256" => Some(Self::Sha256),
            "sha512" | "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Return the algorithm string for otpauth:// URIs.
    pub fn otpauth_name(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// HMAC output length in bytes for this algorithm.
    #[allow(dead_code)]
    fn hmac_output_len(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// Read the default TOTP algorithm from `MILNET_TOTP_ALGORITHM` env var.
///
/// SECURITY: Defaults to SHA-512 (CNSA 2.0 compliant) if unset or unrecognized.
/// SHA-1 is REJECTED for new enrollments even if explicitly configured — it is
/// retained only for verification of legacy tokens during migration.
pub fn default_totp_algorithm() -> TotpAlgorithm {
    let algo = std::env::var("MILNET_TOTP_ALGORITHM")
        .ok()
        .and_then(|v| TotpAlgorithm::from_str_loose(&v))
        .unwrap_or(TotpAlgorithm::Sha512);

    // SECURITY: Block SHA-1 for new enrollments — only SHA-256+ is acceptable.
    if algo == TotpAlgorithm::Sha1 {
        tracing::error!(
            "SECURITY: MILNET_TOTP_ALGORITHM=SHA1 is PROHIBITED for new enrollments. \
             Overriding to SHA-512 (CNSA 2.0). Remove SHA-1 configuration immediately."
        );
        return TotpAlgorithm::Sha512;
    }

    algo
}

/// Returns true if the given algorithm string represents a legacy/deprecated algorithm.
///
/// SECURITY: Legacy algorithms must not be used for new enrollments.
/// Existing tokens using these algorithms should be migrated urgently.
pub fn is_legacy_algorithm(algo: &str) -> bool {
    matches!(algo.to_lowercase().as_str(), "sha1" | "sha-1")
}

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

/// Minimum acceptable algorithm for new TOTP enrollments.
///
/// SECURITY: SHA-1 is cryptographically weakened and MUST NOT be used for new
/// enrollments. CNSA 2.0 mandates SHA-384+ but SHA-256 is the practical minimum
/// for TOTP where collision resistance is less critical than HMAC security.
pub const TOTP_MIN_ALGORITHM: &str = "SHA256";

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

/// Compute HMAC for TOTP using the specified algorithm.
/// Returns the full HMAC output bytes.
fn hmac_totp(algorithm: TotpAlgorithm, secret: &[u8], counter_bytes: &[u8; 8]) -> Vec<u8> {
    match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC-SHA1 accepts any key length");
            mac.update(counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
            mac.update(counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(secret).expect("HMAC-SHA512 accepts any key length");
            mac.update(counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Generate a 6-digit TOTP code for the given secret and unix timestamp.
///
/// Implements HOTP (RFC 4226) with time-based counter per RFC 6238.
/// Uses dynamic truncation to extract a 6-digit code from the HMAC result.
/// Legacy variant — uses SHA-1 for backward compatibility.
pub fn generate_totp(secret: &[u8], time: u64) -> String {
    generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha1)
}

/// Generate a 6-digit TOTP code using the specified hash algorithm.
///
/// Implements HOTP (RFC 4226) with time-based counter per RFC 6238.
/// Dynamic truncation offset is taken from the last byte of the HMAC output,
/// which works correctly for all hash sizes per RFC 6238 Section 1.2.
pub fn generate_totp_with_algorithm(secret: &[u8], time: u64, algorithm: TotpAlgorithm) -> String {
    let counter = time / TIME_STEP;
    let counter_bytes = counter.to_be_bytes();

    let result = hmac_totp(algorithm, secret, &counter_bytes);

    // Dynamic truncation per RFC 4226 Section 5.4
    // Offset is derived from the last byte of the HMAC output regardless of hash size.
    let last_byte_idx = result.len() - 1;
    let offset = (result[last_byte_idx] & 0x0F) as usize;
    let binary = ((result[offset] as u32 & 0x7F) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let otp = binary % 10u32.pow(TOTP_DIGITS);
    format!("{:0width$}", otp, width = TOTP_DIGITS as usize)
}

/// Verify a TOTP code against the given secret and time, checking ± window steps.
/// Legacy variant — uses SHA-1 for backward compatibility.
///
/// Uses constant-time comparison to prevent timing side-channels on the code value.
/// Per RFC 6238 Section 5.2, each code can only be used once — replay within the
/// same time step is rejected via a global used-code cache.
pub fn verify_totp(secret: &[u8], code: &str, time: u64, window: u32) -> bool {
    verify_totp_with_algorithm(secret, code, time, window, TotpAlgorithm::Sha1)
}

/// Verify a TOTP code using the specified hash algorithm.
///
/// Uses constant-time comparison to prevent timing side-channels on the code value.
/// Per RFC 6238 Section 5.2, each code can only be used once — replay within the
/// same time step is rejected via a global used-code cache.
///
/// When `algorithm` is `Sha1`, a deprecation warning is logged via `tracing::warn!`.
pub fn verify_totp_with_algorithm(
    secret: &[u8],
    code: &str,
    time: u64,
    window: u32,
    algorithm: TotpAlgorithm,
) -> bool {
    use subtle::ConstantTimeEq;

    // SECURITY: Log CRITICAL deprecation warning for SHA-1 verification.
    // SHA-1 is still accepted for EXISTING enrollments to avoid locking out
    // users during migration, but every verification triggers an urgent alert.
    if algorithm == TotpAlgorithm::Sha1 {
        tracing::error!(
            "SECURITY: Legacy SHA-1 TOTP verified for user — migration required. \
             SHA-1 is cryptographically weakened and prohibited for new enrollments. \
             Migrate to SHA-512 (CNSA 2.0) immediately. \
             Set MILNET_TOTP_ALGORITHM=sha512 for new enrollments."
        );
    }

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
        let expected = generate_totp_with_algorithm(secret, check_time, algorithm);
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

/// Migrate a user from a legacy TOTP algorithm to SHA-512 (CNSA 2.0).
///
/// Returns the new secret. The caller is responsible for:
/// 1. Storing the new secret in the user's record
/// 2. Presenting a new QR code for re-enrollment
/// 3. Verifying the user can produce a valid code before finalizing
///
/// The old secret should be kept until the user confirms the new enrollment,
/// then securely erased.
///
/// SECURITY: Upgraded from SHA-256 to SHA-512 target to comply with CNSA 2.0.
pub fn migrate_to_sha256() -> (zeroize::Zeroizing<[u8; 32]>, TotpAlgorithm) {
    let secret = generate_secret();
    tracing::info!("TOTP migration: generated new SHA-512 (CNSA 2.0) secret for re-enrollment");
    (secret, TotpAlgorithm::Sha512)
}

/// Build an otpauth:// URI for QR code generation.
///
/// SECURITY: Uses SHA-512 (CNSA 2.0) for new enrollments. SHA-1 is no longer
/// available through this function. Use `secret_to_otpauth_uri_with_algorithm`
/// directly only for legacy migration scenarios.
pub fn secret_to_otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    secret_to_otpauth_uri_with_algorithm(secret, issuer, account, TotpAlgorithm::Sha512)
}

/// Build an otpauth:// URI for QR code generation with specified algorithm.
pub fn secret_to_otpauth_uri_with_algorithm(
    secret: &[u8],
    issuer: &str,
    account: &str,
    algorithm: TotpAlgorithm,
) -> String {
    let encoded_secret = encode_base32(secret);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits=6&period=30",
        issuer, account, encoded_secret, issuer, algorithm.otpauth_name()
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
        // SECURITY: New enrollments use SHA-512 (CNSA 2.0), not SHA-1
        assert!(uri.contains("algorithm=SHA512"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    // ── SHA-256 / SHA-512 TOTP tests ────────────────────────────────────

    #[test]
    fn test_totp_sha256_roundtrip() {
        let secret = b"12345678901234567890123456789012";
        let time = 59u64;
        let code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha256);
        assert_eq!(code.len(), 6);
        assert!(verify_totp_with_algorithm(secret, &code, time, 0, TotpAlgorithm::Sha256));
    }

    #[test]
    fn test_totp_sha512_roundtrip() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let time = 59u64;
        let code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha512);
        assert_eq!(code.len(), 6);
        assert!(verify_totp_with_algorithm(secret, &code, time, 0, TotpAlgorithm::Sha512));
    }

    #[test]
    fn test_sha256_differs_from_sha1() {
        let secret = b"12345678901234567890";
        let time = 59u64;
        let sha1_code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha1);
        let sha256_code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha256);
        // Different algorithms should (overwhelmingly likely) produce different codes
        // Note: there's a 1-in-1M chance they match, so this test is probabilistic
        // but acceptable for a 6-digit code space.
        assert_ne!(sha1_code, sha256_code, "SHA-1 and SHA-256 TOTP codes should differ (probabilistic)");
    }

    #[test]
    fn test_otpauth_uri_with_sha256() {
        let secret = b"12345678901234567890";
        let uri = secret_to_otpauth_uri_with_algorithm(secret, "MILNET", "user@example.com", TotpAlgorithm::Sha256);
        assert!(uri.contains("algorithm=SHA256"));
    }

    #[test]
    fn test_otpauth_uri_with_sha512() {
        let secret = b"12345678901234567890";
        let uri = secret_to_otpauth_uri_with_algorithm(secret, "MILNET", "user@example.com", TotpAlgorithm::Sha512);
        assert!(uri.contains("algorithm=SHA512"));
    }

    #[test]
    fn test_default_algorithm_is_sha512() {
        // SECURITY: When env var is not set, default should be SHA-512 (CNSA 2.0)
        std::env::remove_var("MILNET_TOTP_ALGORITHM");
        assert_eq!(default_totp_algorithm(), TotpAlgorithm::Sha512);
    }

    #[test]
    fn test_migrate_to_sha512() {
        let (secret, algo) = migrate_to_sha256();
        // SECURITY: Migration target is now SHA-512 (CNSA 2.0)
        assert_eq!(algo, TotpAlgorithm::Sha512);
        assert_ne!(*secret, [0u8; 32], "migrated secret must not be all zeros");
    }

    #[test]
    fn test_is_legacy_algorithm() {
        assert!(is_legacy_algorithm("sha1"));
        assert!(is_legacy_algorithm("SHA-1"));
        assert!(is_legacy_algorithm("SHA1"));
        assert!(!is_legacy_algorithm("sha256"));
        assert!(!is_legacy_algorithm("SHA-512"));
        assert!(!is_legacy_algorithm("md5")); // not legacy, just unsupported
    }

    #[test]
    fn test_sha1_blocked_for_new_enrollments() {
        // SECURITY: Even if explicitly configured, SHA-1 is overridden to SHA-512
        std::env::set_var("MILNET_TOTP_ALGORITHM", "sha1");
        let algo = default_totp_algorithm();
        assert_eq!(algo, TotpAlgorithm::Sha512, "SHA-1 must be blocked for new enrollments");
        std::env::remove_var("MILNET_TOTP_ALGORITHM");
    }

    #[test]
    fn test_algorithm_from_str() {
        assert_eq!(TotpAlgorithm::from_str_loose("sha1"), Some(TotpAlgorithm::Sha1));
        assert_eq!(TotpAlgorithm::from_str_loose("SHA-256"), Some(TotpAlgorithm::Sha256));
        assert_eq!(TotpAlgorithm::from_str_loose("sha512"), Some(TotpAlgorithm::Sha512));
        assert_eq!(TotpAlgorithm::from_str_loose("md5"), None);
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
