//! Hardened TOTP tests.
//!
//! Verifies the TOTP implementation enforces:
//!   - Default SHA-512 (CNSA 2.0) for new enrollments
//!   - SHA-1 backward compatibility with deprecation warnings
//!   - SHA-256 acceptance
//!   - Correct TOTP code generation per RFC 6238
//!   - Time window verification
//!   - Replay prevention (RFC 6238 Section 5.2)

use common::totp::*;

// ── Default Algorithm ─────────────────────────────────────────────────────

/// Security property: New enrollments default to SHA-512 (CNSA 2.0)
/// when MILNET_TOTP_ALGORITHM is not set.
#[test]
fn new_enrollment_defaults_to_sha512() {
    std::env::remove_var("MILNET_TOTP_ALGORITHM");
    let algo = default_totp_algorithm();
    assert_eq!(
        algo,
        TotpAlgorithm::Sha512,
        "Default TOTP algorithm must be SHA-512 (CNSA 2.0)"
    );
}

/// Security property: Setting MILNET_TOTP_ALGORITHM=sha512 uses SHA-512.
#[test]
fn enrollment_with_sha512_env_var() {
    std::env::set_var("MILNET_TOTP_ALGORITHM", "sha512");
    let algo = default_totp_algorithm();
    assert_eq!(algo, TotpAlgorithm::Sha512);
    std::env::remove_var("MILNET_TOTP_ALGORITHM");
}

/// Security property: SHA-256 is accepted for new enrollments.
#[test]
fn sha256_enrollment_accepted() {
    let secret = generate_secret();
    let time = 1_700_000_000u64;
    let code = generate_totp_with_algorithm(&*secret, time, TotpAlgorithm::Sha256);
    assert_eq!(code.len(), 6, "TOTP code must be 6 digits");
    // Code must be numeric
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

// ── Algorithm Parsing ─────────────────────────────────────────────────────

/// Security property: Algorithm parsing accepts standard names.
#[test]
fn algorithm_from_str_accepts_standard_names() {
    assert_eq!(TotpAlgorithm::from_str_loose("sha1"), Some(TotpAlgorithm::Sha1));
    assert_eq!(TotpAlgorithm::from_str_loose("sha-1"), Some(TotpAlgorithm::Sha1));
    assert_eq!(TotpAlgorithm::from_str_loose("SHA256"), Some(TotpAlgorithm::Sha256));
    assert_eq!(TotpAlgorithm::from_str_loose("sha-256"), Some(TotpAlgorithm::Sha256));
    assert_eq!(TotpAlgorithm::from_str_loose("SHA512"), Some(TotpAlgorithm::Sha512));
    assert_eq!(TotpAlgorithm::from_str_loose("sha-512"), Some(TotpAlgorithm::Sha512));
}

/// Security property: Unsupported algorithms are rejected.
#[test]
fn unsupported_algorithms_rejected() {
    assert_eq!(TotpAlgorithm::from_str_loose("md5"), None);
    assert_eq!(TotpAlgorithm::from_str_loose("sha3-256"), None);
    assert_eq!(TotpAlgorithm::from_str_loose(""), None);
}

// ── SHA-1 Backward Compatibility ──────────────────────────────────────────

/// Security property: Existing SHA-1 tokens can still be verified for
/// backward compatibility during migration. The system logs a deprecation
/// warning (tested via tracing capture in integration tests).
#[test]
fn sha1_verification_backward_compatible() {
    let secret = b"12345678901234567890";
    let time = 59u64;

    // RFC 6238 test vector
    let code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha1);
    assert_eq!(code, "287082", "SHA-1 TOTP must match RFC 6238 test vector");

    // Verification with SHA-1 must succeed
    assert!(verify_totp_with_algorithm(secret, "287082", time, 0, TotpAlgorithm::Sha1));
}

// ── TOTP Code Generation ──────────────────────────────────────────────────

/// Security property: SHA-512 TOTP code generation produces valid 6-digit codes.
#[test]
fn totp_code_generation_sha512() {
    let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
    let time = 59u64;
    let code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha512);
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

/// Security property: Different algorithms produce different codes for the
/// same secret and time (with overwhelming probability).
#[test]
fn different_algorithms_produce_different_codes() {
    let secret = b"12345678901234567890";
    let time = 59u64;

    let sha1_code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha1);
    let sha256_code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha256);
    let sha512_code = generate_totp_with_algorithm(secret, time, TotpAlgorithm::Sha512);

    // While there's a 1/1M chance any two match, all three matching is 1/1T
    assert!(
        sha1_code != sha256_code || sha256_code != sha512_code,
        "At least two algorithms should produce different codes"
    );
}

// ── TOTP Verification with Time Window ────────────────────────────────────

/// Security property: TOTP verification allows codes within the configured
/// time window (drift tolerance).
#[test]
fn totp_verification_with_time_window() {
    let secret = b"12345678901234567890";
    let time = 59u64; // step 1
    let code = generate_totp(secret, time);

    // At time=89 (step 2), window=1 should accept step 1 code
    assert!(verify_totp(secret, &code, 89, 1));
}

/// Security property: TOTP verification rejects codes outside the window.
#[test]
fn totp_verification_rejects_outside_window() {
    let secret = b"12345678901234567890";
    // Code for step 1 (time=59)
    let code = generate_totp(secret, 59);

    // At step 10 (time=300), window=0 should reject step 1 code
    assert!(!verify_totp(secret, &code, 300, 0));
}

/// Security property: Window is capped at 2 to prevent callers from
/// degrading security by passing a large window value.
#[test]
fn totp_window_capped_at_2() {
    let secret = b"12345678901234567890";
    let code = generate_totp(secret, 59);

    // Even with window=100, the internal cap is 2.
    // At time=300 (step 10), window=2 covers steps 8-12, NOT step 1.
    assert!(!verify_totp(secret, &code, 300, 100));
}

/// Security property: Invalid (non-numeric) TOTP codes are rejected.
#[test]
fn invalid_non_numeric_code_rejected() {
    let secret = b"12345678901234567890";
    assert!(!verify_totp(secret, "abcdef", 59, 1));
    assert!(!verify_totp(secret, "", 59, 1));
    assert!(!verify_totp(secret, "12345a", 59, 1));
}

// ── Secret Generation ─────────────────────────────────────────────────────

/// Security property: Generated TOTP secrets are random and unique.
#[test]
fn generated_secrets_are_random() {
    let s1 = generate_secret();
    let s2 = generate_secret();
    assert_ne!(*s1, *s2, "two generated secrets must not be equal");
    assert_ne!(*s1, [0u8; 32], "generated secret must not be all zeros");
}

// ── OTPAuth URI Generation ────────────────────────────────────────────────

/// Security property: OTPAuth URI with SHA-256 specifies the correct algorithm.
#[test]
fn otpauth_uri_sha256() {
    let secret = b"12345678901234567890";
    let uri = secret_to_otpauth_uri_with_algorithm(secret, "MILNET", "user@mil.gov", TotpAlgorithm::Sha256);
    assert!(uri.contains("algorithm=SHA256"));
    assert!(uri.contains("otpauth://totp/MILNET:user@mil.gov"));
    assert!(uri.contains("digits=6"));
    assert!(uri.contains("period=30"));
}

/// Security property: OTPAuth URI with SHA-512 specifies the correct algorithm.
#[test]
fn otpauth_uri_sha512() {
    let secret = b"12345678901234567890";
    let uri = secret_to_otpauth_uri_with_algorithm(secret, "MILNET", "admin@mil.gov", TotpAlgorithm::Sha512);
    assert!(uri.contains("algorithm=SHA512"));
}

/// Security property: Algorithm otpauth names are correct.
#[test]
fn algorithm_otpauth_names() {
    assert_eq!(TotpAlgorithm::Sha1.otpauth_name(), "SHA1");
    assert_eq!(TotpAlgorithm::Sha256.otpauth_name(), "SHA256");
    assert_eq!(TotpAlgorithm::Sha512.otpauth_name(), "SHA512");
}

// ── Migration ─────────────────────────────────────────────────────────────

/// Security property: Migration generates a new random secret
/// and returns the SHA-512 algorithm identifier (CNSA 2.0 upgrade).
#[test]
fn migrate_to_sha512_produces_new_secret() {
    let (secret, algo) = migrate_to_sha256();
    assert_eq!(algo, TotpAlgorithm::Sha512);
    assert_ne!(*secret, [0u8; 32], "migrated secret must not be all zeros");
}

// ── Base32 Encoding ───────────────────────────────────────────────────────

/// Security property: Base32 encoding matches RFC 4648 test vectors.
#[test]
fn base32_encoding_rfc4648_vectors() {
    assert_eq!(encode_base32(b""), "");
    assert_eq!(encode_base32(b"f"), "MY");
    assert_eq!(encode_base32(b"fo"), "MZXQ");
    assert_eq!(encode_base32(b"foo"), "MZXW6");
    assert_eq!(encode_base32(b"foob"), "MZXW6YQ");
    assert_eq!(encode_base32(b"fooba"), "MZXW6YTB");
    assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
}

// ── Replay Prevention (RFC 6238 Section 5.2) ─────────────────────────────

/// Security property: A TOTP code can only be used ONCE per time step.
/// Second attempt with the same code in the same time step MUST be rejected.
#[test]
fn totp_replay_prevention_rejects_second_use() {
    // Use unique secret to avoid cache interference with other tests
    let mut secret = [0u8; 20];
    getrandom::getrandom(&mut secret).unwrap();
    let time = 1_800_000_000u64;
    let code = generate_totp(&secret, time);

    assert!(verify_totp(&secret, &code, time, 0), "first use must succeed");
    assert!(!verify_totp(&secret, &code, time, 0), "replay must be rejected");
}
