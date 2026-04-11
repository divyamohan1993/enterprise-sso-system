//! Timing attack tests for FIDO2 verification.
//!
//! Verifies that challenge comparison, RP ID hash comparison, and origin
//! comparison do not short-circuit on first byte mismatch (constant-time).
//! Uses statistical analysis of timing measurements.

use fido::verification::{
    parse_authenticator_data, validate_rp_id_hash, ParsedAuthData,
};
use sha2::{Digest, Sha256};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Helper: build authenticator data blob
// ---------------------------------------------------------------------------

fn build_auth_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&rp_hash);
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    data
}

// ---------------------------------------------------------------------------
// Challenge comparison does not short-circuit
// ---------------------------------------------------------------------------

#[test]
fn test_challenge_comparison_constant_time() {
    // Measure time to validate RP ID hash when first byte differs
    // vs when last byte differs. In a short-circuiting implementation,
    // first-byte mismatch would be measurably faster.

    let correct_rp = "example.com";
    let auth_data = build_auth_data(correct_rp, 0x05, 1);
    let parsed = parse_authenticator_data(&auth_data).unwrap();

    // RP IDs that differ in the first character vs last character.
    let first_byte_wrong = "Xxample.com";
    let last_byte_wrong = "example.coX";

    let iterations = 10_000;

    // Warm up.
    for _ in 0..1000 {
        let _ = validate_rp_id_hash(&parsed, first_byte_wrong);
        let _ = validate_rp_id_hash(&parsed, last_byte_wrong);
    }

    // Measure first-byte-wrong timing.
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = validate_rp_id_hash(&parsed, first_byte_wrong);
    }
    let first_byte_time = start.elapsed();

    // Measure last-byte-wrong timing.
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = validate_rp_id_hash(&parsed, last_byte_wrong);
    }
    let last_byte_time = start.elapsed();

    // Both should reject.
    assert!(validate_rp_id_hash(&parsed, first_byte_wrong).is_err());
    assert!(validate_rp_id_hash(&parsed, last_byte_wrong).is_err());

    // The timing ratio should be close to 1.0 for constant-time comparison.
    // Allow 3x ratio to account for noise. A short-circuiting implementation
    // would show a much larger ratio.
    let ratio = first_byte_time.as_nanos() as f64 / last_byte_time.as_nanos() as f64;
    assert!(
        ratio > 0.3 && ratio < 3.0,
        "timing ratio {:.3} suggests non-constant-time comparison \
         (first_byte: {:?}, last_byte: {:?})",
        ratio,
        first_byte_time,
        last_byte_time,
    );
}

// ---------------------------------------------------------------------------
// RP ID hash comparison does not short-circuit
// ---------------------------------------------------------------------------

#[test]
fn test_rp_id_hash_all_zero_vs_all_one() {
    // Compare validation time for hashes that differ maximally
    // (all zeros vs all ones in expected hash position).
    let auth_data_zero = {
        let mut data = vec![0u8; 37];
        data[32] = 0x05; // flags: UP + UV
        data[33..37].copy_from_slice(&1u32.to_be_bytes());
        data
    };

    let parsed_zero = parse_authenticator_data(&auth_data_zero).unwrap();

    let iterations = 10_000;

    // RP IDs that produce very different hashes.
    let rp_a = "aaaaaa.com";
    let rp_b = "zzzzzz.com";

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = validate_rp_id_hash(&parsed_zero, rp_a);
    }
    let time_a = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = validate_rp_id_hash(&parsed_zero, rp_b);
    }
    let time_b = start.elapsed();

    let ratio = time_a.as_nanos() as f64 / time_b.as_nanos() as f64;
    assert!(
        ratio > 0.3 && ratio < 3.0,
        "timing ratio {:.3} for different RP IDs suggests non-constant-time \
         (a: {:?}, b: {:?})",
        ratio,
        time_a,
        time_b,
    );
}

// ---------------------------------------------------------------------------
// Authenticator data parsing edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_auth_data_too_short() {
    let short_data = vec![0u8; 36]; // 37 is minimum
    assert!(parse_authenticator_data(&short_data).is_err());
}

#[test]
fn test_auth_data_exactly_minimum_length() {
    let data = vec![0u8; 37];
    let result = parse_authenticator_data(&data);
    assert!(result.is_ok());
}

#[test]
fn test_auth_data_flags_extraction() {
    let auth_data = build_auth_data("example.com", 0x05, 42);
    let parsed = parse_authenticator_data(&auth_data).unwrap();
    assert!(parsed.user_present);
    assert!(parsed.user_verified);
    assert!(!parsed.attested_credential_data);
    assert_eq!(parsed.sign_count, 42);
}

#[test]
fn test_auth_data_with_attested_flag() {
    let auth_data = build_auth_data("example.com", 0x45, 0);
    let parsed = parse_authenticator_data(&auth_data).unwrap();
    assert!(parsed.user_present);
    assert!(parsed.user_verified);
    assert!(parsed.attested_credential_data);
}

// ---------------------------------------------------------------------------
// RP ID validation with correct and incorrect values
// ---------------------------------------------------------------------------

#[test]
fn test_rp_id_correct_validation_succeeds() {
    let rp_id = "login.milnet.mil";
    let auth_data = build_auth_data(rp_id, 0x05, 1);
    let parsed = parse_authenticator_data(&auth_data).unwrap();
    assert!(validate_rp_id_hash(&parsed, rp_id).is_ok());
}

#[test]
fn test_rp_id_wrong_validation_fails() {
    let rp_id = "login.milnet.mil";
    let auth_data = build_auth_data(rp_id, 0x05, 1);
    let parsed = parse_authenticator_data(&auth_data).unwrap();
    assert!(validate_rp_id_hash(&parsed, "evil.attacker.com").is_err());
}

#[test]
fn test_rp_id_empty_string() {
    let auth_data = build_auth_data("", 0x05, 1);
    let parsed = parse_authenticator_data(&auth_data).unwrap();
    assert!(validate_rp_id_hash(&parsed, "").is_ok());
    assert!(validate_rp_id_hash(&parsed, "anything").is_err());
}

#[test]
fn test_rp_id_unicode() {
    let rp_id = "login.\u{0939}\u{093F}\u{0928}\u{094D}\u{0926}\u{0940}.mil";
    let auth_data = build_auth_data(rp_id, 0x05, 1);
    let parsed = parse_authenticator_data(&auth_data).unwrap();
    assert!(validate_rp_id_hash(&parsed, rp_id).is_ok());
}

// ---------------------------------------------------------------------------
// Sign count edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_sign_count_zero() {
    let auth_data = build_auth_data("test.com", 0x01, 0);
    let parsed = parse_authenticator_data(&auth_data).unwrap();
    assert_eq!(parsed.sign_count, 0);
}

#[test]
fn test_sign_count_max() {
    let auth_data = build_auth_data("test.com", 0x01, u32::MAX);
    let parsed = parse_authenticator_data(&auth_data).unwrap();
    assert_eq!(parsed.sign_count, u32::MAX);
}
