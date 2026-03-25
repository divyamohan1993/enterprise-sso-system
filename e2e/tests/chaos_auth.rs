//! Authentication failure injection tests.
//!
//! Validates brute-force lockout, receipt forgery detection, receipt chain
//! ordering/gap detection, DPoP key hashing, token claim structure, CAC PIN
//! lockout, and tier enforcement.

use common::cac_auth::{CacAuthenticator, CacConfig, tier_requires_cac};
use common::types::{Receipt, TokenClaims};
use crypto::dpop::{dpop_key_hash, generate_dpop_keypair_raw};
use crypto::receipts::{
    hash_receipt, sign_receipt, verify_receipt_signature, ReceiptChain,
};
use risk::scoring::{RiskEngine, RiskSignals};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

fn make_receipt(
    session_id: [u8; 32],
    step_id: u8,
    prev_hash: [u8; 64],
    signing_key: &[u8; 64],
) -> Receipt {
    let mut r = Receipt {
        ceremony_session_id: session_id,
        step_id,
        prev_receipt_hash: prev_hash,
        user_id: Uuid::nil(),
        dpop_key_hash: [0u8; 64],
        timestamp: now_us(),
        nonce: [step_id; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };
    sign_receipt(&mut r, signing_key);
    r
}

fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

// ---------------------------------------------------------------------------
// 1. Brute-force lockout via risk engine
// ---------------------------------------------------------------------------

/// Register a user, record 10 failed password attempts, verify that the risk
/// engine locks the account after exceeding the max_attempts threshold.
#[test]
fn test_opaque_password_brute_force_lockout() {
    let engine = RiskEngine::new();
    let user_id = Uuid::new_v4();

    // Record 10 consecutive failed attempts.
    for _ in 0..10 {
        engine.record_failed_attempt(&user_id);
    }

    // max_attempts = 5 is the SecurityConfig default; the engine must report
    // that the account is locked after 10 failed attempts.
    let locked = engine.is_locked_out(&user_id, 5);
    assert!(locked, "account must be locked after 10 failed attempts (max=5)");
}

// ---------------------------------------------------------------------------
// 2. Correct password succeeds after OPAQUE registration
// ---------------------------------------------------------------------------

/// Register a user, then verify the correct password authenticates successfully.
#[test]
fn test_opaque_correct_password_after_registration() {
    use opaque::store::CredentialStore;

    let mut store = CredentialStore::new();
    let _uid = store.register_with_password("chaos_user", b"correct_password");

    // Verify the correct password.
    let result = store.verify_password("chaos_user", b"correct_password");
    assert!(result.is_ok(), "correct password must authenticate successfully");
}

// ---------------------------------------------------------------------------
// 3. Receipt forgery detection
// ---------------------------------------------------------------------------

/// Create a valid receipt, tamper with its signature bytes, verify that
/// `verify_receipt_signature` rejects the tampered receipt.
#[test]
fn test_receipt_forgery_detected() {
    let signing_key = [0x42u8; 64];
    let session_id = [0x01u8; 32];

    let mut receipt = make_receipt(session_id, 1, [0u8; 64], &signing_key);

    // Tamper: flip several signature bytes.
    if receipt.signature.len() >= 10 {
        for b in receipt.signature[4..10].iter_mut() {
            *b ^= 0xFF;
        }
    } else {
        receipt.signature.push(0xDE);
        receipt.signature.push(0xAD);
    }

    let valid = verify_receipt_signature(&receipt, &signing_key);
    assert!(!valid, "tampered receipt must fail signature verification");
}

// ---------------------------------------------------------------------------
// 4. Receipt chain ordering
// ---------------------------------------------------------------------------

/// Create a chain with 3 receipts in sequential order, verify it validates.
#[test]
fn test_receipt_chain_ordering() {
    let signing_key = [0x11u8; 64];
    let session_id = [0x22u8; 32];

    let mut chain = ReceiptChain::new(session_id);

    let r1 = make_receipt(session_id, 1, [0u8; 64], &signing_key);
    let hash1 = hash_receipt(&r1);
    chain.add_receipt(r1).unwrap();

    let r2 = make_receipt(session_id, 2, hash1, &signing_key);
    let hash2 = hash_receipt(&r2);
    chain.add_receipt(r2).unwrap();

    let r3 = make_receipt(session_id, 3, hash2, &signing_key);
    chain.add_receipt(r3).unwrap();

    assert_eq!(chain.len(), 3, "chain must contain exactly 3 receipts");
    assert!(
        chain.validate_with_key(&signing_key).is_ok(),
        "sequential chain must validate successfully"
    );
}

// ---------------------------------------------------------------------------
// 5. Receipt chain gap detection
// ---------------------------------------------------------------------------

/// Skip step_id 2 in a chain (go directly from step 1 to step 3), verify
/// that `add_receipt` rejects the out-of-sequence receipt.
#[test]
fn test_receipt_chain_gap_detected() {
    let signing_key = [0x33u8; 64];
    let session_id = [0x44u8; 32];

    let mut chain = ReceiptChain::new(session_id);

    let r1 = make_receipt(session_id, 1, [0u8; 64], &signing_key);
    let hash1 = hash_receipt(&r1);
    chain.add_receipt(r1).unwrap();

    // Skip step 2 — go directly to step 3 with the correct prev hash.
    // The chain validator should reject this because it expects step_id=2 next.
    let r3 = make_receipt(session_id, 3, hash1, &signing_key);
    let result = chain.add_receipt(r3);

    assert!(
        result.is_err(),
        "chain must reject a receipt with a non-sequential step_id"
    );
}

// ---------------------------------------------------------------------------
// 6. DPoP key hash is 64 bytes
// ---------------------------------------------------------------------------

/// Generate a DPoP keypair, hash the public key, verify the output is exactly
/// 64 bytes (SHA-512 thumbprint, CNSA 2.0 compliant).
#[test]
fn test_dpop_key_hash_sha512_correct() {
    run_with_large_stack(|| {
        let (_sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let hash = dpop_key_hash(vk_bytes.as_ref());
        assert_eq!(hash.len(), 64, "DPoP key hash must be exactly 64 bytes (SHA-512)");
    });
}

// ---------------------------------------------------------------------------
// 7. TokenClaims dpop_hash field is [u8; 64]
// ---------------------------------------------------------------------------

/// Build a `TokenClaims` value and verify the `dpop_hash` field is a 64-byte
/// array (compile-time type check enforced at runtime).
#[test]
fn test_token_claims_dpop_hash_64_bytes() {
    let claims = TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0x01u8; 32],
        iat: now_us() / 1_000_000,
        exp: (now_us() / 1_000_000) + 600,
        scope: 0,
        dpop_hash: [0xABu8; 64],
        ceremony_id: [0x02u8; 32],
        tier: 3,
        ratchet_epoch: 0,
        token_id: [0x03u8; 16],
        aud: None,
        classification: 0,
    };
    // The type system guarantees [u8; 64]; this assertion verifies the value.
    assert_eq!(
        claims.dpop_hash.len(),
        64,
        "dpop_hash must be exactly 64 bytes"
    );
}

// ---------------------------------------------------------------------------
// 8. CAC PIN lockout after 3 failures
// ---------------------------------------------------------------------------

/// Record 3 consecutive PIN failures for a card, verify the card is locked.
#[test]
fn test_cac_pin_lockout_after_3_failures() {
    let config = CacConfig {
        pkcs11_library: "/stub/libcackey.so".into(),
        pin_max_retries: 3,
        ..Default::default()
    };
    let mut auth = CacAuthenticator::new(config).unwrap();

    let serial = "CARD-SN-123456";
    auth.record_pin_failure(serial);
    assert!(!auth.is_pin_locked(serial), "not yet locked after 1 failure");
    auth.record_pin_failure(serial);
    assert!(!auth.is_pin_locked(serial), "not yet locked after 2 failures");
    auth.record_pin_failure(serial);
    assert!(auth.is_pin_locked(serial), "must be locked after 3 failures (max_retries=3)");
}

// ---------------------------------------------------------------------------
// 9. CAC tier enforcement
// ---------------------------------------------------------------------------

/// Tier 1 (Sovereign) requires CAC; Tier 3 (Sensor) does not.
#[test]
fn test_cac_tier_enforcement() {
    assert!(
        tier_requires_cac(1),
        "tier 1 (Sovereign) must require CAC/PIV"
    );
    assert!(
        !tier_requires_cac(3),
        "tier 3 (Sensor) must not require CAC/PIV"
    );
}
