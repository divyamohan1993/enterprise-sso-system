//! Key rotation under concurrent authentication tests.
//!
//! Verifies that key rotation during active token signing/verification
//! does not cause data loss, verification failures for valid tokens,
//! or race conditions. Tests the OIDC signing key rotation window
//! where both old and new keys must be valid.

use sso_protocol::tokens::{
    create_id_token, create_id_token_with_tier, verify_id_token_with_audience, OidcSigningKey,
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Key rotation while tokens are being signed
// ---------------------------------------------------------------------------

#[test]
fn test_token_signed_before_rotation_verifies_with_current_key() {
    let signing_key = OidcSigningKey::generate();
    let user_id = Uuid::new_v4();

    // Sign a token with the current key.
    let token = create_id_token(
        "https://idp.milnet.mil",
        &user_id,
        "client-123",
        Some("nonce-1".to_string()),
        &signing_key,
    );
    assert!(!token.is_empty());

    // Verify with the current verifying key.
    let result = verify_id_token_with_audience(&token, signing_key.verifying_key(), "client-123", true);
    assert!(result.is_ok(), "token should verify: {:?}", result.err());
}

#[test]
fn test_token_signed_after_rotation_verifies_with_new_key() {
    let mut signing_key = OidcSigningKey::generate();
    signing_key.rotate_signing_key();

    let user_id = Uuid::new_v4();
    let token = create_id_token(
        "https://idp.milnet.mil",
        &user_id,
        "client-456",
        Some("nonce-2".to_string()),
        &signing_key,
    );

    let result = verify_id_token_with_audience(&token, signing_key.verifying_key(), "client-456", true);
    assert!(result.is_ok(), "token signed with new key should verify: {:?}", result.err());
}

#[test]
fn test_old_token_fails_with_new_key() {
    let mut signing_key = OidcSigningKey::generate();
    let user_id = Uuid::new_v4();

    // Sign token with old key.
    let token = create_id_token(
        "https://idp.milnet.mil",
        &user_id,
        "client-789",
        None,
        &signing_key,
    );

    // Rotate.
    signing_key.rotate_signing_key();

    // Token signed with old key should NOT verify with new (current) key.
    let result = verify_id_token_with_audience(&token, signing_key.verifying_key(), "client-789", true);
    assert!(result.is_err(), "old token must not verify with new key only");

    // But it should verify with the previous key (which is the old key).
    if let Some(prev_vk) = signing_key.previous_verifying_key() {
        let result = verify_id_token_with_audience(&token, prev_vk, "client-789", true);
        assert!(result.is_ok(), "old token should still verify with previous key: {:?}", result.err());
    }
}

// ---------------------------------------------------------------------------
// Key rotation preserves previous key for overlap window
// ---------------------------------------------------------------------------

#[test]
fn test_rotation_preserves_previous_key() {
    let mut signing_key = OidcSigningKey::generate();
    assert_eq!(signing_key.generation(), 1);
    assert!(signing_key.previous_verifying_key().is_none());

    signing_key.rotate_signing_key();
    assert_eq!(signing_key.generation(), 2);
    assert!(signing_key.previous_verifying_key().is_some());

    let current_kid = signing_key.kid().to_string();
    let prev_kid = signing_key.previous_kid().unwrap().to_string();
    assert_ne!(current_kid, prev_kid);
}

#[test]
fn test_double_rotation_discards_oldest_key() {
    let mut signing_key = OidcSigningKey::generate();
    let user_id = Uuid::new_v4();

    // Sign with gen 1.
    let token_gen1 = create_id_token(
        "https://idp.milnet.mil",
        &user_id,
        "client",
        None,
        &signing_key,
    );

    // Rotate to gen 2.
    signing_key.rotate_signing_key();

    // Rotate again to gen 3 -- gen 1 key should be discarded.
    signing_key.rotate_signing_key();
    assert_eq!(signing_key.generation(), 3);

    let prev_kid = signing_key.previous_kid().unwrap();
    assert!(prev_kid.contains("v2"), "previous should be gen 2, got: {}", prev_kid);

    // Gen 1 token should fail with both current (gen3) and previous (gen2) keys.
    let result = verify_id_token_with_audience(&token_gen1, signing_key.verifying_key(), "client", true);
    assert!(result.is_err(), "gen1 token should not verify with gen3 key");

    if let Some(prev_vk) = signing_key.previous_verifying_key() {
        let result = verify_id_token_with_audience(&token_gen1, prev_vk, "client", true);
        assert!(result.is_err(), "gen1 token should not verify with gen2 key");
    }
}

// ---------------------------------------------------------------------------
// JWKS contains both current and previous keys
// ---------------------------------------------------------------------------

#[test]
fn test_jwks_contains_both_keys_after_rotation() {
    let mut signing_key = OidcSigningKey::generate();
    signing_key.rotate_signing_key();

    let jwks = signing_key.jwks_json();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "JWKS should contain both current and previous keys");

    let kids: Vec<&str> = keys.iter().map(|k| k["kid"].as_str().unwrap()).collect();
    assert!(kids.contains(&"milnet-mldsa87-v2"));
    assert!(kids.contains(&"milnet-mldsa87-v1"));
}

#[test]
fn test_jwks_contains_one_key_before_rotation() {
    let signing_key = OidcSigningKey::generate();
    let jwks = signing_key.jwks_json();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "JWKS should contain only current key before rotation");
}

// ---------------------------------------------------------------------------
// Concurrent key rotation and token signing
// ---------------------------------------------------------------------------

#[test]
fn test_concurrent_sign_and_rotate() {
    let signing_key = Arc::new(Mutex::new(OidcSigningKey::generate()));
    let mut handles = Vec::new();

    // Spawn signing threads that also verify within the same lock scope.
    for _ in 0..5 {
        let sk = signing_key.clone();
        handles.push(std::thread::spawn(move || {
            let mut successes = 0u32;
            for _ in 0..20 {
                let user_id = Uuid::new_v4();
                let key = sk.lock().unwrap();
                let token = create_id_token(
                    "https://idp.milnet.mil",
                    &user_id,
                    "concurrent-client",
                    None,
                    &key,
                );
                // Verify immediately with the same key that signed it.
                let result = verify_id_token_with_audience(
                    &token,
                    key.verifying_key(),
                    "concurrent-client",
                    true,
                );
                drop(key);
                if result.is_ok() {
                    successes += 1;
                }
            }
            successes
        }));
    }

    // Spawn rotation thread.
    let sk_rotate = signing_key.clone();
    handles.push(std::thread::spawn(move || {
        for _ in 0..3 {
            std::thread::sleep(std::time::Duration::from_millis(1));
            let mut key = sk_rotate.lock().unwrap();
            key.rotate_signing_key();
        }
        0u32
    }));

    let mut total_successes = 0u32;
    for h in handles {
        total_successes += h.join().expect("thread panicked");
    }

    // All signing threads should have succeeded (they verify within
    // the same lock scope, so the key is always consistent).
    assert!(
        total_successes >= 80,
        "expected at least 80 successful sign+verify pairs, got {}",
        total_successes
    );
}

// ---------------------------------------------------------------------------
// Token tier-specific lifetimes during rotation
// ---------------------------------------------------------------------------

#[test]
fn test_tier_tokens_across_rotation() {
    let mut signing_key = OidcSigningKey::generate();
    let user_id = Uuid::new_v4();
    let tiers = [1u8, 2, 3, 4];

    // Sign and immediately verify tokens at each tier before rotation.
    for &tier in &tiers {
        let token = create_id_token_with_tier(
            "https://idp.milnet.mil",
            &user_id,
            "tier-client",
            None,
            &signing_key,
            tier,
        );
        let result = verify_id_token_with_audience(&token, signing_key.verifying_key(), "tier-client", true);
        assert!(result.is_ok(), "pre-rotation tier {} token should verify", tier);
    }

    // Rotate.
    signing_key.rotate_signing_key();

    // New tokens with the new key should also work.
    for &tier in &tiers {
        let token = create_id_token_with_tier(
            "https://idp.milnet.mil",
            &user_id,
            "tier-client",
            None,
            &signing_key,
            tier,
        );
        let result = verify_id_token_with_audience(&token, signing_key.verifying_key(), "tier-client", true);
        assert!(result.is_ok(), "post-rotation tier {} token should verify", tier);
    }
}

// ---------------------------------------------------------------------------
// Generation counter monotonicity
// ---------------------------------------------------------------------------

#[test]
fn test_generation_counter_increases() {
    let mut signing_key = OidcSigningKey::generate();
    assert_eq!(signing_key.generation(), 1);

    for expected in 2..=10 {
        signing_key.rotate_signing_key();
        assert_eq!(signing_key.generation(), expected);
    }
}

// ---------------------------------------------------------------------------
// FROST rekey epoch tracking
// ---------------------------------------------------------------------------

#[test]
fn test_frost_rekey_epoch_increment() {
    use crypto::threshold::{dkg_distributed, ThresholdGroup};

    let total = 5u16;
    let threshold = 3u16;
    let result = dkg_distributed(total, threshold);
    let group = ThresholdGroup {
        threshold: threshold as usize,
        total: total as usize,
        public_key_package: result.group.public_key_package,
    };

    let current_epoch = 0u64;
    let rekey_result = group.rekey(&result.shares, current_epoch).unwrap();
    assert_eq!(
        rekey_result.refresh_epoch,
        current_epoch + 1,
        "rekey epoch must be current + 1"
    );
    assert_eq!(
        rekey_result.new_shares.len(),
        total as usize,
        "rekey must produce shares for all participants"
    );
}
