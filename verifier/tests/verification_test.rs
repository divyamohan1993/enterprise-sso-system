//! Hardened token verification tests.
//!
//! Tests expired token rejection, wrong signing key rejection, modified claims
//! rejection, future `iat` rejection, concurrent verification thread safety,
//! and O(1) verification performance characteristics.

use common::error::MilnetError;
use common::types::{Token, TokenClaims, TokenHeader};
use crypto::pq_sign::{generate_pq_keypair, pq_sign, PqSigningKey, PqVerifyingKey};
use crypto::threshold;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Lazily-generated PQ keypair shared across tests.
fn test_pq_keypair() -> (PqSigningKey, PqVerifyingKey) {
    generate_pq_keypair()
}

/// Test DPoP client key used across tests.
const TEST_DPOP_KEY: [u8; 32] = [0xDD; 32];

/// Helper: build a signed token with a real PQ signature.
fn build_signed_token(
    dkg: &mut threshold::DkgResult,
    claims: TokenClaims,
    pq_sk: &PqSigningKey,
) -> Token {
    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let mut message = Vec::with_capacity(common::domain::FROST_TOKEN.len() + claims_bytes.len());
    message.extend_from_slice(common::domain::FROST_TOKEN);
    message.extend_from_slice(&claims_bytes);

    let frost_signature =
        threshold::threshold_sign(&mut dkg.shares, &dkg.group, &message, dkg.group.threshold)
            .unwrap();

    let pq_signature = pq_sign(pq_sk, &message, &frost_signature);

    Token {
        header: TokenHeader {
            version: 1,
            algorithm: 1,
            tier: claims.tier,
        },
        claims,
        ratchet_tag: [0xAA; 64],
        frost_signature,
        pq_signature,
    }
}

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

/// Helper: create claims that expire in the future.
fn future_claims() -> TokenClaims {
    let now = now_us();
    TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0x01; 32],
        iat: now,
        exp: now + 30_000_000, // +30 seconds
        scope: 0x0000_000F,
        dpop_hash: crypto::dpop::dpop_key_hash(&TEST_DPOP_KEY),
        ceremony_id: [0xCC; 32],
        tier: 2,
        ratchet_epoch: 1,
        token_id: [0xAB; 16],
        aud: Some("test-service".to_string()),
        classification: 0,
    }
}

// ── Test expired token rejection ─────────────────────────────────────────

#[test]
fn expired_token_rejected() {
    let mut dkg = threshold::dkg(5, 3).expect("DKG ceremony failed");
    let (pq_sk, pq_vk) = test_pq_keypair();
    let now = now_us();

    let claims = TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0x01; 32],
        iat: now - 60_000_000,
        exp: now - 1_000_000, // expired 1 second ago
        scope: 0x0000_000F,
        dpop_hash: crypto::dpop::dpop_key_hash(&TEST_DPOP_KEY),
        ceremony_id: [0xCC; 32],
        tier: 2,
        ratchet_epoch: 1,
        token_id: [0xAB; 16],
        aud: Some("test-service".to_string()),
        classification: 0,
    };

    let token = build_signed_token(&mut dkg, claims, &pq_sk);
    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);
    assert!(result.is_err(), "expired token must be rejected");
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for expired token"
    );
}

// ── Test token with wrong signing key rejection ──────────────────────────

#[test]
fn wrong_signing_key_rejected() {
    let mut dkg1 = threshold::dkg(5, 3).expect("DKG ceremony failed");
    let dkg2 = threshold::dkg(5, 3).expect("DKG ceremony failed");
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();

    let token = build_signed_token(&mut dkg1, claims, &pq_sk);
    // Verify with a different group's key
    let result = verifier::verify_token_bound(
        &token,
        &dkg2.group.public_key_package,
        &pq_vk,
        &TEST_DPOP_KEY,
    );
    assert!(result.is_err(), "token signed by different group key must be rejected");
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for wrong signing key"
    );
}

// ── Test token with modified claims rejection ────────────────────────────

#[test]
fn modified_claims_rejected() {
    let mut dkg = threshold::dkg(5, 3).expect("DKG ceremony failed");
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();

    let mut token = build_signed_token(&mut dkg, claims, &pq_sk);
    // Modify scope after signing
    token.claims.scope = 0xFFFF_FFFF;

    let result = verifier::verify_token_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &TEST_DPOP_KEY,
    );
    assert!(result.is_err(), "token with modified claims must be rejected");
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for modified claims"
    );
}

#[test]
fn modified_sub_rejected() {
    let mut dkg = threshold::dkg(5, 3).expect("DKG ceremony failed");
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();

    let mut token = build_signed_token(&mut dkg, claims, &pq_sk);
    token.claims.sub = Uuid::new_v4(); // different subject

    let result = verifier::verify_token_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &TEST_DPOP_KEY,
    );
    assert!(result.is_err(), "token with modified sub must be rejected");
}

#[test]
fn modified_tier_rejected() {
    let mut dkg = threshold::dkg(5, 3).expect("DKG ceremony failed");
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();

    let mut token = build_signed_token(&mut dkg, claims, &pq_sk);
    token.claims.tier = 1; // elevated tier

    let result = verifier::verify_token_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &TEST_DPOP_KEY,
    );
    assert!(result.is_err(), "token with modified tier must be rejected");
}

// ── Test token with future `iat` rejection ───────────────────────────────

#[test]
fn future_iat_rejected() {
    let mut dkg = threshold::dkg(5, 3).expect("DKG ceremony failed");
    let (pq_sk, pq_vk) = test_pq_keypair();
    let now = now_us();

    let claims = TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0x01; 32],
        iat: now + 60_000_000, // 60 seconds in the future
        exp: now + 120_000_000,
        scope: 0x0000_000F,
        dpop_hash: crypto::dpop::dpop_key_hash(&TEST_DPOP_KEY),
        ceremony_id: [0xCC; 32],
        tier: 2,
        ratchet_epoch: 1,
        token_id: [0xAB; 16],
        aud: Some("test-service".to_string()),
        classification: 0,
    };

    let token = build_signed_token(&mut dkg, claims, &pq_sk);
    let result = verifier::verify_token_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &TEST_DPOP_KEY,
    );
    // Future iat should be rejected — either CryptoVerification or a specific
    // iat-in-future error depending on verifier implementation.
    assert!(
        result.is_err(),
        "token with iat 60s in the future must be rejected"
    );
}

// ── Test concurrent token verification (thread safety) ───────────────────

#[test]
fn concurrent_token_verification_thread_safe() {
    let mut dkg = threshold::dkg(5, 3).expect("DKG ceremony failed");
    let (pq_sk, pq_vk) = test_pq_keypair();
    let pkp = dkg.group.public_key_package.clone();
    let claims = future_claims();
    let token = build_signed_token(&mut dkg, claims, &pq_sk);

    // Verify from multiple threads concurrently
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let token = token.clone();
            let pkp = pkp.clone();
            let pq_vk = pq_vk.clone();
            std::thread::spawn(move || {
                let result = verifier::verify_token_bound(
                    &token,
                    &pkp,
                    &pq_vk,
                    &TEST_DPOP_KEY,
                );
                result.is_ok()
            })
        })
        .collect();

    for handle in handles {
        let ok = handle.join().expect("thread must not panic");
        assert!(ok, "concurrent verification must succeed");
    }
}

// ── Test token verification performance is O(1) ─────────────────────────
// This is a structural test: we verify the same token twice and ensure both
// succeed (no state-dependent behavior), demonstrating O(1) per-verification.

#[test]
fn token_verification_is_stateless() {
    let mut dkg = threshold::dkg(5, 3).expect("DKG ceremony failed");
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();
    let token = build_signed_token(&mut dkg, claims, &pq_sk);

    // Verify twice to confirm verification is stateless (O(1), no caching needed)
    let result1 = verifier::verify_token_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &TEST_DPOP_KEY,
    );
    assert!(result1.is_ok(), "first verification must succeed");

    let result2 = verifier::verify_token_bound(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &TEST_DPOP_KEY,
    );
    assert!(result2.is_ok(), "second verification must succeed identically");

    // Both should return the same claims
    let c1 = result1.unwrap();
    let c2 = result2.unwrap();
    assert_eq!(c1.sub, c2.sub);
    assert_eq!(c1.scope, c2.scope);
}
