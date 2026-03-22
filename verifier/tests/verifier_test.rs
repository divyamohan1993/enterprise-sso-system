use common::domain;
use common::error::MilnetError;
use common::types::{Token, TokenClaims, TokenHeader};
use crypto::pq_sign::{generate_pq_keypair, pq_sign, PqSigningKey, PqVerifyingKey};
use crypto::threshold;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type HmacSha512 = Hmac<Sha512>;

/// Deterministic ratchet key for tests.
fn test_ratchet_key() -> [u8; 64] {
    [0xCD; 64]
}

/// Compute an HMAC-SHA512 ratchet tag (mirrors token_builder logic).
fn compute_ratchet_tag(ratchet_key: &[u8; 64], claims_bytes: &[u8], epoch: u64) -> [u8; 64] {
    let mut mac =
        HmacSha512::new_from_slice(ratchet_key).expect("HMAC-SHA512 accepts any key length");
    mac.update(domain::TOKEN_TAG);
    mac.update(claims_bytes);
    mac.update(&epoch.to_le_bytes());
    mac.finalize().into_bytes().into()
}

/// Lazily-generated PQ keypair shared across tests that don't care about key identity.
fn test_pq_keypair() -> (PqSigningKey, PqVerifyingKey) {
    generate_pq_keypair()
}

/// Helper: build a valid signed token with a real ratchet tag and real PQ signature.
fn build_signed_token(
    dkg: &mut threshold::DkgResult,
    claims: TokenClaims,
    ratchet_key: &[u8; 64],
    pq_sk: &PqSigningKey,
) -> Token {
    // Serialize claims with domain prefix
    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let mut message = Vec::with_capacity(domain::FROST_TOKEN.len() + claims_bytes.len());
    message.extend_from_slice(domain::FROST_TOKEN);
    message.extend_from_slice(&claims_bytes);

    let frost_signature =
        threshold::threshold_sign(&mut dkg.shares, &dkg.group, &message, dkg.group.threshold)
            .unwrap();

    let ratchet_tag = compute_ratchet_tag(ratchet_key, &claims_bytes, claims.ratchet_epoch);
    let pq_signature = pq_sign(pq_sk, &message, &frost_signature);

    Token {
        header: TokenHeader {
            version: 1,
            algorithm: 1,
            tier: claims.tier,
        },
        claims,
        ratchet_tag,
        frost_signature,
        pq_signature,
    }
}

/// Helper: build a signed token with a dummy ratchet tag but real PQ signature.
fn build_signed_token_legacy(
    dkg: &mut threshold::DkgResult,
    claims: TokenClaims,
    pq_sk: &PqSigningKey,
) -> Token {
    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let mut message = Vec::with_capacity(domain::FROST_TOKEN.len() + claims_bytes.len());
    message.extend_from_slice(domain::FROST_TOKEN);
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

/// Helper: create claims that expire in the future.
fn future_claims() -> TokenClaims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0x01; 32],
        iat: now,
        exp: now + 30_000_000, // +30 seconds
        scope: 0x0000_000F,
        dpop_hash: [0xBB; 32],
        ceremony_id: [0xCC; 32],
        tier: 2,
        ratchet_epoch: 1,
        token_id: [0xAB; 16],
    }
}

#[test]
fn valid_token_verifies() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();
    let expected_sub = claims.sub;
    let expected_scope = claims.scope;
    let expected_tier = claims.tier;

    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);
    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);

    assert!(result.is_ok(), "expected valid token: {:?}", result.err());
    let verified_claims = result.unwrap();
    assert_eq!(verified_claims.sub, expected_sub);
    assert_eq!(verified_claims.scope, expected_scope);
    assert_eq!(verified_claims.tier, expected_tier);
}

#[test]
fn expired_token_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;

    let claims = TokenClaims {
        sub: Uuid::new_v4(),
        iss: [0x01; 32],
        iat: now - 60_000_000,
        exp: now - 1_000_000, // expired 1 second ago
        scope: 0x0000_000F,
        dpop_hash: [0xBB; 32],
        ceremony_id: [0xCC; 32],
        tier: 1,
        ratchet_epoch: 1,
        token_id: [0xAB; 16],
    };

    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);
    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for expired token"
    );
}

#[test]
fn tampered_signature_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();
    let mut token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    // Flip a byte in the FROST signature
    token.frost_signature[0] ^= 0xFF;

    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error"
    );
}

#[test]
fn tampered_claims_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();
    let mut token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    // Modify claims after signing — signature should no longer match
    token.claims.scope = 0xFFFF_FFFF;

    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error"
    );
}

#[test]
fn wrong_group_key_rejected() {
    let mut dkg1 = threshold::dkg(5, 3);
    let dkg2 = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();
    let token = build_signed_token_legacy(&mut dkg1, claims, &pq_sk);

    // Verify with a different group's key
    let result = verifier::verify_token(&token, &dkg2.group.public_key_package, &pq_vk);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error"
    );
}

// ── Ratchet-aware verification tests ─────────────────────────────────

#[test]
fn test_ratchet_tag_verifies() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let ratchet_key = test_ratchet_key();
    let claims = future_claims();
    let epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key, &pq_sk);
    let result = verifier::verify_token_with_ratchet(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &ratchet_key,
        epoch,
    );

    assert!(
        result.is_ok(),
        "expected ratchet verification to succeed: {:?}",
        result.err()
    );
}

#[test]
fn test_ratchet_tag_verifies_within_window() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let ratchet_key = test_ratchet_key();
    let claims = future_claims(); // ratchet_epoch = 1
    let token_epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key, &pq_sk);

    // Verifier is at epoch = token_epoch + 3 (within window)
    let result = verifier::verify_token_with_ratchet(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &ratchet_key,
        token_epoch + 3,
    );
    assert!(
        result.is_ok(),
        "epoch +3 should be within window: {:?}",
        result.err()
    );
}

#[test]
fn test_wrong_ratchet_key_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let ratchet_key = test_ratchet_key();
    let wrong_key = [0xEE; 64];
    let claims = future_claims();
    let epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key, &pq_sk);

    let result = verifier::verify_token_with_ratchet(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &wrong_key,
        epoch,
    );

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for wrong ratchet key"
    );
}

#[test]
fn test_wrong_epoch_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let ratchet_key = test_ratchet_key();
    let claims = future_claims(); // ratchet_epoch = 1
    let token_epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key, &pq_sk);

    // Verifier is at epoch = token_epoch + 4 (outside +/-3 window)
    let result = verifier::verify_token_with_ratchet(
        &token,
        &dkg.group.public_key_package,
        &pq_vk,
        &ratchet_key,
        token_epoch + 4,
    );

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for epoch outside window"
    );
}

// ── Post-quantum signature tests ─────────────────────────────────────

#[test]
fn test_token_with_pq_signature_verifies() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();

    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    // Both FROST and PQ signatures must pass
    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);
    assert!(result.is_ok(), "token with valid PQ sig should verify: {:?}", result.err());
    // Verify PQ signature is non-empty
    assert!(!token.pq_signature.is_empty(), "pq_signature must not be empty");
}

#[test]
fn test_missing_pq_signature_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();

    let mut token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);
    // Strip the PQ signature
    token.pq_signature = Vec::new();

    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("missing post-quantum signature"),
        "expected missing PQ sig error, got: {}",
        err_msg
    );
}

#[test]
fn test_wrong_pq_key_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, _pq_vk) = test_pq_keypair();
    let (_pq_sk2, pq_vk2) = test_pq_keypair();
    let claims = future_claims();

    let token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);

    // Verify with a different PQ key -- must fail
    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk2);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for wrong PQ key"
    );
}

#[test]
fn test_tampered_pq_signature_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let (pq_sk, pq_vk) = test_pq_keypair();
    let claims = future_claims();

    let mut token = build_signed_token_legacy(&mut dkg, claims, &pq_sk);
    // Corrupt the PQ signature
    if let Some(byte) = token.pq_signature.first_mut() {
        *byte ^= 0xFF;
    }

    let result = verifier::verify_token(&token, &dkg.group.public_key_package, &pq_vk);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error for tampered PQ sig"
    );
}
