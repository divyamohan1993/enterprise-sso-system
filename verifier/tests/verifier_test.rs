use common::domain;
use common::error::MilnetError;
use common::types::{Token, TokenClaims, TokenHeader};
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

/// Helper: build a valid signed token with a real ratchet tag.
fn build_signed_token(dkg: &mut threshold::DkgResult, claims: TokenClaims, ratchet_key: &[u8; 64]) -> Token {
    // Serialize claims with domain prefix
    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let mut message = Vec::with_capacity(domain::FROST_TOKEN.len() + claims_bytes.len());
    message.extend_from_slice(domain::FROST_TOKEN);
    message.extend_from_slice(&claims_bytes);

    let frost_signature =
        threshold::threshold_sign(&mut dkg.shares, &dkg.group, &message, dkg.group.threshold)
            .unwrap();

    let ratchet_tag = compute_ratchet_tag(ratchet_key, &claims_bytes, claims.ratchet_epoch);

    Token {
        header: TokenHeader {
            version: 1,
            algorithm: 1,
            tier: claims.tier,
        },
        claims,
        ratchet_tag,
        frost_signature,
        pq_signature: vec![0xFF; 128],
    }
}

/// Helper: build a signed token with a dummy (placeholder) ratchet tag for backward-compat tests.
fn build_signed_token_legacy(dkg: &mut threshold::DkgResult, claims: TokenClaims) -> Token {
    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let mut message = Vec::with_capacity(domain::FROST_TOKEN.len() + claims_bytes.len());
    message.extend_from_slice(domain::FROST_TOKEN);
    message.extend_from_slice(&claims_bytes);

    let frost_signature =
        threshold::threshold_sign(&mut dkg.shares, &dkg.group, &message, dkg.group.threshold)
            .unwrap();

    Token {
        header: TokenHeader {
            version: 1,
            algorithm: 1,
            tier: claims.tier,
        },
        claims,
        ratchet_tag: [0xAA; 64],
        frost_signature,
        pq_signature: vec![0xFF; 128],
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
    }
}

#[test]
fn valid_token_verifies() {
    let mut dkg = threshold::dkg(5, 3);
    let claims = future_claims();
    let expected_sub = claims.sub;
    let expected_scope = claims.scope;
    let expected_tier = claims.tier;

    let token = build_signed_token_legacy(&mut dkg, claims);
    let result = verifier::verify_token(&token, &dkg.group.public_key_package);

    assert!(result.is_ok(), "expected valid token: {:?}", result.err());
    let verified_claims = result.unwrap();
    assert_eq!(verified_claims.sub, expected_sub);
    assert_eq!(verified_claims.scope, expected_scope);
    assert_eq!(verified_claims.tier, expected_tier);
}

#[test]
fn expired_token_rejected() {
    let mut dkg = threshold::dkg(5, 3);
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
    };

    let token = build_signed_token_legacy(&mut dkg, claims);
    let result = verifier::verify_token(&token, &dkg.group.public_key_package);

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::TokenExpired),
        "expected TokenExpired error"
    );
}

#[test]
fn tampered_signature_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let claims = future_claims();
    let mut token = build_signed_token_legacy(&mut dkg, claims);

    // Flip a byte in the FROST signature
    token.frost_signature[0] ^= 0xFF;

    let result = verifier::verify_token(&token, &dkg.group.public_key_package);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error"
    );
}

#[test]
fn tampered_claims_rejected() {
    let mut dkg = threshold::dkg(5, 3);
    let claims = future_claims();
    let mut token = build_signed_token_legacy(&mut dkg, claims);

    // Modify claims after signing — signature should no longer match
    token.claims.scope = 0xFFFF_FFFF;

    let result = verifier::verify_token(&token, &dkg.group.public_key_package);
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
    let claims = future_claims();
    let token = build_signed_token_legacy(&mut dkg1, claims);

    // Verify with a different group's key
    let result = verifier::verify_token(&token, &dkg2.group.public_key_package);
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
    let ratchet_key = test_ratchet_key();
    let claims = future_claims();
    let epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key);
    let result = verifier::verify_token_with_ratchet(
        &token,
        &dkg.group.public_key_package,
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
    let ratchet_key = test_ratchet_key();
    let claims = future_claims(); // ratchet_epoch = 1
    let token_epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key);

    // Verifier is at epoch = token_epoch + 3 (within window)
    let result = verifier::verify_token_with_ratchet(
        &token,
        &dkg.group.public_key_package,
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
    let ratchet_key = test_ratchet_key();
    let wrong_key = [0xEE; 64];
    let claims = future_claims();
    let epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key);

    let result = verifier::verify_token_with_ratchet(
        &token,
        &dkg.group.public_key_package,
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
    let ratchet_key = test_ratchet_key();
    let claims = future_claims(); // ratchet_epoch = 1
    let token_epoch = claims.ratchet_epoch;

    let token = build_signed_token(&mut dkg, claims, &ratchet_key);

    // Verifier is at epoch = token_epoch + 4 (outside +/-3 window)
    let result = verifier::verify_token_with_ratchet(
        &token,
        &dkg.group.public_key_package,
        &ratchet_key,
        token_epoch + 4,
    );

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::TokenExpired),
        "expected TokenExpired error for epoch outside window"
    );
}
