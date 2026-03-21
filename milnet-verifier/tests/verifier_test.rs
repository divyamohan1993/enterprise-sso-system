use milnet_common::domain;
use milnet_common::error::MilnetError;
use milnet_common::types::{Token, TokenClaims, TokenHeader};
use milnet_crypto::threshold;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Helper: build a valid signed token using the DKG result.
fn build_signed_token(dkg: &mut threshold::DkgResult, claims: TokenClaims) -> Token {
    // Serialize claims with domain prefix
    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let mut message = Vec::with_capacity(domain::FROST_TOKEN.len() + claims_bytes.len());
    message.extend_from_slice(domain::FROST_TOKEN);
    message.extend_from_slice(&claims_bytes);

    // Collect threshold partial signatures
    let partials: Vec<threshold::PartialSignature> = dkg
        .shares
        .iter_mut()
        .take(dkg.group.threshold)
        .map(|share| share.partial_sign(&message))
        .collect();

    let frost_signature = threshold::combine_partials(&dkg.group, &partials, &message).unwrap();

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

    let token = build_signed_token(&mut dkg, claims);
    let result = milnet_verifier::verify_token(&token, &dkg.group.group_verifying_key);

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

    let token = build_signed_token(&mut dkg, claims);
    let result = milnet_verifier::verify_token(&token, &dkg.group.group_verifying_key);

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
    let mut token = build_signed_token(&mut dkg, claims);

    // Flip a byte in the FROST signature
    token.frost_signature[0] ^= 0xFF;

    let result = milnet_verifier::verify_token(&token, &dkg.group.group_verifying_key);
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
    let mut token = build_signed_token(&mut dkg, claims);

    // Modify claims after signing — signature should no longer match
    token.claims.scope = 0xFFFF_FFFF;

    let result = milnet_verifier::verify_token(&token, &dkg.group.group_verifying_key);
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
    let token = build_signed_token(&mut dkg1, claims);

    // Verify with a different group's key
    let result = milnet_verifier::verify_token(&token, &dkg2.group.group_verifying_key);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), MilnetError::CryptoVerification(_)),
        "expected CryptoVerification error"
    );
}
