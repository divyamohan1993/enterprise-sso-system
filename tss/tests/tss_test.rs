use common::types::{Receipt, TokenClaims};
use crypto::receipts::{hash_receipt, sign_receipt};
use crypto::threshold::{dkg, verify_group_signature};
use tss::token_builder::build_token;
use tss::validator::validate_receipt_chain;
use uuid::Uuid;

/// Create a deterministic 64-byte signing key for tests.
fn test_signing_key() -> [u8; 64] {
    [0xAB; 64]
}

/// Create a deterministic 64-byte ratchet key for tests.
fn test_ratchet_key() -> [u8; 64] {
    [0xCD; 64]
}

/// Build a valid receipt chain of the given length, signing each receipt.
fn build_signed_chain(len: usize, signing_key: &[u8; 64]) -> Vec<Receipt> {
    let session_id = [0x01; 32];
    let dpop_hash = [0x02; 32];
    let mut chain = Vec::with_capacity(len);

    for i in 0..len {
        let prev_hash = if i == 0 {
            [0u8; 32]
        } else {
            hash_receipt(&chain[i - 1])
        };

        let mut receipt = Receipt {
            ceremony_session_id: session_id,
            step_id: (i + 1) as u8,
            prev_receipt_hash: prev_hash,
            user_id: Uuid::nil(),
            dpop_key_hash: dpop_hash,
            timestamp: 1_700_000_000_000_000 + (i as i64 * 1_000_000),
            nonce: [i as u8; 32],
            signature: Vec::new(),
            ttl_seconds: 30,
        };
        sign_receipt(&mut receipt, signing_key);
        chain.push(receipt);
    }

    chain
}

/// Helper to create test claims.
fn test_claims() -> TokenClaims {
    TokenClaims {
        sub: Uuid::nil(),
        iss: [0xAA; 32],
        iat: 1_700_000_000_000_000,
        exp: 1_700_000_030_000_000,
        scope: 0x0000_000F,
        dpop_hash: [0xBB; 32],
        ceremony_id: [0x01; 32],
        tier: 1,
        ratchet_epoch: 42,
    }
}

#[test]
fn valid_receipt_chain_accepted() {
    let key = test_signing_key();
    let chain = build_signed_chain(1, &key);
    assert!(validate_receipt_chain(&chain, &key).is_ok());

    // Also test a multi-receipt chain
    let chain3 = build_signed_chain(3, &key);
    assert!(validate_receipt_chain(&chain3, &key).is_ok());
}

#[test]
fn broken_chain_rejected() {
    let key = test_signing_key();
    let mut chain = build_signed_chain(3, &key);

    // Tamper with the second receipt's prev_receipt_hash
    chain[1].prev_receipt_hash = [0xFF; 32];
    // Re-sign so signature is valid but chain linkage is broken
    sign_receipt(&mut chain[1], &key);

    let result = validate_receipt_chain(&chain, &key);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("prev_receipt_hash"),
        "expected prev_receipt_hash error, got: {}",
        err_msg
    );
}

#[test]
fn unsigned_receipt_rejected() {
    let key = test_signing_key();
    let mut chain = build_signed_chain(1, &key);

    // Replace signature with garbage
    chain[0].signature = vec![0xFF; 32];

    let result = validate_receipt_chain(&chain, &key);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("invalid signature"),
        "expected signature error, got: {}",
        err_msg
    );
}

#[test]
fn token_built_and_verifiable() {
    let dkg_result = dkg(5, 3);
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();

    let token = build_token(&claims, &mut shares[..3], &group, &ratchet_key)
        .expect("build_token should succeed");

    // Verify the FROST signature against the group key
    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();
    assert!(verify_group_signature(&group, &msg, &token.frost_signature));
}

#[test]
fn token_claims_preserved() {
    let dkg_result = dkg(5, 3);
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();

    let token = build_token(&claims, &mut shares[..3], &group, &ratchet_key)
        .expect("build_token should succeed");

    // Serialize and deserialize the token, verify claims match
    let serialized = postcard::to_allocvec(&token).unwrap();
    let deserialized: common::types::Token = postcard::from_bytes(&serialized).unwrap();

    assert_eq!(deserialized.claims.sub, claims.sub);
    assert_eq!(deserialized.claims.iss, claims.iss);
    assert_eq!(deserialized.claims.iat, claims.iat);
    assert_eq!(deserialized.claims.exp, claims.exp);
    assert_eq!(deserialized.claims.scope, claims.scope);
    assert_eq!(deserialized.claims.dpop_hash, claims.dpop_hash);
    assert_eq!(deserialized.claims.ceremony_id, claims.ceremony_id);
    assert_eq!(deserialized.claims.tier, claims.tier);
    assert_eq!(deserialized.claims.ratchet_epoch, claims.ratchet_epoch);
    assert_eq!(deserialized.header.version, 1);
    assert_eq!(deserialized.header.algorithm, 1);
    assert_eq!(deserialized.header.tier, claims.tier);
}

#[test]
fn test_ratchet_tag_is_real() {
    let dkg_result = dkg(5, 3);
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();

    let token = build_token(&claims, &mut shares[..3], &group, &ratchet_key)
        .expect("build_token should succeed");

    // The ratchet tag must NOT be all zeros (the old placeholder)
    assert_ne!(token.ratchet_tag, [0u8; 64], "ratchet tag must not be all zeros");
    // It also should not be a trivial constant
    assert_ne!(token.ratchet_tag, [0xDD; 64]);
}
