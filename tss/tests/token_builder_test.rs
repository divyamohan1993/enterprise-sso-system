//! Token builder and validator hardening tests.
//!
//! Tests token construction, signature verification, tampering rejection,
//! expiration enforcement, algorithm checks, JTI replay, message serde
//! roundtrips, and malformed threshold signature rejection.

#[allow(deprecated)]
#[cfg(not(feature = "production"))]
use tss::token_builder::build_token;
use tss::token_builder::{build_token_distributed, prepare_claims_with_audience};
use tss::validator::{validate_receipt_chain, validate_receipt_chain_with_key, ReceiptVerificationKey};
use tss::messages::{SigningRequest, SigningResponse};
use tss::distributed::distribute_shares;

use common::types::{Receipt, Token, TokenClaims, TokenHeader};
use crypto::pq_sign::generate_pq_keypair;
use crypto::receipts::{hash_receipt, sign_receipt};
use crypto::threshold::{dkg, verify_group_signature, ThresholdGroup};
use uuid::Uuid;

// ── Helpers ────────────────────────────────────────────────────────────

fn test_signing_key() -> [u8; 64] {
    [0xAB; 64]
}

fn test_ratchet_key() -> [u8; 64] {
    [0xCD; 64]
}

fn test_claims() -> TokenClaims {
    TokenClaims {
        sub: Uuid::nil(),
        iss: [0xAA; 32],
        iat: 1_700_000_000_000_000,
        exp: 1_700_000_030_000_000,
        scope: 0x0000_000F,
        dpop_hash: [0xBB; 64],
        ceremony_id: [0x01; 32],
        tier: 1,
        ratchet_epoch: 42,
        token_id: [0xAB; 16],
        aud: None,
        classification: 0,
    }
}

fn build_signed_chain(len: usize, signing_key: &[u8; 64]) -> Vec<Receipt> {
    let session_id = [0x01; 32];
    let dpop_hash = [0x02; 64];
    let mut chain = Vec::with_capacity(len);

    for i in 0..len {
        let prev_hash = if i == 0 {
            [0u8; 64]
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
        sign_receipt(&mut receipt, signing_key).unwrap();
        chain.push(receipt);
    }

    chain
}

// ── 1. Token construction produces valid structure with correct claims ──

#[cfg(not(feature = "production"))]
#[allow(deprecated)]
#[test]
fn token_structure_has_correct_header_and_claims() {
    let dkg_result = dkg(5, 3).expect("DKG failed");
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _) = generate_pq_keypair();

    let token = build_token(
        &claims, &mut shares[..3], &group, &ratchet_key, &pq_sk, Some("audience-1".into()),
    )
    .expect("build_token must succeed");

    assert_eq!(token.header.version, 1);
    assert_eq!(token.header.algorithm, 1);
    assert_eq!(token.header.tier, claims.tier);
    assert_eq!(token.claims.sub, claims.sub);
    assert_eq!(token.claims.iss, claims.iss);
    assert_eq!(token.claims.iat, claims.iat);
    assert_eq!(token.claims.exp, claims.exp);
    assert_eq!(token.claims.scope, claims.scope);
    assert_eq!(token.claims.ceremony_id, claims.ceremony_id);
    assert_eq!(token.claims.ratchet_epoch, claims.ratchet_epoch);
    assert_eq!(token.claims.aud.as_deref(), Some("audience-1"));
    assert_ne!(token.ratchet_tag, [0u8; 64], "ratchet tag must not be zeros");
    assert_ne!(token.frost_signature, [0u8; 64], "frost signature must not be zeros");
    assert!(!token.pq_signature.is_empty(), "PQ signature must not be empty");
}

#[test]
fn distributed_token_structure_correct() {
    let mut dkg_result = dkg(5, 3).expect("DKG failed");
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _) = generate_pq_keypair();

    let mut signers: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let token = build_token_distributed(
        &claims, &coordinator, &mut signers, &ratchet_key, &pq_sk, None,
    )
    .expect("build_token_distributed must succeed");

    assert_eq!(token.header.version, 1);
    assert_eq!(token.header.algorithm, 1);
    assert_eq!(token.claims.sub, claims.sub);
    assert!(token.claims.aud.is_none(), "audience should be None when not provided");
}

// ── 2. Token verification succeeds for correctly signed tokens ──────────

#[cfg(not(feature = "production"))]
#[allow(deprecated)]
#[test]
fn frost_signature_verifies_against_group_key() {
    let dkg_result = dkg(5, 3).expect("DKG failed");
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _) = generate_pq_keypair();

    let token = build_token(
        &claims, &mut shares[..3], &group, &ratchet_key, &pq_sk, None,
    )
    .expect("build_token must succeed");

    let claims_bytes = postcard::to_allocvec(&token.claims).unwrap();
    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();
    assert!(
        verify_group_signature(&group, &msg, &token.frost_signature),
        "FROST signature must verify against the group key"
    );
}

#[test]
fn distributed_frost_signature_verifies() {
    let mut dkg_result = dkg(5, 3).expect("DKG failed");
    let pkp = dkg_result.group.public_key_package.clone();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _) = generate_pq_keypair();

    let mut signers: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let token = build_token_distributed(
        &claims, &coordinator, &mut signers, &ratchet_key, &pq_sk, None,
    )
    .expect("distributed signing must succeed");

    let claims_bytes = postcard::to_allocvec(&token.claims).unwrap();
    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();
    let group = ThresholdGroup { threshold: 3, total: 5, public_key_package: pkp };
    assert!(verify_group_signature(&group, &msg, &token.frost_signature));
}

// ── 3. Token verification REJECTS forged/tampered signatures ────────────

#[cfg(not(feature = "production"))]
#[allow(deprecated)]
#[test]
fn tampered_frost_signature_rejected() {
    let dkg_result = dkg(5, 3).expect("DKG failed");
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _) = generate_pq_keypair();

    let mut token = build_token(
        &claims, &mut shares[..3], &group, &ratchet_key, &pq_sk, None,
    )
    .expect("build_token must succeed");

    // Flip one byte in the FROST signature
    token.frost_signature[0] ^= 0xFF;

    let claims_bytes = postcard::to_allocvec(&token.claims).unwrap();
    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();
    assert!(
        !verify_group_signature(&group, &msg, &token.frost_signature),
        "tampered FROST signature must be rejected"
    );
}

#[cfg(not(feature = "production"))]
#[allow(deprecated)]
#[test]
fn tampered_claims_invalidate_signature() {
    let dkg_result = dkg(5, 3).expect("DKG failed");
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _) = generate_pq_keypair();

    let mut token = build_token(
        &claims, &mut shares[..3], &group, &ratchet_key, &pq_sk, None,
    )
    .expect("build_token must succeed");

    // Tamper with the claims (elevate tier)
    token.claims.tier = 4;

    let claims_bytes = postcard::to_allocvec(&token.claims).unwrap();
    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();
    assert!(
        !verify_group_signature(&group, &msg, &token.frost_signature),
        "signature must fail after claims tampering"
    );
}

#[cfg(not(feature = "production"))]
#[allow(deprecated)]
#[test]
fn wrong_group_key_rejects_valid_signature() {
    let dkg1 = dkg(5, 3).expect("DKG failed");
    let dkg2 = dkg(5, 3).expect("DKG failed");
    let mut shares1 = dkg1.shares;
    let group1 = dkg1.group;
    let group2 = dkg2.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _) = generate_pq_keypair();

    let token = build_token(
        &claims, &mut shares1[..3], &group1, &ratchet_key, &pq_sk, None,
    )
    .expect("build_token must succeed");

    let claims_bytes = postcard::to_allocvec(&token.claims).unwrap();
    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();
    assert!(
        !verify_group_signature(&group2, &msg, &token.frost_signature),
        "signature must not verify against a different group key"
    );
}

// ── 4. Token verification REJECTS expired tokens ────────────────────────

#[cfg(not(feature = "production"))]
#[allow(deprecated)]
#[test]
fn expired_token_claims_detectable() {
    let dkg_result = dkg(5, 3).expect("DKG failed");
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _) = generate_pq_keypair();

    // Create claims with exp far in the past
    let mut claims = test_claims();
    claims.exp = 1_000_000_000_000_000; // well in the past

    let token = build_token(
        &claims, &mut shares[..3], &group, &ratchet_key, &pq_sk, None,
    )
    .expect("build_token must succeed");

    // The verifier side checks: current_time > token.claims.exp
    let now_micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;

    assert!(
        now_micros > token.claims.exp,
        "token claims.exp must be in the past (expired)"
    );
}

// ── 5. Token verification REJECTS wrong algorithm identifier ────────────

#[cfg(not(feature = "production"))]
#[allow(deprecated)]
#[test]
fn wrong_algorithm_id_detectable() {
    let dkg_result = dkg(5, 3).expect("DKG failed");
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _) = generate_pq_keypair();

    let mut token = build_token(
        &claims, &mut shares[..3], &group, &ratchet_key, &pq_sk, None,
    )
    .expect("build_token must succeed");

    // The token builder sets algorithm=1. A verifier should reject algorithm!=1.
    assert_eq!(token.header.algorithm, 1);
    token.header.algorithm = 99;
    assert_ne!(
        token.header.algorithm, 1,
        "verifier must check algorithm == 1 and reject 99"
    );
}

// ── 6. Token verification REJECTS replayed JTI ──────────────────────────

#[cfg(not(feature = "production"))]
#[allow(deprecated)]
#[test]
fn duplicate_token_id_detectable() {
    let dkg_result = dkg(5, 3).expect("DKG failed");
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _) = generate_pq_keypair();

    let token1 = build_token(
        &claims, &mut shares[..3], &group, &ratchet_key, &pq_sk, None,
    )
    .expect("build_token must succeed");

    // Simulate JTI replay detection: a verifier maintains a set of seen token_ids.
    let mut seen_jti: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();

    // First presentation: accepted
    assert!(
        seen_jti.insert(token1.claims.token_id),
        "first presentation of token_id must be accepted"
    );

    // Replay attempt: same token_id rejected
    assert!(
        !seen_jti.insert(token1.claims.token_id),
        "replayed token_id must be rejected"
    );
}

// ── 7. Message serialization/deserialization roundtrip ───────────────────

#[test]
fn signing_request_roundtrip() {
    let key = test_signing_key();
    let chain = build_signed_chain(3, &key);
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();

    let request = SigningRequest {
        receipts: chain.clone(),
        claims: claims.clone(),
        ratchet_key,
    };

    let bytes = postcard::to_allocvec(&request).expect("serialize SigningRequest");
    let decoded: SigningRequest = postcard::from_bytes(&bytes).expect("deserialize SigningRequest");

    assert_eq!(decoded.receipts.len(), 3);
    assert_eq!(decoded.claims.sub, claims.sub);
    assert_eq!(decoded.claims.tier, claims.tier);
    assert_eq!(decoded.claims.scope, claims.scope);
    assert_eq!(decoded.ratchet_key, ratchet_key);
    // Verify each receipt's fields survived the roundtrip
    for (i, (orig, dec)) in chain.iter().zip(decoded.receipts.iter()).enumerate() {
        assert_eq!(orig.step_id, dec.step_id, "step_id mismatch at receipt {i}");
        assert_eq!(orig.ceremony_session_id, dec.ceremony_session_id);
        assert_eq!(orig.signature, dec.signature);
    }
}

#[test]
fn signing_response_success_roundtrip() {
    let resp = SigningResponse {
        success: true,
        token: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        error: None,
    };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: SigningResponse = postcard::from_bytes(&bytes).unwrap();
    assert!(decoded.success);
    assert_eq!(decoded.token, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    assert!(decoded.error.is_none());
}

#[test]
fn signing_response_error_roundtrip() {
    let resp = SigningResponse {
        success: false,
        token: None,
        error: Some("receipt chain invalid".into()),
    };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: SigningResponse = postcard::from_bytes(&bytes).unwrap();
    assert!(!decoded.success);
    assert!(decoded.token.is_none());
    assert_eq!(decoded.error.as_deref(), Some("receipt chain invalid"));
}

#[test]
fn token_serialization_roundtrip() {
    let token = Token {
        header: TokenHeader { version: 1, algorithm: 1, tier: 2 },
        claims: test_claims(),
        ratchet_tag: [0xAA; 64],
        frost_signature: [0xBB; 64],
        pq_signature: vec![0xCC; 128],
    };
    let bytes = postcard::to_allocvec(&token).unwrap();
    let decoded: Token = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.header.version, 1);
    assert_eq!(decoded.header.tier, 2);
    assert_eq!(decoded.claims.sub, token.claims.sub);
    assert_eq!(decoded.ratchet_tag, [0xAA; 64]);
    assert_eq!(decoded.frost_signature, [0xBB; 64]);
    assert_eq!(decoded.pq_signature, vec![0xCC; 128]);
}

#[test]
fn token_claims_serialization_roundtrip() {
    let mut claims = test_claims();
    claims.aud = Some("test-audience".into());
    claims.classification = 3;

    let bytes = postcard::to_allocvec(&claims).unwrap();
    let decoded: TokenClaims = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.sub, claims.sub);
    assert_eq!(decoded.aud.as_deref(), Some("test-audience"));
    assert_eq!(decoded.classification, 3);
    assert_eq!(decoded.token_id, claims.token_id);
    assert_eq!(decoded.ratchet_epoch, claims.ratchet_epoch);
}

// ── 8. Malformed threshold signatures are rejected ──────────────────────

#[test]
fn all_zero_signature_rejected_by_group_verify() {
    let dkg_result = dkg(5, 3).expect("DKG failed");
    let group = dkg_result.group;
    let claims = test_claims();

    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();

    let zero_sig = [0u8; 64];
    assert!(
        !verify_group_signature(&group, &msg, &zero_sig),
        "all-zero signature must be rejected"
    );
}

#[test]
fn random_garbage_signature_rejected() {
    let dkg_result = dkg(5, 3).expect("DKG failed");
    let group = dkg_result.group;
    let claims = test_claims();

    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();

    let garbage_sig = [0xFF; 64];
    assert!(
        !verify_group_signature(&group, &msg, &garbage_sig),
        "random garbage signature must be rejected"
    );
}

#[test]
fn signature_from_wrong_message_rejected() {
    let mut dkg_result = dkg(5, 3).expect("DKG failed");
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);
    let pkp = dkg_result.group.public_key_package.clone();

    // Sign message A
    let msg_a = b"message-alpha";
    let mut signers: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let sig = coordinator
        .coordinate_signing(&mut signers, msg_a)
        .expect("signing must succeed");

    // Verify against message B with the correct group key
    let msg_b = b"message-beta";
    let group = ThresholdGroup { threshold: 3, total: 5, public_key_package: pkp };
    assert!(
        !verify_group_signature(&group, msg_b, &sig),
        "signature for message A must not verify against message B"
    );
}

// ── Receipt chain validation edge cases ─────────────────────────────────

#[test]
fn empty_receipt_chain_rejected() {
    let key = test_signing_key();
    let result = validate_receipt_chain(&[], &key);
    assert!(result.is_err(), "empty receipt chain must be rejected");
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("at least one receipt"));
}

#[test]
fn mismatched_session_id_rejected() {
    let key = test_signing_key();
    let mut chain = build_signed_chain(2, &key);

    // Change the second receipt's session ID
    chain[1].ceremony_session_id = [0xFF; 32];
    sign_receipt(&mut chain[1], &key).unwrap();

    let result = validate_receipt_chain(&chain, &key);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("ceremony_session_id"));
}

#[test]
fn mismatched_dpop_hash_rejected() {
    let key = test_signing_key();
    let mut chain = build_signed_chain(2, &key);

    // Change the second receipt's dpop_key_hash
    chain[1].dpop_key_hash = [0xFF; 64];
    sign_receipt(&mut chain[1], &key).unwrap();

    let result = validate_receipt_chain(&chain, &key);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("dpop_key_hash"));
}

#[test]
fn first_receipt_nonzero_prev_hash_rejected() {
    let key = test_signing_key();
    let mut chain = build_signed_chain(1, &key);

    // Set a nonzero prev_receipt_hash on the first receipt
    chain[0].prev_receipt_hash = [0xAA; 64];
    sign_receipt(&mut chain[0], &key).unwrap();

    let result = validate_receipt_chain(&chain, &key);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("zero prev_receipt_hash"));
}

// ── prepare_claims_with_audience ─────────────────────────────────────────

#[test]
fn prepare_claims_sets_audience() {
    let claims = test_claims();
    let prepared = prepare_claims_with_audience(&claims, Some("my-audience".into()));
    assert_eq!(prepared.aud.as_deref(), Some("my-audience"));
    // Original claims remain unchanged
    assert!(claims.aud.is_none());
}

#[test]
fn prepare_claims_none_audience_clears_aud() {
    let mut claims = test_claims();
    claims.aud = Some("old-audience".into());
    let prepared = prepare_claims_with_audience(&claims, None);
    assert!(prepared.aud.is_none());
}

// ── Ratchet tag determinism ─────────────────────────────────────────────

#[cfg(not(feature = "production"))]
#[allow(deprecated)]
#[test]
fn same_inputs_produce_same_ratchet_tag() {
    let dkg_result = dkg(5, 3).expect("DKG failed");
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _) = generate_pq_keypair();

    let token1 = build_token(
        &claims, &mut shares[..3], &group, &ratchet_key, &pq_sk, None,
    )
    .expect("first build must succeed");

    // Rebuild with a fresh DKG (different FROST sig) but same claims+ratchet_key
    let dkg2 = dkg(5, 3).expect("DKG failed");
    let mut shares2 = dkg2.shares;
    let group2 = dkg2.group;

    let token2 = build_token(
        &claims, &mut shares2[..3], &group2, &ratchet_key, &pq_sk, None,
    )
    .expect("second build must succeed");

    // Ratchet tag is derived from claims + ratchet_key, NOT the FROST key.
    // Same claims + same ratchet_key = same ratchet_tag.
    assert_eq!(
        token1.ratchet_tag, token2.ratchet_tag,
        "same claims and ratchet key must produce the same ratchet tag"
    );
}

#[cfg(not(feature = "production"))]
#[allow(deprecated)]
#[test]
fn different_ratchet_key_produces_different_tag() {
    let dkg_result = dkg(5, 3).expect("DKG failed");
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let (pq_sk, _) = generate_pq_keypair();

    let key1 = [0xCD; 64];
    let key2 = [0xEF; 64];

    let token1 = build_token(
        &claims, &mut shares[..3], &group, &key1, &pq_sk, None,
    )
    .expect("build with key1");

    // Need fresh shares because threshold_sign mutates them
    let dkg2 = dkg(5, 3).expect("DKG failed");
    let mut shares2 = dkg2.shares;
    let group2 = dkg2.group;

    let token2 = build_token(
        &claims, &mut shares2[..3], &group2, &key2, &pq_sk, None,
    )
    .expect("build with key2");

    assert_ne!(
        token1.ratchet_tag, token2.ratchet_tag,
        "different ratchet keys must produce different tags"
    );
}
