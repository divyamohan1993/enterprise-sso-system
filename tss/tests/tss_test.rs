#[allow(deprecated)]
use tss::token_builder::build_token;

use common::types::{Receipt, TokenClaims};
use crypto::pq_sign::generate_pq_keypair;
use crypto::receipts::{hash_receipt, sign_receipt};
use crypto::threshold::{dkg, verify_group_signature};
use tss::distributed::distribute_shares;
use tss::token_builder::build_token_distributed;
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

#[allow(deprecated)]
#[test]
fn token_built_and_verifiable() {
    let dkg_result = dkg(5, 3);
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _pq_vk) = generate_pq_keypair();

    let token = build_token(&claims, &mut shares[..3], &group, &ratchet_key, &pq_sk)
        .expect("build_token should succeed");

    // Verify the FROST signature against the group key
    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();
    assert!(verify_group_signature(&group, &msg, &token.frost_signature));
}

#[allow(deprecated)]
#[test]
fn token_claims_preserved() {
    let dkg_result = dkg(5, 3);
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _pq_vk) = generate_pq_keypair();

    let token = build_token(&claims, &mut shares[..3], &group, &ratchet_key, &pq_sk)
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

#[allow(deprecated)]
#[test]
fn test_ratchet_tag_is_real() {
    let dkg_result = dkg(5, 3);
    let mut shares = dkg_result.shares;
    let group = dkg_result.group;
    let claims = test_claims();
    let ratchet_key = test_ratchet_key();
    let (pq_sk, _pq_vk) = generate_pq_keypair();

    let token = build_token(&claims, &mut shares[..3], &group, &ratchet_key, &pq_sk)
        .expect("build_token should succeed");

    // The ratchet tag must NOT be all zeros (the old placeholder)
    assert_ne!(token.ratchet_tag, [0u8; 64], "ratchet tag must not be all zeros");
    // It also should not be a trivial constant
    assert_ne!(token.ratchet_tag, [0xDD; 64]);
}

// ── Distributed signing tests ─────────────────────────────────────────

#[test]
fn test_distributed_signing_works() {
    // DKG -> distribute into 5 separate SignerNodes
    let mut dkg_result = dkg(5, 3);
    let group = &dkg_result.group;
    let public_key_package = group.public_key_package.clone();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    // Coordinator takes 3 nodes, signs message
    let message = b"distributed-signing-test";
    let mut signers: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let sig = coordinator
        .coordinate_signing(&mut signers, message)
        .expect("distributed signing should succeed");

    // Verify signature with public key
    assert!(verify_group_signature(
        &crypto::threshold::ThresholdGroup {
            threshold: 3,
            total: 5,
            public_key_package,
        },
        message,
        &sig,
    ));
}

#[test]
fn test_distributed_2_of_5_fails() {
    // Only 2 nodes -> coordinator rejects (below threshold)
    let mut dkg_result = dkg(5, 3);
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    let message = b"should-fail";
    let mut signers: Vec<&mut _> = nodes.iter_mut().take(2).collect();
    let result = coordinator.coordinate_signing(&mut signers, message);
    assert!(result.is_err(), "signing with 2 of 5 (threshold=3) must fail");
    assert!(
        result.unwrap_err().contains("need 3 signers, got 2"),
        "error should mention threshold requirement"
    );
}

#[test]
fn test_distributed_different_subsets_produce_valid_sigs() {
    // Nodes {0,1,2} sign -> valid
    // Nodes {2,3,4} sign -> valid
    // Same group key verifies both
    let mut dkg_result = dkg(5, 3);
    let public_key_package = dkg_result.group.public_key_package.clone();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    let message = b"subset-test-message";

    let group_for_verify = crypto::threshold::ThresholdGroup {
        threshold: 3,
        total: 5,
        public_key_package,
    };

    // Subset {0,1,2}
    {
        let mut signers: Vec<&mut _> = nodes.iter_mut().take(3).collect();
        let sig = coordinator
            .coordinate_signing(&mut signers, message)
            .expect("subset {0,1,2} should sign");
        assert!(verify_group_signature(&group_for_verify, message, &sig));
    }

    // Subset {2,3,4}
    {
        let mut signers: Vec<&mut _> = nodes.iter_mut().skip(2).take(3).collect();
        let sig = coordinator
            .coordinate_signing(&mut signers, message)
            .expect("subset {2,3,4} should sign");
        assert!(verify_group_signature(&group_for_verify, message, &sig));
    }
}

#[test]
fn test_each_node_holds_exactly_one_share() {
    // After distribute_shares, each SignerNode has one KeyPackage
    // The coordinator has NO signing capability (only PublicKeyPackage)
    let mut dkg_result = dkg(5, 3);
    let (coordinator, nodes) = distribute_shares(&mut dkg_result);

    // 5 nodes, each with a unique identifier
    assert_eq!(nodes.len(), 5);
    let mut ids: Vec<_> = nodes.iter().map(|n| n.identifier()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 5, "each node must have a unique identifier");

    // The coordinator only has the public key package -- verify it has
    // the right threshold configured.
    assert_eq!(coordinator.threshold, 3);

    // The original DKG result's shares are drained (moved into nodes)
    assert!(dkg_result.shares.is_empty());
}

#[test]
fn test_coordinator_cannot_sign_alone() {
    // Coordinator with 0 signers -> error
    let mut dkg_result = dkg(5, 3);
    let (coordinator, _nodes) = distribute_shares(&mut dkg_result);

    let message = b"coordinator-alone";
    let mut no_signers: Vec<&mut tss::distributed::SignerNode> = vec![];
    let result = coordinator.coordinate_signing(&mut no_signers, message);
    assert!(result.is_err(), "coordinator with 0 signers must fail");
}

#[test]
fn test_distributed_token_built_and_verifiable() {
    // Use the distributed path to build a token and verify it
    let mut dkg_result = dkg(5, 3);
    let public_key_package = dkg_result.group.public_key_package.clone();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    let claims = test_claims();
    let ratchet_key = test_ratchet_key();

    let (pq_sk, _pq_vk) = generate_pq_keypair();
    let mut signers: Vec<&mut _> = nodes.iter_mut().take(3).collect();
    let token = build_token_distributed(&claims, &coordinator, &mut signers, &ratchet_key, &pq_sk)
        .expect("build_token_distributed should succeed");

    // Verify the FROST signature against the group key
    let claims_bytes = postcard::to_allocvec(&claims).unwrap();
    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();
    let group_for_verify = crypto::threshold::ThresholdGroup {
        threshold: 3,
        total: 5,
        public_key_package,
    };
    assert!(verify_group_signature(&group_for_verify, &msg, &token.frost_signature));

    // Ratchet tag must be real
    assert_ne!(token.ratchet_tag, [0u8; 64]);
}
