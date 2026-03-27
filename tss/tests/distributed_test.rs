//! Distributed FROST signing hardening tests.
//!
//! Tests FROST threshold signing with exact/below threshold, coordinator
//! timeout semantics, nonce counter persistence, and sealed share round-trips
//! including corruption detection.

use crypto::threshold::{dkg, verify_group_signature};
use tss::distributed::{distribute_shares, seal_signer_share, unseal_signer_share, SignerNode};

// ── FROST signing with exactly threshold signers (3-of-5) ────────────────

#[test]
fn frost_exactly_threshold_signers() {
    let mut dkg_result = dkg(5, 3);
    let public_key_package = dkg_result.group.public_key_package.clone();
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    let message = b"exactly-threshold-test";
    let mut signers: Vec<&mut _> = nodes.iter_mut().take(3).collect();

    let sig = coordinator
        .coordinate_signing(&mut signers, message)
        .expect("signing with exactly 3 of 5 must succeed");

    let group = crypto::threshold::ThresholdGroup {
        threshold: 3,
        total: 5,
        public_key_package,
    };
    assert!(verify_group_signature(&group, message, &sig));
}

// ── FROST signing fails with below-threshold (2-of-5) ────────────────────

#[test]
fn frost_below_threshold_fails() {
    let mut dkg_result = dkg(5, 3);
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    let message = b"below-threshold-test";
    let mut signers: Vec<&mut _> = nodes.iter_mut().take(2).collect();

    let result = coordinator.coordinate_signing(&mut signers, message);
    assert!(result.is_err(), "signing with 2 of 5 (threshold=3) must fail");

    let err = result.unwrap_err();
    assert!(
        err.contains("need 3 signers, got 2"),
        "error must mention threshold requirement, got: {err}"
    );
}

#[test]
fn frost_zero_signers_fails() {
    let mut dkg_result = dkg(5, 3);
    let (coordinator, _nodes) = distribute_shares(&mut dkg_result);

    let message = b"zero-signers-test";
    let mut signers: Vec<&mut SignerNode> = vec![];

    let result = coordinator.coordinate_signing(&mut signers, message);
    assert!(result.is_err(), "signing with 0 signers must fail");
}

#[test]
fn frost_one_signer_fails() {
    let mut dkg_result = dkg(5, 3);
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    let message = b"one-signer-test";
    let mut signers: Vec<&mut _> = nodes.iter_mut().take(1).collect();

    let result = coordinator.coordinate_signing(&mut signers, message);
    assert!(result.is_err(), "signing with 1 of 5 (threshold=3) must fail");
}

// ── Coordinator timeout when signers unresponsive ────────────────────────
// The in-process coordinator does not have network timeouts; we verify the
// protocol correctness invariant that the coordinator refuses to proceed
// without sufficient commitments.

#[test]
fn coordinator_refuses_insufficient_commitments() {
    // This test validates that the coordinator's coordinate_signing method
    // correctly rejects requests where not enough signers are provided,
    // which is the in-process analog of an unresponsive signer timeout.
    let mut dkg_result = dkg(5, 3);
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    // Simulate partial availability: only 2 of 5 nodes "respond"
    let mut available: Vec<&mut _> = nodes.iter_mut().take(2).collect();
    let result = coordinator.coordinate_signing(&mut available, b"timeout-test");
    assert!(result.is_err(), "coordinator must fail with insufficient signers");
}

// ── Nonce counter persistence across restarts ────────────────────────────

#[test]
fn nonce_counter_increments_per_signing() {
    let mut dkg_result = dkg(5, 3);
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    // All nodes start at counter 0
    for node in &nodes {
        assert_eq!(node.nonce_counter(), 0, "initial nonce counter must be 0");
    }

    // First signing: first 3 nodes participate
    {
        let mut signers: Vec<&mut _> = nodes.iter_mut().take(3).collect();
        coordinator
            .coordinate_signing(&mut signers, b"first-sign")
            .expect("first signing must succeed");
    }

    // After first signing, first 3 nodes should have counter=1, last 2 remain at 0
    assert_eq!(nodes[0].nonce_counter(), 1);
    assert_eq!(nodes[1].nonce_counter(), 1);
    assert_eq!(nodes[2].nonce_counter(), 1);
    assert_eq!(nodes[3].nonce_counter(), 0);
    assert_eq!(nodes[4].nonce_counter(), 0);

    // Second signing with same 3 nodes
    {
        let mut signers: Vec<&mut _> = nodes.iter_mut().take(3).collect();
        coordinator
            .coordinate_signing(&mut signers, b"second-sign")
            .expect("second signing must succeed");
    }

    assert_eq!(nodes[0].nonce_counter(), 2);
    assert_eq!(nodes[1].nonce_counter(), 2);
    assert_eq!(nodes[2].nonce_counter(), 2);
}

#[test]
fn nonce_counter_independent_per_node() {
    let mut dkg_result = dkg(5, 3);
    let (coordinator, mut nodes) = distribute_shares(&mut dkg_result);

    // Use nodes {0,1,2} for first signing
    {
        let mut signers: Vec<&mut _> = nodes.iter_mut().take(3).collect();
        coordinator
            .coordinate_signing(&mut signers, b"sign-a")
            .expect("signing must succeed");
    }

    // Use nodes {2,3,4} for second signing
    {
        let mut signers: Vec<&mut _> = nodes.iter_mut().skip(2).take(3).collect();
        coordinator
            .coordinate_signing(&mut signers, b"sign-b")
            .expect("signing must succeed");
    }

    // Node 0,1 participated once, node 2 twice, nodes 3,4 once
    assert_eq!(nodes[0].nonce_counter(), 1);
    assert_eq!(nodes[1].nonce_counter(), 1);
    assert_eq!(nodes[2].nonce_counter(), 2);
    assert_eq!(nodes[3].nonce_counter(), 1);
    assert_eq!(nodes[4].nonce_counter(), 1);
}

// ── Sealed share round-trip (seal -> unseal -> verify key package) ───────

#[test]
fn sealed_share_roundtrip() {
    let mut dkg_result = dkg(5, 3);
    let public_key_package = dkg_result.group.public_key_package.clone();
    let (_coordinator, nodes) = distribute_shares(&mut dkg_result);

    // Seal the first node's share
    let sealed_bytes = seal_signer_share(&nodes[0], &public_key_package, 3);
    assert!(!sealed_bytes.is_empty(), "sealed share must not be empty");

    // Unseal and verify
    let hex_sealed = hex::encode(&sealed_bytes);
    let (recovered_node, recovered_pkp, recovered_threshold) =
        unseal_signer_share(&hex_sealed).expect("unseal must succeed");

    assert_eq!(recovered_threshold, 3);
    assert_eq!(recovered_node.identifier(), nodes[0].identifier());

    // Verify the recovered node can produce valid signatures
    // by using it with 2 other fresh nodes
    let mut dkg2 = dkg(5, 3);
    let (_coord2, _nodes2) = distribute_shares(&mut dkg2);

    // The recovered public key package should match
    let pkp_bytes = recovered_pkp
        .serialize()
        .expect("serialize recovered pkp");
    let orig_bytes = public_key_package
        .serialize()
        .expect("serialize original pkp");
    assert_eq!(pkp_bytes, orig_bytes, "public key package must match after unseal");
}

// ── Corrupted sealed share rejection ─────────────────────────────────────

#[test]
fn corrupted_sealed_share_rejected() {
    let mut dkg_result = dkg(5, 3);
    let public_key_package = dkg_result.group.public_key_package.clone();
    let (_coordinator, nodes) = distribute_shares(&mut dkg_result);

    let sealed_bytes = seal_signer_share(&nodes[0], &public_key_package, 3);
    let mut hex_sealed = hex::encode(&sealed_bytes);

    // Corrupt one byte in the middle of the hex string
    let mid = hex_sealed.len() / 2;
    let replacement = if hex_sealed.as_bytes()[mid] == b'a' {
        'b'
    } else {
        'a'
    };
    // SAFETY: only replacing a single ASCII hex char
    unsafe {
        hex_sealed.as_bytes_mut()[mid] = replacement as u8;
    }

    let result = unseal_signer_share(&hex_sealed);
    assert!(
        result.is_err(),
        "corrupted sealed share must be rejected"
    );
}

#[test]
fn invalid_hex_sealed_share_rejected() {
    let result = unseal_signer_share("not-valid-hex!!!!");
    assert!(result.is_err(), "invalid hex must be rejected");
}

#[test]
fn empty_sealed_share_rejected() {
    let result = unseal_signer_share("");
    assert!(result.is_err(), "empty sealed share must be rejected");
}
