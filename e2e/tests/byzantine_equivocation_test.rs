//! Byzantine equivocation detection test suite.
//!
//! Tests that Byzantine nodes sending conflicting data are detected, that
//! 3-of-7 Byzantine nodes prevent consensus, and that forged ML-DSA-87
//! signatures are rejected by the audit pipeline.

use audit::bft::{BftAuditCluster, BFT_QUORUM, MIN_BFT_NODES};
use common::types::AuditEventType;
use crypto::pq_sign::{
    generate_pq_keypair, pq_sign_raw, pq_verify_raw,
};
use uuid::Uuid;

// ── Constants ────────────────────────────────────────────────────────────

const CLASSIFICATION_UNCLASSIFIED: u8 = 0;

// ── Helpers ──────────────────────────────────────────────────────────────

/// Spawn a thread with an 8 MB stack so ML-DSA-87 key generation does not
/// overflow the default 2 MB Rust test thread stack.
fn run_with_large_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked")
}

// ── Test 1: Byzantine nodes sending conflicting data are detected ─────────

#[test]
fn test_byzantine_nodes_sending_conflicting_data_are_detected() {
    // Create a 7-node cluster (f=2, quorum=5).
    let mut cluster = BftAuditCluster::new(7);

    assert_eq!(
        cluster.nodes.len(),
        MIN_BFT_NODES,
        "cluster must have exactly {} nodes for BFT guarantees, got {}",
        MIN_BFT_NODES,
        cluster.nodes.len()
    );

    // Mark two nodes Byzantine — within f=2 tolerance.
    cluster.set_byzantine(0);
    cluster.set_byzantine(1);

    // A quorum of 5 honest nodes should still reach consensus.
    let result = cluster.propose_entry(
        AuditEventType::AuthSuccess,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.05,
        vec![],
        CLASSIFICATION_UNCLASSIFIED,
    );

    assert!(
        result.is_ok(),
        "consensus should succeed with 2 Byzantine nodes (f=2 tolerated); got: {:?}",
        result.err()
    );

    // Chain divergence: Byzantine nodes have empty logs while honest nodes
    // have one accepted entry. detect_byzantine() should identify them.
    let detected = cluster.detect_byzantine();

    // We expect the 2 pre-marked Byzantine nodes to be flagged via chain
    // divergence (they have empty logs diverging from the 5-node majority).
    assert!(
        !detected.is_empty(),
        "detect_byzantine() should identify diverged nodes after proposal; \
         honest nodes accepted 1 entry while Byzantine nodes have empty logs"
    );

    // Verify the remaining honest nodes still have a consistent chain.
    assert!(
        cluster.verify_consistency(),
        "honest node chains must remain consistent after Byzantine detection"
    );
}

// ── Test 2: 3 Byzantine of 7 nodes prevents consensus ───────────────────

#[test]
fn test_three_byzantine_of_seven_prevents_consensus() {
    // Create a standard 7-node cluster (f=2, quorum=5).
    let mut cluster = BftAuditCluster::new(7);

    // Mark 3 nodes Byzantine — one more than f=2, exceeding fault tolerance.
    cluster.set_byzantine(0);
    cluster.set_byzantine(1);
    cluster.set_byzantine(2);

    // With only 4 honest nodes and quorum=5, consensus must fail.
    let result = cluster.propose_entry(
        AuditEventType::AuthFailure,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.9,
        vec![],
        CLASSIFICATION_UNCLASSIFIED,
    );

    assert!(
        result.is_err(),
        "consensus must FAIL when 3 of 7 nodes are Byzantine (exceeds f=2 tolerance); \
         only {} honest nodes present but quorum requires {}",
        4,
        BFT_QUORUM
    );

    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("quorum not met"),
        "error message should indicate quorum not met; got: '{}'",
        err_msg
    );
}

// ── Test 3: Forged ML-DSA-87 signatures are rejected ────────────────────

#[test]
fn test_forged_mldsa87_signatures_are_rejected() {
    run_with_large_stack(|| {
        // Generate two independent ML-DSA-87 keypairs.
        let (signing_key_a, verifying_key_a) = generate_pq_keypair();
        let (signing_key_b, _verifying_key_b) = generate_pq_keypair();

        let message = b"audit-entry-hash-bytes-32-bytes!"; // representative data

        // Sign with key A.
        let sig_a = pq_sign_raw(&signing_key_a, message);
        assert!(
            !sig_a.is_empty(),
            "ML-DSA-87 signature should not be empty"
        );

        // Verify with the correct key A — must succeed.
        assert!(
            pq_verify_raw(&verifying_key_a, message, &sig_a),
            "ML-DSA-87 signature verification with correct key must succeed; \
             key_a signed the message, verifying_key_a should accept it"
        );

        // Forge: produce a signature with key B, then try to verify with key A.
        let forged_sig = pq_sign_raw(&signing_key_b, message);
        assert!(
            !pq_verify_raw(&verifying_key_a, message, &forged_sig),
            "ML-DSA-87 signature produced by key_b must be REJECTED by verifying_key_a; \
             cross-key forgery must not pass"
        );

        // Forge: bit-flip the legitimate signature.
        let mut corrupted_sig = sig_a.clone();
        corrupted_sig[0] ^= 0xFF;
        corrupted_sig[sig_a.len() / 2] ^= 0xAB;
        assert!(
            !pq_verify_raw(&verifying_key_a, message, &corrupted_sig),
            "bit-flipped ML-DSA-87 signature must be REJECTED; \
             signature integrity check must catch single-bit corruption"
        );

        // Forge: wrong message with correct key/sig pair.
        let tampered_message = b"tampered-audit-entry-hash-bytes!";
        assert!(
            !pq_verify_raw(&verifying_key_a, tampered_message, &sig_a),
            "ML-DSA-87 signature over original message must be REJECTED for a \
             different message; binding must be message-specific"
        );

        // Forge: truncated signature.
        let truncated = &sig_a[..sig_a.len() / 2];
        assert!(
            !pq_verify_raw(&verifying_key_a, message, truncated),
            "truncated ML-DSA-87 signature must be REJECTED; partial signatures \
             must never be accepted"
        );

        // Forge: empty signature.
        assert!(
            !pq_verify_raw(&verifying_key_a, message, &[]),
            "empty signature must be REJECTED by ML-DSA-87 verifier"
        );
    });
}

// ── Test 4: Cluster signing key signs and validates entries end-to-end ───

#[test]
fn test_cluster_with_signing_key_accepts_quorum_entries() {
    run_with_large_stack(|| {
        let (signing_key, _verifying_key) = generate_pq_keypair();
        let mut cluster = BftAuditCluster::new_with_signing_key(7, signing_key);

        // Propose three consecutive entries; each must succeed.
        for i in 0..3u32 {
            let result = cluster.propose_entry(
                AuditEventType::AuthSuccess,
                vec![Uuid::new_v4()],
                vec![Uuid::new_v4()],
                i as f64 * 0.1,
                vec![],
                CLASSIFICATION_UNCLASSIFIED,
            );
            assert!(
                result.is_ok(),
                "entry {} must be accepted by honest 7-node cluster; got: {:?}",
                i,
                result.err()
            );
        }

        assert!(
            cluster.verify_consistency(),
            "all honest nodes must have identical chains after 3 successful proposals"
        );

        // Every honest node's epoch must equal the number of accepted entries.
        for node in cluster.nodes.iter().filter(|n| !n.is_byzantine) {
            assert_eq!(
                node.epoch, 3,
                "honest node {} epoch should be 3 after 3 accepted entries, got {}",
                node.node_id, node.epoch
            );
        }
    });
}

// ── Test 5: verify_consistency returns false on chain divergence ──────────

#[test]
fn test_verify_consistency_detects_divergence() {
    // Build a 7-node cluster and accept one entry.
    let mut cluster = BftAuditCluster::new(7);

    cluster
        .propose_entry(
            AuditEventType::KeyRotation,
            vec![Uuid::new_v4()],
            vec![],
            0.0,
            vec![],
            CLASSIFICATION_UNCLASSIFIED,
        )
        .expect("genesis proposal must succeed on honest 7-node cluster");

    // Before any manipulation all honest nodes must be consistent.
    assert!(
        cluster.verify_consistency(),
        "honest cluster must be consistent after one accepted entry"
    );

    // Simulate divergence by marking nodes 1..6 as Byzantine (so only node 0
    // acts as honest proposer) and then proposing a second entry.  Only node 0
    // will accept the new entry (the others are Byzantine and refuse), but the
    // length check in verify_consistency will see node 0 has 2 entries while
    // the 5 still-honest-looking-but-Byzantine nodes have only 1, triggering
    // a divergence report.
    for id in 1u8..7 {
        cluster.set_byzantine(id);
    }

    // propose_entry will fail quorum (only 1 honest acceptor), but node 0's
    // log will grow to length 2 because accept_entry succeeds for honest nodes
    // regardless of quorum. We accept the error.
    let _ = cluster.propose_entry(
        AuditEventType::AuthFailure,
        vec![Uuid::new_v4()],
        vec![],
        0.9,
        vec![],
        CLASSIFICATION_UNCLASSIFIED,
    );

    // Restore nodes 1..6 as non-Byzantine so verify_consistency compares them
    // (the function only compares non-Byzantine nodes internally).  We need at
    // least two honest nodes with different lengths for the check to fire.
    // Reset node 1 to honest so it has a different length than node 0.
    cluster.nodes[1].is_byzantine = false;

    // Now node 0 has 2 entries and node 1 has 1 entry — chains have diverged.
    assert!(
        !cluster.verify_consistency(),
        "verify_consistency must return false when honest nodes have different \
         chain lengths (node 0 has 2 entries, node 1 has 1 entry)"
    );
}
