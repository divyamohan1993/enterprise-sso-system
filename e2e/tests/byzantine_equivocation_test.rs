//! Byzantine equivocation detection test suite.
//!
//! Tests that Byzantine nodes sending conflicting data are detected, that
//! 4+-of-11 Byzantine nodes prevent consensus, and that forged ML-DSA-87
//! signatures are rejected by the audit pipeline.

use audit::bft::{BftAuditCluster, BFT_QUORUM, MIN_BFT_NODES};
use common::types::{AuditEntry, AuditEventType};
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
    // Create an 11-node cluster (f=3, quorum=7).
    let mut cluster = BftAuditCluster::new(11);

    assert_eq!(
        cluster.nodes.len(),
        MIN_BFT_NODES,
        "cluster must have exactly {} nodes for BFT guarantees, got {}",
        MIN_BFT_NODES,
        cluster.nodes.len()
    );

    // Mark three nodes Byzantine -- within f=3 tolerance.
    cluster.set_byzantine(0);
    cluster.set_byzantine(1);
    cluster.set_byzantine(2);

    // A quorum of 7 honest nodes should still reach consensus.
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
        "consensus should succeed with 3 Byzantine nodes (f=3 tolerated); got: {:?}",
        result.err()
    );

    // Chain divergence: Byzantine nodes have empty logs while honest nodes
    // have one accepted entry. detect_byzantine() should identify them.
    let detected = cluster.detect_byzantine();

    // We expect the 3 pre-marked Byzantine nodes to be flagged via chain
    // divergence (they have empty logs diverging from the 8-node majority).
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

// ── Test 2: 5 Byzantine of 11 nodes prevents consensus ───────────────────

#[test]
fn test_five_byzantine_of_eleven_prevents_consensus() {
    // Create a standard 11-node cluster (f=3, quorum=7).
    let mut cluster = BftAuditCluster::new(11);

    // Mark 5 nodes Byzantine -- two more than f=3, exceeding fault tolerance.
    cluster.set_byzantine(0);
    cluster.set_byzantine(1);
    cluster.set_byzantine(2);
    cluster.set_byzantine(3);
    cluster.set_byzantine(4);

    // With only 6 honest nodes and quorum=7, consensus must fail.
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
        "consensus must FAIL when 5 of 11 nodes are Byzantine (exceeds f=3 tolerance); \
         only {} honest nodes present but quorum requires {}",
        6,
        BFT_QUORUM
    );

    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("quorum") || err_msg.contains("proposer"),
        "error message should indicate quorum or proposer failure; got: '{}'",
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
        let mut cluster = BftAuditCluster::new_with_signing_key(11, signing_key);

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
                "entry {} must be accepted by honest 11-node cluster; got: {:?}",
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
    // Build an 11-node cluster and accept one entry.
    let mut cluster = BftAuditCluster::new(11);

    cluster
        .propose_entry(
            AuditEventType::KeyRotation,
            vec![Uuid::new_v4()],
            vec![],
            0.0,
            vec![],
            CLASSIFICATION_UNCLASSIFIED,
        )
        .expect("genesis proposal must succeed on honest 11-node cluster");

    // Before any manipulation all honest nodes must be consistent.
    assert!(
        cluster.verify_consistency(),
        "honest cluster must be consistent after one accepted entry"
    );

    // Simulate divergence by directly manipulating a node's log.
    // The two-phase BFT protocol prevents partial commits, so we cannot
    // create divergence through the normal proposal path. Instead, we
    // directly tamper with a node's state to simulate what a Byzantine
    // attacker with disk access could do.
    //
    // Append a rogue entry directly to node 1's log (bypassing the protocol).
    // Use the correct prev_hash so append_raw accepts it, but the content
    // differs from what other nodes have, creating a length divergence.
    let node1_last_hash = audit::log::hash_entry(
        &cluster.nodes[1].log.entries()[cluster.nodes[1].log.len() - 1],
    );
    let rogue_entry = AuditEntry {
        event_id: Uuid::new_v4(),
        event_type: AuditEventType::AuthFailure,
        user_ids: vec![Uuid::new_v4()],
        device_ids: vec![],
        ceremony_receipts: vec![],
        risk_score: 0.9,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64,
        prev_hash: node1_last_hash,
        signature: vec![],
        classification: CLASSIFICATION_UNCLASSIFIED,
    };
    // Force-append the rogue entry to node 1's log
    cluster.nodes[1]
        .log
        .append_raw(rogue_entry)
        .expect("rogue append with correct prev_hash must succeed");

    // Now node 0 has 1 entry and node 1 has 2 entries.
    assert!(
        !cluster.verify_consistency(),
        "verify_consistency must return false when honest nodes have different \
         chain lengths (node 0 has 1 entry, node 1 has 2 entries due to tampering)"
    );
}
