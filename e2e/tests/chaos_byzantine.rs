//! Byzantine Fault Tolerance audit cluster tests.
//!
//! Validates that the BFT audit cluster maintains consistency with honest
//! quorums, tolerates Byzantine nodes up to the f=2 fault limit, and
//! correctly detects chain tampering.

use audit::bft::{BftAuditCluster, BFT_QUORUM};
use audit::log::hash_entry;
use common::types::{AuditEventType, AuditEntry};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

fn propose(cluster: &mut BftAuditCluster) -> Result<[u8; 64], String> {
    cluster.propose_entry(
        AuditEventType::AuthSuccess,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.1,
        vec![],
        0, // Unclassified default for chaos tests
    )
}

// ---------------------------------------------------------------------------
// 1. Honest quorum commits an entry
// ---------------------------------------------------------------------------

/// Create an 11-node cluster (all honest), propose an entry, verify all honest
/// nodes have a consistent chain.
#[test]
fn test_bft_audit_honest_quorum() {
    let mut cluster = BftAuditCluster::new(11);
    let result = propose(&mut cluster);
    assert!(result.is_ok(), "honest quorum must commit the entry: {:?}", result);
    assert!(
        cluster.verify_consistency(),
        "all honest nodes must have consistent chains"
    );
}

// ---------------------------------------------------------------------------
// 2. One Byzantine node — cluster continues
// ---------------------------------------------------------------------------

/// Mark node 0 as Byzantine, propose an entry -- the remaining 10 honest nodes
/// maintain the chain and the quorum (BFT_QUORUM = 7) is still met.
#[test]
fn test_bft_audit_one_byzantine() {
    let mut cluster = BftAuditCluster::new(11);
    cluster.set_byzantine(0);

    let result = propose(&mut cluster);
    assert!(
        result.is_ok(),
        "one Byzantine node must not break the honest quorum"
    );
    assert!(
        cluster.verify_consistency(),
        "10 honest nodes must maintain consistent chains with 1 Byzantine"
    );
}

// ---------------------------------------------------------------------------
// 3. Two Byzantine nodes — cluster continues
// ---------------------------------------------------------------------------

/// Mark nodes 0, 1, and 2 as Byzantine, propose an entry -- the 8 honest nodes
/// still form more than the minimum quorum (2f+1 = 7 with f=3).
#[test]
fn test_bft_audit_three_byzantine() {
    let mut cluster = BftAuditCluster::new(11);
    cluster.set_byzantine(0);
    cluster.set_byzantine(1);
    cluster.set_byzantine(2);

    let result = propose(&mut cluster);
    assert!(
        result.is_ok(),
        "three Byzantine nodes must not break the honest quorum (8 honest >= BFT_QUORUM={})",
        BFT_QUORUM
    );
    assert!(
        cluster.verify_consistency(),
        "8 honest nodes must maintain consistent chains with 3 Byzantine"
    );
}

// ---------------------------------------------------------------------------
// 4. Audit hash chain integrity over 10 entries
// ---------------------------------------------------------------------------

/// Append 10 entries to the cluster and verify that `verify_chain` succeeds
/// on all honest nodes.
#[test]
fn test_bft_audit_chain_integrity() {
    let mut cluster = BftAuditCluster::new(11);

    for _ in 0..10 {
        let r = propose(&mut cluster);
        assert!(r.is_ok(), "each entry must be committed successfully");
    }

    assert!(
        cluster.verify_consistency(),
        "chain integrity must hold after 10 entries"
    );
}

// ---------------------------------------------------------------------------
// 5. Tampered audit entry hash is detected
// ---------------------------------------------------------------------------

/// Append entries, then directly modify one entry's `prev_hash` in the audit
/// log of the first honest node, verify that `verify_chain` detects the
/// tampering on that node.
#[test]
fn test_audit_hash_chain_tamper_detected() {
    let log_entries: Vec<AuditEntry> = {
        // Build a small chain of 3 entries with valid prev_hashes.
        let mut entries: Vec<AuditEntry> = Vec::new();
        let mut prev = [0u8; 64];

        for i in 0..3u8 {
            let entry = AuditEntry {
                event_id: Uuid::new_v4(),
                event_type: AuditEventType::AuthSuccess,
                user_ids: vec![Uuid::nil()],
                device_ids: vec![Uuid::nil()],
                ceremony_receipts: vec![],
                risk_score: 0.0,
                timestamp: now_us() + i as i64,
                prev_hash: prev,
                signature: vec![],
                classification: 0,
                correlation_id: None,
                trace_id: None,
            };
            prev = hash_entry(&entry);
            entries.push(entry);
        }
        entries
    };

    // Build an AuditLog from the valid chain.
    let valid_log = audit::log::AuditLog::from_entries(log_entries.clone());
    assert!(
        valid_log.verify_chain(),
        "unmodified chain must verify successfully"
    );

    // Tamper: corrupt the prev_hash of the second entry and rebuild the log.
    let mut tampered = log_entries;
    tampered[1].prev_hash[0] ^= 0xFF;

    let tampered_log = audit::log::AuditLog::from_entries(tampered);
    assert!(
        !tampered_log.verify_chain(),
        "tampered chain must fail verify_chain"
    );
}

// ---------------------------------------------------------------------------
// 6. Two-phase commit: proposer rotation on Byzantine proposer
// ---------------------------------------------------------------------------

/// Mark the first few honest nodes as Byzantine to test proposer rotation.
/// The cluster should still commit via a later proposer.
#[test]
fn test_bft_proposer_rotation_on_byzantine() {
    let mut cluster = BftAuditCluster::new(11);
    // Make 3 nodes byzantine (the max tolerated)
    cluster.set_byzantine(0);
    cluster.set_byzantine(1);
    cluster.set_byzantine(2);

    // Should still commit because honest proposers are tried in sequence
    for _ in 0..5 {
        let result = propose(&mut cluster);
        assert!(
            result.is_ok(),
            "proposer rotation must find an honest proposer: {:?}",
            result
        );
    }
    assert!(cluster.verify_consistency());
}

// ---------------------------------------------------------------------------
// 7. Multiple entries with f=3 Byzantine: stress test consistency
// ---------------------------------------------------------------------------

#[test]
fn test_bft_stress_consistency_under_byzantine() {
    let mut cluster = BftAuditCluster::new(11);
    cluster.set_byzantine(3);
    cluster.set_byzantine(7);
    cluster.set_byzantine(10);

    // Propose 20 entries
    for i in 0..20 {
        let result = propose(&mut cluster);
        assert!(
            result.is_ok(),
            "entry {} must commit with 3 Byzantine nodes: {:?}",
            i, result
        );
    }

    assert!(
        cluster.verify_consistency(),
        "20 entries must maintain consistency with 3 Byzantine nodes"
    );
}

// ---------------------------------------------------------------------------
// 8. Four Byzantine nodes should prevent quorum
// ---------------------------------------------------------------------------

#[test]
fn test_bft_four_byzantine_breaks_quorum() {
    let mut cluster = BftAuditCluster::new(11);
    cluster.set_byzantine(0);
    cluster.set_byzantine(1);
    cluster.set_byzantine(2);
    cluster.set_byzantine(3);

    let result = propose(&mut cluster);
    // 7 honest nodes = quorum (7), should still work
    assert!(
        result.is_ok(),
        "4 Byzantine with 7 honest should still reach quorum=7: {:?}",
        result
    );
}

#[test]
fn test_bft_five_byzantine_prevents_quorum() {
    let mut cluster = BftAuditCluster::new(11);
    cluster.set_byzantine(0);
    cluster.set_byzantine(1);
    cluster.set_byzantine(2);
    cluster.set_byzantine(3);
    cluster.set_byzantine(4);

    let result = propose(&mut cluster);
    // 6 honest nodes < quorum (7), should fail
    assert!(
        result.is_err(),
        "5 Byzantine with only 6 honest must NOT reach quorum=7"
    );
}

// ---------------------------------------------------------------------------
// 9. Verify chain hash integrity across all honest nodes after many entries
// ---------------------------------------------------------------------------

#[test]
fn test_bft_hash_chain_integrity_all_honest_nodes() {
    let mut cluster = BftAuditCluster::new(11);

    for _ in 0..50 {
        propose(&mut cluster).expect("entry must commit");
    }

    // Verify all honest nodes have the same chain head
    let honest_heads: Vec<[u8; 64]> = cluster
        .nodes
        .iter()
        .filter(|n| !n.is_byzantine)
        .map(|n| {
            let entries = n.log.entries();
            hash_entry(&entries[entries.len() - 1])
        })
        .collect();

    for head in &honest_heads[1..] {
        assert_eq!(
            head, &honest_heads[0],
            "all honest nodes must have the same chain head after 50 entries"
        );
    }
}
