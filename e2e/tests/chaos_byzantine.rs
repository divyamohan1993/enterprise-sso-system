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

/// Create a 7-node cluster (all honest), propose an entry, verify all honest
/// nodes have a consistent chain.
#[test]
fn test_bft_audit_honest_quorum() {
    let mut cluster = BftAuditCluster::new(7);
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

/// Mark node 0 as Byzantine, propose an entry — the remaining 6 honest nodes
/// maintain the chain and the quorum (BFT_QUORUM = 5) is still met.
#[test]
fn test_bft_audit_one_byzantine() {
    let mut cluster = BftAuditCluster::new(7);
    cluster.set_byzantine(0);

    let result = propose(&mut cluster);
    assert!(
        result.is_ok(),
        "one Byzantine node must not break the honest quorum"
    );
    assert!(
        cluster.verify_consistency(),
        "6 honest nodes must maintain consistent chains with 1 Byzantine"
    );
}

// ---------------------------------------------------------------------------
// 3. Two Byzantine nodes — cluster continues
// ---------------------------------------------------------------------------

/// Mark nodes 0 and 1 as Byzantine, propose an entry — the 5 honest nodes
/// still form the minimum quorum (2f+1 = 5 with f=2).
#[test]
fn test_bft_audit_two_byzantine() {
    let mut cluster = BftAuditCluster::new(7);
    cluster.set_byzantine(0);
    cluster.set_byzantine(1);

    let result = propose(&mut cluster);
    assert!(
        result.is_ok(),
        "two Byzantine nodes must not break the honest quorum (5 honest ≥ BFT_QUORUM={})",
        BFT_QUORUM
    );
    assert!(
        cluster.verify_consistency(),
        "5 honest nodes must maintain consistent chains with 2 Byzantine"
    );
}

// ---------------------------------------------------------------------------
// 4. Audit hash chain integrity over 10 entries
// ---------------------------------------------------------------------------

/// Append 10 entries to the cluster and verify that `verify_chain` succeeds
/// on all honest nodes.
#[test]
fn test_bft_audit_chain_integrity() {
    let mut cluster = BftAuditCluster::new(7);

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
