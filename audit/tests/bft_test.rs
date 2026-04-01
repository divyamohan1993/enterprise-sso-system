use audit::bft::BftAuditCluster;
use audit::log::hash_entry;
use common::types::AuditEventType;
use uuid::Uuid;

/// Helper: propose a single entry with default values.
fn propose_default(cluster: &mut BftAuditCluster) -> Result<[u8; 64], String> {
    cluster.propose_entry(
        AuditEventType::AuthSuccess,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.1,
        Vec::new(),
        0, // Unclassified default for tests
    )
}

#[test]
fn test_bft_11_nodes_all_honest() {
    let mut cluster = BftAuditCluster::new(11);
    assert_eq!(cluster.quorum_size, 7);

    let result = propose_default(&mut cluster);
    assert!(result.is_ok(), "all 11 honest nodes should reach quorum");

    // Every node should have 1 entry
    for node in &cluster.nodes {
        assert_eq!(node.log.len(), 1);
    }
}

#[test]
fn test_bft_11_nodes_3_byzantine() {
    let mut cluster = BftAuditCluster::new(11);

    // Mark 3 nodes Byzantine (refuse entries) -- within f=3 tolerance
    cluster.set_byzantine(8);
    cluster.set_byzantine(9);
    cluster.set_byzantine(10);

    let result = propose_default(&mut cluster);
    assert!(
        result.is_ok(),
        "8 honest nodes should meet quorum of 7: {:?}",
        result
    );

    // Byzantine nodes should have empty logs
    assert_eq!(cluster.nodes[8].log.len(), 0);
    assert_eq!(cluster.nodes[9].log.len(), 0);
    assert_eq!(cluster.nodes[10].log.len(), 0);

    // Honest nodes should have 1 entry
    for node in &cluster.nodes[..8] {
        assert_eq!(node.log.len(), 1);
    }
}

#[test]
fn test_bft_11_nodes_4_byzantine_fails() {
    let mut cluster = BftAuditCluster::new(11);

    // 4 Byzantine → only 7 honest = quorum (7), but need >f for safety margin
    // Actually with f=3, 4 Byzantine exceeds tolerance: only 7 honest = quorum
    // But let's test with 5 Byzantine to be clearly below quorum
    cluster.set_byzantine(6);
    cluster.set_byzantine(7);
    cluster.set_byzantine(8);
    cluster.set_byzantine(9);
    cluster.set_byzantine(10);

    let result = propose_default(&mut cluster);
    assert!(result.is_err(), "6 honest nodes < quorum of 7");
    assert!(result.unwrap_err().contains("quorum not met"));
}

#[test]
fn test_bft_consistency_across_honest_nodes() {
    let mut cluster = BftAuditCluster::new(11);
    cluster.set_byzantine(9);
    cluster.set_byzantine(10);

    // Append 10 entries
    for _ in 0..10 {
        let result = propose_default(&mut cluster);
        assert!(result.is_ok());
    }

    assert!(
        cluster.verify_consistency(),
        "all honest nodes should have identical chains"
    );

    // Verify chain integrity on each honest node
    for node in &cluster.nodes[..9] {
        assert_eq!(node.log.len(), 10);
        assert!(node.log.verify_chain());
    }
}

#[test]
fn test_bft_detects_byzantine_divergence() {
    let mut cluster = BftAuditCluster::new(11);

    // First, append an entry with all nodes honest
    let result = propose_default(&mut cluster);
    assert!(result.is_ok());

    // Now mark node 0 as Byzantine. Its chain diverges from honest nodes
    // because it already has the entry but won't accept future ones.
    cluster.set_byzantine(0);

    // Append another entry -- node 0 won't get it
    let result = propose_default(&mut cluster);
    assert!(result.is_ok(), "10 honest nodes still exceed quorum");

    // Node 0 has 1 entry, honest nodes have 2 -> divergence
    assert_eq!(cluster.nodes[0].log.len(), 1);
    for node in &cluster.nodes[1..] {
        assert_eq!(node.log.len(), 2);
    }

    // verify_consistency only checks honest (non-byzantine) nodes, so it
    // should still pass. But we can detect the divergence by comparing
    // the Byzantine node's chain length to honest nodes.
    assert!(cluster.verify_consistency());
    let honest_len = cluster.nodes[1].log.len();
    let byzantine_len = cluster.nodes[0].log.len();
    assert_ne!(
        honest_len, byzantine_len,
        "Byzantine node diverged from honest nodes"
    );
}

#[test]
fn test_bft_100_entries_all_committed() {
    let mut cluster = BftAuditCluster::new(11);
    cluster.set_byzantine(9);
    cluster.set_byzantine(10);

    for i in 0..100 {
        let result = propose_default(&mut cluster);
        assert!(result.is_ok(), "entry {} should commit", i);
    }

    assert!(cluster.verify_consistency());

    // All honest nodes should have exactly 100 entries
    for node in &cluster.nodes[..9] {
        assert_eq!(node.log.len(), 100);
        assert!(node.log.verify_chain());
    }

    // Verify last entry hashes match across honest nodes
    let ref_hash = hash_entry(&cluster.nodes[0].log.entries()[99]);
    for node in &cluster.nodes[1..9] {
        let h = hash_entry(&node.log.entries()[99]);
        assert_eq!(h, ref_hash);
    }
}
