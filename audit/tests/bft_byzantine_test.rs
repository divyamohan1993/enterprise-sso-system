//! I17 [MED] Byzantine simulation: forged signatures from f honest-equivalent
//! nodes must not poison the consistent honest chain.

mod test_bootstrap;
#[allow(unused_imports)]
use test_bootstrap as _;

use audit::bft::BftAuditCluster;
use common::types::AuditEventType;
use uuid::Uuid;

#[test]
fn byzantine_minority_cannot_poison_chain() {
    let (sk, _vk) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = BftAuditCluster::new_with_signing_key(11, sk);

    // Mark 3 nodes Byzantine (max f for n=11).
    cluster.set_byzantine(8);
    cluster.set_byzantine(9);
    cluster.set_byzantine(10);

    for i in 0..15 {
        cluster
            .propose_entry(
                AuditEventType::AuthSuccess,
                vec![Uuid::new_v4()],
                vec![],
                (i as f64) * 0.05,
                vec![],
                0,
            )
            .expect("8 honest >= quorum 7");
    }

    assert!(
        cluster.verify_consistency(),
        "honest majority must remain consistent under Byzantine signing"
    );

    // Honest nodes have all 15 entries; Byzantine logs are rejected/empty.
    for node in &cluster.nodes[..8] {
        assert_eq!(node.log.len(), 15);
        assert!(node.log.verify_chain());
    }
    for node in &cluster.nodes[8..] {
        assert_eq!(node.log.len(), 0, "Byzantine node must not contaminate quorum");
    }
}

#[test]
fn byzantine_quorum_loss_triggers_rejection() {
    let (sk, _vk) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = BftAuditCluster::new_with_signing_key(11, sk);

    // 5 Byzantine -> only 6 honest < quorum 7 -> proposals must fail.
    for i in 6..11 {
        cluster.set_byzantine(i);
    }
    let result = cluster.propose_entry(
        AuditEventType::SystemDegraded,
        vec![],
        vec![],
        1.0,
        vec![],
        0,
    );
    assert!(result.is_err(), "loss of quorum must reject");
    assert!(result.unwrap_err().to_lowercase().contains("quorum"));
}
