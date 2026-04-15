mod test_bootstrap;
#[allow(unused_imports)]
use test_bootstrap as _;

use proptest::prelude::*;
use audit::bft::BftAuditCluster;
use audit::log::hash_entry;
use common::types::AuditEventType;
use uuid::Uuid;

fn propose_default(cluster: &mut BftAuditCluster) -> Result<[u8; 64], String> {
    cluster.propose_entry(
        AuditEventType::AuthSuccess,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.1,
        Vec::new(),
        0,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))] // I20

    /// Honest quorum always reaches agreement.
    #[test]
    fn honest_quorum_always_agrees(
        num_entries in 1usize..20,
    ) {
        let n = 11;
        let mut cluster = BftAuditCluster::new(n);

        for i in 0..num_entries {
            let result = propose_default(&mut cluster);
            prop_assert!(result.is_ok(), "entry {} should commit with all honest nodes", i);
        }

        prop_assert!(cluster.verify_consistency(), "all honest nodes must have identical chains");

        for node in &cluster.nodes {
            prop_assert_eq!(node.log.len(), num_entries, "each node must have {} entries", num_entries);
            prop_assert!(node.log.verify_chain(), "chain integrity must hold");
        }
    }

    /// Minority Byzantine nodes cannot corrupt the chain.
    #[test]
    fn minority_byzantine_cannot_corrupt(
        num_byzantine in 1usize..4,
        num_entries in 1usize..15,
    ) {
        let n = 11;
        let mut cluster = BftAuditCluster::new(n);

        // Mark up to 3 nodes as Byzantine (within f=3 tolerance)
        for i in 0..num_byzantine {
            cluster.set_byzantine((n - 1 - i) as u8);
        }

        for i in 0..num_entries {
            let result = propose_default(&mut cluster);
            prop_assert!(
                result.is_ok(),
                "entry {} should commit with {} Byzantine nodes (f=3)",
                i, num_byzantine
            );
        }

        prop_assert!(cluster.verify_consistency(), "honest nodes must agree");

        // Byzantine nodes should have empty logs
        for i in 0..num_byzantine {
            prop_assert_eq!(
                cluster.nodes[n - 1 - i].log.len(), 0,
                "Byzantine node must have empty log"
            );
        }

        // Honest nodes should have all entries
        let honest_count = n - num_byzantine;
        for i in 0..honest_count {
            prop_assert_eq!(
                cluster.nodes[i].log.len(), num_entries,
                "honest node {} must have {} entries", i, num_entries
            );
        }
    }

    /// All honest nodes have identical chain state after consensus.
    #[test]
    fn honest_nodes_identical_state(
        num_entries in 5usize..25,
        num_byzantine in 0usize..3,
    ) {
        let n = 11;
        let mut cluster = BftAuditCluster::new(n);

        for i in 0..num_byzantine {
            cluster.set_byzantine((n - 1 - i) as u8);
        }

        for _ in 0..num_entries {
            let result = propose_default(&mut cluster);
            prop_assert!(result.is_ok());
        }

        prop_assert!(cluster.verify_consistency());

        // All honest nodes must have identical last entry hash
        let honest_count = n - num_byzantine;
        if honest_count > 1 && num_entries > 0 {
            let ref_hash = hash_entry(&cluster.nodes[0].log.entries()[num_entries - 1]);
            for i in 1..honest_count {
                let h = hash_entry(&cluster.nodes[i].log.entries()[num_entries - 1]);
                prop_assert_eq!(h, ref_hash, "honest node {} diverged from node 0", i);
            }
        }
    }
}
