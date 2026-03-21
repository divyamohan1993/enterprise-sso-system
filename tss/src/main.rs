#![forbid(unsafe_code)]
//! tss: Threshold Signer (FROST 3-of-5).
//!
//! At startup, runs DKG to establish the threshold group, then distributes
//! shares across separate signer nodes. The coordinator holds NO signing
//! keys -- it only aggregates partial signatures.

use crypto::threshold::dkg;
use tss::distributed::distribute_shares;

fn main() {
    // Run DKG at startup (3-of-5 threshold)
    let mut dkg_result = dkg(5, 3);
    tracing::info!(
        threshold = dkg_result.group.threshold,
        total = dkg_result.group.total,
        "DKG ceremony complete"
    );

    // Distribute shares: each SignerNode gets exactly ONE key share.
    // The coordinator holds NO signing keys.
    let (coordinator, nodes) = distribute_shares(&mut dkg_result);

    println!(
        "tss: distributed — coordinator (no keys) + {} signer nodes (1 share each)",
        nodes.len()
    );
    println!(
        "tss: threshold = {}, total = {}",
        coordinator.threshold,
        nodes.len()
    );

    // In production, each `node` would be sent to a separate process:
    //   Node 1 → process/container 1  (holds share 1)
    //   Node 2 → process/container 2  (holds share 2)
    //   Node 3 → process/container 3  (holds share 3)
    //   Node 4 → process/container 4  (holds share 4)
    //   Node 5 → process/container 5  (holds share 5)
    //
    // The coordinator runs here and communicates via SHARD IPC.
    for (i, node) in nodes.iter().enumerate() {
        println!(
            "  signer node {}: identifier = {:?}",
            i + 1,
            node.identifier()
        );
    }

    // TODO: spawn SHARD IPC listeners for each signer node (Phase 3 networking)
    println!("tss: ready for distributed signing requests");
}
