#![forbid(unsafe_code)]
//! milnet-tss: Threshold Signer (FROST 3-of-5).
//!
//! At startup, runs DKG to establish the threshold group, then spawns a
//! service listener for signing requests.

use milnet_crypto::threshold::dkg;

fn main() {
    // Run DKG at startup (3-of-5 threshold)
    let dkg_result = dkg(5, 3);
    tracing::info!(
        threshold = dkg_result.group.threshold,
        total = dkg_result.group.total,
        "DKG ceremony complete, TSS ready"
    );

    // TODO: spawn service listener (Phase 3 networking)
    println!(
        "milnet-tss: DKG complete, group has {}/{} threshold",
        dkg_result.group.threshold, dkg_result.group.total
    );
}
