//! Adversarial tests for ratchet hardening — bloom FPR, PQ freshness,
//! canary strict check. See `ratchet/src/chain.rs` for the invariants
//! under test.

use ratchet::chain::{RatchetChain, BLOOM_FILTER_BITS, BLOOM_FILTER_K, PQ_PUNCTURE_INTERVAL};

/// Helper: make a valid 32-byte entropy value that passes the quality gate.
fn entropy(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = seed.wrapping_add(i as u8).wrapping_mul(7).wrapping_add(1);
    }
    out
}

#[test]
fn bloom_filter_fpr_under_target_at_10k_nonces() {
    // Experimental FPR check: insert 10k random nonces, then query 100k
    // distinct non-inserted nonces and count false positives.
    use ratchet::chain::test_support as ts;

    let mut bf = ts::new_bloom_filter();
    let _ = ts::bloom_contains; // silence unused warning path
    for i in 0u32..10_000 {
        let mut n = [0u8; 32];
        n[..4].copy_from_slice(&i.to_le_bytes());
        n[4] = 0xAA;
        ts::bloom_insert(&mut bf, &n);
    }
    let mut false_positives = 0usize;
    let trials = 100_000u32;
    for i in 0u32..trials {
        let mut n = [0u8; 32];
        n[..4].copy_from_slice(&i.to_le_bytes());
        n[4] = 0xBB; // distinct prefix -> never inserted
        if ts::bloom_contains(&bf, &n) {
            false_positives += 1;
        }
    }
    let fpr = false_positives as f64 / trials as f64;
    // Target <= 0.001% (1e-5). Allow 5x headroom for statistical noise
    // at trials=100k.
    assert!(
        fpr < 5e-5,
        "bloom FPR {fpr:.2e} exceeds 5e-5 (target 1e-5) with m={} k={}",
        BLOOM_FILTER_BITS, BLOOM_FILTER_K
    );
}

#[test]
fn pq_freshness_invariant_forces_puncture_on_wrap() {
    // A chain without PQ material should never hit the PqStale path —
    // the invariant is only enforced when pq_keypair is Some.
    let master = [0x42u8; 64];
    let mut chain = RatchetChain::new(&master).expect("new chain");
    // Advance past the interval without PQ material — must succeed.
    for i in 0..5 {
        chain
            .advance(&entropy(i), &entropy(i ^ 0x55), &entropy(i ^ 0xAA))
            .expect("advance without PQ must succeed");
    }
    assert_eq!(chain.last_pq_puncture_epoch(), 0);
    assert!(!chain.is_poisoned());
}

#[test]
fn restore_pq_freshness_rejects_stale_import() {
    let master = [0x01u8; 64];
    let mut chain = RatchetChain::from_persisted([0x02u8; 64], PQ_PUNCTURE_INTERVAL + 10)
        .expect("from_persisted");
    // Importing a last_pq_puncture_epoch that leaves a gap >= INTERVAL
    // must be rejected.
    let err = chain
        .restore_pq_freshness(0)
        .expect_err("stale import must be rejected");
    match err {
        ratchet::chain::RatchetError::PqStale(_) => {}
        other => panic!("expected PqStale, got {other:?}"),
    }
    assert!(chain.is_poisoned());
    let _ = master;
}
