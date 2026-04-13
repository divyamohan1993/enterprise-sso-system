//! I13 [MED] Epoch wraparound near u64::MAX.
//!
//! Sets epoch to a large value via `from_persisted` and asserts the chain
//! refuses to advance past overflow rather than silently wrapping.

use ratchet::chain::{RatchetChain, RatchetError};

fn key64() -> [u8; 64] {
    let mut k = [0u8; 64];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(1);
    }
    k
}

fn good_entropy() -> [u8; 32] {
    let mut e = [0u8; 32];
    getrandom::getrandom(&mut e).unwrap();
    e
}

fn fresh_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).unwrap();
    n
}

#[test]
fn epoch_near_u64_max_refuses_wrap() {
    // Start one short of u64::MAX so the next advance lands on MAX, then
    // the following advance must refuse to wrap.
    let near_max = u64::MAX - 1;
    let mut chain = RatchetChain::from_persisted(key64(), near_max)
        .expect("chain restorable at high epoch");

    // 1st advance: MAX-1 -> MAX (allowed)
    chain
        .advance(&good_entropy(), &good_entropy(), &fresh_nonce())
        .expect("advance from MAX-1 to MAX must succeed");
    assert_eq!(chain.epoch(), u64::MAX);

    // 2nd advance: at MAX -> MUST refuse.
    let r = chain.advance(&good_entropy(), &good_entropy(), &fresh_nonce());
    assert!(
        r.is_err(),
        "advance past u64::MAX must return EpochOverflow, not silently wrap"
    );
    if let Err(RatchetError::EpochOverflow) = r {
        // expected
    } else if let Err(other) = r {
        panic!("expected EpochOverflow, got {other:?}");
    }
}

#[test]
fn epoch_does_not_silently_wrap_after_failure() {
    let mut chain = RatchetChain::from_persisted(key64(), u64::MAX).unwrap();
    // Any further advance is forbidden.
    let r = chain.advance(&good_entropy(), &good_entropy(), &fresh_nonce());
    assert!(r.is_err(), "u64::MAX epoch is terminal");
    // Epoch must NOT wrap to 0.
    assert_ne!(chain.epoch(), 0, "epoch must not wrap to 0");
}
