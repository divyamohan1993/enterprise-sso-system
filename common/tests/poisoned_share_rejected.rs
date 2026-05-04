//! Regression test for **X-C** — `reconstruct_2of3` had no commitment
//! verification.
//!
//! Defect cited at:
//!   - `common/src/sealed_keys.rs:1583` (legacy `reconstruct_2of3`)
//!
//! Original bug: the function Lagrange-interpolated whatever shares the
//! PKCS#11 slots / UDS helpers returned and handed the result to the
//! caller as the master KEK. A single corrupted slot silently poisoned
//! the resulting KEK; the caller had no way to bind the reconstruction
//! to a known-good commitment.
//!
//! Fix under test: the new signature
//! `reconstruct_2of3(parts: &[KekShare; 2], expected: Option<&KekVerifyHash>)
//!   -> Result<Zeroizing<[u8;32]>, MilnetError>`
//! verifies `BLAKE3(reconstructed) == *expected` via constant-time
//! comparison when `expected.is_some()`. On mismatch the function
//! returns `Err(MilnetError::CorruptedKekShare)` and the intermediate
//! buffer is zeroized via `Zeroizing` Drop.

use common::error::MilnetError;
use common::sealed_keys::{compute_kek_verify_blake3, reconstruct_2of3};
use common::threshold_kek::{reconstruct_secret, split_secret};

#[test]
fn good_shares_with_matching_commitment_succeed() {
    // Generate 2-of-3 shares of a known KEK.
    let original_kek: [u8; 32] = [0x37; 32];
    let shares = split_secret(&original_kek, 2, 3).expect("split");
    assert_eq!(shares.len(), 3);

    // Take any two shares — Lagrange interpolation reconstructs identically.
    let parts = [shares[0].clone(), shares[1].clone()];

    // Sanity: the underlying Shamir reconstruction matches.
    let reconstructed_raw = reconstruct_secret(&parts[..]).expect("reconstruct");
    assert_eq!(&reconstructed_raw[..], &original_kek[..]);

    // Pass the matching commitment — must succeed.
    let expected = compute_kek_verify_blake3(&original_kek);
    let kek = reconstruct_2of3(&parts, Some(&expected)).expect("commitment match");
    assert_eq!(&kek[..], &original_kek[..]);
}

#[test]
fn poisoned_share_with_commitment_is_rejected() {
    // Generate 2-of-3 shares of a known KEK.
    let original_kek: [u8; 32] = [0x37; 32];
    let shares = split_secret(&original_kek, 2, 3).expect("split");

    // Mutate one share's value (simulate slot corruption / hostile slot).
    let mut bad = shares[0].clone();
    bad.value[0] ^= 0xFF;

    let parts = [bad, shares[1].clone()];
    let expected = compute_kek_verify_blake3(&original_kek);

    let result = reconstruct_2of3(&parts, Some(&expected));
    match result {
        Err(MilnetError::CorruptedKekShare) => {
            // Pass: a corrupted slot is no longer accepted silently.
        }
        Err(other) => panic!(
            "expected CorruptedKekShare on poisoned reconstruction, got {other:?}"
        ),
        Ok(_) => panic!(
            "X-C regression: poisoned reconstruction was accepted without \
             commitment verification — the very defect this patch fixes"
        ),
    }
}

#[test]
fn legacy_callers_passing_none_still_compile_and_work() {
    // Phase 0 callers (sealed_keys.rs around 1705/1872) pass `None` until
    // Phase 8 wires the VSS commitment env. This must continue to work
    // (no commitment check, no rejection of valid reconstructions).
    let original_kek: [u8; 32] = [0x99; 32];
    let shares = split_secret(&original_kek, 2, 3).expect("split");
    let parts = [shares[0].clone(), shares[1].clone()];

    let kek = reconstruct_2of3(&parts, None).expect("None must succeed");
    assert_eq!(&kek[..], &original_kek[..]);
}

#[test]
fn poisoned_share_without_commitment_silently_returns_wrong_kek() {
    // Documenting the residual Phase 0 behaviour: with `None`, a
    // poisoned share still produces *some* output (mathematically
    // determined by Lagrange interpolation on the corrupted polynomial)
    // — Phase 8 is required to actually catch this. This test exists to
    // make the regression visible if a future change accidentally turns
    // the Phase 0 None path into a check-by-default and breaks legacy
    // callers that have not yet been wired with commitments.
    let original_kek: [u8; 32] = [0xC4; 32];
    let shares = split_secret(&original_kek, 2, 3).expect("split");
    let mut bad = shares[0].clone();
    bad.value[0] ^= 0xFF;
    let parts = [bad, shares[1].clone()];

    let kek = reconstruct_2of3(&parts, None)
        .expect("None must succeed even on corruption (Phase 0 behaviour)");
    assert_ne!(
        &kek[..],
        &original_kek[..],
        "corrupted share must yield a different KEK (Phase 0 detects nothing without commitment)"
    );
}

#[test]
fn commitment_constant_time_compare_invariant() {
    // Two distinct KEKs must yield distinct BLAKE3 commitments —
    // otherwise the commitment-verification check is meaningless.
    let a: [u8; 32] = [0x11; 32];
    let b: [u8; 32] = [0x22; 32];
    let ha = compute_kek_verify_blake3(&a);
    let hb = compute_kek_verify_blake3(&b);
    assert_ne!(ha, hb, "BLAKE3 must distinguish distinct KEKs");
}
