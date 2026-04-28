//! Regression test for Codex review P2 (PR #27): a future-dated
//! `MfaAssertedClaim` MUST be rejected. The original implementation only
//! checked `now - asserted_at <= TTL`, which evaluates to `true` whenever
//! `asserted_at` is in the future (because the difference is negative and
//! always `<= TTL`). A claim minted with a wall-clock-skewed or tampered
//! `asserted_at` could therefore remain valid until that future time
//! arrived, defeating the 60-second freshness window.
//!
//! These tests exercise the corrected lower-bound check via the public
//! API by synthesising a claim with `compute_binding_tag` — a public,
//! `#[doc(hidden)]` helper that the lib exposes specifically so
//! adversarial-shape claims can be constructed in regression tests
//! without granting test-only inserts that could regress in production.

use stepup_mfa::{
    compute_binding_tag, now_secs, verify_mfa_asserted_claim, MfaAssertedClaim, Sensitivity,
    MFA_ASSERTED_FORWARD_SKEW_SECS,
};

fn sid(seed: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = seed;
    id
}

#[test]
fn future_dated_claim_far_in_future_rejected() {
    let s = sid(0xA1);
    let future = now_secs() + 3_600; // 1h ahead
    let tag = compute_binding_tag(&s, future, Sensitivity::Critical);
    let claim = MfaAssertedClaim {
        session_id: s,
        asserted_at: future,
        for_sensitivity: Sensitivity::Critical,
        binding_tag: tag,
    };
    assert!(
        !verify_mfa_asserted_claim(&claim, &s, Sensitivity::Critical),
        "future-dated claim must NOT verify"
    );
}

#[test]
fn future_dated_claim_just_beyond_skew_rejected() {
    let s = sid(0xA2);
    // Just over the tolerated forward skew — still must reject.
    let future = now_secs() + MFA_ASSERTED_FORWARD_SKEW_SECS + 1;
    let tag = compute_binding_tag(&s, future, Sensitivity::Critical);
    let claim = MfaAssertedClaim {
        session_id: s,
        asserted_at: future,
        for_sensitivity: Sensitivity::Critical,
        binding_tag: tag,
    };
    assert!(
        !verify_mfa_asserted_claim(&claim, &s, Sensitivity::Critical),
        "claim asserted beyond forward-skew tolerance must NOT verify"
    );
}

#[test]
fn small_forward_skew_within_tolerance_still_verifies() {
    let s = sid(0xA3);
    // Within tolerance — must still verify so legitimate clock drift
    // between asserter and verifier does not falsely reject users.
    let future = now_secs() + (MFA_ASSERTED_FORWARD_SKEW_SECS - 1).max(0);
    let tag = compute_binding_tag(&s, future, Sensitivity::Critical);
    let claim = MfaAssertedClaim {
        session_id: s,
        asserted_at: future,
        for_sensitivity: Sensitivity::Critical,
        binding_tag: tag,
    };
    assert!(
        verify_mfa_asserted_claim(&claim, &s, Sensitivity::Critical),
        "claim within forward-skew tolerance must verify"
    );
}
