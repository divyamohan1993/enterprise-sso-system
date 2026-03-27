//! Ceremony state machine hardening tests.
//!
//! Validates timeout enforcement, invalid state transitions, concurrent
//! ceremony limits, cleanup on timeout, and receipt chain binding to session ID.

use orchestrator::ceremony::{CeremonySession, CeremonyState, CEREMONY_TIMEOUT_SECS};

// ── Timeout tests ────────────────────────────────────────────────────────

#[test]
fn ceremony_timeout_is_30_seconds() {
    assert_eq!(CEREMONY_TIMEOUT_SECS, 30, "ceremony timeout must be 30 seconds");
}

#[test]
fn ceremony_fresh_session_not_expired() {
    let session = CeremonySession::new([0x01; 32]);
    assert!(!session.is_expired(), "freshly created session must not be expired");
}

#[test]
fn ceremony_expired_after_timeout() {
    let mut session = CeremonySession::new([0x01; 32]);
    // Manually backdate the created_at timestamp
    session.created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - CEREMONY_TIMEOUT_SECS
        - 1;

    assert!(session.is_expired(), "session must be expired after timeout");
}

#[test]
fn ceremony_not_expired_just_before_timeout() {
    let mut session = CeremonySession::new([0x01; 32]);
    // Set created_at to exactly CEREMONY_TIMEOUT_SECS ago (not exceeded)
    session.created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - CEREMONY_TIMEOUT_SECS;

    assert!(
        !session.is_expired(),
        "session at exactly the timeout boundary should not be expired (needs to exceed, not equal)"
    );
}

// ── Invalid state transition tests ───────────────────────────────────────

#[test]
fn invalid_transition_pending_tss_to_pending_opaque() {
    // PendingTss -> PendingOpaque (via opaque_complete) should fail
    let mut session = CeremonySession::new([0x01; 32]);
    session.opaque_complete().unwrap(); // PendingOpaque -> PendingTss
    assert_eq!(session.state, CeremonyState::PendingTss);

    let result = session.opaque_complete();
    assert!(result.is_err(), "PendingTss -> PendingTss via opaque_complete must fail");
    // State must remain PendingTss
    assert_eq!(session.state, CeremonyState::PendingTss);
}

#[test]
fn invalid_transition_pending_opaque_to_complete() {
    // PendingOpaque -> Complete (via tss_complete) should fail
    let mut session = CeremonySession::new([0x01; 32]);
    let result = session.tss_complete();
    assert!(result.is_err(), "PendingOpaque -> Complete must fail");
    assert_eq!(session.state, CeremonyState::PendingOpaque);
}

#[test]
fn invalid_transition_complete_to_anything() {
    let mut session = CeremonySession::new([0x01; 32]);
    session.opaque_complete().unwrap();
    session.tss_complete().unwrap();
    assert_eq!(session.state, CeremonyState::Complete);

    assert!(session.opaque_complete().is_err(), "Complete -> PendingTss must fail");
    assert!(session.tss_complete().is_err(), "Complete -> Complete must fail");
    assert!(session.fail("reason".into()).is_err(), "Complete -> Failed must fail");

    // State must remain Complete
    assert_eq!(session.state, CeremonyState::Complete);
}

#[test]
fn invalid_transition_failed_to_anything() {
    let mut session = CeremonySession::new([0x01; 32]);
    session.fail("initial failure".into()).unwrap();

    assert!(session.opaque_complete().is_err(), "Failed -> PendingTss must fail");
    assert!(session.tss_complete().is_err(), "Failed -> Complete must fail");
    assert!(session.fail("double fail".into()).is_err(), "Failed -> Failed must fail");
}

#[test]
fn valid_full_state_machine_progression() {
    let mut session = CeremonySession::new([0xAA; 32]);

    // PendingOpaque -> PendingTss -> Complete
    assert_eq!(session.state, CeremonyState::PendingOpaque);
    session.opaque_complete().unwrap();
    assert_eq!(session.state, CeremonyState::PendingTss);
    session.tss_complete().unwrap();
    assert_eq!(session.state, CeremonyState::Complete);
}

// ── Concurrent ceremony limit per user ───────────────────────────────────
// The CeremonySession is per-session; concurrent ceremonies are tracked by
// the orchestrator service. Here we verify that multiple sessions can coexist
// with different session IDs and each maintains independent state.

#[test]
fn concurrent_sessions_independent_state() {
    let mut session_a = CeremonySession::new([0x01; 32]);
    let mut session_b = CeremonySession::new([0x02; 32]);

    // Advance session A to PendingTss
    session_a.opaque_complete().unwrap();
    // Session B should still be PendingOpaque
    assert_eq!(session_b.state, CeremonyState::PendingOpaque);

    // Advance session B to Complete
    session_b.opaque_complete().unwrap();
    session_b.tss_complete().unwrap();
    // Session A should still be PendingTss
    assert_eq!(session_a.state, CeremonyState::PendingTss);
}

// ── Ceremony cleanup on timeout ──────────────────────────────────────────
// Verify that expired sessions in any state are detectable for cleanup.

#[test]
fn expired_session_in_pending_opaque_detected() {
    let mut session = CeremonySession::new([0x01; 32]);
    session.created_at -= CEREMONY_TIMEOUT_SECS + 1;
    assert!(session.is_expired());
    assert_eq!(session.state, CeremonyState::PendingOpaque);
}

#[test]
fn expired_session_in_pending_tss_detected() {
    let mut session = CeremonySession::new([0x01; 32]);
    session.opaque_complete().unwrap();
    session.created_at -= CEREMONY_TIMEOUT_SECS + 1;
    assert!(session.is_expired());
    assert_eq!(session.state, CeremonyState::PendingTss);
}

// ── Receipt chain binding to session ID ──────────────────────────────────

#[test]
fn receipt_chain_bound_to_session_id() {
    let session_id = [0xBE; 32];
    let session = CeremonySession::new(session_id);

    // The internal receipt chain should be initialized with the same session ID
    // We verify this by attempting to add a receipt with a mismatched session
    use common::types::Receipt;
    use uuid::Uuid;

    let wrong_session_receipt = Receipt {
        ceremony_session_id: [0xFF; 32], // wrong session ID
        step_id: 1,
        prev_receipt_hash: [0u8; 64],
        user_id: Uuid::nil(),
        dpop_key_hash: [0xBB; 64],
        timestamp: 1_700_000_000_000_000,
        nonce: [0x10; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };

    // The receipt chain should reject a receipt with mismatched session ID
    let mut chain = session.receipt_chain;
    let result = chain.add_receipt(wrong_session_receipt);
    assert!(result.is_err(), "receipt with wrong session ID must be rejected");
    let err = result.unwrap_err();
    assert!(
        err.contains("session_id mismatch"),
        "error should mention session_id mismatch, got: {err}"
    );
}

#[test]
fn receipt_chain_accepts_matching_session_id() {
    let session_id = [0xBE; 32];
    let session = CeremonySession::new(session_id);

    use common::types::Receipt;
    use uuid::Uuid;

    let correct_receipt = Receipt {
        ceremony_session_id: session_id,
        step_id: 1,
        prev_receipt_hash: [0u8; 64],
        user_id: Uuid::nil(),
        dpop_key_hash: [0xBB; 64],
        timestamp: 1_700_000_000_000_000,
        nonce: [0x10; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };

    let mut chain = session.receipt_chain;
    let result = chain.add_receipt(correct_receipt);
    assert!(result.is_ok(), "receipt with matching session ID must be accepted");
}
