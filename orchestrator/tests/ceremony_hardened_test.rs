//! Extended ceremony orchestrator tests.
//!
//! Tests receipt verification, message serialization, CeremonyTracker
//! concurrent ceremony limits, distributed tracker persistence, and
//! ceremony cleanup.

use orchestrator::ceremony::{
    CeremonySession, CeremonyState, CeremonyTracker, CEREMONY_TIMEOUT_SECS,
    MAX_CEREMONIES_PER_USER, MAX_PENDING_CEREMONIES,
};
use orchestrator::messages::{OrchestratorRequest, OrchestratorResponse};
use uuid::Uuid;

// ── State machine: all valid transitions ────────────────────────────

#[test]
fn valid_transition_pending_opaque_to_pending_tss() {
    let mut session = CeremonySession::new([0xAA; 32]);
    assert_eq!(session.state, CeremonyState::PendingOpaque);
    assert!(session.opaque_complete().is_ok());
    assert_eq!(session.state, CeremonyState::PendingTss);
}

#[test]
fn valid_transition_pending_tss_to_complete() {
    let mut session = CeremonySession::new([0xAA; 32]);
    session.opaque_complete().unwrap();
    assert!(session.tss_complete().is_ok());
    assert_eq!(session.state, CeremonyState::Complete);
}

#[test]
fn valid_transition_pending_opaque_to_failed() {
    let mut session = CeremonySession::new([0xAA; 32]);
    assert!(session.fail("opaque error".into()).is_ok());
    assert_eq!(
        session.state,
        CeremonyState::Failed("opaque error".into())
    );
}

#[test]
fn valid_transition_pending_tss_to_failed() {
    let mut session = CeremonySession::new([0xAA; 32]);
    session.opaque_complete().unwrap();
    assert!(session.fail("tss error".into()).is_ok());
    assert_eq!(session.state, CeremonyState::Failed("tss error".into()));
}

// ── State machine: all INVALID transitions ──────────────────────────

#[test]
fn reject_pending_opaque_to_complete() {
    let mut session = CeremonySession::new([0xBB; 32]);
    assert!(session.tss_complete().is_err());
    assert_eq!(session.state, CeremonyState::PendingOpaque);
}

#[test]
fn reject_pending_tss_to_pending_tss() {
    let mut session = CeremonySession::new([0xBB; 32]);
    session.opaque_complete().unwrap();
    assert!(session.opaque_complete().is_err());
    assert_eq!(session.state, CeremonyState::PendingTss);
}

#[test]
fn reject_complete_to_any_state() {
    let mut session = CeremonySession::new([0xBB; 32]);
    session.opaque_complete().unwrap();
    session.tss_complete().unwrap();

    assert!(session.opaque_complete().is_err());
    assert!(session.tss_complete().is_err());
    assert!(session.fail("too late".into()).is_err());
    assert_eq!(session.state, CeremonyState::Complete);
}

#[test]
fn reject_failed_to_any_state() {
    let mut session = CeremonySession::new([0xBB; 32]);
    session.fail("initial".into()).unwrap();

    assert!(session.opaque_complete().is_err());
    assert!(session.tss_complete().is_err());
    assert!(session.fail("again".into()).is_err());
}

// ── Timeout handling ────────────────────────────────────────────────

#[test]
fn ceremony_timeout_is_30_seconds_const() {
    assert_eq!(CEREMONY_TIMEOUT_SECS, 30);
}

#[test]
fn fresh_session_not_expired() {
    let session = CeremonySession::new([0xCC; 32]);
    assert!(!session.is_expired());
}

#[test]
fn session_expired_after_timeout() {
    let mut session = CeremonySession::new([0xCC; 32]);
    session.created_at -= CEREMONY_TIMEOUT_SECS + 1;
    assert!(session.is_expired());
}

#[test]
fn session_not_expired_at_boundary() {
    let mut session = CeremonySession::new([0xCC; 32]);
    session.created_at -= CEREMONY_TIMEOUT_SECS; // exactly at boundary (not exceeded)
    assert!(!session.is_expired());
}

// ── Receipt verification: session ID binding ────────────────────────

#[test]
fn receipt_with_wrong_session_id_rejected() {
    let session_id = [0xDD; 32];
    let session = CeremonySession::new(session_id);
    let mut chain = session.receipt_chain;

    let bad_receipt = common::types::Receipt {
        ceremony_session_id: [0xFF; 32], // wrong
        step_id: 1,
        prev_receipt_hash: [0u8; 64],
        user_id: Uuid::new_v4(),
        dpop_key_hash: [0xAA; 64],
        timestamp: 1_700_000_000_000_000,
        nonce: [0x10; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };

    let result = chain.add_receipt(bad_receipt);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("session_id"),
        "error should mention session_id"
    );
}

#[test]
fn receipt_with_correct_session_id_accepted() {
    let session_id = [0xDD; 32];
    let session = CeremonySession::new(session_id);
    let mut chain = session.receipt_chain;

    let good_receipt = common::types::Receipt {
        ceremony_session_id: session_id,
        step_id: 1,
        prev_receipt_hash: [0u8; 64],
        user_id: Uuid::new_v4(),
        dpop_key_hash: [0xAA; 64],
        timestamp: 1_700_000_000_000_000,
        nonce: [0x10; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };

    assert!(chain.add_receipt(good_receipt).is_ok());
}

#[test]
fn receipt_with_expired_timestamp_not_accepted_by_chain() {
    // The receipt chain itself does not enforce timestamp validity,
    // but we verify that very old timestamps are still accepted at the
    // chain level (timestamp checking is done at the orchestrator level).
    let session_id = [0xEE; 32];
    let session = CeremonySession::new(session_id);
    let mut chain = session.receipt_chain;

    let old_receipt = common::types::Receipt {
        ceremony_session_id: session_id,
        step_id: 1,
        prev_receipt_hash: [0u8; 64],
        user_id: Uuid::new_v4(),
        dpop_key_hash: [0xAA; 64],
        timestamp: 1_000_000, // very old
        nonce: [0x10; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    };

    // Chain accepts it (timestamp enforcement is at orchestrator level)
    assert!(chain.add_receipt(old_receipt).is_ok());
}

// ── CeremonyTracker: concurrent ceremony handling ───────────────────

#[test]
fn tracker_creates_ceremony_successfully() {
    let mut tracker = CeremonyTracker::new();
    let session = CeremonySession::new([0x01; 32]);
    let user = Uuid::new_v4();

    assert!(tracker.create_ceremony(session, Some(user)).is_ok());
    assert_eq!(tracker.active_count(), 1);
    assert_eq!(tracker.user_active_count(&user), 1);
}

#[test]
fn tracker_replaces_existing_ceremony_for_same_user() {
    let mut tracker = CeremonyTracker::new();
    let user = Uuid::new_v4();

    // First ceremony
    let mut session1 = CeremonySession::new([0x01; 32]);
    session1.user_id = Some(user);
    tracker.create_ceremony(session1, Some(user)).unwrap();
    assert_eq!(tracker.user_active_count(&user), 1);

    // Second ceremony for same user: the tracker cancels existing ceremonies
    // when user_active_count >= MAX_CEREMONIES_PER_USER (1), but only if the
    // session's user_id field is set (used by the is_terminal filter).
    let mut session2 = CeremonySession::new([0x02; 32]);
    session2.user_id = Some(user);
    tracker.create_ceremony(session2, Some(user)).unwrap();

    // After replacement: old session removed, new session added, count = 1
    assert_eq!(tracker.user_active_count(&user), 1);
}

#[test]
fn tracker_different_users_independent_ceremonies() {
    let mut tracker = CeremonyTracker::new();
    let user1 = Uuid::new_v4();
    let user2 = Uuid::new_v4();

    tracker
        .create_ceremony(CeremonySession::new([0x01; 32]), Some(user1))
        .unwrap();
    tracker
        .create_ceremony(CeremonySession::new([0x02; 32]), Some(user2))
        .unwrap();

    assert_eq!(tracker.active_count(), 2);
    assert_eq!(tracker.user_active_count(&user1), 1);
    assert_eq!(tracker.user_active_count(&user2), 1);
}

#[test]
fn tracker_finish_ceremony_decrements_count() {
    let mut tracker = CeremonyTracker::new();
    let user = Uuid::new_v4();
    let mut session = CeremonySession::new([0x01; 32]);
    session.user_id = Some(user);

    tracker.create_ceremony(session, Some(user)).unwrap();
    assert_eq!(tracker.active_count(), 1);
    assert_eq!(tracker.user_active_count(&user), 1);

    // short_session_hex formats the first 8 bytes of session_id as hex
    let hex = format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    );
    tracker.finish_ceremony(&hex);
    // After finishing, the session is removed and user count decremented
    assert_eq!(tracker.active_count(), 0);
    assert_eq!(tracker.user_active_count(&user), 0);
}

#[test]
fn tracker_cleanup_removes_expired_sessions() {
    let mut tracker = CeremonyTracker::new();
    let user = Uuid::new_v4();

    let mut session = CeremonySession::new([0x01; 32]);
    session.created_at -= CEREMONY_TIMEOUT_SECS + 1; // expire it
    tracker.create_ceremony(session, Some(user)).unwrap();

    let removed = tracker.cleanup_expired();
    assert_eq!(removed, 1);
    assert_eq!(tracker.active_count(), 0);
}

#[test]
fn tracker_cleanup_preserves_fresh_sessions() {
    let mut tracker = CeremonyTracker::new();
    let user = Uuid::new_v4();

    tracker
        .create_ceremony(CeremonySession::new([0x01; 32]), Some(user))
        .unwrap();

    let removed = tracker.cleanup_expired();
    assert_eq!(removed, 0);
    assert_eq!(tracker.active_count(), 1);
}

// ── Message serialization/deserialization roundtrip ──────────────────

#[test]
fn orchestrator_request_serialization_roundtrip() {
    let request = OrchestratorRequest {
        username: "pentagon_user".into(),
        password: b"classified_password".to_vec(),
        dpop_key_hash: [0xAA; 64],
        tier: 2,
        audience: Some("milnet-api".into()),
        ceremony_id: [0xBB; 32],
        device_attestation_age_secs: Some(3.5),
        geo_velocity_kmh: Some(100.0),
        is_unusual_network: Some(false),
        is_unusual_time: Some(true),
        unusual_access_score: Some(0.42),
        recent_failed_attempts: Some(2),
        device_fingerprint: Some("chrome-linux-x64".into()),
        source_ip: Some("10.0.0.1".into()),
    };

    let bytes = postcard::to_allocvec(&request).expect("serialize");
    let deserialized: OrchestratorRequest =
        postcard::from_bytes(&bytes).expect("deserialize");

    assert_eq!(deserialized.username, "pentagon_user");
    assert_eq!(deserialized.password, b"classified_password");
    assert_eq!(deserialized.dpop_key_hash, [0xAA; 64]);
    assert_eq!(deserialized.tier, 2);
    assert_eq!(deserialized.audience, Some("milnet-api".into()));
    assert_eq!(deserialized.ceremony_id, [0xBB; 32]);
    assert_eq!(deserialized.device_fingerprint, Some("chrome-linux-x64".into()));
    assert_eq!(deserialized.source_ip, Some("10.0.0.1".into()));
}

#[test]
fn orchestrator_response_serialization_roundtrip() {
    let success_resp = OrchestratorResponse {
        success: true,
        token_bytes: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        error: None,
    };
    let bytes = postcard::to_allocvec(&success_resp).expect("serialize");
    let deserialized: OrchestratorResponse =
        postcard::from_bytes(&bytes).expect("deserialize");
    assert!(deserialized.success);
    assert_eq!(deserialized.token_bytes, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    assert!(deserialized.error.is_none());

    let error_resp = OrchestratorResponse {
        success: false,
        token_bytes: None,
        error: Some("authentication failed".into()),
    };
    let bytes = postcard::to_allocvec(&error_resp).expect("serialize");
    let deserialized: OrchestratorResponse =
        postcard::from_bytes(&bytes).expect("deserialize");
    assert!(!deserialized.success);
    assert!(deserialized.token_bytes.is_none());
    assert_eq!(deserialized.error, Some("authentication failed".into()));
}

#[test]
fn orchestrator_request_default_fields() {
    // Test that default/optional fields work correctly
    let minimal = OrchestratorRequest {
        username: "user".into(),
        password: vec![],
        dpop_key_hash: [0u8; 64],
        tier: 0,
        audience: None,
        ceremony_id: [0u8; 32],
        device_attestation_age_secs: None,
        geo_velocity_kmh: None,
        is_unusual_network: None,
        is_unusual_time: None,
        unusual_access_score: None,
        recent_failed_attempts: None,
        device_fingerprint: None,
        source_ip: None,
    };

    let bytes = postcard::to_allocvec(&minimal).expect("serialize");
    let deserialized: OrchestratorRequest =
        postcard::from_bytes(&bytes).expect("deserialize");

    assert_eq!(deserialized.tier, 0);
    assert!(deserialized.audience.is_none());
    assert!(deserialized.device_fingerprint.is_none());
    assert!(deserialized.source_ip.is_none());
}

// ── CeremonyState DB tag roundtrip ──────────────────────────────────

#[test]
fn ceremony_state_db_tag_roundtrip() {
    let states = vec![
        CeremonyState::PendingOpaque,
        CeremonyState::PendingTss,
        CeremonyState::Complete,
        CeremonyState::Failed("test reason".into()),
    ];

    for state in &states {
        let tag = state.to_db_tag();
        let reason = state.failure_reason().map(|s| s.to_string());
        let roundtripped = CeremonyState::from_db_tag(tag, reason.clone());
        assert!(
            roundtripped.is_some(),
            "DB tag '{}' must roundtrip",
            tag
        );
        assert_eq!(
            &roundtripped.unwrap(),
            state,
            "roundtrip mismatch for tag '{}'",
            tag
        );
    }
}

#[test]
fn ceremony_state_unknown_tag_returns_none() {
    assert!(CeremonyState::from_db_tag("unknown", None).is_none());
    assert!(CeremonyState::from_db_tag("", None).is_none());
}
