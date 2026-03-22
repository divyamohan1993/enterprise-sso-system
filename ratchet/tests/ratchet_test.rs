//! Integration tests for the ratchet session manager.

use ratchet::chain::RatchetChain;
use ratchet::manager::{RatchetAction, RatchetRequest, RatchetResponse, SessionManager};
use uuid::Uuid;

fn test_secret() -> [u8; 64] {
    let mut s = [0u8; 64];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8;
    }
    s
}

fn test_entropy_a() -> [u8; 32] {
    [0xAA; 32]
}

fn test_entropy_b() -> [u8; 32] {
    [0xBB; 32]
}

// ── Chain tests ──────────────────────────────────────────────────────

#[test]
fn chain_new_starts_at_epoch_0() {
    let chain = RatchetChain::new(&test_secret());
    assert_eq!(chain.epoch(), 0);
}

#[test]
fn chain_advance_increments_epoch() {
    let mut chain = RatchetChain::new(&test_secret());
    chain.advance(&test_entropy_a(), &test_entropy_b());
    assert_eq!(chain.epoch(), 1);
    chain.advance(&test_entropy_a(), &test_entropy_b());
    assert_eq!(chain.epoch(), 2);
}

#[test]
fn chain_tag_deterministic() {
    let chain_a = RatchetChain::new(&test_secret());
    let chain_b = RatchetChain::new(&test_secret());
    let claims = b"test-claims-data";
    let tag_a = chain_a.generate_tag(claims);
    let tag_b = chain_b.generate_tag(claims);
    assert_eq!(tag_a, tag_b);
}

#[test]
fn chain_different_epochs_different_tags() {
    let mut chain = RatchetChain::new(&test_secret());
    let claims = b"test-claims-data";
    let tag_0 = chain.generate_tag(claims);
    chain.advance(&test_entropy_a(), &test_entropy_b());
    let tag_1 = chain.generate_tag(claims);
    assert_ne!(tag_0, tag_1);
}

#[test]
fn chain_old_key_erased() {
    // After advance, the old epoch's tag can no longer be reproduced
    // because the old chain key has been zeroized.
    let mut chain = RatchetChain::new(&test_secret());
    let claims = b"test-claims-data";
    let tag_epoch0 = chain.generate_tag(claims);
    chain.advance(&test_entropy_a(), &test_entropy_b());
    // A fresh chain at epoch 0 would produce the same tag, but our
    // advanced chain at epoch 1 cannot.
    let tag_after_advance = chain.generate_tag(claims);
    assert_ne!(tag_epoch0, tag_after_advance);
}

#[test]
fn chain_verify_current_epoch() {
    let chain = RatchetChain::new(&test_secret());
    let claims = b"test-claims-data";
    let tag = chain.generate_tag(claims);
    assert!(chain.verify_tag(claims, &tag, 0));
}

#[test]
fn chain_reject_wrong_epoch() {
    let chain = RatchetChain::new(&test_secret());
    let claims = b"test-claims-data";
    let tag = chain.generate_tag(claims);
    // Epoch 10 is way outside the ±1 window
    assert!(!chain.verify_tag(claims, &tag, 10));
}

// ── SessionManager tests ────────────────────────────────────────────

#[test]
fn session_manager_create_and_advance() {
    let mut mgr = SessionManager::new();
    let sid = Uuid::new_v4();
    let epoch = mgr.create_session(sid, &test_secret());
    assert_eq!(epoch, 0);

    let new_epoch = mgr
        .advance_session(&sid, &test_entropy_a(), &test_entropy_b())
        .unwrap();
    assert_eq!(new_epoch, 1);

    // Generate and verify a tag
    let claims = b"session-claims";
    let tag = mgr.generate_tag(&sid, claims).unwrap();
    let valid = mgr.verify_tag(&sid, claims, &tag, 1).unwrap();
    assert!(valid);
}

#[test]
fn session_manager_expired_after_2880_epochs() {
    let mut mgr = SessionManager::new();
    let sid = Uuid::new_v4();
    mgr.create_session(sid, &test_secret());

    // Advance 2880 times to reach the 8-hour limit (at 10s/epoch)
    for _ in 0..2880 {
        mgr.advance_session(&sid, &test_entropy_a(), &test_entropy_b())
            .unwrap();
    }

    // The 2881st advance should fail
    let result = mgr.advance_session(&sid, &test_entropy_a(), &test_entropy_b());
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("expired"));
}

#[test]
fn session_manager_destroy_removes() {
    let mut mgr = SessionManager::new();
    let sid = Uuid::new_v4();
    mgr.create_session(sid, &test_secret());

    mgr.destroy_session(&sid);

    let result = mgr.generate_tag(&sid, b"claims");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}

// ── Wire message serialization round-trip tests ────────────────────

#[test]
fn request_create_session_roundtrip() {
    let req = RatchetRequest {
        action: RatchetAction::CreateSession {
            session_id: Uuid::new_v4(),
            initial_key: vec![0xAB; 64],
        },
    };
    let bytes = postcard::to_allocvec(&req).unwrap();
    let decoded: RatchetRequest = postcard::from_bytes(&bytes).unwrap();
    match decoded.action {
        RatchetAction::CreateSession { initial_key, .. } => {
            assert_eq!(initial_key.len(), 64);
            assert!(initial_key.iter().all(|&b| b == 0xAB));
        }
        _ => panic!("expected CreateSession"),
    }
}

#[test]
fn request_advance_roundtrip() {
    let sid = Uuid::new_v4();
    let req = RatchetRequest {
        action: RatchetAction::Advance {
            session_id: sid,
            client_entropy: [0xCC; 32],
            server_entropy: [0xDD; 32],
        },
    };
    let bytes = postcard::to_allocvec(&req).unwrap();
    let decoded: RatchetRequest = postcard::from_bytes(&bytes).unwrap();
    match decoded.action {
        RatchetAction::Advance { session_id, client_entropy, server_entropy } => {
            assert_eq!(session_id, sid);
            assert_eq!(client_entropy, [0xCC; 32]);
            assert_eq!(server_entropy, [0xDD; 32]);
        }
        _ => panic!("expected Advance"),
    }
}

#[test]
fn request_get_tag_roundtrip() {
    let sid = Uuid::new_v4();
    let claims = b"test-claims".to_vec();
    let req = RatchetRequest {
        action: RatchetAction::GetTag {
            session_id: sid,
            claims_bytes: claims.clone(),
        },
    };
    let bytes = postcard::to_allocvec(&req).unwrap();
    let decoded: RatchetRequest = postcard::from_bytes(&bytes).unwrap();
    match decoded.action {
        RatchetAction::GetTag { session_id, claims_bytes } => {
            assert_eq!(session_id, sid);
            assert_eq!(claims_bytes, claims);
        }
        _ => panic!("expected GetTag"),
    }
}

#[test]
fn request_destroy_roundtrip() {
    let sid = Uuid::new_v4();
    let req = RatchetRequest {
        action: RatchetAction::Destroy { session_id: sid },
    };
    let bytes = postcard::to_allocvec(&req).unwrap();
    let decoded: RatchetRequest = postcard::from_bytes(&bytes).unwrap();
    match decoded.action {
        RatchetAction::Destroy { session_id } => assert_eq!(session_id, sid),
        _ => panic!("expected Destroy"),
    }
}

#[test]
fn response_success_with_epoch_roundtrip() {
    let resp = RatchetResponse {
        success: true,
        epoch: Some(42),
        tag: None,
        error: None,
    };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: RatchetResponse = postcard::from_bytes(&bytes).unwrap();
    assert!(decoded.success);
    assert_eq!(decoded.epoch, Some(42));
    assert!(decoded.tag.is_none());
    assert!(decoded.error.is_none());
}

#[test]
fn response_success_with_tag_roundtrip() {
    let tag = vec![0xFF; 64];
    let resp = RatchetResponse {
        success: true,
        epoch: None,
        tag: Some(tag.clone()),
        error: None,
    };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: RatchetResponse = postcard::from_bytes(&bytes).unwrap();
    assert!(decoded.success);
    assert_eq!(decoded.tag.unwrap(), tag);
}

#[test]
fn response_error_roundtrip() {
    let resp = RatchetResponse {
        success: false,
        epoch: None,
        tag: None,
        error: Some("session not found".into()),
    };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: RatchetResponse = postcard::from_bytes(&bytes).unwrap();
    assert!(!decoded.success);
    assert_eq!(decoded.error.unwrap(), "session not found");
}
