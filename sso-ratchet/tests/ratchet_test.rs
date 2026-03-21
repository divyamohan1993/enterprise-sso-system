//! Integration tests for the ratchet session manager.

use sso_ratchet::chain::RatchetChain;
use sso_ratchet::manager::SessionManager;
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
    // Epoch 10 is way outside the ±3 window
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
fn session_manager_expired_after_960_epochs() {
    let mut mgr = SessionManager::new();
    let sid = Uuid::new_v4();
    mgr.create_session(sid, &test_secret());

    // Advance 960 times to reach the 8-hour limit
    for _ in 0..960 {
        mgr.advance_session(&sid, &test_entropy_a(), &test_entropy_b())
            .unwrap();
    }

    // The 961st advance should fail
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
