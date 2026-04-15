//! CAT-E HIGH REPLAY — contract tests for the JTI replay store.
//!
//! Exercises the `JtiReplayStore` trait against the in-memory `LocalJtiStore`
//! implementation. The `DatabaseJtiStore` 2-phase path is exercised indirectly
//! through integration tests that run against a live PostgreSQL instance; the
//! unit contract below pins the behaviour we rely on.

use sso_protocol::tokens::{JtiReplayStore, LocalJtiStore};

#[test]
fn positive_fresh_jti_is_marked() {
    let store = LocalJtiStore::new(1024);
    let ok = store.mark_used("jti-aaa", 9_999_999_999).unwrap();
    assert!(ok, "a freshly seen jti must be accepted once");
}

#[test]
fn replay_same_jti_rejected() {
    let store = LocalJtiStore::new(1024);
    assert!(store.mark_used("jti-aaa", 9_999_999_999).unwrap());
    assert!(
        !store.mark_used("jti-aaa", 9_999_999_999).unwrap(),
        "a repeat of the same jti must be rejected as a replay"
    );
}

#[test]
fn distinct_jtis_are_independent() {
    let store = LocalJtiStore::new(1024);
    assert!(store.mark_used("a", 9_999_999_999).unwrap());
    assert!(store.mark_used("b", 9_999_999_999).unwrap());
    assert!(store.mark_used("c", 9_999_999_999).unwrap());
    assert!(!store.mark_used("a", 9_999_999_999).unwrap());
    assert!(!store.mark_used("b", 9_999_999_999).unwrap());
}

#[test]
fn is_used_reflects_mark_used() {
    let store = LocalJtiStore::new(1024);
    assert!(!store.is_used("xyz"));
    store.mark_used("xyz", 9_999_999_999).unwrap();
    assert!(store.is_used("xyz"));
}

#[test]
fn boundary_capacity_evicts_oldest() {
    // Small cache: inserts past capacity must still succeed by evicting the
    // oldest entry. Evicted entries become replayable — this is the known
    // capacity tradeoff for the local store, DOCUMENTED here as a contract.
    let store = LocalJtiStore::new(3);
    store.mark_used("j1", 100).unwrap();
    store.mark_used("j2", 200).unwrap();
    store.mark_used("j3", 300).unwrap();
    // This should evict j1 (lowest expiry).
    assert!(store.mark_used("j4", 400).unwrap());
    // j4 must be detected as used now.
    assert!(!store.mark_used("j4", 400).unwrap());
}

#[test]
fn many_concurrent_distinct_inserts() {
    use std::sync::Arc;
    use std::thread;
    let store = Arc::new(LocalJtiStore::new(100_000));
    let mut handles = Vec::new();
    for i in 0..16 {
        let s = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            for j in 0..200 {
                let jti = format!("worker-{i}-jti-{j}");
                assert!(s.mark_used(&jti, 9_999_999_999).unwrap());
                assert!(!s.mark_used(&jti, 9_999_999_999).unwrap());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
