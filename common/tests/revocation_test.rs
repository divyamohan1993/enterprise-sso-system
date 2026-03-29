//! Token revocation list tests.
//!
//! Verifies the RevocationList and SharedRevocationList correctly:
//!   - Reject revoked tokens on verification (O(1) lookup)
//!   - Handle TTL-based expiry and cleanup
//!   - Enforce bounded capacity with oldest-entry eviction
//!   - Support concurrent access via SharedRevocationList
//!   - Persist revocations to disk and recover on restart

use common::revocation::*;

// ── Basic Revocation ──────────────────────────────────────────────────────

/// Security property: A revoked token MUST be rejected on verification.
/// This is the fundamental invariant of the revocation system.
#[test]
fn revoked_token_is_rejected_on_verification() {
    let mut rl = RevocationList::default();
    let token_id = [0xDE; 16];

    assert!(!rl.is_revoked(&token_id), "token must not be revoked initially");
    assert!(rl.revoke(token_id), "first revocation must return true");
    assert!(rl.is_revoked(&token_id), "revoked token MUST be detected");
}

/// Security property: Double revocation is a no-op (idempotent).
/// Returns false to indicate the token was already revoked.
#[test]
fn double_revocation_is_idempotent() {
    let mut rl = RevocationList::default();
    let token_id = [0xAB; 16];

    assert!(rl.revoke(token_id));
    assert!(!rl.revoke(token_id), "double revocation must return false");
    assert_eq!(rl.len(), 1, "count must not increase on double revoke");
}

/// Security property: Unknown tokens are NOT in the revocation list.
#[test]
fn unknown_token_is_not_in_revocation_list() {
    let rl = RevocationList::default();
    let unknown = [0x00; 16];
    assert!(!rl.is_revoked(&unknown));
}

// ── TTL Expiry ────────────────────────────────────────────────────────────

/// Security property: Cleanup preserves recently revoked entries.
/// Tokens revoked within the TTL window must remain in the list.
#[test]
fn cleanup_preserves_recent_entries() {
    let mut rl = RevocationList::default();
    let recent_token = [0x02; 16];
    rl.revoke(recent_token);

    rl.cleanup();
    assert!(
        rl.is_revoked(&recent_token),
        "recently revoked token must survive cleanup"
    );
}

/// Security property: Custom TTL cleanup with a very short lifetime
/// still preserves tokens revoked just now.
#[test]
fn cleanup_expired_with_long_lifetime_preserves_recent() {
    let mut rl = RevocationList::default();
    let token = [0x04; 16];
    rl.revoke(token);

    // Cleanup with 3600-second (1hr) lifetime should keep recent entry
    rl.cleanup_expired(3600);
    assert!(rl.is_revoked(&token), "recent token must survive 1hr cleanup");
}

/// Security property: Cleanup with very short lifetime (1 second) still
/// preserves tokens revoked less than 1 second ago.
#[test]
fn cleanup_expired_very_short_preserves_just_revoked() {
    let mut rl = RevocationList::default();
    let token = [0x05; 16];
    rl.revoke(token);

    // Even 1-second cleanup should preserve just-revoked token
    rl.cleanup_expired(1);
    assert!(
        rl.is_revoked(&token),
        "just-revoked token must survive even 1s cleanup"
    );
}

// ── Bounded Capacity ──────────────────────────────────────────────────────

/// Security property: The revocation list is bounded to prevent memory
/// exhaustion from revocation flooding attacks. When at capacity, the
/// oldest entries are evicted to make room.
#[test]
fn bounded_capacity_evicts_oldest_on_overflow() {
    let mut rl = RevocationList::default();

    // Fill to capacity (100,000 entries)
    for i in 0..100_000u128 {
        let mut id = [0u8; 16];
        id.copy_from_slice(&i.to_le_bytes());
        rl.revoke(id);
    }
    assert_eq!(rl.len(), 100_000);

    // Overflow triggers eviction of oldest 10%
    let overflow = [0xFF; 16];
    assert!(rl.revoke(overflow));
    assert!(rl.is_revoked(&overflow));
    // After evicting 10% and adding 1: 90,001
    assert_eq!(rl.len(), 90_001);
}

// ── SharedRevocationList (Thread-Safe) ────────────────────────────────────

/// Security property: SharedRevocationList provides thread-safe revocation
/// checking for concurrent async tasks.
#[test]
fn shared_revocation_list_basic_operations() {
    let srl = SharedRevocationList::default();
    let id = [0xCD; 16];

    assert!(!srl.is_revoked(&id));
    assert!(srl.revoke(id));
    assert!(srl.is_revoked(&id));
    assert!(!srl.revoke(id)); // duplicate
    assert_eq!(srl.len(), 1);
    assert_eq!(srl.revoked_count(), 1);
    assert!(!srl.is_empty());
}

/// Security property: Cloned SharedRevocationList shares state.
/// This is critical for distributing the list across async tasks.
#[test]
fn shared_clone_shares_state() {
    let srl = SharedRevocationList::default();
    let clone = srl.clone();
    let id = [0xAA; 16];

    srl.revoke(id);
    assert!(clone.is_revoked(&id), "clone must see revocations from original");

    let id2 = [0xBB; 16];
    clone.revoke(id2);
    assert!(srl.is_revoked(&id2), "original must see revocations from clone");
}

/// Security property: SharedRevocationList cleanup preserves recent entries.
#[test]
fn shared_cleanup_preserves_recent() {
    let srl = SharedRevocationList::default();
    let id = [0xEF; 16];

    srl.revoke(id);

    // Cleanup with a long lifetime should preserve the entry
    srl.cleanup_expired(3600);
    assert!(srl.is_revoked(&id), "recent entry must survive cleanup");
}

/// Security property: SharedRevocationList default cleanup (8-hour window)
/// preserves recently revoked tokens.
#[test]
fn shared_default_cleanup_preserves_recent() {
    let srl = SharedRevocationList::default();
    let id = [0x99; 16];

    srl.revoke(id);
    srl.cleanup();
    assert!(srl.is_revoked(&id), "recent entry must survive default cleanup");
}

// ── Concurrent Safety ─────────────────────────────────────────────────────

/// Security property: Concurrent revocation list updates are safe.
/// Multiple threads can revoke tokens simultaneously without data corruption.
#[test]
fn concurrent_revocation_updates_are_safe() {
    let srl = SharedRevocationList::default();
    let mut handles = Vec::new();

    for thread_idx in 0..4u8 {
        let srl_clone = srl.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100u8 {
                let mut id = [0u8; 16];
                id[0] = thread_idx;
                id[1] = i;
                srl_clone.revoke(id);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread must not panic");
    }

    // All 400 unique tokens should be revoked
    assert_eq!(srl.revoked_count(), 400);

    // Verify random samples
    for thread_idx in 0..4u8 {
        let mut id = [0u8; 16];
        id[0] = thread_idx;
        id[1] = 50;
        assert!(srl.is_revoked(&id));
    }
}

// ── Persistence ───────────────────────────────────────────────────────────

/// Security property: Revocations survive process restarts when persisted.
/// This ensures that revoked tokens cannot be used after a service restart.
#[test]
fn persistence_roundtrip_survives_restart() {
    let dir = std::env::temp_dir().join(format!("revoc_rt_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("revocations.dat");
    let _ = std::fs::remove_file(&path);

    let id1 = [0x10; 16];
    let id2 = [0x20; 16];

    // Revoke and persist
    {
        let mut rl = RevocationList::with_persistence(path.clone());
        assert!(rl.revoke(id1));
        assert!(rl.revoke(id2));
        assert_eq!(rl.len(), 2);
    }

    // Simulate restart: new instance from same file
    {
        let rl = RevocationList::with_persistence(path.clone());
        assert!(rl.is_revoked(&id1), "id1 must survive restart");
        assert!(rl.is_revoked(&id2), "id2 must survive restart");
        assert_eq!(rl.len(), 2);
    }

    // Cleanup
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

/// Security property: Expired entries are filtered out during file load.
/// This prevents the revocation list from growing unbounded across restarts.
#[test]
fn persistence_filters_expired_entries_on_load() {
    use std::io::Write;

    let dir = std::env::temp_dir().join(format!("revoc_expire_rt_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("revocations.dat");
    let _ = std::fs::remove_file(&path);

    let id_valid = [0x30; 16];
    let id_expired = [0x40; 16];

    // Write file with one valid and one expired entry
    // Use epoch-based timestamps: valid entry expires far in the future,
    // expired entry has already expired.
    {
        let mut f = std::fs::File::create(&path).unwrap();
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let future = now_us + (8 * 60 * 60 * 1_000_000); // 8 hours from now
        let past = now_us - 1_000_000; // already expired
        writeln!(f, "{},{}", hex::encode(id_valid), future).unwrap();
        writeln!(f, "{},{}", hex::encode(id_expired), past).unwrap();
    }

    let rl = RevocationList::with_persistence(path.clone());
    assert!(rl.is_revoked(&id_valid), "valid entry must be loaded");
    assert!(!rl.is_revoked(&id_expired), "expired entry must be filtered");
    assert_eq!(rl.len(), 1);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

/// Security property: SharedRevocationList also supports persistence.
#[test]
fn shared_persistence_roundtrip() {
    let dir = std::env::temp_dir().join(format!("shared_persist_rt_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("revocations.dat");
    let _ = std::fs::remove_file(&path);

    let id = [0x50; 16];

    {
        let srl = SharedRevocationList::with_persistence(path.clone());
        assert!(srl.revoke(id));
    }

    {
        let srl = SharedRevocationList::with_persistence(path.clone());
        assert!(srl.is_revoked(&id), "should survive restart via SharedRevocationList");
    }

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

// ── RevocationCommand ─────────────────────────────────────────────────────

/// Security property: Revocation commands carry a reason for audit trail.
#[test]
fn revocation_command_carries_reason() {
    let cmd = RevocationCommand {
        token_id: [0xAB; 16],
        reason: RevocationReason::Compromised,
    };
    assert_eq!(cmd.reason, RevocationReason::Compromised);

    let cmd2 = RevocationCommand {
        token_id: [0xCD; 16],
        reason: RevocationReason::Duress,
    };
    assert_eq!(cmd2.reason, RevocationReason::Duress);

    let cmd3 = RevocationCommand {
        token_id: [0xEF; 16],
        reason: RevocationReason::Administrative,
    };
    assert_eq!(cmd3.reason, RevocationReason::Administrative);

    let cmd4 = RevocationCommand {
        token_id: [0x12; 16],
        reason: RevocationReason::UserLogout,
    };
    assert_eq!(cmd4.reason, RevocationReason::UserLogout);
}

// ── Lazy Cleanup ──────────────────────────────────────────────────────────

/// Security property: maybe_lazy_cleanup does not remove recently revoked tokens.
#[test]
fn lazy_cleanup_preserves_recent() {
    let srl = SharedRevocationList::default();
    let id = [0x77; 16];

    srl.revoke(id);
    srl.maybe_lazy_cleanup(3600);
    assert!(srl.is_revoked(&id), "lazy cleanup must preserve recent tokens");
}

// ── Multiple Revocations ──────────────────────────────────────────────────

/// Security property: Multiple distinct tokens can be revoked and all are
/// correctly tracked.
#[test]
fn multiple_distinct_revocations() {
    let mut rl = RevocationList::default();

    let ids: Vec<[u8; 16]> = (0..50u8)
        .map(|i| {
            let mut id = [0u8; 16];
            id[0] = i;
            id
        })
        .collect();

    for &id in &ids {
        assert!(rl.revoke(id));
    }

    assert_eq!(rl.len(), 50);

    for &id in &ids {
        assert!(rl.is_revoked(&id), "all revoked tokens must be tracked");
    }

    // Non-revoked token should not be present
    let non_revoked = [0xFF; 16];
    assert!(!rl.is_revoked(&non_revoked));
}

/// Security property: RevocationList default is empty.
#[test]
fn default_revocation_list_is_empty() {
    let rl = RevocationList::default();
    assert!(rl.is_empty());
    assert_eq!(rl.len(), 0);
    assert_eq!(rl.revoked_count(), 0);
}
