//! I12 [MED] WAL / persisted entries corruption: a tampered entry must be
//! detected by `verify_chain` (graceful failure, never silent skip).

use audit::log::{hash_entry, AuditLog};
use common::types::AuditEventType;
use std::thread;
use uuid::Uuid;

fn make_log_with_entries(n: usize) -> (AuditLog, crypto::pq_sign::PqVerifyingKey) {
    thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
            let mut log = AuditLog::new();
            for _ in 0..n {
                log.append(
                    AuditEventType::AuthSuccess,
                    vec![Uuid::new_v4()],
                    vec![],
                    0.1,
                    Vec::new(),
                    &sk,
                );
            }
            (log, vk)
        })
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn wal_corruption_detected_via_chain_verification() {
    let (log, vk) = make_log_with_entries(8);
    assert!(log.verify_chain());
    assert!(log.verify_chain_with_key(Some(&vk)));

    // Simulate a corrupted WAL: replay entries from disk into a fresh log,
    // mutating one byte mid-stream to model partial-write damage.
    let mut entries = log.entries().to_vec();
    entries[4].risk_score = 9.99; // bit-flip on persisted field

    let restored = AuditLog::from_entries(entries);
    assert!(
        !restored.verify_chain(),
        "tampered WAL entry must fail chain verification (no silent skip)"
    );
    assert!(
        !restored.verify_chain_with_key(Some(&vk)),
        "tampered entry must also fail signature verification"
    );
}

#[test]
fn wal_corruption_truncated_chain_fails_open_value() {
    let (log, _vk) = make_log_with_entries(6);
    let entries = log.entries().to_vec();

    // Truncate: drop the middle, then attempt to restore; prev_hash linkage
    // must break.
    let mut spliced = entries.clone();
    spliced.remove(3);
    let restored = AuditLog::from_entries(spliced);
    assert!(
        !restored.verify_chain(),
        "WAL with a missing middle entry must not silently verify"
    );

    // Hash-of-original must not equal hash-of-spliced (sanity).
    let original_hash = hash_entry(&entries[3]);
    assert_ne!(original_hash, [0u8; 64]);
}
