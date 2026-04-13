//! I4 [CRIT] Concurrent audit append stress test.
//!
//! 500 threads append to a single audit log under a Mutex. Verifies that
//! every entry persists, the chain remains intact, and no entry is lost.

use audit::log::AuditLog;
use common::types::AuditEventType;
use std::sync::{Arc, Mutex};
use std::thread;
use uuid::Uuid;

const THREAD_COUNT: usize = 500;
const ENTRIES_PER_THREAD: usize = 4;

#[test]
fn concurrent_500_threads_append_chain_intact() {
    let (sk, vk) = thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| crypto::pq_sign::generate_pq_keypair())
        .unwrap()
        .join()
        .unwrap();

    let log = Arc::new(Mutex::new(AuditLog::new()));
    let sk = Arc::new(sk);

    let mut handles = Vec::with_capacity(THREAD_COUNT);
    for tid in 0..THREAD_COUNT {
        let log = Arc::clone(&log);
        let sk = Arc::clone(&sk);
        handles.push(
            thread::Builder::new()
                .stack_size(8 * 1024 * 1024)
                .spawn(move || {
                    for _ in 0..ENTRIES_PER_THREAD {
                        let mut guard = log.lock().expect("audit log mutex poisoned");
                        guard.append(
                            AuditEventType::AuthSuccess,
                            vec![Uuid::new_v4()],
                            vec![Uuid::new_v4()],
                            (tid as f64) / (THREAD_COUNT as f64),
                            Vec::new(),
                            &sk,
                        );
                    }
                })
                .expect("thread spawn failed"),
        );
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }

    let log = log.lock().expect("audit log mutex poisoned at assertion");
    assert_eq!(
        log.len(),
        THREAD_COUNT * ENTRIES_PER_THREAD,
        "no entries may be lost under concurrent contention"
    );
    assert!(log.verify_chain(), "chain integrity must hold under contention");
    assert!(log.verify_chain_with_key(Some(&vk)), "all signatures must verify");
}
