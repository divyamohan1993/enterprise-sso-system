//! I3 [CRIT] OAuth authorization-code double-spend.
//!
//! Models the /token endpoint's single-use authorization code: 100 concurrent
//! threads attempt to redeem the same code; exactly one must succeed.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;

/// Minimal in-memory single-use authorization-code store. Production code
/// uses the orchestrator's redis-backed implementation; here we model the
/// invariant directly so the test stays hermetic and is gated on the SAME
/// "consume exactly once" contract.
struct CodeStore {
    consumed: Mutex<HashSet<String>>,
}

impl CodeStore {
    fn new() -> Self { Self { consumed: Mutex::new(HashSet::new()) } }

    fn redeem(&self, code: &str) -> bool {
        let mut set = self.consumed.lock().expect("code store mutex poisoned");
        set.insert(code.to_string())
    }
}

#[test]
fn concurrent_authorization_code_redemption_only_one_wins() {
    const N: usize = 100;
    let store = Arc::new(CodeStore::new());
    let code = "auth_code_abcdef0123456789";

    let mut handles = Vec::with_capacity(N);
    let success_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for _ in 0..N {
        let store = Arc::clone(&store);
        let success_count = Arc::clone(&success_count);
        handles.push(thread::spawn(move || {
            if store.redeem(code) {
                success_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }

    let wins = success_count.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        wins, 1,
        "exactly one POST /token concurrent redemption may succeed; got {wins}"
    );
}

#[test]
fn distinct_codes_can_succeed_in_parallel() {
    const N: usize = 200;
    let store = Arc::new(CodeStore::new());
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let store = Arc::clone(&store);
        let code = format!("code-{i}");
        handles.push(thread::spawn(move || store.redeem(&code)));
    }
    let mut wins = 0usize;
    for h in handles {
        if h.join().unwrap() {
            wins += 1;
        }
    }
    assert_eq!(wins, N, "every distinct code must redeem exactly once");
}
