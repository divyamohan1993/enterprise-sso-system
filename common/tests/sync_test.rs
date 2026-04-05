use common::sync::{lock_or_panic, lock_or_recover, siem_lock, siem_read, siem_write};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

// ── 1. lock_or_panic succeeds on healthy mutex ─────────────────────────

#[test]
fn lock_or_panic_succeeds_on_healthy_mutex() {
    let mutex = Mutex::new(42);
    let guard = lock_or_panic(&mutex, "test-healthy");
    assert_eq!(*guard, 42);
}

#[test]
fn lock_or_panic_allows_mutation() {
    let mutex = Mutex::new(0);
    {
        let mut guard = lock_or_panic(&mutex, "test-mutate");
        *guard = 99;
    }
    let guard = lock_or_panic(&mutex, "test-verify");
    assert_eq!(*guard, 99);
}

#[test]
#[should_panic(expected = "mutex poisoned")]
fn lock_or_panic_panics_on_poisoned_mutex() {
    let mutex = Arc::new(Mutex::new(0));
    let m = mutex.clone();

    // Poison the mutex by panicking while holding the lock.
    let _ = thread::spawn(move || {
        let _guard = m.lock().unwrap();
        panic!("intentional poison");
    })
    .join();

    // This should panic because the mutex is poisoned.
    let _guard = lock_or_panic(&mutex, "test-poisoned");
}

// ── 2. lock_or_recover recovers from poisoned mutex ────────────────────

#[test]
fn lock_or_recover_succeeds_on_healthy_mutex() {
    let mutex = Mutex::new("hello");
    let guard = lock_or_recover(&mutex, "test-healthy");
    assert_eq!(*guard, "hello");
}

#[test]
fn lock_or_recover_recovers_from_poisoned_mutex() {
    let mutex = Arc::new(Mutex::new(42));
    let m = mutex.clone();

    // Poison the mutex.
    let _ = thread::spawn(move || {
        let _guard = m.lock().unwrap();
        panic!("intentional poison");
    })
    .join();

    // lock_or_recover should NOT panic; it recovers with the inner value.
    let guard = lock_or_recover(&mutex, "test-recover");
    assert_eq!(*guard, 42, "recovered value must match pre-poison state");
}

// ── 3. siem_lock/siem_read/siem_write succeed on healthy locks ─────────

#[test]
fn siem_lock_succeeds_on_healthy_mutex() {
    let mutex = Mutex::new(vec![1, 2, 3]);
    let guard = siem_lock(&mutex, "test-siem-lock");
    assert_eq!(guard.len(), 3);
}

#[test]
fn siem_read_succeeds_on_healthy_rwlock() {
    let lock = RwLock::new("data");
    let guard = siem_read(&lock, "test-siem-read");
    assert_eq!(*guard, "data");
}

#[test]
fn siem_write_succeeds_on_healthy_rwlock() {
    let lock = RwLock::new(0i32);
    {
        let mut guard = siem_write(&lock, "test-siem-write");
        *guard = 123;
    }
    let guard = siem_read(&lock, "test-siem-verify");
    assert_eq!(*guard, 123);
}

#[test]
fn siem_lock_recovers_from_poisoned_mutex() {
    let mutex = Arc::new(Mutex::new(77));
    let m = mutex.clone();

    let _ = thread::spawn(move || {
        let _guard = m.lock().unwrap();
        panic!("intentional poison for siem_lock");
    })
    .join();

    // siem_lock recovers (does not panic).
    let guard = siem_lock(&mutex, "test-siem-poisoned");
    assert_eq!(*guard, 77);
}

#[test]
fn siem_read_recovers_from_poisoned_rwlock() {
    let lock = Arc::new(RwLock::new(88));
    let l = lock.clone();

    let _ = thread::spawn(move || {
        let _guard = l.write().unwrap();
        panic!("intentional poison for siem_read");
    })
    .join();

    let guard = siem_read(&lock, "test-siem-read-poisoned");
    assert_eq!(*guard, 88);
}

#[test]
fn siem_write_recovers_from_poisoned_rwlock() {
    let lock = Arc::new(RwLock::new(99));
    let l = lock.clone();

    let _ = thread::spawn(move || {
        let _guard = l.write().unwrap();
        panic!("intentional poison for siem_write");
    })
    .join();

    let mut guard = siem_write(&lock, "test-siem-write-poisoned");
    *guard = 100;
    assert_eq!(*guard, 100);
}

// ── 4. Concurrent access doesn't deadlock ──────────────────────────────

#[test]
fn concurrent_lock_or_panic_does_not_deadlock() {
    let mutex = Arc::new(Mutex::new(0u64));
    let mut handles = Vec::new();

    for _ in 0..10 {
        let m = mutex.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let mut guard = lock_or_panic(&m, "concurrent-test");
                *guard += 1;
            }
        }));
    }

    for h in handles {
        h.join().expect("thread must not panic");
    }

    let final_val = lock_or_panic(&mutex, "final-check");
    assert_eq!(*final_val, 1000, "10 threads x 100 increments = 1000");
}

#[test]
fn concurrent_rwlock_reads_do_not_deadlock() {
    let lock = Arc::new(RwLock::new(42));
    let mut handles = Vec::new();

    for _ in 0..20 {
        let l = lock.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let guard = siem_read(&l, "concurrent-read");
                assert_eq!(*guard, 42);
            }
        }));
    }

    for h in handles {
        h.join().expect("reader thread must not panic");
    }
}

#[test]
fn concurrent_rwlock_mixed_reads_writes() {
    let lock = Arc::new(RwLock::new(0u64));
    let mut handles = Vec::new();

    // 5 writer threads
    for _ in 0..5 {
        let l = lock.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                let mut guard = siem_write(&l, "concurrent-writer");
                *guard += 1;
            }
        }));
    }

    // 5 reader threads
    for _ in 0..5 {
        let l = lock.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                let _guard = siem_read(&l, "concurrent-reader");
            }
        }));
    }

    for h in handles {
        h.join().expect("thread must not panic");
    }

    let final_val = siem_read(&lock, "final-check");
    assert_eq!(*final_val, 250, "5 writers x 50 increments = 250");
}
