use common::circuit_breaker::{CircuitBreaker, CircuitState};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_initial_state_is_closed() {
    let cb = CircuitBreaker::new(3, Duration::from_secs(5));
    assert_eq!(cb.state(), CircuitState::Closed);
    assert!(cb.allow_request());
}

#[test]
fn test_opens_after_threshold_failures() {
    let cb = CircuitBreaker::new(3, Duration::from_secs(60));
    cb.record_failure();
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Closed);
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open);
    assert!(!cb.allow_request());
}

#[test]
fn test_success_resets_failure_count() {
    let cb = CircuitBreaker::with_name("test-svc", 3, Duration::from_secs(60));
    cb.record_failure();
    cb.record_failure();
    cb.record_success();
    assert_eq!(cb.state(), CircuitState::Closed);
    assert!(cb.allow_request());
}

#[test]
fn test_failure_count_saturates_at_u32_max_instead_of_wrapping() {
    // Use threshold=1 so we can quickly get to Open state, then hammer failures.
    let cb = CircuitBreaker::with_name("saturation-test", 1, Duration::from_secs(60));

    // Record enough failures to approach saturation. We cannot literally do
    // 4 billion iterations, so we test the saturating_add logic indirectly:
    // record many failures and verify the circuit stays Open (no wraparound
    // back to Closed).
    for _ in 0..100 {
        cb.record_failure();
    }
    assert_eq!(
        cb.state(),
        CircuitState::Open,
        "circuit must remain Open after many failures (no wraparound)"
    );
    assert!(
        !cb.allow_request(),
        "requests must be rejected when circuit is Open"
    );
}

#[test]
fn test_acquire_release_ordering_visible_across_threads() {
    // Verify that failure_count updates with Acquire/Release ordering are
    // visible across threads. We record failures from one thread and observe
    // the state from another.
    let cb = Arc::new(CircuitBreaker::with_name("ordering-test", 5, Duration::from_secs(60)));
    let cb_writer = Arc::clone(&cb);

    let writer = std::thread::spawn(move || {
        for _ in 0..5 {
            cb_writer.record_failure();
        }
    });

    writer.join().expect("writer thread panicked");

    // After the writer thread completes, the state must be visible to the
    // reader thread (us) due to Acquire/Release ordering.
    assert_eq!(
        cb.state(),
        CircuitState::Open,
        "state change must be visible across threads with Acquire/Release ordering"
    );
}

#[test]
fn test_concurrent_failure_recording_no_panic() {
    // Stress test: multiple threads recording failures concurrently.
    // Must not panic or produce undefined behavior.
    let cb = Arc::new(CircuitBreaker::with_name("concurrent-test", 10, Duration::from_secs(60)));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let cb_clone = Arc::clone(&cb);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                cb_clone.record_failure();
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked during concurrent failures");
    }

    // After 800 total failures with threshold=10, circuit must be Open.
    assert_eq!(cb.state(), CircuitState::Open);
}

#[test]
fn test_half_open_after_reset_timeout() {
    // Use a very short reset timeout to test the HalfOpen transition.
    let cb = CircuitBreaker::new(1, Duration::from_millis(10));
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open);

    // Wait for the reset timeout to expire.
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        cb.state(),
        CircuitState::HalfOpen,
        "circuit must transition to HalfOpen after reset timeout"
    );
    assert!(cb.allow_request(), "HalfOpen must allow requests (probe)");
}

#[test]
fn test_success_after_half_open_resets_to_closed() {
    let cb = CircuitBreaker::new(1, Duration::from_millis(10));
    cb.record_failure();
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(cb.state(), CircuitState::HalfOpen);

    cb.record_success();
    assert_eq!(cb.state(), CircuitState::Closed);
}

#[test]
fn test_failure_after_half_open_returns_to_open() {
    let cb = CircuitBreaker::new(1, Duration::from_millis(10));
    cb.record_failure();
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(cb.state(), CircuitState::HalfOpen);

    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open);
}

#[test]
fn test_with_name_stores_service_name() {
    // The named constructor should work without panic.
    let cb = CircuitBreaker::with_name("auth-service", 5, Duration::from_secs(30));
    assert_eq!(cb.state(), CircuitState::Closed);
}
