use common::retry::{retry_with_backoff, RetryConfig};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── 1. retry_with_backoff succeeds on first try ────────────────────────

#[tokio::test]
async fn succeeds_on_first_try() {
    let cfg = RetryConfig {
        max_retries: 5,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(10),
        multiplier: 2.0,
    };
    let count = Arc::new(AtomicU32::new(0));
    let c = count.clone();

    let result: Result<i32, String> = retry_with_backoff(&cfg, "test-first-try", || {
        let c = c.clone();
        async move {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(42)
        }
    })
    .await;

    assert_eq!(result.unwrap(), 42);
    assert_eq!(count.load(Ordering::Relaxed), 1, "must call operation exactly once");
}

// ── 2. retry_with_backoff retries on failure then succeeds ─────────────

#[tokio::test]
async fn retries_then_succeeds() {
    let cfg = RetryConfig {
        max_retries: 5,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(10),
        multiplier: 2.0,
    };
    let count = Arc::new(AtomicU32::new(0));
    let c = count.clone();

    let result: Result<&str, String> = retry_with_backoff(&cfg, "test-retry-success", || {
        let c = c.clone();
        async move {
            let n = c.fetch_add(1, Ordering::Relaxed);
            if n < 3 {
                Err(format!("transient error {n}"))
            } else {
                Ok("recovered")
            }
        }
    })
    .await;

    assert_eq!(result.unwrap(), "recovered");
    assert_eq!(count.load(Ordering::Relaxed), 4); // 3 failures + 1 success
}

// ── 3. retry_with_backoff exhausts all retries and returns error ───────

#[tokio::test]
async fn exhausts_retries_returns_last_error() {
    let cfg = RetryConfig {
        max_retries: 2,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
        multiplier: 2.0,
    };
    let count = Arc::new(AtomicU32::new(0));
    let c = count.clone();

    let result: Result<(), String> = retry_with_backoff(&cfg, "test-exhaust", || {
        let c = c.clone();
        async move {
            let n = c.fetch_add(1, Ordering::Relaxed);
            Err(format!("persistent-error-{n}"))
        }
    })
    .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "persistent-error-2");
    assert_eq!(count.load(Ordering::Relaxed), 3); // 1 initial + 2 retries
}

// ── 4. Delay increases exponentially between retries ───────────────────

#[test]
fn delay_increases_exponentially_between_attempts() {
    let cfg = RetryConfig {
        max_retries: 10,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(60),
        multiplier: 2.0,
    };

    // Sample median of multiple calls to smooth out jitter
    let median_delay = |attempt: u32| -> u128 {
        let mut samples: Vec<u128> = (0..21)
            .map(|_| cfg.delay_for_attempt(attempt).as_millis())
            .collect();
        samples.sort();
        samples[10] // median
    };

    let d0 = median_delay(0); // ~100ms
    let d1 = median_delay(1); // ~200ms
    let d2 = median_delay(2); // ~400ms
    let d3 = median_delay(3); // ~800ms

    assert!(d1 > d0, "delay must increase: d1={d1} > d0={d0}");
    assert!(d2 > d1, "delay must increase: d2={d2} > d1={d1}");
    assert!(d3 > d2, "delay must increase: d3={d3} > d2={d2}");
}

// ── 5. Jitter adds randomness (delays are not identical across runs) ───

#[test]
fn jitter_produces_variation() {
    let cfg = RetryConfig::default();
    let delays: Vec<u128> = (0..30).map(|_| cfg.delay_for_attempt(0).as_millis()).collect();
    let all_same = delays.iter().all(|&d| d == delays[0]);
    assert!(!all_same, "30 delay samples at same attempt must not all be identical (CSPRNG jitter)");
}

// ── 6. Max delay is capped ─────────────────────────────────────────────

#[test]
fn delay_is_capped_at_max() {
    let cfg = RetryConfig {
        max_retries: 100,
        initial_delay: Duration::from_secs(1),
        max_delay: Duration::from_secs(5),
        multiplier: 10.0,
    };

    // At attempt 20, uncapped base would be 1s * 10^20, well beyond max.
    // With +25% jitter, max possible = 5000 * 1.25 = 6250ms.
    for _ in 0..50 {
        let d = cfg.delay_for_attempt(20);
        assert!(
            d.as_millis() <= 6500,
            "delay must be capped near max_delay, got {}ms",
            d.as_millis()
        );
    }
}

// ── Bonus: timing sanity check ─────────────────────────────────────────

#[tokio::test]
async fn actual_retry_timing_is_bounded() {
    let cfg = RetryConfig {
        max_retries: 2,
        initial_delay: Duration::from_millis(5),
        max_delay: Duration::from_millis(20),
        multiplier: 2.0,
    };

    let start = Instant::now();
    let _: Result<(), String> = retry_with_backoff(&cfg, "timing-test", || async {
        Err::<(), String>("fail".into())
    })
    .await;
    let elapsed = start.elapsed();

    // 2 retries with delays ~5ms and ~10ms = ~15ms minimum, plus jitter.
    // Should complete in well under 1 second.
    assert!(
        elapsed < Duration::from_secs(1),
        "retry loop took too long: {:?}",
        elapsed
    );
}
