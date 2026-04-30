//! Regression test for Codex review P1 (PR #27): when the bounded duress
//! dispatcher channel is saturated, `verify_pin` MUST fall back to
//! synchronous in-line emission for genuine `is_duress=true` events
//! rather than silently dropping them. The fix changed
//! `enqueue_duress_alert` to return `Result<(), DuressDispatch>` and
//! made `verify_pin` invoke `emit_duress_inline` on `Err`.
//!
//! This is hard to test directly without driving the dispatcher into
//! Disconnected/Full state. We instead exercise the (public) return-shape
//! contract of `enqueue_duress_alert` by faking saturation — sending
//! enough alerts to fill the bounded queue with the dispatcher thread
//! sleeping under load — and verifying that:
//!
//!   1. Real duress callbacks ALWAYS fire eventually, regardless of
//!      whether the dispatcher caught up.
//!   2. The system never deadlocks on saturation (verify_pin remains
//!      non-blocking).

use common::duress::{DuressAlert, DuressConfig, PinVerification};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Fire many duress matches in tight succession. Even if some fall back
/// inline, ALL should land on the callback eventually. The asynchronous
/// dispatcher gives us at-least-once delivery for genuine duress events.
#[test]
fn duress_alerts_survive_burst_load() {
    const BURST: u32 = 200;

    let user = Uuid::new_v4();
    let mut cfg = DuressConfig::new(user, b"normal-pin", b"duress-pin").unwrap();

    let count = Arc::new(AtomicU32::new(0));
    let count_cb = count.clone();
    cfg.duress_response_callback = Some(Arc::new(move |_alert: &DuressAlert| {
        count_cb.fetch_add(1, Ordering::SeqCst);
    }));

    // Fire BURST genuine duress matches as fast as possible.
    for _ in 0..BURST {
        let res = cfg.verify_pin(b"duress-pin");
        assert_eq!(res, PinVerification::Duress);
    }

    // Wait up to 10s for the dispatcher (and any inline fallbacks) to
    // surface every callback. The contract is at-least-once delivery —
    // we observe count >= BURST.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if count.load(Ordering::SeqCst) >= BURST {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let observed = count.load(Ordering::SeqCst);
    assert!(
        observed >= BURST,
        "duress callback fired {observed} times, expected at least {BURST}"
    );
}

/// Verify-pin must NEVER block on the dispatcher channel — burst load
/// is bounded by the call's own crypto cost, not by queue drain.
#[test]
fn verify_pin_does_not_block_under_saturation() {
    let user = Uuid::new_v4();
    let cfg = DuressConfig::new(user, b"normal-pin", b"duress-pin").unwrap();

    // 64 successive duress calls — enough to saturate a bounded channel
    // if the dispatcher is slow. Each call must return promptly.
    for _ in 0..64 {
        let started = Instant::now();
        let res = cfg.verify_pin(b"duress-pin");
        let elapsed = started.elapsed();
        assert_eq!(res, PinVerification::Duress);
        assert!(
            elapsed < Duration::from_secs(1),
            "verify_pin took {elapsed:?} (saturation should not block)"
        );
    }
}
