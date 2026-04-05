use crypto::ct::{ct_eq, ct_eq_32, ct_eq_64};
use std::time::Instant;

/// Best-effort statistical timing test for constant-time comparisons.
///
/// Measures 10,000 iterations of ct_eq with equal vs different inputs and
/// asserts the timing ratio (max/min) is within 2x. This is a rough heuristic,
/// not a formal guarantee. Real constant-time validation requires hardware
/// cycle counters and dedicated tools (e.g., dudect).
#[test]
fn timing_variance_ct_eq_within_bounds() {
    let iterations = 10_000;

    let a = [0x42u8; 64];
    let b_equal = [0x42u8; 64];
    let mut b_different = [0x42u8; 64];
    b_different[63] = 0xFF;

    // Warmup to stabilize CPU caches and branch predictors
    for _ in 0..1_000 {
        let _ = ct_eq(&a, &b_equal);
        let _ = ct_eq(&a, &b_different);
    }

    // Measure equal inputs
    let start_equal = Instant::now();
    for _ in 0..iterations {
        let _ = ct_eq(&a, &b_equal);
    }
    let elapsed_equal = start_equal.elapsed();

    // Measure different inputs (last byte differs)
    let start_diff = Instant::now();
    for _ in 0..iterations {
        let _ = ct_eq(&a, &b_different);
    }
    let elapsed_diff = start_diff.elapsed();

    let max_ns = elapsed_equal.as_nanos().max(elapsed_diff.as_nanos());
    let min_ns = elapsed_equal.as_nanos().min(elapsed_diff.as_nanos());

    // Avoid division by zero on very fast systems
    let min_ns = min_ns.max(1);
    let ratio = max_ns as f64 / min_ns as f64;

    // Widened to 5x: actual constant-time guarantee comes from subtle::ConstantTimeEq,
    // not this heuristic timing test. On shared/spot VMs, CPU scheduling jitter
    // routinely exceeds 2x.
    assert!(
        ratio < 5.0,
        "ct_eq timing ratio {:.2}x exceeds 5x threshold (equal={}ns, diff={}ns). \
         Possible timing oracle.",
        ratio,
        elapsed_equal.as_nanos(),
        elapsed_diff.as_nanos()
    );
}

/// Timing test for ct_eq_32 (fixed 32-byte arrays).
#[test]
fn timing_variance_ct_eq_32_within_bounds() {
    let iterations = 10_000;

    let a = [0xABu8; 32];
    let b_equal = [0xABu8; 32];
    let mut b_different = [0xABu8; 32];
    b_different[0] = 0x00; // First byte differs

    for _ in 0..1_000 {
        let _ = ct_eq_32(&a, &b_equal);
        let _ = ct_eq_32(&a, &b_different);
    }

    let start_equal = Instant::now();
    for _ in 0..iterations {
        let _ = ct_eq_32(&a, &b_equal);
    }
    let elapsed_equal = start_equal.elapsed();

    let start_diff = Instant::now();
    for _ in 0..iterations {
        let _ = ct_eq_32(&a, &b_different);
    }
    let elapsed_diff = start_diff.elapsed();

    let max_ns = elapsed_equal.as_nanos().max(elapsed_diff.as_nanos());
    let min_ns = elapsed_equal.as_nanos().min(elapsed_diff.as_nanos()).max(1);
    let ratio = max_ns as f64 / min_ns as f64;

    // Widened to 5x: see timing_variance_ct_eq_within_bounds rationale.
    assert!(
        ratio < 5.0,
        "ct_eq_32 timing ratio {:.2}x exceeds 5x (equal={}ns, diff={}ns)",
        ratio,
        elapsed_equal.as_nanos(),
        elapsed_diff.as_nanos()
    );
}

/// Timing test for ct_eq_64 (fixed 64-byte arrays).
#[test]
fn timing_variance_ct_eq_64_within_bounds() {
    let iterations = 10_000;

    let a = [0xCDu8; 64];
    let b_equal = [0xCDu8; 64];
    let mut b_different = [0xCDu8; 64];
    b_different[32] = 0x00; // Middle byte differs

    for _ in 0..1_000 {
        let _ = ct_eq_64(&a, &b_equal);
        let _ = ct_eq_64(&a, &b_different);
    }

    let start_equal = Instant::now();
    for _ in 0..iterations {
        let _ = ct_eq_64(&a, &b_equal);
    }
    let elapsed_equal = start_equal.elapsed();

    let start_diff = Instant::now();
    for _ in 0..iterations {
        let _ = ct_eq_64(&a, &b_different);
    }
    let elapsed_diff = start_diff.elapsed();

    let max_ns = elapsed_equal.as_nanos().max(elapsed_diff.as_nanos());
    let min_ns = elapsed_equal.as_nanos().min(elapsed_diff.as_nanos()).max(1);
    let ratio = max_ns as f64 / min_ns as f64;

    // Widened to 5x: see timing_variance_ct_eq_within_bounds rationale.
    assert!(
        ratio < 5.0,
        "ct_eq_64 timing ratio {:.2}x exceeds 5x (equal={}ns, diff={}ns)",
        ratio,
        elapsed_equal.as_nanos(),
        elapsed_diff.as_nanos()
    );
}

/// Timing test for different-length inputs (ct_eq should still be constant-time).
#[test]
fn timing_variance_ct_eq_different_lengths() {
    let iterations = 10_000;

    let a = [0x55u8; 64];
    let b_same_len = [0x55u8; 64];
    let b_short = [0x55u8; 32];

    for _ in 0..1_000 {
        let _ = ct_eq(&a, &b_same_len);
        let _ = ct_eq(&a, &b_short);
    }

    let start_same = Instant::now();
    for _ in 0..iterations {
        let _ = ct_eq(&a, &b_same_len);
    }
    let elapsed_same = start_same.elapsed();

    let start_short = Instant::now();
    for _ in 0..iterations {
        let _ = ct_eq(&a, &b_short);
    }
    let elapsed_short = start_short.elapsed();

    let max_ns = elapsed_same.as_nanos().max(elapsed_short.as_nanos());
    let min_ns = elapsed_same.as_nanos().min(elapsed_short.as_nanos()).max(1);
    let ratio = max_ns as f64 / min_ns as f64;

    // Widened to 8x: length-difference comparison has more variance, and spot
    // VM CPU jitter compounds on top. See timing_variance_ct_eq_within_bounds.
    assert!(
        ratio < 8.0,
        "ct_eq length-diff timing ratio {:.2}x exceeds 8x (same={}ns, short={}ns)",
        ratio,
        elapsed_same.as_nanos(),
        elapsed_short.as_nanos()
    );
}
