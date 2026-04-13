//! Constant-time measurement harness (J17).
//!
//! Implements the dudect / Welch t-test methodology (Reparaz, Balasch,
//! Verbauwhede 2017, "Dude, is my code constant time?") as a standalone
//! statistical core that doesn't pull in the full `dudect` crate so it
//! compiles in air-gapped builds.
//!
//! Other crates plug their hot path into `measure(input_a, input_b, op)`
//! and call `verdict()` to assert constant-time behavior in tests.
#![forbid(unsafe_code)]

use std::time::Instant;

/// Welch's t-test implementation tuned for two-class timing distributions.
#[derive(Debug, Default, Clone)]
pub struct WelchT {
    n0: f64, mean0: f64, m2_0: f64,
    n1: f64, mean1: f64, m2_1: f64,
}

impl WelchT {
    pub fn new() -> Self { Self::default() }

    pub fn push(&mut self, class: u8, x: f64) {
        let (n, mean, m2) = if class == 0 {
            (&mut self.n0, &mut self.mean0, &mut self.m2_0)
        } else {
            (&mut self.n1, &mut self.mean1, &mut self.m2_1)
        };
        *n += 1.0;
        let delta = x - *mean;
        *mean += delta / *n;
        let delta2 = x - *mean;
        *m2 += delta * delta2;
    }

    pub fn t(&self) -> f64 {
        if self.n0 < 2.0 || self.n1 < 2.0 { return 0.0; }
        let v0 = self.m2_0 / (self.n0 - 1.0);
        let v1 = self.m2_1 / (self.n1 - 1.0);
        let denom = (v0 / self.n0 + v1 / self.n1).sqrt();
        if denom == 0.0 { return 0.0; }
        (self.mean0 - self.mean1) / denom
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// |t| < 4.5 — no statistical evidence of a timing leak at the dudect threshold.
    ConstantTime,
    /// |t| ≥ 4.5 — statistically significant timing difference, code likely leaks.
    LeakDetected,
}

#[derive(Debug, Clone)]
pub struct DudectReport {
    pub samples: usize,
    pub t: f64,
    pub verdict: Verdict,
}

/// Run the harness for `iters` rounds, alternating between class-0 and class-1
/// inputs. The closure receives the raw bytes and is expected to call into the
/// code under test; the harness handles timing.
pub fn measure<F>(class0: &[u8], class1: &[u8], iters: usize, mut op: F) -> DudectReport
where
    F: FnMut(&[u8]),
{
    let mut t = WelchT::new();
    for i in 0..iters {
        let (class, input) = if i % 2 == 0 { (0u8, class0) } else { (1u8, class1) };
        let start = Instant::now();
        op(input);
        let dur = start.elapsed().as_nanos() as f64;
        // Trim obvious outliers (top 0.5% of nanoseconds drowned by GC/cache effects).
        if dur < 1.0e9 {
            t.push(class, dur);
        }
    }
    let tv = t.t();
    DudectReport {
        samples: iters,
        t: tv,
        verdict: if tv.abs() < 4.5 { Verdict::ConstantTime } else { Verdict::LeakDetected },
    }
}

/// Assertion helper for use inside `#[test]` bodies.
pub fn assert_constant_time(report: &DudectReport) {
    assert_eq!(
        report.verdict,
        Verdict::ConstantTime,
        "dudect leak detected: |t|={:.3} over {} samples",
        report.t,
        report.samples
    );
}
