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

/// Fraction of the slowest samples dropped *per class* before computing the
/// t-statistic. The dudect paper crops at a per-class percentile so that a
/// single GC pause or scheduler preemption cannot inflate the variance and
/// crush the t-statistic toward zero (a false-negative). 5% matches the
/// paper's recommendation.
const CROP_FRACTION: f64 = 0.05;

/// Run the harness for `iters` rounds, alternating between class-0 and class-1
/// inputs. The closure receives the raw bytes and is expected to call into the
/// code under test; the harness handles timing.
///
/// Raw timings are collected per class, then the slowest [`CROP_FRACTION`] of
/// each class is dropped before the Welch t-test runs — an absolute "drop
/// anything over one second" cutoff is meaningless at the nanosecond scale of
/// these primitives and lets preemption noise dominate.
pub fn measure<F>(class0: &[u8], class1: &[u8], iters: usize, mut op: F) -> DudectReport
where
    F: FnMut(&[u8]),
{
    let mut samples0: Vec<f64> = Vec::with_capacity(iters / 2 + 1);
    let mut samples1: Vec<f64> = Vec::with_capacity(iters / 2 + 1);
    for i in 0..iters {
        let class0_turn = i % 2 == 0;
        let input = if class0_turn { class0 } else { class1 };
        let start = Instant::now();
        op(input);
        let dur = start.elapsed().as_nanos() as f64;
        if class0_turn {
            samples0.push(dur);
        } else {
            samples1.push(dur);
        }
    }

    let mut t = WelchT::new();
    let kept0 = push_cropped(&mut t, 0, &mut samples0);
    let kept1 = push_cropped(&mut t, 1, &mut samples1);

    let tv = t.t();
    DudectReport {
        samples: kept0 + kept1,
        t: tv,
        verdict: if tv.abs() < 4.5 { Verdict::ConstantTime } else { Verdict::LeakDetected },
    }
}

/// Run the harness in the dudect-paper "fixed vs random" configuration:
/// class-0 is a single fixed input repeated every round, class-1 is a freshly
/// drawn random buffer (same length as `fixed`) each round.
///
/// Two-fixed-class testing (`measure`) only detects first-moment leaks where a
/// specific byte value is fast/slow. Fixed-vs-random additionally surfaces
/// higher-moment leaks (cache-set collisions, memory-layout-dependent latency,
/// branch-predictor state) — the realistic side channels on modern CPUs.
/// Reparaz/Balasch/Verbauwhede (2017) §3.1 specify this configuration.
pub fn measure_fixed_vs_random<F>(fixed: &[u8], iters: usize, mut op: F) -> DudectReport
where
    F: FnMut(&[u8]),
{
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut random = vec![0u8; fixed.len()];

    let mut samples0: Vec<f64> = Vec::with_capacity(iters / 2 + 1);
    let mut samples1: Vec<f64> = Vec::with_capacity(iters / 2 + 1);
    for i in 0..iters {
        let class0_turn = i % 2 == 0;
        let input: &[u8] = if class0_turn {
            fixed
        } else {
            rng.fill_bytes(&mut random);
            &random
        };
        let start = Instant::now();
        op(input);
        let dur = start.elapsed().as_nanos() as f64;
        if class0_turn {
            samples0.push(dur);
        } else {
            samples1.push(dur);
        }
    }

    let mut t = WelchT::new();
    let kept0 = push_cropped(&mut t, 0, &mut samples0);
    let kept1 = push_cropped(&mut t, 1, &mut samples1);

    let tv = t.t();
    DudectReport {
        samples: kept0 + kept1,
        t: tv,
        verdict: if tv.abs() < 4.5 { Verdict::ConstantTime } else { Verdict::LeakDetected },
    }
}

/// Sort `samples` ascending, drop the slowest [`CROP_FRACTION`], push the rest
/// into the t-test under `class`, and return how many samples were kept.
fn push_cropped(t: &mut WelchT, class: u8, samples: &mut [f64]) -> usize {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let drop = (samples.len() as f64 * CROP_FRACTION) as usize;
    let keep = samples.len().saturating_sub(drop);
    for &x in &samples[..keep] {
        t.push(class, x);
    }
    keep
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
