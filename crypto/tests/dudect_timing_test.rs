//! I5 [HIGH] Statistical constant-time test (Welch t-test, dudect-style).
//!
//! Hand-rolled (no extra crate dependency) to avoid pulling unverified
//! dev-deps. Collects N samples from two populations (matching vs differing
//! inputs) and asserts |t| stays under the dudect threshold of 4.5.

use crypto::ct::{ct_eq, ct_eq_32};
use std::time::Instant;

const SAMPLES_PER_CLASS: usize = 50_000;
const T_THRESHOLD: f64 = 4.5;

fn measure<F: FnMut() -> bool>(mut f: F, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        let _ = std::hint::black_box(f());
        let dt = start.elapsed().as_nanos() as f64;
        out.push(dt);
    }
    out
}

/// Welch's t statistic over two independent samples.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let na = a.len() as f64;
    let nb = b.len() as f64;
    let ma = a.iter().sum::<f64>() / na;
    let mb = b.iter().sum::<f64>() / nb;
    let va = a.iter().map(|x| (x - ma).powi(2)).sum::<f64>() / (na - 1.0);
    let vb = b.iter().map(|x| (x - mb).powi(2)).sum::<f64>() / (nb - 1.0);
    let denom = (va / na + vb / nb).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (ma - mb) / denom
    }
}

/// Crop the worst 5% outliers — mitigates GC / scheduler jitter the way
/// dudect does in its "percentile" mode.
fn crop(mut v: Vec<f64>) -> Vec<f64> {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let drop_n = v.len() / 20;
    v.drain(v.len() - drop_n..);
    v
}

#[test]
#[ignore = "long-running statistical test — run on C2 VM with `cargo test --release -- --ignored`"]
fn ct_eq_is_constant_time_welch() {
    let secret = [0xAAu8; 32];
    let same = [0xAAu8; 32];
    let diff_first = {
        let mut x = [0xAAu8; 32];
        x[0] = 0x55;
        x
    };
    let diff_last = {
        let mut x = [0xAAu8; 32];
        x[31] = 0x55;
        x
    };

    // Class A: equal inputs. Class B: differ at first byte.
    let class_a = measure(|| ct_eq_32(&secret, &same), SAMPLES_PER_CLASS);
    let class_b = measure(|| ct_eq_32(&secret, &diff_first), SAMPLES_PER_CLASS);
    let class_c = measure(|| ct_eq_32(&secret, &diff_last), SAMPLES_PER_CLASS);

    let t_ab = welch_t(&crop(class_a.clone()), &crop(class_b));
    let t_ac = welch_t(&crop(class_a), &crop(class_c));

    assert!(
        t_ab.abs() < T_THRESHOLD,
        "ct_eq_32 leaks first-byte timing: t={t_ab:.3}"
    );
    assert!(
        t_ac.abs() < T_THRESHOLD,
        "ct_eq_32 leaks last-byte timing: t={t_ac:.3}"
    );
}

#[test]
#[ignore = "long-running statistical test — run on C2 VM with `cargo test --release -- --ignored`"]
fn ct_eq_variable_length_constant_time() {
    let secret = vec![0xAAu8; 256];
    let same = vec![0xAAu8; 256];
    let early_diff = {
        let mut x = vec![0xAAu8; 256];
        x[1] = 0x55;
        x
    };
    let late_diff = {
        let mut x = vec![0xAAu8; 256];
        x[255] = 0x55;
        x
    };

    let class_a = crop(measure(|| ct_eq(&secret, &same), SAMPLES_PER_CLASS));
    let class_b = crop(measure(|| ct_eq(&secret, &early_diff), SAMPLES_PER_CLASS));
    let class_c = crop(measure(|| ct_eq(&secret, &late_diff), SAMPLES_PER_CLASS));

    let t_ab = welch_t(&class_a, &class_b);
    let t_bc = welch_t(&class_b, &class_c);
    assert!(t_ab.abs() < T_THRESHOLD, "ct_eq early-diff leak: t={t_ab:.3}");
    assert!(t_bc.abs() < T_THRESHOLD, "ct_eq early-vs-late leak: t={t_bc:.3}");
}
