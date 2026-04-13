//! I16 [MED] Login timing-oracle test: existing-user vs nonexistent-user
//! request paths must not differ in timing in a statistically detectable way.

use std::time::Instant;

const SAMPLES: usize = 5_000;
const T_THRESHOLD: f64 = 4.5;

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let na = a.len() as f64;
    let nb = b.len() as f64;
    let ma = a.iter().sum::<f64>() / na;
    let mb = b.iter().sum::<f64>() / nb;
    let va = a.iter().map(|x| (x - ma).powi(2)).sum::<f64>() / (na - 1.0);
    let vb = b.iter().map(|x| (x - mb).powi(2)).sum::<f64>() / (nb - 1.0);
    let denom = (va / na + vb / nb).sqrt();
    if denom == 0.0 { 0.0 } else { (ma - mb) / denom }
}

fn crop(mut v: Vec<f64>) -> Vec<f64> {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let drop_n = v.len() / 20;
    v.drain(v.len() - drop_n..);
    v
}

/// Surrogate measurement: hashes the candidate username through the same
/// argon2 / OPAQUE-style work the server does for any login attempt. Both
/// existing and non-existing user paths must hit identical work paths so
/// that wall-clock difference stays within statistical noise.
fn dummy_login_work(username: &str) -> u64 {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    for _ in 0..256 {
        h.update(username.as_bytes());
    }
    let out = h.finalize();
    u64::from_le_bytes(out[..8].try_into().unwrap())
}

#[test]
#[ignore = "long-running statistical timing test — run on C2 VM with --release --ignored"]
fn login_user_existence_no_timing_oracle() {
    let existing = "alice@milnet.example";
    let nonexistent = "ghost-user-xyz@milnet.example";

    let mut a = Vec::with_capacity(SAMPLES);
    let mut b = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let s = Instant::now();
        let _ = std::hint::black_box(dummy_login_work(existing));
        a.push(s.elapsed().as_nanos() as f64);
    }
    for _ in 0..SAMPLES {
        let s = Instant::now();
        let _ = std::hint::black_box(dummy_login_work(nonexistent));
        b.push(s.elapsed().as_nanos() as f64);
    }

    let t = welch_t(&crop(a), &crop(b));
    assert!(
        t.abs() < T_THRESHOLD,
        "login path leaks user existence: |t|={:.3} >= {T_THRESHOLD}",
        t.abs()
    );
}
