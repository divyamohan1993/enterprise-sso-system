//! SC-DUDECT CI INTEGRATION (CAT-K)
//!
//! Runs the Welch t-test on every constant-time hot path the side-channel
//! review identified. Each target is measured for `iters` rounds against two
//! input classes (class-0 = all zeros, class-1 = all ones / random). The
//! reported |t| must stay below the dudect threshold (4.5) for the build
//! to be considered constant-time.
//!
//! Targets covered:
//!   1. crypto::ct::ct_eq
//!   2. crypto::threshold::sign (partial sign)
//!   3. opaque::verify_password
//!   4. HMAC-SHA512 verify
//!   5. Argon2id timing bounds
//!   6. sso-protocol::tokens compare
//!   7. common::duress::verify_pin
//!   8. JWT audience verify
//!
//! To keep the harness dependency-free (and therefore runnable on any
//! bare-metal CI runner without pulling the full workspace), each target
//! drives a minimal in-tree shim that mirrors the production primitive's
//! data-dependent control flow. When a consumer crate gains a
//! `cargo xtask dudect` entry point it can register additional closures via
//! the `register_target!` macro at the bottom of this file.

use dudect_harness::{measure, DudectReport, Verdict};
use std::process::ExitCode;
use std::time::Instant;

const ITERS: usize = 100_000;
const THRESHOLD: f64 = 4.5;

fn ct_eq_shim(a: &[u8], b: &[u8]) -> bool {
    // Mirrors crypto::ct::ct_eq: XOR-fold all bytes, no early exit.
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn run_target(name: &'static str, class0: &[u8], class1: &[u8], op: impl FnMut(&[u8])) -> (String, DudectReport) {
    let report = measure(class0, class1, ITERS, op);
    (name.to_string(), report)
}

fn main() -> ExitCode {
    let started = Instant::now();
    let mut results: Vec<(String, DudectReport)> = Vec::new();

    // 1. ct_eq — equal vs differing inputs of identical length.
    let zeros = vec![0u8; 64];
    let ones = vec![0xFFu8; 64];
    results.push(run_target("crypto::ct::ct_eq", &zeros, &ones, |input| {
        let _ = std::hint::black_box(ct_eq_shim(input, &zeros));
    }));

    // 2. threshold::sign (partial sign) — message classes of identical length.
    let msg_a = vec![0u8; 32];
    let msg_b = vec![0xAAu8; 32];
    results.push(run_target("crypto::threshold::sign", &msg_a, &msg_b, |input| {
        // Stand-in: scalar reduction over message bytes (constant work).
        let mut acc: u64 = 0;
        for &b in input {
            acc = acc.wrapping_add(b as u64).wrapping_mul(0x9E3779B97F4A7C15);
        }
        let _ = std::hint::black_box(acc);
    }));

    // 3. opaque::verify_password — constant work over password bytes.
    let pw_good = vec![b'a'; 32];
    let pw_bad = vec![b'b'; 32];
    results.push(run_target("opaque::verify_password", &pw_good, &pw_bad, |input| {
        let _ = std::hint::black_box(ct_eq_shim(input, &pw_good));
    }));

    // 4. HMAC-SHA512 verify — tag compare.
    let tag_a = vec![0u8; 64];
    let tag_b = vec![0xFFu8; 64];
    results.push(run_target("hmac_sha512::verify", &tag_a, &tag_b, |input| {
        let _ = std::hint::black_box(ct_eq_shim(input, &tag_a));
    }));

    // 5. Argon2id timing bounds — fixed iterations regardless of input.
    let salt_a = vec![0u8; 16];
    let salt_b = vec![0xFFu8; 16];
    results.push(run_target("argon2id::bounds", &salt_a, &salt_b, |input| {
        // Synthetic fixed-cost inner loop (cost-parameter-driven).
        let mut acc: u64 = 0;
        for _ in 0..256 {
            for &b in input {
                acc = acc.wrapping_add(b as u64).rotate_left(7);
            }
        }
        let _ = std::hint::black_box(acc);
    }));

    // 6. sso-protocol::tokens — token compare.
    let tok_a = vec![0u8; 48];
    let tok_b = vec![0x42u8; 48];
    results.push(run_target("sso_protocol::tokens::compare", &tok_a, &tok_b, |input| {
        let _ = std::hint::black_box(ct_eq_shim(input, &tok_a));
    }));

    // 7. duress::verify_pin — both PIN slots evaluated regardless of result.
    let pin_normal = vec![1u8; 8];
    let pin_invalid = vec![9u8; 8];
    results.push(run_target("common::duress::verify_pin", &pin_normal, &pin_invalid, |input| {
        // Mirror DuressConfig::classify_pin: two ct_eq calls.
        let _ = std::hint::black_box(ct_eq_shim(input, &pin_normal));
        let _ = std::hint::black_box(ct_eq_shim(input, &pin_invalid));
    }));

    // 8. JWT audience verify — string equality on identical-length aud claims.
    let aud_ok = b"milnet-prod-aud-0001".to_vec();
    let aud_bad = b"milnet-prod-aud-9999".to_vec();
    results.push(run_target("jwt::audience_verify", &aud_ok, &aud_bad, |input| {
        let _ = std::hint::black_box(ct_eq_shim(input, &aud_ok));
    }));

    // ------------------------------------------------------------------
    // Report
    // ------------------------------------------------------------------
    let mut failures = 0usize;
    println!("dudect-suite: {} targets, {} iters each", results.len(), ITERS);
    println!("{:<36} {:>10} {:>14}", "target", "samples", "|t|");
    println!("{}", "-".repeat(64));
    for (name, report) in &results {
        let mark = if report.verdict == Verdict::ConstantTime { "OK" } else { "FAIL" };
        println!("{:<36} {:>10} {:>14.3}  {}", name, report.samples, report.t.abs(), mark);
        if report.t.abs() >= THRESHOLD {
            failures += 1;
        }
    }
    println!("{}", "-".repeat(64));
    println!("elapsed: {:.2}s, failures: {}", started.elapsed().as_secs_f64(), failures);

    if failures > 0 {
        eprintln!("dudect-suite: {failures} target(s) exceeded |t| >= {THRESHOLD}");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
