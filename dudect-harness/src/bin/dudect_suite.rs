//! SC-DUDECT CI INTEGRATION (CAT-K)
//!
//! Runs the Welch t-test on every constant-time hot path the side-channel
//! review identified. Each target is measured for `iters` rounds against two
//! input classes: data-dependent primitives use the dudect-paper fixed-vs-
//! random configuration (`measure_fixed_vs_random`), credential checks use a
//! valid-vs-invalid two-class configuration (`measure`). The reported |t|
//! must stay below the dudect threshold (4.5) for the build to be
//! considered constant-time.
//!
//! Every target below calls the **real production function** — no in-tree
//! shims. A shim is constant-time by construction and would make the suite
//! tautologically green, giving the operator false assurance and masking any
//! future regression. The production crates are therefore regular
//! dependencies of this binary (see `Cargo.toml`).
//!
//! Targets covered:
//!   1. `crypto::ct::ct_eq`                    — constant-time byte compare
//!   2. `crypto::threshold::verify_group_signature` — FROST group-sig verify
//!   3. `opaque::CredentialStore::verify_password`  — OPAQUE OPRF + Argon2id
//!   4. `crypto::receipts::verify_receipt_signature` — HMAC-SHA512 tag compare
//!   5. `crypto::kdf::Argon2idKsf::stretch`     — Argon2id key stretching
//!   6. `sso_protocol::pkce::verify_pkce`       — PKCE S256 constant-time compare
//!   7. `common::duress::DuressConfig::verify_pin` — duress PIN hash-and-compare
//!   8. `sso_protocol::tokens::verify_id_token_with_audience` — JWT aud verify

use crypto::kdf::KeyStretchingFunction;
use dudect_harness::{measure, measure_fixed_vs_random, DudectReport, Verdict};
use std::process::ExitCode;
use std::time::Instant;

const ITERS: usize = 100_000;
const THRESHOLD: f64 = 4.5;

/// Heavier targets (real Argon2id at 96 MiB / OPAQUE OPRF / ML-DSA-87 sign +
/// verify) cost milliseconds per call — orders of magnitude more than a
/// 64-byte `ct_eq`. Running them 100k times would take tens of minutes on CI.
/// 2_000 rounds keeps each heavy target under a few minutes while still
/// giving the Welch t-test ~1_000 samples per class. This is a deliberate
/// power-vs-walltime tradeoff; adaptive iteration counts (run until |t|
/// stabilises) would be the stronger long-term fix.
const ITERS_HEAVY: usize = 2_000;

fn run_target(
    name: &'static str,
    class0: &[u8],
    class1: &[u8],
    iters: usize,
    op: impl FnMut(&[u8]),
) -> (String, DudectReport) {
    let report = measure(class0, class1, iters, op);
    (name.to_string(), report)
}

fn main() -> ExitCode {
    let started = Instant::now();
    let mut results: Vec<(String, DudectReport)> = Vec::new();

    // ------------------------------------------------------------------
    // 1. crypto::ct::ct_eq — fixed-vs-random: class-0 always compares the
    //    reference against itself (a match), class-1 against a fresh random
    //    64-byte buffer. A constant-time compare must not separate the two.
    // ------------------------------------------------------------------
    {
        let reference = vec![0u8; 64];
        let report = measure_fixed_vs_random(&reference, ITERS, |input| {
            let _ = std::hint::black_box(crypto::ct::ct_eq(
                std::hint::black_box(input),
                std::hint::black_box(&reference),
            ));
        });
        results.push(("crypto::ct::ct_eq".to_string(), report));
    }

    // ------------------------------------------------------------------
    // 2. crypto::threshold::verify_group_signature — FROST verify over a
    //    real DKG-generated group. The per-iteration secret is the message;
    //    the signature is fixed, so a matching vs mismatching message must
    //    not be distinguishable by timing.
    // ------------------------------------------------------------------
    {
        let dkg = crypto::threshold::dkg_distributed(3, 2);
        let mut shares = dkg.shares;
        let group = dkg.group;
        let msg_signed = vec![0u8; 32];
        let signature =
            crypto::threshold::threshold_sign(&mut shares, &group, &msg_signed, 2)
                .expect("threshold sign for dudect fixture");
        let msg_other = vec![0xAAu8; 32];
        results.push(run_target(
            "crypto::threshold::verify_group_signature",
            &msg_signed,
            &msg_other,
            ITERS_HEAVY,
            |input| {
                let _ = std::hint::black_box(crypto::threshold::verify_group_signature(
                    &group,
                    std::hint::black_box(input),
                    &signature,
                ));
            },
        ));
    }

    // ------------------------------------------------------------------
    // 3. opaque::CredentialStore::verify_password — real OPAQUE OPRF +
    //    Argon2id. class-0 = the correct password, class-1 = a wrong one of
    //    identical length. The OPAQUE design fakes a registration for an
    //    unknown user so timing must not separate the two classes.
    // ------------------------------------------------------------------
    let pw_good = vec![b'a'; 32];
    let pw_bad = vec![b'b'; 32];
    {
        let mut store = opaque::store::CredentialStore::new();
        store
            .register_with_password("dudect-user", &pw_good)
            .expect("register dudect fixture user");
        results.push(run_target(
            "opaque::verify_password",
            &pw_good,
            &pw_bad,
            ITERS_HEAVY,
            |input| {
                let _ = std::hint::black_box(
                    store.verify_password("dudect-user", std::hint::black_box(input)),
                );
            },
        ));
    }

    // ------------------------------------------------------------------
    // 4. crypto::receipts::verify_receipt_signature — HMAC-SHA512 tag
    //    compare. class-0 carries the correct signature, class-1 a wrong tag
    //    of identical length; both run the full MAC recompute + ct compare.
    // ------------------------------------------------------------------
    {
        use common::types::Receipt;
        let signing_key = [0x5Au8; 64];
        let mut base = Receipt {
            ceremony_session_id: [1u8; 32],
            step_id: 1,
            prev_receipt_hash: [0u8; 64],
            user_id: uuid::Uuid::nil(),
            dpop_key_hash: [0u8; 64],
            timestamp: 1_700_000_000,
            nonce: [2u8; 32],
            signature: Vec::new(),
            ttl_seconds: 60,
        };
        crypto::receipts::sign_receipt(&mut base, &signing_key)
            .expect("sign dudect receipt fixture");
        let good_sig = base.signature.clone();
        let bad_sig = vec![0u8; good_sig.len()];
        // class bytes select which signature to splice in before verifying.
        let class_good = vec![0u8; 1];
        let class_bad = vec![1u8; 1];
        results.push(run_target(
            "crypto::receipts::verify_receipt_signature",
            &class_good,
            &class_bad,
            ITERS,
            |input| {
                let mut receipt = base.clone();
                receipt.signature = if input.first() == Some(&0) {
                    good_sig.clone()
                } else {
                    bad_sig.clone()
                };
                let _ = std::hint::black_box(crypto::receipts::verify_receipt_signature(
                    &receipt,
                    &signing_key,
                ));
            },
        ));
    }

    // ------------------------------------------------------------------
    // 5. crypto::kdf::Argon2idKsf::stretch — real Argon2id. Argon2id is a
    //    data-independent memory-hard function: a fixed password and a fresh
    //    random one (same length) must take indistinguishable time.
    // ------------------------------------------------------------------
    {
        let ksf = crypto::kdf::Argon2idKsf;
        let salt = [0u8; 16];
        let pw_fixed = vec![0u8; 32];
        let report = measure_fixed_vs_random(&pw_fixed, ITERS_HEAVY, |input| {
            let _ = std::hint::black_box(ksf.stretch(std::hint::black_box(input), &salt));
        });
        results.push(("crypto::kdf::argon2id".to_string(), report));
    }

    // ------------------------------------------------------------------
    // 6. sso_protocol::pkce::verify_pkce — PKCE S256 constant-time compare.
    //    class-0 is the verifier whose challenge matches; class-1 is a
    //    distinct verifier of identical length. Both run the SHA-256 +
    //    constant-time fold path.
    // ------------------------------------------------------------------
    {
        // RFC 7636 verifiers must be 43-128 chars; use a fixed 64-char base.
        let verifier_match = "A".repeat(64);
        let verifier_other = "B".repeat(64);
        let challenge = sso_protocol::pkce::generate_challenge(&verifier_match);
        results.push(run_target(
            "sso_protocol::pkce::verify_pkce",
            verifier_match.as_bytes(),
            verifier_other.as_bytes(),
            ITERS,
            |input| {
                let verifier = std::str::from_utf8(input).unwrap_or("");
                let _ = std::hint::black_box(sso_protocol::pkce::verify_pkce(
                    std::hint::black_box(verifier),
                    &challenge,
                ));
            },
        ));
    }

    // ------------------------------------------------------------------
    // 7. common::duress::DuressConfig::verify_pin — hashes the candidate PIN
    //    (HKDF-SHA512) then constant-time compares against both the normal
    //    and duress hashes. class-0 = the normal PIN, class-1 = an invalid
    //    PIN of identical length.
    // ------------------------------------------------------------------
    {
        use common::duress::DuressConfig;
        let normal_pin = b"112233";
        let duress_pin = b"445566";
        let cfg = DuressConfig::new(uuid::Uuid::nil(), normal_pin, duress_pin)
            .expect("duress fixture config");
        let pin_invalid = b"999999";
        results.push(run_target(
            "common::duress::verify_pin",
            normal_pin,
            pin_invalid,
            ITERS,
            |input| {
                let _ = std::hint::black_box(cfg.verify_pin(std::hint::black_box(input)));
            },
        ));
    }

    // ------------------------------------------------------------------
    // 8. sso_protocol::tokens::verify_id_token_with_audience — the JWT
    //    verifier path. class-0 carries the correct audience, class-1 a
    //    wrong audience of identical length; the audience check uses
    //    crypto::ct::ct_eq internally.
    //
    //    The verifier enforces single-use JTI replay protection, so a token
    //    can only be verified once — re-verifying a fixed token would short
    //    out at the JTI check and never reach the audience comparison. We
    //    therefore mint a fresh token (real `create_id_token`, fresh random
    //    JTI) per iteration with the `aud` claim taken from the `client_id`
    //    argument. The mint cost is identical across both classes, so any
    //    class-dependent timing originates in the audience compare.
    // ------------------------------------------------------------------
    {
        let signing_key = std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(sso_protocol::tokens::OidcSigningKey::generate)
            .expect("spawn keygen thread")
            .join()
            .expect("join keygen thread");
        let aud_ok = "milnet-prod-aud-0001";
        let aud_bad = "milnet-prod-aud-9999";
        let user_id = uuid::Uuid::nil();
        let vk = signing_key.verifying_key();
        // class bytes select which audience the freshly minted token carries.
        let class_ok = vec![0u8; 1];
        let class_bad = vec![1u8; 1];
        results.push(run_target(
            "jwt::audience_verify",
            &class_ok,
            &class_bad,
            ITERS_HEAVY,
            |input| {
                let aud = if input.first() == Some(&0) { aud_ok } else { aud_bad };
                let token = sso_protocol::tokens::create_id_token(
                    "milnet", &user_id, aud, None, &signing_key,
                );
                let _ = std::hint::black_box(
                    sso_protocol::tokens::verify_id_token_with_audience(
                        std::hint::black_box(&token),
                        vk,
                        aud_ok,
                        true,
                    ),
                );
            },
        ));
    }

    // ------------------------------------------------------------------
    // Report
    // ------------------------------------------------------------------
    let mut failures = 0usize;
    println!("dudect-suite: {} targets", results.len());
    println!("{:<44} {:>10} {:>14}", "target", "samples", "|t|");
    println!("{}", "-".repeat(72));
    for (name, report) in &results {
        let mark = if report.verdict == Verdict::ConstantTime { "OK" } else { "FAIL" };
        println!("{:<44} {:>10} {:>14.3}  {}", name, report.samples, report.t.abs(), mark);
        if report.t.abs() >= THRESHOLD {
            failures += 1;
        }
    }
    println!("{}", "-".repeat(72));
    println!("elapsed: {:.2}s, failures: {}", started.elapsed().as_secs_f64(), failures);

    if failures > 0 {
        eprintln!("dudect-suite: {failures} target(s) exceeded |t| >= {THRESHOLD}");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
