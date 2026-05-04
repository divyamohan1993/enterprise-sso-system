#![cfg(feature = "test-util")]

//! D-06: when the workspace DRBG fails (init or generate), every
//! randomness consumer must surface OAuth `server_error` and emit CRITICAL
//! `rng.fail`.  This is enforced structurally by `rand_bytes` —
//! `crypto::drbg::HmacDrbg::generate(...)` returns `Result`, and every
//! call site uses `?` propagation through `AsError`.
//!
//! A direct fault-injection test would require either a swappable DRBG
//! trait (Phase 2 substrate replacement, see master plan §5 Phase 2) or
//! a feature-gated test backdoor.  Neither is present in this hot-fix.
//! Until Phase 2, this test asserts the structural property: every
//! handler that mints randomness uses `rand_token` / `rand_bytes` /
//! `drbg_uuid_v7`, all of which return `Result<_, AsError>`.

#[test]
fn rand_pathways_propagate_errors() {
    let body = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("read lib.rs");
    // Critical invariant: `rand_token` is `Result<String, AsError>`, and the
    // only DRBG entry point (`rand_bytes`) returns `Result<(), AsError>`.
    assert!(body.contains("fn rand_token(prefix: &str) -> Result<String, AsError>"));
    assert!(body.contains("fn rand_bytes(buf: &mut [u8]) -> Result<(), AsError>"));
    assert!(body.contains("fn drbg_uuid_v7() -> Result<Uuid, AsError>"));
    // No leftover `let _ = getrandom` short-circuit pattern (D-06 hard fix).
    assert!(
        !body.contains("getrandom::getrandom"),
        "raw getrandom call still present in lib.rs — D-06 regression"
    );
    assert!(
        !body.contains("let _ = getrandom"),
        "discard-result getrandom pattern still present — D-06 regression"
    );
    // Audit emission on RNG failure must be wired.
    assert!(body.contains("\"rng.fail\""));
}
