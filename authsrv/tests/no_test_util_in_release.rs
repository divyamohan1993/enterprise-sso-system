#![cfg(feature = "test-util")]

//! D-19: `pub fn test_state` and `pub fn pkce_pair` MUST NOT be reachable
//! from a production-only build.  This test verifies the symbols are
//! exposed under `--features test-util`, and documents that under
//! `--no-default-features --features production` the `#[cfg(any(test,
//! feature = "test-util"))]` attribute on `lib.rs:test_state` and
//! `lib.rs:pkce_pair` removes them from the public API.
//!
//! Hard verification command:
//!   cargo build -p authsrv --no-default-features --features production
//! followed by:
//!   cargo doc -p authsrv --no-default-features --features production --no-deps
//! The generated rustdoc must NOT list `test_state` / `pkce_pair`.

#[test]
fn test_util_feature_enabled_exposes_helpers() {
    // Compile-only check: these symbols MUST resolve when test-util is on.
    let _: fn() -> std::sync::Arc<authsrv::AsState> = authsrv::test_state;
    let _: fn() -> (String, String) = authsrv::pkce_pair;
    let _: &str = authsrv::TEST_SESSION_HEADER;
    let _: &str = authsrv::TEST_CLIENT_ID;
    let _: &str = authsrv::TEST_CLIENT_SECRET;
}
