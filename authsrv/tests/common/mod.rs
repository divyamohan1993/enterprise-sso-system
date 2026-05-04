//! Shared bootstrap for integration tests.
//!
//! Each test binary calls `app()` to build a router with the test fixture
//! state.  The DRBG is initialised once per process via `OnceLock`, so
//! subsequent calls are no-ops.

use authsrv::{ensure_drbg_init, router, test_state, AsState};
use std::sync::Arc;

#[allow(dead_code)]
pub fn app() -> (axum::Router, Arc<AsState>) {
    ensure_drbg_init();
    let s = test_state();
    (router().with_state(s.clone()), s)
}

#[allow(dead_code)]
pub fn audit_drain_count() -> usize {
    authsrv::drain_audit_count()
}
