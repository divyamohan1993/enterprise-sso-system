#![doc = "STUB: AAL3 CAC/PIV support is NOT implemented. This module provides type stubs only."]
#![doc = "Deploying in AAL3 mode will fail at runtime via a loud panic from init_cac_or_panic()."]
//! CAC/PIV PKCS#11 module — re-exports from `common::cac`.
//!
//! The CAC types live in the `common` crate so that both `crypto` and other
//! crates can use them without circular dependencies. This module simply
//! re-exports everything for callers that depend on `crypto`.
//!
//! # CAT-I STUB NOTICE
//!
//! Real PKCS#11 CAC/PIV hardware authentication (opensc-pkcs11.so loader,
//! piv-auth cert enumeration, signature verification) is NOT implemented in
//! this build. The re-exported types from `common::cac` provide the data
//! shape only. Any deployment that sets `MILNET_REQUIRE_AAL3=1` MUST call
//! [`init_cac_or_panic`] at startup so the process fails fast instead of
//! silently running without AAL3 assurance.

pub use common::cac::*;

/// CAT-I startup gate for AAL3 deployments.
///
/// Call from every service `main()` that might be deployed in AAL3 mode.
/// When `MILNET_REQUIRE_AAL3=1` is set, this panics loudly because the
/// underlying PKCS#11 implementation is a stub. When the env var is unset,
/// this is a silent no-op.
///
/// # Panics
///
/// Panics unconditionally with a CAT-I diagnostic message if
/// `MILNET_REQUIRE_AAL3=1` is set at process start.
pub fn init_cac_or_panic() {
    if std::env::var("MILNET_REQUIRE_AAL3").as_deref() == Ok("1") {
        panic!(
            "MILNET: CAC/PIV AAL3 not implemented — deploying in AAL3 mode \
             is not supported in this build. See crypto/src/cac.rs"
        );
    }
}
