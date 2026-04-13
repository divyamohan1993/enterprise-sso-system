#![forbid(unsafe_code)]
//! fido: FIDO2/WebAuthn support for the MILNET SSO system.
//!
//! Supports platform authenticators (Windows Hello, Touch ID) and
//! cross-platform authenticators (YubiKey, other security keys).

pub mod authentication;
pub mod policy;
pub mod registration;
pub mod types;
pub mod verification;
