#![forbid(unsafe_code)]
//! opaque: T-OPAQUE Password Service.
//!
//! Implements real OPAQUE (RFC 9497) password-authenticated key exchange using
//! the opaque-ke crate. The server NEVER sees the plaintext password — not
//! during registration, not during login.

pub mod messages;
pub mod opaque_impl;
pub mod rate_limit;
pub mod service;
pub mod store;
pub mod threshold;
