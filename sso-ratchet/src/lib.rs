#![forbid(unsafe_code)]
//! sso-ratchet: Forward-secret session ratchet with HKDF-SHA512 chains.

pub mod chain;
pub mod manager;
