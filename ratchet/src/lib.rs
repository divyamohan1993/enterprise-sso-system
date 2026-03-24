//! ratchet: Forward-secret session ratchet with HKDF-SHA512 chains.
//!
//! Uses unsafe code for memory-locked chain key storage (mlock/munlock/madvise)
//! and canary-based buffer overflow detection.

pub mod chain;
pub mod manager;
