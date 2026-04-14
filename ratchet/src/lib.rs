//! ratchet: Forward-secret session ratchet with HKDF-SHA512 chains.
//!
//! Uses unsafe code for memory-locked chain key storage (mlock/munlock/madvise)
//! and canary-based buffer overflow detection.
//!
//! A2: the chain carries an optional X-Wing PQ puncture mechanism. Every
//! [`chain::PQ_PUNCTURE_INTERVAL`] epochs, a pre-computed X-Wing ciphertext
//! is decapsulated with the session's local X-Wing secret and the resulting
//! shared secret is mixed into the HKDF chain, providing CNSA 2.0 Level 5
//! PQ re-keying independent of the classical ratchet. Bumped to
//! [`chain::PROTOCOL_VERSION`] = 2 when the PQ path was introduced.

pub mod chain;
pub mod manager;

/// A2: re-export the current protocol version for wire-level negotiation.
pub use chain::PROTOCOL_VERSION;
