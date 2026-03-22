#![warn(unsafe_code)]
//! crypto: Cryptographic primitives wrapper for the MILNET SSO system.
//!
//! Provides hash functions (SHA-2, SHA-3, BLAKE3), HKDF key derivation,
//! HMAC message authentication, constant-time comparison, and military-grade
//! hardening primitives:
//! - Envelope encryption (AES-256-GCM) for data at rest
//! - Key seal abstraction (HSM-ready key hierarchy)
//! - Hardened multi-source entropy (NIST SP 800-90B)
//! - Binary/config attestation (BLAKE3 tamper detection)
//!
//! The `memguard` module requires unsafe for mlock/munlock and is excluded
//! from the crate-level `deny(unsafe_code)` via its own module-level allow.

pub mod ct;
pub mod dpop;
pub mod entropy;
pub mod receipts;
pub mod threshold;
pub mod pq_sign;
pub mod xwing;

// ── Military hardening modules ──
pub mod envelope;
pub mod seal;
#[allow(unsafe_code)]
pub mod memguard;
pub mod attest;
pub mod hsm;
pub mod tpm;
