#![forbid(unsafe_code)]
//! milnet-crypto: Cryptographic primitives wrapper for the MILNET SSO system.
//!
//! Provides hash functions (SHA-2, SHA-3, BLAKE3), HKDF key derivation,
//! HMAC message authentication, and constant-time comparison utilities.

pub mod ct;
pub mod entropy;
pub mod receipts;
pub mod threshold;
pub mod xwing;
