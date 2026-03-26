//! Shared key loading for inter-service communication.
//!
//! All services MUST use the same SHARD HMAC key and receipt signing key
//! to communicate. Keys are loaded via the sealed key infrastructure
//! which supports encrypted env vars (sealed keys) in production.
//!
//! In production mode (`MILNET_PRODUCTION=1`), plaintext keys are rejected.
//!
//! Key material is wrapped in types that implement `ZeroizeOnDrop` so that
//! memory is securely erased when the key goes out of scope — even on panic
//! unwind paths.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wrapper for the shared SHARD HMAC key that securely zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedHmacKey(pub [u8; 64]);

/// Wrapper for the shared receipt signing key that securely zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ReceiptSigningKey(pub [u8; 64]);

/// Load the shared SHARD HMAC key from sealed or raw environment.
/// All services must use the SAME key for SHARD message authentication.
/// In production, requires `SHARD_HMAC_KEY_SEALED` (encrypted).
/// Falls back to a deterministic dev key if neither is set (dev only).
pub fn load_shard_hmac_key() -> SharedHmacKey {
    SharedHmacKey(crate::sealed_keys::load_shard_hmac_key_sealed())
}

/// Load the shared receipt signing key from sealed or raw environment.
/// OPAQUE and TSS must use the SAME key for receipt verification.
/// In production, requires `RECEIPT_SIGNING_KEY_SEALED` (encrypted).
pub fn load_receipt_signing_key() -> ReceiptSigningKey {
    ReceiptSigningKey(crate::sealed_keys::load_receipt_signing_key_sealed())
}
