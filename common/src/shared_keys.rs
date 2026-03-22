//! Shared key loading for inter-service communication.
//!
//! All services MUST use the same SHARD HMAC key and receipt signing key
//! to communicate. Keys are loaded via the sealed key infrastructure
//! which supports encrypted env vars (sealed keys) in production.
//!
//! In production mode (`MILNET_PRODUCTION=1`), plaintext keys are rejected.

/// Load the shared SHARD HMAC key from sealed or raw environment.
/// All services must use the SAME key for SHARD message authentication.
/// In production, requires `SHARD_HMAC_KEY_SEALED` (encrypted).
/// Falls back to a deterministic dev key if neither is set (dev only).
pub fn load_shard_hmac_key() -> [u8; 64] {
    crate::sealed_keys::load_shard_hmac_key_sealed()
}

/// Load the shared receipt signing key from sealed or raw environment.
/// OPAQUE and TSS must use the SAME key for receipt verification.
/// In production, requires `RECEIPT_SIGNING_KEY_SEALED` (encrypted).
pub fn load_receipt_signing_key() -> [u8; 64] {
    crate::sealed_keys::load_receipt_signing_key_sealed()
}
