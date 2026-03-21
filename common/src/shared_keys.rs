//! Shared key loading for inter-service communication.
//!
//! All services MUST use the same SHARD HMAC key and receipt signing key
//! to communicate. Keys are loaded from environment variables.
//! In production, these come from a secrets manager or HSM.

/// Load the shared SHARD HMAC key from environment.
/// All services must use the SAME key for SHARD message authentication.
/// Falls back to a deterministic dev key if SHARD_HMAC_KEY is not set.
pub fn load_shard_hmac_key() -> [u8; 64] {
    load_key_from_env("SHARD_HMAC_KEY", b"MILNET-DEV-SHARD-HMAC-KEY-NOT-FOR-PRODUCTION!!!!!")
}

/// Load the shared receipt signing key from environment.
/// OPAQUE and TSS must use the SAME key for receipt verification.
pub fn load_receipt_signing_key() -> [u8; 64] {
    load_key_from_env(
        "RECEIPT_SIGNING_KEY",
        b"MILNET-DEV-RECEIPT-KEY-NOT-FOR-PRODUCTION!!!!!!!!",
    )
}

fn load_key_from_env(var: &str, dev_seed: &[u8]) -> [u8; 64] {
    match std::env::var(var) {
        Ok(hex_str) if hex_str.len() >= 128 => {
            // Parse hex-encoded 64-byte key
            let mut key = [0u8; 64];
            for (i, chunk) in hex_str.as_bytes().chunks(2).take(64).enumerate() {
                let hex = std::str::from_utf8(chunk).unwrap_or("00");
                key[i] = u8::from_str_radix(hex, 16).unwrap_or(0);
            }
            key
        }
        _ => {
            eprintln!(
                "WARNING: {var} not set or invalid. Using deterministic dev key. NOT FOR PRODUCTION."
            );
            // Deterministic dev key from seed — same across all services
            use sha2::{Digest, Sha512};
            let hash = Sha512::digest(dev_seed);
            let mut key = [0u8; 64];
            key.copy_from_slice(&hash);
            key
        }
    }
}
