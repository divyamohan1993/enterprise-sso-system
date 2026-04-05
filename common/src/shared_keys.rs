//! Shared key loading for inter-service communication.
//!
//! All services MUST use the same SHARD HMAC key and receipt signing key
//! to communicate. Keys are loaded via the sealed key infrastructure
//! which requires encrypted env vars (sealed keys). Plaintext keys are
//! always rejected — there is only production mode.
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

/// Load the shared SHARD HMAC key from sealed environment.
/// All services must use the SAME key for SHARD message authentication.
/// Requires `SHARD_HMAC_KEY_SEALED` (encrypted). No fallbacks.
pub fn load_shard_hmac_key() -> SharedHmacKey {
    SharedHmacKey(crate::sealed_keys::load_shard_hmac_key_sealed())
}

/// Load the shared receipt signing key from sealed or raw environment.
/// OPAQUE and TSS must use the SAME key for receipt verification.
/// In production, requires `RECEIPT_SIGNING_KEY_SEALED` (encrypted).
pub fn load_receipt_signing_key() -> ReceiptSigningKey {
    ReceiptSigningKey(crate::sealed_keys::load_receipt_signing_key_sealed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_hmac_key_zeroizes_on_drop() {
        // Create a key with known non-zero bytes.
        let key_ptr: *const [u8; 64];
        {
            let key = SharedHmacKey([0xAB; 64]);
            key_ptr = &key.0 as *const [u8; 64];
            // Key is alive here.
            assert_eq!(key.0[0], 0xAB);
        }
        // After drop, reading the raw memory is UB in the general case,
        // but we can at least verify the type implements ZeroizeOnDrop
        // by checking the trait bound at compile time.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SharedHmacKey>();
        let _ = key_ptr; // suppress unused warning
    }

    #[test]
    fn receipt_signing_key_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ReceiptSigningKey>();
    }

    #[test]
    fn shared_hmac_key_holds_64_bytes() {
        let data = [0x42u8; 64];
        let key = SharedHmacKey(data);
        assert_eq!(key.0.len(), 64);
        assert_eq!(key.0[0], 0x42);
        assert_eq!(key.0[63], 0x42);
    }

    #[test]
    fn receipt_signing_key_holds_64_bytes() {
        let data = [0xFF; 64];
        let key = ReceiptSigningKey(data);
        assert_eq!(key.0.len(), 64);
        assert_eq!(key.0[0], 0xFF);
        assert_eq!(key.0[63], 0xFF);
    }

    #[test]
    fn shared_hmac_key_implements_zeroize() {
        use zeroize::Zeroize;
        let mut key = SharedHmacKey([0xCC; 64]);
        key.zeroize();
        assert_eq!(key.0, [0u8; 64], "zeroize must clear all bytes to zero");
    }

    #[test]
    fn receipt_signing_key_implements_zeroize() {
        use zeroize::Zeroize;
        let mut key = ReceiptSigningKey([0xDD; 64]);
        key.zeroize();
        assert_eq!(key.0, [0u8; 64], "zeroize must clear all bytes to zero");
    }
}
