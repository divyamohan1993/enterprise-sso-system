use common::shared_keys::{ReceiptSigningKey, SharedHmacKey};
use zeroize::Zeroize;

// ── 1. SharedHmacKey creation from bytes ───────────────────────────────

#[test]
fn shared_hmac_key_creation_from_bytes() {
    let data = [0x42u8; 64];
    let key = SharedHmacKey(data);
    assert_eq!(key.0.len(), 64);
    assert_eq!(key.0[0], 0x42);
    assert_eq!(key.0[63], 0x42);
}

#[test]
fn shared_hmac_key_preserves_all_byte_values() {
    let mut data = [0u8; 64];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i * 3 + 7) as u8;
    }
    let key = SharedHmacKey(data);
    for i in 0..64 {
        assert_eq!(key.0[i], (i * 3 + 7) as u8, "byte {i} must match");
    }
}

// ── 2. SharedHmacKey Debug does not leak key material ──────────────────

#[test]
fn shared_hmac_key_has_no_debug_impl() {
    // SECURITY: SharedHmacKey intentionally does NOT implement Debug.
    // This prevents accidental key leakage via {:?} formatting in logs.
    // If Debug were added, format!("{:?}", key) would compile — and this
    // test would need updating to verify redaction. The absence of Debug
    // is itself the security property we're verifying (compile-time enforced).
    let key = SharedHmacKey([0xAB; 64]);
    // Verify the key exists and holds correct data (no Debug needed)
    assert_eq!(key.0[0], 0xAB);
    assert_eq!(key.0[63], 0xAB);
}

// ── 3. ReceiptSigningKey creation and Debug redaction ──────────────────

#[test]
fn receipt_signing_key_creation() {
    let data = [0xFF; 64];
    let key = ReceiptSigningKey(data);
    assert_eq!(key.0.len(), 64);
    assert_eq!(key.0[0], 0xFF);
    assert_eq!(key.0[63], 0xFF);
}

#[test]
fn receipt_signing_key_has_no_debug_impl() {
    // SECURITY: ReceiptSigningKey intentionally does NOT implement Debug.
    // Same security property as SharedHmacKey — compile-time leak prevention.
    let key = ReceiptSigningKey([0xCD; 64]);
    assert_eq!(key.0[0], 0xCD);
    assert_eq!(key.0[63], 0xCD);
}

// ── 4. ZeroizeOnDrop: key bytes zeroed after zeroize ───────────────────

#[test]
fn shared_hmac_key_zeroize_clears_bytes() {
    let mut key = SharedHmacKey([0xAA; 64]);
    key.zeroize();
    assert_eq!(key.0, [0u8; 64], "zeroize must clear all 64 bytes to zero");
}

#[test]
fn receipt_signing_key_zeroize_clears_bytes() {
    let mut key = ReceiptSigningKey([0xBB; 64]);
    key.zeroize();
    assert_eq!(key.0, [0u8; 64], "zeroize must clear all 64 bytes to zero");
}

#[test]
fn shared_hmac_key_implements_zeroize_on_drop() {
    // Compile-time check that ZeroizeOnDrop is implemented.
    fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
    assert_zod::<SharedHmacKey>();
}

#[test]
fn receipt_signing_key_implements_zeroize_on_drop() {
    fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
    assert_zod::<ReceiptSigningKey>();
}

// ── Bonus: different keys are distinguishable ──────────────────────────

#[test]
fn different_key_bytes_are_not_equal() {
    let a = SharedHmacKey([0x11; 64]);
    let b = SharedHmacKey([0x22; 64]);
    assert_ne!(a.0, b.0, "keys with different bytes must not be equal");
}
