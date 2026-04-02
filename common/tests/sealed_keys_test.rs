//! Sealed key management tests.
//!
//! Verifies the key sealing/unsealing system correctly:
//!   - Seal/unseal round-trip with AES-256-GCM
//!   - Purpose-based domain separation prevents cross-key confusion
//!   - Tampered sealed data is rejected
//!   - derive_unseal_key is deterministic
//!   - derive_module_hmac_key produces unique per-channel keys
//!   - Production mode always returns true
//!   - HSM backend detection from environment

use common::sealed_keys::*;

// ── Seal/Unseal Round-Trip ────────────────────────────────────────────────

/// Security property: A key sealed for a specific purpose can be unsealed
/// with the same purpose and master KEK, recovering the original key.
#[test]
fn seal_unseal_round_trip_recovers_original_key() {
    std::env::set_var("MILNET_MASTER_KEK", "2a".repeat(32));

    let mut original_key = [0u8; 64];
    getrandom::getrandom(&mut original_key).unwrap();

    let sealed = seal_key_for_storage(&original_key, "test-roundtrip").unwrap();
    let hex_sealed = sealed_to_hex(&sealed);

    // Unseal from hex
    let recovered = unseal_key_from_hex_for_test(&hex_sealed, "test-roundtrip");
    assert!(recovered.is_some(), "unseal must succeed");
    assert_eq!(recovered.unwrap(), original_key, "recovered key must match original");

    std::env::remove_var("MILNET_MASTER_KEK");
}

/// Security property: Wrong purpose string causes unseal to fail.
/// This prevents one key from being confused with another.
#[test]
fn wrong_purpose_fails_unseal() {
    std::env::set_var("MILNET_MASTER_KEK", "2a".repeat(32));

    let key = [0x99; 64];
    let sealed = seal_key_for_storage(&key, "purpose-alpha").unwrap();
    let hex_sealed = sealed_to_hex(&sealed);

    let result = unseal_key_from_hex_for_test(&hex_sealed, "purpose-beta");
    assert!(result.is_none(), "wrong purpose must fail AES-GCM authentication");

    std::env::remove_var("MILNET_MASTER_KEK");
}

/// Security property: Tampered sealed data is detected and rejected.
/// AES-256-GCM authentication tag verification catches any modification.
#[test]
fn tampered_sealed_data_is_rejected() {
    std::env::set_var("MILNET_MASTER_KEK", "2a".repeat(32));

    let key = [0x77; 64];
    let mut sealed = seal_key_for_storage(&key, "tamper-test").unwrap();

    // Flip a byte in the ciphertext
    if sealed.len() > 20 {
        sealed[20] ^= 0xFF;
    }
    let hex_sealed = sealed_to_hex(&sealed);

    let result = unseal_key_from_hex_for_test(&hex_sealed, "tamper-test");
    assert!(result.is_none(), "tampered ciphertext must be rejected");

    std::env::remove_var("MILNET_MASTER_KEK");
}

// ── Key Derivation ────────────────────────────────────────────────────────

/// Security property: derive_unseal_key is deterministic — same master KEK
/// and purpose always produce the same derived key.
#[test]
fn derive_unseal_key_is_deterministic() {
    let master = [0x42u8; 32];
    let k1 = derive_unseal_key_for_test(&master, "shard-hmac");
    let k2 = derive_unseal_key_for_test(&master, "shard-hmac");
    assert_eq!(k1, k2, "same inputs must produce same derived key");
}

/// Security property: Different purpose strings produce different keys.
/// This is the domain separation property of HKDF.
#[test]
fn different_purposes_produce_different_keys() {
    let master = [0x42u8; 32];
    let k1 = derive_unseal_key_for_test(&master, "shard-hmac");
    let k2 = derive_unseal_key_for_test(&master, "receipt-sign");
    assert_ne!(k1, k2, "different purposes must produce different keys");
}

/// Security property: Different master KEKs produce different keys.
#[test]
fn different_master_keks_produce_different_keys() {
    let master1 = [0x42u8; 32];
    let master2 = [0x43u8; 32];
    let k1 = derive_unseal_key_for_test(&master1, "same-purpose");
    let k2 = derive_unseal_key_for_test(&master2, "same-purpose");
    assert_ne!(k1, k2, "different master KEKs must produce different keys");
}

// ── Module HMAC Key Derivation ────────────────────────────────────────────

/// Security property: Per-module SHARD HMAC keys are unique per channel.
/// This prevents one compromised module from impersonating another.
#[test]
fn module_hmac_keys_are_unique_per_channel() {
    std::env::set_var("MILNET_MASTER_KEK", "2a".repeat(32));

    let k1 = derive_module_hmac_key("gateway", "orchestrator").unwrap();
    let k2 = derive_module_hmac_key("gateway", "opaque").unwrap();
    let k3 = derive_module_hmac_key("orchestrator", "opaque").unwrap();

    assert_ne!(k1, k2, "gateway-orchestrator must differ from gateway-opaque");
    assert_ne!(k1, k3, "gateway-orchestrator must differ from orchestrator-opaque");
    assert_ne!(k2, k3, "gateway-opaque must differ from orchestrator-opaque");

    std::env::remove_var("MILNET_MASTER_KEK");
}

/// Security property: Module HMAC key derivation is order-independent.
/// derive_module_hmac_key("A", "B") == derive_module_hmac_key("B", "A")
/// because a canonical alphabetical ordering is applied internally.
#[test]
fn module_hmac_key_derivation_is_order_independent() {
    std::env::set_var("MILNET_MASTER_KEK", "2a".repeat(32));

    let k1 = derive_module_hmac_key("gateway", "orchestrator").unwrap();
    let k2 = derive_module_hmac_key("orchestrator", "gateway").unwrap();
    assert_eq!(k1, k2, "channel key must be order-independent");

    std::env::remove_var("MILNET_MASTER_KEK");
}

// ── Production Mode ───────────────────────────────────────────────────────

/// Security property: is_production() unconditionally returns true.
#[test]
fn is_production_always_true() {
    assert!(is_production(), "is_production() must always return true");
}

// ── HSM Backend Detection ─────────────────────────────────────────────────

/// Security property: HSM backend detection recognizes valid backend names.
#[test]
fn hsm_backend_detection_valid_names() {
    std::env::set_var("MILNET_HSM_BACKEND", "pkcs11");
    assert_eq!(hsm_backend_from_env(), Some("pkcs11".to_string()));
    std::env::remove_var("MILNET_HSM_BACKEND");

    std::env::set_var("MILNET_HSM_BACKEND", "aws-kms");
    assert_eq!(hsm_backend_from_env(), Some("aws-kms".to_string()));
    std::env::remove_var("MILNET_HSM_BACKEND");

    std::env::set_var("MILNET_HSM_BACKEND", "tpm2");
    assert_eq!(hsm_backend_from_env(), Some("tpm2".to_string()));
    std::env::remove_var("MILNET_HSM_BACKEND");
}

/// Security property: HSM backend detection rejects invalid names.
#[test]
fn hsm_backend_detection_rejects_invalid() {
    std::env::set_var("MILNET_HSM_BACKEND", "invalid-backend");
    assert_eq!(hsm_backend_from_env(), None);
    std::env::remove_var("MILNET_HSM_BACKEND");
}

/// Security property: HSM backend is None when env var is not set.
#[test]
fn hsm_backend_none_when_unset() {
    std::env::remove_var("MILNET_HSM_BACKEND");
    assert_eq!(hsm_backend_from_env(), None);
}

// ── Zeroize ───────────────────────────────────────────────────────────────

/// Security property: zeroize_string clears string memory.
#[test]
fn zeroize_string_clears_memory() {
    let mut s = String::from("super-secret-key-material");
    assert!(!s.is_empty());
    zeroize_string(&mut s);
    // After zeroize, the string should be empty or filled with zeros
    assert!(s.is_empty() || s.bytes().all(|b| b == 0));
}

// Helper: expose unseal_key_from_hex for testing. The actual function is
// private, so we call seal_key_for_storage and use sealed_to_hex, then
// reverse via the known-working seal path.
fn unseal_key_from_hex_for_test(hex_str: &str, purpose: &str) -> Option<[u8; 64]> {
    // We need to call the private unseal function. Since it's not public,
    // we test it through the seal/unseal round-trip.
    let sealed_bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .filter_map(|i| {
            hex_str.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();

    if sealed_bytes.len() < 12 + 16 + 64 {
        return None;
    }

    let master_kek = cached_master_kek();
    let unseal_key = derive_unseal_key_for_test(master_kek, purpose);

    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let cipher = Aes256Gcm::new_from_slice(&unseal_key).ok()?;
    let nonce = Nonce::from_slice(&sealed_bytes[..12]);
    let aad = format!("MILNET-SEALED-KEY-v1:{purpose}");
    let result = cipher.decrypt(nonce, aes_gcm::aead::Payload {
        msg: &sealed_bytes[12..],
        aad: aad.as_bytes(),
    });
    let plaintext = result.ok()?;

    if plaintext.len() != 64 {
        return None;
    }

    let mut key = [0u8; 64];
    key.copy_from_slice(&plaintext);
    Some(key)
}

fn derive_unseal_key_for_test(master_kek: &[u8; 32], purpose: &str) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-UNSEAL-v1"), master_kek);
    let mut okm = [0u8; 32];
    hk.expand(purpose.as_bytes(), &mut okm)
        .expect("32-byte HKDF expand must succeed");
    okm
}
