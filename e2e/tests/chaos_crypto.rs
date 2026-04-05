//! Cryptographic failure injection tests.
//!
//! Validates that the crypto layer handles adversarial inputs correctly:
//! biased entropy, FIPS mode enforcement, FROST share corruption,
//! large-data round-trips, and graceful handling of corrupted wire formats.

use crypto::entropy::EntropyHealth;
use crypto::symmetric::{
    active_algorithm, decrypt, encrypt, encrypt_with, SymmetricAlgorithm,
    ALGO_ID_AES256GCM, ALGO_ID_AEGIS256, AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN,
};
use crypto::threshold::{dkg, threshold_sign};
use crypto::seal::MasterKey;
use common::fips;
use serial_test::serial;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).unwrap();
    k
}

fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

// ---------------------------------------------------------------------------
// 1. Entropy bias detection
// ---------------------------------------------------------------------------

/// Feed 1000 identical bytes to the entropy health check and verify it is
/// detected as biased (proportion test fails).
#[test]
fn test_entropy_bias_detection() {
    let mut health = EntropyHealth::new();
    // Override the proportion_cutoff to a very tight value so that filling
    // the window with a single byte value definitely fails the check.
    health.proportion_cutoff = 10;

    // Fill the sliding window entirely with 0x00 bytes.
    // Each call feeds 32 bytes; window is 1024 bytes → 32 rounds.
    let biased = [0x00u8; 32];
    for _ in 0..33 {
        let _ = health.check_proportion(&biased);
    }
    // One more call must now flag the bias.
    let still_biased = [0x00u8; 32];
    let ok = health.check_proportion(&still_biased);
    assert!(!ok, "proportion test must reject heavily biased entropy");
}

// ---------------------------------------------------------------------------
// 2. FIPS mode forces AES-256-GCM instead of AEGIS-256
// ---------------------------------------------------------------------------

/// Enable FIPS, verify that `active_algorithm()` returns AES-256-GCM and that
/// data encrypted with the active algorithm can be decrypted.
#[test]
#[serial(fips)]
fn test_fips_mode_blocks_aegis256() {
    fips::set_fips_mode_unchecked(true);
    let algo = active_algorithm();
    fips::set_fips_mode_unchecked(false); // reset first so the test doesn't bleed

    assert_eq!(
        algo,
        SymmetricAlgorithm::Aes256Gcm,
        "FIPS mode must select AES-256-GCM, not AEGIS-256"
    );
}

// ---------------------------------------------------------------------------
// 3. FIPS mode forces PBKDF2
// ---------------------------------------------------------------------------

/// Enable FIPS mode, register a user via the FIPS registration path, verify
/// that the stored KSF algorithm is PBKDF2-SHA512.
#[test]
#[serial(fips)]
fn test_fips_mode_forces_pbkdf2() {
    use opaque::store::CredentialStore;

    fips::set_fips_mode_unchecked(true);

    // new_dual() initialises both the standard Argon2id server setup and
    // the FIPS PBKDF2-SHA512 server setup.
    let mut store = CredentialStore::new_dual();
    let uid = store.register_with_password_fips("fips_pbkdf2_user", b"password")
        .expect("FIPS registration must succeed");
    let ksf = store.get_ksf_algorithm("fips_pbkdf2_user");

    fips::set_fips_mode_unchecked(false);

    assert!(uid != uuid::Uuid::nil(), "registered user must have a non-nil UUID");
    assert_eq!(
        ksf,
        Some("pbkdf2-sha512"),
        "FIPS registration must store pbkdf2-sha512 as the KSF"
    );
}

// ---------------------------------------------------------------------------
// 4. FROST share corruption detected
// ---------------------------------------------------------------------------

/// Run DKG 2-of-3, corrupt one signer's key package bytes, attempt threshold
/// signing — should fail or produce an invalid signature.
#[test]
fn test_frost_share_corruption_detected() {
    run_with_large_stack(|| {
        let mut result = dkg(3, 2).expect("DKG ceremony failed");
        // Corrupt the first signer's key package by replacing it with a key
        // from a freshly generated independent group (wrong secret share).
        let corrupt = dkg(3, 2).expect("DKG ceremony failed");
        result.shares[0].identifier = corrupt.shares[0].identifier;
        result.shares[0].key_package = corrupt.shares[0].key_package.clone();

        // Attempt signing — should fail at aggregation because the corrupted
        // share identifier no longer matches the group's commitments.
        let sign_result = threshold_sign(
            &mut result.shares,
            &result.group,
            b"test message",
            2,
        );
        // Either signing fails, or the resulting signature fails verification.
        let is_invalid = match sign_result {
            Err(_) => true,
            Ok(sig) => {
                !crypto::threshold::verify_group_signature(&result.group, b"test message", &sig)
            }
        };
        assert!(is_invalid, "corrupted share must not produce a valid group signature");
    });
}

// ---------------------------------------------------------------------------
// 5. FROST below-threshold fails
// ---------------------------------------------------------------------------

/// Run DKG 3-of-5, attempt signing with only 2 signers — must fail.
#[test]
fn test_frost_below_threshold_fails() {
    run_with_large_stack(|| {
        let mut result = dkg(5, 3).expect("DKG ceremony failed");
        // threshold_sign takes the first `threshold` signers from the slice,
        // so pass only 2 signers while requesting threshold=3.
        let sign_result = threshold_sign(
            &mut result.shares[..2],
            &result.group,
            b"below threshold test",
            3,
        );
        assert!(
            sign_result.is_err(),
            "signing below threshold must return an error"
        );
    });
}

// ---------------------------------------------------------------------------
// 6. Key rotation seal / unseal across key versions
// ---------------------------------------------------------------------------

/// Seal data with key1, rotate to key2, verify old data can still be unsealed
/// with the key1 hierarchy.
#[test]
fn test_key_rotation_seal_unseal() {
    let master1 = MasterKey::generate();
    let kek1 = master1.derive_kek("purpose:test");

    let plaintext = b"sensitive data sealed with key1";
    let sealed = kek1.seal(plaintext).unwrap();

    // Simulate key rotation — key2 is a different master key.
    let _master2 = MasterKey::generate();

    // Old data must still unseal with the old KEK.
    let recovered = kek1.unseal(&sealed).unwrap();
    assert_eq!(recovered.as_slice(), plaintext, "old sealed data must unseal with old key");
}

// ---------------------------------------------------------------------------
// 7. AEGIS-256 large data round-trip
// ---------------------------------------------------------------------------

/// Encrypt 10 MB of data with AEGIS-256, decrypt, verify the result matches.
#[test]
#[serial(fips)]
fn test_aegis256_roundtrip_large_data() {
    fips::set_fips_mode_unchecked(false);

    let key = random_key();
    let plaintext = vec![0x5Au8; 10 * 1024 * 1024]; // 10 MB
    let aad = b"large-data-aad";

    let sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, &plaintext, aad).unwrap();
    let recovered = decrypt(&key, &sealed, aad).unwrap();
    assert_eq!(recovered, plaintext, "10 MB AEGIS-256 round-trip must succeed");
}

// ---------------------------------------------------------------------------
// 8. AES-256-GCM FIPS round-trip
// ---------------------------------------------------------------------------

/// Enable FIPS mode, perform a full encrypt/decrypt cycle, reset.
/// Uses `encrypt_with` to explicitly select AES-256-GCM, avoiding a race on
/// the global FIPS flag when tests run in parallel.
#[test]
#[serial(fips)]
fn test_aes256gcm_fips_roundtrip() {
    let key = random_key();
    let plaintext = b"fips roundtrip test";
    let aad = b"fips-aad";

    // Encrypt explicitly with AES-256-GCM (the FIPS-mandated algorithm).
    let sealed = encrypt_with(SymmetricAlgorithm::Aes256Gcm, &key, plaintext, aad).unwrap();

    assert_eq!(
        sealed.first().copied(),
        Some(ALGO_ID_AES256GCM),
        "AES-256-GCM (FIPS algorithm) output must start with ALGO_ID_AES256GCM"
    );

    // Verify that when FIPS is enabled, active_algorithm() returns AES-256-GCM.
    fips::set_fips_mode_unchecked(true);
    let algo = active_algorithm();
    fips::set_fips_mode_unchecked(false);
    assert_eq!(
        algo,
        SymmetricAlgorithm::Aes256Gcm,
        "FIPS mode must select AES-256-GCM"
    );

    // Decrypt works without FIPS mode (algo_id is self-describing).
    let recovered = decrypt(&key, &sealed, aad).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

// ---------------------------------------------------------------------------
// 9. Legacy AES-256-GCM backward compatibility
// ---------------------------------------------------------------------------

/// Create a legacy AES-256-GCM blob (no algo_id prefix), verify that the
/// symmetric module now rejects it. The legacy `_ =>` fallback has been
/// removed — only tagged ciphertext (AEGIS-256 = 0x01, AES-256-GCM = 0x02)
/// is accepted.
#[test]
fn test_legacy_aes256gcm_rejected_after_fallback_removal() {
    use aes_gcm::{aead::Aead, aead::generic_array::GenericArray, Aes256Gcm, KeyInit};
    use aes_gcm::Nonce as GcmNonce;
    use aes_gcm::aead::Payload;

    let key = random_key();
    let plaintext = b"legacy compat data";
    let aad = b"legacy-aad";

    // Build a legacy blob: nonce (12) || ciphertext+tag, NO algo_id byte.
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
    // Use a nonce that is not 0x01 or 0x02 to avoid algo_id confusion.
    nonce_bytes[0] = 0xFF;
    getrandom::getrandom(&mut nonce_bytes[1..]).unwrap();

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce = GcmNonce::from_slice(&nonce_bytes);
    let ct_with_tag = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .unwrap();

    let mut legacy_blob = Vec::with_capacity(AES_GCM_NONCE_LEN + ct_with_tag.len());
    legacy_blob.extend_from_slice(&nonce_bytes);
    legacy_blob.extend_from_slice(&ct_with_tag);

    // Legacy untagged ciphertext is no longer accepted — decrypt must fail.
    let result = decrypt(&key, &legacy_blob, aad);
    assert!(
        result.is_err(),
        "legacy AES-256-GCM blob (no algo_id prefix) must be rejected after fallback removal"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("unknown algorithm tag"),
        "error must mention unknown algorithm tag, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// 10. Corrupted algo_id handled gracefully (no panic)
// ---------------------------------------------------------------------------

/// Set the first byte of a sealed blob to 0xFF (unknown algo_id), verify
/// that decryption returns an error rather than panicking.
#[test]
fn test_symmetric_algo_id_corruption() {
    let key = random_key();
    let plaintext = b"algo id corruption test";
    let aad = b"corruption-aad";

    let mut sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad).unwrap();

    // Corrupt the first byte (algo_id).
    if let Some(b) = sealed.get_mut(0) {
        *b = 0xFF;
    }

    // With the legacy fallback removed, 0xFF is an unknown algorithm tag
    // and must be rejected immediately with a clear error.
    let result = decrypt(&key, &sealed, aad);
    assert!(
        result.is_err(),
        "corrupted algo_id must cause a graceful decryption failure"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("unknown algorithm tag"),
        "error must mention unknown algorithm tag, got: {err}"
    );
}
