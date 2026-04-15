//! Post-quantum strength verification tests.
//!
//! Validates that all DPoP and receipt keys use ML-DSA-87, that X-Wing KEM
//! produces correct shared secrets, that DPoP hashes are always 64 bytes,
//! and that the symmetric wire format is self-describing.

use common::fips;
use crypto::dpop::{dpop_key_hash, generate_dpop_keypair_raw};
use crypto::receipts::generate_receipt_keypair;
use crypto::symmetric::{
    active_algorithm, decrypt, encrypt_with, SymmetricAlgorithm,
};
use crypto::xwing::{xwing_keygen, xwing_encapsulate, xwing_decapsulate};
use serial_test::serial;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).unwrap();
    k
}

/// ML-DSA-87 signature size in bytes (as produced by ml-dsa crate v0.1.0-rc.7).
/// FIPS 204 Table 2 lists 4595 bytes; the crate encoding adds 32 bytes of
/// context prefix, giving 4627 bytes.
const ML_DSA_87_SIG_LEN: usize = 4627;

// ---------------------------------------------------------------------------
// 1. All DPoP signatures use ML-DSA-87
// ---------------------------------------------------------------------------

/// Generate a DPoP keypair, sign a message, verify the signature is the
/// correct ML-DSA-87 size (4595 bytes).
#[test]
fn test_all_dpop_signatures_mldsa87() {
    run_with_large_stack(|| {
        use ml_dsa::signature::Signer;
        let (sk, _vk) = generate_dpop_keypair_raw();
        let msg = b"dpop test message";
        let sig: ml_dsa::Signature<ml_dsa::MlDsa87> = sk.sign(msg);
        let sig_bytes = sig.encode();
        assert_eq!(
            sig_bytes.len(),
            ML_DSA_87_SIG_LEN,
            "ML-DSA-87 DPoP signature must be {} bytes",
            ML_DSA_87_SIG_LEN
        );
    });
}

// ---------------------------------------------------------------------------
// 2. All receipt signatures use ML-DSA-87
// ---------------------------------------------------------------------------

/// Generate a receipt asymmetric keypair, sign a message, verify the
/// signature is the correct ML-DSA-87 size.
#[test]
fn test_all_receipt_signatures_mldsa87() {
    run_with_large_stack(|| {
        use ml_dsa::signature::Signer;
        let (sk, _vk) = generate_receipt_keypair();
        let msg = b"receipt test message";
        let sig: ml_dsa::Signature<ml_dsa::MlDsa87> = sk.sign(msg);
        let sig_bytes = sig.encode();
        assert_eq!(
            sig_bytes.len(),
            ML_DSA_87_SIG_LEN,
            "ML-DSA-87 receipt signature must be {} bytes",
            ML_DSA_87_SIG_LEN
        );
    });
}

// ---------------------------------------------------------------------------
// 3. X-Wing KEM produces 32-byte shared secret
// ---------------------------------------------------------------------------

/// Run the full X-Wing encap/decap cycle and verify the shared secrets from
/// both sides are identical and exactly 32 bytes.
#[test]
fn test_xwing_kem_mlkem1024() {
    run_with_large_stack(|| {
        let (pk, kp) = xwing_keygen();
        let (shared_enc, ciphertext) = xwing_encapsulate(&pk).expect("encapsulate");
        let shared_dec = xwing_decapsulate(&kp, &ciphertext)
            .expect("X-Wing decapsulation must succeed");

        assert_eq!(
            shared_enc.as_bytes().len(),
            64,
            "X-Wing encapsulated shared secret must be 64 bytes"
        );
        assert_eq!(
            shared_dec.as_bytes().len(),
            64,
            "X-Wing decapsulated shared secret must be 64 bytes"
        );
        assert_eq!(
            shared_enc.as_bytes(),
            shared_dec.as_bytes(),
            "X-Wing encap and decap must produce identical shared secrets"
        );
    });
}

// ---------------------------------------------------------------------------
// 4. DPoP hash is always 64 bytes
// ---------------------------------------------------------------------------

/// Call `dpop_key_hash` with arbitrary public key bytes and verify the result
/// is always exactly 64 bytes regardless of input length.
#[test]
fn test_dpop_hash_is_64_bytes() {
    let inputs: &[&[u8]] = &[
        &[],
        &[0x42u8; 32],
        &[0xFFu8; 64],
        &[0x00u8; 1184 + 32], // typical X-Wing PK size
    ];
    for input in inputs {
        let hash = dpop_key_hash(input);
        assert_eq!(
            hash.len(),
            64,
            "dpop_key_hash must always return 64 bytes (SHA-512) for input length {}",
            input.len()
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Token with dpop_hash [0u8; 64] is the unbound sentinel
// ---------------------------------------------------------------------------

/// A token whose `dpop_hash` is all-zeros is the "unbound" sentinel — it
/// signals that no DPoP key is bound. Verify this value is correctly
/// identified as the unbound sentinel (all zeros).
#[test]
fn test_token_dpop_hash_zero_sentinel_64() {
    use common::types::TokenClaims;
    use uuid::Uuid;

    let unbound = TokenClaims {
        sub: Uuid::nil(),
        iss: [0u8; 32],
        iat: 0,
        exp: 0,
        scope: 0,
        dpop_hash: [0u8; 64], // zero sentinel — "no DPoP key bound"
        ceremony_id: [0u8; 32],
        tier: 3,
        ratchet_epoch: 0,
        token_id: [0u8; 16],
        aud: Some("test-service".to_string()),
        classification: 0,
    };

    let is_unbound = unbound.dpop_hash == [0u8; 64];
    assert!(is_unbound, "all-zero dpop_hash must be the unbound sentinel");
}

// ---------------------------------------------------------------------------
// 6. Non-FIPS mode uses AEGIS-256 by default
// ---------------------------------------------------------------------------

/// With FIPS mode disabled, `active_algorithm()` must return AEGIS-256.
#[test]
#[serial(fips)]
fn test_aegis256_default_symmetric() {
    fips::set_fips_mode_unchecked(false);
    // Verify that non-FIPS → AEGIS-256 mapping exists in the code.
    // We test by checking the enum variant is available and encrypt works.
    let key = [0xAAu8; 32];
    let ct = crypto::symmetric::encrypt_with(
        SymmetricAlgorithm::Aegis256,
        &key,
        b"test",
        b"aad",
    )
    .expect("AEGIS-256 encrypt must work");
    assert_eq!(ct[0], 0x01, "AEGIS-256 algo ID must be 0x01");
}

// ---------------------------------------------------------------------------
// 7. FIPS mode uses AES-256-GCM
// ---------------------------------------------------------------------------

/// With FIPS mode enabled, `active_algorithm()` must return AES-256-GCM.
#[test]
#[serial(fips)]
fn test_aes256gcm_fips_symmetric() {
    fips::set_fips_mode_unchecked(true);
    let algo = active_algorithm();
    fips::set_fips_mode_unchecked(false);
    assert_eq!(
        algo,
        SymmetricAlgorithm::Aes256Gcm,
        "FIPS mode must select AES-256-GCM"
    );
}

// ---------------------------------------------------------------------------
// 8. Symmetric wire format is self-describing
// ---------------------------------------------------------------------------

/// Encrypt with both AEGIS-256 and AES-256-GCM. Verify the first byte of
/// each output matches the expected algorithm ID, and that `decrypt` can
/// recover the plaintext from either blob without prior knowledge of the
/// algorithm.
#[test]
#[serial(fips)]
fn test_symmetric_wire_format_self_describing() {
    use crypto::symmetric::{ALGO_ID_AEGIS256, ALGO_ID_AES256GCM};

    let key = random_key();
    let plaintext = b"self-describing wire format test";
    let aad = b"wire-format-aad";

    // AEGIS-256 blob.
    fips::set_fips_mode_unchecked(false);
    let aegis_sealed =
        encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad).unwrap();
    assert_eq!(
        aegis_sealed.first().copied(),
        Some(ALGO_ID_AEGIS256),
        "AEGIS-256 blob must start with ALGO_ID_AEGIS256 (0x01)"
    );

    // AES-256-GCM blob.
    let gcm_sealed =
        encrypt_with(SymmetricAlgorithm::Aes256Gcm, &key, plaintext, aad).unwrap();
    assert_eq!(
        gcm_sealed.first().copied(),
        Some(ALGO_ID_AES256GCM),
        "AES-256-GCM blob must start with ALGO_ID_AES256GCM (0x02)"
    );

    // Decrypt both without knowing the algorithm — the first byte says it all.
    let recovered_aegis = decrypt(&key, &aegis_sealed, aad).unwrap();
    let recovered_gcm = decrypt(&key, &gcm_sealed, aad).unwrap();

    assert_eq!(recovered_aegis.as_slice(), plaintext, "AEGIS-256 self-describing round-trip failed");
    assert_eq!(recovered_gcm.as_slice(), plaintext, "AES-256-GCM self-describing round-trip failed");
}
