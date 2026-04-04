//! FIPS 140-3 Startup Known-Answer Tests (KATs).
//!
//! Implements self-tests per FIPS 140-3 Section 9 that MUST run at module
//! startup before any cryptographic service is provided. Each algorithm
//! is tested against hardcoded test vectors (from NIST CAVP where available).
//!
//! If ANY test fails, the module panics with a detailed error message
//! to prevent use of a potentially compromised cryptographic module.
//!
//! Tested algorithms:
//! - AES-256-GCM (FIPS 197 / SP 800-38D)
//! - SHA-512 (FIPS 180-4)
//! - SHA3-256 (FIPS 202)
//! - HKDF-SHA512 (SP 800-56C)
//! - HMAC-SHA512 (FIPS 198-1)
//! - PBKDF2-SHA512 (SP 800-132) — determinism test
//! - AEGIS-256 — encrypt/decrypt roundtrip
//! - ML-KEM-1024 (FIPS 203) — roundtrip test
//! - ML-DSA-87 (FIPS 204) — roundtrip test
//! - X-Wing combiner (ML-KEM-1024 + X25519) — full encap/decap + session key derivation
//! - FROST Ristretto255 — threshold signing (2-of-3 DKG + sign + verify)
//! - SLH-DSA-SHA2-256f (FIPS 205) — hash-based signature roundtrip

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest as Sha2Digest, Sha512};
use sha3::Sha3_256;

type HmacSha512 = Hmac<Sha512>;

// ────────────────────────────────────────────────────────────────────
// Test Vectors
// ────────────────────────────────────────────────────────────────────

/// AES-256-GCM test vector (NIST CAVP GCM Test Vectors).
/// Key:   feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308
/// IV:    cafebabefacedbaddecaf888
/// PT:    d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
///        1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255
/// AAD:   (empty)
const AES_GCM_KEY: [u8; 32] = [
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83,
    0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
    0x83, 0x08,
];

const AES_GCM_NONCE: [u8; 12] = [
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
];

const AES_GCM_PLAINTEXT: [u8; 64] = [
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26,
    0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
    0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
    0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
    0x1a, 0xaf, 0xd2, 0x55,
];

/// Expected AES-256-GCM ciphertext || tag for the above inputs (no AAD).
/// From NIST SP 800-38D test case #16.
const AES_GCM_EXPECTED_CT_TAG: [u8; 80] = [
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42,
    0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55,
    0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56,
    0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62,
    0x89, 0x80, 0x15, 0xad, 0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd, 0xec, 0x1a, 0x50,
    0x22, 0x70, 0xe3, 0xcc, 0x6c,
];

/// SHA-512 test vector (NIST CAVP).
/// Input: "abc"
/// Expected output (SHA-512):
const SHA512_INPUT: &[u8] = b"abc";
const SHA512_EXPECTED: [u8; 64] = [
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
    0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
    0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
    0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
    0xa5, 0x4c, 0xa4, 0x9f,
];

/// SHA3-256 test vector (NIST CAVP).
/// Input: "abc"
/// Expected output (SHA3-256):
const SHA3_256_INPUT: &[u8] = b"abc";
const SHA3_256_EXPECTED: [u8; 32] = [
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
    0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
    0x15, 0x32,
];

/// HKDF-SHA512 test vector (RFC 5869 adapted for SHA-512).
/// IKM:  0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
/// Salt: 0x000102030405060708090a0b0c (13 bytes)
/// Info: 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
/// L:    42
const HKDF_IKM: [u8; 22] = [
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
];

const HKDF_SALT: [u8; 13] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];

const HKDF_INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

/// HMAC-SHA512 test vector (RFC 4231 Test Case 2).
/// Key:  "Jefe"
/// Data: "what do ya want for nothing?"
const HMAC_KEY: &[u8] = b"Jefe";
const HMAC_DATA: &[u8] = b"what do ya want for nothing?";
const HMAC_SHA512_EXPECTED: [u8; 64] = [
    0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56, 0xe0,
    0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25,
    0x05, 0x54, 0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03, 0x4f, 0x65, 0xf8,
    0xf0, 0xe6, 0xfd, 0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b, 0x63, 0x6e, 0x07, 0x0a,
    0x38, 0xbc, 0xe7, 0x37,
];

// ────────────────────────────────────────────────────────────────────
// Individual KAT functions
// ────────────────────────────────────────────────────────────────────

/// KAT: AES-256-GCM encrypt with known test vector.
fn kat_aes_256_gcm() -> Result<(), String> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&AES_GCM_KEY));
    let nonce = Nonce::from_slice(&AES_GCM_NONCE);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, AES_GCM_PLAINTEXT.as_ref())
        .map_err(|e| format!("AES-256-GCM KAT: encryption failed: {}", e))?;

    if ciphertext_with_tag.as_slice() != AES_GCM_EXPECTED_CT_TAG.as_slice() {
        return Err(format!(
            "AES-256-GCM KAT: ciphertext mismatch. Got {} bytes, expected {} bytes. \
             First 16 bytes: {:02x?} vs {:02x?}",
            ciphertext_with_tag.len(),
            AES_GCM_EXPECTED_CT_TAG.len(),
            &ciphertext_with_tag[..core::cmp::min(16, ciphertext_with_tag.len())],
            &AES_GCM_EXPECTED_CT_TAG[..16],
        ));
    }

    // Verify decryption roundtrip
    let decrypted = cipher
        .decrypt(nonce, ciphertext_with_tag.as_ref())
        .map_err(|e| format!("AES-256-GCM KAT: decryption failed: {}", e))?;

    if decrypted.as_slice() != AES_GCM_PLAINTEXT.as_slice() {
        return Err("AES-256-GCM KAT: decryption roundtrip mismatch".into());
    }

    tracing::info!("FIPS KAT: AES-256-GCM PASSED");
    Ok(())
}

/// KAT: SHA-512 hash with known test vector.
fn kat_sha512() -> Result<(), String> {
    let mut hasher = Sha512::new();
    hasher.update(SHA512_INPUT);
    let result = hasher.finalize();

    if result.as_slice() != SHA512_EXPECTED.as_slice() {
        return Err(format!(
            "SHA-512 KAT: hash mismatch. Got {:02x?}, expected {:02x?}",
            &result[..8],
            &SHA512_EXPECTED[..8],
        ));
    }

    tracing::info!("FIPS KAT: SHA-512 PASSED");
    Ok(())
}

/// KAT: SHA3-256 hash with known test vector.
fn kat_sha3_256() -> Result<(), String> {
    let mut hasher = Sha3_256::new();
    hasher.update(SHA3_256_INPUT);
    let result = hasher.finalize();

    if result.as_slice() != SHA3_256_EXPECTED.as_slice() {
        return Err(format!(
            "SHA3-256 KAT: hash mismatch. Got {:02x?}, expected {:02x?}",
            &result[..8],
            &SHA3_256_EXPECTED[..8],
        ));
    }

    tracing::info!("FIPS KAT: SHA3-256 PASSED");
    Ok(())
}

/// KAT: HKDF-SHA512 key derivation.
///
/// We compute HKDF-SHA512 with known IKM/salt/info and verify the output
/// is deterministic and non-zero. Since RFC 5869 only provides SHA-256
/// test vectors, we verify determinism and roundtrip rather than a fixed
/// expected output.
fn kat_hkdf_sha512() -> Result<(), String> {
    let hk = Hkdf::<Sha512>::new(Some(&HKDF_SALT), &HKDF_IKM);
    let mut okm1 = [0u8; 42];
    hk.expand(&HKDF_INFO, &mut okm1)
        .map_err(|e| format!("HKDF-SHA512 KAT: expand failed: {}", e))?;

    // Verify output is non-zero
    if okm1 == [0u8; 42] {
        return Err("HKDF-SHA512 KAT: output is all zeros".into());
    }

    // Verify determinism
    let hk2 = Hkdf::<Sha512>::new(Some(&HKDF_SALT), &HKDF_IKM);
    let mut okm2 = [0u8; 42];
    hk2.expand(&HKDF_INFO, &mut okm2)
        .map_err(|e| format!("HKDF-SHA512 KAT: second expand failed: {}", e))?;

    if okm1 != okm2 {
        return Err("HKDF-SHA512 KAT: non-deterministic output".into());
    }

    // Verify known output (computed from reference implementation):
    // HKDF-SHA512 with these inputs produces a specific OKM.
    // We verify the first 16 bytes as a spot check.
    let expected_prefix: [u8; 16] = [
        0x83, 0x23, 0x90, 0x08, 0x6c, 0xda, 0x71, 0xfb, 0x47, 0x62, 0x5b, 0xb5, 0xce, 0xb1,
        0x68, 0xe4,
    ];
    if okm1[..16] != expected_prefix {
        return Err(format!(
            "HKDF-SHA512 KAT: output prefix mismatch. Got {:02x?}, expected {:02x?}",
            &okm1[..16], &expected_prefix
        ));
    }

    tracing::info!("FIPS KAT: HKDF-SHA512 PASSED");
    Ok(())
}

/// KAT: HMAC-SHA512 with known test vector (RFC 4231 Test Case 2).
fn kat_hmac_sha512() -> Result<(), String> {
    let mut mac =
        <HmacSha512 as hmac::Mac>::new_from_slice(HMAC_KEY).map_err(|e| format!("HMAC-SHA512 KAT: init failed: {}", e))?;
    mac.update(HMAC_DATA);
    let result = mac.finalize().into_bytes();

    if result.as_slice() != HMAC_SHA512_EXPECTED.as_slice() {
        return Err(format!(
            "HMAC-SHA512 KAT: MAC mismatch. Got {:02x?}, expected {:02x?}",
            &result[..8],
            &HMAC_SHA512_EXPECTED[..8],
        ));
    }

    tracing::info!("FIPS KAT: HMAC-SHA512 PASSED");
    Ok(())
}

/// KAT: ML-KEM-1024 encapsulate/decapsulate roundtrip.
///
/// Since ML-KEM uses randomized encapsulation, we cannot compare against
/// a fixed test vector. Instead we verify the roundtrip property:
/// decapsulate(encapsulate(ek)) produces the same shared secret.
fn kat_ml_kem_1024() -> Result<(), String> {
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{KemCore, MlKem1024};

    let mut rng = rand::rngs::OsRng;
    let (dk, ek) = MlKem1024::generate(&mut rng);

    let (ct, ss_enc) = ek
        .encapsulate(&mut rng)
        .map_err(|_| "ML-KEM-1024 KAT: encapsulation failed".to_string())?;

    let ss_dec = dk
        .decapsulate(&ct)
        .map_err(|_| "ML-KEM-1024 KAT: decapsulation failed".to_string())?;

    if ss_enc.as_slice() != ss_dec.as_slice() {
        return Err("ML-KEM-1024 KAT: shared secret mismatch after roundtrip".into());
    }

    // Verify shared secret is non-zero
    if ss_enc.as_slice().iter().all(|&b| b == 0) {
        return Err("ML-KEM-1024 KAT: shared secret is all zeros".into());
    }

    // Verify shared secret length is 32 bytes (ML-KEM-1024 spec)
    if ss_enc.as_slice().len() != 32 {
        return Err(format!(
            "ML-KEM-1024 KAT: shared secret length is {}, expected 32",
            ss_enc.as_slice().len()
        ));
    }

    // Verify implicit rejection: decapsulating with a different key must produce
    // a DIFFERENT shared secret (ML-KEM uses implicit rejection, not an error).
    let (dk_wrong, _ek_wrong) = MlKem1024::generate(&mut rng);
    let ss_wrong = dk_wrong
        .decapsulate(&ct)
        .map_err(|_| "ML-KEM-1024 KAT: wrong-key decapsulation failed unexpectedly".to_string())?;

    if ss_wrong.as_slice() == ss_enc.as_slice() {
        return Err("ML-KEM-1024 KAT: wrong key produced same shared secret (implicit rejection broken)".into());
    }

    tracing::info!("FIPS KAT: ML-KEM-1024 PASSED");
    Ok(())
}

/// KAT: X-Wing hybrid KEM combiner (ML-KEM-1024 + X25519) roundtrip.
///
/// Verifies the full X-Wing encapsulate/decapsulate cycle produces matching
/// shared secrets, and that the HKDF-SHA512 session key derivation is
/// deterministic for the same inputs.
fn kat_xwing_combiner() -> Result<(), String> {
    use crate::xwing::{XWingKeyPair, xwing_encapsulate, xwing_decapsulate, derive_session_key};

    // Generate a keypair
    let kp = XWingKeyPair::generate();
    let pk = kp.public_key();

    // Encapsulate: client produces (shared_secret, ciphertext)
    let (ss_enc, ct) = xwing_encapsulate(&pk)
        .map_err(|e| format!("X-Wing KAT: encapsulation failed: {}", e))?;

    // Decapsulate: server recovers the same shared_secret
    let ss_dec = xwing_decapsulate(&kp, &ct)
        .map_err(|e| format!("X-Wing KAT: decapsulation failed: {}", e))?;

    // Shared secrets must match
    if ss_enc.as_bytes() != ss_dec.as_bytes() {
        return Err("X-Wing KAT: shared secret mismatch after encap/decap roundtrip".into());
    }

    // Shared secret must be non-zero
    if ss_enc.as_bytes().iter().all(|&b| b == 0) {
        return Err("X-Wing KAT: shared secret is all zeros".into());
    }

    // Session key derivation must be deterministic
    let context = b"KAT-test-context";
    let sk1 = derive_session_key(&ss_enc, context)
        .map_err(|e| format!("X-Wing KAT: session key derivation failed: {}", e))?;
    let sk2 = derive_session_key(&ss_enc, context)
        .map_err(|e| format!("X-Wing KAT: session key derivation failed: {}", e))?;
    if sk1 != sk2 {
        return Err("X-Wing KAT: session key derivation is non-deterministic".into());
    }

    // Session key must be non-zero
    if sk1.iter().all(|&b| b == 0) {
        return Err("X-Wing KAT: derived session key is all zeros".into());
    }

    // Different contexts must produce different session keys
    let sk3 = derive_session_key(&ss_enc, b"different-context")
        .map_err(|e| format!("X-Wing KAT: session key derivation failed: {}", e))?;
    if sk1 == sk3 {
        return Err("X-Wing KAT: different contexts produced same session key".into());
    }

    tracing::info!("FIPS KAT: X-Wing combiner (ML-KEM-1024 + X25519) PASSED");
    Ok(())
}

/// KAT: FROST Ristretto255 threshold signing roundtrip.
///
/// Verifies that a t-of-n threshold group can produce a valid signature
/// using the trusted dealer ceremony, and that the signature verifies
/// against the group's public key.
fn kat_frost_ristretto255() -> Result<(), String> {
    use crate::threshold;

    // Generate a 2-of-3 threshold group
    let mut dkg_result = threshold::dkg(3, 2)?;

    if dkg_result.shares.len() != 3 {
        return Err(format!(
            "FROST KAT: expected 3 shares, got {}",
            dkg_result.shares.len()
        ));
    }

    // Verify that the group has the correct threshold
    if dkg_result.group.threshold != 2 || dkg_result.group.total != 3 {
        return Err(format!(
            "FROST KAT: wrong group parameters t={}, n={}",
            dkg_result.group.threshold, dkg_result.group.total
        ));
    }

    // Perform a threshold signing round with 2 of 3 signers
    let test_message = b"FIPS 140-3 FROST Ristretto255 known-answer test message";

    let signing_result = threshold::threshold_sign(
        &mut dkg_result.shares,
        &dkg_result.group,
        test_message,
        2, // threshold
    );

    match signing_result {
        Ok(signature) => {
            // Verify the threshold signature against the group public key
            if !threshold::verify_group_signature(
                &dkg_result.group,
                test_message,
                &signature,
            ) {
                return Err("FROST KAT: threshold signature verification failed".into());
            }

            // Wrong message must not verify
            if threshold::verify_group_signature(
                &dkg_result.group,
                b"tampered message",
                &signature,
            ) {
                return Err("FROST KAT: verification succeeded for wrong message".into());
            }
        }
        Err(e) => {
            return Err(format!("FROST KAT: threshold signing failed: {}", e));
        }
    }

    tracing::info!("FIPS KAT: FROST Ristretto255 (2-of-3) PASSED");
    Ok(())
}

/// KAT: SLH-DSA-SHA2-256f (FIPS 205) sign/verify roundtrip.
///
/// Verifies that SLH-DSA key generation, signing, and verification produce
/// correct results, and that tampered messages are rejected.
fn kat_slh_dsa() -> Result<(), String> {
    use crate::slh_dsa;

    // Generate a keypair
    let (sk, vk) = slh_dsa::slh_dsa_keygen();

    let test_message = b"FIPS 140-3 SLH-DSA-SHA2-256f known-answer test message";

    // Sign the test message
    let signature = slh_dsa::slh_dsa_sign(&sk, test_message);

    // Verify the signature
    if !slh_dsa::slh_dsa_verify(&vk, test_message, &signature) {
        return Err("SLH-DSA KAT: signature verification failed".into());
    }

    // Wrong message must not verify
    if slh_dsa::slh_dsa_verify(&vk, b"tampered message", &signature) {
        return Err("SLH-DSA KAT: verification succeeded for wrong message".into());
    }

    // Public key must be non-zero
    let pk_bytes = vk.to_bytes();
    if pk_bytes.iter().all(|&b| b == 0) {
        return Err("SLH-DSA KAT: public key is all zeros".into());
    }

    tracing::info!("FIPS KAT: SLH-DSA-SHA2-256f (FIPS 205) PASSED");
    Ok(())
}

/// KAT: PBKDF2-SHA512 key derivation.
///
/// Uses known inputs (password="password", salt="salt", iterations=4096, len=32)
/// and verifies the output is non-zero and deterministic.
fn kat_pbkdf2_sha512() -> Result<(), String> {
    let password = b"password";
    let salt = b"salt";
    let iterations = 4096u32;
    let output_len = 32usize;

    let mut key1 = vec![0u8; output_len];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, iterations, &mut key1);

    // Verify output is non-zero
    if key1.iter().all(|&b| b == 0) {
        return Err("PBKDF2-SHA512 KAT: derived key is all zeros".into());
    }

    // Verify determinism
    let mut key2 = vec![0u8; output_len];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, iterations, &mut key2);

    if key1 != key2 {
        return Err("PBKDF2-SHA512 KAT: non-deterministic output".into());
    }

    tracing::info!("FIPS KAT: PBKDF2-SHA512 PASSED");
    Ok(())
}

/// KAT: AEGIS-256 encrypt/decrypt roundtrip.
///
/// Generates a random key, encrypts a known plaintext, decrypts the result,
/// and verifies the roundtrip matches.
fn kat_aegis256() -> Result<(), String> {
    use crate::symmetric::{encrypt_with, decrypt, SymmetricAlgorithm};

    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key)
        .map_err(|e| format!("AEGIS-256 KAT: key generation failed: {}", e))?;

    let plaintext = b"AEGIS-256 KAT test data";
    let aad = &[];

    let sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad)
        .map_err(|e| format!("AEGIS-256 KAT: encryption failed: {}", e))?;

    let decrypted = decrypt(&key, &sealed, aad)
        .map_err(|e| format!("AEGIS-256 KAT: decryption failed: {}", e))?;

    if decrypted != plaintext {
        return Err("AEGIS-256 KAT: decrypted plaintext does not match original".into());
    }

    // Determinism check: same key + same plaintext + same nonce must produce same ciphertext
    let sealed2 = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad)
        .map_err(|e| format!("AEGIS-256 KAT: second encryption failed: {}", e))?;
    // Note: AEGIS-256 uses random nonces, so sealed != sealed2 is expected.
    // But both must decrypt to the same plaintext.
    let decrypted2 = decrypt(&key, &sealed2, aad)
        .map_err(|e| format!("AEGIS-256 KAT: second decryption failed: {}", e))?;
    if decrypted2 != plaintext {
        return Err("AEGIS-256 KAT: second roundtrip mismatch".into());
    }

    // Wrong key must fail decryption
    let mut wrong_key = key;
    wrong_key[0] ^= 0xFF;
    if decrypt(&wrong_key, &sealed, aad).is_ok() {
        return Err("AEGIS-256 KAT: decryption succeeded with wrong key".into());
    }

    tracing::info!("FIPS KAT: AEGIS-256 PASSED");
    Ok(())
}

/// KAT: ML-DSA-87 sign/verify with fixed seed (deterministic).
///
/// Uses a hardcoded seed for deterministic keypair generation, signs a fixed
/// message, verifies the signature, and checks that the same seed always
/// produces compatible keys.
fn kat_ml_dsa_87() -> Result<(), String> {
    use ml_dsa::{
        signature::{Signer, Verifier},
        KeyGen, MlDsa87,
    };

    // Fixed KAT seed — deterministic keypair generation
    let seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    let kp = MlDsa87::from_seed(&seed.into());
    let sk = kp.signing_key();
    let vk = kp.verifying_key();

    let test_message = b"FIPS 140-3 ML-DSA-87 known-answer test message";
    let sig: ml_dsa::Signature<MlDsa87> = sk.sign(test_message);

    // Verify signature is valid
    vk.verify(test_message, &sig)
        .map_err(|_| "ML-DSA-87 KAT: signature verification failed".to_string())?;

    // Verify wrong message is rejected
    if vk.verify(b"tampered message", &sig).is_ok() {
        return Err("ML-DSA-87 KAT: verification succeeded for wrong message".into());
    }

    // Verify determinism: same seed must produce same keypair
    let kp2 = MlDsa87::from_seed(&seed.into());
    let _vk2 = kp2.verifying_key();
    let sig2: ml_dsa::Signature<MlDsa87> = kp2.signing_key().sign(test_message);

    vk.verify(test_message, &sig2)
        .map_err(|_| "ML-DSA-87 KAT: determinism check failed — same seed produced incompatible keys".to_string())?;

    tracing::info!("FIPS KAT: ML-DSA-87 PASSED (fixed-seed deterministic)");
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────

/// Run ALL FIPS 140-3 startup known-answer tests.
///
/// This function MUST be called at module startup before any cryptographic
/// operations are performed. It tests every algorithm used by the system
/// against known test vectors or verified roundtrip properties.
///
/// # Returns
///
/// `Ok(())` if all tests pass.
///
/// # Errors
///
/// Returns `Err(String)` with a detailed description of the first failing
/// test. In production, callers should `panic!` on any error to prevent
/// use of a potentially compromised cryptographic module.
///
/// # Panics
///
/// Individual sub-tests do not panic; errors are collected and returned.
/// The caller is responsible for deciding whether to panic.
pub fn run_startup_kats() -> Result<(), String> {
    tracing::info!("FIPS 140-3 startup known-answer tests: BEGIN");

    // Run each KAT. On first failure, return the error immediately.
    // ML-DSA-87 and X-Wing need large stacks for key generation.
    kat_aes_256_gcm()?;
    kat_sha512()?;
    kat_sha3_256()?;
    kat_hkdf_sha512()?;
    kat_hmac_sha512()?;
    kat_pbkdf2_sha512()?;
    kat_aegis256()?;
    kat_ml_kem_1024()?;

    // ML-DSA-87 keys are large (~4KB). Run in a thread with larger stack.
    let ml_dsa_result = std::thread::Builder::new()
        .name("fips-kat-ml-dsa".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(kat_ml_dsa_87)
        .map_err(|e| format!("ML-DSA-87 KAT: failed to spawn thread: {}", e))?
        .join()
        .map_err(|_| "ML-DSA-87 KAT: thread panicked".to_string())?;
    ml_dsa_result?;

    // X-Wing combiner (ML-KEM-1024 + X25519) — needs large stack for ML-KEM.
    let xwing_result = std::thread::Builder::new()
        .name("fips-kat-xwing".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(kat_xwing_combiner)
        .map_err(|e| format!("X-Wing KAT: failed to spawn thread: {}", e))?
        .join()
        .map_err(|_| "X-Wing KAT: thread panicked".to_string())?;
    xwing_result?;

    // FROST Ristretto255 threshold signing — moderate stack requirements.
    let frost_result = std::thread::Builder::new()
        .name("fips-kat-frost".into())
        .stack_size(4 * 1024 * 1024)
        .spawn(kat_frost_ristretto255)
        .map_err(|e| format!("FROST KAT: failed to spawn thread: {}", e))?
        .join()
        .map_err(|_| "FROST KAT: thread panicked".to_string())?;
    frost_result?;

    // SLH-DSA-SHA2-256f (FIPS 205) — hash-based signatures.
    let slh_dsa_result = std::thread::Builder::new()
        .name("fips-kat-slh-dsa".into())
        .stack_size(4 * 1024 * 1024)
        .spawn(kat_slh_dsa)
        .map_err(|e| format!("SLH-DSA KAT: failed to spawn thread: {}", e))?
        .join()
        .map_err(|_| "SLH-DSA KAT: thread panicked".to_string())?;
    slh_dsa_result?;

    tracing::info!("FIPS 140-3 startup known-answer tests: ALL PASSED (12/12)");
    Ok(())
}

/// Run startup KATs and panic on failure.
///
/// This is the recommended entry point for production use. Call this
/// once at application startup.
pub fn run_startup_kats_or_panic() {
    if let Err(e) = run_startup_kats() {
        panic!(
            "FIPS 140-3 STARTUP SELF-TEST FAILURE: {}. \
             Cryptographic module is NOT safe to use. \
             This is a critical security event — investigate immediately.",
            e
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kat_aes_256_gcm() {
        kat_aes_256_gcm().expect("AES-256-GCM KAT should pass");
    }

    #[test]
    fn test_kat_sha512() {
        kat_sha512().expect("SHA-512 KAT should pass");
    }

    #[test]
    fn test_kat_sha3_256() {
        kat_sha3_256().expect("SHA3-256 KAT should pass");
    }

    #[test]
    fn test_kat_hkdf_sha512() {
        kat_hkdf_sha512().expect("HKDF-SHA512 KAT should pass");
    }

    #[test]
    fn test_kat_hmac_sha512() {
        kat_hmac_sha512().expect("HMAC-SHA512 KAT should pass");
    }

    #[test]
    fn test_kat_pbkdf2_sha512() {
        kat_pbkdf2_sha512().expect("PBKDF2-SHA512 KAT should pass");
    }

    #[test]
    fn test_kat_aegis256() {
        kat_aegis256().expect("AEGIS-256 KAT should pass");
    }

    #[test]
    fn test_kat_ml_kem_1024() {
        kat_ml_kem_1024().expect("ML-KEM-1024 KAT should pass");
    }

    #[test]
    fn test_kat_ml_dsa_87() {
        // Run with large stack for ML-DSA-87 key generation
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                kat_ml_dsa_87().expect("ML-DSA-87 KAT should pass");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_kat_xwing_combiner() {
        // X-Wing needs large stack for ML-KEM-1024 key generation
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                kat_xwing_combiner().expect("X-Wing combiner KAT should pass");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_kat_frost_ristretto255() {
        std::thread::Builder::new()
            .stack_size(4 * 1024 * 1024)
            .spawn(|| {
                kat_frost_ristretto255().expect("FROST Ristretto255 KAT should pass");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_kat_slh_dsa() {
        std::thread::Builder::new()
            .stack_size(4 * 1024 * 1024)
            .spawn(|| {
                kat_slh_dsa().expect("SLH-DSA KAT should pass");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_run_all_startup_kats() {
        run_startup_kats().expect("All startup KATs should pass");
    }

    #[test]
    fn test_sha512_vector_correctness() {
        // Verify our hardcoded SHA-512("abc") vector is correct
        let mut hasher = Sha512::new();
        hasher.update(b"abc");
        let result = hasher.finalize();
        assert_eq!(
            result.as_slice(),
            SHA512_EXPECTED.as_slice(),
            "SHA-512 test vector must match NIST CAVP"
        );
    }

    #[test]
    fn test_sha3_256_vector_correctness() {
        // Verify our hardcoded SHA3-256("abc") vector is correct
        let mut hasher = Sha3_256::new();
        hasher.update(b"abc");
        let result = hasher.finalize();
        assert_eq!(
            result.as_slice(),
            SHA3_256_EXPECTED.as_slice(),
            "SHA3-256 test vector must match NIST CAVP"
        );
    }

    #[test]
    fn test_hmac_sha512_vector_correctness() {
        // Verify our hardcoded HMAC-SHA512 vector is correct (RFC 4231 TC2)
        let mut mac = <HmacSha512 as hmac::Mac>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        let result = mac.finalize().into_bytes();
        assert_eq!(
            result.as_slice(),
            HMAC_SHA512_EXPECTED.as_slice(),
            "HMAC-SHA512 test vector must match RFC 4231"
        );
    }
}
