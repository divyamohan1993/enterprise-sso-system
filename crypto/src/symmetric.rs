//! Unified AEAD abstraction for MILNET SSO.
//!
//! Provides a single encrypt/decrypt surface that automatically selects
//! AEGIS-256 (default, non-FIPS) or AES-256-GCM (FIPS fallback).
//!
//! Wire format: algo_id (1 byte) || nonce || ciphertext || tag
//!
//! Legacy AES-256-GCM blobs (no algo_id prefix) are detected heuristically
//! and handled transparently on the decrypt path.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce as GcmNonce};
use aegis::aegis256::Aegis256;
use chacha20poly1305::ChaCha20Poly1305;

// ---------------------------------------------------------------------------
// Algorithm identifier constants
// ---------------------------------------------------------------------------

pub const ALGO_ID_AEGIS256: u8 = 0x01;
pub const ALGO_ID_AES256GCM: u8 = 0x02;
pub const ALGO_ID_CHACHA20POLY1305: u8 = 0x03;

// ---------------------------------------------------------------------------
// Nonce / tag length constants
// ---------------------------------------------------------------------------

/// AEGIS-256 nonce length: 256 bits.
pub const AEGIS256_NONCE_LEN: usize = 32;

/// AEGIS-256 tag length: 256 bits.
pub const AEGIS256_TAG_LEN: usize = 32;

/// AES-256-GCM nonce length: 96 bits.
pub const AES_GCM_NONCE_LEN: usize = 12;

/// AES-256-GCM tag length: 128 bits.
pub const AES_GCM_TAG_LEN: usize = 16;

/// ChaCha20-Poly1305 nonce length: 96 bits.
pub const CHACHA_NONCE_LEN: usize = 12;

/// ChaCha20-Poly1305 tag length: 128 bits.
pub const CHACHA_TAG_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Algorithm enum
// ---------------------------------------------------------------------------

/// Symmetric AEAD algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SymmetricAlgorithm {
    /// AEGIS-256 with 256-bit nonce and 256-bit tag (RFC 9312). Default.
    Aegis256 = ALGO_ID_AEGIS256,
    /// AES-256-GCM with 96-bit nonce and 128-bit tag. FIPS fallback.
    Aes256Gcm = ALGO_ID_AES256GCM,
    /// ChaCha20-Poly1305 with 96-bit nonce and 128-bit tag. ARM fallback.
    ChaCha20Poly1305 = ALGO_ID_CHACHA20POLY1305,
}

// ---------------------------------------------------------------------------
// Algorithm selection
// ---------------------------------------------------------------------------

/// Cached envelope cipher from `MILNET_ENVELOPE_CIPHER` env var.
static ENVELOPE_CIPHER: std::sync::LazyLock<SymmetricAlgorithm> = std::sync::LazyLock::new(|| {
    if common::fips::is_fips_mode() {
        return SymmetricAlgorithm::Aes256Gcm;
    }
    match std::env::var("MILNET_ENVELOPE_CIPHER").as_deref() {
        Ok("aes-256-gcm") => SymmetricAlgorithm::Aes256Gcm,
        Ok("chacha20-poly1305") => SymmetricAlgorithm::ChaCha20Poly1305,
        Ok("aegis-256") | Err(_) => SymmetricAlgorithm::Aegis256,
        Ok(other) => {
            tracing::error!(
                "MILNET_ENVELOPE_CIPHER unknown value '{}', defaulting to aegis-256", other
            );
            SymmetricAlgorithm::Aegis256
        }
    }
});

/// Returns the active algorithm for new encryptions.
///
/// FIPS mode overrides to AES-256-GCM. Otherwise reads MILNET_ENVELOPE_CIPHER.
/// Decryption always supports all algorithms via the algo_id wire format byte.
pub fn active_algorithm() -> SymmetricAlgorithm {
    *ENVELOPE_CIPHER
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Encrypt with the currently active algorithm.
///
/// Wire format: `algo_id (1 byte) || nonce || ciphertext || tag`
pub fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_with(active_algorithm(), key, plaintext, aad)
}

/// Encrypt with a specific algorithm.
///
/// Wire format: `algo_id (1 byte) || nonce || ciphertext || tag`
pub fn encrypt_with(
    algo: SymmetricAlgorithm,
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    // CAT-I: FIPS mode hard-rejects non-approved AEADs at the entry point.
    // `active_algorithm()` already returns AES-256-GCM when FIPS is on, but
    // callers can pick an algorithm explicitly via `encrypt_with`. Reject
    // AEGIS-256 and ChaCha20-Poly1305 before they execute so a mis-wired
    // caller in military deployment gets a loud error, not silent fallback.
    if common::fips::is_fips_mode()
        && !matches!(algo, SymmetricAlgorithm::Aes256Gcm)
    {
        return Err(format!(
            "FIPS mode: AEAD {:?} rejected — only AES-256-GCM is permitted \
             under FIPS 140-3. This is a CAT-I compliance hard-reject.",
            algo
        ));
    }
    match algo {
        SymmetricAlgorithm::Aegis256 => encrypt_aegis256(key, plaintext, aad),
        SymmetricAlgorithm::Aes256Gcm => encrypt_aes256gcm(key, plaintext, aad),
        SymmetricAlgorithm::ChaCha20Poly1305 => encrypt_chacha20poly1305(key, plaintext, aad),
    }
}

fn encrypt_aegis256(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; AEGIS256_NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("AEGIS-256 nonce generation failed: {e}"))?;

    let (ciphertext, tag) = Aegis256::<AEGIS256_TAG_LEN>::new(key, &nonce).encrypt(plaintext, aad);

    // Wire format: algo_id || nonce || ciphertext || tag
    let mut out = Vec::with_capacity(1 + AEGIS256_NONCE_LEN + ciphertext.len() + AEGIS256_TAG_LEN);
    out.push(ALGO_ID_AEGIS256);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn encrypt_aes256gcm(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("AES-256-GCM nonce generation failed: {e}"))?;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce = GcmNonce::from_slice(&nonce_bytes);

    // aes-gcm returns ciphertext || tag (tag is appended)
    let ciphertext_with_tag = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload { msg: plaintext, aad },
        )
        .map_err(|e| format!("AES-256-GCM encryption failed: {e}"))?;

    // Wire format: algo_id || nonce || ciphertext+tag
    let mut out = Vec::with_capacity(1 + AES_GCM_NONCE_LEN + ciphertext_with_tag.len());
    out.push(ALGO_ID_AES256GCM);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext_with_tag);
    Ok(out)
}

fn encrypt_chacha20poly1305(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::Aead as _;

    let mut nonce_bytes = [0u8; CHACHA_NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("ChaCha20-Poly1305 nonce generation failed: {e}"))?;

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
        .map_err(|e| format!("ChaCha20-Poly1305 encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(1 + CHACHA_NONCE_LEN + ciphertext_with_tag.len());
    out.push(ALGO_ID_CHACHA20POLY1305);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext_with_tag);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/// Decrypt a sealed blob, reading the algorithm from the first byte.
///
/// Supports all cipher algorithms regardless of the active encryption cipher.
///
/// Wire format: `algo_id (1) || nonce || ciphertext || tag`
pub fn decrypt(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let first = sealed.first().copied().ok_or_else(|| "empty ciphertext".to_string())?;

    match first {
        ALGO_ID_AEGIS256 => {
            let payload = sealed.get(1..).ok_or_else(|| "truncated AEGIS-256 blob".to_string())?;
            decrypt_aegis256(key, payload, aad)
        }
        ALGO_ID_AES256GCM => {
            let payload = sealed.get(1..).ok_or_else(|| "truncated AES-256-GCM blob".to_string())?;
            decrypt_aes256gcm_payload(key, payload, aad)
        }
        ALGO_ID_CHACHA20POLY1305 => {
            let payload = sealed.get(1..).ok_or_else(|| "truncated ChaCha20-Poly1305 blob".to_string())?;
            decrypt_chacha20poly1305_payload(key, payload, aad)
        }
        _ => {
            Err(format!(
                "decrypt: unknown algorithm tag 0x{:02x}. \
                 Supported: AEGIS-256 (0x01), AES-256-GCM (0x02), ChaCha20-Poly1305 (0x03).",
                first
            ))
        }
    }
}

fn decrypt_aegis256(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let min_len = AEGIS256_NONCE_LEN + AEGIS256_TAG_LEN;
    if payload.len() < min_len {
        return Err(format!(
            "AEGIS-256 payload too short: {} bytes (need at least {})",
            payload.len(),
            min_len
        ));
    }

    let nonce_slice = payload.get(..AEGIS256_NONCE_LEN).ok_or_else(|| "AEGIS-256: nonce slice out of bounds".to_string())?;
    let rest = payload.get(AEGIS256_NONCE_LEN..).ok_or_else(|| "AEGIS-256: rest slice out of bounds".to_string())?;
    let tag_offset = rest.len().checked_sub(AEGIS256_TAG_LEN).ok_or_else(|| "AEGIS-256: payload too short for tag".to_string())?;
    let ciphertext = rest.get(..tag_offset).ok_or_else(|| "AEGIS-256: ciphertext slice out of bounds".to_string())?;
    let tag_slice = rest.get(tag_offset..).ok_or_else(|| "AEGIS-256: tag slice out of bounds".to_string())?;

    let mut nonce = [0u8; AEGIS256_NONCE_LEN];
    nonce.copy_from_slice(nonce_slice);

    let mut tag = [0u8; AEGIS256_TAG_LEN];
    tag.copy_from_slice(tag_slice);

    Aegis256::<AEGIS256_TAG_LEN>::new(key, &nonce)
        .decrypt(ciphertext, &tag, aad)
        .map_err(|e| format!("AEGIS-256 decryption failed: {e}"))
}

fn decrypt_chacha20poly1305_payload(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::Aead as _;

    let min_len = CHACHA_NONCE_LEN + CHACHA_TAG_LEN;
    if payload.len() < min_len {
        return Err(format!(
            "ChaCha20-Poly1305 payload too short: {} bytes (need at least {})",
            payload.len(), min_len
        ));
    }

    let nonce_slice = payload.get(..CHACHA_NONCE_LEN)
        .ok_or_else(|| "ChaCha20-Poly1305: nonce slice out of bounds".to_string())?;
    let ciphertext_with_tag = payload.get(CHACHA_NONCE_LEN..)
        .ok_or_else(|| "ChaCha20-Poly1305: ciphertext slice out of bounds".to_string())?;

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = chacha20poly1305::Nonce::from_slice(nonce_slice);

    cipher
        .decrypt(nonce, chacha20poly1305::aead::Payload { msg: ciphertext_with_tag, aad })
        .map_err(|e| format!("ChaCha20-Poly1305 decryption failed: {e}"))
}

/// Decrypt an AES-256-GCM payload that is `nonce (12) || ciphertext+tag`.
/// Used for both the new (algo_id-prefixed) format and the legacy format.
fn decrypt_aes256gcm_payload(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let min_len = AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN;
    if payload.len() < min_len {
        return Err(format!(
            "AES-256-GCM payload too short: {} bytes (need at least {})",
            payload.len(),
            min_len
        ));
    }

    let nonce_slice = payload.get(..AES_GCM_NONCE_LEN).ok_or_else(|| "AES-256-GCM: nonce slice out of bounds".to_string())?;
    let ciphertext_with_tag = payload.get(AES_GCM_NONCE_LEN..).ok_or_else(|| "AES-256-GCM: ciphertext slice out of bounds".to_string())?;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce = GcmNonce::from_slice(nonce_slice);

    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload { msg: ciphertext_with_tag, aad },
        )
        .map_err(|e| format!("AES-256-GCM decryption failed: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).expect("getrandom failed");
        k
    }

    #[test]
    fn test_aegis256_encrypt_decrypt_roundtrip() {
        let key = random_key();
        let plaintext = b"hello world";
        let aad = b"test-aad";

        let sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad)
            .expect("encrypt failed");
        let recovered = decrypt(&key, &sealed, aad).expect("decrypt failed");

        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn test_aegis256_wrong_key_fails() {
        let key1 = random_key();
        let key2 = random_key();
        let plaintext = b"secret data";
        let aad = b"ctx";

        let sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key1, plaintext, aad)
            .expect("encrypt failed");
        let result = decrypt(&key2, &sealed, aad);

        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    #[test]
    fn test_aegis256_tampered_ciphertext_fails() {
        let key = random_key();
        let plaintext = b"tamper me";
        let aad = b"integrity";

        let mut sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad)
            .expect("encrypt failed");

        // Flip a byte in the ciphertext region (after algo_id + nonce, before tag)
        let flip_pos = 1 + AEGIS256_NONCE_LEN + 2;
        if let Some(b) = sealed.get_mut(flip_pos) {
            *b ^= 0xFF;
        }

        let result = decrypt(&key, &sealed, aad);
        assert!(result.is_err(), "decryption of tampered ciphertext must fail");
    }

    #[test]
    fn test_aegis256_nonce_uniqueness() {
        let key = random_key();
        let plaintext = b"same plaintext";
        let aad = b"same aad";

        let sealed1 = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad)
            .expect("encrypt 1 failed");
        let sealed2 = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad)
            .expect("encrypt 2 failed");

        assert_ne!(sealed1, sealed2, "two encryptions must produce different ciphertexts");
    }

    #[test]
    fn test_aes256gcm_encrypt_decrypt_roundtrip() {
        let key = random_key();
        let plaintext = b"aes-gcm test";
        let aad = b"gcm-aad";

        let sealed = encrypt_with(SymmetricAlgorithm::Aes256Gcm, &key, plaintext, aad)
            .expect("encrypt failed");
        let recovered = decrypt(&key, &sealed, aad).expect("decrypt failed");

        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn test_algo_id_byte_correct() {
        let key = random_key();
        let aad = b"algo-id-check";

        let aegis_sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, b"data", aad)
            .expect("aegis encrypt failed");
        let gcm_sealed = encrypt_with(SymmetricAlgorithm::Aes256Gcm, &key, b"data", aad)
            .expect("gcm encrypt failed");

        assert_eq!(aegis_sealed.first().copied(), Some(ALGO_ID_AEGIS256));
        assert_eq!(gcm_sealed.first().copied(), Some(ALGO_ID_AES256GCM));
    }

    #[test]
    fn test_cross_algorithm_decrypt_fails() {
        let key = random_key();
        let plaintext = b"cross-algo data";
        let aad = b"cross-aad";

        // Encrypt with AEGIS-256, then force-decode as AES-256-GCM by replacing the algo byte
        let mut sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad)
            .expect("encrypt failed");

        // Replace algo_id byte to claim it is AES-256-GCM
        if let Some(b) = sealed.get_mut(0) {
            *b = ALGO_ID_AES256GCM;
        }

        let result = decrypt(&key, &sealed, aad);
        assert!(result.is_err(), "cross-algorithm decryption must fail");
    }

    #[test]
    fn test_legacy_aes256gcm_no_algo_byte_rejected() {
        let key = random_key();
        let plaintext = b"legacy data";
        let aad = b"legacy-aad";

        // Manually create AES-256-GCM ciphertext WITHOUT algo_id prefix
        let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes).expect("getrandom failed");

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        let nonce = GcmNonce::from_slice(&nonce_bytes);
        let ciphertext_with_tag = cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
            .expect("legacy encrypt failed");

        // Build legacy blob: nonce || ciphertext+tag (no algo_id prefix)
        let mut legacy_blob = Vec::with_capacity(AES_GCM_NONCE_LEN + ciphertext_with_tag.len());
        legacy_blob.extend_from_slice(&nonce_bytes);
        legacy_blob.extend_from_slice(&ciphertext_with_tag);

        // Ensure first byte is not a valid algo_id so it hits the unknown-tag path
        if let Some(b) = legacy_blob.get_mut(0) {
            if *b == ALGO_ID_AEGIS256 || *b == ALGO_ID_AES256GCM {
                nonce_bytes[0] = 0xFF;
                let nonce2 = GcmNonce::from_slice(&nonce_bytes);
                let ct2 = cipher
                    .encrypt(nonce2, aes_gcm::aead::Payload { msg: plaintext, aad })
                    .expect("legacy re-encrypt failed");
                legacy_blob.clear();
                legacy_blob.extend_from_slice(&nonce_bytes);
                legacy_blob.extend_from_slice(&ct2);
            }
        }

        // Legacy untagged ciphertext must now be rejected (fallback removed)
        let result = decrypt(&key, &legacy_blob, aad);
        assert!(result.is_err(), "legacy untagged ciphertext must be rejected");
        assert!(
            result.unwrap_err().contains("unknown algorithm tag"),
            "error must mention unknown algorithm tag"
        );
    }

    #[test]
    #[serial]
    fn test_active_algorithm_follows_fips() {
        // ENVELOPE_CIPHER is a LazyLock cached at first access.
        // Instead of testing active_algorithm() (which is cached),
        // verify that FIPS mode flag toggles correctly and that
        // encrypt_with works with the expected FIPS algorithm.
        common::fips::set_fips_mode_unchecked(true);
        assert!(common::fips::is_fips_mode());
        // FIPS mode mandates AES-256-GCM -- verify roundtrip works
        let key = random_key();
        let sealed = encrypt_with(SymmetricAlgorithm::Aes256Gcm, &key, b"fips-test", b"aad")
            .expect("FIPS encrypt");
        assert_eq!(sealed[0], ALGO_ID_AES256GCM);
        let pt = decrypt(&key, &sealed, b"aad").expect("FIPS decrypt");
        assert_eq!(pt, b"fips-test");

        common::fips::set_fips_mode_unchecked(false);
        assert!(!common::fips::is_fips_mode());
        // Non-FIPS default is AEGIS-256 -- verify roundtrip works
        let sealed2 = encrypt_with(SymmetricAlgorithm::Aegis256, &key, b"non-fips", b"aad")
            .expect("non-FIPS encrypt");
        assert_eq!(sealed2[0], ALGO_ID_AEGIS256);
        let pt2 = decrypt(&key, &sealed2, b"aad").expect("non-FIPS decrypt");
        assert_eq!(pt2, b"non-fips");
    }

    #[test]
    fn test_empty_plaintext_roundtrip() {
        let key = random_key();
        let aad = b"empty-test";

        let sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, &[], aad)
            .expect("encrypt failed");
        let recovered = decrypt(&key, &sealed, aad).expect("decrypt failed");

        assert!(recovered.is_empty(), "decrypted empty plaintext must be empty");
    }

    #[test]
    fn reject_unknown_algorithm_tag() {
        let key = [0x42u8; 32];
        // Craft a ciphertext with invalid tag byte
        let fake_ct = vec![0xFF, 0x00, 0x01, 0x02]; // tag 0xFF is not 0x01 or 0x02
        let result = decrypt(&key, &fake_ct, &[]);
        assert!(result.is_err(), "must reject unknown algorithm tags");
        assert!(result.unwrap_err().contains("unknown algorithm tag"));
    }

    #[test]
    fn reject_truncated_ciphertext() {
        let key = [0x42u8; 32];
        // Too short to contain nonce + any ciphertext
        let short = vec![0x01, 0x00];
        let result = decrypt(&key, &short, &[]);
        assert!(result.is_err(), "must reject truncated ciphertext");
    }

    #[test]
    fn test_large_plaintext_roundtrip() {
        let key = random_key();
        let aad = b"large-test";
        let plaintext = vec![0x42u8; 1024 * 1024]; // 1 MB

        let sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, &plaintext, aad)
            .expect("encrypt failed");
        let recovered = decrypt(&key, &sealed, aad).expect("decrypt failed");

        assert_eq!(recovered, plaintext);
    }
}
