#![forbid(unsafe_code)]

//! Envelope encryption for protecting data at rest.
//!
//! Every sensitive database field is encrypted with a unique Data Encryption Key (DEK).
//! DEKs are wrapped (encrypted) by a Key Encryption Key (KEK) for secure storage.
//!
//! Uses AEGIS-256 by default (non-FIPS) or AES-256-GCM in FIPS mode.
//! Wire format (new): algo_id (1 byte) || nonce || ciphertext || tag.
//! Wire format (legacy/wrap): 12-byte nonce || ciphertext || 16-byte GCM tag.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES-GCM nonce length in bytes (96 bits per SP 800-38D).
const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length in bytes (128 bits).
const TAG_LEN: usize = 16;

/// AES-256 key length in bytes.
const KEY_LEN: usize = 32;

/// Minimum sealed-data length: nonce + tag (ciphertext may be empty for empty plaintext).
const MIN_SEALED_LEN: usize = NONCE_LEN + TAG_LEN;

/// AAD used when wrapping/unwrapping DEKs under a KEK.
const KEK_WRAP_AAD: &[u8] = b"MILNET-KEK-WRAP-v1";

/// Prefix for field-level AAD construction.
const AAD_PREFIX: &[u8] = b"MILNET-AAD-v1:";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by envelope encryption operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// AES-GCM encryption failed (should be rare outside resource exhaustion).
    EncryptionFailed,
    /// AES-GCM decryption failed — wrong key, corrupted ciphertext, or AAD mismatch.
    DecryptionFailed,
    /// The byte slice provided to `SealedData::from_bytes` is too short.
    InvalidSealedData,
    /// The byte slice provided to `WrappedKey::from_bytes` is too short.
    InvalidWrappedKey,
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "AES-256-GCM encryption failed"),
            Self::DecryptionFailed => write!(f, "AES-256-GCM decryption failed"),
            Self::InvalidSealedData => write!(f, "sealed data too short or malformed"),
            Self::InvalidWrappedKey => write!(f, "wrapped key too short or malformed"),
        }
    }
}

// ---------------------------------------------------------------------------
// DataEncryptionKey
// ---------------------------------------------------------------------------

/// A 256-bit data encryption key with automatic zeroization on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey([u8; KEY_LEN]);

impl core::fmt::Debug for DataEncryptionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DataEncryptionKey([REDACTED])")
    }
}

impl DataEncryptionKey {
    /// Generate a fresh DEK from the OS CSPRNG (`getrandom`).
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_LEN];
        getrandom::getrandom(&mut key).expect("OS CSPRNG failure");
        Self(key)
    }

    /// Construct from an existing 32-byte array.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw key material.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// KeyEncryptionKey
// ---------------------------------------------------------------------------

/// A 256-bit key encryption key with automatic zeroization on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyEncryptionKey([u8; KEY_LEN]);

impl KeyEncryptionKey {
    /// Generate a fresh KEK from the OS CSPRNG (`getrandom`).
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_LEN];
        getrandom::getrandom(&mut key).expect("OS CSPRNG failure");
        Self(key)
    }

    /// Construct from an existing 32-byte array.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
}

// ---------------------------------------------------------------------------
// SealedData
// ---------------------------------------------------------------------------

/// Sealed (encrypted) payload: nonce (12) || ciphertext || tag (16).
#[derive(Clone, Debug)]
pub struct SealedData {
    bytes: Vec<u8>,
}

impl SealedData {
    /// Return the raw sealed bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reconstruct from a byte vector, validating minimum length.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, EnvelopeError> {
        if bytes.len() < MIN_SEALED_LEN {
            return Err(EnvelopeError::InvalidSealedData);
        }
        Ok(Self { bytes })
    }

    /// The 12-byte nonce that was used for this encryption.
    pub fn nonce(&self) -> &[u8] {
        &self.bytes[..NONCE_LEN]
    }
}

// ---------------------------------------------------------------------------
// WrappedKey
// ---------------------------------------------------------------------------

/// A DEK encrypted (wrapped) under a KEK: nonce (12) || encrypted_dek || tag (16).
#[derive(Clone, Debug)]
pub struct WrappedKey {
    bytes: Vec<u8>,
}

impl WrappedKey {
    /// Return the raw wrapped-key bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reconstruct from a byte vector, validating minimum length.
    ///
    /// A wrapped 32-byte DEK must be at least `NONCE_LEN + KEY_LEN + TAG_LEN` bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, EnvelopeError> {
        if bytes.len() < NONCE_LEN + KEY_LEN + TAG_LEN {
            return Err(EnvelopeError::InvalidWrappedKey);
        }
        Ok(Self { bytes })
    }
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` under `dek` with the given AAD.
///
/// Uses AEGIS-256 (non-FIPS) or AES-256-GCM (FIPS mode).
/// Wire format: `algo_id (1) || nonce || ciphertext || tag`.
pub fn encrypt(
    dek: &DataEncryptionKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedData, EnvelopeError> {
    let bytes = crate::symmetric::encrypt(dek.as_bytes(), plaintext, aad)
        .map_err(|_| EnvelopeError::EncryptionFailed)?;
    Ok(SealedData { bytes })
}

/// Decrypt `sealed` using `dek` and the given AAD.
///
/// Handles both the new algo_id-prefixed format and the legacy
/// `nonce (12) || ciphertext+tag` AES-256-GCM format.
///
/// Returns the original plaintext or an error if authentication fails.
pub fn decrypt(
    dek: &DataEncryptionKey,
    sealed: &SealedData,
    aad: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    crate::symmetric::decrypt(dek.as_bytes(), sealed.to_bytes(), aad)
        .map_err(|_| EnvelopeError::DecryptionFailed)
}

/// Wrap (encrypt) a DEK under a KEK for secure storage.
///
/// Uses a fixed AAD (`MILNET-KEK-WRAP-v1`) to bind the ciphertext to its purpose.
pub fn wrap_key(
    kek: &KeyEncryptionKey,
    dek: &DataEncryptionKey,
) -> Result<WrappedKey, EnvelopeError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).expect("OS CSPRNG failure");

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&kek.0));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: dek.as_bytes(),
                aad: KEK_WRAP_AAD,
            },
        )
        .map_err(|_| EnvelopeError::EncryptionFailed)?;

    let mut wrapped = Vec::with_capacity(NONCE_LEN + ciphertext_with_tag.len());
    wrapped.extend_from_slice(&nonce_bytes);
    wrapped.extend_from_slice(&ciphertext_with_tag);

    Ok(WrappedKey { bytes: wrapped })
}

/// Unwrap (decrypt) a DEK that was previously wrapped under a KEK.
pub fn unwrap_key(
    kek: &KeyEncryptionKey,
    wrapped: &WrappedKey,
) -> Result<DataEncryptionKey, EnvelopeError> {
    let raw = wrapped.to_bytes();
    let nonce_bytes = &raw[..NONCE_LEN];
    let ciphertext_with_tag = &raw[NONCE_LEN..];

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&kek.0));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext_with_tag,
                aad: KEK_WRAP_AAD,
            },
        )
        .map_err(|_| EnvelopeError::DecryptionFailed)?;

    if plaintext.len() != KEY_LEN {
        return Err(EnvelopeError::DecryptionFailed);
    }

    let mut key_bytes = [0u8; KEY_LEN];
    key_bytes.copy_from_slice(&plaintext);
    Ok(DataEncryptionKey::from_bytes(key_bytes))
}

/// Build context-binding AAD for a specific database field.
///
/// Format: `MILNET-AAD-v1:<table>:<column>:<row_id>`
pub fn build_aad(table: &str, column: &str, row_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        AAD_PREFIX.len() + table.len() + 1 + column.len() + 1 + row_id.len(),
    );
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(table.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(column.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(row_id);
    aad
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate a DEK and encrypt/decrypt round-trip.
    #[test]
    fn round_trip_encrypt_decrypt() {
        let dek = DataEncryptionKey::generate();
        let plaintext = b"TOP SECRET: launch codes alpha-7";
        let aad = build_aad("credentials", "secret", b"row-42");

        let sealed = encrypt(&dek, plaintext, &aad).expect("encrypt");
        let recovered = decrypt(&dek, &sealed, &aad).expect("decrypt");

        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let dek = DataEncryptionKey::generate();
        let aad = b"context";

        let sealed = encrypt(&dek, b"", aad).expect("encrypt");
        let recovered = decrypt(&dek, &sealed, aad).expect("decrypt");

        assert!(recovered.is_empty());
    }

    #[test]
    fn aad_mismatch_fails() {
        let dek = DataEncryptionKey::generate();
        let plaintext = b"sensitive payload";
        let aad_good = build_aad("users", "password_hash", b"u-1");
        let aad_bad = build_aad("users", "password_hash", b"u-2");

        let sealed = encrypt(&dek, plaintext, &aad_good).expect("encrypt");
        let result = decrypt(&dek, &sealed, &aad_bad);

        assert_eq!(result.unwrap_err(), EnvelopeError::DecryptionFailed);
    }

    #[test]
    fn wrong_key_fails() {
        let dek1 = DataEncryptionKey::generate();
        let dek2 = DataEncryptionKey::generate();
        let plaintext = b"classified data";
        let aad = b"context";

        let sealed = encrypt(&dek1, plaintext, aad).expect("encrypt");
        let result = decrypt(&dek2, &sealed, aad);

        assert_eq!(result.unwrap_err(), EnvelopeError::DecryptionFailed);
    }

    #[test]
    fn nonce_uniqueness() {
        let dek = DataEncryptionKey::generate();
        let plaintext = b"same plaintext twice";
        let aad = b"same aad";

        let sealed1 = encrypt(&dek, plaintext, aad).expect("encrypt 1");
        let sealed2 = encrypt(&dek, plaintext, aad).expect("encrypt 2");

        // Different nonces means different ciphertext.
        assert_ne!(sealed1.to_bytes(), sealed2.to_bytes());

        // But both decrypt to the same plaintext.
        assert_eq!(
            decrypt(&dek, &sealed1, aad).unwrap(),
            decrypt(&dek, &sealed2, aad).unwrap()
        );
    }

    #[test]
    fn key_wrap_unwrap_round_trip() {
        let kek = KeyEncryptionKey::generate();
        let dek = DataEncryptionKey::generate();
        let original_bytes = *dek.as_bytes();

        let wrapped = wrap_key(&kek, &dek).expect("wrap");
        let recovered = unwrap_key(&kek, &wrapped).expect("unwrap");

        assert_eq!(recovered.as_bytes(), &original_bytes);
    }

    #[test]
    fn wrong_kek_fails() {
        let kek1 = KeyEncryptionKey::generate();
        let kek2 = KeyEncryptionKey::generate();
        let dek = DataEncryptionKey::generate();

        let wrapped = wrap_key(&kek1, &dek).expect("wrap");
        let result = unwrap_key(&kek2, &wrapped);

        assert_eq!(result.unwrap_err(), EnvelopeError::DecryptionFailed);
    }

    #[test]
    fn sealed_data_min_length_validation() {
        // Less than NONCE_LEN + TAG_LEN = 28 bytes should fail.
        let too_short = vec![0u8; MIN_SEALED_LEN - 1];
        assert_eq!(
            SealedData::from_bytes(too_short).unwrap_err(),
            EnvelopeError::InvalidSealedData,
        );

        // Exactly MIN_SEALED_LEN is valid (empty plaintext case).
        let just_right = vec![0u8; MIN_SEALED_LEN];
        assert!(SealedData::from_bytes(just_right).is_ok());
    }

    #[test]
    fn wrapped_key_min_length_validation() {
        // Wrapped key must be at least NONCE_LEN + KEY_LEN + TAG_LEN = 60 bytes.
        let min_len = NONCE_LEN + KEY_LEN + TAG_LEN;

        let too_short = vec![0u8; min_len - 1];
        assert_eq!(
            WrappedKey::from_bytes(too_short).unwrap_err(),
            EnvelopeError::InvalidWrappedKey,
        );

        let just_right = vec![0u8; min_len];
        assert!(WrappedKey::from_bytes(just_right).is_ok());
    }

    #[test]
    fn sealed_data_round_trip_serialization() {
        let dek = DataEncryptionKey::generate();
        let plaintext = b"serialization test";
        let aad = b"ctx";

        let sealed = encrypt(&dek, plaintext, aad).expect("encrypt");
        let raw = sealed.to_bytes().to_vec();
        let restored = SealedData::from_bytes(raw).expect("from_bytes");
        let recovered = decrypt(&dek, &restored, aad).expect("decrypt");

        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn wrapped_key_round_trip_serialization() {
        let kek = KeyEncryptionKey::generate();
        let dek = DataEncryptionKey::generate();
        let original_bytes = *dek.as_bytes();

        let wrapped = wrap_key(&kek, &dek).expect("wrap");
        let raw = wrapped.to_bytes().to_vec();
        let restored = WrappedKey::from_bytes(raw).expect("from_bytes");
        let recovered = unwrap_key(&kek, &restored).expect("unwrap");

        assert_eq!(recovered.as_bytes(), &original_bytes);
    }

    #[test]
    fn build_aad_format() {
        let aad = build_aad("sessions", "token", b"\x01\x02\x03");
        let expected = b"MILNET-AAD-v1:sessions:token:\x01\x02\x03";
        assert_eq!(aad.as_slice(), expected.as_slice());
    }

    #[test]
    fn sealed_data_nonce_accessor() {
        let dek = DataEncryptionKey::generate();
        let sealed = encrypt(&dek, b"data", b"aad").expect("encrypt");

        let nonce = sealed.nonce();
        assert_eq!(nonce.len(), NONCE_LEN);
        // The nonce should match the first 12 bytes of the raw output.
        assert_eq!(nonce, &sealed.to_bytes()[..NONCE_LEN]);
    }

    #[test]
    fn dek_from_bytes() {
        let raw = [0xABu8; KEY_LEN];
        let dek = DataEncryptionKey::from_bytes(raw);
        assert_eq!(dek.as_bytes(), &raw);
    }

    #[test]
    fn kek_from_bytes() {
        let raw = [0xCDu8; KEY_LEN];
        let kek = KeyEncryptionKey::from_bytes(raw);
        // Verify via wrap/unwrap that the key works.
        let dek = DataEncryptionKey::generate();
        let wrapped = wrap_key(&kek, &dek).expect("wrap");
        let recovered = unwrap_key(&kek, &wrapped).expect("unwrap");
        assert_eq!(recovered.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dek = DataEncryptionKey::generate();
        let aad = b"integrity check";
        let sealed = encrypt(&dek, b"tamper me", aad).expect("encrypt");

        let mut tampered = sealed.to_bytes().to_vec();
        // Flip a byte in the ciphertext region (after nonce, before tag).
        if tampered.len() > NONCE_LEN + 1 {
            tampered[NONCE_LEN] ^= 0xFF;
        }
        let bad_sealed = SealedData::from_bytes(tampered).expect("from_bytes");
        let result = decrypt(&dek, &bad_sealed, aad);

        assert_eq!(result.unwrap_err(), EnvelopeError::DecryptionFailed);
    }

    // -- AEGIS-256 / FIPS / legacy compat -----------------------------------

    #[test]
    fn test_envelope_aegis256_roundtrip() {
        common::fips::set_fips_mode_unchecked(false);
        let dek = DataEncryptionKey::generate();
        let plaintext = b"aegis-256-envelope-test-data";
        let aad = build_aad("users", "secret", b"u-aegis-1");

        let sealed = encrypt(&dek, plaintext, &aad).expect("encrypt");
        // New format starts with AEGIS-256 algo_id byte
        assert_eq!(
            sealed.to_bytes().first().copied(),
            Some(crate::symmetric::ALGO_ID_AEGIS256)
        );
        let recovered = decrypt(&dek, &sealed, &aad).expect("decrypt");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn test_envelope_fips_fallback() {
        common::fips::set_fips_mode_unchecked(true);
        let dek = DataEncryptionKey::generate();
        let plaintext = b"fips-envelope-test-data";
        let aad = build_aad("users", "secret", b"u-fips-1");

        let sealed = encrypt(&dek, plaintext, &aad).expect("encrypt");
        // FIPS mode uses AES-256-GCM
        assert_eq!(
            sealed.to_bytes().first().copied(),
            Some(crate::symmetric::ALGO_ID_AES256GCM)
        );
        let recovered = decrypt(&dek, &sealed, &aad).expect("decrypt");
        assert_eq!(recovered.as_slice(), plaintext);
        common::fips::set_fips_mode_unchecked(false);
    }

    #[test]
    fn test_envelope_legacy_backward_compat() {
        // Build a legacy AES-256-GCM blob (no algo_id prefix): nonce (12) || ct+tag
        common::fips::set_fips_mode_unchecked(false);
        let dek = DataEncryptionKey::generate();
        let plaintext = b"legacy-envelope-data";
        let aad = build_aad("sessions", "token", b"s-legacy-1");

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes).expect("getrandom");
        let cipher = Aes256Gcm::new(GenericArray::from_slice(dek.as_bytes()));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad: &aad })
            .expect("legacy encrypt");

        let mut legacy_bytes = Vec::with_capacity(NONCE_LEN + ct.len());
        legacy_bytes.extend_from_slice(&nonce_bytes);
        legacy_bytes.extend_from_slice(&ct);

        // Ensure first byte is not 0x01 or 0x02
        if legacy_bytes.first().copied() == Some(crate::symmetric::ALGO_ID_AEGIS256)
            || legacy_bytes.first().copied() == Some(crate::symmetric::ALGO_ID_AES256GCM)
        {
            nonce_bytes[0] = 0xFF;
            let nonce2 = Nonce::from_slice(&nonce_bytes);
            let ct2 = cipher
                .encrypt(nonce2, aes_gcm::aead::Payload { msg: plaintext, aad: &aad })
                .expect("legacy re-encrypt");
            legacy_bytes.clear();
            legacy_bytes.extend_from_slice(&nonce_bytes);
            legacy_bytes.extend_from_slice(&ct2);
        }

        let legacy_sealed = SealedData::from_bytes(legacy_bytes).expect("from_bytes");
        let recovered = decrypt(&dek, &legacy_sealed, &aad).expect("legacy decrypt");
        assert_eq!(recovered.as_slice(), plaintext);
    }
}
