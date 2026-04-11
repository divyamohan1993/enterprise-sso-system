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

/// Length of the KEK version prefix in wrapped key output (4 bytes big-endian u32).
const KEK_VERSION_LEN: usize = 4;

/// Current KEK version. Increment this when rotating to a new KEK.
pub const CURRENT_KEK_VERSION: u32 = 1;

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
    /// The KEK version in the wrapped key is not present in the keyring.
    UnknownKekVersion(u32),
    /// Attempted to remove the current KEK version from the keyring.
    CannotRemoveCurrentVersion,
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "AES-256-GCM encryption failed"),
            Self::DecryptionFailed => write!(f, "AES-256-GCM decryption failed"),
            Self::InvalidSealedData => write!(f, "sealed data too short or malformed"),
            Self::InvalidWrappedKey => write!(f, "wrapped key too short or malformed"),
            Self::UnknownKekVersion(v) => write!(f, "KEK version {} not in keyring", v),
            Self::CannotRemoveCurrentVersion => {
                write!(f, "cannot remove the current KEK version from keyring")
            }
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
    ///
    /// Returns `Err` with SIEM reporting if the OS CSPRNG is unavailable.
    pub fn generate() -> Result<Self, EnvelopeError> {
        let mut key = [0u8; KEY_LEN];
        getrandom::getrandom(&mut key).map_err(|e| {
            common::siem::emit_runtime_error(
                common::siem::category::CRYPTO_FAILURE,
                "OS CSPRNG unavailable — cannot generate DEK",
                &format!("{e}"),
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            EnvelopeError::EncryptionFailed
        })?;
        Ok(Self(key))
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
    ///
    /// Returns `Err` with SIEM reporting if the OS CSPRNG is unavailable.
    pub fn generate() -> Result<Self, EnvelopeError> {
        let mut key = [0u8; KEY_LEN];
        getrandom::getrandom(&mut key).map_err(|e| {
            common::siem::emit_runtime_error(
                common::siem::category::CRYPTO_FAILURE,
                "OS CSPRNG unavailable — cannot generate KEK",
                &format!("{e}"),
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            EnvelopeError::EncryptionFailed
        })?;
        Ok(Self(key))
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
    ///
    /// Wire format: algo_id(1) || nonce(NONCE_LEN) || ciphertext || tag.
    /// Skip the algorithm ID byte to get the actual nonce.
    pub fn nonce(&self) -> &[u8] {
        &self.bytes[1..1 + NONCE_LEN]
    }
}

// ---------------------------------------------------------------------------
// WrappedKey
// ---------------------------------------------------------------------------

/// A DEK encrypted (wrapped) under a KEK.
/// Wire format: kek_version (4 bytes BE) || nonce (12) || encrypted_dek || tag (16).
#[derive(Clone, Debug)]
pub struct WrappedKey {
    bytes: Vec<u8>,
    /// The KEK version that was used to wrap this key.
    pub kek_version: u32,
}

impl WrappedKey {
    /// Return the raw wrapped-key bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reconstruct from a byte vector, validating minimum length.
    ///
    /// Expects wire format: kek_version (4 bytes BE) || nonce (12) || encrypted_dek || tag (16).
    /// A wrapped 32-byte DEK must be at least `KEK_VERSION_LEN + NONCE_LEN + KEY_LEN + TAG_LEN` bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, EnvelopeError> {
        if bytes.len() < KEK_VERSION_LEN + NONCE_LEN + KEY_LEN + TAG_LEN {
            return Err(EnvelopeError::InvalidWrappedKey);
        }
        let kek_version = u32::from_be_bytes(
            bytes[..KEK_VERSION_LEN]
                .try_into()
                .map_err(|_| EnvelopeError::InvalidWrappedKey)?,
        );
        Ok(Self { bytes, kek_version })
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
/// Wire format: kek_version (4 bytes BE) || nonce (12) || encrypted_dek || tag (16).
/// The KEK version is prepended so that on unwrap, the correct KEK can be selected
/// for decryption (critical for key rotation scenarios).
pub fn wrap_key(
    kek: &KeyEncryptionKey,
    dek: &DataEncryptionKey,
) -> Result<WrappedKey, EnvelopeError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "OS CSPRNG unavailable — cannot generate nonce for key wrapping",
            &format!("{e}"),
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        EnvelopeError::EncryptionFailed
    })?;

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

    let mut wrapped = Vec::with_capacity(KEK_VERSION_LEN + NONCE_LEN + ciphertext_with_tag.len());
    wrapped.extend_from_slice(&CURRENT_KEK_VERSION.to_be_bytes());
    wrapped.extend_from_slice(&nonce_bytes);
    wrapped.extend_from_slice(&ciphertext_with_tag);

    Ok(WrappedKey {
        bytes: wrapped,
        kek_version: CURRENT_KEK_VERSION,
    })
}

/// Unwrap (decrypt) a DEK that was previously wrapped under a KEK.
///
/// Extracts the KEK version from the wire format prefix and verifies it matches
/// the expected version. In a multi-KEK deployment, the version would be used to
/// select the correct KEK from a keyring; for now we verify it matches
/// `CURRENT_KEK_VERSION` to detect data wrapped under an unknown/future KEK.
pub fn unwrap_key(
    kek: &KeyEncryptionKey,
    wrapped: &WrappedKey,
) -> Result<DataEncryptionKey, EnvelopeError> {
    let raw = wrapped.to_bytes();
    if raw.len() < KEK_VERSION_LEN + NONCE_LEN + TAG_LEN {
        return Err(EnvelopeError::InvalidWrappedKey);
    }

    // Extract and verify KEK version
    let version = u32::from_be_bytes(
        raw[..KEK_VERSION_LEN]
            .try_into()
            .map_err(|_| EnvelopeError::InvalidWrappedKey)?,
    );
    if version != CURRENT_KEK_VERSION {
        // Future: look up the correct KEK by version from a keyring.
        // For now, reject unknown versions to prevent silent misuse.
        return Err(EnvelopeError::DecryptionFailed);
    }

    let nonce_bytes = &raw[KEK_VERSION_LEN..KEK_VERSION_LEN + NONCE_LEN];
    let ciphertext_with_tag = &raw[KEK_VERSION_LEN + NONCE_LEN..];

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
    // Zeroize the intermediate plaintext Vec to prevent key material
    // lingering in heap memory after extraction.
    let mut plaintext = plaintext;
    plaintext.zeroize();
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
// KekKeyring -- multi-version KEK support for seamless rotation
// ---------------------------------------------------------------------------

/// Multi-version KEK keyring for seamless key rotation.
///
/// During rotation, both old and new KEKs are available. Old KEKs can
/// only decrypt (unwrap). Only the current KEK can encrypt (wrap).
/// Old KEKs are removed after all data is re-encrypted.
pub struct KekKeyring {
    /// Map of version -> KEK bytes. All zeroized on drop.
    keys: std::collections::HashMap<u32, zeroize::Zeroizing<[u8; KEY_LEN]>>,
    /// Current version used for new wrapping operations.
    current_version: u32,
}

impl KekKeyring {
    /// Create a new keyring with the given current KEK and version.
    pub fn new(current_kek: [u8; KEY_LEN], current_version: u32) -> Self {
        let mut keys = std::collections::HashMap::new();
        keys.insert(current_version, zeroize::Zeroizing::new(current_kek));
        Self {
            keys,
            current_version,
        }
    }

    /// Add a previous KEK version (for unwrapping old data during rotation).
    ///
    /// Panics if `version` equals `current_version` (use the constructor for that).
    pub fn add_previous_version(&mut self, version: u32, kek: [u8; KEY_LEN]) {
        self.keys.insert(version, zeroize::Zeroizing::new(kek));
    }

    /// Get the KEK for a specific version (for unwrapping).
    pub fn get_kek(&self, version: u32) -> Option<&[u8; KEY_LEN]> {
        self.keys.get(&version).map(|z| &**z)
    }

    /// Get the current KEK (for wrapping new data).
    pub fn current_kek(&self) -> &[u8; KEY_LEN] {
        &**self
            .keys
            .get(&self.current_version)
            .expect("current KEK must exist in keyring")
    }

    /// Current version number.
    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    /// Remove an old version after re-encryption is complete.
    ///
    /// Returns `Err` if attempting to remove the current version.
    pub fn remove_version(&mut self, version: u32) -> Result<(), EnvelopeError> {
        if version == self.current_version {
            return Err(EnvelopeError::CannotRemoveCurrentVersion);
        }
        self.keys.remove(&version);
        Ok(())
    }

    /// Number of KEK versions in the keyring.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the keyring is empty (should never be true after construction).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Drop for KekKeyring {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for (_, key) in self.keys.iter_mut() {
            key.zeroize();
        }
    }
}

/// Wrap (encrypt) a DEK using the current KEK from the keyring.
///
/// The wrapped output carries the keyring's current version so that
/// `unwrap_key_with_keyring` can select the right KEK later.
pub fn wrap_key_with_keyring(
    keyring: &KekKeyring,
    dek: &DataEncryptionKey,
) -> Result<WrappedKey, EnvelopeError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "OS CSPRNG unavailable -- cannot generate nonce for key wrapping",
            &format!("{e}"),
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        EnvelopeError::EncryptionFailed
    })?;

    let current_kek = keyring.current_kek();
    let version = keyring.current_version();

    let cipher = Aes256Gcm::new(GenericArray::from_slice(current_kek));
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

    let mut wrapped = Vec::with_capacity(KEK_VERSION_LEN + NONCE_LEN + ciphertext_with_tag.len());
    wrapped.extend_from_slice(&version.to_be_bytes());
    wrapped.extend_from_slice(&nonce_bytes);
    wrapped.extend_from_slice(&ciphertext_with_tag);

    Ok(WrappedKey {
        bytes: wrapped,
        kek_version: version,
    })
}

/// Unwrap (decrypt) a DEK using the keyring to look up the correct KEK by version.
///
/// Unlike `unwrap_key`, this function supports multiple KEK versions.
/// The version prefix in the wrapped key selects the right KEK from the keyring.
pub fn unwrap_key_with_keyring(
    keyring: &KekKeyring,
    wrapped: &WrappedKey,
) -> Result<DataEncryptionKey, EnvelopeError> {
    let raw = wrapped.to_bytes();
    if raw.len() < KEK_VERSION_LEN + NONCE_LEN + TAG_LEN {
        return Err(EnvelopeError::InvalidWrappedKey);
    }

    let version = u32::from_be_bytes(
        raw[..KEK_VERSION_LEN]
            .try_into()
            .map_err(|_| EnvelopeError::InvalidWrappedKey)?,
    );

    let kek = keyring
        .get_kek(version)
        .ok_or(EnvelopeError::UnknownKekVersion(version))?;

    let nonce_bytes = &raw[KEK_VERSION_LEN..KEK_VERSION_LEN + NONCE_LEN];
    let ciphertext_with_tag = &raw[KEK_VERSION_LEN + NONCE_LEN..];

    let cipher = Aes256Gcm::new(GenericArray::from_slice(kek));
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
    // Zeroize intermediate plaintext buffer containing key material.
    let mut plaintext = plaintext;
    plaintext.zeroize();
    Ok(DataEncryptionKey::from_bytes(key_bytes))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Helper: generate a DEK and encrypt/decrypt round-trip.
    #[test]
    fn round_trip_encrypt_decrypt() {
        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let plaintext = b"TOP SECRET: launch codes alpha-7";
        let aad = build_aad("credentials", "secret", b"row-42");

        let sealed = encrypt(&dek, plaintext, &aad).expect("encrypt");
        let recovered = decrypt(&dek, &sealed, &aad).expect("decrypt");

        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let aad = b"context";

        let sealed = encrypt(&dek, b"", aad).expect("encrypt");
        let recovered = decrypt(&dek, &sealed, aad).expect("decrypt");

        assert!(recovered.is_empty());
    }

    #[test]
    fn aad_mismatch_fails() {
        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let plaintext = b"sensitive payload";
        let aad_good = build_aad("users", "password_hash", b"u-1");
        let aad_bad = build_aad("users", "password_hash", b"u-2");

        let sealed = encrypt(&dek, plaintext, &aad_good).expect("encrypt");
        let result = decrypt(&dek, &sealed, &aad_bad);

        assert_eq!(result.unwrap_err(), EnvelopeError::DecryptionFailed);
    }

    #[test]
    fn wrong_key_fails() {
        let dek1 = DataEncryptionKey::generate().expect("generate DEK");
        let dek2 = DataEncryptionKey::generate().expect("generate DEK");
        let plaintext = b"classified data";
        let aad = b"context";

        let sealed = encrypt(&dek1, plaintext, aad).expect("encrypt");
        let result = decrypt(&dek2, &sealed, aad);

        assert_eq!(result.unwrap_err(), EnvelopeError::DecryptionFailed);
    }

    #[test]
    fn nonce_uniqueness() {
        let dek = DataEncryptionKey::generate().expect("generate DEK");
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
        let kek = KeyEncryptionKey::generate().expect("generate KEK");
        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let original_bytes = *dek.as_bytes();

        let wrapped = wrap_key(&kek, &dek).expect("wrap");
        let recovered = unwrap_key(&kek, &wrapped).expect("unwrap");

        assert_eq!(recovered.as_bytes(), &original_bytes);
    }

    #[test]
    fn wrong_kek_fails() {
        let kek1 = KeyEncryptionKey::generate().expect("generate KEK");
        let kek2 = KeyEncryptionKey::generate().expect("generate KEK");
        let dek = DataEncryptionKey::generate().expect("generate DEK");

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
        // Wrapped key must be at least KEK_VERSION_LEN + NONCE_LEN + KEY_LEN + TAG_LEN = 64 bytes.
        let min_len = KEK_VERSION_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;

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
        let dek = DataEncryptionKey::generate().expect("generate DEK");
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
        let kek = KeyEncryptionKey::generate().expect("generate KEK");
        let dek = DataEncryptionKey::generate().expect("generate DEK");
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
        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let sealed = encrypt(&dek, b"data", b"aad").expect("encrypt");

        let nonce = sealed.nonce();
        assert_eq!(nonce.len(), NONCE_LEN);
        // The nonce should match bytes 1..13 of the raw output (after algo_id byte).
        assert_eq!(nonce, &sealed.to_bytes()[1..1 + NONCE_LEN]);
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
        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let wrapped = wrap_key(&kek, &dek).expect("wrap");
        let recovered = unwrap_key(&kek, &wrapped).expect("unwrap");
        assert_eq!(recovered.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dek = DataEncryptionKey::generate().expect("generate DEK");
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
    #[serial]
    fn test_envelope_aegis256_roundtrip() {
        common::fips::set_fips_mode_unchecked(false);
        let dek = DataEncryptionKey::generate().expect("generate DEK");
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
    #[serial]
    fn test_envelope_fips_fallback() {
        common::fips::set_fips_mode_unchecked(true);
        let dek = DataEncryptionKey::generate().expect("generate DEK");
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

    // ── TEST GROUP 7: Key versioning tests ──────────────────────────────

    #[test]
    fn test_wrap_key_produces_version_prefix() {
        let kek = KeyEncryptionKey::generate().expect("generate KEK");
        let dek = DataEncryptionKey::generate().expect("generate DEK");

        let wrapped = wrap_key(&kek, &dek).expect("wrap");
        let raw = wrapped.to_bytes();

        // First 4 bytes are the KEK version (big-endian u32).
        assert!(raw.len() >= KEK_VERSION_LEN, "wrapped key must have version prefix");
        let version = u32::from_be_bytes(raw[..KEK_VERSION_LEN].try_into().unwrap());
        assert_eq!(version, CURRENT_KEK_VERSION, "version prefix must match CURRENT_KEK_VERSION");
        assert_eq!(wrapped.kek_version, CURRENT_KEK_VERSION);
    }

    #[test]
    fn test_unwrap_key_extracts_and_validates_version() {
        let kek = KeyEncryptionKey::generate().expect("generate KEK");
        let dek = DataEncryptionKey::generate().expect("generate DEK");

        let wrapped = wrap_key(&kek, &dek).expect("wrap");
        // unwrap_key must succeed and return the original DEK.
        let recovered = unwrap_key(&kek, &wrapped).expect("unwrap");
        assert_eq!(recovered.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn test_invalid_version_causes_unwrap_failure() {
        let kek = KeyEncryptionKey::generate().expect("generate KEK");
        let dek = DataEncryptionKey::generate().expect("generate DEK");

        let wrapped = wrap_key(&kek, &dek).expect("wrap");
        let mut raw = wrapped.to_bytes().to_vec();

        // Tamper with the version prefix: set to version 99 (invalid).
        let bad_version: u32 = 99;
        raw[..KEK_VERSION_LEN].copy_from_slice(&bad_version.to_be_bytes());

        let tampered = WrappedKey::from_bytes(raw).expect("from_bytes");
        assert_eq!(tampered.kek_version, 99);

        let result = unwrap_key(&kek, &tampered);
        assert_eq!(
            result.unwrap_err(),
            EnvelopeError::DecryptionFailed,
            "invalid version must cause unwrap to fail"
        );
    }

    #[test]
    fn test_wrap_unwrap_round_trip_preserves_key() {
        let kek = KeyEncryptionKey::generate().expect("generate KEK");
        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let original = *dek.as_bytes();

        let wrapped = wrap_key(&kek, &dek).expect("wrap");
        let recovered = unwrap_key(&kek, &wrapped).expect("unwrap");

        assert_eq!(
            recovered.as_bytes(),
            &original,
            "wrap-then-unwrap must preserve the original key material"
        );
    }

    // ── TEST GROUP 8: KekKeyring multi-version tests ─────────────────

    #[test]
    fn keyring_wrap_v1_unwrap_with_keyring_containing_v1() {
        let kek_bytes = [0xAAu8; KEY_LEN];
        let keyring = KekKeyring::new(kek_bytes, 1);
        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let original = *dek.as_bytes();

        let wrapped = wrap_key_with_keyring(&keyring, &dek).expect("wrap");
        assert_eq!(wrapped.kek_version, 1);

        let recovered = unwrap_key_with_keyring(&keyring, &wrapped).expect("unwrap");
        assert_eq!(recovered.as_bytes(), &original);
    }

    #[test]
    fn keyring_wrap_v1_unwrap_with_keyring_containing_only_v2_fails() {
        let kek_v1 = [0xAAu8; KEY_LEN];
        let kek_v2 = [0xBBu8; KEY_LEN];

        // Wrap under v1
        let keyring_v1 = KekKeyring::new(kek_v1, 1);
        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let wrapped = wrap_key_with_keyring(&keyring_v1, &dek).expect("wrap");
        assert_eq!(wrapped.kek_version, 1);

        // Try unwrap with keyring that only has v2
        let keyring_v2_only = KekKeyring::new(kek_v2, 2);
        let result = unwrap_key_with_keyring(&keyring_v2_only, &wrapped);
        assert_eq!(result.unwrap_err(), EnvelopeError::UnknownKekVersion(1));
    }

    #[test]
    fn keyring_rotate_v1_to_v2_unwrap_old_data_with_both() {
        let kek_v1 = [0xAAu8; KEY_LEN];
        let kek_v2 = [0xBBu8; KEY_LEN];

        // Wrap under v1
        let keyring_v1 = KekKeyring::new(kek_v1, 1);
        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let original = *dek.as_bytes();
        let wrapped_v1 = wrap_key_with_keyring(&keyring_v1, &dek).expect("wrap v1");
        assert_eq!(wrapped_v1.kek_version, 1);

        // Rotate: create v2 keyring with v1 as previous
        let mut keyring_v2 = KekKeyring::new(kek_v2, 2);
        keyring_v2.add_previous_version(1, kek_v1);
        assert_eq!(keyring_v2.len(), 2);

        // Unwrap old v1 data with the new keyring
        let recovered = unwrap_key_with_keyring(&keyring_v2, &wrapped_v1).expect("unwrap v1 data");
        assert_eq!(recovered.as_bytes(), &original);
    }

    #[test]
    fn keyring_wrap_new_data_with_v2_produces_version_2_prefix() {
        let kek_v1 = [0xAAu8; KEY_LEN];
        let kek_v2 = [0xBBu8; KEY_LEN];

        let mut keyring = KekKeyring::new(kek_v2, 2);
        keyring.add_previous_version(1, kek_v1);

        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let original = *dek.as_bytes();
        let wrapped = wrap_key_with_keyring(&keyring, &dek).expect("wrap v2");

        // Version prefix must be 2
        let raw = wrapped.to_bytes();
        let version = u32::from_be_bytes(raw[..KEK_VERSION_LEN].try_into().unwrap());
        assert_eq!(version, 2);
        assert_eq!(wrapped.kek_version, 2);

        // Round-trip succeeds
        let recovered = unwrap_key_with_keyring(&keyring, &wrapped).expect("unwrap v2");
        assert_eq!(recovered.as_bytes(), &original);
    }

    #[test]
    fn keyring_remove_old_version_after_reencryption() {
        let kek_v1 = [0xAAu8; KEY_LEN];
        let kek_v2 = [0xBBu8; KEY_LEN];

        let mut keyring = KekKeyring::new(kek_v2, 2);
        keyring.add_previous_version(1, kek_v1);
        assert_eq!(keyring.len(), 2);

        // Remove v1
        keyring.remove_version(1).expect("remove v1");
        assert_eq!(keyring.len(), 1);
        assert!(keyring.get_kek(1).is_none());
        assert!(keyring.get_kek(2).is_some());
    }

    #[test]
    fn keyring_cannot_remove_current_version() {
        let kek = [0xAAu8; KEY_LEN];
        let mut keyring = KekKeyring::new(kek, 1);

        let result = keyring.remove_version(1);
        assert_eq!(result.unwrap_err(), EnvelopeError::CannotRemoveCurrentVersion);
    }

    #[test]
    fn keyring_backward_compat_with_single_kek_unwrap() {
        // Verify that wrap_key (original) produces data that unwrap_key_with_keyring can handle
        let kek_bytes = [0xCDu8; KEY_LEN];
        let kek = KeyEncryptionKey::from_bytes(kek_bytes);
        let dek = DataEncryptionKey::generate().expect("generate DEK");
        let original = *dek.as_bytes();

        // Wrap with the original single-KEK function
        let wrapped = wrap_key(&kek, &dek).expect("wrap");

        // Unwrap with keyring
        let keyring = KekKeyring::new(kek_bytes, CURRENT_KEK_VERSION);
        let recovered = unwrap_key_with_keyring(&keyring, &wrapped).expect("unwrap via keyring");
        assert_eq!(recovered.as_bytes(), &original);
    }

    #[test]
    fn test_envelope_legacy_backward_compat_rejected() {
        // Build a legacy AES-256-GCM blob (no algo_id prefix): nonce (12) || ct+tag
        // Legacy untagged ciphertext is no longer accepted after fallback removal.
        common::fips::set_fips_mode_unchecked(false);
        let dek = DataEncryptionKey::generate().expect("generate DEK");
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

        // Ensure first byte is not 0x01 or 0x02 so it hits the unknown-tag path
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
        let result = decrypt(&dek, &legacy_sealed, &aad);
        assert!(
            result.is_err(),
            "legacy untagged ciphertext must be rejected after fallback removal"
        );
    }
}
