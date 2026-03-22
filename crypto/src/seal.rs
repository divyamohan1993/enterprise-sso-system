//! Key seal abstraction layer (HSM-ready).
//!
//! Provides a trait-based key management hierarchy:
//! Master Key → KEKs (per-purpose) → DEKs (per-record)
//!
//! Software implementation uses HKDF-SHA512 key derivation.
//! HSM implementation would use PKCS#11 key wrapping.

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors arising from key seal / unseal operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// Encryption (sealing) failed.
    SealFailed,
    /// Decryption (unsealing) failed — wrong key or tampered ciphertext.
    UnsealFailed,
    /// The supplied master key material is invalid (e.g. empty seed).
    InvalidMasterKey,
    /// HKDF extraction or expansion failed.
    KeyDerivationFailed,
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SealError::SealFailed => write!(f, "seal operation failed"),
            SealError::UnsealFailed => write!(f, "unseal operation failed"),
            SealError::InvalidMasterKey => write!(f, "invalid master key material"),
            SealError::KeyDerivationFailed => write!(f, "key derivation failed"),
        }
    }
}

impl std::error::Error for SealError {}

// ---------------------------------------------------------------------------
// Master Key
// ---------------------------------------------------------------------------

/// 256-bit master key at the root of the key hierarchy.
///
/// Automatically zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; 32],
}

impl MasterKey {
    /// Derive a master key from an arbitrary-length seed using HKDF-SHA512.
    ///
    /// The seed should come from a hardware RNG, TPM, or key ceremony.
    pub fn from_seed(seed: &[u8]) -> Result<Self, SealError> {
        if seed.is_empty() {
            return Err(SealError::InvalidMasterKey);
        }

        let salt = b"MILNET-MASTER-KEY-v1";
        let hk = Hkdf::<Sha512>::new(Some(salt), seed);
        let mut okm = [0u8; 32];
        hk.expand(b"master-key", &mut okm)
            .map_err(|_| SealError::KeyDerivationFailed)?;
        Ok(Self { bytes: okm })
    }

    /// Construct a master key from raw bytes (caller is responsible for
    /// ensuring the bytes have sufficient entropy).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Generate a master key from the OS CSPRNG (`getrandom`).
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
        Self { bytes }
    }

    /// Derive a purpose-specific Key Encryption Key (KEK) from this master key.
    ///
    /// Each unique `purpose` string yields a cryptographically independent KEK.
    pub fn derive_kek(&self, purpose: &str) -> DerivedKek {
        let hk = Hkdf::<Sha512>::new(None, &self.bytes);
        let mut info = Vec::with_capacity(11 + purpose.len());
        info.extend_from_slice(b"MILNET-KEK-");
        info.extend_from_slice(purpose.as_bytes());

        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm)
            .expect("HKDF expand should not fail for 32 byte output");
        DerivedKek { bytes: okm }
    }
}

// ---------------------------------------------------------------------------
// Derived KEK
// ---------------------------------------------------------------------------

/// A purpose-bound Key Encryption Key derived from the master key.
///
/// Used to seal (wrap) and unseal (unwrap) Data Encryption Keys.
/// Automatically zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKek {
    bytes: [u8; 32],
}

/// Minimum sealed payload length: 12-byte nonce + 16-byte AES-GCM tag.
const MIN_SEALED_LEN: usize = 12 + 16;

/// Additional Authenticated Data used for all seal operations.
const SEAL_AAD: &[u8] = b"MILNET-SEAL-v1";

impl DerivedKek {
    /// Seal (encrypt) plaintext using AES-256-GCM with a random nonce.
    ///
    /// Returns `nonce (12 bytes) || ciphertext+tag`.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&self.bytes);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).map_err(|_| SealError::SealFailed)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad: SEAL_AAD,
        };
        let ciphertext = cipher.encrypt(nonce, payload).map_err(|_| SealError::SealFailed)?;

        let mut sealed = Vec::with_capacity(12 + ciphertext.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Unseal (decrypt) a payload previously sealed with [`seal`](Self::seal).
    ///
    /// Expects the format `nonce (12 bytes) || ciphertext+tag`.
    pub fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if sealed.len() < MIN_SEALED_LEN {
            return Err(SealError::UnsealFailed);
        }

        let (nonce_bytes, ciphertext) = sealed.split_at(12);
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&self.bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: SEAL_AAD,
        };
        cipher.decrypt(nonce, payload).map_err(|_| SealError::UnsealFailed)
    }
}

// ---------------------------------------------------------------------------
// Key Hierarchy (convenience wrapper)
// ---------------------------------------------------------------------------

/// Convenience wrapper around the full key hierarchy.
///
/// Provides purpose-specific KEK derivation and one-shot seal/unseal helpers.
pub struct KeyHierarchy {
    master: MasterKey,
}

impl KeyHierarchy {
    /// Create a new key hierarchy rooted at the given master key.
    pub fn new(master_key: MasterKey) -> Self {
        Self { master: master_key }
    }

    /// Derive a KEK scoped to a database table.
    ///
    /// The KEK info string is `"table:" || table_name`.
    pub fn kek_for_table(&self, table_name: &str) -> DerivedKek {
        let purpose = format!("table:{}", table_name);
        self.master.derive_kek(&purpose)
    }

    /// Derive a KEK scoped to a downstream service.
    ///
    /// The KEK info string is `"service:" || service_name`.
    pub fn kek_for_service(&self, service_name: &str) -> DerivedKek {
        let purpose = format!("service:{}", service_name);
        self.master.derive_kek(&purpose)
    }

    /// Derive a KEK for `purpose` and seal the given key material.
    pub fn seal_key_material(
        &self,
        purpose: &str,
        key_bytes: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        let kek = self.master.derive_kek(purpose);
        kek.seal(key_bytes)
    }

    /// Derive a KEK for `purpose` and unseal previously sealed key material.
    pub fn unseal_key_material(
        &self,
        purpose: &str,
        sealed: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        let kek = self.master.derive_kek(purpose);
        kek.unseal(sealed)
    }
}

// ---------------------------------------------------------------------------
// Production Key Source trait (HSM / TPM / KMS interface)
// ---------------------------------------------------------------------------

/// Trait for production key sources (HSM, TPM, KMS).
///
/// Implementations MUST:
/// - Store the master key in hardware (FIPS 140-3 Level 3+)
/// - Support key rotation without service downtime
/// - Audit all key access operations
/// - Enforce access control (caller identity + authorization)
///
/// # HSM Implementation Notes
/// - PKCS#11: Use C_WrapKey/C_UnwrapKey with CKM_AES_KEY_WRAP_KWP
/// - AWS CloudHSM: Use AES key wrap with OAEP padding
/// - YubiHSM2: Use wrap-data command with wrap key
pub trait ProductionKeySource: Send + Sync {
    /// Load the current master key from the hardware store.
    fn load_master_key(&self) -> Result<MasterKey, SealError>;

    /// Rotate the master key and return the new key.
    ///
    /// Callers must re-wrap all existing KEKs / DEKs under the new master.
    fn rotate_master_key(&self) -> Result<MasterKey, SealError>;

    /// Seal plaintext using the hardware key for `purpose`.
    fn seal_with_hardware(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, SealError>;

    /// Unseal ciphertext using the hardware key for `purpose`.
    fn unseal_with_hardware(&self, sealed: &[u8], purpose: &str) -> Result<Vec<u8>, SealError>;
}

// ---------------------------------------------------------------------------
// Software Key Source (development / testing)
// ---------------------------------------------------------------------------

/// Software-only implementation of [`ProductionKeySource`].
///
/// Suitable for development, testing, and environments without HSM access.
/// **Do not use in production** — the master key lives in process memory.
pub struct SoftwareKeySource {
    seed: Vec<u8>,
}

impl SoftwareKeySource {
    /// Create a new software key source from a seed.
    pub fn new(seed: &[u8]) -> Result<Self, SealError> {
        if seed.is_empty() {
            return Err(SealError::InvalidMasterKey);
        }
        Ok(Self {
            seed: seed.to_vec(),
        })
    }
}

impl ProductionKeySource for SoftwareKeySource {
    fn load_master_key(&self) -> Result<MasterKey, SealError> {
        MasterKey::from_seed(&self.seed)
    }

    fn rotate_master_key(&self) -> Result<MasterKey, SealError> {
        // In a real HSM this would generate a new key in hardware.
        // The software implementation simply generates a fresh random key.
        Ok(MasterKey::generate())
    }

    fn seal_with_hardware(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let mk = self.load_master_key()?;
        let kek = mk.derive_kek(purpose);
        kek.seal(plaintext)
    }

    fn unseal_with_hardware(&self, sealed: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let mk = self.load_master_key()?;
        let kek = mk.derive_kek(purpose);
        kek.unseal(sealed)
    }
}

// ---------------------------------------------------------------------------
// Factory: create key source from HSM configuration
// ---------------------------------------------------------------------------

/// Create a [`ProductionKeySource`] from an [`HsmConfig`](crate::hsm::HsmConfig).
///
/// This is the recommended way to instantiate the key management layer.
/// The returned source delegates to the appropriate HSM backend:
///
/// - `HsmBackend::Pkcs11` — PKCS#11 HSM (Thales Luna, CloudHSM, YubiHSM2, SoftHSM2)
/// - `HsmBackend::AwsKms` — AWS KMS envelope encryption
/// - `HsmBackend::Tpm2` — TPM 2.0 sealed keys
/// - `HsmBackend::Software` — development fallback (blocked in production)
///
/// # Fail-Closed
/// In production mode (`MILNET_PRODUCTION=1`), the `Software` backend is
/// rejected. All hardware backend errors fail-closed (deny access).
pub fn create_key_source(
    config: &crate::hsm::HsmConfig,
) -> Result<Box<dyn ProductionKeySource>, crate::hsm::HsmError> {
    crate::hsm::create_key_source(config)
}

/// Create a [`ProductionKeySource`] from environment variables.
///
/// Reads `MILNET_HSM_BACKEND` and related env vars. Falls back to `Software`
/// if `MILNET_HSM_BACKEND` is not set.
pub fn create_key_source_from_env() -> Result<Box<dyn ProductionKeySource>, crate::hsm::HsmError> {
    crate::hsm::create_key_source_from_env()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &[u8] = b"test-seed-with-enough-entropy-for-hkdf-extraction";

    // -- Master key derivation determinism ----------------------------------

    #[test]
    fn master_key_from_seed_is_deterministic() {
        let mk1 = MasterKey::from_seed(TEST_SEED).unwrap();
        let mk2 = MasterKey::from_seed(TEST_SEED).unwrap();
        assert_eq!(mk1.bytes, mk2.bytes);
    }

    #[test]
    fn master_key_different_seeds_differ() {
        let mk1 = MasterKey::from_seed(b"seed-alpha").unwrap();
        let mk2 = MasterKey::from_seed(b"seed-beta").unwrap();
        assert_ne!(mk1.bytes, mk2.bytes);
    }

    #[test]
    fn master_key_empty_seed_rejected() {
        let result = MasterKey::from_seed(b"");
        assert_eq!(result.err(), Some(SealError::InvalidMasterKey));
    }

    #[test]
    fn master_key_from_bytes_roundtrip() {
        let bytes = [42u8; 32];
        let mk = MasterKey::from_bytes(bytes);
        assert_eq!(mk.bytes, bytes);
    }

    #[test]
    fn master_key_generate_produces_nonzero() {
        let mk = MasterKey::generate();
        assert_ne!(mk.bytes, [0u8; 32]);
    }

    // -- KEK derivation -----------------------------------------------------

    #[test]
    fn different_purposes_produce_different_keks() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek_a = mk.derive_kek("users");
        let kek_b = mk.derive_kek("sessions");
        assert_ne!(kek_a.bytes, kek_b.bytes);
    }

    #[test]
    fn same_purpose_produces_same_kek() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek1 = mk.derive_kek("tokens");
        let kek2 = mk.derive_kek("tokens");
        assert_eq!(kek1.bytes, kek2.bytes);
    }

    // -- Seal / unseal round-trip -------------------------------------------

    #[test]
    fn seal_unseal_roundtrip() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek = mk.derive_kek("test-purpose");

        let plaintext = b"super-secret-data-encryption-key";
        let sealed = kek.seal(plaintext).unwrap();
        let recovered = kek.unseal(&sealed).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn seal_unseal_empty_plaintext() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek = mk.derive_kek("empty");

        let sealed = kek.seal(b"").unwrap();
        let recovered = kek.unseal(&sealed).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn sealed_output_has_expected_overhead() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek = mk.derive_kek("overhead");

        let plaintext = b"sixteen-bytes!!!" ; // 16 bytes
        let sealed = kek.seal(plaintext).unwrap();
        // 12 nonce + 16 plaintext + 16 tag = 44
        assert_eq!(sealed.len(), 12 + 16 + 16);
    }

    // -- Wrong key / tampered ciphertext ------------------------------------

    #[test]
    fn wrong_kek_fails_unseal() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek_a = mk.derive_kek("correct");
        let kek_b = mk.derive_kek("wrong");

        let sealed = kek_a.seal(b"secret").unwrap();
        let result = kek_b.unseal(&sealed);
        assert_eq!(result.err(), Some(SealError::UnsealFailed));
    }

    #[test]
    fn tampered_ciphertext_fails_unseal() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek = mk.derive_kek("tamper");

        let mut sealed = kek.seal(b"integrity-check").unwrap();
        // Flip a bit in the ciphertext portion (after the 12-byte nonce)
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;

        let result = kek.unseal(&sealed);
        assert_eq!(result.err(), Some(SealError::UnsealFailed));
    }

    #[test]
    fn too_short_sealed_fails() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek = mk.derive_kek("short");

        let result = kek.unseal(&[0u8; 27]); // one byte short of MIN_SEALED_LEN
        assert_eq!(result.err(), Some(SealError::UnsealFailed));
    }

    // -- KeyHierarchy convenience -------------------------------------------

    #[test]
    fn key_hierarchy_table_kek() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let hierarchy = KeyHierarchy::new(mk);

        let kek = hierarchy.kek_for_table("credentials");
        // Verify it is the same as deriving manually.
        let mk2 = MasterKey::from_seed(TEST_SEED).unwrap();
        let expected = mk2.derive_kek("table:credentials");
        assert_eq!(kek.bytes, expected.bytes);
    }

    #[test]
    fn key_hierarchy_service_kek() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let hierarchy = KeyHierarchy::new(mk);

        let kek = hierarchy.kek_for_service("auth-gateway");
        let mk2 = MasterKey::from_seed(TEST_SEED).unwrap();
        let expected = mk2.derive_kek("service:auth-gateway");
        assert_eq!(kek.bytes, expected.bytes);
    }

    #[test]
    fn key_hierarchy_seal_unseal() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let hierarchy = KeyHierarchy::new(mk);

        let dek = b"random-data-encryption-key-bytes";
        let sealed = hierarchy.seal_key_material("tokens", dek).unwrap();

        // Unseal with the same hierarchy (needs a new MasterKey since the
        // original was moved).
        let mk2 = MasterKey::from_seed(TEST_SEED).unwrap();
        let hierarchy2 = KeyHierarchy::new(mk2);
        let recovered = hierarchy2.unseal_key_material("tokens", &sealed).unwrap();
        assert_eq!(recovered, dek);
    }

    #[test]
    fn key_hierarchy_wrong_purpose_fails() {
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let hierarchy = KeyHierarchy::new(mk);
        let sealed = hierarchy.seal_key_material("purpose-a", b"key").unwrap();

        let mk2 = MasterKey::from_seed(TEST_SEED).unwrap();
        let hierarchy2 = KeyHierarchy::new(mk2);
        let result = hierarchy2.unseal_key_material("purpose-b", &sealed);
        assert_eq!(result.err(), Some(SealError::UnsealFailed));
    }

    // -- SoftwareKeySource --------------------------------------------------

    #[test]
    fn software_key_source_load_is_deterministic() {
        let source = SoftwareKeySource::new(TEST_SEED).unwrap();
        let mk1 = source.load_master_key().unwrap();
        let mk2 = source.load_master_key().unwrap();
        assert_eq!(mk1.bytes, mk2.bytes);
    }

    #[test]
    fn software_key_source_empty_seed_rejected() {
        let result = SoftwareKeySource::new(b"");
        assert_eq!(result.err(), Some(SealError::InvalidMasterKey));
    }

    #[test]
    fn software_key_source_seal_unseal_roundtrip() {
        let source = SoftwareKeySource::new(TEST_SEED).unwrap();
        let plaintext = b"hardware-would-protect-this";
        let sealed = source.seal_with_hardware(plaintext, "vault").unwrap();
        let recovered = source.unseal_with_hardware(&sealed, "vault").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn software_key_source_wrong_purpose_fails() {
        let source = SoftwareKeySource::new(TEST_SEED).unwrap();
        let sealed = source.seal_with_hardware(b"data", "correct").unwrap();
        let result = source.unseal_with_hardware(&sealed, "incorrect");
        assert_eq!(result.err(), Some(SealError::UnsealFailed));
    }

    #[test]
    fn software_key_source_rotate_produces_new_key() {
        let source = SoftwareKeySource::new(TEST_SEED).unwrap();
        let original = source.load_master_key().unwrap();
        let rotated = source.rotate_master_key().unwrap();
        // Rotated key should differ from the seed-derived key
        assert_ne!(original.bytes, rotated.bytes);
    }

    #[test]
    fn software_key_source_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SoftwareKeySource>();
    }
}
