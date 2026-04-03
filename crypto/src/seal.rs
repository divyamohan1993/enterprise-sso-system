//! Key seal abstraction layer (HSM-ready).
//!
//! Provides a trait-based key management hierarchy:
//! Master Key → KEKs (per-purpose) → DEKs (per-record)
//!
//! Software implementation uses HKDF-SHA512 key derivation.
//! HSM implementation would use PKCS#11 key wrapping.

#![allow(unsafe_code)]

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

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
/// Automatically zeroized when dropped. Callers that store a `MasterKey` at a
/// stable address (e.g. inside `OnceLock`, `ProtectedKek`, or a long-lived
/// struct) should call [`mlock_key_bytes`] on the *final* location to prevent
/// swapping to disk. The constructors intentionally do NOT mlock because the
/// returned value may be moved, which would invalidate the mlocked address.
#[derive(Zeroize)]
pub struct MasterKey {
    bytes: [u8; 32],
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        // Munlock before zeroize so the region is still valid.
        munlock_key_bytes(self.bytes.as_ptr());
        self.bytes.zeroize();
    }
}

/// Lock key bytes into RAM (prevent swap) and exclude from core dumps.
///
/// # Safety contract
/// The pointer **must** be the final resting location of the key material.
/// Calling this before the struct is moved is a bug: the move copies the bytes
/// to a new (unprotected) address and the old (mlocked) region is freed.
/// Call this only after the key has been placed in its long-lived storage
/// (e.g. inside a `OnceLock`, `ProtectedKek`, or heap-pinned container).
pub(crate) fn mlock_key_bytes(ptr: *const u8) {
    unsafe {
        libc::mlock(ptr as *const libc::c_void, 32);
        libc::madvise(ptr as *mut libc::c_void, 32, libc::MADV_DONTDUMP);
    }
}

/// Unlock previously mlocked key bytes. Harmless no-op if the region was
/// never mlocked (the kernel silently ignores munlock on non-locked pages).
fn munlock_key_bytes(ptr: *const u8) {
    unsafe {
        libc::munlock(ptr as *const libc::c_void, 32);
    }
}

impl MasterKey {
    /// Lock the key bytes into RAM at their current address.
    ///
    /// Call this **only** after the `MasterKey` has reached its final storage
    /// location (e.g. inside a `OnceLock`, `ProtectedKek`, or long-lived struct).
    /// Calling before a move is a bug: the bytes will be copied to a new address.
    pub fn mlock(&self) {
        mlock_key_bytes(self.bytes.as_ptr());
    }

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
        let key = Self { bytes: okm };
        okm.zeroize();
        // NOTE: mlock is applied by the caller at the final storage location
        // (e.g. ProtectedKek, OnceLock). Mlocking here is ineffective because
        // the returned value will be moved, invalidating the address.
        Ok(key)
    }

    /// Construct a master key from raw bytes (caller is responsible for
    /// ensuring the bytes have sufficient entropy).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        // NOTE: mlock is applied by the caller at the final storage location.
        // The previous Box-then-deref pattern was a bug: the key was mlocked
        // at a heap address, then moved out, leaving the final location unprotected.
        Self { bytes }
    }

    /// Generate a master key from the OS CSPRNG (`getrandom`).
    ///
    /// # Panics
    /// In military deployment mode (`MILNET_MILITARY_DEPLOYMENT=1`), software
    /// key generation is forbidden — master keys MUST originate from an HSM
    /// (PKCS#11, AWS KMS, or TPM 2.0).  This prevents plaintext master key
    /// material from ever existing in process memory on a compromised host.
    pub fn generate() -> Self {
        let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
            .map(|v| v == "1")
            .unwrap_or(false);
        if is_military {
            panic!(
                "FATAL: MasterKey::generate() called in military deployment mode \
                 (MILNET_MILITARY_DEPLOYMENT=1). Software key generation is FORBIDDEN. \
                 Master keys MUST come from an HSM (set MILNET_HSM_BACKEND=pkcs11|aws_kms|tpm2). \
                 Aborting to prevent plaintext key material in process memory."
            );
        }
        let mut bytes = [0u8; 32];
        if getrandom::getrandom(&mut bytes).is_err() {
            panic!("FATAL: OS CSPRNG unavailable — cannot generate master key safely");
        }
        // NOTE: mlock is applied by the caller at the final storage location.
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
        if hk.expand(&info, &mut okm).is_err() {
            panic!("FATAL: HKDF-SHA512 expand failed for 32-byte KEK derivation");
        }
        let kek = DerivedKek { bytes: okm };
        okm.zeroize();
        // NOTE: mlock deferred to caller's final storage location.
        kek
    }
}

// ---------------------------------------------------------------------------
// Derived KEK
// ---------------------------------------------------------------------------

/// A purpose-bound Key Encryption Key derived from the master key.
///
/// Used to seal (wrap) and unseal (unwrap) Data Encryption Keys.
/// Automatically zeroized when dropped. Call [`DerivedKek::mlock`] after the
/// value reaches its final storage location to prevent swapping to disk.
#[derive(Zeroize)]
pub struct DerivedKek {
    bytes: [u8; 32],
}

impl Drop for DerivedKek {
    fn drop(&mut self) {
        munlock_key_bytes(self.bytes.as_ptr());
        self.bytes.zeroize();
    }
}

impl DerivedKek {
    /// Lock the KEK bytes into RAM at their current address.
    ///
    /// Call this **only** after the `DerivedKek` has reached its final storage
    /// location. See [`MasterKey::mlock`] for details.
    pub fn mlock(&self) {
        mlock_key_bytes(self.bytes.as_ptr());
    }
}

/// Additional Authenticated Data used for all seal operations.
const SEAL_AAD: &[u8] = b"MILNET-SEAL-v1";

impl DerivedKek {
    /// Seal (encrypt) plaintext using the active symmetric algorithm (AEGIS-256
    /// by default, AES-256-GCM in FIPS mode) with a random nonce.
    ///
    /// Returns `algo_id (1 byte) || nonce || ciphertext || tag`.
    /// Legacy data without an algo_id prefix is still accepted by [`unseal`].
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        crate::symmetric::encrypt(&self.bytes, plaintext, SEAL_AAD)
            .map_err(|_| SealError::SealFailed)
    }

    /// Unseal (decrypt) a payload previously sealed with [`seal`](Self::seal).
    ///
    /// Handles:
    /// - New format: `algo_id (1 byte) || nonce || ciphertext || tag`
    /// - Legacy format: `nonce (12 bytes) || ciphertext+tag` (AES-256-GCM, no prefix)
    pub fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        crate::symmetric::decrypt(&self.bytes, sealed, SEAL_AAD)
            .map_err(|_| SealError::UnsealFailed)
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

impl Drop for SoftwareKeySource {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
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
// SealedKeystore — defense-in-depth encrypted key storage
// ---------------------------------------------------------------------------

/// In-memory keystore that encrypts all keys with a secondary derived key.
///
/// Defense-in-depth: even if process memory is dumped (e.g., via /proc/pid/mem),
/// keys stored in the SealedKeystore are encrypted with a secondary key derived
/// from the master key. An attacker must compromise both the master key AND the
/// memory dump to recover the stored keys.
///
/// The secondary encryption key is derived via HKDF-SHA512 from the master key
/// with a unique domain separator, ensuring it is cryptographically independent.
pub struct SealedKeystore {
    /// The secondary KEK used to encrypt stored keys. Derived from the master key.
    secondary_kek: DerivedKek,
    /// Encrypted key entries: purpose -> sealed bytes.
    entries: std::collections::HashMap<String, Vec<u8>>,
}

impl SealedKeystore {
    /// Create a new SealedKeystore with a secondary key derived from the master key.
    ///
    /// The secondary key is derived using HKDF-SHA512 with domain separator
    /// "sealed-keystore-secondary" to ensure cryptographic independence from
    /// all other derived keys in the hierarchy.
    pub fn new(master: &MasterKey) -> Self {
        let secondary_kek = master.derive_kek("sealed-keystore-secondary");
        Self {
            secondary_kek,
            entries: std::collections::HashMap::new(),
        }
    }

    /// Store a key under the given purpose, encrypting it with the secondary KEK.
    ///
    /// The plaintext key bytes are sealed immediately; the caller should zeroize
    /// their copy after calling this method.
    pub fn store(&mut self, purpose: &str, key_bytes: &[u8]) -> Result<(), SealError> {
        let sealed = self.secondary_kek.seal(key_bytes)?;
        self.entries.insert(purpose.to_string(), sealed);
        Ok(())
    }

    /// Retrieve and decrypt a key stored under the given purpose.
    ///
    /// Returns `None` if no key is stored for the purpose.
    /// Returns `Err` if decryption fails (secondary KEK mismatch or tampering).
    pub fn retrieve(&self, purpose: &str) -> Result<Option<Vec<u8>>, SealError> {
        match self.entries.get(purpose) {
            Some(sealed) => {
                let plaintext = self.secondary_kek.unseal(sealed)?;
                Ok(Some(plaintext))
            }
            None => Ok(None),
        }
    }

    /// Remove a stored key, zeroizing the sealed bytes.
    pub fn remove(&mut self, purpose: &str) {
        if let Some(mut sealed) = self.entries.remove(purpose) {
            sealed.zeroize();
        }
    }

    /// Returns the number of keys currently stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no keys are stored.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Drop for SealedKeystore {
    fn drop(&mut self) {
        // Zeroize all sealed entries on drop.
        for (_, sealed) in self.entries.iter_mut() {
            sealed.zeroize();
        }
        self.entries.clear();
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
// Key Rotation Scheduler (reminder system — operator approval required)
// ---------------------------------------------------------------------------

/// A scheduler that monitors key age and emits SIEM alerts when rotation is
/// overdue.
///
/// This is a **reminder system only** — it does NOT perform automatic rotation.
/// Actual key rotation requires operator approval and a key ceremony.  The
/// scheduler simply detects when the configured interval has elapsed and emits
/// a HIGH-severity SIEM event to prompt operators.
pub struct KeyRotationScheduler {
    /// How often a key should be rotated (default: 90 days).
    pub rotation_interval: std::time::Duration,
    /// When the last rotation occurred. `None` means "never rotated / unknown".
    last_rotation: Option<std::time::Instant>,
    /// Optional callback invoked when rotation is detected as overdue.
    /// This can be used for custom notification integrations beyond SIEM.
    rotation_callback: Option<Box<dyn Fn() + Send + Sync>>,
}

impl KeyRotationScheduler {
    /// Create a new scheduler with default 90-day rotation interval.
    pub fn new() -> Self {
        Self {
            rotation_interval: std::time::Duration::from_secs(90 * 24 * 3600),
            last_rotation: None,
            rotation_callback: None,
        }
    }

    /// Create a scheduler with a custom rotation interval.
    pub fn with_interval(interval: std::time::Duration) -> Self {
        Self {
            rotation_interval: interval,
            last_rotation: None,
            rotation_callback: None,
        }
    }

    /// Set a callback to invoke when rotation is detected as overdue.
    pub fn set_rotation_callback<F: Fn() + Send + Sync + 'static>(&mut self, cb: F) {
        self.rotation_callback = Some(Box::new(cb));
    }

    /// Record that a key rotation just occurred.
    pub fn record_rotation(&mut self) {
        self.last_rotation = Some(std::time::Instant::now());
    }

    /// Check whether a key rotation is overdue.
    ///
    /// Returns `true` if:
    /// - No rotation has ever been recorded, OR
    /// - The time since the last rotation exceeds `rotation_interval`.
    pub fn check_rotation_due(&self) -> bool {
        match self.last_rotation {
            None => true,
            Some(last) => last.elapsed() >= self.rotation_interval,
        }
    }

    /// Spawn a background tokio task that periodically checks whether key
    /// rotation is overdue.  When it is, a HIGH-severity SIEM event
    /// (`key_rotation_overdue`) is emitted and the optional callback is
    /// invoked.
    ///
    /// The check runs every `check_interval`.  A sensible default is once
    /// per hour.
    ///
    /// Returns a `tokio::task::JoinHandle` that can be used to abort the
    /// monitor if needed.
    pub fn schedule_rotation(
        self,
        check_interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        // Move self into an Arc<Mutex> so the spawned task can read it.
        let scheduler = std::sync::Arc::new(std::sync::Mutex::new(self));

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            // Skip the first immediate tick to let the system stabilize.
            interval.tick().await;

            tracing::info!(
                "key rotation scheduler started (check interval: {:?})",
                check_interval
            );

            loop {
                interval.tick().await;

                let (due, rotation_interval) = {
                    let sched = scheduler.lock().unwrap_or_else(|e| e.into_inner());
                    (sched.check_rotation_due(), sched.rotation_interval)
                };

                if due {
                    tracing::warn!(
                        rotation_interval_days = rotation_interval.as_secs() / 86400,
                        "key rotation is OVERDUE — operator action required"
                    );

                    // Emit SIEM alert
                    common::siem::SecurityEvent::key_rotation_overdue(
                        &format!(
                            "master key rotation overdue (interval: {} days). \
                             Operator approval and key ceremony required.",
                            rotation_interval.as_secs() / 86400
                        ),
                    );

                    // Invoke optional callback
                    let sched = scheduler.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(ref cb) = sched.rotation_callback {
                        cb();
                    }
                } else {
                    tracing::debug!("key rotation check: not yet due");
                }
            }
        })
    }
}

impl Default for KeyRotationScheduler {
    fn default() -> Self {
        Self::new()
    }
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
        // Ensure non-FIPS so AEGIS-256 is selected.
        common::fips::set_fips_mode_unchecked(false);
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek = mk.derive_kek("overhead");

        let plaintext = b"sixteen-bytes!!!" ; // 16 bytes
        let sealed = kek.seal(plaintext).unwrap();
        // AEGIS-256: 1 (algo_id) + 32 (nonce) + 16 (plaintext) + 32 (tag) = 81
        assert_eq!(sealed.len(), 1 + 32 + 16 + 32);
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

    // -- AEGIS-256 / FIPS / legacy compat -----------------------------------

    #[test]
    fn test_seal_aegis256_roundtrip() {
        // Non-FIPS mode → AEGIS-256
        common::fips::set_fips_mode_unchecked(false);
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek = mk.derive_kek("aegis-test");
        let plaintext = b"aegis-256-sealed-secret-data";
        let sealed = kek.seal(plaintext).unwrap();
        let recovered = kek.unseal(&sealed).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_seal_fips_aes256gcm_roundtrip() {
        // FIPS mode → AES-256-GCM
        common::fips::set_fips_mode_unchecked(true);
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek = mk.derive_kek("fips-test");
        let plaintext = b"fips-aes256gcm-sealed-data";
        let sealed = kek.seal(plaintext).unwrap();
        let recovered = kek.unseal(&sealed).unwrap();
        assert_eq!(recovered, plaintext);
        common::fips::set_fips_mode_unchecked(false);
    }

    #[test]
    fn test_seal_legacy_backward_compat() {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::Aead;

        common::fips::set_fips_mode_unchecked(false);
        let mk = MasterKey::from_seed(TEST_SEED).unwrap();
        let kek = mk.derive_kek("legacy-compat");
        let plaintext = b"legacy-sealed-plaintext";

        // Build a legacy AES-256-GCM blob: nonce (12) || ciphertext+tag  (no algo_id prefix)
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).unwrap();
        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&kek.bytes));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload { msg: plaintext, aad: SEAL_AAD },
            )
            .unwrap();

        let mut legacy_blob = Vec::with_capacity(12 + ct.len());
        legacy_blob.extend_from_slice(&nonce_bytes);
        legacy_blob.extend_from_slice(&ct);

        // Ensure the first byte is NOT 0x01 or 0x02 (algo_id values)
        if legacy_blob.first().copied() == Some(crate::symmetric::ALGO_ID_AEGIS256)
            || legacy_blob.first().copied() == Some(crate::symmetric::ALGO_ID_AES256GCM)
        {
            nonce_bytes[0] = 0xFF;
            let nonce2 = Nonce::from_slice(&nonce_bytes);
            let ct2 = cipher
                .encrypt(nonce2, aes_gcm::aead::Payload { msg: plaintext, aad: SEAL_AAD })
                .unwrap();
            legacy_blob.clear();
            legacy_blob.extend_from_slice(&nonce_bytes);
            legacy_blob.extend_from_slice(&ct2);
        }

        // Legacy untagged blobs are now rejected after the removal of the
        // legacy AES-GCM decrypt fallback. This is the expected behavior —
        // old ciphertexts must be re-encrypted under the V2 envelope format.
        let result = kek.unseal(&legacy_blob);
        assert!(
            result.is_err(),
            "legacy untagged ciphertext must be rejected after fallback removal"
        );
    }
}
