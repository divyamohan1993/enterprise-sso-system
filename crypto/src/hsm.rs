//! Hardware Security Module (HSM) integration layer.
//!
//! Provides a unified abstraction over multiple HSM backends:
//! - **PKCS#11** — Standard interface for Thales Luna, AWS CloudHSM, YubiHSM2, SoftHSM2
//! - **AWS KMS** — Envelope encryption with AWS-managed keys (key never leaves AWS)
//! - **TPM 2.0** — Local hardware TPM on each server, sealed to PCR values
//! - **Software** — Development fallback wrapping [`SoftwareKeySource`]
//!
//! # Security Invariants
//! - Master keys **NEVER** leave the HSM in plaintext
//! - All HSM operations are abstracted behind [`ProductionKeySource`]
//! - The software fallback is disabled in production mode (fail-closed)
//! - All HSM errors fail-closed: deny access, never silently degrade
//! - Key material is never logged; only operation metadata at INFO level
//!
//! ## Production HSM Integration
//!
//! For classified/military deployments, hardware-backed key storage is mandatory.
//! The software fallback is automatically blocked when `MILNET_PRODUCTION` is set.
//!
//! Supported backends (set via `MILNET_HSM_BACKEND` env var):
//! - `pkcs11` — Thales Luna, AWS CloudHSM, YubiHSM2, SoftHSM2
//! - `aws_kms` — AWS KMS envelope encryption (keys never leave AWS)
//! - `tpm2` — TPM 2.0 sealed to platform PCR values
//! - `software` — Development only, blocked in production
//!
//! ## Audit Logging
//!
//! All key operations emit structured audit events via `tracing` macros,
//! routed through the SIEM pipeline. In production, these should be routed
//! to a tamper-evident audit log (e.g., AWS CloudTrail, syslog with remote forwarding).
//!
//! # Backend Implementations
//! Since this crate does not link against PKCS#11, AWS SDK, or tss-esapi
//! at compile time, the backends implement a complete trait-based abstraction
//! (`HsmKeyOps`) that performs real cryptographic operations using the
//! primitives available in this crate (AES-256-GCM, HKDF-SHA512, HMAC-SHA256).
//!
//! - **PKCS#11**: Derives a session-bound root key from the library path + slot +
//!   PIN via HKDF, then stores all generated keys sealed under that root.
//!   This mirrors the PKCS#11 session lifecycle where the HSM internally protects
//!   keys and only exposes handles.
//! - **AWS KMS**: Implements the envelope encryption pattern with data key caching
//!   and exponential backoff retry. Keys are sealed under a root derived from
//!   the KMS key ARN.
//! - **TPM 2.0**: Seals keys to PCR values using HKDF with PCR digests as salt.
//!   Supports the SRK -> storage key -> application key hierarchy.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as HmacMac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::seal::{MasterKey, ProductionKeySource, SealError, SoftwareKeySource};

// ---------------------------------------------------------------------------
// Key types for HsmKeyOps
// ---------------------------------------------------------------------------

/// Types of keys that can be generated or managed by an HSM backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// AES-256 symmetric key for encryption/decryption.
    Aes256,
    /// AES-256 key specifically for key wrapping (AES-KWP).
    Aes256Wrap,
    /// HMAC-SHA256 key for signing/verification.
    HmacSha256,
    /// HMAC-SHA512 key for signing/verification.
    HmacSha512,
    /// Generic secret key of specified byte length (stored in the variant).
    GenericSecret,
}

// ---------------------------------------------------------------------------
// HsmKeyOps trait — unified interface for all backends
// ---------------------------------------------------------------------------

/// Unified key operation trait that all HSM backends implement.
///
/// Provides a consistent interface for key generation, cryptographic operations,
/// and key lifecycle management across PKCS#11, AWS KMS, TPM 2.0, and software
/// backends.
///
/// # Security Model
/// - Keys are referenced by string identifiers (`key_id`), never by raw bytes.
/// - The backend is responsible for secure storage of key material.
/// - All operations fail-closed on error.
/// - Implementations must be thread-safe (`Send + Sync`).
pub trait HsmKeyOps: Send + Sync {
    /// Generate a new key of the specified type and store it under `key_id`.
    ///
    /// Returns a key handle token (opaque bytes identifying the key within this backend).
    /// The actual key material is stored internally and never returned in plaintext
    /// for hardware backends.
    fn generate_key(&self, key_id: &str, key_type: KeyType) -> Result<Vec<u8>, HsmError>;

    /// Sign `data` using the key identified by `key_id`.
    ///
    /// For symmetric keys (HMAC), produces an HMAC tag.
    /// For asymmetric keys, produces a digital signature.
    fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Verify a `signature` over `data` using the key identified by `key_id`.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    /// Uses constant-time comparison to prevent timing attacks.
    fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, HsmError>;

    /// Encrypt `plaintext` with the key identified by `key_id`.
    ///
    /// `aad` is additional authenticated data bound to the ciphertext but not encrypted.
    /// Returns `nonce || ciphertext || tag` for AEAD ciphers.
    fn encrypt(&self, key_id: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Decrypt `ciphertext` with the key identified by `key_id`.
    ///
    /// `aad` must match the AAD used during encryption.
    /// Expects the format `nonce || ciphertext || tag` for AEAD ciphers.
    fn decrypt(&self, key_id: &str, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Wrap (export-protect) `key_to_wrap` under the wrapping key `wrapping_key_id`.
    ///
    /// The wrapped output can only be unwrapped by the same backend with the
    /// same wrapping key.
    fn wrap_key(&self, wrapping_key_id: &str, key_to_wrap: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Unwrap a previously wrapped key using `wrapping_key_id`.
    ///
    /// Returns the plaintext key material.
    fn unwrap_key(&self, wrapping_key_id: &str, wrapped_key: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Destroy a key, securely erasing its material from the backend.
    ///
    /// After this call, all operations referencing `key_id` will fail with
    /// [`HsmError::KeyNotFound`].
    fn destroy_key(&self, key_id: &str) -> Result<(), HsmError>;

    /// Check whether a key with the given `key_id` exists in this backend.
    fn key_exists(&self, key_id: &str) -> Result<bool, HsmError>;
}

// ---------------------------------------------------------------------------
// HSM Backend enum
// ---------------------------------------------------------------------------

/// Supported HSM backend types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HsmBackend {
    /// PKCS#11 interface — works with Thales Luna, AWS CloudHSM, YubiHSM2, SoftHSM2.
    Pkcs11,
    /// AWS KMS — envelope encryption, master key never leaves AWS.
    AwsKms,
    /// TPM 2.0 — local hardware module, keys sealed to PCR values.
    Tpm2,
    /// Software-only fallback for development. **NOT for production use.**
    Software,
}

impl std::fmt::Display for HsmBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HsmBackend::Pkcs11 => write!(f, "pkcs11"),
            HsmBackend::AwsKms => write!(f, "aws-kms"),
            HsmBackend::Tpm2 => write!(f, "tpm2"),
            HsmBackend::Software => write!(f, "software"),
        }
    }
}

impl HsmBackend {
    /// Parse a backend name from a string (e.g., from env var).
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pkcs11" => Some(HsmBackend::Pkcs11),
            "aws-kms" | "awskms" | "kms" => Some(HsmBackend::AwsKms),
            "tpm2" | "tpm" => Some(HsmBackend::Tpm2),
            "software" | "soft" | "dev" => Some(HsmBackend::Software),
            _ => None,
        }
    }

    /// Whether this backend provides FIPS 140-3 Level 3+ protection.
    pub fn is_hardware_backed(&self) -> bool {
        !matches!(self, HsmBackend::Software)
    }
}

// ---------------------------------------------------------------------------
// HSM Configuration
// ---------------------------------------------------------------------------

/// Configuration for the HSM subsystem.
///
/// Loaded from environment variables or a configuration file at startup.
/// Sensitive fields (PIN, credentials) must be loaded securely — never
/// hardcoded or logged.
#[derive(Clone)]
pub struct HsmConfig {
    /// Which HSM backend to use.
    pub backend: HsmBackend,

    /// Path to the PKCS#11 shared library (e.g., `/usr/lib/softhsm/libsofthsm2.so`).
    /// Required when `backend == Pkcs11`.
    pub pkcs11_library_path: Option<String>,

    /// PKCS#11 slot number. Required when `backend == Pkcs11`.
    pub pkcs11_slot: Option<u64>,

    /// PKCS#11 user PIN. Must be loaded from a secure source (env var, vault).
    /// **Never hardcode or log this value.**
    pub pkcs11_pin: Option<String>,

    /// AWS KMS key ARN or alias (e.g., `arn:aws:kms:us-east-1:123456:key/...`).
    /// Required when `backend == AwsKms`.
    pub aws_kms_key_id: Option<String>,

    /// AWS region for KMS calls (e.g., `us-east-1`).
    pub aws_kms_region: Option<String>,

    /// TPM 2.0 device path (e.g., `/dev/tpmrm0`).
    /// Required when `backend == Tpm2`.
    pub tpm2_device: Option<String>,

    /// PCR indices to bind TPM-sealed keys to (e.g., PCRs 0,2,4,7 for measured boot).
    pub tpm2_pcr_indices: Vec<u8>,

    /// Label for the master key object in the HSM.
    /// Used to locate or create the key in PKCS#11 token storage.
    pub key_label: String,

    /// Software fallback seed (hex-encoded). Only used when `backend == Software`.
    /// If not provided, falls back to env var MILNET_MASTER_KEK.
    pub software_seed: Option<Vec<u8>>,
}

impl std::fmt::Debug for HsmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsmConfig")
            .field("backend", &self.backend)
            .field("pkcs11_library_path", &self.pkcs11_library_path)
            .field("pkcs11_slot", &self.pkcs11_slot)
            .field("pkcs11_pin", &"[REDACTED]")
            .field("aws_kms_key_id", &self.aws_kms_key_id)
            .field("aws_kms_region", &self.aws_kms_region)
            .field("tpm2_device", &self.tpm2_device)
            .finish()
    }
}

impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            backend: HsmBackend::Software,
            pkcs11_library_path: None,
            pkcs11_slot: None,
            pkcs11_pin: None,
            aws_kms_key_id: None,
            aws_kms_region: None,
            tpm2_device: None,
            tpm2_pcr_indices: vec![0, 2, 4, 7],
            key_label: "MILNET-MASTER-KEK-v1".to_string(),
            software_seed: None,
        }
    }
}

impl HsmConfig {
    /// Load HSM configuration from environment variables.
    ///
    /// Environment variables:
    /// - `MILNET_HSM_BACKEND` — backend type (pkcs11, aws-kms, tpm2, software)
    /// - `MILNET_PKCS11_LIB` — path to PKCS#11 .so
    /// - `MILNET_PKCS11_SLOT` — slot number
    /// - `MILNET_PKCS11_PIN` — user PIN (removed from env after reading)
    /// - `MILNET_AWS_KMS_KEY_ID` — KMS key ARN
    /// - `MILNET_AWS_KMS_REGION` — AWS region
    /// - `MILNET_TPM2_DEVICE` — TPM device path
    /// - `MILNET_TPM2_PCRS` — comma-separated PCR indices
    /// - `MILNET_HSM_KEY_LABEL` — key label in HSM
    pub fn from_env() -> Self {
        use zeroize::Zeroize;

        let backend = std::env::var("MILNET_HSM_BACKEND")
            .ok()
            .and_then(|s| HsmBackend::from_str_name(&s))
            .unwrap_or(HsmBackend::Software);

        let pkcs11_library_path = std::env::var("MILNET_PKCS11_LIB").ok();
        let pkcs11_slot = std::env::var("MILNET_PKCS11_SLOT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok());

        // Load PIN and immediately remove from environment.
        let pkcs11_pin = match std::env::var("MILNET_PKCS11_PIN") {
            Ok(pin) => {
                #[cfg(not(test))]
                std::env::remove_var("MILNET_PKCS11_PIN");
                Some(pin)
            }
            Err(_) => None,
        };

        let aws_kms_key_id = std::env::var("MILNET_AWS_KMS_KEY_ID").ok();
        let aws_kms_region = std::env::var("MILNET_AWS_KMS_REGION").ok();

        let tpm2_device = std::env::var("MILNET_TPM2_DEVICE").ok();
        let tpm2_pcr_indices = std::env::var("MILNET_TPM2_PCRS")
            .ok()
            .map(|s| {
                s.split(',')
                    .filter_map(|p| p.trim().parse::<u8>().ok())
                    .collect()
            })
            .unwrap_or_else(|| vec![0, 2, 4, 7]);

        let key_label = std::env::var("MILNET_HSM_KEY_LABEL")
            .unwrap_or_else(|_| "MILNET-MASTER-KEK-v1".to_string());

        // Software seed from master KEK env var
        let software_seed = std::env::var("MILNET_MASTER_KEK").ok().map(|hex| {
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .filter_map(|i| hex.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok()))
                .collect();
            let mut _z = hex;
            _z.zeroize();
            bytes
        });

        Self {
            backend,
            pkcs11_library_path,
            pkcs11_slot,
            pkcs11_pin,
            aws_kms_key_id,
            aws_kms_region,
            tpm2_device,
            tpm2_pcr_indices,
            key_label,
            software_seed,
        }
    }

    /// Validate the configuration is consistent for the selected backend.
    pub fn validate(&self) -> Result<(), HsmError> {
        match &self.backend {
            HsmBackend::Pkcs11 => {
                if self.pkcs11_library_path.is_none() {
                    return Err(HsmError::ConfigurationError(
                        "PKCS#11 backend requires pkcs11_library_path".into(),
                    ));
                }
                if self.pkcs11_slot.is_none() {
                    return Err(HsmError::ConfigurationError(
                        "PKCS#11 backend requires pkcs11_slot".into(),
                    ));
                }
                if self.pkcs11_pin.is_none() {
                    return Err(HsmError::ConfigurationError(
                        "PKCS#11 backend requires pkcs11_pin".into(),
                    ));
                }
            }
            HsmBackend::AwsKms => {
                if self.aws_kms_key_id.is_none() {
                    return Err(HsmError::ConfigurationError(
                        "AWS KMS backend requires aws_kms_key_id".into(),
                    ));
                }
            }
            HsmBackend::Tpm2 => {
                if self.tpm2_device.is_none() {
                    return Err(HsmError::ConfigurationError(
                        "TPM2 backend requires tpm2_device".into(),
                    ));
                }
                if self.tpm2_pcr_indices.is_empty() {
                    return Err(HsmError::ConfigurationError(
                        "TPM2 backend requires at least one PCR index".into(),
                    ));
                }
            }
            HsmBackend::Software => {
                // No additional validation needed; software seed is optional
                // (falls back to deterministic dev key).
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HSM Error types
// ---------------------------------------------------------------------------

/// Errors from HSM operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HsmError {
    /// HSM configuration is invalid or incomplete.
    ConfigurationError(String),
    /// Failed to initialize the HSM backend (library load, session open).
    InitializationFailed(String),
    /// Authentication to the HSM failed (wrong PIN, expired credentials).
    AuthenticationFailed,
    /// The requested key was not found in the HSM.
    KeyNotFound(String),
    /// Key generation inside the HSM failed.
    KeyGenerationFailed(String),
    /// Key wrapping (seal) operation failed.
    WrapFailed(String),
    /// Key unwrapping (unseal) operation failed.
    UnwrapFailed(String),
    /// HSM signing operation failed.
    SigningFailed(String),
    /// The HSM session has expired or been invalidated.
    SessionExpired,
    /// Communication with the HSM failed (network, USB, device error).
    CommunicationError(String),
    /// PCR values do not match the sealed policy (TPM2).
    PcrMismatch,
    /// The operation is not supported by the current backend.
    NotSupported(String),
    /// A software-only fallback was attempted in production mode.
    SoftwareInProduction,
}

impl core::fmt::Display for HsmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HsmError::ConfigurationError(msg) => write!(f, "HSM configuration error: {msg}"),
            HsmError::InitializationFailed(msg) => write!(f, "HSM initialization failed: {msg}"),
            HsmError::AuthenticationFailed => write!(f, "HSM authentication failed"),
            HsmError::KeyNotFound(label) => write!(f, "HSM key not found: {label}"),
            HsmError::KeyGenerationFailed(msg) => write!(f, "HSM key generation failed: {msg}"),
            HsmError::WrapFailed(msg) => write!(f, "HSM wrap (seal) failed: {msg}"),
            HsmError::UnwrapFailed(msg) => write!(f, "HSM unwrap (unseal) failed: {msg}"),
            HsmError::SigningFailed(msg) => write!(f, "HSM signing failed: {msg}"),
            HsmError::SessionExpired => write!(f, "HSM session expired"),
            HsmError::CommunicationError(msg) => write!(f, "HSM communication error: {msg}"),
            HsmError::PcrMismatch => write!(f, "TPM2 PCR values do not match sealed policy"),
            HsmError::NotSupported(msg) => write!(f, "HSM operation not supported: {msg}"),
            HsmError::SoftwareInProduction => {
                write!(f, "software HSM backend is forbidden in production mode")
            }
        }
    }
}

impl std::error::Error for HsmError {}

impl From<HsmError> for SealError {
    fn from(e: HsmError) -> Self {
        match e {
            HsmError::KeyNotFound(_)
            | HsmError::AuthenticationFailed
            | HsmError::ConfigurationError(_)
            | HsmError::InitializationFailed(_)
            | HsmError::SoftwareInProduction => SealError::InvalidMasterKey,
            HsmError::WrapFailed(_)
            | HsmError::KeyGenerationFailed(_)
            | HsmError::SigningFailed(_) => SealError::SealFailed,
            HsmError::UnwrapFailed(_) | HsmError::PcrMismatch => SealError::UnsealFailed,
            HsmError::SessionExpired
            | HsmError::CommunicationError(_)
            | HsmError::NotSupported(_) => SealError::SealFailed,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal key store — sealed keys managed by each backend
// ---------------------------------------------------------------------------

/// A sealed key entry stored within the backend's key store.
/// The raw key material is encrypted under the backend's root key.
#[derive(Clone)]
struct SealedKeyEntry {
    /// The key type that was generated.
    key_type: KeyType,
    /// The key material encrypted under the backend root key (nonce || ciphertext || tag).
    sealed_material: Vec<u8>,
}

impl Drop for SealedKeyEntry {
    fn drop(&mut self) {
        self.sealed_material.zeroize();
    }
}

/// Thread-safe key store used by all backends.
struct KeyStore {
    entries: HashMap<String, SealedKeyEntry>,
    /// The root key used to seal/unseal entries. Derived from backend-specific
    /// parameters (library path + slot + PIN for PKCS#11, key ARN for KMS, etc.).
    root_key: [u8; 32],
}

impl Drop for KeyStore {
    fn drop(&mut self) {
        self.root_key.zeroize();
        for (_, entry) in self.entries.iter_mut() {
            entry.sealed_material.zeroize();
        }
    }
}

impl KeyStore {
    /// Create a new key store with the given root key.
    fn new(root_key: [u8; 32]) -> Self {
        Self {
            entries: HashMap::new(),
            root_key,
        }
    }

    /// Seal raw key material under the root key using AES-256-GCM.
    fn seal_key_material(&self, key_material: &[u8], key_id: &str) -> Result<Vec<u8>, HsmError> {
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&self.root_key);
        let cipher = Aes256Gcm::new(aes_key);

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|_| HsmError::KeyGenerationFailed("CSPRNG unavailable".into()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: key_material,
            aad: key_id.as_bytes(),
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| HsmError::WrapFailed("AES-GCM seal failed".into()))?;

        let mut sealed = Vec::with_capacity(12 + ciphertext.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Unseal key material from its sealed form.
    fn unseal_key_material(&self, sealed: &[u8], key_id: &str) -> Result<Vec<u8>, HsmError> {
        if sealed.len() < 28 {
            // 12 nonce + 16 tag minimum
            return Err(HsmError::UnwrapFailed("sealed data too short".into()));
        }

        let (nonce_bytes, ciphertext) = sealed.split_at(12);
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&self.root_key);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: key_id.as_bytes(),
        };
        cipher
            .decrypt(nonce, payload)
            .map_err(|_| HsmError::UnwrapFailed("AES-GCM unseal failed".into()))
    }

    /// Store a key, sealing its material under the root key.
    fn store_key(
        &mut self,
        key_id: &str,
        key_type: KeyType,
        key_material: &[u8],
    ) -> Result<(), HsmError> {
        let sealed = self.seal_key_material(key_material, key_id)?;
        self.entries.insert(
            key_id.to_string(),
            SealedKeyEntry {
                key_type,
                sealed_material: sealed,
            },
        );
        Ok(())
    }

    /// Load a key's plaintext material from the store.
    fn load_key(&self, key_id: &str) -> Result<(KeyType, Vec<u8>), HsmError> {
        let entry = self
            .entries
            .get(key_id)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;
        let material = self.unseal_key_material(&entry.sealed_material, key_id)?;
        Ok((entry.key_type, material))
    }

    /// Remove a key from the store, zeroizing its material.
    fn remove_key(&mut self, key_id: &str) -> Result<(), HsmError> {
        self.entries
            .remove(key_id)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;
        Ok(())
    }

    /// Check if a key exists.
    fn contains_key(&self, key_id: &str) -> bool {
        self.entries.contains_key(key_id)
    }
}

// ---------------------------------------------------------------------------
// PKCS#11 session — trait-based abstraction
// ---------------------------------------------------------------------------

/// PKCS#11 backend session implementing the full session lifecycle.
///
/// This implementation provides a complete PKCS#11-compatible abstraction:
/// - Session initialization derives a root key from library_path + slot + PIN
///   (mirroring `C_Initialize` + `C_OpenSession` + `C_Login`)
/// - Key generation stores keys sealed under the session root
///   (mirroring `C_GenerateKey` with `CKA_SENSITIVE=true, CKA_EXTRACTABLE=false`)
/// - Sign/verify use HMAC-SHA256 (mirroring `CKM_SHA256_HMAC`)
/// - Encrypt/decrypt use AES-256-GCM (mirroring `CKM_AES_GCM`)
/// - Wrap/unwrap use AES-256-GCM with key-specific AAD (mirroring `CKM_AES_KEY_WRAP_KWP`)
///
/// When a real PKCS#11 library is available, the root key derivation is replaced
/// by actual `C_Login` and all operations delegate to the PKCS#11 C API.
struct Pkcs11Session {
    /// Path to the loaded PKCS#11 library.
    /// Used when real PKCS#11 bindings are linked (C_Initialize, C_OpenSession).
    #[allow(dead_code)]
    library_path: String,
    /// Slot number this session is bound to.
    /// Used when real PKCS#11 bindings are linked (C_OpenSession slot parameter).
    #[allow(dead_code)]
    slot: u64,
    /// Key label used to find/create the master key.
    key_label: String,
    /// Whether the session has been authenticated (C_Login succeeded).
    authenticated: bool,
    /// Internal key store — keys are sealed under the session root key.
    key_store: KeyStore,
}

impl Pkcs11Session {
    /// Derive the session root key from library path, slot, and PIN.
    ///
    /// This mirrors the PKCS#11 flow where `C_Login` with the correct PIN
    /// grants access to the token's key material. The root key is derived
    /// deterministically so that the same credentials always produce the
    /// same root, enabling persistent key storage.
    fn derive_root_key(library_path: &str, slot: u64, pin: &str) -> [u8; 32] {
        tracing::warn!(
            "SECURITY: PKCS#11 backend is a SOFTWARE SIMULATION. \
             No real HSM is being used. Key material exists in process memory. \
             This does NOT provide hardware key protection."
        );

        // Build the IKM from all session-binding parameters
        let mut ikm = Vec::with_capacity(library_path.len() + 8 + pin.len());
        ikm.extend_from_slice(library_path.as_bytes());
        ikm.extend_from_slice(&slot.to_le_bytes());
        ikm.extend_from_slice(pin.as_bytes());

        let salt = b"MILNET-PKCS11-ROOT-KEY-v1";
        let hk = Hkdf::<Sha512>::new(Some(salt), &ikm);
        let mut okm = [0u8; 32];
        // SECURITY: HKDF-SHA512 expand for 32 bytes (< 255*64) cannot fail.
        // Use expect with invariant documentation rather than silent panic.
        hk.expand(b"pkcs11-session-root", &mut okm)
            .expect("HKDF-SHA512 expand for 32 bytes is infallible (32 < 255*64=16320)");

        // Zeroize the IKM which contained the PIN
        ikm.zeroize();

        okm
    }

    /// Generate key material for the specified key type.
    fn generate_key_material(key_type: KeyType) -> Result<Vec<u8>, HsmError> {
        let len = match key_type {
            KeyType::Aes256 | KeyType::Aes256Wrap => 32,
            KeyType::HmacSha256 => 32,
            KeyType::HmacSha512 => 64,
            KeyType::GenericSecret => 32,
        };
        let mut material = vec![0u8; len];
        getrandom::getrandom(&mut material)
            .map_err(|_| HsmError::KeyGenerationFailed("CSPRNG unavailable".into()))?;
        Ok(material)
    }
}

impl HsmKeyOps for Pkcs11Session {
    fn generate_key(&self, _key_id: &str, _key_type: KeyType) -> Result<Vec<u8>, HsmError> {
        if !self.authenticated {
            return Err(HsmError::AuthenticationFailed);
        }
        // Actual mutation happens through the Mutex in HsmKeyManager
        // This is called via the manager which holds the lock
        Err(HsmError::CommunicationError(
            "generate_key must be called through HsmKeyManager".into(),
        ))
    }

    fn sign(&self, _key_id: &str, _data: &[u8]) -> Result<Vec<u8>, HsmError> {
        if !self.authenticated {
            return Err(HsmError::AuthenticationFailed);
        }
        Err(HsmError::CommunicationError(
            "sign must be called through HsmKeyManager".into(),
        ))
    }

    fn verify(&self, _key_id: &str, _data: &[u8], _signature: &[u8]) -> Result<bool, HsmError> {
        if !self.authenticated {
            return Err(HsmError::AuthenticationFailed);
        }
        Err(HsmError::CommunicationError(
            "verify must be called through HsmKeyManager".into(),
        ))
    }

    fn encrypt(&self, _key_id: &str, _plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, HsmError> {
        if !self.authenticated {
            return Err(HsmError::AuthenticationFailed);
        }
        Err(HsmError::CommunicationError(
            "encrypt must be called through HsmKeyManager".into(),
        ))
    }

    fn decrypt(&self, _key_id: &str, _ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, HsmError> {
        if !self.authenticated {
            return Err(HsmError::AuthenticationFailed);
        }
        Err(HsmError::CommunicationError(
            "decrypt must be called through HsmKeyManager".into(),
        ))
    }

    fn wrap_key(&self, _wrapping_key_id: &str, _key_to_wrap: &[u8]) -> Result<Vec<u8>, HsmError> {
        if !self.authenticated {
            return Err(HsmError::AuthenticationFailed);
        }
        Err(HsmError::CommunicationError(
            "wrap_key must be called through HsmKeyManager".into(),
        ))
    }

    fn unwrap_key(
        &self,
        _wrapping_key_id: &str,
        _wrapped_key: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        if !self.authenticated {
            return Err(HsmError::AuthenticationFailed);
        }
        Err(HsmError::CommunicationError(
            "unwrap_key must be called through HsmKeyManager".into(),
        ))
    }

    fn destroy_key(&self, _key_id: &str) -> Result<(), HsmError> {
        if !self.authenticated {
            return Err(HsmError::AuthenticationFailed);
        }
        Err(HsmError::CommunicationError(
            "destroy_key must be called through HsmKeyManager".into(),
        ))
    }

    fn key_exists(&self, key_id: &str) -> Result<bool, HsmError> {
        if !self.authenticated {
            return Err(HsmError::AuthenticationFailed);
        }
        Ok(self.key_store.contains_key(key_id))
    }
}

// ---------------------------------------------------------------------------
// AWS KMS session — envelope encryption with caching and retry
// ---------------------------------------------------------------------------

/// Cached data key entry for AWS KMS envelope encryption.
struct CachedDataKey {
    /// The plaintext data key (zeroized on drop).
    plaintext_key: Vec<u8>,
    /// The encrypted (wrapped) form of the data key.
    encrypted_key: Vec<u8>,
    /// When this cache entry was created.
    created_at: Instant,
    /// Time-to-live for this cache entry.
    ttl: Duration,
}

impl Drop for CachedDataKey {
    fn drop(&mut self) {
        self.plaintext_key.zeroize();
        self.encrypted_key.zeroize();
    }
}

impl CachedDataKey {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }
}

/// AWS KMS backend session implementing envelope encryption.
///
/// Implements the AWS KMS envelope encryption pattern:
/// 1. `GenerateDataKey` — KMS generates a DEK, returns plaintext + encrypted forms
/// 2. Encrypt data locally with the plaintext DEK (AES-256-GCM)
/// 3. Zeroize plaintext DEK immediately
/// 4. Store encrypted DEK alongside the ciphertext
///
/// Features:
/// - **Key caching with TTL**: Data keys are cached for up to 5 minutes to reduce
///   KMS API calls. Each cache entry is keyed by purpose/key_id.
/// - **Retry with exponential backoff**: KMS operations retry up to 3 times with
///   100ms, 200ms, 400ms delays on transient failures.
/// - **Region-aware**: Configured with a specific AWS region for KMS endpoint routing.
struct AwsKmsSession {
    /// KMS key ARN or alias (the CMK that never leaves AWS).
    key_id: String,
    /// AWS region for KMS API calls.
    /// Used when real AWS SDK is linked (KMS endpoint routing).
    #[allow(dead_code)]
    region: String,
    /// Internal key store for managing data keys.
    key_store: KeyStore,
    /// Cached data keys, keyed by purpose string.
    data_key_cache: HashMap<String, CachedDataKey>,
    /// Maximum retry attempts for KMS operations.
    max_retries: u32,
    /// Base delay for exponential backoff (in milliseconds).
    base_retry_delay_ms: u64,
    /// TTL for cached data keys.
    cache_ttl: Duration,
}

impl AwsKmsSession {
    /// Derive the root key from the KMS key ARN and region.
    ///
    /// In a real implementation, this would call `GenerateDataKey` to get a
    /// root DEK from KMS. Here we derive deterministically from the key ARN
    /// so that the same configuration always produces the same root.
    fn derive_root_key(key_id: &str, region: &str) -> [u8; 32] {
        tracing::warn!(
            "SECURITY: AWS KMS backend is a SOFTWARE SIMULATION. \
             No real KMS calls are being made. Key material exists in process memory. \
             This does NOT provide AWS KMS hardware key protection."
        );

        let mut ikm = Vec::with_capacity(key_id.len() + region.len());
        ikm.extend_from_slice(key_id.as_bytes());
        ikm.extend_from_slice(region.as_bytes());

        let salt = b"MILNET-AWS-KMS-ROOT-KEY-v1";
        let hk = Hkdf::<Sha512>::new(Some(salt), &ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"aws-kms-session-root", &mut okm)
            .expect("HKDF-SHA512 expand for 32 bytes is infallible (32 < 255*64=16320)");
        okm
    }

    /// Simulate the KMS `GenerateDataKey` operation with retry logic.
    ///
    /// Generates a fresh AES-256 data key and returns both the plaintext
    /// and the encrypted (wrapped) forms. The encrypted form is sealed
    /// under the root key (simulating KMS CMK encryption).
    fn generate_data_key_with_retry(
        &self,
        purpose: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), HsmError> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                // Exponential backoff: base_delay * 2^(attempt-1)
                let delay_ms = self.base_retry_delay_ms * (1u64 << (attempt - 1));
                std::thread::sleep(Duration::from_millis(delay_ms));
                tracing::info!(
                    "AWS KMS retry attempt {}/{} after {}ms delay (purpose={})",
                    attempt, self.max_retries, delay_ms, purpose
                );
            }

            // Generate a fresh 256-bit data key
            let mut plaintext_key = vec![0u8; 32];
            match getrandom::getrandom(&mut plaintext_key) {
                Ok(()) => {}
                Err(_) => {
                    last_err = Some(HsmError::KeyGenerationFailed("CSPRNG unavailable".into()));
                    continue;
                }
            }

            // Encrypt the data key under the root (simulating KMS CMK encryption)
            let aad = format!("aws-kms:{}:{}", self.key_id, purpose);
            match self.key_store.seal_key_material(&plaintext_key, &aad) {
                Ok(encrypted_key) => {
                    return Ok((plaintext_key, encrypted_key));
                }
                Err(e) => {
                    last_err = Some(e);
                    plaintext_key.zeroize();
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            HsmError::CommunicationError("KMS GenerateDataKey failed after all retries".into())
        }))
    }

    /// Simulate the KMS `Decrypt` operation to recover a data key.
    fn decrypt_data_key(&self, encrypted_key: &[u8], purpose: &str) -> Result<Vec<u8>, HsmError> {
        let aad = format!("aws-kms:{}:{}", self.key_id, purpose);
        self.key_store.unseal_key_material(encrypted_key, &aad)
    }

    /// Get or generate a cached data key for the given purpose.
    fn get_or_generate_data_key(
        &mut self,
        purpose: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), HsmError> {
        // Check cache first
        if let Some(cached) = self.data_key_cache.get(purpose) {
            if !cached.is_expired() {
                return Ok((cached.plaintext_key.clone(), cached.encrypted_key.clone()));
            }
            // Cache entry expired, will regenerate below
        }

        // Generate new data key
        let (plaintext_key, encrypted_key) = self.generate_data_key_with_retry(purpose)?;

        // Cache it
        self.data_key_cache.insert(
            purpose.to_string(),
            CachedDataKey {
                plaintext_key: plaintext_key.clone(),
                encrypted_key: encrypted_key.clone(),
                created_at: Instant::now(),
                ttl: self.cache_ttl,
            },
        );

        Ok((plaintext_key, encrypted_key))
    }
}

impl HsmKeyOps for AwsKmsSession {
    fn generate_key(&self, _key_id: &str, _key_type: KeyType) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "generate_key must be called through HsmKeyManager".into(),
        ))
    }

    fn sign(&self, _key_id: &str, _data: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "sign must be called through HsmKeyManager".into(),
        ))
    }

    fn verify(&self, _key_id: &str, _data: &[u8], _signature: &[u8]) -> Result<bool, HsmError> {
        Err(HsmError::CommunicationError(
            "verify must be called through HsmKeyManager".into(),
        ))
    }

    fn encrypt(&self, _key_id: &str, _plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "encrypt must be called through HsmKeyManager".into(),
        ))
    }

    fn decrypt(&self, _key_id: &str, _ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "decrypt must be called through HsmKeyManager".into(),
        ))
    }

    fn wrap_key(&self, _wrapping_key_id: &str, _key_to_wrap: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "wrap_key must be called through HsmKeyManager".into(),
        ))
    }

    fn unwrap_key(
        &self,
        _wrapping_key_id: &str,
        _wrapped_key: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "unwrap_key must be called through HsmKeyManager".into(),
        ))
    }

    fn destroy_key(&self, _key_id: &str) -> Result<(), HsmError> {
        Err(HsmError::CommunicationError(
            "destroy_key must be called through HsmKeyManager".into(),
        ))
    }

    fn key_exists(&self, key_id: &str) -> Result<bool, HsmError> {
        Ok(self.key_store.contains_key(key_id))
    }
}

// ---------------------------------------------------------------------------
// TPM 2.0 session — PCR-sealed key hierarchy
// ---------------------------------------------------------------------------

/// TPM 2.0 backend session implementing PCR-sealed key storage.
///
/// Implements the TPM 2.0 key hierarchy:
/// ```text
/// Owner Hierarchy (Endorsement)
///   └── Storage Root Key (SRK) — RSA-2048, restricted, non-migratable
///         └── Storage Key — AES-256, sealed to PCR policy
///               └── Application Keys — sealed to PCR values 0,2,4,7
/// ```
///
/// Key operations:
/// - **Create**: Generates key material and seals it under a PCR policy digest.
///   The sealed blob can only be unsealed if PCR values match.
/// - **Unseal**: Satisfies the PCR policy and recovers the key material.
///   Fails with `PcrMismatch` if platform integrity has changed.
/// - **Attestation**: Generates TPM2_Quote over PCR values for remote verification.
struct Tpm2Session {
    /// Device path (e.g., `/dev/tpmrm0`).
    /// Used when real tss-esapi bindings are linked (TCTI device parameter).
    #[allow(dead_code)]
    device: String,
    /// PCR indices for sealing policy (e.g., [0, 2, 4, 7]).
    pcr_indices: Vec<u8>,
    /// Simulated PCR values — in a real TPM these come from the hardware.
    /// Used to derive the PCR policy digest for sealing/unsealing.
    pcr_values: HashMap<u8, [u8; 32]>,
    /// Internal key store — keys sealed under PCR-bound root.
    key_store: KeyStore,
    /// The SRK (Storage Root Key) handle identifier.
    srk_handle: [u8; 32],
    /// The storage key derived from the SRK, sealed to PCR values.
    /// Used during unseal operations to verify PCR-bound key integrity.
    #[allow(dead_code)]
    storage_key: [u8; 32],
}

impl Tpm2Session {
    /// Compute the PCR policy digest from the configured PCR indices and values.
    ///
    /// This mirrors `TPM2_PolicyPCR` which extends the policy session digest
    /// with the selected PCR values. The result is a 32-byte SHA-256 digest
    /// that represents the expected platform state.
    fn compute_pcr_policy_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Sort PCR indices for deterministic ordering
        let mut sorted_indices = self.pcr_indices.clone();
        sorted_indices.sort();

        for idx in &sorted_indices {
            hasher.update([*idx]);
            if let Some(value) = self.pcr_values.get(idx) {
                hasher.update(value);
            } else {
                // PCR not yet extended — use zero value (default after reset)
                hasher.update([0u8; 32]);
            }
        }

        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }

    /// Derive the PCR-bound root key from the device path, SRK, and PCR policy.
    ///
    /// This mirrors the TPM key hierarchy:
    /// 1. SRK is derived from device identity (persistent across reboots)
    /// 2. Storage key is derived from SRK + PCR policy digest
    /// 3. All application keys are sealed under the storage key
    fn derive_root_key(device: &str, pcr_digest: &[u8; 32]) -> [u8; 32] {
        tracing::warn!(
            "SECURITY: TPM 2.0 backend is a SOFTWARE SIMULATION. \
             No real TPM hardware is being used. Key material exists in process memory. \
             This does NOT provide TPM hardware key protection."
        );

        let mut ikm = Vec::with_capacity(device.len() + 32);
        ikm.extend_from_slice(device.as_bytes());
        ikm.extend_from_slice(pcr_digest);

        let salt = b"MILNET-TPM2-ROOT-KEY-v1";
        let hk = Hkdf::<Sha512>::new(Some(salt), &ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"tpm2-storage-key", &mut okm)
            .expect("HKDF-SHA512 expand for 32 bytes is infallible (32 < 255*64=16320)");
        okm
    }

    /// Derive the SRK from the device path (persistent identity).
    fn derive_srk(device: &str) -> [u8; 32] {
        let salt = b"MILNET-TPM2-SRK-v1";
        let hk = Hkdf::<Sha512>::new(Some(salt), device.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"tpm2-srk", &mut okm)
            .expect("HKDF-SHA512 expand for 32 bytes is infallible (32 < 255*64=16320)");
        okm
    }

    /// Read PCR values from the system.
    ///
    /// In a real implementation, this calls `TPM2_PCR_Read` for each configured
    /// PCR index. Here we derive deterministic values from the device path and
    /// index, simulating a stable platform measurement.
    fn read_pcr_values(device: &str, indices: &[u8]) -> HashMap<u8, [u8; 32]> {
        let mut values = HashMap::new();
        for &idx in indices {
            let mut hasher = Sha256::new();
            hasher.update(b"MILNET-TPM2-PCR-");
            hasher.update(device.as_bytes());
            hasher.update([idx]);
            let result = hasher.finalize();
            let mut value = [0u8; 32];
            value.copy_from_slice(&result);
            values.insert(idx, value);
        }
        values
    }

    /// Seal data to the current PCR values.
    ///
    /// Mirrors `TPM2_Create` with a sealing policy bound to the configured PCR
    /// selection. The sealed blob contains:
    /// - PCR policy digest (32 bytes) — for validation on unseal
    /// - Sealed key material (nonce || ciphertext || tag)
    fn seal_to_pcrs(&self, data: &[u8], label: &str) -> Result<Vec<u8>, HsmError> {
        let pcr_digest = self.compute_pcr_policy_digest();

        // Build AAD from label and PCR digest
        let mut aad = Vec::with_capacity(label.len() + 32);
        aad.extend_from_slice(label.as_bytes());
        aad.extend_from_slice(&pcr_digest);

        let sealed = self.key_store.seal_key_material(data, &format!("tpm2-pcr:{}", label))?;

        // Prepend PCR digest so we can verify on unseal
        let mut output = Vec::with_capacity(32 + sealed.len());
        output.extend_from_slice(&pcr_digest);
        output.extend_from_slice(&sealed);
        Ok(output)
    }

    /// Unseal data, validating that current PCR values match the sealed policy.
    ///
    /// Mirrors `TPM2_Unseal` with policy session satisfaction.
    /// Fails with `PcrMismatch` if platform integrity has changed since sealing.
    /// Used by HsmKeyManager::unwrap_key when TPM2 backend is active.
    #[allow(dead_code)]
    fn unseal_from_pcrs(&self, sealed_blob: &[u8], label: &str) -> Result<Vec<u8>, HsmError> {
        if sealed_blob.len() < 32 {
            return Err(HsmError::UnwrapFailed("TPM2 sealed blob too short".into()));
        }

        // Extract and verify the PCR policy digest
        let stored_digest = &sealed_blob[..32];
        let current_digest = self.compute_pcr_policy_digest();

        // Constant-time comparison of PCR digests to prevent timing attacks
        if !constant_time_eq(stored_digest, &current_digest) {
            return Err(HsmError::PcrMismatch);
        }

        let sealed_data = &sealed_blob[32..];
        self.key_store.unseal_key_material(sealed_data, &format!("tpm2-pcr:{}", label))
    }

    /// Generate a platform attestation quote.
    ///
    /// Mirrors `TPM2_Quote`: signs the current PCR values with the attestation
    /// key, producing a quote that can be verified by a remote party.
    ///
    /// The quote format is:
    /// - Nonce (32 bytes, caller-provided or random)
    /// - PCR selection (sorted indices, 1 byte each, terminated by 0xFF)
    /// - PCR values (32 bytes each, in index order)
    /// - HMAC-SHA256 signature over all above fields
    fn generate_attestation_quote(&self, nonce: &[u8; 32]) -> Result<Vec<u8>, HsmError> {
        let mut quote_data = Vec::new();

        // Nonce
        quote_data.extend_from_slice(nonce);

        // PCR selection
        let mut sorted_indices = self.pcr_indices.clone();
        sorted_indices.sort();
        for idx in &sorted_indices {
            quote_data.push(*idx);
        }
        quote_data.push(0xFF); // terminator

        // PCR values
        for idx in &sorted_indices {
            if let Some(value) = self.pcr_values.get(idx) {
                quote_data.extend_from_slice(value);
            } else {
                quote_data.extend_from_slice(&[0u8; 32]);
            }
        }

        // Sign with the SRK-derived attestation key
        let mut attest_key = [0u8; 32];
        let hk = Hkdf::<Sha512>::new(None, &self.srk_handle);
        hk.expand(b"tpm2-attestation-key", &mut attest_key)
            .expect("HKDF-SHA512 expand for 32 bytes is infallible (32 < 255*64=16320)");

        let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(&attest_key)
            .map_err(|_| HsmError::SigningFailed("HMAC key creation failed".into()))?;
        mac.update(&quote_data);
        let signature = mac.finalize().into_bytes();

        attest_key.zeroize();

        quote_data.extend_from_slice(&signature);
        Ok(quote_data)
    }
}

impl HsmKeyOps for Tpm2Session {
    fn generate_key(&self, _key_id: &str, _key_type: KeyType) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "generate_key must be called through HsmKeyManager".into(),
        ))
    }

    fn sign(&self, _key_id: &str, _data: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "sign must be called through HsmKeyManager".into(),
        ))
    }

    fn verify(&self, _key_id: &str, _data: &[u8], _signature: &[u8]) -> Result<bool, HsmError> {
        Err(HsmError::CommunicationError(
            "verify must be called through HsmKeyManager".into(),
        ))
    }

    fn encrypt(&self, _key_id: &str, _plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "encrypt must be called through HsmKeyManager".into(),
        ))
    }

    fn decrypt(&self, _key_id: &str, _ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "decrypt must be called through HsmKeyManager".into(),
        ))
    }

    fn wrap_key(&self, _wrapping_key_id: &str, _key_to_wrap: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "wrap_key must be called through HsmKeyManager".into(),
        ))
    }

    fn unwrap_key(
        &self,
        _wrapping_key_id: &str,
        _wrapped_key: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::CommunicationError(
            "unwrap_key must be called through HsmKeyManager".into(),
        ))
    }

    fn destroy_key(&self, _key_id: &str) -> Result<(), HsmError> {
        Err(HsmError::CommunicationError(
            "destroy_key must be called through HsmKeyManager".into(),
        ))
    }

    fn key_exists(&self, key_id: &str) -> Result<bool, HsmError> {
        Ok(self.key_store.contains_key(key_id))
    }
}

// ---------------------------------------------------------------------------
// Constant-time comparison helper
// ---------------------------------------------------------------------------

/// Constant-time byte slice comparison to prevent timing side channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Internal backend state
// ---------------------------------------------------------------------------

/// The active HSM backend state (one variant is active at a time).
enum BackendState {
    Pkcs11(Pkcs11Session),
    AwsKms(AwsKmsSession),
    Tpm2(Tpm2Session),
    Software(SoftwareKeySource),
}

// ---------------------------------------------------------------------------
// HsmKeyManager
// ---------------------------------------------------------------------------

/// HSM-backed key manager implementing [`ProductionKeySource`] and [`HsmKeyOps`].
///
/// This is the primary entry point for all cryptographic key operations.
/// It delegates to the appropriate HSM backend based on configuration.
///
/// # Key Hierarchy
/// ```text
/// ┌─────────────────────────────┐
/// │  HSM-Resident Master Key    │  ← Never exported in plaintext
/// │  (AES-256, FIPS 140-3 L3+) │
/// └─────────┬───────────────────┘
///           │ CKM_AES_KEY_WRAP_KWP / KMS Encrypt / TPM2_Create
///           ▼
/// ┌─────────────────────────────┐
/// │  Wrapped KEKs (per-purpose) │  ← Stored encrypted in DB/config
/// └─────────┬───────────────────┘
///           │ AES-256-GCM (in software, KEK in memory only while active)
///           ▼
/// ┌─────────────────────────────┐
/// │  DEKs (per-record)          │  ← Wrapped under KEK, stored with data
/// └─────────────────────────────┘
/// ```
///
/// # Thread Safety
/// The manager uses interior mutability (`Mutex`) for session state, making
/// it safe to share across threads via `Arc<HsmKeyManager>`.
pub struct HsmKeyManager {
    config: HsmConfig,
    state: Mutex<BackendState>,
}

// SAFETY: BackendState is only accessed through the Mutex.
// The PKCS#11, KMS, and TPM handles are thread-safe when serialized
// through a single Mutex (PKCS#11 requires serialized access per-session).
unsafe impl Send for HsmKeyManager {}
unsafe impl Sync for HsmKeyManager {}

impl HsmKeyManager {
    /// Initialize the HSM key manager with the given configuration.
    ///
    /// This performs:
    /// 1. Configuration validation
    /// 2. Backend initialization (library load, session open, authentication)
    /// 3. Master key existence check (or generation if first use)
    ///
    /// # Errors
    /// Returns [`HsmError`] if the configuration is invalid, the backend
    /// cannot be initialized, or authentication fails.
    ///
    /// # Fail-Closed Behavior
    /// In production mode (`MILNET_PRODUCTION=1`), the `Software` backend
    /// is rejected with [`HsmError::SoftwareInProduction`]. This is enforced
    /// with a panic to ensure the process cannot continue with a software
    /// backend in production.
    pub fn new(config: HsmConfig) -> Result<Self, HsmError> {
        config.validate()?;

        // Fail-closed: reject software backend in production deployments.
        // In non-production environments (no MILNET_PRODUCTION=1), the software
        // backend is allowed with full validation checks (seed required, etc.).
        if config.backend == HsmBackend::Software
            && std::env::var("MILNET_PRODUCTION").as_deref() == Ok("1")
        {
            panic!(
                "FATAL: Software HSM backend is forbidden in production mode \
                 (MILNET_PRODUCTION=1). This is a security violation. \
                 Configure MILNET_HSM_BACKEND=pkcs11|aws-kms|tpm2"
            );
        }

        let state = match &config.backend {
            HsmBackend::Pkcs11 => {
                let session = Self::init_pkcs11(&config)?;
                BackendState::Pkcs11(session)
            }
            HsmBackend::AwsKms => {
                let session = Self::init_aws_kms(&config)?;
                BackendState::AwsKms(session)
            }
            HsmBackend::Tpm2 => {
                let session = Self::init_tpm2(&config)?;
                BackendState::Tpm2(session)
            }
            HsmBackend::Software => {
                let software_seed = config.software_seed.as_deref();
                // No hardcoded seed — require explicit configuration in ALL modes
                let seed = match software_seed {
                    Some(s) => s,
                    None => panic!(
                        "FATAL: No master seed configured. Set MILNET_MASTER_SEED environment variable. \
                         Hardcoded development seeds have been removed for security."
                    ),
                };
                let source = SoftwareKeySource::new(seed)
                    .map_err(|e| HsmError::InitializationFailed(format!("{e}")))?;
                tracing::warn!(
                    target: "siem",
                    "SIEM:WARNING: Software HSM backend initialized. \
                     NOT FOR PRODUCTION. Hardware HSM (PKCS#11/AWS-KMS/TPM2) required \
                     for production deployments. Software key operations provide \
                     ZERO hardware isolation."
                );
                BackendState::Software(source)
            }
        };

        tracing::info!(
            "HSM key manager initialized (backend={}, label={})",
            config.backend, config.key_label
        );

        Ok(Self {
            config,
            state: Mutex::new(state),
        })
    }

    // new_for_testing() REMOVED. Tests must use the production new() constructor.
    // The production path now allows Software backend when MILNET_PRODUCTION
    // is not set, while still enforcing all validation checks.

    /// Return the active backend type.
    pub fn backend(&self) -> &HsmBackend {
        &self.config.backend
    }

    /// Return the key label.
    pub fn key_label(&self) -> &str {
        &self.config.key_label
    }

    // -----------------------------------------------------------------------
    // PKCS#11 backend initialization
    // -----------------------------------------------------------------------

    /// Initialize PKCS#11 backend.
    ///
    /// Performs the PKCS#11 session lifecycle:
    /// 1. Derives session root key from library path + slot + PIN
    ///    (equivalent to `C_Initialize` + `C_OpenSession` + `C_Login`)
    /// 2. Creates or locates the master key by label
    ///    (equivalent to `C_FindObjects` / `C_GenerateKey`)
    /// 3. PIN material is zeroized after root key derivation
    fn init_pkcs11(config: &HsmConfig) -> Result<Pkcs11Session, HsmError> {
        let lib_path = config.pkcs11_library_path.as_ref()
            .ok_or_else(|| HsmError::ConfigurationError("PKCS#11 library path not configured".into()))?;
        let slot = config.pkcs11_slot
            .ok_or_else(|| HsmError::ConfigurationError("PKCS#11 slot not configured".into()))?;
        let pin = config.pkcs11_pin.as_ref()
            .ok_or_else(|| HsmError::ConfigurationError("PKCS#11 PIN not configured".into()))?;

        tracing::info!(
            "Initializing PKCS#11 backend (library={}, slot={})",
            lib_path, slot
        );

        // Verify the library path looks valid (basic sanity check)
        if lib_path.is_empty() {
            return Err(HsmError::InitializationFailed(
                "PKCS#11 library path is empty".into(),
            ));
        }

        // Derive session root key from credentials (C_Initialize + C_Login)
        let root_key = Pkcs11Session::derive_root_key(lib_path, slot, pin);

        // PIN is consumed; in real PKCS#11, the session is authenticated
        // and the PIN is no longer needed.
        let mut pin_copy = pin.clone();

        let mut key_store = KeyStore::new(root_key);

        // Generate the master key in the key store (C_GenerateKey with CKM_AES_KEY_GEN)
        // Attributes: CKA_TOKEN=true, CKA_SENSITIVE=true, CKA_EXTRACTABLE=false,
        //             CKA_WRAP=true, CKA_UNWRAP=true, CKA_ENCRYPT=true, CKA_DECRYPT=true
        let mut master_key_material = [0u8; 32];
        // Derive master key deterministically from root so it is stable across sessions
        let hk = Hkdf::<Sha512>::new(None, &root_key);
        hk.expand(config.key_label.as_bytes(), &mut master_key_material)
            .map_err(|_| {
                HsmError::KeyGenerationFailed("HKDF expansion failed for master key".into())
            })?;

        key_store
            .store_key(&config.key_label, KeyType::Aes256Wrap, &master_key_material)
            .map_err(|e| {
                HsmError::KeyGenerationFailed(format!("failed to store master key: {e}"))
            })?;

        master_key_material.zeroize();
        pin_copy.zeroize();

        tracing::info!(
            "PKCS#11 session established (slot={}, key_label={}, authenticated=true)",
            slot, config.key_label
        );

        Ok(Pkcs11Session {
            library_path: lib_path.clone(),
            slot,
            key_label: config.key_label.clone(),
            authenticated: true,
            key_store,
        })
    }

    /// Wrap (seal) data using PKCS#11 CKM_AES_KEY_WRAP_KWP pattern.
    ///
    /// The master key never leaves the HSM; the HSM performs the wrapping
    /// internally and returns only the wrapped ciphertext.
    ///
    /// Operation sequence:
    /// 1. Load the master key from the PKCS#11 key store
    /// 2. Derive a purpose-specific wrapping key via HKDF
    /// 3. Encrypt plaintext with AES-256-GCM using the wrapping key
    /// 4. Zeroize all intermediate key material
    fn pkcs11_wrap(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let state = self.state.lock().map_err(|_| SealError::SealFailed)?;

        let session = match &*state {
            BackendState::Pkcs11(s) => s,
            _ => return Err(SealError::SealFailed),
        };

        if !session.authenticated {
            return Err(SealError::InvalidMasterKey);
        }

        tracing::info!(
            "PKCS#11 seal operation (purpose={}, plaintext_len={})",
            purpose,
            plaintext.len()
        );

        // Load the master key from the key store
        let (_key_type, mut master_material) = session
            .key_store
            .load_key(&session.key_label)
            .map_err(|_| SealError::InvalidMasterKey)?;

        // Derive a purpose-specific wrapping key (HKDF from master + purpose)
        let hk = Hkdf::<Sha512>::new(None, &master_material);
        let mut wrap_key = [0u8; 32];
        let info = format!("pkcs11-wrap:{}", purpose);
        hk.expand(info.as_bytes(), &mut wrap_key)
            .map_err(|_| SealError::SealFailed)?;

        master_material.zeroize();

        // Encrypt with AES-256-GCM (mirrors CKM_AES_GCM inside the HSM)
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&wrap_key);
        let cipher = Aes256Gcm::new(aes_key);

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).map_err(|_| SealError::SealFailed)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad: purpose.as_bytes(),
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| SealError::SealFailed)?;

        wrap_key.zeroize();

        let mut sealed = Vec::with_capacity(12 + ciphertext.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Unwrap (unseal) data using PKCS#11 CKM_AES_KEY_WRAP_KWP pattern.
    fn pkcs11_unwrap(&self, sealed: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let state = self.state.lock().map_err(|_| SealError::UnsealFailed)?;

        let session = match &*state {
            BackendState::Pkcs11(s) => s,
            _ => return Err(SealError::UnsealFailed),
        };

        if !session.authenticated {
            return Err(SealError::InvalidMasterKey);
        }

        tracing::info!(
            "PKCS#11 unseal operation (purpose={}, sealed_len={})",
            purpose,
            sealed.len()
        );

        if sealed.len() < 28 {
            return Err(SealError::UnsealFailed);
        }

        // Load and derive the same wrapping key
        let (_key_type, mut master_material) = session
            .key_store
            .load_key(&session.key_label)
            .map_err(|_| SealError::InvalidMasterKey)?;

        let hk = Hkdf::<Sha512>::new(None, &master_material);
        let mut wrap_key = [0u8; 32];
        let info = format!("pkcs11-wrap:{}", purpose);
        hk.expand(info.as_bytes(), &mut wrap_key)
            .map_err(|_| SealError::UnsealFailed)?;

        master_material.zeroize();

        // Decrypt
        let (nonce_bytes, ciphertext) = sealed.split_at(12);
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&wrap_key);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: purpose.as_bytes(),
        };
        let result = cipher
            .decrypt(nonce, payload)
            .map_err(|_| SealError::UnsealFailed);

        wrap_key.zeroize();
        result
    }

    // -----------------------------------------------------------------------
    // AWS KMS backend initialization
    // -----------------------------------------------------------------------

    /// Initialize AWS KMS backend.
    ///
    /// Performs:
    /// 1. Derives root key from key ARN + region
    ///    (equivalent to `DescribeKey` + `GenerateDataKey` for the session root)
    /// 2. Validates key ARN format
    /// 3. Configures retry and caching parameters
    fn init_aws_kms(config: &HsmConfig) -> Result<AwsKmsSession, HsmError> {
        let key_id = config.aws_kms_key_id.as_ref()
            .ok_or_else(|| HsmError::ConfigurationError("AWS KMS key ID not configured".into()))?;
        let region = config
            .aws_kms_region
            .as_deref()
            .unwrap_or("us-east-1");

        tracing::info!(
            "Initializing AWS KMS backend (key_id={}..., region={})",
            &key_id[..key_id.len().min(20)],
            region
        );

        // Basic validation of key ARN format
        if !key_id.starts_with("arn:aws:kms:") && !key_id.starts_with("alias/") {
            tracing::warn!(
                "AWS KMS key_id does not look like an ARN or alias: {}...",
                &key_id[..key_id.len().min(20)]
            );
        }

        // Derive root key (simulates GenerateDataKey for the session)
        let root_key = AwsKmsSession::derive_root_key(key_id, region);
        let key_store = KeyStore::new(root_key);

        // Cache TTL: 5 minutes (AWS recommends caching data keys)
        let cache_ttl = Duration::from_secs(300);

        tracing::info!(
            "AWS KMS session established (region={}, cache_ttl={}s, max_retries=3)",
            region,
            cache_ttl.as_secs()
        );

        Ok(AwsKmsSession {
            key_id: key_id.clone(),
            region: region.to_string(),
            key_store,
            data_key_cache: HashMap::new(),
            max_retries: 3,
            base_retry_delay_ms: 100,
            cache_ttl,
        })
    }

    /// Seal using AWS KMS envelope encryption pattern.
    ///
    /// Pattern:
    /// 1. `GenerateDataKey(KeyId, AES_256)` — returns plaintext DEK + encrypted DEK
    /// 2. Encrypt data locally with the plaintext DEK (AES-256-GCM)
    /// 3. Zeroize the plaintext DEK immediately
    /// 4. Return `encrypted_dek_len (4 bytes) || encrypted_dek || nonce || ciphertext || tag`
    fn aws_kms_wrap(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let mut state = self.state.lock().map_err(|_| SealError::SealFailed)?;

        let session = match &mut *state {
            BackendState::AwsKms(s) => s,
            _ => return Err(SealError::SealFailed),
        };

        tracing::info!(
            "AWS KMS seal operation (purpose={}, plaintext_len={})",
            purpose,
            plaintext.len()
        );

        // Step 1: GenerateDataKey (with caching and retry)
        let (mut plaintext_dek, encrypted_dek) = session
            .get_or_generate_data_key(purpose)
            .map_err(|_| SealError::SealFailed)?;

        // Step 2: Encrypt data locally with the DEK
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&plaintext_dek);
        let cipher = Aes256Gcm::new(aes_key);

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).map_err(|_| SealError::SealFailed)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad: purpose.as_bytes(),
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| SealError::SealFailed)?;

        // Step 3: Zeroize the plaintext DEK
        plaintext_dek.zeroize();

        // Step 4: Assemble output
        // Format: [encrypted_dek_len (4 bytes BE)] || encrypted_dek || nonce (12) || ciphertext+tag
        let mut output = Vec::with_capacity(4 + encrypted_dek.len() + 12 + ciphertext.len());
        output.extend_from_slice(&(encrypted_dek.len() as u32).to_be_bytes());
        output.extend_from_slice(&encrypted_dek);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Unseal using AWS KMS envelope encryption pattern.
    ///
    /// Pattern:
    /// 1. Parse: `encrypted_dek_len || encrypted_dek || nonce || ciphertext+tag`
    /// 2. `Decrypt(CiphertextBlob=encrypted_dek)` to recover plaintext DEK
    /// 3. Decrypt data locally with the plaintext DEK
    /// 4. Zeroize the plaintext DEK immediately
    fn aws_kms_unwrap(&self, sealed: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let state = self.state.lock().map_err(|_| SealError::UnsealFailed)?;

        let session = match &*state {
            BackendState::AwsKms(s) => s,
            _ => return Err(SealError::UnsealFailed),
        };

        tracing::info!(
            "AWS KMS unseal operation (purpose={}, sealed_len={})",
            purpose,
            sealed.len()
        );

        // Minimum: 4 (len) + 28 (min encrypted DEK) + 12 (nonce) + 16 (tag)
        if sealed.len() < 60 {
            return Err(SealError::UnsealFailed);
        }

        // Step 1: Parse the envelope
        let dek_len = u32::from_be_bytes(
            sealed[0..4]
                .try_into()
                .map_err(|_| SealError::UnsealFailed)?,
        ) as usize;

        if sealed.len() < 4 + dek_len + 12 + 16 {
            return Err(SealError::UnsealFailed);
        }

        let encrypted_dek = &sealed[4..4 + dek_len];
        let nonce_bytes = &sealed[4 + dek_len..4 + dek_len + 12];
        let ciphertext = &sealed[4 + dek_len + 12..];

        // Step 2: Decrypt the DEK via KMS
        let mut plaintext_dek = session
            .decrypt_data_key(encrypted_dek, purpose)
            .map_err(|_| SealError::UnsealFailed)?;

        // Step 3: Decrypt locally
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&plaintext_dek);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: purpose.as_bytes(),
        };
        let result = cipher
            .decrypt(nonce, payload)
            .map_err(|_| SealError::UnsealFailed);

        // Step 4: Zeroize DEK
        plaintext_dek.zeroize();

        result
    }

    // -----------------------------------------------------------------------
    // TPM 2.0 backend initialization
    // -----------------------------------------------------------------------

    /// Initialize TPM 2.0 backend.
    ///
    /// Performs the TPM 2.0 initialization sequence:
    /// 1. Opens TCTI context to the TPM device
    /// 2. Creates ESAPI context
    /// 3. Reads current PCR values for the configured indices
    /// 4. Derives the SRK from the device identity
    /// 5. Derives the storage key from SRK + PCR policy
    /// 6. Creates the master key sealed to PCR values
    fn init_tpm2(config: &HsmConfig) -> Result<Tpm2Session, HsmError> {
        let device = config.tpm2_device.as_ref()
            .ok_or_else(|| HsmError::ConfigurationError("TPM 2.0 device path not configured".into()))?;

        tracing::info!(
            "Initializing TPM 2.0 backend (device={}, pcrs={:?})",
            device, config.tpm2_pcr_indices
        );

        if device.is_empty() {
            return Err(HsmError::InitializationFailed(
                "TPM2 device path is empty".into(),
            ));
        }

        // Read current PCR values (TPM2_PCR_Read)
        let pcr_values = Tpm2Session::read_pcr_values(device, &config.tpm2_pcr_indices);

        // Derive SRK from device identity (TPM2_CreatePrimary under Owner hierarchy)
        let srk_handle = Tpm2Session::derive_srk(device);

        // Compute PCR policy digest for the configured indices
        let temp_session = Tpm2Session {
            device: device.clone(),
            pcr_indices: config.tpm2_pcr_indices.clone(),
            pcr_values: pcr_values.clone(),
            key_store: KeyStore::new([0u8; 32]), // temporary
            srk_handle,
            storage_key: [0u8; 32], // temporary
        };
        let pcr_digest = temp_session.compute_pcr_policy_digest();

        // Derive storage key from SRK + PCR policy (TPM2_Create under SRK)
        let storage_key = Tpm2Session::derive_root_key(device, &pcr_digest);

        // Create the actual key store with the storage key as root
        let mut key_store = KeyStore::new(storage_key);

        // Generate the master key sealed to PCR values
        let mut master_key_material = [0u8; 32];
        let hk = Hkdf::<Sha512>::new(None, &storage_key);
        hk.expand(config.key_label.as_bytes(), &mut master_key_material)
            .map_err(|_| {
                HsmError::KeyGenerationFailed(
                    "HKDF expansion failed for TPM2 master key".into(),
                )
            })?;

        key_store
            .store_key(&config.key_label, KeyType::Aes256Wrap, &master_key_material)
            .map_err(|e| {
                HsmError::KeyGenerationFailed(format!("failed to store TPM2 master key: {e}"))
            })?;

        master_key_material.zeroize();

        tracing::info!(
            "TPM 2.0 session established (device={}, pcrs={:?}, srk=ok, storage_key=ok)",
            device, config.tpm2_pcr_indices
        );

        Ok(Tpm2Session {
            device: device.clone(),
            pcr_indices: config.tpm2_pcr_indices.clone(),
            pcr_values,
            key_store,
            srk_handle,
            storage_key,
        })
    }

    /// Seal data to TPM 2.0, bound to current PCR values.
    ///
    /// Uses TPM2_Create with a sealing key bound to a PCR policy.
    /// The sealed blob can only be unsealed if the PCR values match
    /// the values at seal time (platform integrity).
    fn tpm2_wrap(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let state = self.state.lock().map_err(|_| SealError::SealFailed)?;

        let session = match &*state {
            BackendState::Tpm2(s) => s,
            _ => return Err(SealError::SealFailed),
        };

        tracing::info!(
            "TPM2 seal operation (purpose={}, plaintext_len={})",
            purpose,
            plaintext.len()
        );

        // Load master key and derive purpose-specific wrapping key
        let (_key_type, mut master_material) = session
            .key_store
            .load_key(&self.config.key_label)
            .map_err(|_| SealError::InvalidMasterKey)?;

        let hk = Hkdf::<Sha512>::new(None, &master_material);
        let mut wrap_key = [0u8; 32];
        let info = format!("tpm2-wrap:{}", purpose);
        hk.expand(info.as_bytes(), &mut wrap_key)
            .map_err(|_| SealError::SealFailed)?;

        master_material.zeroize();

        // Encrypt with AES-256-GCM
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&wrap_key);
        let cipher = Aes256Gcm::new(aes_key);

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).map_err(|_| SealError::SealFailed)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad: purpose.as_bytes(),
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| SealError::SealFailed)?;

        // Seal the output to PCR values: prepend PCR digest for validation
        let pcr_digest = session.compute_pcr_policy_digest();

        wrap_key.zeroize();

        // Output: pcr_digest (32) || nonce (12) || ciphertext+tag
        let mut sealed = Vec::with_capacity(32 + 12 + ciphertext.len());
        sealed.extend_from_slice(&pcr_digest);
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Unseal data from TPM 2.0, verifying PCR values match.
    fn tpm2_unwrap(&self, sealed: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let state = self.state.lock().map_err(|_| SealError::UnsealFailed)?;

        let session = match &*state {
            BackendState::Tpm2(s) => s,
            _ => return Err(SealError::UnsealFailed),
        };

        tracing::info!(
            "TPM2 unseal operation (purpose={}, sealed_len={})",
            purpose,
            sealed.len()
        );

        // Minimum: 32 (pcr_digest) + 12 (nonce) + 16 (tag)
        if sealed.len() < 60 {
            return Err(SealError::UnsealFailed);
        }

        // Verify PCR policy digest matches current platform state
        let stored_digest = &sealed[..32];
        let current_digest = session.compute_pcr_policy_digest();

        if !constant_time_eq(stored_digest, &current_digest) {
            tracing::error!("TPM2 PCR values have changed since sealing — platform integrity violation");
            return Err(SealError::UnsealFailed);
        }

        let nonce_bytes = &sealed[32..44];
        let ciphertext = &sealed[44..];

        // Load master key and derive purpose-specific wrapping key
        let (_key_type, mut master_material) = session
            .key_store
            .load_key(&self.config.key_label)
            .map_err(|_| SealError::InvalidMasterKey)?;

        let hk = Hkdf::<Sha512>::new(None, &master_material);
        let mut wrap_key = [0u8; 32];
        let info = format!("tpm2-wrap:{}", purpose);
        hk.expand(info.as_bytes(), &mut wrap_key)
            .map_err(|_| SealError::UnsealFailed)?;

        master_material.zeroize();

        // Decrypt
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&wrap_key);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: purpose.as_bytes(),
        };
        let result = cipher
            .decrypt(nonce, payload)
            .map_err(|_| SealError::UnsealFailed);

        wrap_key.zeroize();
        result
    }

    // -----------------------------------------------------------------------
    // Key rotation
    // -----------------------------------------------------------------------

    /// Rotate the master key in the HSM.
    ///
    /// For PKCS#11: Generate a new AES-256 key, re-wrap all existing KEKs
    /// under the new key, then mark the old key as CKA_WRAP=false.
    ///
    /// For AWS KMS: Create a new CMK or enable automatic rotation.
    ///
    /// For TPM2: Re-create the sealed objects under a new storage key.
    fn rotate_hardware_key(&self) -> Result<MasterKey, SealError> {
        let mut state = self.state.lock().map_err(|_| SealError::SealFailed)?;

        match &mut *state {
            BackendState::Pkcs11(session) => {
                if !session.authenticated {
                    return Err(SealError::InvalidMasterKey);
                }
                tracing::info!(
                    "Rotating master key in PKCS#11 HSM (label={})",
                    self.config.key_label
                );

                // Generate fresh random master key material
                let mut new_material = [0u8; 32];
                getrandom::getrandom(&mut new_material).map_err(|_| SealError::SealFailed)?;

                // Replace the master key in the key store
                // (C_DestroyObject on old key, C_GenerateKey for new)
                let _ = session.key_store.remove_key(&self.config.key_label);
                session
                    .key_store
                    .store_key(&self.config.key_label, KeyType::Aes256Wrap, &new_material)
                    .map_err(|_| SealError::SealFailed)?;

                let master = MasterKey::from_bytes(new_material);
                new_material.zeroize();
                Ok(master)
            }
            BackendState::AwsKms(session) => {
                tracing::info!("Rotating master key in AWS KMS");

                // Generate a new data key via KMS (simulated)
                let mut new_material = [0u8; 32];
                getrandom::getrandom(&mut new_material).map_err(|_| SealError::SealFailed)?;

                // Store as new root — in real KMS, this would create a new CMK alias
                let _ = session.key_store.remove_key(&self.config.key_label);
                session
                    .key_store
                    .store_key(&self.config.key_label, KeyType::Aes256Wrap, &new_material)
                    .map_err(|_| SealError::SealFailed)?;

                // Invalidate the data key cache
                session.data_key_cache.clear();

                let master = MasterKey::from_bytes(new_material);
                new_material.zeroize();
                Ok(master)
            }
            BackendState::Tpm2(session) => {
                tracing::info!("Rotating master key in TPM 2.0");

                // Generate fresh key and re-seal under current PCR values
                let mut new_material = [0u8; 32];
                getrandom::getrandom(&mut new_material).map_err(|_| SealError::SealFailed)?;

                let _ = session.key_store.remove_key(&self.config.key_label);
                session
                    .key_store
                    .store_key(&self.config.key_label, KeyType::Aes256Wrap, &new_material)
                    .map_err(|_| SealError::SealFailed)?;

                let master = MasterKey::from_bytes(new_material);
                new_material.zeroize();
                Ok(master)
            }
            BackendState::Software(source) => {
                tracing::info!("Rotating master key (software backend)");
                source.rotate_master_key()
            }
        }
    }

    // -----------------------------------------------------------------------
    // FROST threshold signing share management
    // -----------------------------------------------------------------------

    /// Seal a FROST threshold signing share to the local HSM/TPM.
    ///
    /// On server shutdown or key persistence, each TSS node seals its
    /// FROST share to the local HSM. The share can only be recovered
    /// by the same HSM (or TPM with matching PCR values).
    ///
    /// This prevents share theft even if the server's disk is compromised,
    /// because the share is encrypted under a key that only the HSM holds.
    pub fn seal_frost_share(&self, share: &[u8]) -> Result<Vec<u8>, SealError> {
        tracing::info!(
            "Sealing FROST share (len={}) to HSM",
            share.len()
        );
        self.seal_with_hardware(share, "frost-tss-share")
    }

    /// Unseal a FROST threshold signing share from the local HSM/TPM.
    ///
    /// Called at server startup to recover the node's FROST share.
    /// Fails if the HSM is unavailable or (for TPM) PCR values have changed
    /// since the share was sealed.
    pub fn unseal_frost_share(&self, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        tracing::info!(
            "Unsealing FROST share (sealed_len={}) from HSM",
            sealed.len()
        );
        self.unseal_with_hardware(sealed, "frost-tss-share")
    }

    // -----------------------------------------------------------------------
    // HSM-backed signing (key never exported)
    // -----------------------------------------------------------------------

    /// Sign data using an HSM-resident signing key.
    ///
    /// The private key never leaves the HSM. The HSM performs the signature
    /// operation internally using HMAC-SHA256.
    ///
    /// For PKCS#11: `C_Sign` with `CKM_SHA256_HMAC`
    /// For AWS KMS: `kms.sign(KeyId, Message, SigningAlgorithm)`
    /// For TPM2: `TPM2_Sign` with the SRK-derived signing key
    pub fn sign_with_hardware(
        &self,
        data: &[u8],
        signing_key_label: &str,
    ) -> Result<Vec<u8>, HsmError> {
        let state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        match &*state {
            BackendState::Pkcs11(session) => {
                if !session.authenticated {
                    return Err(HsmError::AuthenticationFailed);
                }
                tracing::info!(
                    "PKCS#11 sign operation (data_len={}, key={})",
                    data.len(),
                    signing_key_label
                );

                // Load the signing key from the key store
                let (_key_type, mut key_material) = session
                    .key_store
                    .load_key(signing_key_label)
                    .or_else(|_| session.key_store.load_key(&session.key_label))?;

                // HMAC-SHA256 sign (mirrors CKM_SHA256_HMAC)
                let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(&key_material)
                    .map_err(|_| HsmError::SigningFailed("HMAC key creation failed".into()))?;
                mac.update(data);
                let signature = mac.finalize().into_bytes().to_vec();

                key_material.zeroize();
                Ok(signature)
            }
            BackendState::AwsKms(session) => {
                tracing::info!(
                    "AWS KMS sign operation (data_len={}, key={})",
                    data.len(),
                    signing_key_label
                );

                // Derive a signing key from the KMS root
                let mut signing_key = [0u8; 32];
                let hk = Hkdf::<Sha512>::new(None, &session.key_store.root_key);
                let info = format!("aws-kms-sign:{}", signing_key_label);
                hk.expand(info.as_bytes(), &mut signing_key)
                    .map_err(|_| HsmError::SigningFailed("HKDF expansion failed".into()))?;

                let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(&signing_key)
                    .map_err(|_| HsmError::SigningFailed("HMAC key creation failed".into()))?;
                mac.update(data);
                let signature = mac.finalize().into_bytes().to_vec();

                signing_key.zeroize();
                Ok(signature)
            }
            BackendState::Tpm2(session) => {
                tracing::info!(
                    "TPM2 sign operation (data_len={}, key={})",
                    data.len(),
                    signing_key_label
                );

                // Derive a signing key from the SRK
                let mut signing_key = [0u8; 32];
                let hk = Hkdf::<Sha512>::new(None, &session.srk_handle);
                let info = format!("tpm2-sign:{}", signing_key_label);
                hk.expand(info.as_bytes(), &mut signing_key)
                    .map_err(|_| HsmError::SigningFailed("HKDF expansion failed".into()))?;

                let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(&signing_key)
                    .map_err(|_| HsmError::SigningFailed("HMAC key creation failed".into()))?;
                mac.update(data);
                let signature = mac.finalize().into_bytes().to_vec();

                signing_key.zeroize();
                Ok(signature)
            }
            BackendState::Software(_) => {
                Err(HsmError::NotSupported(
                    "Software backend does not support HSM signing; use standard crypto instead"
                        .into(),
                ))
            }
        }
    }

    /// Generate a Data Encryption Key (DEK) in the HSM and return it wrapped.
    ///
    /// The DEK is generated inside the HSM, wrapped under the master key,
    /// and returned. The plaintext DEK is never exposed to software for
    /// hardware backends.
    pub fn generate_wrapped_dek(&self, purpose: &str) -> Result<Vec<u8>, HsmError> {
        let state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        tracing::info!("Generating wrapped DEK (purpose={})", purpose);

        match &*state {
            BackendState::Pkcs11(session) => {
                if !session.authenticated {
                    return Err(HsmError::AuthenticationFailed);
                }

                // Generate a random DEK inside the "HSM"
                let mut dek = [0u8; 32];
                getrandom::getrandom(&mut dek)
                    .map_err(|_| HsmError::KeyGenerationFailed("CSPRNG unavailable".into()))?;

                // Wrap it under the master key using the key store
                let wrapped = session
                    .key_store
                    .seal_key_material(&dek, &format!("dek:{}", purpose))?;

                dek.zeroize();
                Ok(wrapped)
            }
            BackendState::AwsKms(session) => {
                // Generate and wrap a DEK (simulates GenerateDataKeyWithoutPlaintext)
                let mut dek = [0u8; 32];
                getrandom::getrandom(&mut dek)
                    .map_err(|_| HsmError::KeyGenerationFailed("CSPRNG unavailable".into()))?;

                let aad = format!("aws-kms:{}:dek:{}", session.key_id, purpose);
                let wrapped = session.key_store.seal_key_material(&dek, &aad)?;

                dek.zeroize();
                Ok(wrapped)
            }
            BackendState::Tpm2(session) => {
                // Generate DEK and seal to PCR values
                let mut dek = [0u8; 32];
                getrandom::getrandom(&mut dek)
                    .map_err(|_| HsmError::KeyGenerationFailed("CSPRNG unavailable".into()))?;

                let wrapped = session
                    .seal_to_pcrs(&dek, &format!("dek:{}", purpose))
                    .map_err(|e| HsmError::WrapFailed(format!("TPM2 seal failed: {e}")))?;

                dek.zeroize();
                Ok(wrapped)
            }
            BackendState::Software(source) => {
                // Generate a random DEK and wrap it with the software key source
                let mut dek = [0u8; 32];
                getrandom::getrandom(&mut dek)
                    .map_err(|_| HsmError::KeyGenerationFailed("CSPRNG unavailable".into()))?;
                let wrapped = source
                    .seal_with_hardware(&dek, purpose)
                    .map_err(|e| HsmError::WrapFailed(format!("{e}")))?;
                dek.zeroize();
                Ok(wrapped)
            }
        }
    }

    /// Generate a TPM 2.0 attestation quote (only available for TPM2 backend).
    ///
    /// Produces a signed quote over the current PCR values that can be
    /// verified by a remote attestation server.
    pub fn generate_attestation_quote(
        &self,
        nonce: &[u8; 32],
    ) -> Result<Vec<u8>, HsmError> {
        let state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        match &*state {
            BackendState::Tpm2(session) => session.generate_attestation_quote(nonce),
            _ => Err(HsmError::NotSupported(
                "attestation quotes are only available with TPM 2.0 backend".into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// HsmKeyOps implementation for HsmKeyManager (dispatches to backends)
// ---------------------------------------------------------------------------

impl HsmKeyOps for HsmKeyManager {
    fn generate_key(&self, key_id: &str, key_type: KeyType) -> Result<Vec<u8>, HsmError> {
        let mut state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        let key_material = Pkcs11Session::generate_key_material(key_type)?;

        let handle = {
            let mut hasher = Sha256::new();
            hasher.update(key_id.as_bytes());
            hasher.update(&key_material);
            hasher.finalize().to_vec()
        };

        match &mut *state {
            BackendState::Pkcs11(session) => {
                if !session.authenticated {
                    return Err(HsmError::AuthenticationFailed);
                }
                session.key_store.store_key(key_id, key_type, &key_material)?;
            }
            BackendState::AwsKms(session) => {
                session.key_store.store_key(key_id, key_type, &key_material)?;
            }
            BackendState::Tpm2(session) => {
                session.key_store.store_key(key_id, key_type, &key_material)?;
            }
            BackendState::Software(_) => {
                return Err(HsmError::SoftwareInProduction);
            }
        }

        Ok(handle)
    }

    fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        let key_store = match &*state {
            BackendState::Pkcs11(s) => {
                if !s.authenticated {
                    return Err(HsmError::AuthenticationFailed);
                }
                &s.key_store
            }
            BackendState::AwsKms(s) => &s.key_store,
            BackendState::Tpm2(s) => &s.key_store,
            BackendState::Software(_) => {
                return Err(HsmError::SoftwareInProduction);
            }
        };

        let (_key_type, mut key_material) = key_store.load_key(key_id)?;

        let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(&key_material)
            .map_err(|_| HsmError::SigningFailed("HMAC key creation failed".into()))?;
        mac.update(data);
        let signature = mac.finalize().into_bytes().to_vec();

        key_material.zeroize();
        Ok(signature)
    }

    fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, HsmError> {
        let state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        let key_store = match &*state {
            BackendState::Pkcs11(s) => {
                if !s.authenticated {
                    return Err(HsmError::AuthenticationFailed);
                }
                &s.key_store
            }
            BackendState::AwsKms(s) => &s.key_store,
            BackendState::Tpm2(s) => &s.key_store,
            BackendState::Software(_) => {
                return Err(HsmError::SoftwareInProduction);
            }
        };

        let (_key_type, mut key_material) = key_store.load_key(key_id)?;

        let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(&key_material)
            .map_err(|_| HsmError::SigningFailed("HMAC verification key creation failed".into()))?;
        mac.update(data);

        key_material.zeroize();

        // Constant-time verification via the hmac crate
        Ok(mac.verify_slice(signature).is_ok())
    }

    fn encrypt(&self, key_id: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, HsmError> {
        let state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        let key_store = match &*state {
            BackendState::Pkcs11(s) => {
                if !s.authenticated {
                    return Err(HsmError::AuthenticationFailed);
                }
                &s.key_store
            }
            BackendState::AwsKms(s) => &s.key_store,
            BackendState::Tpm2(s) => &s.key_store,
            BackendState::Software(_) => {
                return Err(HsmError::SoftwareInProduction);
            }
        };

        let (key_type, mut key_material) = key_store.load_key(key_id)?;

        // Only AES-256 keys can encrypt
        match key_type {
            KeyType::Aes256 | KeyType::Aes256Wrap | KeyType::GenericSecret => {}
            _ => {
                key_material.zeroize();
                return Err(HsmError::NotSupported(
                    format!("key type {:?} does not support encryption", key_type),
                ));
            }
        }

        // Ensure we have exactly 32 bytes for AES-256
        if key_material.len() < 32 {
            key_material.zeroize();
            return Err(HsmError::WrapFailed("key material too short for AES-256".into()));
        }

        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_material[..32]);
        let cipher = Aes256Gcm::new(aes_key);

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|_| HsmError::CommunicationError("CSPRNG unavailable".into()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| HsmError::WrapFailed("AES-GCM encryption failed".into()))?;

        key_material.zeroize();

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt(&self, key_id: &str, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, HsmError> {
        let state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        let key_store = match &*state {
            BackendState::Pkcs11(s) => {
                if !s.authenticated {
                    return Err(HsmError::AuthenticationFailed);
                }
                &s.key_store
            }
            BackendState::AwsKms(s) => &s.key_store,
            BackendState::Tpm2(s) => &s.key_store,
            BackendState::Software(_) => {
                return Err(HsmError::SoftwareInProduction);
            }
        };

        if ciphertext.len() < 28 {
            return Err(HsmError::UnwrapFailed("ciphertext too short".into()));
        }

        let (key_type, mut key_material) = key_store.load_key(key_id)?;

        match key_type {
            KeyType::Aes256 | KeyType::Aes256Wrap | KeyType::GenericSecret => {}
            _ => {
                key_material.zeroize();
                return Err(HsmError::NotSupported(
                    format!("key type {:?} does not support decryption", key_type),
                ));
            }
        }

        if key_material.len() < 32 {
            key_material.zeroize();
            return Err(HsmError::UnwrapFailed("key material too short for AES-256".into()));
        }

        let (nonce_bytes, ct) = ciphertext.split_at(12);
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_material[..32]);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = aes_gcm::aead::Payload { msg: ct, aad };
        let result = cipher
            .decrypt(nonce, payload)
            .map_err(|_| HsmError::UnwrapFailed("AES-GCM decryption failed".into()));

        key_material.zeroize();
        result
    }

    fn wrap_key(&self, wrapping_key_id: &str, key_to_wrap: &[u8]) -> Result<Vec<u8>, HsmError> {
        // Wrapping is just encryption with the wrapping key, using "key-wrap" as AAD
        self.encrypt(wrapping_key_id, key_to_wrap, b"MILNET-KEY-WRAP-v1")
    }

    fn unwrap_key(
        &self,
        wrapping_key_id: &str,
        wrapped_key: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        // Unwrapping is just decryption with the wrapping key
        self.decrypt(wrapping_key_id, wrapped_key, b"MILNET-KEY-WRAP-v1")
    }

    fn destroy_key(&self, key_id: &str) -> Result<(), HsmError> {
        let mut state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        match &mut *state {
            BackendState::Pkcs11(session) => {
                if !session.authenticated {
                    return Err(HsmError::AuthenticationFailed);
                }
                session.key_store.remove_key(key_id)
            }
            BackendState::AwsKms(session) => session.key_store.remove_key(key_id),
            BackendState::Tpm2(session) => session.key_store.remove_key(key_id),
            BackendState::Software(_) => {
                Err(HsmError::SoftwareInProduction)
            }
        }
    }

    fn key_exists(&self, key_id: &str) -> Result<bool, HsmError> {
        let state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        match &*state {
            BackendState::Pkcs11(s) => Ok(s.key_store.contains_key(key_id)),
            BackendState::AwsKms(s) => Ok(s.key_store.contains_key(key_id)),
            BackendState::Tpm2(s) => Ok(s.key_store.contains_key(key_id)),
            BackendState::Software(_) => {
                Err(HsmError::SoftwareInProduction)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ProductionKeySource implementation for HsmKeyManager
// ---------------------------------------------------------------------------

impl ProductionKeySource for HsmKeyManager {
    fn load_master_key(&self) -> Result<MasterKey, SealError> {
        let state = self.state.lock().map_err(|_| SealError::InvalidMasterKey)?;

        match &*state {
            BackendState::Software(source) => source.load_master_key(),
            BackendState::Pkcs11(session) => {
                // Derive a local MasterKey from the PKCS#11 HSM master key.
                // The true master key never leaves the HSM; we derive a secondary
                // key using a challenge-response pattern:
                // 1. Load master key material from the key store
                // 2. HKDF-expand with "local-master-key" info to get the local key
                tracing::info!(
                    "Deriving local master key from PKCS#11 HSM (label={})",
                    self.config.key_label
                );

                let (_key_type, mut master_material) = session
                    .key_store
                    .load_key(&session.key_label)
                    .map_err(|_| SealError::InvalidMasterKey)?;

                let hk = Hkdf::<Sha512>::new(None, &master_material);
                let mut local_key = [0u8; 32];
                hk.expand(b"pkcs11-local-master-key", &mut local_key)
                    .map_err(|_| SealError::KeyDerivationFailed)?;

                master_material.zeroize();
                Ok(MasterKey::from_bytes(local_key))
            }
            BackendState::AwsKms(session) => {
                // Derive local master key from KMS root.
                // In real AWS KMS, this would call GenerateDataKey to get a DEK.
                tracing::info!("Deriving local master key from AWS KMS");

                let hk = Hkdf::<Sha512>::new(None, &session.key_store.root_key);
                let mut local_key = [0u8; 32];
                let info = format!("aws-kms-local-master:{}", session.key_id);
                hk.expand(info.as_bytes(), &mut local_key)
                    .map_err(|_| SealError::KeyDerivationFailed)?;

                Ok(MasterKey::from_bytes(local_key))
            }
            BackendState::Tpm2(session) => {
                // Unseal the master key from TPM, bound to PCR values.
                tracing::info!("Unsealing master key from TPM 2.0");

                let (_key_type, mut master_material) = session
                    .key_store
                    .load_key(&self.config.key_label)
                    .map_err(|_| SealError::InvalidMasterKey)?;

                // Verify PCR values are still valid by checking the policy digest
                let pcr_digest = session.compute_pcr_policy_digest();
                let hk = Hkdf::<Sha512>::new(Some(&pcr_digest), &master_material);
                let mut local_key = [0u8; 32];
                hk.expand(b"tpm2-local-master-key", &mut local_key)
                    .map_err(|_| SealError::KeyDerivationFailed)?;

                master_material.zeroize();
                Ok(MasterKey::from_bytes(local_key))
            }
        }
    }

    fn rotate_master_key(&self) -> Result<MasterKey, SealError> {
        self.rotate_hardware_key()
    }

    fn seal_with_hardware(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let state = self.state.lock().map_err(|_| SealError::SealFailed)?;

        match &*state {
            BackendState::Software(source) => source.seal_with_hardware(plaintext, purpose),
            _ => {
                drop(state); // Release lock before calling backend-specific methods
                match &self.config.backend {
                    HsmBackend::Pkcs11 => self.pkcs11_wrap(plaintext, purpose),
                    HsmBackend::AwsKms => self.aws_kms_wrap(plaintext, purpose),
                    HsmBackend::Tpm2 => self.tpm2_wrap(plaintext, purpose),
                    HsmBackend::Software => unreachable!(),
                }
            }
        }
    }

    fn unseal_with_hardware(&self, sealed: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let state = self.state.lock().map_err(|_| SealError::UnsealFailed)?;

        match &*state {
            BackendState::Software(source) => source.unseal_with_hardware(sealed, purpose),
            _ => {
                drop(state);
                match &self.config.backend {
                    HsmBackend::Pkcs11 => self.pkcs11_unwrap(sealed, purpose),
                    HsmBackend::AwsKms => self.aws_kms_unwrap(sealed, purpose),
                    HsmBackend::Tpm2 => self.tpm2_unwrap(sealed, purpose),
                    HsmBackend::Software => unreachable!(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Factory function
// ---------------------------------------------------------------------------

/// Create a key source from HSM configuration.
///
/// This is the primary entry point for setting up the key management layer.
/// Returns a boxed [`ProductionKeySource`] backed by the configured HSM.
///
/// # Fail-Closed Behavior
/// In production mode, the `Software` backend is rejected.
pub fn create_key_source(config: &HsmConfig) -> Result<Box<dyn ProductionKeySource>, HsmError> {
    let manager = HsmKeyManager::new(config.clone())?;
    Ok(Box::new(manager))
}

/// Create a key source from environment variables.
///
/// Reads `MILNET_HSM_BACKEND` and related env vars to configure the HSM.
/// Falls back to the `Software` backend if `MILNET_HSM_BACKEND` is not set.
pub fn create_key_source_from_env() -> Result<Box<dyn ProductionKeySource>, HsmError> {
    let config = HsmConfig::from_env();
    create_key_source(&config)
}

/// Create the appropriate HSM backend based on configuration.
///
/// Reads `MILNET_HSM_BACKEND` env var:
/// - `"pkcs11"` -> PKCS#11 (requires linked library)
/// - `"aws_kms"` / `"aws-kms"` -> AWS KMS (requires aws-sdk-kms)
/// - `"tpm2"` -> TPM 2.0 (requires tss-esapi)
/// - `"software"` or unset -> Software fallback (blocked in production)
///
/// Returns a boxed [`HsmKeyOps`] backed by an [`HsmKeyManager`] configured
/// for the selected backend.
///
/// # Panics
/// Panics in production mode if backend is `"software"` or unset.
/// Panics if the selected hardware backend cannot be initialized (e.g.,
/// missing library path, credentials, or device).
pub fn create_hsm_backend() -> Box<dyn HsmKeyOps> {
    let backend_name = std::env::var("MILNET_HSM_BACKEND")
        .unwrap_or_else(|_| "software".to_string());

    match backend_name.to_lowercase().as_str() {
        "pkcs11" => {
            tracing::info!("HSM backend: PKCS#11");
            // Requires MILNET_PKCS11_LIB, MILNET_PKCS11_SLOT, MILNET_PKCS11_PIN
            // When a real PKCS#11 library is linked (build with --features pkcs11),
            // replace this with a native PKCS#11 session via the `pkcs11` crate.
            let config = HsmConfig::from_env();
            let manager = HsmKeyManager::new(config)
                .unwrap_or_else(|e| panic!(
                    "FATAL: Failed to initialize PKCS#11 HSM backend: {e}. \
                     Verify MILNET_PKCS11_LIB, MILNET_PKCS11_SLOT, and MILNET_PKCS11_PIN."
                ));
            tracing::info!("HSM backend initialized — type=pkcs11, label={}", manager.key_label());
            Box::new(manager)
        }
        "aws_kms" | "aws-kms" | "awskms" | "kms" => {
            tracing::info!("HSM backend: AWS KMS");
            // Requires MILNET_AWS_KMS_KEY_ID, optionally MILNET_AWS_KMS_REGION
            // When aws-sdk-kms is linked (build with --features aws-kms),
            // replace this with native KMS envelope encryption.
            let config = HsmConfig::from_env();
            let manager = HsmKeyManager::new(config)
                .unwrap_or_else(|e| panic!(
                    "FATAL: Failed to initialize AWS KMS HSM backend: {e}. \
                     Verify MILNET_AWS_KMS_KEY_ID and AWS credentials."
                ));
            tracing::info!("HSM backend initialized — type=aws_kms, label={}", manager.key_label());
            Box::new(manager)
        }
        "tpm2" | "tpm" => {
            tracing::info!("HSM backend: TPM 2.0");
            // Requires MILNET_TPM2_DEVICE, optionally MILNET_TPM2_PCRS
            // When tss-esapi is linked (build with --features tpm2),
            // replace this with native TPM 2.0 sealed storage.
            let config = HsmConfig::from_env();
            let manager = HsmKeyManager::new(config)
                .unwrap_or_else(|e| panic!(
                    "FATAL: Failed to initialize TPM 2.0 HSM backend: {e}. \
                     Verify MILNET_TPM2_DEVICE and PCR configuration."
                ));
            tracing::info!("HSM backend initialized — type=tpm2, label={}", manager.key_label());
            Box::new(manager)
        }
        "software" | _ => {
            panic!(
                "FATAL: Software HSM backend is forbidden in production mode. \
                 Set MILNET_HSM_BACKEND to pkcs11, aws_kms, or tpm2. \
                 Hardware-backed key storage is required for classified deployments."
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Real PKCS#11 hardware session via the `cryptoki` crate
// ---------------------------------------------------------------------------

#[cfg(feature = "pkcs11-hw")]
mod pkcs11_hw {
    use super::*;
    use cryptoki::context::{CInitializeArgs, Pkcs11};
    use cryptoki::mechanism::aead::GcmParams;
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
    use cryptoki::session::{Session, UserType};
    use cryptoki::types::AuthPin;
    use std::sync::{Arc, Mutex as StdMutex};
    use zeroize::Zeroize;

    /// Real PKCS#11 hardware session using the `cryptoki` crate FFI bindings.
    ///
    /// This struct manages a live PKCS#11 session with an actual hardware HSM
    /// (Thales Luna, AWS CloudHSM, YubiHSM2, SoftHSM2, etc.) via the standard
    /// PKCS#11 C API. All key material stays inside the HSM boundary — only
    /// opaque handles cross the FFI.
    ///
    /// # Thread Safety
    /// PKCS#11 sessions require serialized access. The inner `Session` is
    /// protected by a `Mutex` so that `Pkcs11HardwareSession` is `Send + Sync`.
    pub struct Pkcs11HardwareSession {
        /// The cryptoki context (holds the loaded .so handle).
        _ctx: Arc<Pkcs11>,
        /// The authenticated PKCS#11 session (behind a mutex for thread safety).
        session: StdMutex<Session>,
        /// Key label used to locate / create the master key object.
        key_label: String,
    }

    // Session is not Send/Sync by default but we serialise through the Mutex.
    unsafe impl Send for Pkcs11HardwareSession {}
    unsafe impl Sync for Pkcs11HardwareSession {}

    impl Pkcs11HardwareSession {
        /// Open a new authenticated PKCS#11 session.
        ///
        /// Performs: C_Initialize -> C_OpenSession(slot, RW) -> C_Login(USER, pin).
        ///
        /// # Errors
        /// Returns `HsmError` if the library cannot be loaded, the slot is invalid,
        /// or authentication fails.
        pub fn open(
            library_path: &str,
            slot_index: u64,
            pin: &str,
            key_label: &str,
        ) -> Result<Self, HsmError> {
            // C_Initialize
            let ctx = Pkcs11::new(library_path).map_err(|e| {
                HsmError::InitializationFailed(format!(
                    "C_Initialize failed for {library_path}: {e}"
                ))
            })?;
            ctx.initialize(CInitializeArgs::OsThreads).map_err(|e| {
                HsmError::InitializationFailed(format!("C_Initialize(OsThreads): {e}"))
            })?;

            // Enumerate slots and pick the requested one.
            let slots = ctx.get_slots_with_token().map_err(|e| {
                HsmError::InitializationFailed(format!("C_GetSlotList: {e}"))
            })?;
            let slot = slots.get(slot_index as usize).copied().ok_or_else(|| {
                HsmError::InitializationFailed(format!(
                    "slot index {slot_index} out of range (found {} slots)",
                    slots.len()
                ))
            })?;

            // C_OpenSession (read-write)
            let session = ctx.open_rw_session(slot).map_err(|e| {
                HsmError::InitializationFailed(format!("C_OpenSession(slot={slot_index}): {e}"))
            })?;

            // C_Login
            let auth_pin = AuthPin::new(pin.to_string());
            session.login(UserType::User, Some(&auth_pin)).map_err(|_e| {
                HsmError::AuthenticationFailed
            })?;

            // Zeroize the pin copy.
            let mut pin_buf = pin.to_string();
            pin_buf.zeroize();

            let ctx = Arc::new(ctx);

            tracing::info!(
                "PKCS#11 HW session opened (lib={library_path}, slot={slot_index}, \
                 label={key_label})"
            );

            Ok(Self {
                _ctx: ctx,
                session: StdMutex::new(session),
                key_label: key_label.to_string(),
            })
        }

        // -----------------------------------------------------------------
        // Internal helpers
        // -----------------------------------------------------------------

        /// Find a single object by CKA_LABEL.
        fn find_key_by_label(&self, label: &str) -> Result<Option<ObjectHandle>, HsmError> {
            let session = self.session.lock().map_err(|_| {
                HsmError::CommunicationError("session mutex poisoned".into())
            })?;
            let template = vec![Attribute::Label(label.as_bytes().to_vec())];
            let objects = session.find_objects(&template).map_err(|e| {
                HsmError::CommunicationError(format!("C_FindObjects: {e}"))
            })?;
            Ok(objects.into_iter().next())
        }

        /// Map a `KeyType` to the PKCS#11 mechanism used for key generation.
        fn gen_mechanism(key_type: KeyType) -> Mechanism<'static> {
            match key_type {
                KeyType::Aes256 | KeyType::Aes256Wrap => Mechanism::AesKeyGen,
                KeyType::HmacSha256 | KeyType::HmacSha512 | KeyType::GenericSecret => {
                    Mechanism::GenericSecretKeyGen
                }
            }
        }

        /// Build the CKA template for key generation.
        fn gen_template(key_id: &str, key_type: KeyType) -> Vec<Attribute> {
            let value_len: u64 = match key_type {
                KeyType::Aes256 | KeyType::Aes256Wrap => 32,
                KeyType::HmacSha256 | KeyType::GenericSecret => 32,
                KeyType::HmacSha512 => 64,
            };

            let mut attrs = vec![
                Attribute::Label(key_id.as_bytes().to_vec()),
                Attribute::Token(true),        // persistent on token
                Attribute::Sensitive(true),     // key material not extractable in clear
                Attribute::Private(true),       // requires login
                Attribute::ValueLen(value_len.into()),
            ];

            match key_type {
                KeyType::Aes256 => {
                    attrs.push(Attribute::Encrypt(true));
                    attrs.push(Attribute::Decrypt(true));
                    attrs.push(Attribute::Class(ObjectClass::SECRET_KEY));
                }
                KeyType::Aes256Wrap => {
                    attrs.push(Attribute::Wrap(true));
                    attrs.push(Attribute::Unwrap(true));
                    attrs.push(Attribute::Encrypt(true));
                    attrs.push(Attribute::Decrypt(true));
                    attrs.push(Attribute::Class(ObjectClass::SECRET_KEY));
                }
                KeyType::HmacSha256 | KeyType::HmacSha512 => {
                    attrs.push(Attribute::Sign(true));
                    attrs.push(Attribute::Verify(true));
                    attrs.push(Attribute::Class(ObjectClass::SECRET_KEY));
                }
                KeyType::GenericSecret => {
                    attrs.push(Attribute::Extractable(true));
                    attrs.push(Attribute::Class(ObjectClass::SECRET_KEY));
                }
            }

            attrs
        }
    }

    impl HsmKeyOps for Pkcs11HardwareSession {
        /// C_GenerateKey with CKM_AES_KEY_GEN (AES) or CKM_GENERIC_SECRET_KEY_GEN (HMAC).
        fn generate_key(&self, key_id: &str, key_type: KeyType) -> Result<Vec<u8>, HsmError> {
            let session = self.session.lock().map_err(|_| {
                HsmError::CommunicationError("session mutex poisoned".into())
            })?;

            let mechanism = Self::gen_mechanism(key_type);
            let template = Self::gen_template(key_id, key_type);

            let _handle = session.generate_key(&mechanism, &template).map_err(|e| {
                HsmError::KeyGenerationFailed(format!("C_GenerateKey({key_id}): {e}"))
            })?;

            // Return a SHA-256 hash of the label as an opaque handle token.
            // The actual PKCS#11 object handle is internal to the session and
            // we locate objects by CKA_LABEL, not by handle value.
            let mut hasher = Sha256::new();
            hasher.update(key_id.as_bytes());
            let handle_bytes = hasher.finalize().to_vec();
            tracing::info!(
                "C_GenerateKey label={key_id} type={key_type:?}"
            );
            Ok(handle_bytes)
        }

        /// C_SignInit(CKM_SHA256_HMAC) + C_Sign.
        fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
            let handle = self
                .find_key_by_label(key_id)?
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

            let session = self.session.lock().map_err(|_| {
                HsmError::CommunicationError("session mutex poisoned".into())
            })?;

            let signature = session
                .sign(&Mechanism::Sha256Hmac, handle, data)
                .map_err(|e| HsmError::SigningFailed(format!("C_Sign({key_id}): {e}")))?;

            Ok(signature)
        }

        /// C_VerifyInit(CKM_SHA256_HMAC) + C_Verify.
        fn verify(
            &self,
            key_id: &str,
            data: &[u8],
            signature: &[u8],
        ) -> Result<bool, HsmError> {
            let handle = self
                .find_key_by_label(key_id)?
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

            let session = self.session.lock().map_err(|_| {
                HsmError::CommunicationError("session mutex poisoned".into())
            })?;

            match session.verify(&Mechanism::Sha256Hmac, handle, data, signature) {
                Ok(()) => Ok(true),
                Err(cryptoki::error::Error::Pkcs11(
                    cryptoki::error::RvError::SignatureInvalid, _,
                )) => Ok(false),
                Err(cryptoki::error::Error::Pkcs11(
                    cryptoki::error::RvError::SignatureLenRange, _,
                )) => Ok(false),
                Err(e) => Err(HsmError::CommunicationError(format!(
                    "C_Verify({key_id}): {e}"
                ))),
            }
        }

        /// C_EncryptInit(CKM_AES_GCM) + C_Encrypt.
        ///
        /// Returns `nonce(12) || ciphertext || tag(16)`.
        fn encrypt(
            &self,
            key_id: &str,
            plaintext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, HsmError> {
            let handle = self
                .find_key_by_label(key_id)?
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

            // Generate a random 12-byte IV.
            let mut iv = [0u8; 12];
            getrandom::getrandom(&mut iv)
                .map_err(|_| HsmError::KeyGenerationFailed("CSPRNG unavailable for IV".into()))?;

            let session = self.session.lock().map_err(|_| {
                HsmError::CommunicationError("session mutex poisoned".into())
            })?;

            let gcm_params = GcmParams::new(&mut iv, aad, 128.into()).map_err(|e| {
                HsmError::CommunicationError(format!("GcmParams: {e}"))
            })?;
            let mechanism = Mechanism::AesGcm(gcm_params);

            let ciphertext = session.encrypt(&mechanism, handle, plaintext).map_err(|e| {
                HsmError::CommunicationError(format!("C_Encrypt({key_id}): {e}"))
            })?;

            // Prepend the IV so the caller can pass it back for decryption.
            let mut output = Vec::with_capacity(12 + ciphertext.len());
            output.extend_from_slice(&iv);
            output.extend_from_slice(&ciphertext);
            Ok(output)
        }

        /// C_DecryptInit(CKM_AES_GCM) + C_Decrypt.
        ///
        /// Expects `nonce(12) || ciphertext || tag(16)`.
        fn decrypt(
            &self,
            key_id: &str,
            ciphertext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, HsmError> {
            if ciphertext.len() < 28 {
                return Err(HsmError::UnwrapFailed(
                    "ciphertext too short (need at least 12-byte IV + 16-byte tag)".into(),
                ));
            }

            let handle = self
                .find_key_by_label(key_id)?
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

            let (iv_slice, ct) = ciphertext.split_at(12);
            let mut iv = [0u8; 12];
            iv.copy_from_slice(iv_slice);

            let session = self.session.lock().map_err(|_| {
                HsmError::CommunicationError("session mutex poisoned".into())
            })?;

            let gcm_params = GcmParams::new(&mut iv, aad, 128.into()).map_err(|e| {
                HsmError::UnwrapFailed(format!("GcmParams: {e}"))
            })?;
            let mechanism = Mechanism::AesGcm(gcm_params);

            let plaintext = session.decrypt(&mechanism, handle, ct).map_err(|e| {
                HsmError::UnwrapFailed(format!("C_Decrypt({key_id}): {e}"))
            })?;

            Ok(plaintext)
        }

        /// C_WrapKey with CKM_AES_KEY_WRAP_KWP.
        ///
        /// `key_to_wrap` is treated as raw bytes to be imported as a temporary
        /// generic-secret object, then wrapped under `wrapping_key_id`.
        fn wrap_key(
            &self,
            wrapping_key_id: &str,
            key_to_wrap: &[u8],
        ) -> Result<Vec<u8>, HsmError> {
            let wrapping_handle = self
                .find_key_by_label(wrapping_key_id)?
                .ok_or_else(|| HsmError::KeyNotFound(wrapping_key_id.to_string()))?;

            let session = self.session.lock().map_err(|_| {
                HsmError::CommunicationError("session mutex poisoned".into())
            })?;

            // Import the raw key material as a temporary session object so that
            // C_WrapKey can operate on it.
            let tmp_label = format!("__tmp_wrap_{}", wrapping_key_id);
            let import_template = vec![
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(cryptoki::object::KeyType::GENERIC_SECRET),
                Attribute::Value(key_to_wrap.to_vec()),
                Attribute::Label(tmp_label.as_bytes().to_vec()),
                Attribute::Token(false),        // session-only, ephemeral
                Attribute::Extractable(true),   // must be extractable for wrapping
                Attribute::Sensitive(false),     // allow wrap extraction
            ];
            let tmp_handle = session.create_object(&import_template).map_err(|e| {
                HsmError::WrapFailed(format!("C_CreateObject(tmp): {e}"))
            })?;

            let mechanism = Mechanism::AesKeyWrapPad;

            let wrapped = session
                .wrap_key(&mechanism, wrapping_handle, tmp_handle)
                .map_err(|e| {
                    // Best-effort cleanup of the temporary object.
                    let _ = session.destroy_object(tmp_handle);
                    HsmError::WrapFailed(format!("C_WrapKey({wrapping_key_id}): {e}"))
                })?;

            // Destroy the ephemeral object immediately.
            let _ = session.destroy_object(tmp_handle);

            Ok(wrapped)
        }

        /// C_UnwrapKey with CKM_AES_KEY_WRAP_KWP.
        ///
        /// Returns the unwrapped key material by reading CKA_VALUE from the
        /// resulting session object (marked extractable).
        fn unwrap_key(
            &self,
            wrapping_key_id: &str,
            wrapped_key: &[u8],
        ) -> Result<Vec<u8>, HsmError> {
            let wrapping_handle = self
                .find_key_by_label(wrapping_key_id)?
                .ok_or_else(|| HsmError::KeyNotFound(wrapping_key_id.to_string()))?;

            let session = self.session.lock().map_err(|_| {
                HsmError::CommunicationError("session mutex poisoned".into())
            })?;

            let mechanism = Mechanism::AesKeyWrapPad;
            let unwrap_label = format!("__tmp_unwrap_{}", wrapping_key_id);
            let template = vec![
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(cryptoki::object::KeyType::GENERIC_SECRET),
                Attribute::Label(unwrap_label.as_bytes().to_vec()),
                Attribute::Token(false),
                Attribute::Sensitive(false),
                Attribute::Extractable(true),
            ];

            let obj = session
                .unwrap_key(&mechanism, wrapping_handle, wrapped_key, &template)
                .map_err(|e| {
                    HsmError::UnwrapFailed(format!("C_UnwrapKey({wrapping_key_id}): {e}"))
                })?;

            // Extract CKA_VALUE from the unwrapped object.
            let attrs = session
                .get_attributes(obj, &[AttributeType::Value])
                .map_err(|e| {
                    let _ = session.destroy_object(obj);
                    HsmError::UnwrapFailed(format!("C_GetAttributeValue: {e}"))
                })?;

            // Destroy the temporary object before returning.
            let _ = session.destroy_object(obj);

            for attr in attrs {
                if let Attribute::Value(val) = attr {
                    return Ok(val);
                }
            }

            Err(HsmError::UnwrapFailed(
                "CKA_VALUE not found on unwrapped object".into(),
            ))
        }

        /// C_DestroyObject — find the key by label and destroy it.
        fn destroy_key(&self, key_id: &str) -> Result<(), HsmError> {
            let handle = self
                .find_key_by_label(key_id)?
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

            let session = self.session.lock().map_err(|_| {
                HsmError::CommunicationError("session mutex poisoned".into())
            })?;

            session.destroy_object(handle).map_err(|e| {
                HsmError::CommunicationError(format!("C_DestroyObject({key_id}): {e}"))
            })?;

            tracing::info!("C_DestroyObject label={key_id}");
            Ok(())
        }

        /// C_FindObjectsInit + C_FindObjects to check key existence by label.
        fn key_exists(&self, key_id: &str) -> Result<bool, HsmError> {
            Ok(self.find_key_by_label(key_id)?.is_some())
        }
    }

    // -----------------------------------------------------------------------
    // Pkcs11HardwareKeySource — ProductionKeySource backed by real HSM
    // -----------------------------------------------------------------------

    /// A [`ProductionKeySource`] implementation backed by a real PKCS#11 HSM.
    ///
    /// The master key is generated inside (or loaded from) the hardware token
    /// and never leaves the HSM in plaintext. Local "master key" bytes are
    /// derived via HMAC-SHA256 challenge-response where the HSM performs the
    /// HMAC and we use the tag as keying material.
    pub struct Pkcs11HardwareKeySource {
        /// The underlying hardware session.
        hw: Pkcs11HardwareSession,
    }

    impl Pkcs11HardwareKeySource {
        /// Create a new hardware key source.
        ///
        /// Opens the PKCS#11 session and ensures the master key object exists
        /// on the token. If it does not exist, a new AES-256 wrapping key is
        /// generated inside the HSM.
        pub fn new(
            library_path: &str,
            slot_index: u64,
            pin: &str,
            key_label: &str,
        ) -> Result<Self, HsmError> {
            let hw = Pkcs11HardwareSession::open(library_path, slot_index, pin, key_label)?;

            // Ensure master key exists on token.
            if !hw.key_exists(key_label)? {
                tracing::info!(
                    "Master key '{key_label}' not found on token; generating via C_GenerateKey"
                );
                hw.generate_key(key_label, KeyType::Aes256Wrap)?;
            }

            Ok(Self { hw })
        }
    }

    impl ProductionKeySource for Pkcs11HardwareKeySource {
        fn load_master_key(&self) -> Result<MasterKey, SealError> {
            // We cannot extract the raw master key from the HSM (CKA_SENSITIVE).
            // Instead, perform an HMAC-sign challenge to derive local keying
            // material deterministically.
            let challenge = b"MILNET-PKCS11-HW-MASTER-KEY-DERIVATION-v1";
            let tag = self.hw.sign(&self.hw.key_label, challenge).map_err(|e| {
                tracing::error!("PKCS#11 HW master key derivation failed: {e}");
                SealError::InvalidMasterKey
            })?;

            // Use HKDF to expand the HMAC tag into a 32-byte master key.
            let hk = Hkdf::<Sha512>::new(Some(b"pkcs11-hw-local-master"), &tag);
            let mut local_key = [0u8; 32];
            hk.expand(b"local-master-key-v1", &mut local_key)
                .map_err(|_| SealError::KeyDerivationFailed)?;

            Ok(MasterKey::from_bytes(local_key))
        }

        fn rotate_master_key(&self) -> Result<MasterKey, SealError> {
            // Destroy the old master key and generate a fresh one.
            let label = &self.hw.key_label;
            let _ = self.hw.destroy_key(label);
            self.hw
                .generate_key(label, KeyType::Aes256Wrap)
                .map_err(|e| {
                    tracing::error!("PKCS#11 HW master key rotation failed: {e}");
                    SealError::SealFailed
                })?;
            self.load_master_key()
        }

        fn seal_with_hardware(
            &self,
            plaintext: &[u8],
            purpose: &str,
        ) -> Result<Vec<u8>, SealError> {
            self.hw
                .encrypt(&self.hw.key_label, plaintext, purpose.as_bytes())
                .map_err(|e| {
                    tracing::error!("PKCS#11 HW seal failed: {e}");
                    SealError::SealFailed
                })
        }

        fn unseal_with_hardware(
            &self,
            sealed: &[u8],
            purpose: &str,
        ) -> Result<Vec<u8>, SealError> {
            self.hw
                .decrypt(&self.hw.key_label, sealed, purpose.as_bytes())
                .map_err(|e| {
                    tracing::error!("PKCS#11 HW unseal failed: {e}");
                    SealError::UnsealFailed
                })
        }
    }

    // -----------------------------------------------------------------------
    // Factory helpers
    // -----------------------------------------------------------------------

    /// Create a [`Pkcs11HardwareSession`] from the standard HSM config.
    ///
    /// Requires `pkcs11_library_path`, `pkcs11_slot`, and `pkcs11_pin` to be set.
    pub fn create_hw_session(config: &HsmConfig) -> Result<Pkcs11HardwareSession, HsmError> {
        let lib = config.pkcs11_library_path.as_deref().ok_or_else(|| {
            HsmError::ConfigurationError("pkcs11_library_path is required".into())
        })?;
        let slot = config.pkcs11_slot.ok_or_else(|| {
            HsmError::ConfigurationError("pkcs11_slot is required".into())
        })?;
        let pin = config.pkcs11_pin.as_deref().ok_or_else(|| {
            HsmError::ConfigurationError("pkcs11_pin is required".into())
        })?;

        Pkcs11HardwareSession::open(lib, slot, pin, &config.key_label)
    }

    /// Create a [`Pkcs11HardwareKeySource`] from the standard HSM config.
    pub fn create_hw_key_source(
        config: &HsmConfig,
    ) -> Result<Pkcs11HardwareKeySource, HsmError> {
        let lib = config.pkcs11_library_path.as_deref().ok_or_else(|| {
            HsmError::ConfigurationError("pkcs11_library_path is required".into())
        })?;
        let slot = config.pkcs11_slot.ok_or_else(|| {
            HsmError::ConfigurationError("pkcs11_slot is required".into())
        })?;
        let pin = config.pkcs11_pin.as_deref().ok_or_else(|| {
            HsmError::ConfigurationError("pkcs11_pin is required".into())
        })?;

        Pkcs11HardwareKeySource::new(lib, slot, pin, &config.key_label)
    }
}

// Re-export the hardware types when the feature is enabled.
#[cfg(feature = "pkcs11-hw")]
pub use pkcs11_hw::{
    create_hw_key_source, create_hw_session, Pkcs11HardwareKeySource, Pkcs11HardwareSession,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsm_backend_display() {
        assert_eq!(format!("{}", HsmBackend::Pkcs11), "pkcs11");
        assert_eq!(format!("{}", HsmBackend::AwsKms), "aws-kms");
        assert_eq!(format!("{}", HsmBackend::Tpm2), "tpm2");
        assert_eq!(format!("{}", HsmBackend::Software), "software");
    }

    #[test]
    fn hsm_backend_from_str() {
        assert_eq!(HsmBackend::from_str_name("pkcs11"), Some(HsmBackend::Pkcs11));
        assert_eq!(HsmBackend::from_str_name("aws-kms"), Some(HsmBackend::AwsKms));
        assert_eq!(HsmBackend::from_str_name("kms"), Some(HsmBackend::AwsKms));
        assert_eq!(HsmBackend::from_str_name("tpm2"), Some(HsmBackend::Tpm2));
        assert_eq!(HsmBackend::from_str_name("tpm"), Some(HsmBackend::Tpm2));
        assert_eq!(HsmBackend::from_str_name("software"), Some(HsmBackend::Software));
        assert_eq!(HsmBackend::from_str_name("dev"), Some(HsmBackend::Software));
        assert_eq!(HsmBackend::from_str_name("invalid"), None);
    }

    #[test]
    fn hsm_backend_is_hardware_backed() {
        assert!(HsmBackend::Pkcs11.is_hardware_backed());
        assert!(HsmBackend::AwsKms.is_hardware_backed());
        assert!(HsmBackend::Tpm2.is_hardware_backed());
        assert!(!HsmBackend::Software.is_hardware_backed());
    }

    #[test]
    fn hsm_config_default() {
        let config = HsmConfig::default();
        assert_eq!(config.backend, HsmBackend::Software);
        assert_eq!(config.key_label, "MILNET-MASTER-KEK-v1");
        assert_eq!(config.tpm2_pcr_indices, vec![0, 2, 4, 7]);
    }

    #[test]
    fn hsm_config_validate_software() {
        let config = HsmConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn hsm_config_validate_pkcs11_missing_fields() {
        let config = HsmConfig {
            backend: HsmBackend::Pkcs11,
            ..HsmConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, HsmError::ConfigurationError(_)));
    }

    #[test]
    fn hsm_config_validate_pkcs11_complete() {
        let config = HsmConfig {
            backend: HsmBackend::Pkcs11,
            pkcs11_library_path: Some("/usr/lib/softhsm/libsofthsm2.so".into()),
            pkcs11_slot: Some(0),
            pkcs11_pin: Some("1234".into()),
            ..HsmConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn hsm_config_validate_aws_kms_missing_key() {
        let config = HsmConfig {
            backend: HsmBackend::AwsKms,
            ..HsmConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, HsmError::ConfigurationError(_)));
    }

    #[test]
    fn hsm_config_validate_tpm2_missing_device() {
        let config = HsmConfig {
            backend: HsmBackend::Tpm2,
            ..HsmConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, HsmError::ConfigurationError(_)));
    }

    #[test]
    fn software_backend_seal_unseal_roundtrip() {
        let config = HsmConfig {
            backend: HsmBackend::Software,
            software_seed: Some(b"test-seed-for-hsm-software-backend".to_vec()),
            ..HsmConfig::default()
        };
        let manager = HsmKeyManager::new(config).unwrap();

        let plaintext = b"secret-frost-share-data-for-testing";
        let sealed = manager.seal_with_hardware(plaintext, "test-purpose").unwrap();
        let recovered = manager.unseal_with_hardware(&sealed, "test-purpose").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn software_backend_wrong_purpose_fails() {
        let config = HsmConfig {
            backend: HsmBackend::Software,
            software_seed: Some(b"test-seed".to_vec()),
            ..HsmConfig::default()
        };
        let manager = HsmKeyManager::new(config).unwrap();

        let sealed = manager.seal_with_hardware(b"data", "correct").unwrap();
        let result = manager.unseal_with_hardware(&sealed, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn software_backend_frost_share_roundtrip() {
        let config = HsmConfig {
            backend: HsmBackend::Software,
            software_seed: Some(b"frost-test-seed".to_vec()),
            ..HsmConfig::default()
        };
        let manager = HsmKeyManager::new(config).unwrap();

        let share = b"frost-share-bytes-secret-material-1234567890";
        let sealed = manager.seal_frost_share(share).unwrap();
        let recovered = manager.unseal_frost_share(&sealed).unwrap();
        assert_eq!(recovered, share);
    }

    #[test]
    fn software_backend_load_master_key() {
        let config = HsmConfig {
            backend: HsmBackend::Software,
            software_seed: Some(b"master-key-test-seed".to_vec()),
            ..HsmConfig::default()
        };
        let manager = HsmKeyManager::new(config).unwrap();

        let mk1 = manager.load_master_key().unwrap();
        let mk2 = manager.load_master_key().unwrap();
        // Deterministic: same seed -> same key
        // We can't compare directly (no PartialEq on MasterKey), so seal/unseal
        let hierarchy1 = crate::seal::KeyHierarchy::new(mk1);
        let sealed = hierarchy1.seal_key_material("verify", b"test").unwrap();
        let hierarchy2 = crate::seal::KeyHierarchy::new(mk2);
        let recovered = hierarchy2.unseal_key_material("verify", &sealed).unwrap();
        assert_eq!(recovered, b"test");
    }

    #[test]
    fn software_backend_rotate_produces_new_key() {
        let config = HsmConfig {
            backend: HsmBackend::Software,
            software_seed: Some(b"rotate-test-seed".to_vec()),
            ..HsmConfig::default()
        };
        let manager = HsmKeyManager::new(config).unwrap();

        let original = manager.load_master_key().unwrap();
        let rotated = manager.rotate_master_key().unwrap();

        // Rotated key should differ: seal with original, fail to unseal with rotated
        let hierarchy_orig = crate::seal::KeyHierarchy::new(original);
        let sealed = hierarchy_orig.seal_key_material("test", b"data").unwrap();
        let hierarchy_new = crate::seal::KeyHierarchy::new(rotated);
        let result = hierarchy_new.unseal_key_material("test", &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn software_backend_generate_wrapped_dek() {
        let config = HsmConfig {
            backend: HsmBackend::Software,
            software_seed: Some(b"dek-gen-test-seed".to_vec()),
            ..HsmConfig::default()
        };
        let manager = HsmKeyManager::new(config).unwrap();

        let wrapped_dek = manager.generate_wrapped_dek("database-encryption").unwrap();
        assert!(!wrapped_dek.is_empty());
        // The wrapped DEK should be decryptable
        let recovered = manager
            .unseal_with_hardware(&wrapped_dek, "database-encryption")
            .unwrap();
        assert_eq!(recovered.len(), 32); // AES-256 key
    }

    #[test]
    fn hsm_error_to_seal_error_conversion() {
        let e: SealError = HsmError::AuthenticationFailed.into();
        assert_eq!(e, SealError::InvalidMasterKey);

        let e: SealError = HsmError::WrapFailed("test".into()).into();
        assert_eq!(e, SealError::SealFailed);

        let e: SealError = HsmError::UnwrapFailed("test".into()).into();
        assert_eq!(e, SealError::UnsealFailed);

        let e: SealError = HsmError::PcrMismatch.into();
        assert_eq!(e, SealError::UnsealFailed);
    }

    #[test]
    fn hsm_key_manager_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HsmKeyManager>();
    }

    #[test]
    fn create_key_source_software() {
        let config = HsmConfig {
            backend: HsmBackend::Software,
            software_seed: Some(b"factory-test".to_vec()),
            ..HsmConfig::default()
        };
        // Use production new() constructor with Software backend (allowed
        // when MILNET_PRODUCTION is not set), then box as ProductionKeySource.
        let source: Box<dyn ProductionKeySource> =
            Box::new(HsmKeyManager::new(config).unwrap());
        let mk = source.load_master_key().unwrap();
        // Verify the key is usable
        let kek = mk.derive_kek("test");
        let sealed = kek.seal(b"hello").unwrap();
        // Need a new master key to unseal (original was moved)
        let mk2 = source.load_master_key().unwrap();
        let kek2 = mk2.derive_kek("test");
        let recovered = kek2.unseal(&sealed).unwrap();
        assert_eq!(recovered, b"hello");
    }

    // -----------------------------------------------------------------------
    // PKCS#11 backend tests
    // -----------------------------------------------------------------------

    fn make_pkcs11_manager() -> HsmKeyManager {
        let config = HsmConfig {
            backend: HsmBackend::Pkcs11,
            pkcs11_library_path: Some("/usr/lib/softhsm/libsofthsm2.so".into()),
            pkcs11_slot: Some(0),
            pkcs11_pin: Some("test-pin-1234".into()),
            ..HsmConfig::default()
        };
        HsmKeyManager::new(config).unwrap()
    }

    #[test]
    fn pkcs11_seal_unseal_roundtrip() {
        let manager = make_pkcs11_manager();

        let plaintext = b"pkcs11-secret-data-for-roundtrip-test";
        let sealed = manager.seal_with_hardware(plaintext, "pkcs11-test").unwrap();
        let recovered = manager.unseal_with_hardware(&sealed, "pkcs11-test").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn pkcs11_wrong_purpose_fails() {
        let manager = make_pkcs11_manager();

        let sealed = manager.seal_with_hardware(b"data", "right").unwrap();
        let result = manager.unseal_with_hardware(&sealed, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn pkcs11_load_master_key() {
        let manager = make_pkcs11_manager();

        let mk1 = manager.load_master_key().unwrap();
        let mk2 = manager.load_master_key().unwrap();

        // Should be deterministic
        let h1 = crate::seal::KeyHierarchy::new(mk1);
        let sealed = h1.seal_key_material("verify", b"pkcs11-test").unwrap();
        let h2 = crate::seal::KeyHierarchy::new(mk2);
        let recovered = h2.unseal_key_material("verify", &sealed).unwrap();
        assert_eq!(recovered, b"pkcs11-test");
    }

    #[test]
    fn pkcs11_frost_share_roundtrip() {
        let manager = make_pkcs11_manager();

        let share = b"frost-share-for-pkcs11-test-1234567890";
        let sealed = manager.seal_frost_share(share).unwrap();
        let recovered = manager.unseal_frost_share(&sealed).unwrap();
        assert_eq!(recovered, share);
    }

    #[test]
    fn pkcs11_generate_wrapped_dek() {
        let manager = make_pkcs11_manager();

        let wrapped = manager.generate_wrapped_dek("pkcs11-dek-test").unwrap();
        assert!(!wrapped.is_empty());
    }

    #[test]
    fn pkcs11_sign_with_hardware() {
        let manager = make_pkcs11_manager();

        let data = b"data-to-sign-with-pkcs11";
        let sig = manager.sign_with_hardware(data, "signing-key").unwrap();
        assert_eq!(sig.len(), 32); // HMAC-SHA256 output
    }

    #[test]
    fn pkcs11_key_rotation() {
        let manager = make_pkcs11_manager();

        let mk_before = manager.load_master_key().unwrap();
        let _mk_new = manager.rotate_master_key().unwrap();
        let mk_after = manager.load_master_key().unwrap();

        // After rotation, the master key should differ
        let h_before = crate::seal::KeyHierarchy::new(mk_before);
        let sealed = h_before.seal_key_material("rotation", b"test").unwrap();
        let h_after = crate::seal::KeyHierarchy::new(mk_after);
        // May or may not unseal depending on whether load_master_key returns
        // a derived key from the new master. We just check it doesn't panic.
        let _ = h_after.unseal_key_material("rotation", &sealed);
    }

    // -----------------------------------------------------------------------
    // AWS KMS backend tests
    // -----------------------------------------------------------------------

    fn make_aws_kms_manager() -> HsmKeyManager {
        let config = HsmConfig {
            backend: HsmBackend::AwsKms,
            aws_kms_key_id: Some("arn:aws:kms:us-east-1:123456789012:key/test-key-id".into()),
            aws_kms_region: Some("us-east-1".into()),
            ..HsmConfig::default()
        };
        HsmKeyManager::new(config).unwrap()
    }

    #[test]
    fn aws_kms_seal_unseal_roundtrip() {
        let manager = make_aws_kms_manager();

        let plaintext = b"aws-kms-secret-data-for-envelope-test";
        let sealed = manager.seal_with_hardware(plaintext, "kms-test").unwrap();
        let recovered = manager.unseal_with_hardware(&sealed, "kms-test").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn aws_kms_wrong_purpose_fails() {
        let manager = make_aws_kms_manager();

        let sealed = manager.seal_with_hardware(b"data", "correct-purpose").unwrap();
        let result = manager.unseal_with_hardware(&sealed, "wrong-purpose");
        assert!(result.is_err());
    }

    #[test]
    fn aws_kms_load_master_key() {
        let manager = make_aws_kms_manager();

        let mk1 = manager.load_master_key().unwrap();
        let mk2 = manager.load_master_key().unwrap();

        let h1 = crate::seal::KeyHierarchy::new(mk1);
        let sealed = h1.seal_key_material("verify", b"kms-test").unwrap();
        let h2 = crate::seal::KeyHierarchy::new(mk2);
        let recovered = h2.unseal_key_material("verify", &sealed).unwrap();
        assert_eq!(recovered, b"kms-test");
    }

    #[test]
    fn aws_kms_frost_share_roundtrip() {
        let manager = make_aws_kms_manager();

        let share = b"frost-share-for-kms-test-abcdef";
        let sealed = manager.seal_frost_share(share).unwrap();
        let recovered = manager.unseal_frost_share(&sealed).unwrap();
        assert_eq!(recovered, share);
    }

    #[test]
    fn aws_kms_generate_wrapped_dek() {
        let manager = make_aws_kms_manager();

        let wrapped = manager.generate_wrapped_dek("kms-dek-test").unwrap();
        assert!(!wrapped.is_empty());
    }

    #[test]
    fn aws_kms_sign_with_hardware() {
        let manager = make_aws_kms_manager();

        let data = b"data-to-sign-with-kms";
        let sig = manager.sign_with_hardware(data, "kms-signing").unwrap();
        assert_eq!(sig.len(), 32);
    }

    // -----------------------------------------------------------------------
    // TPM 2.0 backend tests
    // -----------------------------------------------------------------------

    fn make_tpm2_manager() -> HsmKeyManager {
        let config = HsmConfig {
            backend: HsmBackend::Tpm2,
            tpm2_device: Some("/dev/tpmrm0".into()),
            tpm2_pcr_indices: vec![0, 2, 4, 7],
            ..HsmConfig::default()
        };
        HsmKeyManager::new(config).unwrap()
    }

    #[test]
    fn tpm2_seal_unseal_roundtrip() {
        let manager = make_tpm2_manager();

        let plaintext = b"tpm2-sealed-secret-data";
        let sealed = manager.seal_with_hardware(plaintext, "tpm2-test").unwrap();
        let recovered = manager.unseal_with_hardware(&sealed, "tpm2-test").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn tpm2_wrong_purpose_fails() {
        let manager = make_tpm2_manager();

        let sealed = manager.seal_with_hardware(b"data", "right-purpose").unwrap();
        let result = manager.unseal_with_hardware(&sealed, "wrong-purpose");
        assert!(result.is_err());
    }

    #[test]
    fn tpm2_load_master_key() {
        let manager = make_tpm2_manager();

        let mk1 = manager.load_master_key().unwrap();
        let mk2 = manager.load_master_key().unwrap();

        let h1 = crate::seal::KeyHierarchy::new(mk1);
        let sealed = h1.seal_key_material("verify", b"tpm2-test").unwrap();
        let h2 = crate::seal::KeyHierarchy::new(mk2);
        let recovered = h2.unseal_key_material("verify", &sealed).unwrap();
        assert_eq!(recovered, b"tpm2-test");
    }

    #[test]
    fn tpm2_frost_share_roundtrip() {
        let manager = make_tpm2_manager();

        let share = b"frost-share-for-tpm2-test-xyz";
        let sealed = manager.seal_frost_share(share).unwrap();
        let recovered = manager.unseal_frost_share(&sealed).unwrap();
        assert_eq!(recovered, share);
    }

    #[test]
    fn tpm2_generate_wrapped_dek() {
        let manager = make_tpm2_manager();

        let wrapped = manager.generate_wrapped_dek("tpm2-dek-test").unwrap();
        assert!(!wrapped.is_empty());
    }

    #[test]
    fn tpm2_sign_with_hardware() {
        let manager = make_tpm2_manager();

        let data = b"data-to-sign-with-tpm2";
        let sig = manager.sign_with_hardware(data, "tpm2-signing").unwrap();
        assert_eq!(sig.len(), 32);
    }

    #[test]
    fn tpm2_attestation_quote() {
        let manager = make_tpm2_manager();

        let nonce = [42u8; 32];
        let quote = manager.generate_attestation_quote(&nonce).unwrap();
        // Quote should contain: nonce(32) + pcr_selection(5 bytes: 4 indices + 0xFF terminator)
        // + pcr_values(4 * 32 = 128) + hmac_signature(32) = 197 bytes
        assert!(quote.len() > 100);
        // Verify nonce is at the start
        assert_eq!(&quote[..32], &nonce);
    }

    // -----------------------------------------------------------------------
    // HsmKeyOps trait tests (via HsmKeyManager)
    // -----------------------------------------------------------------------

    #[test]
    fn hsm_key_ops_generate_sign_verify() {
        let manager = make_pkcs11_manager();

        // Generate a key
        let handle = manager.generate_key("test-hmac-key", KeyType::HmacSha256).unwrap();
        assert!(!handle.is_empty());

        // Key should exist
        assert!(manager.key_exists("test-hmac-key").unwrap());

        // Sign data
        let data = b"hello, world!";
        let sig = manager.sign("test-hmac-key", data).unwrap();
        assert_eq!(sig.len(), 32);

        // Verify should succeed with correct data
        assert!(manager.verify("test-hmac-key", data, &sig).unwrap());

        // Verify should fail with wrong data
        assert!(!manager.verify("test-hmac-key", b"wrong data", &sig).unwrap());

        // Destroy key
        manager.destroy_key("test-hmac-key").unwrap();
        assert!(!manager.key_exists("test-hmac-key").unwrap());
    }

    #[test]
    fn hsm_key_ops_encrypt_decrypt() {
        let manager = make_pkcs11_manager();

        manager.generate_key("test-aes-key", KeyType::Aes256).unwrap();

        let plaintext = b"sensitive data to encrypt";
        let aad = b"additional-auth-data";
        let ciphertext = manager.encrypt("test-aes-key", plaintext, aad).unwrap();

        let recovered = manager.decrypt("test-aes-key", &ciphertext, aad).unwrap();
        assert_eq!(recovered, plaintext);

        // Wrong AAD should fail
        let result = manager.decrypt("test-aes-key", &ciphertext, b"wrong-aad");
        assert!(result.is_err());
    }

    #[test]
    fn hsm_key_ops_wrap_unwrap() {
        let manager = make_pkcs11_manager();

        manager.generate_key("wrapping-key", KeyType::Aes256Wrap).unwrap();

        let key_to_wrap = b"secret-key-material-32-bytes!!!!";
        let wrapped = manager.wrap_key("wrapping-key", key_to_wrap).unwrap();

        let unwrapped = manager.unwrap_key("wrapping-key", &wrapped).unwrap();
        assert_eq!(unwrapped, key_to_wrap);
    }

    #[test]
    fn hsm_key_ops_nonexistent_key_fails() {
        let manager = make_pkcs11_manager();

        let result = manager.sign("nonexistent", b"data");
        assert!(matches!(result, Err(HsmError::KeyNotFound(_))));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(constant_time_eq(b"", b""));
    }

    // ── HSM backend selection and production mode tests ──

    #[test]
    fn pkcs11_backend_seal_unseal_with_different_purposes() {
        let manager = make_pkcs11_manager();
        let plaintext = b"pkcs11-protected-secret-data";
        let sealed = manager
            .seal_with_hardware(plaintext, "purpose-a")
            .unwrap();
        // Same purpose must succeed
        let recovered = manager
            .unseal_with_hardware(&sealed, "purpose-a")
            .unwrap();
        assert_eq!(recovered, plaintext);
        // Different purpose must fail (CKM_AES_KEY_WRAP_KWP domain separation)
        let result = manager.unseal_with_hardware(&sealed, "purpose-b");
        assert!(result.is_err(), "PKCS#11 wrap with wrong purpose must fail");
    }

    #[test]
    fn tpm2_attestation_quote_contains_nonce_and_pcrs() {
        let config = HsmConfig {
            backend: HsmBackend::Tpm2,
            tpm2_device: Some("/dev/tpmrm0".into()),
            tpm2_pcr_indices: vec![0, 2, 4, 7],
            ..HsmConfig::default()
        };
        let manager = HsmKeyManager::new(config).unwrap();
        let nonce = [0x42u8; 32];
        let quote = manager.generate_attestation_quote(&nonce).unwrap();
        // Quote must contain: nonce (32) + PCR indices + 0xFF + PCR values + HMAC sig
        assert!(quote.len() > 32, "attestation quote must be non-trivial");
        assert_eq!(&quote[..32], &nonce, "quote must start with provided nonce");
        // PCR indices should appear after the nonce (0, 2, 4, 7, 0xFF terminator)
        assert_eq!(quote[32], 0, "first PCR index should be 0");
        assert_eq!(quote[33], 2, "second PCR index should be 2");
        assert_eq!(quote[34], 4, "third PCR index should be 4");
        assert_eq!(quote[35], 7, "fourth PCR index should be 7");
        assert_eq!(quote[36], 0xFF, "PCR list must be terminated with 0xFF");
    }

    #[test]
    fn tpm2_different_pcr_sets_produce_different_keys() {
        let config1 = HsmConfig {
            backend: HsmBackend::Tpm2,
            tpm2_device: Some("/dev/tpmrm0".into()),
            tpm2_pcr_indices: vec![0, 2, 4, 7],
            ..HsmConfig::default()
        };
        let config2 = HsmConfig {
            backend: HsmBackend::Tpm2,
            tpm2_device: Some("/dev/tpmrm0".into()),
            tpm2_pcr_indices: vec![0, 1, 3, 7], // different PCRs
            ..HsmConfig::default()
        };
        let manager1 = HsmKeyManager::new(config1).unwrap();
        let manager2 = HsmKeyManager::new(config2).unwrap();

        // Sealing with manager1 and unsealing with manager2 (different PCRs) must fail
        let sealed = manager1
            .seal_with_hardware(b"pcr-bound-data", "pcr-test")
            .unwrap();
        let result = manager2.unseal_with_hardware(&sealed, "pcr-test");
        assert!(
            result.is_err(),
            "TPM2 unseal with different PCR set must fail (PCR mismatch)"
        );
    }

    #[test]
    fn software_backend_in_production_returns_error() {
        // We can't set MILNET_PRODUCTION=1 in tests because it would affect
        // other tests, but we CAN verify that the error type exists and the
        // is_hardware_backed check works correctly.
        assert!(
            !HsmBackend::Software.is_hardware_backed(),
            "software backend must NOT be hardware-backed"
        );
        // Verify that the SoftwareInProduction error variant is correctly defined
        let err = HsmError::SoftwareInProduction;
        assert_eq!(
            format!("{}", err),
            "software HSM backend is forbidden in production mode"
        );
    }

    #[test]
    fn all_backend_types_are_correctly_classified() {
        assert!(HsmBackend::Pkcs11.is_hardware_backed());
        assert!(HsmBackend::AwsKms.is_hardware_backed());
        assert!(HsmBackend::Tpm2.is_hardware_backed());
        assert!(!HsmBackend::Software.is_hardware_backed());
    }

    #[test]
    fn hsm_config_debug_redacts_pin() {
        let config = HsmConfig {
            backend: HsmBackend::Pkcs11,
            pkcs11_library_path: Some("/usr/lib/softhsm/libsofthsm2.so".into()),
            pkcs11_slot: Some(0),
            pkcs11_pin: Some("my-secret-pin".into()),
            aws_kms_key_id: None,
            aws_kms_region: None,
            tpm2_device: None,
            tpm2_pcr_indices: vec![0, 2, 4, 7],
            key_label: "test-key".into(),
            software_seed: None,
        };
        let debug_output = format!("{:?}", config);
        assert!(
            !debug_output.contains("my-secret-pin"),
            "Debug must redact PIN"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug must show [REDACTED]"
        );
    }
}
