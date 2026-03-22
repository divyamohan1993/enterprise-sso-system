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
//! # External Dependencies (not linked — interface only)
//! ```toml
//! # requires: pkcs11 = "0.5"        — for PKCS#11 backend
//! # requires: aws-sdk-kms = "1.x"   — for AWS KMS backend
//! # requires: tss-esapi = "7.x"     — for TPM 2.0 backend
//! ```

use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::seal::{DerivedKek, MasterKey, ProductionKeySource, SealError, SoftwareKeySource};

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
#[derive(Debug, Clone)]
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
        let software_seed = std::env::var("MILNET_MASTER_KEK").ok().map(|mut hex| {
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
// PKCS#11 session state (opaque handle)
// ---------------------------------------------------------------------------

/// Opaque handle to a PKCS#11 session and key object.
///
/// In a real implementation, this would hold:
/// - `pkcs11::Context` — the loaded PKCS#11 library
/// - `CK_SESSION_HANDLE` — the authenticated session
/// - `CK_OBJECT_HANDLE` — handle to the master AES-256 key
///
/// ```ignore
/// // requires: pkcs11 = "0.5"
/// use pkcs11::Ctx;
/// use pkcs11::types::{CK_SESSION_HANDLE, CK_OBJECT_HANDLE};
/// ```
struct Pkcs11Session {
    /// Path to the loaded PKCS#11 library.
    _library_path: String,
    /// Slot number this session is bound to.
    _slot: u64,
    /// Key label used to find/create the master key.
    _key_label: String,
    /// Whether the session has been authenticated (C_Login succeeded).
    authenticated: bool,
}

// ---------------------------------------------------------------------------
// AWS KMS session state
// ---------------------------------------------------------------------------

/// Opaque handle to an AWS KMS client and key.
///
/// In a real implementation, this would hold:
/// - `aws_sdk_kms::Client` — the KMS client
/// - Key ID / ARN for the master CMK
///
/// ```ignore
/// // requires: aws-sdk-kms = "1.x"
/// // requires: aws-config = "1.x"
/// use aws_sdk_kms::Client as KmsClient;
/// ```
struct AwsKmsSession {
    /// KMS key ARN or alias.
    _key_id: String,
    /// AWS region.
    _region: String,
}

// ---------------------------------------------------------------------------
// TPM 2.0 session state
// ---------------------------------------------------------------------------

/// Opaque handle to a TPM 2.0 context.
///
/// In a real implementation, this would hold:
/// - `tss_esapi::Context` — the ESAPI context
/// - `tss_esapi::handles::KeyHandle` — handle to the primary/storage key
///
/// ```ignore
/// // requires: tss-esapi = "7.x"
/// use tss_esapi::Context as TpmContext;
/// use tss_esapi::handles::KeyHandle;
/// ```
struct Tpm2Session {
    /// Device path (e.g., `/dev/tpmrm0`).
    _device: String,
    /// PCR indices for sealing policy.
    _pcr_indices: Vec<u8>,
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

/// HSM-backed key manager implementing [`ProductionKeySource`].
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
    /// is rejected with [`HsmError::SoftwareInProduction`].
    pub fn new(config: HsmConfig) -> Result<Self, HsmError> {
        config.validate()?;

        // Fail-closed: reject software backend in production
        if config.backend == HsmBackend::Software && common::sealed_keys::is_production() {
            eprintln!(
                "FATAL: Software HSM backend is forbidden in production mode. \
                 Configure a hardware HSM via MILNET_HSM_BACKEND."
            );
            return Err(HsmError::SoftwareInProduction);
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
                let seed = config
                    .software_seed
                    .as_deref()
                    .unwrap_or(b"MILNET-DEV-MASTER-KEK-NOT-FOR-PRODUCTION");
                let source = SoftwareKeySource::new(seed)
                    .map_err(|e| HsmError::InitializationFailed(format!("{e}")))?;
                eprintln!(
                    "WARNING: Using software HSM backend. NOT FOR PRODUCTION."
                );
                BackendState::Software(source)
            }
        };

        eprintln!(
            "INFO: HSM key manager initialized (backend={}, label={})",
            config.backend, config.key_label
        );

        Ok(Self {
            config,
            state: Mutex::new(state),
        })
    }

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
    /// Real implementation would:
    /// 1. Load the PKCS#11 shared library via `Ctx::new(path)`
    /// 2. Call `C_Initialize`
    /// 3. Open a session on the configured slot: `C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)`
    /// 4. Authenticate: `C_Login(session, CKU_USER, pin)`
    /// 5. Find the master key by label: `C_FindObjects` with `CKA_LABEL`
    /// 6. If not found, generate: `C_GenerateKey` with CKM_AES_KEY_GEN, 256-bit
    ///    Attributes: CKA_EXTRACTABLE=false, CKA_SENSITIVE=true, CKA_WRAP=true, CKA_UNWRAP=true
    fn init_pkcs11(config: &HsmConfig) -> Result<Pkcs11Session, HsmError> {
        let lib_path = config.pkcs11_library_path.as_ref().unwrap();
        let slot = config.pkcs11_slot.unwrap();
        let _pin = config.pkcs11_pin.as_ref().unwrap();

        eprintln!(
            "INFO: Initializing PKCS#11 backend (library={}, slot={})",
            lib_path, slot
        );

        // TODO: Real PKCS#11 initialization
        // ```
        // let ctx = Ctx::new(lib_path)
        //     .map_err(|e| HsmError::InitializationFailed(format!("C_Initialize: {e}")))?;
        // ctx.initialize(None)
        //     .map_err(|e| HsmError::InitializationFailed(format!("{e}")))?;
        //
        // let session = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
        //     .map_err(|e| HsmError::InitializationFailed(format!("C_OpenSession: {e}")))?;
        //
        // ctx.login(session, CKU_USER, Some(pin.as_bytes()))
        //     .map_err(|e| HsmError::AuthenticationFailed)?;
        //
        // // Find or generate master AES-256 key
        // let template = vec![
        //     Attribute::new(CKA_CLASS, CKO_SECRET_KEY),
        //     Attribute::new(CKA_KEY_TYPE, CKK_AES),
        //     Attribute::new(CKA_LABEL, config.key_label.as_bytes()),
        // ];
        // let objects = ctx.find_objects(session, &template)
        //     .map_err(|e| HsmError::CommunicationError(format!("{e}")))?;
        //
        // if objects.is_empty() {
        //     // Generate new master key — non-extractable, wrap/unwrap capable
        //     let gen_template = vec![
        //         Attribute::new(CKA_CLASS, CKO_SECRET_KEY),
        //         Attribute::new(CKA_KEY_TYPE, CKK_AES),
        //         Attribute::new(CKA_VALUE_LEN, 32u64),  // AES-256
        //         Attribute::new(CKA_LABEL, config.key_label.as_bytes()),
        //         Attribute::new(CKA_TOKEN, true),
        //         Attribute::new(CKA_PRIVATE, true),
        //         Attribute::new(CKA_SENSITIVE, true),
        //         Attribute::new(CKA_EXTRACTABLE, false),  // CRITICAL: key never leaves HSM
        //         Attribute::new(CKA_WRAP, true),
        //         Attribute::new(CKA_UNWRAP, true),
        //         Attribute::new(CKA_ENCRYPT, true),
        //         Attribute::new(CKA_DECRYPT, true),
        //     ];
        //     ctx.generate_key(session, &Mechanism::new(CKM_AES_KEY_GEN), &gen_template)?;
        // }
        // ```

        Ok(Pkcs11Session {
            _library_path: lib_path.clone(),
            _slot: slot,
            _key_label: config.key_label.clone(),
            authenticated: true,
        })
    }

    /// Wrap (seal) data using PKCS#11 CKM_AES_KEY_WRAP_KWP.
    ///
    /// The master key never leaves the HSM; the HSM performs the wrapping
    /// internally and returns only the wrapped ciphertext.
    ///
    /// Real implementation:
    /// ```ignore
    /// // Generate a temporary AES-256 DEK inside the HSM
    /// let dek_handle = ctx.generate_key(session, CKM_AES_KEY_GEN, &dek_template)?;
    ///
    /// // Wrap the DEK under the master key using AES-KWP (NIST SP 800-38F)
    /// let mechanism = Mechanism::new(CKM_AES_KEY_WRAP_KWP);
    /// let wrapped_dek = ctx.wrap_key(session, &mechanism, master_key_handle, dek_handle)?;
    ///
    /// // Use the DEK handle to encrypt the plaintext inside the HSM
    /// let ciphertext = ctx.encrypt(session, &Mechanism::new(CKM_AES_GCM), dek_handle, plaintext)?;
    ///
    /// // Destroy the temporary DEK handle
    /// ctx.destroy_object(session, dek_handle)?;
    ///
    /// // Return wrapped_dek || ciphertext
    /// ```
    fn pkcs11_wrap(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let _state = self.state.lock().map_err(|_| SealError::SealFailed)?;

        // In a real implementation, the HSM performs the wrapping.
        // For the interface layer, we document the PKCS#11 call sequence
        // and return an error indicating hardware is required.
        //
        // The actual call sequence:
        // 1. Derive a purpose-specific wrapping context (HKDF in software
        //    is acceptable because the _master_ key stays in HSM)
        // 2. C_WrapKey with CKM_AES_KEY_WRAP_KWP
        // 3. Return the wrapped blob

        eprintln!(
            "INFO: PKCS#11 seal operation (purpose={}, plaintext_len={})",
            purpose,
            plaintext.len()
        );

        // Placeholder: in production, this would call into the PKCS#11 library.
        // For now, fail-closed — hardware not available.
        Err(SealError::SealFailed)
    }

    /// Unwrap (unseal) data using PKCS#11 CKM_AES_KEY_WRAP_KWP.
    fn pkcs11_unwrap(&self, sealed: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let _state = self.state.lock().map_err(|_| SealError::UnsealFailed)?;

        eprintln!(
            "INFO: PKCS#11 unseal operation (purpose={}, sealed_len={})",
            purpose,
            sealed.len()
        );

        // Real implementation:
        // 1. Split sealed = wrapped_dek || ciphertext
        // 2. C_UnwrapKey with CKM_AES_KEY_WRAP_KWP to recover DEK handle
        // 3. C_Decrypt with CKM_AES_GCM using DEK handle
        // 4. C_DestroyObject on DEK handle
        // 5. Return plaintext

        Err(SealError::UnsealFailed)
    }

    // -----------------------------------------------------------------------
    // AWS KMS backend initialization
    // -----------------------------------------------------------------------

    /// Initialize AWS KMS backend.
    ///
    /// Real implementation would:
    /// 1. Load AWS credentials from environment/IAM role
    /// 2. Create KMS client: `aws_sdk_kms::Client::new(&config)`
    /// 3. Verify key access: `kms.describe_key(key_id)`
    /// 4. Verify key is enabled and has ENCRYPT_DECRYPT usage
    fn init_aws_kms(config: &HsmConfig) -> Result<AwsKmsSession, HsmError> {
        let key_id = config.aws_kms_key_id.as_ref().unwrap();
        let region = config
            .aws_kms_region
            .as_deref()
            .unwrap_or("us-east-1");

        eprintln!(
            "INFO: Initializing AWS KMS backend (key_id={}..., region={})",
            &key_id[..key_id.len().min(20)],
            region
        );

        // TODO: Real AWS KMS initialization
        // ```
        // let aws_config = aws_config::defaults(BehaviorVersion::latest())
        //     .region(Region::new(region.to_string()))
        //     .load()
        //     .await
        //     .map_err(|e| HsmError::InitializationFailed(format!("{e}")))?;
        //
        // let client = aws_sdk_kms::Client::new(&aws_config);
        //
        // // Verify key exists and is usable
        // client.describe_key().key_id(key_id).send().await
        //     .map_err(|e| HsmError::KeyNotFound(format!("{e}")))?;
        // ```

        Ok(AwsKmsSession {
            _key_id: key_id.clone(),
            _region: region.to_string(),
        })
    }

    /// Seal using AWS KMS envelope encryption pattern.
    ///
    /// Pattern:
    /// 1. Call `GenerateDataKey(KeyId, AES_256)` — returns plaintext DEK + encrypted DEK
    /// 2. Encrypt data locally with the plaintext DEK (AES-256-GCM)
    /// 3. Zeroize the plaintext DEK immediately
    /// 4. Return encrypted_dek || nonce || ciphertext || tag
    ///
    /// The CMK (Customer Master Key) never leaves AWS.
    fn aws_kms_wrap(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let _state = self.state.lock().map_err(|_| SealError::SealFailed)?;

        eprintln!(
            "INFO: AWS KMS seal operation (purpose={}, plaintext_len={})",
            purpose,
            plaintext.len()
        );

        // Real implementation:
        // ```
        // // 1. Generate a data encryption key via KMS
        // let resp = client.generate_data_key()
        //     .key_id(&self.key_id)
        //     .key_spec(DataKeySpec::Aes256)
        //     .encryption_context("purpose", purpose)
        //     .send().await
        //     .map_err(|e| SealError::SealFailed)?;
        //
        // let plaintext_dek = resp.plaintext().unwrap();  // 32 bytes, in memory briefly
        // let encrypted_dek = resp.ciphertext_blob().unwrap();  // ~184 bytes (KMS wrapped)
        //
        // // 2. Encrypt data locally with the DEK
        // let cipher = Aes256Gcm::new_from_slice(plaintext_dek)?;
        // let nonce = generate_nonce();
        // let ciphertext = cipher.encrypt(&nonce, Payload { msg: plaintext, aad: purpose.as_bytes() })?;
        //
        // // 3. Zeroize the plaintext DEK
        // plaintext_dek.zeroize();
        //
        // // 4. Assemble: [encrypted_dek_len (4 bytes)] || encrypted_dek || nonce || ciphertext
        // let mut output = Vec::new();
        // output.extend_from_slice(&(encrypted_dek.len() as u32).to_be_bytes());
        // output.extend_from_slice(encrypted_dek);
        // output.extend_from_slice(&nonce);
        // output.extend_from_slice(&ciphertext);
        // Ok(output)
        // ```

        Err(SealError::SealFailed)
    }

    /// Unseal using AWS KMS envelope encryption pattern.
    ///
    /// Pattern:
    /// 1. Parse: encrypted_dek_len || encrypted_dek || nonce || ciphertext
    /// 2. Call `Decrypt(CiphertextBlob=encrypted_dek)` to recover plaintext DEK
    /// 3. Decrypt data locally with the plaintext DEK
    /// 4. Zeroize the plaintext DEK immediately
    fn aws_kms_unwrap(&self, sealed: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let _state = self.state.lock().map_err(|_| SealError::UnsealFailed)?;

        eprintln!(
            "INFO: AWS KMS unseal operation (purpose={}, sealed_len={})",
            purpose,
            sealed.len()
        );

        // Real implementation:
        // ```
        // // 1. Parse the envelope
        // let dek_len = u32::from_be_bytes(sealed[0..4].try_into()?) as usize;
        // let encrypted_dek = &sealed[4..4+dek_len];
        // let nonce = &sealed[4+dek_len..4+dek_len+12];
        // let ciphertext = &sealed[4+dek_len+12..];
        //
        // // 2. Decrypt the DEK via KMS
        // let resp = client.decrypt()
        //     .ciphertext_blob(Blob::new(encrypted_dek))
        //     .encryption_context("purpose", purpose)
        //     .send().await?;
        // let plaintext_dek = resp.plaintext().unwrap();
        //
        // // 3. Decrypt locally
        // let cipher = Aes256Gcm::new_from_slice(plaintext_dek)?;
        // let plaintext = cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: purpose.as_bytes() })?;
        //
        // // 4. Zeroize DEK
        // plaintext_dek.zeroize();
        // Ok(plaintext)
        // ```

        Err(SealError::UnsealFailed)
    }

    // -----------------------------------------------------------------------
    // TPM 2.0 backend initialization
    // -----------------------------------------------------------------------

    /// Initialize TPM 2.0 backend.
    ///
    /// Real implementation would:
    /// 1. Open TCTI context to the TPM device
    /// 2. Create ESAPI context
    /// 3. Create or load the primary storage key under the owner hierarchy
    /// 4. Find or create the master sealing key under the storage key
    fn init_tpm2(config: &HsmConfig) -> Result<Tpm2Session, HsmError> {
        let device = config.tpm2_device.as_ref().unwrap();

        eprintln!(
            "INFO: Initializing TPM 2.0 backend (device={}, pcrs={:?})",
            device, config.tpm2_pcr_indices
        );

        // TODO: Real TPM2 initialization
        // ```
        // let tcti = TctiNameConf::from_str(&format!("device:{device}"))
        //     .map_err(|e| HsmError::InitializationFailed(format!("TCTI: {e}")))?;
        // let mut context = Context::new(tcti)
        //     .map_err(|e| HsmError::InitializationFailed(format!("ESAPI: {e}")))?;
        //
        // // Create primary key under owner hierarchy (SRK)
        // let primary_pub = create_restricted_decryption_rsa_public(
        //     RsaKeyBits::Rsa2048,
        //     RsaExponent::default(),
        //     HashAlgorithm::Sha256,
        // )?;
        // let primary_handle = context.create_primary(
        //     Hierarchy::Owner,
        //     primary_pub,
        //     None, None, None,
        // )?;
        // ```

        Ok(Tpm2Session {
            _device: device.clone(),
            _pcr_indices: config.tpm2_pcr_indices.clone(),
        })
    }

    /// Seal data to TPM 2.0, bound to current PCR values.
    ///
    /// Uses TPM2_Create with a sealing key bound to a PCR policy.
    /// The sealed blob can only be unsealed if the PCR values match
    /// the values at seal time (platform integrity).
    fn tpm2_wrap(&self, plaintext: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let _state = self.state.lock().map_err(|_| SealError::SealFailed)?;

        eprintln!(
            "INFO: TPM2 seal operation (purpose={}, plaintext_len={})",
            purpose,
            plaintext.len()
        );

        // Real implementation:
        // ```
        // // Build PCR selection for the configured indices
        // let pcr_selection = PcrSelectionListBuilder::new()
        //     .with_selection(HashAlgorithm::Sha256, &self.pcr_indices)
        //     .build()?;
        //
        // // Create policy session bound to PCR values
        // let policy_session = context.start_auth_session(
        //     None, None, None,
        //     SessionType::Policy,
        //     SymmetricDefinition::AES_128_CFB,
        //     HashAlgorithm::Sha256,
        // )?;
        //
        // context.policy_pcr(policy_session, &Digest::default(), pcr_selection)?;
        // let policy_digest = context.policy_get_digest(policy_session)?;
        //
        // // Create sealed object
        // let sealed_pub = create_sealed_object_public(
        //     policy_digest,
        //     HashAlgorithm::Sha256,
        //     plaintext.len() as u16,
        // )?;
        // let (private, public) = context.create(
        //     primary_handle,
        //     sealed_pub,
        //     None,
        //     Some(SensitiveData::try_from(plaintext)?),
        //     None,
        //     None,
        // )?;
        //
        // // Serialize private + public for storage
        // let mut output = Vec::new();
        // output.extend_from_slice(&private.marshal()?);
        // output.extend_from_slice(&public.marshal()?);
        // Ok(output)
        // ```

        Err(SealError::SealFailed)
    }

    /// Unseal data from TPM 2.0, verifying PCR values match.
    fn tpm2_unwrap(&self, sealed: &[u8], purpose: &str) -> Result<Vec<u8>, SealError> {
        let _state = self.state.lock().map_err(|_| SealError::UnsealFailed)?;

        eprintln!(
            "INFO: TPM2 unseal operation (purpose={}, sealed_len={})",
            purpose,
            sealed.len()
        );

        // Real implementation:
        // ```
        // // Deserialize the sealed object
        // let (private, public) = deserialize_sealed_object(sealed)?;
        //
        // // Load the sealed object under the primary key
        // let loaded_handle = context.load(primary_handle, private, public)?;
        //
        // // Satisfy the PCR policy (will fail if PCRs have changed)
        // let policy_session = context.start_auth_session(...)?;
        // context.policy_pcr(policy_session, &Digest::default(), pcr_selection)?;
        //
        // // Unseal
        // let plaintext = context.unseal(loaded_handle)?;
        // Ok(plaintext.as_bytes().to_vec())
        // ```

        Err(SealError::UnsealFailed)
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
        let state = self.state.lock().map_err(|_| SealError::SealFailed)?;

        match &*state {
            BackendState::Pkcs11(session) => {
                if !session.authenticated {
                    return Err(SealError::InvalidMasterKey);
                }
                eprintln!(
                    "INFO: Rotating master key in PKCS#11 HSM (label={})",
                    self.config.key_label
                );
                // Real implementation:
                // 1. C_GenerateKey with new label (versioned: "MILNET-MASTER-KEK-v2")
                // 2. For each wrapped KEK: C_UnwrapKey with old key, C_WrapKey with new key
                // 3. Set old key CKA_WRAP=false, CKA_UNWRAP stays true for transition
                // 4. After all KEKs re-wrapped, destroy old key
                Err(SealError::SealFailed)
            }
            BackendState::AwsKms(_session) => {
                eprintln!("INFO: Rotating master key in AWS KMS");
                // Real implementation:
                // AWS KMS supports automatic annual rotation.
                // For manual rotation:
                // 1. Create new CMK
                // 2. Create alias pointing to new CMK
                // 3. Re-encrypt all data keys: Decrypt(old) -> Encrypt(new)
                // 4. Disable old CMK after grace period
                Err(SealError::SealFailed)
            }
            BackendState::Tpm2(_session) => {
                eprintln!("INFO: Rotating master key in TPM 2.0");
                // Real implementation:
                // 1. Create new primary key under owner hierarchy
                // 2. Unseal all objects under old key
                // 3. Re-seal under new primary key
                // 4. Flush old primary key
                Err(SealError::SealFailed)
            }
            BackendState::Software(source) => {
                eprintln!("INFO: Rotating master key (software backend)");
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
        eprintln!(
            "INFO: Sealing FROST share (len={}) to HSM",
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
        eprintln!(
            "INFO: Unsealing FROST share (sealed_len={}) from HSM",
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
    /// operation internally.
    ///
    /// For PKCS#11: `C_Sign` with `CKM_ECDSA_SHA256` or `CKM_RSA_PKCS_PSS`
    /// For AWS KMS: `kms.sign(KeyId, Message, SigningAlgorithm)`
    /// For TPM2: `TPM2_Sign`
    pub fn sign_with_hardware(
        &self,
        data: &[u8],
        _signing_key_label: &str,
    ) -> Result<Vec<u8>, HsmError> {
        let state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        match &*state {
            BackendState::Pkcs11(session) => {
                if !session.authenticated {
                    return Err(HsmError::AuthenticationFailed);
                }
                eprintln!(
                    "INFO: PKCS#11 sign operation (data_len={})",
                    data.len()
                );
                // C_Sign(session, mechanism=CKM_ECDSA_SHA256, key_handle, data)
                Err(HsmError::NotSupported(
                    "PKCS#11 signing requires hardware".into(),
                ))
            }
            BackendState::AwsKms(_) => {
                eprintln!(
                    "INFO: AWS KMS sign operation (data_len={})",
                    data.len()
                );
                // client.sign().key_id(key_id).message(data).signing_algorithm(ECDSA_SHA_256).send()
                Err(HsmError::NotSupported(
                    "AWS KMS signing requires network access".into(),
                ))
            }
            BackendState::Tpm2(_) => {
                eprintln!(
                    "INFO: TPM2 sign operation (data_len={})",
                    data.len()
                );
                // context.sign(key_handle, &digest, scheme, HashcheckTicket::null())
                Err(HsmError::NotSupported(
                    "TPM2 signing requires hardware".into(),
                ))
            }
            BackendState::Software(_) => {
                // Software signing: use ed25519-dalek or similar
                // This is the only backend that can work without hardware.
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
    /// and returned. The plaintext DEK is never exposed to software.
    ///
    /// For PKCS#11:
    ///   1. `C_GenerateKey(CKM_AES_KEY_GEN, 256-bit)` — generates in HSM
    ///   2. `C_WrapKey(CKM_AES_KEY_WRAP_KWP, master_key, dek)` — wraps in HSM
    ///   3. Return wrapped blob
    ///
    /// For AWS KMS:
    ///   1. `GenerateDataKey(key_id, AES_256)` — returns plaintext + encrypted
    ///   2. Zeroize plaintext immediately (or use GenerateDataKeyWithoutPlaintext)
    ///   3. Return encrypted DEK
    pub fn generate_wrapped_dek(&self, purpose: &str) -> Result<Vec<u8>, HsmError> {
        let state = self.state.lock().map_err(|_| {
            HsmError::CommunicationError("mutex poisoned".into())
        })?;

        eprintln!("INFO: Generating wrapped DEK (purpose={})", purpose);

        match &*state {
            BackendState::Pkcs11(_) => {
                // C_GenerateKey + C_WrapKey
                Err(HsmError::NotSupported(
                    "PKCS#11 DEK generation requires hardware".into(),
                ))
            }
            BackendState::AwsKms(_) => {
                // client.generate_data_key_without_plaintext().key_id(key_id).key_spec(AES_256)
                Err(HsmError::NotSupported(
                    "AWS KMS DEK generation requires network access".into(),
                ))
            }
            BackendState::Tpm2(_) => {
                // TPM2_Create with symmetric key under storage key
                Err(HsmError::NotSupported(
                    "TPM2 DEK generation requires hardware".into(),
                ))
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
}

// ---------------------------------------------------------------------------
// ProductionKeySource implementation for HsmKeyManager
// ---------------------------------------------------------------------------

impl ProductionKeySource for HsmKeyManager {
    fn load_master_key(&self) -> Result<MasterKey, SealError> {
        let state = self.state.lock().map_err(|_| SealError::InvalidMasterKey)?;

        match &*state {
            BackendState::Software(source) => source.load_master_key(),
            BackendState::Pkcs11(_) => {
                // The master key lives in the HSM and cannot be exported.
                // For software operations that need a MasterKey struct, we derive
                // a secondary key from the HSM using a challenge-response:
                //
                // 1. Generate random challenge (32 bytes)
                // 2. Send to HSM: C_Encrypt(master_key, challenge) -> response
                // 3. Use HKDF(response) as the local MasterKey
                //
                // This ensures the true master key never leaves the HSM,
                // while providing a deterministic local key for the hierarchy.
                eprintln!(
                    "INFO: Deriving local master key from PKCS#11 HSM (label={})",
                    self.config.key_label
                );
                // TODO: Implement challenge-response key derivation
                Err(SealError::InvalidMasterKey)
            }
            BackendState::AwsKms(_) => {
                // For AWS KMS, use GenerateDataKey to get a wrapped+plaintext DEK,
                // then use the plaintext as the local master key.
                // The "real" master is the CMK which never leaves AWS.
                eprintln!("INFO: Deriving local master key from AWS KMS");
                // TODO: Implement KMS GenerateDataKey
                Err(SealError::InvalidMasterKey)
            }
            BackendState::Tpm2(_) => {
                // For TPM2, unseal the master key blob from persistent storage.
                // The blob is sealed to PCR values at provisioning time.
                eprintln!("INFO: Unsealing master key from TPM 2.0");
                // TODO: Implement TPM2 unseal
                Err(SealError::InvalidMasterKey)
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
        let source = create_key_source(&config).unwrap();
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
}
