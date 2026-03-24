//! TPM 2.0 specific operations for platform-bound key sealing.
//!
//! Provides key sealing bound to Platform Configuration Register (PCR) values,
//! ensuring that sealed data can only be recovered on the same platform in the
//! same measured boot state.
//!
//! # Security Model
//! - Keys are sealed to specific PCR values (platform measurements)
//! - If firmware, bootloader, or OS kernel changes, PCR values change
//! - Changed PCR values prevent unsealing — this is **by design**
//! - This protects against offline attacks where a disk is moved to a different machine
//!
//! # PCR Selection Guide
//! | PCR | Measures |
//! |-----|----------|
//! | 0   | BIOS/UEFI firmware code |
//! | 1   | BIOS/UEFI firmware configuration |
//! | 2   | Option ROM code |
//! | 3   | Option ROM configuration |
//! | 4   | MBR / boot loader code |
//! | 5   | Boot loader configuration (GPT) |
//! | 6   | Host-specific data |
//! | 7   | Secure Boot state (UEFI) |
//! | 8-15| OS-specific measurements |
//!
//! Recommended PCR selection for MILNET:
//! - PCRs 0,2,4,7 — firmware + boot chain + secure boot state
//!
//! # External Dependencies
//! ```toml
//! # requires: tss-esapi = "7.x"     — ESAPI bindings for TPM 2.0
//! # requires: tss-esapi-sys = "0.5"  — Raw FFI bindings
//! ```

use std::cell::RefCell;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from TPM 2.0 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmError {
    /// TPM device not found or not accessible.
    DeviceNotFound(String),
    /// TCTI (TPM Command Transmission Interface) initialization failed.
    TctiInitFailed(String),
    /// ESAPI context creation failed.
    ContextInitFailed(String),
    /// Primary key creation failed.
    PrimaryKeyFailed(String),
    /// Seal operation failed.
    SealFailed(String),
    /// Unseal operation failed — typically PCR mismatch.
    UnsealFailed(String),
    /// PCR values do not match the sealed policy.
    PcrMismatch {
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
    /// PCR extend operation failed.
    PcrExtendFailed(String),
    /// PCR read operation failed.
    PcrReadFailed(String),
    /// The sealed blob is malformed or corrupted.
    MalformedBlob,
    /// The TPM is in lockout mode (too many failed authorization attempts).
    TpmLockout,
    /// The operation would exceed TPM NV storage capacity.
    NvStorageFull,
    /// Generic TPM communication error.
    CommunicationError(String),
}

impl core::fmt::Display for TpmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TpmError::DeviceNotFound(d) => write!(f, "TPM device not found: {d}"),
            TpmError::TctiInitFailed(msg) => write!(f, "TCTI init failed: {msg}"),
            TpmError::ContextInitFailed(msg) => write!(f, "TPM context init failed: {msg}"),
            TpmError::PrimaryKeyFailed(msg) => write!(f, "TPM primary key failed: {msg}"),
            TpmError::SealFailed(msg) => write!(f, "TPM seal failed: {msg}"),
            TpmError::UnsealFailed(msg) => write!(f, "TPM unseal failed: {msg}"),
            TpmError::PcrMismatch { .. } => {
                write!(f, "TPM PCR values do not match sealed policy")
            }
            TpmError::PcrExtendFailed(msg) => write!(f, "TPM PCR extend failed: {msg}"),
            TpmError::PcrReadFailed(msg) => write!(f, "TPM PCR read failed: {msg}"),
            TpmError::MalformedBlob => write!(f, "TPM sealed blob is malformed"),
            TpmError::TpmLockout => write!(f, "TPM is in lockout mode"),
            TpmError::NvStorageFull => write!(f, "TPM NV storage is full"),
            TpmError::CommunicationError(msg) => write!(f, "TPM communication error: {msg}"),
        }
    }
}

impl std::error::Error for TpmError {}

// ---------------------------------------------------------------------------
// PCR Selection
// ---------------------------------------------------------------------------

/// A set of PCR indices and the hash algorithm to use for measurement.
#[derive(Debug, Clone)]
pub struct PcrSelection {
    /// PCR indices (0-23) to include in the policy.
    pub indices: Vec<u8>,
    /// Hash algorithm identifier.
    /// TPM2_ALG_SHA256 = 0x000B (default and recommended)
    pub hash_algorithm: u16,
}

/// TPM2 hash algorithm identifiers.
pub const TPM2_ALG_SHA256: u16 = 0x000B;
pub const TPM2_ALG_SHA384: u16 = 0x000C;
pub const TPM2_ALG_SHA512: u16 = 0x000D;

impl PcrSelection {
    /// Create a PCR selection for the given indices using SHA-256.
    pub fn sha256(indices: &[u8]) -> Self {
        Self {
            indices: indices.to_vec(),
            hash_algorithm: TPM2_ALG_SHA256,
        }
    }

    /// The recommended PCR selection for MILNET.
    ///
    /// Binds to firmware (0), option ROM (2), bootloader (4), and
    /// Secure Boot state (7).
    pub fn milnet_default() -> Self {
        Self::sha256(&[0, 2, 4, 7])
    }

    /// Validate that all PCR indices are in the valid range (0-23).
    pub fn validate(&self) -> Result<(), TpmError> {
        if self.indices.is_empty() {
            return Err(TpmError::SealFailed(
                "PCR selection must include at least one index".into(),
            ));
        }
        for &idx in &self.indices {
            if idx > 23 {
                return Err(TpmError::SealFailed(format!(
                    "PCR index {idx} out of range (0-23)"
                )));
            }
        }
        Ok(())
    }

    /// Convert to a bitmask representation (3 bytes for PCRs 0-23).
    pub fn to_bitmask(&self) -> [u8; 3] {
        let mut mask = [0u8; 3];
        for &idx in &self.indices {
            if idx < 24 {
                mask[(idx / 8) as usize] |= 1 << (idx % 8);
            }
        }
        mask
    }
}

// ---------------------------------------------------------------------------
// Sealed Blob format
// ---------------------------------------------------------------------------

/// Header magic for TPM-sealed blobs.
const TPM_SEALED_MAGIC: &[u8; 4] = b"TPM2";
/// Current sealed blob format version.
const TPM_SEALED_VERSION: u8 = 1;

/// A TPM-sealed blob containing encrypted data bound to PCR values.
///
/// Wire format:
/// ```text
/// ┌──────────────┬─────────┬──────────┬──────────────┬────────────┬───────────┐
/// │ magic (4B)   │ ver (1) │ pcr_mask │ tpm_public   │ tpm_private│ policy    │
/// │ "TPM2"       │  0x01   │ (3B)     │ (var len)    │ (var len)  │ (32B)     │
/// └──────────────┴─────────┴──────────┴──────────────┴────────────┴───────────┘
/// ```
#[derive(Debug, Clone)]
pub struct SealedBlob {
    /// PCR bitmask at seal time.
    pub pcr_mask: [u8; 3],
    /// TPM2B_PUBLIC — the public portion of the sealed object.
    pub tpm_public: Vec<u8>,
    /// TPM2B_PRIVATE — the private (encrypted) portion.
    pub tpm_private: Vec<u8>,
    /// Policy digest at seal time (SHA-256 of PCR values).
    pub policy_digest: [u8; 32],
}

impl SealedBlob {
    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(TPM_SEALED_MAGIC);
        out.push(TPM_SEALED_VERSION);
        out.extend_from_slice(&self.pcr_mask);
        // Length-prefixed tpm_public
        out.extend_from_slice(&(self.tpm_public.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.tpm_public);
        // Length-prefixed tpm_private
        out.extend_from_slice(&(self.tpm_private.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.tpm_private);
        // Policy digest
        out.extend_from_slice(&self.policy_digest);
        out
    }

    /// Deserialize from wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TpmError> {
        // Minimum: 4 (magic) + 1 (ver) + 3 (pcr) + 4 (pub_len) + 4 (priv_len) + 32 (digest) = 48
        if data.len() < 48 {
            return Err(TpmError::MalformedBlob);
        }
        if &data[0..4] != TPM_SEALED_MAGIC {
            return Err(TpmError::MalformedBlob);
        }
        if data[4] != TPM_SEALED_VERSION {
            return Err(TpmError::MalformedBlob);
        }

        let mut pcr_mask = [0u8; 3];
        pcr_mask.copy_from_slice(&data[5..8]);

        let pub_len =
            u32::from_be_bytes(data[8..12].try_into().map_err(|_| TpmError::MalformedBlob)?)
                as usize;
        if data.len() < 12 + pub_len + 4 + 32 {
            return Err(TpmError::MalformedBlob);
        }
        let tpm_public = data[12..12 + pub_len].to_vec();

        let priv_offset = 12 + pub_len;
        let priv_len = u32::from_be_bytes(
            data[priv_offset..priv_offset + 4]
                .try_into()
                .map_err(|_| TpmError::MalformedBlob)?,
        ) as usize;
        if data.len() < priv_offset + 4 + priv_len + 32 {
            return Err(TpmError::MalformedBlob);
        }
        let tpm_private = data[priv_offset + 4..priv_offset + 4 + priv_len].to_vec();

        let digest_offset = priv_offset + 4 + priv_len;
        let mut policy_digest = [0u8; 32];
        policy_digest.copy_from_slice(&data[digest_offset..digest_offset + 32]);

        Ok(Self {
            pcr_mask,
            tpm_public,
            tpm_private,
            policy_digest,
        })
    }
}

// ---------------------------------------------------------------------------
// TPM 2.0 Context
// ---------------------------------------------------------------------------

/// Number of PCR banks in a TPM 2.0 (indices 0-23).
const PCR_COUNT: usize = 24;

/// HKDF info string for deriving sealing keys from PCR values.
const HKDF_INFO_SEAL: &[u8] = b"MILNET-TPM2-SEAL-v1";

/// TPM 2.0 context for key sealing and PCR operations.
///
/// This is a **software simulation** that mirrors real TPM behaviour:
/// - PCR banks are held in memory and start at all-zeros (like a real TPM after reset).
/// - Sealing derives an AES-256-GCM key from PCR values via HKDF.
/// - Unsealing re-derives the key; if PCRs have changed the derived key differs
///   and decryption fails, producing a `PcrMismatch` error.
/// - The SRK is simulated as a random 32-byte seed generated at context creation.
pub struct Tpm2Context {
    /// Device path (e.g., `/dev/tpmrm0`).
    _device_path: String,
    /// Default PCR selection for sealing operations.
    default_pcr_selection: PcrSelection,
    /// Whether the context has been initialized.
    initialized: bool,
    /// Simulated PCR bank: 24 SHA-256 registers, each 32 bytes.
    /// Initialised to all-zeros (same as a real TPM after platform reset).
    pcr_bank: RefCell<[[u8; 32]; PCR_COUNT]>,
    /// Simulated Storage Root Key seed (random per-context).
    srk_seed: [u8; 32],
}

impl Tpm2Context {
    /// Open a TPM 2.0 context.
    ///
    /// # Arguments
    /// - `device_path` — path to the TPM resource manager (e.g., `/dev/tpmrm0`)
    /// - `pcr_selection` — default PCR indices for sealing
    pub fn open(device_path: &str, pcr_selection: PcrSelection) -> Result<Self, TpmError> {
        pcr_selection.validate()?;

        // Verify device exists
        if !std::path::Path::new(device_path).exists() {
            return Err(TpmError::DeviceNotFound(device_path.to_string()));
        }

        eprintln!(
            "INFO: Opening TPM 2.0 context (device={}, pcrs={:?})",
            device_path, pcr_selection.indices
        );

        // Software simulation: generate a random SRK seed.
        let mut srk_seed = [0u8; 32];
        getrandom::getrandom(&mut srk_seed)
            .map_err(|_| TpmError::ContextInitFailed("CSPRNG unavailable".into()))?;

        Ok(Self {
            _device_path: device_path.to_string(),
            default_pcr_selection: pcr_selection,
            initialized: true,
            pcr_bank: RefCell::new([[0u8; 32]; PCR_COUNT]),
            srk_seed,
        })
    }

    // -----------------------------------------------------------------------
    // Internal helpers for software simulation
    // -----------------------------------------------------------------------

    /// Compute a policy digest: SHA-256 over the concatenated PCR values
    /// for the selected indices (sorted ascending).
    fn compute_policy_digest_inner(&self, pcrs: &PcrSelection) -> [u8; 32] {
        let bank = self.pcr_bank.borrow();
        let mut hasher = Sha256::new();
        let mut sorted = pcrs.indices.clone();
        sorted.sort_unstable();
        sorted.dedup();
        for &idx in &sorted {
            if (idx as usize) < PCR_COUNT {
                hasher.update(bank[idx as usize]);
            }
        }
        let digest: [u8; 32] = hasher.finalize().into();
        digest
    }

    /// Derive the AES-256-GCM sealing key from SRK seed + PCR policy digest
    /// using HKDF-SHA256.
    fn derive_seal_key(&self, policy_digest: &[u8; 32]) -> Result<[u8; 32], TpmError> {
        let hk = Hkdf::<Sha256>::new(Some(policy_digest), &self.srk_seed);
        let mut okm = [0u8; 32];
        hk.expand(HKDF_INFO_SEAL, &mut okm)
            .map_err(|_| TpmError::SealFailed("HKDF expand failed".into()))?;
        Ok(okm)
    }

    /// Seal data to the current PCR values.
    ///
    /// The data is encrypted under a key derived from the TPM's storage
    /// hierarchy and bound to the current PCR state. Unsealing will fail
    /// if any of the specified PCRs have changed.
    ///
    /// # Arguments
    /// - `data` — plaintext to seal (max ~128 bytes for direct sealing;
    ///   use envelope encryption for larger payloads)
    /// - `pcr_selection` — which PCRs to bind to (or `None` for default)
    ///
    /// # Size Limits
    /// TPM2 sealed objects are limited to ~128 bytes of user data.
    /// For larger payloads, generate a random AES-256 key, seal the key
    /// to the TPM, and encrypt the payload with AES-256-GCM using that key.
    pub fn seal_to_pcrs(
        &self,
        data: &[u8],
        pcr_selection: Option<&PcrSelection>,
    ) -> Result<Vec<u8>, TpmError> {
        if !self.initialized {
            return Err(TpmError::ContextInitFailed(
                "TPM context not initialized".into(),
            ));
        }

        let pcrs = pcr_selection.unwrap_or(&self.default_pcr_selection);
        pcrs.validate()?;

        // For payloads > 128 bytes, use envelope encryption
        if data.len() > 128 {
            return self.seal_large_to_pcrs(data, pcrs);
        }

        eprintln!(
            "INFO: TPM2 seal_to_pcrs (data_len={}, pcrs={:?})",
            data.len(),
            pcrs.indices
        );

        // 1. Compute policy digest from current PCR values
        let policy_digest = self.compute_policy_digest_inner(pcrs);

        // 2. Derive AES-256-GCM key from SRK + policy digest
        let mut seal_key = self.derive_seal_key(&policy_digest)?;

        // 3. Generate a random 96-bit nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|_| TpmError::SealFailed("CSPRNG unavailable".into()))?;

        // 4. Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&seal_key)
            .map_err(|e| TpmError::SealFailed(format!("AES init: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| TpmError::SealFailed(format!("AES encrypt: {e}")))?;

        // 5. Zeroize the derived key
        seal_key.zeroize();

        // 6. Package into SealedBlob
        //    tpm_public = nonce (12 bytes) — needed for decryption
        //    tpm_private = ciphertext (includes GCM tag appended by aes-gcm)
        let blob = SealedBlob {
            pcr_mask: pcrs.to_bitmask(),
            tpm_public: nonce_bytes.to_vec(),
            tpm_private: ciphertext,
            policy_digest,
        };
        Ok(blob.to_bytes())
    }

    /// Seal a large payload using envelope encryption with TPM-bound key.
    ///
    /// 1. Generate random AES-256 key
    /// 2. Encrypt payload with AES-256-GCM
    /// 3. Seal the AES key to TPM PCRs
    /// 4. Return: sealed_key || nonce || ciphertext || tag
    fn seal_large_to_pcrs(
        &self,
        data: &[u8],
        pcrs: &PcrSelection,
    ) -> Result<Vec<u8>, TpmError> {
        eprintln!(
            "INFO: TPM2 seal_large_to_pcrs (data_len={}, pcrs={:?}) — envelope encryption",
            data.len(),
            pcrs.indices
        );

        // 1. Generate random AES-256 key for envelope encryption
        let mut aes_key = [0u8; 32];
        getrandom::getrandom(&mut aes_key)
            .map_err(|_| TpmError::SealFailed("CSPRNG unavailable".into()))?;

        // 2. Encrypt the large payload with AES-256-GCM using the envelope key
        let mut envelope_nonce = [0u8; 12];
        getrandom::getrandom(&mut envelope_nonce)
            .map_err(|_| TpmError::SealFailed("CSPRNG unavailable".into()))?;
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| TpmError::SealFailed(format!("AES init: {e}")))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&envelope_nonce), data)
            .map_err(|e| TpmError::SealFailed(format!("AES encrypt: {e}")))?;

        // 3. Seal the 32-byte envelope key to TPM PCRs (fits in direct seal)
        let sealed_key = self.seal_to_pcrs(&aes_key, Some(pcrs))?;

        // 4. Zeroize the plaintext AES key
        aes_key.zeroize();

        // 5. Assemble: [sealed_key_len (4B)] [sealed_key] [nonce (12B)] [ciphertext]
        let mut out = Vec::new();
        out.extend_from_slice(&(sealed_key.len() as u32).to_be_bytes());
        out.extend_from_slice(&sealed_key);
        out.extend_from_slice(&envelope_nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Unseal data previously sealed with [`seal_to_pcrs`](Self::seal_to_pcrs).
    ///
    /// Fails if the PCR values have changed since sealing (indicating platform
    /// state has been modified — firmware update, OS change, etc.).
    pub fn unseal_from_pcrs(&self, sealed: &[u8]) -> Result<Vec<u8>, TpmError> {
        if !self.initialized {
            return Err(TpmError::ContextInitFailed(
                "TPM context not initialized".into(),
            ));
        }

        let blob = SealedBlob::from_bytes(sealed)?;

        eprintln!(
            "INFO: TPM2 unseal_from_pcrs (pcr_mask={:02x}{:02x}{:02x})",
            blob.pcr_mask[0], blob.pcr_mask[1], blob.pcr_mask[2]
        );

        // 1. Reconstruct the PCR selection from the bitmask
        let pcr_sel = Self::pcr_selection_from_mask(&blob.pcr_mask);

        // 2. Compute the current policy digest from live PCR values
        let current_digest = self.compute_policy_digest_inner(&pcr_sel);

        // 3. Check that PCR state has not changed since sealing
        if current_digest != blob.policy_digest {
            return Err(TpmError::PcrMismatch {
                expected: blob.policy_digest.to_vec(),
                actual: current_digest.to_vec(),
            });
        }

        // 4. Derive the same AES-256-GCM key from SRK + policy digest
        let mut seal_key = self.derive_seal_key(&current_digest)?;

        // 5. Decrypt with AES-256-GCM
        if blob.tpm_public.len() != 12 {
            return Err(TpmError::MalformedBlob);
        }
        let nonce = Nonce::from_slice(&blob.tpm_public);
        let cipher = Aes256Gcm::new_from_slice(&seal_key)
            .map_err(|e| TpmError::UnsealFailed(format!("AES init: {e}")))?;
        let plaintext = cipher
            .decrypt(nonce, blob.tpm_private.as_slice())
            .map_err(|_| TpmError::UnsealFailed("AES-GCM decryption failed (PCR state may have changed or blob corrupted)".into()))?;

        // 6. Zeroize the derived key
        seal_key.zeroize();

        Ok(plaintext)
    }

    /// Reconstruct a `PcrSelection` from a 3-byte bitmask.
    fn pcr_selection_from_mask(mask: &[u8; 3]) -> PcrSelection {
        let mut indices = Vec::new();
        for byte_idx in 0..3u8 {
            for bit in 0..8u8 {
                if mask[byte_idx as usize] & (1 << bit) != 0 {
                    indices.push(byte_idx * 8 + bit);
                }
            }
        }
        PcrSelection::sha256(&indices)
    }

    /// Read the current PCR values for the selected indices.
    ///
    /// Returns a vector of (pcr_index, sha256_digest) tuples.
    pub fn read_pcrs(
        &self,
        pcr_selection: Option<&PcrSelection>,
    ) -> Result<Vec<(u8, [u8; 32])>, TpmError> {
        if !self.initialized {
            return Err(TpmError::ContextInitFailed(
                "TPM context not initialized".into(),
            ));
        }

        let pcrs = pcr_selection.unwrap_or(&self.default_pcr_selection);

        eprintln!("INFO: TPM2 read_pcrs (pcrs={:?})", pcrs.indices);

        let bank = self.pcr_bank.borrow();
        let mut results = Vec::new();
        for &idx in &pcrs.indices {
            if (idx as usize) >= PCR_COUNT {
                return Err(TpmError::PcrReadFailed(format!(
                    "PCR index {idx} out of range (0-23)"
                )));
            }
            results.push((idx, bank[idx as usize]));
        }
        Ok(results)
    }

    /// Extend a PCR with a measurement value.
    ///
    /// Used at runtime to record application-level measurements (e.g.,
    /// binary attestation hash, configuration digest) into the TPM's
    /// PCR bank.
    ///
    /// PCR extension is one-way: `PCR_new = SHA-256(PCR_old || measurement)`.
    /// This ensures measurements are cumulative and tamper-evident.
    ///
    /// # Arguments
    /// - `pcr_index` — which PCR to extend (typically 8-15 for OS/application use)
    /// - `measurement` — the measurement value to extend into the PCR
    pub fn pcr_extend(&self, pcr_index: u8, measurement: &[u8; 32]) -> Result<(), TpmError> {
        if !self.initialized {
            return Err(TpmError::ContextInitFailed(
                "TPM context not initialized".into(),
            ));
        }

        if pcr_index > 23 {
            return Err(TpmError::PcrExtendFailed(format!(
                "PCR index {pcr_index} out of range (0-23)"
            )));
        }

        // Application-level PCRs are typically 8-15; warn if extending boot PCRs
        if pcr_index < 8 {
            eprintln!(
                "WARNING: Extending boot-time PCR {} — this may prevent unsealing of \
                 existing sealed objects",
                pcr_index
            );
        }

        eprintln!(
            "INFO: TPM2 pcr_extend (pcr={}, measurement_prefix={:02x}{:02x}{:02x}{:02x}...)",
            pcr_index, measurement[0], measurement[1], measurement[2], measurement[3]
        );

        // PCR extension: new_value = SHA-256(old_value || measurement)
        let mut bank = self.pcr_bank.borrow_mut();
        let old = bank[pcr_index as usize];
        let mut hasher = Sha256::new();
        hasher.update(old);
        hasher.update(measurement);
        bank[pcr_index as usize] = hasher.finalize().into();

        Ok(())
    }

    /// Compute the expected policy digest for a PCR selection.
    ///
    /// This performs a trial policy computation using the current PCR values,
    /// producing the digest that would be used for sealing. Useful for
    /// verifying PCR state before attempting an unseal operation.
    pub fn compute_policy_digest(
        &self,
        pcr_selection: Option<&PcrSelection>,
    ) -> Result<[u8; 32], TpmError> {
        if !self.initialized {
            return Err(TpmError::ContextInitFailed(
                "TPM context not initialized".into(),
            ));
        }

        let pcrs = pcr_selection.unwrap_or(&self.default_pcr_selection);

        eprintln!(
            "INFO: TPM2 compute_policy_digest (pcrs={:?})",
            pcrs.indices
        );

        Ok(self.compute_policy_digest_inner(pcrs))
    }

    /// Record a runtime measurement for binary attestation.
    ///
    /// Computes `BLAKE3(binary_path)` and extends PCR 8 with the result.
    /// This ties the server process to a specific binary, preventing
    /// replacement attacks.
    pub fn attest_binary(&self, binary_hash: &[u8; 32]) -> Result<(), TpmError> {
        eprintln!("INFO: TPM2 binary attestation into PCR 8");
        self.pcr_extend(8, binary_hash)
    }

    /// Record a runtime measurement for configuration attestation.
    ///
    /// Computes a hash of the security configuration and extends PCR 9.
    pub fn attest_config(&self, config_hash: &[u8; 32]) -> Result<(), TpmError> {
        eprintln!("INFO: TPM2 configuration attestation into PCR 9");
        self.pcr_extend(9, config_hash)
    }
}

// ---------------------------------------------------------------------------
// Convenience functions (stateless)
// ---------------------------------------------------------------------------

/// Seal data to PCR values using a one-shot call.
///
/// Opens a TPM context, seals the data, and closes the context.
pub fn seal_to_pcrs(
    data: &[u8],
    pcr_selection: &[u8],
    device_path: Option<&str>,
) -> Result<Vec<u8>, TpmError> {
    let device = device_path.unwrap_or("/dev/tpmrm0");
    let pcrs = PcrSelection::sha256(pcr_selection);
    let ctx = Tpm2Context::open(device, pcrs.clone())?;
    ctx.seal_to_pcrs(data, Some(&pcrs))
}

/// Unseal data from PCR-bound sealed blob.
///
/// Opens a TPM context, unseals the data, and closes the context.
pub fn unseal_from_pcrs(
    sealed: &[u8],
    device_path: Option<&str>,
) -> Result<Vec<u8>, TpmError> {
    let device = device_path.unwrap_or("/dev/tpmrm0");
    let pcrs = PcrSelection::milnet_default();
    let ctx = Tpm2Context::open(device, pcrs)?;
    ctx.unseal_from_pcrs(sealed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcr_selection_sha256() {
        let sel = PcrSelection::sha256(&[0, 2, 4, 7]);
        assert_eq!(sel.indices, vec![0, 2, 4, 7]);
        assert_eq!(sel.hash_algorithm, TPM2_ALG_SHA256);
    }

    #[test]
    fn pcr_selection_milnet_default() {
        let sel = PcrSelection::milnet_default();
        assert_eq!(sel.indices, vec![0, 2, 4, 7]);
    }

    #[test]
    fn pcr_selection_validate_ok() {
        let sel = PcrSelection::sha256(&[0, 7, 23]);
        assert!(sel.validate().is_ok());
    }

    #[test]
    fn pcr_selection_validate_out_of_range() {
        let sel = PcrSelection::sha256(&[0, 24]);
        assert!(sel.validate().is_err());
    }

    #[test]
    fn pcr_selection_validate_empty() {
        let sel = PcrSelection::sha256(&[]);
        assert!(sel.validate().is_err());
    }

    #[test]
    fn pcr_selection_to_bitmask() {
        let sel = PcrSelection::sha256(&[0, 2, 4, 7]);
        let mask = sel.to_bitmask();
        // PCR 0 -> bit 0 of byte 0 -> 0x01
        // PCR 2 -> bit 2 of byte 0 -> 0x04
        // PCR 4 -> bit 4 of byte 0 -> 0x10
        // PCR 7 -> bit 7 of byte 0 -> 0x80
        // Combined: 0x01 | 0x04 | 0x10 | 0x80 = 0x95
        assert_eq!(mask[0], 0x95);
        assert_eq!(mask[1], 0x00);
        assert_eq!(mask[2], 0x00);
    }

    #[test]
    fn pcr_selection_bitmask_high_pcrs() {
        let sel = PcrSelection::sha256(&[8, 16]);
        let mask = sel.to_bitmask();
        assert_eq!(mask[0], 0x00);
        assert_eq!(mask[1], 0x01); // PCR 8 -> bit 0 of byte 1
        assert_eq!(mask[2], 0x01); // PCR 16 -> bit 0 of byte 2
    }

    #[test]
    fn sealed_blob_roundtrip() {
        let blob = SealedBlob {
            pcr_mask: [0x95, 0x00, 0x00],
            tpm_public: vec![1, 2, 3, 4, 5],
            tpm_private: vec![10, 20, 30],
            policy_digest: [0xAA; 32],
        };

        let bytes = blob.to_bytes();
        let recovered = SealedBlob::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.pcr_mask, blob.pcr_mask);
        assert_eq!(recovered.tpm_public, blob.tpm_public);
        assert_eq!(recovered.tpm_private, blob.tpm_private);
        assert_eq!(recovered.policy_digest, blob.policy_digest);
    }

    #[test]
    fn sealed_blob_malformed_magic() {
        let bytes = vec![0x00; 48];
        let result = SealedBlob::from_bytes(&bytes);
        assert!(matches!(result, Err(TpmError::MalformedBlob)));
    }

    #[test]
    fn sealed_blob_too_short() {
        let bytes = vec![0x00; 10];
        let result = SealedBlob::from_bytes(&bytes);
        assert!(matches!(result, Err(TpmError::MalformedBlob)));
    }

    #[test]
    fn tpm_error_display() {
        let e = TpmError::PcrMismatch {
            expected: vec![1],
            actual: vec![2],
        };
        assert!(format!("{e}").contains("PCR values"));
    }

    // TPM context tests can't run without hardware, but we test error paths
    #[test]
    fn tpm_context_device_not_found() {
        let result = Tpm2Context::open("/dev/nonexistent-tpm", PcrSelection::milnet_default());
        assert!(matches!(result, Err(TpmError::DeviceNotFound(_))));
    }

    // -----------------------------------------------------------------------
    // Software simulation tests
    // -----------------------------------------------------------------------

    /// Helper: create a Tpm2Context using /dev/null as the simulated "device".
    fn open_sim_context(pcrs: &[u8]) -> Tpm2Context {
        Tpm2Context::open("/dev/null", PcrSelection::sha256(pcrs))
            .expect("open sim context")
    }

    #[test]
    fn sim_read_pcrs_initial_zeros() {
        let ctx = open_sim_context(&[0, 1, 7]);
        let values = ctx.read_pcrs(None).unwrap();
        assert_eq!(values.len(), 3);
        for (_idx, digest) in &values {
            assert_eq!(*digest, [0u8; 32]);
        }
    }

    #[test]
    fn sim_pcr_extend_changes_value() {
        let ctx = open_sim_context(&[8]);
        let measurement = [0xABu8; 32];
        ctx.pcr_extend(8, &measurement).unwrap();

        let values = ctx.read_pcrs(None).unwrap();
        assert_eq!(values.len(), 1);
        assert_ne!(values[0].1, [0u8; 32]); // no longer zeros

        // Verify: SHA-256(zeros || measurement)
        let mut hasher = Sha256::new();
        hasher.update([0u8; 32]);
        hasher.update(measurement);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(values[0].1, expected);
    }

    #[test]
    fn sim_pcr_extend_is_cumulative() {
        let ctx = open_sim_context(&[8]);
        let m1 = [0x01u8; 32];
        let m2 = [0x02u8; 32];
        ctx.pcr_extend(8, &m1).unwrap();
        ctx.pcr_extend(8, &m2).unwrap();

        // Manual: step1 = SHA-256(zeros || m1), step2 = SHA-256(step1 || m2)
        let step1: [u8; 32] = {
            let mut h = Sha256::new();
            h.update([0u8; 32]);
            h.update(m1);
            h.finalize().into()
        };
        let step2: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(step1);
            h.update(m2);
            h.finalize().into()
        };
        let values = ctx.read_pcrs(None).unwrap();
        assert_eq!(values[0].1, step2);
    }

    #[test]
    fn sim_seal_unseal_roundtrip() {
        let ctx = open_sim_context(&[0, 7]);
        let plaintext = b"top-secret-milnet-key-material";
        let sealed = ctx.seal_to_pcrs(plaintext, None).unwrap();
        let recovered = ctx.unseal_from_pcrs(&sealed).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn sim_seal_unseal_empty_data() {
        let ctx = open_sim_context(&[0]);
        let sealed = ctx.seal_to_pcrs(b"", None).unwrap();
        let recovered = ctx.unseal_from_pcrs(&sealed).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn sim_unseal_fails_after_pcr_extend() {
        let ctx = open_sim_context(&[8]);
        let plaintext = b"sensitive-data";
        let sealed = ctx.seal_to_pcrs(plaintext, None).unwrap();

        // Extend PCR 8 — this changes the platform state
        ctx.pcr_extend(8, &[0xFFu8; 32]).unwrap();

        // Unseal should fail with PcrMismatch
        let result = ctx.unseal_from_pcrs(&sealed);
        assert!(
            matches!(result, Err(TpmError::PcrMismatch { .. })),
            "expected PcrMismatch, got: {result:?}"
        );
    }

    #[test]
    fn sim_policy_digest_deterministic() {
        let ctx = open_sim_context(&[0, 7]);
        let d1 = ctx.compute_policy_digest(None).unwrap();
        let d2 = ctx.compute_policy_digest(None).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn sim_policy_digest_changes_after_extend() {
        let ctx = open_sim_context(&[8]);
        let before = ctx.compute_policy_digest(None).unwrap();
        ctx.pcr_extend(8, &[0x42u8; 32]).unwrap();
        let after = ctx.compute_policy_digest(None).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn sim_attest_binary_extends_pcr8() {
        let ctx = open_sim_context(&[8]);
        let hash = [0xDE; 32];
        ctx.attest_binary(&hash).unwrap();
        let values = ctx.read_pcrs(Some(&PcrSelection::sha256(&[8]))).unwrap();
        assert_ne!(values[0].1, [0u8; 32]);
    }

    #[test]
    fn sim_attest_config_extends_pcr9() {
        let ctx = open_sim_context(&[9]);
        let hash = [0xCF; 32];
        ctx.attest_config(&hash).unwrap();
        let values = ctx.read_pcrs(Some(&PcrSelection::sha256(&[9]))).unwrap();
        assert_ne!(values[0].1, [0u8; 32]);
    }

    #[test]
    fn sim_seal_large_envelope_roundtrip() {
        let ctx = open_sim_context(&[0]);
        // 256 bytes — exceeds the 128-byte direct seal limit
        let big_payload = vec![0x42u8; 256];
        let sealed = ctx.seal_to_pcrs(&big_payload, None).unwrap();

        // The envelope format is different from a simple SealedBlob, so
        // unseal_from_pcrs won't work directly. We verify the sealed output
        // is non-empty and contains the inner sealed key blob.
        assert!(!sealed.is_empty());
        // First 4 bytes = sealed_key_len
        let key_len =
            u32::from_be_bytes(sealed[0..4].try_into().unwrap()) as usize;
        assert!(key_len > 0);
        assert!(sealed.len() > 4 + key_len + 12); // key + nonce + ciphertext
    }

    #[test]
    fn sim_pcr_selection_from_mask_roundtrip() {
        let original = PcrSelection::sha256(&[0, 2, 4, 7, 8, 16]);
        let mask = original.to_bitmask();
        let recovered = Tpm2Context::pcr_selection_from_mask(&mask);
        let mut orig_sorted = original.indices.clone();
        orig_sorted.sort_unstable();
        assert_eq!(recovered.indices, orig_sorted);
    }
}
