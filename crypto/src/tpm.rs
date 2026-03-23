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

/// TPM 2.0 context for key sealing and PCR operations.
///
/// In a real implementation, this wraps `tss_esapi::Context`.
/// The interface is defined here; actual TPM calls are marked with TODO.
pub struct Tpm2Context {
    /// Device path (e.g., `/dev/tpmrm0`).
    _device_path: String,
    /// Default PCR selection for sealing operations.
    default_pcr_selection: PcrSelection,
    /// Whether the context has been initialized.
    initialized: bool,
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

        // TODO: Real TPM2 context initialization
        // ```
        // let tcti = TctiNameConf::from_str(&format!("device:{device_path}"))
        //     .map_err(|e| TpmError::TctiInitFailed(format!("{e}")))?;
        // let mut context = Context::new(tcti)
        //     .map_err(|e| TpmError::ContextInitFailed(format!("{e}")))?;
        //
        // // Create the primary storage key (SRK) under the Owner hierarchy
        // // This is idempotent — the same SRK is returned for the same template.
        // let srk_template = create_restricted_decryption_rsa_public(
        //     RsaKeyBits::Rsa2048,
        //     RsaExponent::default(),
        //     HashAlgorithm::Sha256,
        // )?;
        // let srk_handle = context.create_primary(
        //     Hierarchy::Owner,
        //     srk_template,
        //     None, // auth value
        //     None, // initial data
        //     None, // outside info
        // )?;
        // ```

        Ok(Self {
            _device_path: device_path.to_string(),
            default_pcr_selection: pcr_selection,
            initialized: true,
        })
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

        // TODO: Real TPM2 seal
        // ```
        // // 1. Build PCR policy
        // let pcr_selection_list = PcrSelectionListBuilder::new()
        //     .with_selection(
        //         HashingAlgorithm::Sha256,
        //         &pcrs.indices.iter().map(|&i| PcrSlot::from(i)).collect::<Vec<_>>(),
        //     )
        //     .build()?;
        //
        // // 2. Create trial policy session to compute policy digest
        // let trial_session = context.start_auth_session(
        //     None, None, None,
        //     SessionType::Trial,
        //     SymmetricDefinition::AES_128_CFB,
        //     HashingAlgorithm::Sha256,
        // )?;
        // context.policy_pcr(trial_session, &Digest::default(), pcr_selection_list.clone())?;
        // let policy_digest = context.policy_get_digest(trial_session)?;
        // context.flush_context(trial_session.into())?;
        //
        // // 3. Create sealed object template
        // let sealed_pub = ObjectAttributes::new()
        //     .with_fixed_tpm(true)
        //     .with_fixed_parent(true)
        //     .with_no_da(true);
        // // set policy_digest, hash algorithm, etc.
        //
        // // 4. Create the sealed object under the SRK
        // let (private, public) = context.create(
        //     srk_handle,
        //     sealed_pub,
        //     None,
        //     Some(SensitiveData::try_from(data)?),
        //     None,
        //     None,
        // )?;
        //
        // // 5. Package into SealedBlob
        // let blob = SealedBlob {
        //     pcr_mask: pcrs.to_bitmask(),
        //     tpm_public: public.marshall()?,
        //     tpm_private: private.marshall()?,
        //     policy_digest: policy_digest.as_bytes().try_into()?,
        // };
        // Ok(blob.to_bytes())
        // ```

        // Placeholder: return error indicating hardware required
        Err(TpmError::SealFailed(
            "TPM2 hardware not available — use software backend for development".into(),
        ))
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

        // 1. Generate random AES-256 key
        let mut aes_key = [0u8; 32];
        getrandom::getrandom(&mut aes_key)
            .map_err(|_| TpmError::SealFailed("CSPRNG unavailable".into()))?;

        // 2. Encrypt payload with AES-256-GCM
        // (Would use the aes_key here)

        // 3. Seal the AES key to TPM PCRs
        // (Would call seal_to_pcrs recursively with the 32-byte key)

        // 4. Zeroize the plaintext AES key
        aes_key.zeroize();

        Err(TpmError::SealFailed(
            "TPM2 hardware not available — use software backend for development".into(),
        ))
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

        // TODO: Real TPM2 unseal
        // ```
        // // 1. Deserialize the TPM objects
        // let public = Public::unmarshall(&blob.tpm_public)?;
        // let private = Private::unmarshall(&blob.tpm_private)?;
        //
        // // 2. Load the sealed object under the SRK
        // let loaded_handle = context.load(srk_handle, private, public)?;
        //
        // // 3. Create real policy session (not trial)
        // let policy_session = context.start_auth_session(
        //     None, None, None,
        //     SessionType::Policy,
        //     SymmetricDefinition::AES_128_CFB,
        //     HashingAlgorithm::Sha256,
        // )?;
        //
        // // 4. Satisfy PCR policy — this reads current PCR values and checks
        // //    against the sealed policy digest. If PCRs have changed, this fails.
        // let pcr_selection_list = pcr_mask_to_selection(&blob.pcr_mask);
        // context.policy_pcr(policy_session, &Digest::default(), pcr_selection_list)?;
        //
        // // 5. Unseal — returns the plaintext data
        // context.execute_with_sessions((Some(policy_session.into()), None, None), |ctx| {
        //     ctx.unseal(loaded_handle)
        // })?;
        //
        // // 6. Flush the loaded object
        // context.flush_context(loaded_handle.into())?;
        // ```

        Err(TpmError::UnsealFailed(
            "TPM2 hardware not available — use software backend for development".into(),
        ))
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

        // TODO: Real TPM2 PCR read
        // ```
        // let (_, _, pcr_data) = context.pcr_read(&pcr_selection_list)?;
        // let mut results = Vec::new();
        // for (idx, digest) in pcrs.indices.iter().zip(pcr_data.pcr_bank(HashingAlgorithm::Sha256)?) {
        //     let mut value = [0u8; 32];
        //     value.copy_from_slice(digest.as_bytes());
        //     results.push((*idx, value));
        // }
        // Ok(results)
        // ```

        Err(TpmError::PcrReadFailed(
            "TPM2 hardware not available".into(),
        ))
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

        // TODO: Real TPM2 PCR extend
        // ```
        // let pcr_handle = PcrHandle::from(pcr_index);
        // let digest = Digest::try_from(measurement.as_slice())?;
        // let digest_values = DigestValues::new()
        //     .with_value(HashingAlgorithm::Sha256, digest);
        // context.pcr_extend(pcr_handle, digest_values)?;
        // ```

        Err(TpmError::PcrExtendFailed(
            "TPM2 hardware not available".into(),
        ))
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

        // TODO: Real implementation using trial policy session
        // ```
        // let trial_session = context.start_auth_session(
        //     None, None, None,
        //     SessionType::Trial,
        //     SymmetricDefinition::AES_128_CFB,
        //     HashingAlgorithm::Sha256,
        // )?;
        // context.policy_pcr(trial_session, &Digest::default(), pcr_selection_list)?;
        // let digest = context.policy_get_digest(trial_session)?;
        // context.flush_context(trial_session.into())?;
        // let mut result = [0u8; 32];
        // result.copy_from_slice(digest.as_bytes());
        // Ok(result)
        // ```

        Err(TpmError::PcrReadFailed(
            "TPM2 hardware not available".into(),
        ))
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
}
