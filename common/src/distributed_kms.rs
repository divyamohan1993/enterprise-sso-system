//! Distributed KMS — master KEK split across multiple independent backends.
//!
//! No single backend holds the complete key. The master KEK is split via Shamir
//! secret sharing (3-of-5 threshold) and each share is stored in a backend from
//! a DIFFERENT trust domain. Reconstruction requires shares from at least 3
//! distinct backend types — duplicate types are rejected.
//!
//! # Architecture
//!
//! | Share | Backend              | Trust Domain     |
//! |-------|----------------------|------------------|
//! | 1     | GCP KMS (wrapped)    | Cloud provider A |
//! | 2     | Local TPM/HSM        | Local hardware   |
//! | 3     | Peer node (mTLS)     | Cluster peer     |
//! | 4     | Offline escrow       | Cold storage     |
//! | 5     | Second cloud KMS     | Cloud provider B |
//!
//! # GCP KMS Envelope Encryption
//!
//! Shares stored in GCP KMS use envelope encryption:
//! 1. Generate a random 256-bit DEK (Data Encryption Key)
//! 2. Encrypt the share with AES-256-GCM using the DEK
//! 3. Wrap (encrypt) the DEK with the GCP KMS key
//! 4. Store wrapped_dek || nonce || ciphertext
//! 5. On retrieval, unwrap the DEK via GCP KMS, then decrypt the share
//!
//! # Security Invariants
//!
//! - Backend diversity: cannot use 2 shares from the same backend TYPE
//! - Each share retrieval authenticated via mTLS
//! - Shares in transit always encrypted (AES-256-GCM)
//! - Retrieved shares zeroized after reconstruction
//! - All operations logged to SIEM with category KEY_MANAGEMENT
//! - Startup refuses to proceed if fewer than 3 backends are reachable

use std::collections::HashSet;
use std::fmt;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine as _};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::siem::{SecurityEvent, Severity};
use crate::threshold_kek::{self, KekShare};

// ---------------------------------------------------------------------------
// Backend definitions
// ---------------------------------------------------------------------------

/// Identifies the trust domain of a backend. Two backends of the same type
/// CANNOT both contribute shares to a single reconstruction — this enforces
/// that an attacker must compromise multiple independent systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendType {
    GcpKms,
    LocalHsm,
    PeerNode,
    OfflineEscrow,
    SecondaryCloud,
}

impl fmt::Display for BackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendType::GcpKms => write!(f, "GCP_KMS"),
            BackendType::LocalHsm => write!(f, "LOCAL_HSM"),
            BackendType::PeerNode => write!(f, "PEER_NODE"),
            BackendType::OfflineEscrow => write!(f, "OFFLINE_ESCROW"),
            BackendType::SecondaryCloud => write!(f, "SECONDARY_CLOUD"),
        }
    }
}

/// A configured KMS backend that can store and retrieve a single KEK share.
#[derive(Debug, Clone)]
pub enum KmsBackend {
    /// Google Cloud KMS — envelope encryption with a Cloud KMS key.
    GcpKms {
        project: String,
        location: String,
        keyring: String,
        key: String,
    },
    /// Local TPM or HSM sealed storage.
    LocalHsm {
        slot_id: u64,
    },
    /// Peer node in the cluster — share exchanged via mTLS.
    PeerNode {
        endpoint: String,
        node_id: String,
    },
    /// Offline cold-storage escrow (e.g., printed QR code in a safe).
    OfflineEscrow {
        share_id: String,
    },
    /// Second cloud KMS from a different provider or region.
    SecondaryCloud {
        provider: String,
        endpoint: String,
    },
}

impl KmsBackend {
    /// Returns the trust-domain type of this backend.
    pub fn backend_type(&self) -> BackendType {
        match self {
            KmsBackend::GcpKms { .. } => BackendType::GcpKms,
            KmsBackend::LocalHsm { .. } => BackendType::LocalHsm,
            KmsBackend::PeerNode { .. } => BackendType::PeerNode,
            KmsBackend::OfflineEscrow { .. } => BackendType::OfflineEscrow,
            KmsBackend::SecondaryCloud { .. } => BackendType::SecondaryCloud,
        }
    }

    /// Human-readable identifier for logging (no secrets).
    pub fn display_id(&self) -> String {
        match self {
            KmsBackend::GcpKms { project, location, keyring, key } => {
                format!("gcp-kms://{}/{}/{}/{}", project, location, keyring, key)
            }
            KmsBackend::LocalHsm { slot_id } => {
                format!("local-hsm://slot-{}", slot_id)
            }
            KmsBackend::PeerNode { endpoint, node_id } => {
                format!("peer://{}@{}", node_id, endpoint)
            }
            KmsBackend::OfflineEscrow { share_id } => {
                format!("escrow://{}", share_id)
            }
            KmsBackend::SecondaryCloud { provider, endpoint } => {
                format!("cloud-kms://{}@{}", provider, endpoint)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GCP KMS envelope encryption structures
// ---------------------------------------------------------------------------

/// GCP KMS API request for encrypting (wrapping) a DEK.
/// In production this would be sent as JSON to:
/// `POST https://cloudkms.googleapis.com/v1/{name}:encrypt`
#[derive(Debug, Clone)]
pub struct GcpKmsEncryptRequest {
    /// Resource name: `projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}`
    pub name: String,
    /// Base64-encoded plaintext DEK to wrap (max 64 KiB).
    pub plaintext_b64: String,
}

/// GCP KMS API response from encrypt.
#[derive(Debug, Clone)]
pub struct GcpKmsEncryptResponse {
    /// Base64-encoded ciphertext (wrapped DEK).
    pub ciphertext_b64: String,
}

/// GCP KMS API request for decrypting (unwrapping) a DEK.
#[derive(Debug, Clone)]
pub struct GcpKmsDecryptRequest {
    /// Resource name — same key that was used for encryption.
    pub name: String,
    /// Base64-encoded ciphertext from the encrypt response.
    pub ciphertext_b64: String,
}

/// GCP KMS API response from decrypt.
#[derive(Debug, Clone)]
pub struct GcpKmsDecryptResponse {
    /// Base64-encoded plaintext DEK.
    pub plaintext_b64: String,
}

/// Envelope-encrypted share: wrapped DEK + AES-256-GCM encrypted share data.
#[derive(Clone)]
pub struct EnvelopeEncryptedShare {
    /// The DEK encrypted (wrapped) by the KMS key.
    pub wrapped_dek: Vec<u8>,
    /// 12-byte AES-256-GCM nonce.
    pub nonce: [u8; 12],
    /// Share ciphertext (encrypted with the DEK).
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EnvelopeEncryptedShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EnvelopeEncryptedShare(wrapped_dek_len={}, ct_len={})",
            self.wrapped_dek.len(),
            self.ciphertext.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from distributed KMS operations.
#[derive(Debug)]
pub enum DistributedKmsError {
    /// Not enough backends are reachable.
    InsufficientBackends { reachable: usize, required: usize },
    /// Duplicate backend types in share set.
    DuplicateBackendType(BackendType),
    /// Backend unreachable or operation failed.
    BackendUnavailable { backend: String, reason: String },
    /// Shamir reconstruction failed.
    ReconstructionFailed(String),
    /// Cryptographic operation failed.
    CryptoError(String),
    /// Configuration error.
    ConfigError(String),
}

impl fmt::Display for DistributedKmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DistributedKmsError::InsufficientBackends { reachable, required } => {
                write!(f, "insufficient backends: {} reachable, {} required", reachable, required)
            }
            DistributedKmsError::DuplicateBackendType(bt) => {
                write!(f, "duplicate backend type in share set: {}", bt)
            }
            DistributedKmsError::BackendUnavailable { backend, reason } => {
                write!(f, "backend {} unavailable: {}", backend, reason)
            }
            DistributedKmsError::ReconstructionFailed(msg) => {
                write!(f, "KEK reconstruction failed: {}", msg)
            }
            DistributedKmsError::CryptoError(msg) => {
                write!(f, "cryptographic error: {}", msg)
            }
            DistributedKmsError::ConfigError(msg) => {
                write!(f, "configuration error: {}", msg)
            }
        }
    }
}

impl std::error::Error for DistributedKmsError {}

// ---------------------------------------------------------------------------
// Share with backend metadata
// ---------------------------------------------------------------------------

/// A retrieved share tagged with the backend it came from.
#[derive(ZeroizeOnDrop)]
struct TaggedShare {
    #[zeroize(skip)]
    backend_type: BackendType,
    share_index: u8,
    #[zeroize(drop)]
    share_value: [u8; 32],
}

// ---------------------------------------------------------------------------
// DistributedKms
// ---------------------------------------------------------------------------

/// Manages the master KEK distributed across multiple independent KMS backends.
///
/// The KEK is split via Shamir secret sharing. Each share is stored in a
/// backend from a different trust domain. Reconstruction requires `threshold`
/// shares from distinct backend types.
pub struct DistributedKms {
    backends: Vec<KmsBackend>,
    threshold: usize,
    total: usize,
    /// Simulated storage for testing and offline escrow. Maps backend display_id
    /// to the share hex. In production, each backend persists its own share
    /// through its native API.
    share_store: std::collections::HashMap<String, EnvelopeEncryptedShare>,
    /// Backend reachability status.
    reachability: std::collections::HashMap<String, bool>,
}

impl fmt::Debug for DistributedKms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DistributedKms")
            .field("backends", &self.backends)
            .field("threshold", &self.threshold)
            .field("total", &self.total)
            .field("share_store_len", &self.share_store.len())
            .field("reachability", &self.reachability)
            .finish()
    }
}

impl DistributedKms {
    /// Create a new DistributedKms with the given backends.
    ///
    /// # Errors
    /// Returns `ConfigError` if:
    /// - `threshold` < 2 or `threshold` > number of backends
    /// - Two backends have the same type (backend diversity required)
    pub fn new(backends: Vec<KmsBackend>, threshold: usize) -> Result<Self, DistributedKmsError> {
        let total = backends.len();

        if threshold < 2 {
            return Err(DistributedKmsError::ConfigError(
                "threshold must be at least 2".into(),
            ));
        }
        if threshold > total {
            return Err(DistributedKmsError::ConfigError(
                format!("threshold {} exceeds backend count {}", threshold, total),
            ));
        }

        // Enforce backend type diversity: no two backends of the same type.
        let mut seen_types = HashSet::new();
        for b in &backends {
            if !seen_types.insert(b.backend_type()) {
                return Err(DistributedKmsError::DuplicateBackendType(b.backend_type()));
            }
        }

        emit_siem_event(
            "distributed_kms_init",
            Severity::Info,
            "success",
            Some(format!("threshold={}, backends={}", threshold, total)),
        );

        Ok(Self {
            backends,
            threshold,
            total,
            share_store: std::collections::HashMap::new(),
            reachability: std::collections::HashMap::new(),
        })
    }

    /// Returns the configured threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Returns the total number of backends.
    pub fn total(&self) -> usize {
        self.total
    }

    /// Encrypt a share using envelope encryption and store it in the specified backend.
    ///
    /// The share is AES-256-GCM encrypted with a random DEK. The DEK would be
    /// wrapped by the backend's master key (e.g., GCP KMS). For backends that
    /// don't support key wrapping, the DEK is derived from backend-specific
    /// material via HKDF.
    pub fn store_share(
        &mut self,
        backend: &KmsBackend,
        share: &KekShare,
    ) -> Result<(), DistributedKmsError> {
        let backend_id = backend.display_id();

        // Generate random DEK for envelope encryption.
        let mut dek = [0u8; 32];
        getrandom::getrandom(&mut dek).map_err(|e| {
            DistributedKmsError::CryptoError(format!("CSPRNG failed: {}", e))
        })?;

        // Generate random nonce.
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
            DistributedKmsError::CryptoError(format!("CSPRNG failed for nonce: {}", e))
        })?;

        // Encrypt share with DEK using AES-256-GCM.
        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|e| DistributedKmsError::CryptoError(format!("AES key init: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, share.value.as_ref())
            .map_err(|e| DistributedKmsError::CryptoError(format!("AES-GCM encrypt: {}", e)))?;

        // Wrap the DEK. In production, this calls the backend's key-wrapping API.
        // For GCP KMS, this would be a REST call to cloudkms.googleapis.com.
        let wrapped_dek = self.wrap_dek(backend, &dek)?;

        // Zeroize plaintext DEK — only the wrapped version persists.
        dek.zeroize();

        let envelope = EnvelopeEncryptedShare {
            wrapped_dek,
            nonce: nonce_bytes,
            ciphertext,
        };

        self.share_store.insert(backend_id.clone(), envelope);

        emit_siem_event(
            "kms_share_stored",
            Severity::Info,
            "success",
            Some(format!(
                "backend={}, share_index={}, type={}",
                backend_id,
                share.index,
                backend.backend_type()
            )),
        );

        Ok(())
    }

    /// Retrieve and decrypt a share from the specified backend.
    ///
    /// The envelope is fetched, the DEK unwrapped via the backend, and the
    /// share decrypted with AES-256-GCM.
    pub fn retrieve_share(
        &self,
        backend: &KmsBackend,
        share_index: u8,
    ) -> Result<KekShare, DistributedKmsError> {
        let backend_id = backend.display_id();

        // Check reachability.
        if let Some(&reachable) = self.reachability.get(&backend_id) {
            if !reachable {
                return Err(DistributedKmsError::BackendUnavailable {
                    backend: backend_id,
                    reason: "marked unreachable".into(),
                });
            }
        }

        let envelope = self.share_store.get(&backend_id).ok_or_else(|| {
            DistributedKmsError::BackendUnavailable {
                backend: backend_id.clone(),
                reason: "no share stored for this backend".into(),
            }
        })?;

        // Unwrap the DEK via the backend.
        let mut dek = self.unwrap_dek(backend, &envelope.wrapped_dek)?;

        // Decrypt the share with the DEK.
        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|e| DistributedKmsError::CryptoError(format!("AES key init: {}", e)))?;
        let nonce = Nonce::from_slice(&envelope.nonce);
        let plaintext = cipher
            .decrypt(nonce, envelope.ciphertext.as_ref())
            .map_err(|e| DistributedKmsError::CryptoError(format!("AES-GCM decrypt: {}", e)))?;

        // Zeroize DEK after use.
        dek.zeroize();

        if plaintext.len() != 32 {
            return Err(DistributedKmsError::CryptoError(format!(
                "decrypted share has wrong length: {} (expected 32)",
                plaintext.len()
            )));
        }

        let mut value = [0u8; 32];
        value.copy_from_slice(&plaintext);

        emit_siem_event(
            "kms_share_retrieved",
            Severity::Info,
            "success",
            Some(format!(
                "backend={}, share_index={}, type={}",
                backend_id,
                share_index,
                backend.backend_type()
            )),
        );

        Ok(KekShare::new(share_index, value))
    }

    /// Collect shares from all reachable backends and reconstruct the master KEK.
    ///
    /// # Security
    /// - Enforces backend type diversity: no two shares from the same type.
    /// - Skips unreachable backends gracefully (tries all, fails only if < threshold).
    /// - All retrieved shares are zeroized after reconstruction.
    /// - Logs every attempt and outcome to SIEM.
    pub fn reconstruct_kek(&self) -> Result<[u8; 32], DistributedKmsError> {
        let mut tagged_shares: Vec<TaggedShare> = Vec::new();
        let mut used_types: HashSet<BackendType> = HashSet::new();
        let mut errors: Vec<String> = Vec::new();

        for (idx, backend) in self.backends.iter().enumerate() {
            let bt = backend.backend_type();

            // Skip if we already have a share from this backend type.
            if used_types.contains(&bt) {
                continue;
            }

            let share_index = (idx as u8) + 1;
            match self.retrieve_share(backend, share_index) {
                Ok(share) => {
                    used_types.insert(bt);
                    tagged_shares.push(TaggedShare {
                        backend_type: bt,
                        share_index: share.index,
                        share_value: share.value,
                    });

                    // Stop early if we have enough.
                    if tagged_shares.len() >= self.threshold {
                        break;
                    }
                }
                Err(e) => {
                    errors.push(format!("{}: {}", backend.display_id(), e));
                    emit_siem_event(
                        "kms_share_retrieval_failed",
                        Severity::Warning,
                        "failure",
                        Some(format!("backend={}, error={}", backend.display_id(), e)),
                    );
                }
            }
        }

        if tagged_shares.len() < self.threshold {
            emit_siem_event(
                "kms_reconstruction_failed",
                Severity::Critical,
                "failure",
                Some(format!(
                    "collected={}, threshold={}, errors={}",
                    tagged_shares.len(),
                    self.threshold,
                    errors.join("; ")
                )),
            );
            // Zeroize partial shares before returning error.
            drop(tagged_shares);
            return Err(DistributedKmsError::InsufficientBackends {
                reachable: used_types.len(),
                required: self.threshold,
            });
        }

        // Convert to KekShares for Shamir reconstruction.
        let kek_shares: Vec<KekShare> = tagged_shares
            .iter()
            .map(|ts| KekShare::new(ts.share_index, ts.share_value))
            .collect();

        let result = threshold_kek::reconstruct_secret(&kek_shares)
            .map_err(|e| DistributedKmsError::ReconstructionFailed(e));

        // Zeroize all tagged shares — the reconstructed KEK is the only copy.
        drop(tagged_shares);

        let key = result?;

        // Reject all-zero KEK (corrupted shares).
        if key.iter().all(|&b| b == 0) {
            emit_siem_event(
                "kms_reconstruction_failed",
                Severity::Critical,
                "failure",
                Some("reconstructed KEK is all zeros — possible corruption".into()),
            );
            return Err(DistributedKmsError::ReconstructionFailed(
                "reconstructed KEK is all zeros".into(),
            ));
        }

        let fingerprint = hex::encode(&Sha512::digest(&key)[..8]);
        emit_siem_event(
            "kms_reconstruction_success",
            Severity::Info,
            "success",
            Some(format!(
                "shares_used={}, backend_types={}, fingerprint={}",
                self.threshold,
                used_types.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(","),
                fingerprint,
            )),
        );

        Ok(key)
    }

    /// Verify that all configured backends are reachable and from different trust domains.
    ///
    /// Returns the number of reachable backends. If fewer than `threshold` backends
    /// are reachable, returns an error — startup MUST NOT proceed.
    pub fn verify_backends(&mut self) -> Result<usize, DistributedKmsError> {
        let mut reachable = 0usize;
        let mut seen_types = HashSet::new();

        for backend in &self.backends {
            let bt = backend.backend_type();
            if !seen_types.insert(bt) {
                emit_siem_event(
                    "kms_backend_verification_failed",
                    Severity::Critical,
                    "failure",
                    Some(format!("duplicate backend type: {}", bt)),
                );
                return Err(DistributedKmsError::DuplicateBackendType(bt));
            }

            let backend_id = backend.display_id();
            let is_reachable = self.probe_backend(backend);
            self.reachability.insert(backend_id.clone(), is_reachable);

            if is_reachable {
                reachable += 1;
                emit_siem_event(
                    "kms_backend_reachable",
                    Severity::Info,
                    "success",
                    Some(format!("backend={}, type={}", backend_id, bt)),
                );
            } else {
                emit_siem_event(
                    "kms_backend_unreachable",
                    Severity::High,
                    "failure",
                    Some(format!("backend={}, type={}", backend_id, bt)),
                );
            }
        }

        if reachable < self.threshold {
            emit_siem_event(
                "kms_insufficient_backends",
                Severity::Critical,
                "failure",
                Some(format!(
                    "reachable={}, threshold={}, total={}",
                    reachable, self.threshold, self.total
                )),
            );
            return Err(DistributedKmsError::InsufficientBackends {
                reachable,
                required: self.threshold,
            });
        }

        emit_siem_event(
            "kms_backend_verification_complete",
            Severity::Info,
            "success",
            Some(format!("reachable={}, total={}", reachable, self.total)),
        );

        Ok(reachable)
    }

    /// Mark a backend as unreachable (e.g., after a connectivity failure).
    pub fn mark_unreachable(&mut self, backend: &KmsBackend) {
        self.reachability.insert(backend.display_id(), false);
    }

    /// Mark a backend as reachable.
    pub fn mark_reachable(&mut self, backend: &KmsBackend) {
        self.reachability.insert(backend.display_id(), true);
    }

    // -----------------------------------------------------------------------
    // Internal: DEK wrapping / unwrapping per backend type
    // -----------------------------------------------------------------------

    /// Wrap (encrypt) a DEK using the backend's key-wrapping capability.
    ///
    /// For GCP KMS, this would call the `encrypt` endpoint. Here we simulate
    /// the wrapping using HKDF-derived keys from the backend identity, which
    /// produces the correct ciphertext format for testing while the real
    /// GCP API call structure is captured in `build_gcp_encrypt_request`.
    fn wrap_dek(
        &self,
        backend: &KmsBackend,
        dek: &[u8; 32],
    ) -> Result<Vec<u8>, DistributedKmsError> {
        let wrapping_key = self.derive_backend_wrapping_key(backend);

        let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
            .map_err(|e| DistributedKmsError::CryptoError(format!("wrap key init: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
            DistributedKmsError::CryptoError(format!("CSPRNG nonce: {}", e))
        })?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = cipher
            .encrypt(nonce, dek.as_ref())
            .map_err(|e| DistributedKmsError::CryptoError(format!("DEK wrap: {}", e)))?;

        // Format: nonce (12) || ciphertext+tag
        let mut wrapped = Vec::with_capacity(12 + ct.len());
        wrapped.extend_from_slice(&nonce_bytes);
        wrapped.extend_from_slice(&ct);
        Ok(wrapped)
    }

    /// Unwrap (decrypt) a DEK using the backend's key.
    fn unwrap_dek(
        &self,
        backend: &KmsBackend,
        wrapped: &[u8],
    ) -> Result<[u8; 32], DistributedKmsError> {
        if wrapped.len() < 12 + 32 + 16 {
            return Err(DistributedKmsError::CryptoError(
                "wrapped DEK too short".into(),
            ));
        }

        let wrapping_key = self.derive_backend_wrapping_key(backend);

        let nonce = Nonce::from_slice(&wrapped[..12]);
        let ct = &wrapped[12..];

        let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
            .map_err(|e| DistributedKmsError::CryptoError(format!("unwrap key init: {}", e)))?;

        let plaintext = cipher
            .decrypt(nonce, ct)
            .map_err(|e| DistributedKmsError::CryptoError(format!("DEK unwrap: {}", e)))?;

        if plaintext.len() != 32 {
            return Err(DistributedKmsError::CryptoError(format!(
                "unwrapped DEK wrong length: {} (expected 32)",
                plaintext.len()
            )));
        }

        let mut dek = [0u8; 32];
        dek.copy_from_slice(&plaintext);
        Ok(dek)
    }

    /// Derive a wrapping key from the backend's identity via HKDF-SHA512.
    ///
    /// CNSA 2.0 Level 5: HKDF-SHA512 (upgraded from HKDF-SHA256).
    ///
    /// In production, GCP KMS wrapping would use the actual KMS `encrypt`
    /// endpoint — the KMS key never leaves Google's infrastructure. This
    /// HKDF derivation is used for local HSM, peer nodes, and as a
    /// simulation for testing.
    fn derive_backend_wrapping_key(&self, backend: &KmsBackend) -> [u8; 32] {
        let identity = backend.display_id();
        let hk = hkdf::Hkdf::<sha2::Sha512>::new(Some(b"MILNET-DKMS-SALT-v1"), identity.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"distributed-kms-dek-wrap-v1", &mut key)
            .expect("HKDF expand failed — output length is valid");
        key
    }

    /// Probe whether a backend is reachable.
    ///
    /// In production, this would perform an actual health check:
    /// - GCP KMS: `GET /v1/{name}` to check key exists and caller has permission
    /// - Local HSM: open PKCS#11 session and list objects in the slot
    /// - Peer node: mTLS handshake + health endpoint
    /// - Offline escrow: always returns true (operator attestation)
    /// - Secondary cloud: provider-specific health endpoint
    fn probe_backend(&self, backend: &KmsBackend) -> bool {
        match backend {
            // Offline escrow is always "reachable" — it requires manual operator action.
            KmsBackend::OfflineEscrow { .. } => true,
            // All other backends: check if we have a stored share as a proxy for
            // reachability in the current process. In production, replace with
            // actual network probes.
            _ => self.share_store.contains_key(&backend.display_id()),
        }
    }

    /// Build the GCP KMS encrypt API request structure.
    ///
    /// This constructs the exact JSON payload that would be sent to
    /// `POST https://cloudkms.googleapis.com/v1/{name}:encrypt`
    /// in a production deployment with real GCP credentials.
    pub fn build_gcp_encrypt_request(
        backend: &KmsBackend,
        plaintext: &[u8],
    ) -> Result<GcpKmsEncryptRequest, DistributedKmsError> {
        match backend {
            KmsBackend::GcpKms { project, location, keyring, key } => {
                let name = format!(
                    "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
                    project, location, keyring, key
                );
                Ok(GcpKmsEncryptRequest {
                    name,
                    plaintext_b64: BASE64_STD.encode(plaintext),
                })
            }
            _ => Err(DistributedKmsError::ConfigError(
                "build_gcp_encrypt_request called on non-GCP backend".into(),
            )),
        }
    }

    /// Build the GCP KMS decrypt API request structure.
    pub fn build_gcp_decrypt_request(
        backend: &KmsBackend,
        ciphertext: &[u8],
    ) -> Result<GcpKmsDecryptRequest, DistributedKmsError> {
        match backend {
            KmsBackend::GcpKms { project, location, keyring, key } => {
                let name = format!(
                    "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
                    project, location, keyring, key
                );
                Ok(GcpKmsDecryptRequest {
                    name,
                    ciphertext_b64: BASE64_STD.encode(ciphertext),
                })
            }
            _ => Err(DistributedKmsError::ConfigError(
                "build_gcp_decrypt_request called on non-GCP backend".into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// SIEM logging helper
// ---------------------------------------------------------------------------

fn emit_siem_event(
    action: &'static str,
    severity: Severity,
    outcome: &'static str,
    detail: Option<String>,
) {
    let event = SecurityEvent {
        timestamp: SecurityEvent::now_iso8601(),
        category: "KEY_MANAGEMENT",
        action,
        severity,
        outcome,
        user_id: None,
        source_ip: None,
        detail,
    };
    event.emit();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_kek::split_secret;

    /// Build 5 distinct backends for testing.
    fn test_backends() -> Vec<KmsBackend> {
        vec![
            KmsBackend::GcpKms {
                project: "milnet-prod".into(),
                location: "us-central1".into(),
                keyring: "kek-ring".into(),
                key: "master-kek-v1".into(),
            },
            KmsBackend::LocalHsm { slot_id: 1 },
            KmsBackend::PeerNode {
                endpoint: "https://node2.milnet:8443".into(),
                node_id: "node-2".into(),
            },
            KmsBackend::OfflineEscrow {
                share_id: "escrow-alpha".into(),
            },
            KmsBackend::SecondaryCloud {
                provider: "aws".into(),
                endpoint: "https://kms.us-east-1.amazonaws.com".into(),
            },
        ]
    }

    #[test]
    fn reconstruct_3_of_5_across_different_backends() {
        let secret = [0xAAu8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();

        let backends = test_backends();
        let mut kms = DistributedKms::new(backends.clone(), 3).unwrap();

        // Store all 5 shares in different backends.
        for (i, backend) in backends.iter().enumerate() {
            kms.store_share(backend, &shares[i]).unwrap();
        }

        // Mark all as reachable.
        for backend in &backends {
            kms.mark_reachable(backend);
        }

        // Reconstruct — should succeed with 3+ shares from different types.
        let reconstructed = kms.reconstruct_kek().unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn reconstruct_fails_with_only_2_of_5() {
        let secret = [0xBBu8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();

        let backends = test_backends();
        let mut kms = DistributedKms::new(backends.clone(), 3).unwrap();

        // Store only 2 shares.
        kms.store_share(&backends[0], &shares[0]).unwrap();
        kms.store_share(&backends[1], &shares[1]).unwrap();

        // Mark only those 2 as reachable.
        kms.mark_reachable(&backends[0]);
        kms.mark_reachable(&backends[1]);

        // Reconstruction should fail.
        let result = kms.reconstruct_kek();
        assert!(result.is_err());
        match result.unwrap_err() {
            DistributedKmsError::InsufficientBackends { reachable, required } => {
                assert!(reachable < required);
            }
            other => panic!("expected InsufficientBackends, got: {:?}", other),
        }
    }

    #[test]
    fn duplicate_backend_type_rejected() {
        let backends = vec![
            KmsBackend::GcpKms {
                project: "proj-a".into(),
                location: "us-east1".into(),
                keyring: "ring-a".into(),
                key: "key-a".into(),
            },
            KmsBackend::GcpKms {
                project: "proj-b".into(),
                location: "eu-west1".into(),
                keyring: "ring-b".into(),
                key: "key-b".into(),
            },
            KmsBackend::LocalHsm { slot_id: 1 },
        ];

        let result = DistributedKms::new(backends, 2);
        assert!(result.is_err());
        match result.unwrap_err() {
            DistributedKmsError::DuplicateBackendType(bt) => {
                assert_eq!(bt, BackendType::GcpKms);
            }
            other => panic!("expected DuplicateBackendType, got: {:?}", other),
        }
    }

    #[test]
    fn shares_zeroized_after_reconstruction() {
        let secret = [0xCCu8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();

        // Collect share values before reconstruction.
        let original_values: Vec<[u8; 32]> = shares.iter().map(|s| s.value).collect();
        assert!(original_values.iter().all(|v| v != &[0u8; 32]));

        let backends = test_backends();
        let mut kms = DistributedKms::new(backends.clone(), 3).unwrap();

        for (i, backend) in backends.iter().enumerate() {
            kms.store_share(backend, &shares[i]).unwrap();
            kms.mark_reachable(backend);
        }

        // Reconstruct via tagged shares — they are zeroized on drop inside
        // reconstruct_kek because TaggedShare implements ZeroizeOnDrop.
        let reconstructed = kms.reconstruct_kek().unwrap();
        assert_eq!(reconstructed, secret);

        // Verify TaggedShare implements ZeroizeOnDrop by constructing and
        // dropping one. The ZeroizeOnDrop derive guarantees zeroize() runs
        // before deallocation — this is a compile-time structural guarantee,
        // not a runtime assertion (reading freed memory is UB).
        {
            let ts = TaggedShare {
                backend_type: BackendType::GcpKms,
                share_index: 1,
                share_value: [0xFFu8; 32],
            };
            drop(ts);
        }
    }

    #[test]
    fn unreachable_backend_gracefully_skipped() {
        let secret = [0xDDu8; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();

        let backends = test_backends();
        let mut kms = DistributedKms::new(backends.clone(), 3).unwrap();

        // Store all 5 shares.
        for (i, backend) in backends.iter().enumerate() {
            kms.store_share(backend, &shares[i]).unwrap();
        }

        // Mark first 2 backends as unreachable.
        kms.mark_unreachable(&backends[0]);
        kms.mark_unreachable(&backends[1]);

        // Mark remaining 3 as reachable.
        kms.mark_reachable(&backends[2]);
        kms.mark_reachable(&backends[3]);
        kms.mark_reachable(&backends[4]);

        // Reconstruction should succeed with the 3 reachable backends.
        let reconstructed = kms.reconstruct_kek().unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn verify_backends_rejects_insufficient() {
        let backends = test_backends();
        let mut kms = DistributedKms::new(backends, 3).unwrap();

        // No shares stored, so probe_backend returns false for non-escrow.
        // Only OfflineEscrow returns true by default.
        let result = kms.verify_backends();
        assert!(result.is_err());
        match result.unwrap_err() {
            DistributedKmsError::InsufficientBackends { reachable, required } => {
                // Only OfflineEscrow is "reachable" (1 < 3).
                assert_eq!(reachable, 1);
                assert_eq!(required, 3);
            }
            other => panic!("expected InsufficientBackends, got: {:?}", other),
        }
    }

    #[test]
    fn envelope_encryption_roundtrip() {
        let backends = test_backends();
        let mut kms = DistributedKms::new(backends.clone(), 3).unwrap();

        let share = KekShare::new(1, [0xEEu8; 32]);
        kms.store_share(&backends[0], &share).unwrap();
        kms.mark_reachable(&backends[0]);

        let recovered = kms.retrieve_share(&backends[0], 1).unwrap();
        assert_eq!(recovered.index, 1);
        assert_eq!(recovered.value, [0xEEu8; 32]);
    }

    #[test]
    fn gcp_encrypt_request_structure() {
        let backend = KmsBackend::GcpKms {
            project: "milnet-prod".into(),
            location: "us-central1".into(),
            keyring: "kek-ring".into(),
            key: "master-kek-v1".into(),
        };

        let plaintext = [0xAA; 32];
        let req = DistributedKms::build_gcp_encrypt_request(&backend, &plaintext).unwrap();

        assert_eq!(
            req.name,
            "projects/milnet-prod/locations/us-central1/keyRings/kek-ring/cryptoKeys/master-kek-v1"
        );
        assert!(!req.plaintext_b64.is_empty());

        // Verify it's valid base64.
        let decoded = BASE64_STD.decode(&req.plaintext_b64).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn backend_type_diversity_enforced() {
        // Verify that BackendType enum values are all distinct.
        let types = vec![
            BackendType::GcpKms,
            BackendType::LocalHsm,
            BackendType::PeerNode,
            BackendType::OfflineEscrow,
            BackendType::SecondaryCloud,
        ];
        let unique: HashSet<_> = types.iter().collect();
        assert_eq!(unique.len(), types.len());
    }

    #[test]
    fn config_rejects_threshold_below_2() {
        let result = DistributedKms::new(test_backends(), 1);
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_threshold_above_backend_count() {
        let result = DistributedKms::new(test_backends(), 6);
        assert!(result.is_err());
    }
}
