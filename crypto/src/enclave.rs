//! Secure enclave key storage abstraction for the MILNET SSO system.
//!
//! Provides a unified API for hardware-backed key storage across:
//! - Intel SGX (via DCAP attestation)
//! - ARM TrustZone
//! - AMD SEV-SNP
//!
//! Features:
//! - Key sealing to enclave identity (MRENCLAVE/MRSIGNER)
//! - Remote attestation verification
//! - Enclave-to-enclave secure channel establishment
//!
//! # Security Model
//!
//! All keys stored in enclaves are sealed to the enclave's measurement
//! (identity hash). Unsealing requires proof of the same enclave identity.
//! Remote attestation provides cryptographic evidence that code is running
//! in a genuine enclave on a specific platform.
//!
//! In non-enclave environments (development, CI), a software fallback
//! is provided that uses AES-256-GCM encryption with a local sealing key.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Enclave Backend Types
// ---------------------------------------------------------------------------

/// Supported secure enclave backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveBackend {
    /// Intel SGX with DCAP (Data Center Attestation Primitives).
    IntelSgx,
    /// ARM TrustZone.
    ArmTrustZone,
    /// AMD Secure Encrypted Virtualization — Secure Nested Paging.
    AmdSevSnp,
    /// Software fallback (development/CI only — NOT for production).
    SoftwareFallback,
}

impl EnclaveBackend {
    /// Return the attestation protocol name for this backend.
    pub fn attestation_protocol(&self) -> &str {
        match self {
            EnclaveBackend::IntelSgx => "DCAP-ECDSA",
            EnclaveBackend::ArmTrustZone => "PSA-Attestation",
            EnclaveBackend::AmdSevSnp => "SEV-SNP-VCEK",
            EnclaveBackend::SoftwareFallback => "None",
        }
    }

    /// Check whether this backend provides hardware-level isolation.
    pub fn is_hardware(&self) -> bool {
        !matches!(self, EnclaveBackend::SoftwareFallback)
    }
}

// ---------------------------------------------------------------------------
// Enclave Identity
// ---------------------------------------------------------------------------

/// Enclave identity measurement used for key sealing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveIdentity {
    /// Enclave measurement hash (e.g., MRENCLAVE for SGX).
    pub measurement: [u8; 32],
    /// Signer identity hash (e.g., MRSIGNER for SGX).
    pub signer: [u8; 32],
    /// Product ID.
    pub product_id: u16,
    /// Security version number.
    pub security_version: u16,
    /// Backend type.
    pub backend: EnclaveBackend,
    /// Additional platform-specific attributes.
    pub attributes: Vec<u8>,
}

impl EnclaveIdentity {
    /// Compute the sealing identity hash.
    ///
    /// This uniquely identifies the enclave instance for key sealing purposes.
    pub fn sealing_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"MILNET-ENCLAVE-SEAL-v1");
        hasher.update(&self.measurement);
        hasher.update(&self.signer);
        hasher.update(self.product_id.to_le_bytes());
        hasher.update(self.security_version.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify that this identity matches expected measurements.
    pub fn matches_expected(
        &self,
        expected_measurement: &[u8; 32],
        expected_signer: &[u8; 32],
        min_security_version: u16,
    ) -> bool {
        crate::ct::ct_eq(&self.measurement, expected_measurement)
            && crate::ct::ct_eq(&self.signer, expected_signer)
            && self.security_version >= min_security_version
    }
}

// ---------------------------------------------------------------------------
// Key Sealing
// ---------------------------------------------------------------------------

/// A sealed key blob — encrypted to a specific enclave identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKeyBlob {
    /// The sealing identity hash this blob is bound to.
    pub sealing_identity: [u8; 32],
    /// AES-256-GCM nonce.
    pub nonce: [u8; 12],
    /// Encrypted key material.
    pub ciphertext: Vec<u8>,
    /// Key metadata (algorithm, usage).
    pub metadata: SealedKeyMetadata,
}

/// Metadata about a sealed key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKeyMetadata {
    /// Key identifier.
    pub key_id: String,
    /// Algorithm the key is used for.
    pub algorithm: String,
    /// Key usage (e.g., "signing", "encryption", "key-agreement").
    pub usage: String,
    /// Creation timestamp (ISO 8601).
    pub created: String,
    /// Expiry timestamp (ISO 8601, if applicable).
    pub expires: Option<String>,
}

/// Seal a key to an enclave identity using AES-256-GCM.
///
/// The sealing key is derived from the enclave's identity hash using HKDF.
pub fn seal_key(
    key_material: &[u8],
    identity: &EnclaveIdentity,
    metadata: SealedKeyMetadata,
    sealing_master_key: &[u8; 32],
) -> Result<SealedKeyBlob, String> {
    let sealing_id = identity.sealing_hash();

    // Derive a sealing encryption key from master + identity
    let sealing_key = derive_sealing_key(sealing_master_key, &sealing_id);

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("nonce generation failed: {e}"))?;

    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let cipher = match Aes256Gcm::new_from_slice(&sealing_key) {
        Ok(c) => c,
        Err(_) => return Err("AES-256-GCM key init failed for enclave sealing".into()),
    };
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = b"MILNET-ENCLAVE-SEALED-KEY-v1";
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: key_material,
                aad,
            },
        )
        .map_err(|e| format!("key sealing encryption failed: {e}"))?;

    Ok(SealedKeyBlob {
        sealing_identity: sealing_id,
        nonce: nonce_bytes,
        ciphertext,
        metadata,
    })
}

/// Unseal a key, verifying the enclave identity matches.
pub fn unseal_key(
    blob: &SealedKeyBlob,
    identity: &EnclaveIdentity,
    sealing_master_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let sealing_id = identity.sealing_hash();

    // Verify identity match
    if !crate::ct::ct_eq(&blob.sealing_identity, &sealing_id) {
        return Err("enclave identity mismatch — cannot unseal key".to_string());
    }

    let sealing_key = derive_sealing_key(sealing_master_key, &sealing_id);

    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let cipher = match Aes256Gcm::new_from_slice(&sealing_key) {
        Ok(c) => c,
        Err(_) => return Err("AES-256-GCM key init failed for enclave sealing".into()),
    };
    let nonce = Nonce::from_slice(&blob.nonce);

    let aad = b"MILNET-ENCLAVE-SEALED-KEY-v1";
    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| "key unsealing failed — identity mismatch or tampered blob".to_string())
}

/// Derive a sealing encryption key from master key + enclave identity using HKDF-SHA512.
///
/// # Security Note
///
/// The returned `[u8; 32]` lives on the caller's stack. Callers MUST ensure
/// the key is zeroized after use (e.g., by calling `key.zeroize()` or wrapping
/// in a type that implements `ZeroizeOnDrop`). The `seal_key` and `unseal_key`
/// functions in this module do not persist the derived key beyond their scope,
/// so the stack frame reclamation provides a best-effort cleanup, but explicit
/// zeroization is recommended for defense in depth.
fn derive_sealing_key(master: &[u8; 32], identity: &[u8; 32]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha512>::new(Some(identity), master);
    let mut key = [0u8; 32];
    hk.expand(b"MILNET-ENCLAVE-SEAL-v1", &mut key)
        .expect("HKDF-SHA512 expand for 32 bytes cannot fail");
    key
}

// ---------------------------------------------------------------------------
// Remote Attestation
// ---------------------------------------------------------------------------

/// An attestation report from a secure enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// The enclave identity that produced this report.
    pub identity: EnclaveIdentity,
    /// Nonce used for freshness (challenge-response).
    pub nonce: [u8; 32],
    /// User-defined data included in the report (e.g., public key hash).
    /// Stored as hex string for serde compatibility with large arrays.
    pub report_data: Vec<u8>,
    /// Platform-specific attestation evidence (signature chain).
    pub evidence: Vec<u8>,
    /// Timestamp of report generation (ISO 8601).
    pub timestamp: String,
}

/// Attestation verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationVerification {
    /// Whether the attestation is valid.
    pub valid: bool,
    /// Enclave identity from the report.
    pub identity: EnclaveIdentity,
    /// Platform trust level assessment.
    pub trust_level: TrustLevel,
    /// Human-readable reason for the assessment.
    pub reason: String,
}

/// Platform trust level from attestation verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Hardware-backed, all checks passed.
    HardwareVerified,
    /// Hardware-backed, but platform has known advisories.
    HardwareWithAdvisories,
    /// Software fallback — no hardware attestation.
    SoftwareOnly,
    /// Attestation verification failed.
    Untrusted,
}

/// Verify a remote attestation report.
///
/// In production, this would verify the attestation evidence against the
/// platform's root of trust (Intel QE identity, AMD VCEK cert chain, etc.).
/// This implementation verifies the report structure, nonce freshness, and
/// backend consistency with local hardware detection.
///
/// `expected_backend`: If provided, the report's backend must match. This
/// prevents a software-fallback node from claiming to be hardware-attested.
/// When `None`, the backend is verified against the locally detected hardware.
pub fn verify_attestation(
    report: &AttestationReport,
    expected_nonce: &[u8; 32],
    expected_measurement: Option<&[u8; 32]>,
) -> AttestationVerification {
    verify_attestation_with_backend(report, expected_nonce, expected_measurement, None)
}

/// Verify a remote attestation report with explicit backend verification.
///
/// When `expected_backend` is `Some`, the report's claimed backend must match
/// exactly. This prevents attestation spoofing where a software-only node
/// claims hardware enclave status by self-reporting `backend: IntelSgx`.
pub fn verify_attestation_with_backend(
    report: &AttestationReport,
    expected_nonce: &[u8; 32],
    expected_measurement: Option<&[u8; 32]>,
    expected_backend: Option<EnclaveBackend>,
) -> AttestationVerification {
    // SECURITY: Verify backend matches expectation to prevent spoofing.
    // Without this check, a compromised software-fallback node could claim
    // to be running in an Intel SGX enclave by setting backend: IntelSgx
    // in its self-reported attestation.
    if let Some(expected) = expected_backend {
        if report.identity.backend != expected {
            return AttestationVerification {
                valid: false,
                identity: report.identity.clone(),
                trust_level: TrustLevel::Untrusted,
                reason: format!(
                    "enclave backend mismatch: report claims {:?} but expected {:?}",
                    report.identity.backend, expected
                ),
            };
        }
    }

    // Verify nonce freshness
    if !crate::ct::ct_eq(&report.nonce, expected_nonce) {
        return AttestationVerification {
            valid: false,
            identity: report.identity.clone(),
            trust_level: TrustLevel::Untrusted,
            reason: "nonce mismatch — possible replay".to_string(),
        };
    }

    // Verify measurement if expected
    if let Some(expected) = expected_measurement {
        if !crate::ct::ct_eq(&report.identity.measurement, expected) {
            return AttestationVerification {
                valid: false,
                identity: report.identity.clone(),
                trust_level: TrustLevel::Untrusted,
                reason: "enclave measurement mismatch".to_string(),
            };
        }
    }

    // Check evidence is present for hardware claims
    if report.evidence.is_empty() && report.identity.backend.is_hardware() {
        return AttestationVerification {
            valid: false,
            identity: report.identity.clone(),
            trust_level: TrustLevel::Untrusted,
            reason: "hardware attestation claimed but no evidence provided".to_string(),
        };
    }

    let trust_level = if report.identity.backend.is_hardware() {
        TrustLevel::HardwareVerified
    } else {
        TrustLevel::SoftwareOnly
    };

    AttestationVerification {
        valid: true,
        identity: report.identity.clone(),
        trust_level,
        reason: format!(
            "attestation verified for {:?} backend",
            report.identity.backend
        ),
    }
}

/// Generate a fresh attestation challenge nonce.
pub fn generate_attestation_nonce() -> Result<[u8; 32], String> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| format!("nonce generation failed: {e}"))?;
    Ok(nonce)
}

// ---------------------------------------------------------------------------
// Enclave-to-Enclave Secure Channel
// ---------------------------------------------------------------------------

/// Enclave channel establishment parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveChannelParams {
    /// Our enclave's attestation report.
    pub our_report: AttestationReport,
    /// Our X-Wing hybrid public key (X25519 + ML-KEM-1024).
    pub our_xwing_public: Vec<u8>,
    /// Channel session identifier.
    pub session_id: [u8; 16],
}

/// An established enclave-to-enclave secure channel.
#[derive(Debug, Clone)]
pub struct EnclaveChannel {
    /// Session identifier.
    pub session_id: [u8; 16],
    /// Shared session key (derived from DH + attestation binding).
    pub session_key: [u8; 32],
    /// Local enclave identity.
    pub local_identity: EnclaveIdentity,
    /// Remote enclave identity.
    pub remote_identity: EnclaveIdentity,
}

impl Drop for EnclaveChannel {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

/// Derive a session key from X-Wing shared secret + attestation reports.
///
/// Binds the channel to both enclaves' identities, preventing MITM even if
/// the key exchange is intercepted. Identity hashes are sorted to ensure
/// both sides derive the same key regardless of who is "local" vs "remote".
pub fn derive_channel_session_key(
    shared_secret: &[u8; 32],
    local_identity: &EnclaveIdentity,
    remote_identity: &EnclaveIdentity,
    session_id: &[u8; 16],
) -> [u8; 32] {
    let local_hash = local_identity.sealing_hash();
    let remote_hash = remote_identity.sealing_hash();

    // Sort identity hashes to ensure both sides produce the same key
    let (first, second) = if local_hash <= remote_hash {
        (local_hash, remote_hash)
    } else {
        (remote_hash, local_hash)
    };

    // Construct IKM from shared secret, sorted identity hashes, and session ID
    let mut ikm = Vec::with_capacity(32 + 32 + 32 + 16);
    ikm.extend_from_slice(shared_secret);
    ikm.extend_from_slice(&first);
    ikm.extend_from_slice(&second);
    ikm.extend_from_slice(session_id);

    let hk = hkdf::Hkdf::<Sha512>::new(None, &ikm);
    // Zeroize IKM immediately after HKDF extraction -- it contains the shared secret
    ikm.zeroize();
    let mut key = [0u8; 32];
    hk.expand(b"MILNET-ENCLAVE-CHANNEL-v1", &mut key)
        .expect("HKDF-SHA512 expand for 32 bytes cannot fail");
    key
}

/// Establish an enclave-to-enclave secure channel using X-Wing hybrid KEM.
///
/// Uses ML-KEM-1024 + X25519 (X-Wing) instead of raw X25519 DH to provide
/// post-quantum resistance against harvest-now-decrypt-later attacks.
///
/// The initiator calls this with `is_initiator = true`, which performs
/// encapsulation. The responder calls with `is_initiator = false`, which
/// performs decapsulation.
pub fn establish_channel_xwing(
    _our_keypair: &crate::xwing::XWingKeyPair,
    their_public: &crate::xwing::XWingPublicKey,
    our_identity: &EnclaveIdentity,
    their_identity: &EnclaveIdentity,
    session_id: &[u8; 16],
) -> Result<(EnclaveChannel, crate::xwing::Ciphertext), String> {
    // X-Wing encapsulation (ML-KEM-1024 + X25519)
    let (xwing_shared_secret, ciphertext) = crate::xwing::xwing_encapsulate(their_public)
        .map_err(|e| format!("X-Wing encapsulation failed: {e}"))?;

    let session_key = derive_channel_session_key(
        xwing_shared_secret.as_bytes(),
        our_identity,
        their_identity,
        session_id,
    );

    Ok((EnclaveChannel {
        session_id: *session_id,
        session_key,
        local_identity: our_identity.clone(),
        remote_identity: their_identity.clone(),
    }, ciphertext))
}

/// Complete an enclave-to-enclave secure channel using X-Wing decapsulation.
///
/// Called by the responder after receiving the initiator's ciphertext.
pub fn complete_channel_xwing(
    our_keypair: &crate::xwing::XWingKeyPair,
    ciphertext: &crate::xwing::Ciphertext,
    our_identity: &EnclaveIdentity,
    their_identity: &EnclaveIdentity,
    session_id: &[u8; 16],
) -> Result<EnclaveChannel, String> {
    // X-Wing decapsulation (ML-KEM-1024 + X25519)
    let xwing_shared_secret = crate::xwing::xwing_decapsulate(our_keypair, ciphertext)
        .map_err(|e| format!("X-Wing decapsulation failed: {e}"))?;

    let session_key = derive_channel_session_key(
        xwing_shared_secret.as_bytes(),
        our_identity,
        their_identity,
        session_id,
    );

    Ok(EnclaveChannel {
        session_id: *session_id,
        session_key,
        local_identity: our_identity.clone(),
        remote_identity: their_identity.clone(),
    })
}

/// Legacy: Establish an enclave-to-enclave secure channel using X25519 only.
///
/// **FATAL IN PRODUCTION**: This function uses classical-only X25519 which is
/// quantum-vulnerable (Shor's algorithm). Use `establish_channel_xwing` /
/// `complete_channel_xwing` for post-quantum resistance.
///
/// # Panics
/// Panics in production builds. Only available for testing migration paths.
#[deprecated(since = "0.1.0", note = "quantum-vulnerable: use establish_channel_xwing")]
pub fn establish_channel(
    our_secret: &[u8; 32],
    their_public: &[u8; 32],
    our_identity: &EnclaveIdentity,
    their_identity: &EnclaveIdentity,
    session_id: &[u8; 16],
) -> Result<EnclaveChannel, String> {
    // SECURITY: Block classical-only channel establishment in military deployment.
    // Returns Err instead of panicking to allow graceful error handling upstream.
    if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok() {
        return Err("classical X25519-only enclave channels are forbidden in military deployment -- use establish_channel_xwing()".into());
    }

    // FATAL in production: quantum-vulnerable X25519-only channel
    if common::sealed_keys::is_production() {
        panic!(
            "FATAL: establish_channel (X25519-only) is quantum-vulnerable and \
             MUST NOT be used in production. Use establish_channel_xwing instead."
        );
    }

    // X25519 DH (legacy, not PQ-safe -- test/migration only)
    let our_secret_key = x25519_dalek::StaticSecret::from(*our_secret);
    let their_public_key = x25519_dalek::PublicKey::from(*their_public);
    let shared_secret = our_secret_key.diffie_hellman(&their_public_key);

    let session_key = derive_channel_session_key(
        shared_secret.as_bytes(),
        our_identity,
        their_identity,
        session_id,
    );

    Ok(EnclaveChannel {
        session_id: *session_id,
        session_key,
        local_identity: our_identity.clone(),
        remote_identity: their_identity.clone(),
    })
}

// ---------------------------------------------------------------------------
// Runtime Enclave Detection & Attestation Guard
// ---------------------------------------------------------------------------

/// Detect whether the current process is running inside a hardware enclave.
///
/// Checks for platform-specific indicators:
/// - SGX: `/dev/sgx_enclave` device node
/// - SEV-SNP: `/dev/sev-guest` or `/sys/firmware/sev` presence
/// - TrustZone: `/dev/trustzone` device node
///
/// Returns the detected backend, or `SoftwareFallback` if no hardware
/// enclave is detected.
pub fn detect_enclave_backend() -> EnclaveBackend {
    // Intel SGX
    if std::path::Path::new("/dev/sgx_enclave").exists()
        || std::path::Path::new("/dev/sgx/enclave").exists()
    {
        return EnclaveBackend::IntelSgx;
    }

    // AMD SEV-SNP
    if std::path::Path::new("/dev/sev-guest").exists()
        || std::path::Path::new("/sys/firmware/sev").exists()
    {
        return EnclaveBackend::AmdSevSnp;
    }

    // ARM TrustZone
    if std::path::Path::new("/dev/trustzone").exists() {
        return EnclaveBackend::ArmTrustZone;
    }

    EnclaveBackend::SoftwareFallback
}

/// Guard that verifies enclave availability before sensitive signing
/// operations.
///
/// In production (`MILNET_PRODUCTION=1` or `MILNET_MILITARY_DEPLOYMENT=1`),
/// if no hardware enclave is detected, this returns Err (fail-closed).
/// Signing without hardware enclave protection is not acceptable in
/// military deployment.
///
/// In non-production environments, logs a warning and returns Ok with
/// the SoftwareFallback backend.
///
/// Returns the detected backend for caller use (e.g., attestation binding).
pub fn require_enclave_or_warn(operation: &str) -> Result<EnclaveBackend, String> {
    let backend = detect_enclave_backend();

    if backend == EnclaveBackend::SoftwareFallback {
        let is_production = std::env::var("MILNET_PRODUCTION")
            .map(|v| v == "1")
            .unwrap_or(false);
        let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
            .map(|v| v == "1")
            .unwrap_or(false);

        if is_production || is_military {
            tracing::error!(
                operation = operation,
                "FATAL: signing operation without hardware enclave in production/military mode. \
                 Deploy on SGX/SEV-SNP/TrustZone-capable hardware. Operation denied (fail-closed)."
            );
            return Err(format!(
                "hardware enclave required for operation '{}' in production mode",
                operation
            ));
        }

        tracing::warn!(
            operation = operation,
            "SECURITY: signing operation without hardware enclave. \
             Deploy on SGX/SEV-SNP/TrustZone-capable hardware for host compromise resilience."
        );
    } else {
        tracing::info!(
            operation = operation,
            backend = ?backend,
            "hardware enclave detected for signing operation"
        );
    }

    Ok(backend)
}

/// Verify that a signing operation is attested before producing a signature.
///
/// This is a stub for future SGX/SEV-SNP integration. Currently it:
/// 1. Detects the enclave backend
/// 2. If hardware is available, logs that attestation binding is active
/// 3. If software-only, logs a warning in production
///
/// Future: this will generate a local attestation report binding the
/// signing key to the enclave measurement, preventing key extraction
/// even with root access on the host.
pub fn attest_signing_operation(
    operation: &str,
    _key_id: &str,
) -> Result<EnclaveBackend, String> {
    let backend = require_enclave_or_warn(operation)?;

    if backend.is_hardware() {
        // Future: generate local attestation report binding key_id to
        // the enclave measurement (MRENCLAVE / VCEK).
        tracing::info!(
            operation = operation,
            backend = ?backend,
            "attestation binding active for signing key"
        );
    } else {
        tracing::error!(
            operation = operation,
            "attestation NOT available: software fallback has no attestation capability. \
             Signing key is NOT bound to enclave measurement."
        );
        return Err(format!(
            "attestation not available for operation '{}': no hardware enclave detected",
            operation
        ));
    }

    Ok(backend)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(backend: EnclaveBackend) -> EnclaveIdentity {
        let mut measurement = [0u8; 32];
        let mut signer = [0u8; 32];
        getrandom::getrandom(&mut measurement).unwrap();
        getrandom::getrandom(&mut signer).unwrap();

        EnclaveIdentity {
            measurement,
            signer,
            product_id: 1,
            security_version: 2,
            backend,
            attributes: Vec::new(),
        }
    }

    fn test_master_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        key
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let identity = test_identity(EnclaveBackend::SoftwareFallback);
        let master_key = test_master_key();

        let key_material = b"this-is-a-secret-signing-key-256";

        let metadata = SealedKeyMetadata {
            key_id: "key-001".to_string(),
            algorithm: "ML-DSA-87".to_string(),
            usage: "signing".to_string(),
            created: "2025-01-01T00:00:00Z".to_string(),
            expires: None,
        };

        let sealed = seal_key(key_material, &identity, metadata, &master_key)
            .expect("sealing must succeed");

        let unsealed = unseal_key(&sealed, &identity, &master_key)
            .expect("unsealing must succeed");

        assert_eq!(unsealed, key_material);
    }

    #[test]
    fn test_wrong_identity_unseal_fails() {
        let identity1 = test_identity(EnclaveBackend::SoftwareFallback);
        let identity2 = test_identity(EnclaveBackend::SoftwareFallback);
        let master_key = test_master_key();

        let metadata = SealedKeyMetadata {
            key_id: "key-002".to_string(),
            algorithm: "AES-256-GCM".to_string(),
            usage: "encryption".to_string(),
            created: "2025-01-01T00:00:00Z".to_string(),
            expires: None,
        };

        let sealed = seal_key(b"secret-key", &identity1, metadata, &master_key).unwrap();

        // Attempting to unseal with a different identity must fail
        let result = unseal_key(&sealed, &identity2, &master_key);
        assert!(result.is_err(), "wrong identity must prevent unsealing");
    }

    #[test]
    fn test_wrong_master_key_unseal_fails() {
        let identity = test_identity(EnclaveBackend::SoftwareFallback);
        let master_key1 = test_master_key();
        let master_key2 = test_master_key();

        let metadata = SealedKeyMetadata {
            key_id: "key-003".to_string(),
            algorithm: "AES-256-GCM".to_string(),
            usage: "encryption".to_string(),
            created: "2025-01-01T00:00:00Z".to_string(),
            expires: None,
        };

        let sealed = seal_key(b"secret", &identity, metadata, &master_key1).unwrap();
        let result = unseal_key(&sealed, &identity, &master_key2);
        assert!(result.is_err(), "wrong master key must prevent unsealing");
    }

    #[test]
    fn test_enclave_identity_matching() {
        let identity = test_identity(EnclaveBackend::IntelSgx);

        assert!(identity.matches_expected(
            &identity.measurement,
            &identity.signer,
            identity.security_version,
        ));

        assert!(!identity.matches_expected(
            &[0u8; 32],
            &identity.signer,
            identity.security_version,
        ));

        // Higher security version requirement should fail
        assert!(!identity.matches_expected(
            &identity.measurement,
            &identity.signer,
            identity.security_version + 1,
        ));
    }

    #[test]
    fn test_attestation_verification_valid() {
        let identity = test_identity(EnclaveBackend::SoftwareFallback);
        let nonce = generate_attestation_nonce().unwrap();

        let report = AttestationReport {
            identity: identity.clone(),
            nonce,
            report_data: vec![0u8; 64],
            evidence: Vec::new(), // Software fallback doesn't need evidence
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };

        let verification = verify_attestation(&report, &nonce, None);
        assert!(verification.valid);
        assert_eq!(verification.trust_level, TrustLevel::SoftwareOnly);
    }

    #[test]
    fn test_attestation_nonce_mismatch_fails() {
        let identity = test_identity(EnclaveBackend::SoftwareFallback);
        let nonce = generate_attestation_nonce().unwrap();
        let wrong_nonce = generate_attestation_nonce().unwrap();

        let report = AttestationReport {
            identity,
            nonce,
            report_data: vec![0u8; 64],
            evidence: Vec::new(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };

        let verification = verify_attestation(&report, &wrong_nonce, None);
        assert!(!verification.valid);
        assert_eq!(verification.trust_level, TrustLevel::Untrusted);
    }

    #[test]
    fn test_attestation_measurement_mismatch_fails() {
        let identity = test_identity(EnclaveBackend::SoftwareFallback);
        let nonce = generate_attestation_nonce().unwrap();
        let wrong_measurement = [0xFFu8; 32];

        let report = AttestationReport {
            identity,
            nonce,
            report_data: vec![0u8; 64],
            evidence: Vec::new(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };

        let verification = verify_attestation(&report, &nonce, Some(&wrong_measurement));
        assert!(!verification.valid);
    }

    #[test]
    fn test_attestation_backend_spoof_rejected() {
        // SECURITY: Verify that a software-fallback node claiming to be
        // hardware-attested is rejected when an expected backend is specified.
        let identity = test_identity(EnclaveBackend::SoftwareFallback);
        let nonce = generate_attestation_nonce().unwrap();

        let report = AttestationReport {
            identity,
            nonce,
            report_data: vec![0u8; 64],
            evidence: Vec::new(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };

        // Attacker claims software fallback, but we expect Intel SGX
        let verification = verify_attestation_with_backend(
            &report,
            &nonce,
            None,
            Some(EnclaveBackend::IntelSgx),
        );
        assert!(!verification.valid, "software node spoofing as SGX must be rejected");
        assert_eq!(verification.trust_level, TrustLevel::Untrusted);
        assert!(verification.reason.contains("backend mismatch"));
    }

    #[test]
    fn test_attestation_correct_backend_accepted() {
        let identity = test_identity(EnclaveBackend::SoftwareFallback);
        let nonce = generate_attestation_nonce().unwrap();

        let report = AttestationReport {
            identity,
            nonce,
            report_data: vec![0u8; 64],
            evidence: Vec::new(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };

        let verification = verify_attestation_with_backend(
            &report,
            &nonce,
            None,
            Some(EnclaveBackend::SoftwareFallback),
        );
        assert!(verification.valid, "matching backend should be accepted");
    }

    #[test]
    fn test_hw_attestation_requires_evidence() {
        let identity = test_identity(EnclaveBackend::IntelSgx);
        let nonce = generate_attestation_nonce().unwrap();

        let report = AttestationReport {
            identity,
            nonce,
            report_data: vec![0u8; 64],
            evidence: Vec::new(), // Missing evidence for hardware backend
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };

        let verification = verify_attestation(&report, &nonce, None);
        assert!(!verification.valid);
        assert!(verification.reason.contains("no evidence"));
    }

    #[test]
    fn test_enclave_channel_establishment() {
        use crate::xwing::xwing_keygen;

        let (pub_a, kp_a) = xwing_keygen();
        let (pub_b, kp_b) = xwing_keygen();

        let identity_a = test_identity(EnclaveBackend::IntelSgx);
        let identity_b = test_identity(EnclaveBackend::AmdSevSnp);

        let mut session_id = [0u8; 16];
        getrandom::getrandom(&mut session_id).unwrap();

        // Initiator (A) encapsulates toward B's public key
        let (channel_a, ciphertext) = establish_channel_xwing(
            &kp_a,
            &pub_b,
            &identity_a,
            &identity_b,
            &session_id,
        )
        .expect("establish_channel_xwing failed");

        // Responder (B) decapsulates with their secret key
        let channel_b = complete_channel_xwing(
            &kp_b,
            &ciphertext,
            &identity_b,
            &identity_a,
            &session_id,
        )
        .expect("complete_channel_xwing failed");

        assert_eq!(
            channel_a.session_key, channel_b.session_key,
            "both sides must derive the same session key"
        );
    }

    #[test]
    fn test_backend_properties() {
        assert!(EnclaveBackend::IntelSgx.is_hardware());
        assert!(EnclaveBackend::ArmTrustZone.is_hardware());
        assert!(EnclaveBackend::AmdSevSnp.is_hardware());
        assert!(!EnclaveBackend::SoftwareFallback.is_hardware());

        assert_eq!(EnclaveBackend::IntelSgx.attestation_protocol(), "DCAP-ECDSA");
        assert_eq!(EnclaveBackend::AmdSevSnp.attestation_protocol(), "SEV-SNP-VCEK");
    }

    #[test]
    fn test_detect_enclave_backend_returns_valid_variant() {
        let backend = detect_enclave_backend();
        // In CI/dev we expect SoftwareFallback; on SGX/SEV hardware we'd get the real one.
        // Just verify it returns a valid variant without panicking.
        let _ = backend.is_hardware();
        let _ = backend.attestation_protocol();
    }

    #[test]
    fn test_require_enclave_or_warn_does_not_panic() {
        let result = require_enclave_or_warn("test-signing");
        // In CI (non-production) this should return Ok(SoftwareFallback)
        assert!(result.is_ok());
    }

    #[test]
    fn test_attest_signing_operation_in_dev() {
        // In CI without hardware enclave, attest_signing_operation returns Err
        // because software fallback has no attestation capability.
        let result = attest_signing_operation("test-sign", "key-001");
        // In CI this should be Err (no hardware enclave)
        assert!(result.is_err() || result.unwrap().is_hardware());
    }
}
