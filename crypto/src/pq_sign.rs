//! Post-quantum digital signatures using ML-DSA-87 (FIPS 204)
//!
//! Nested signing: PQ signature covers (payload || FROST_signature),
//! providing post-quantum security on top of classical FROST.
//!
//! # Crypto Agility (CNSA 2.0 Level 5 / FIPS 140-3)
//!
//! This module supports runtime-selectable signature algorithms to enable
//! algorithm migration without code changes:
//!
//! - **ML-DSA-87** (FIPS 204, Level 5): Default, CNSA 2.0 Level 5 mandated.
//! - **SLH-DSA-SHA2-256f** (FIPS 205): Hash-based, conservative fallback.
//!   Security rests solely on hash function security (zero lattice assumptions).
//!
//! **ML-DSA-65 is REJECTED** — it is NIST Level 3 only, which does not meet
//! CNSA 2.0 Level 5 requirements. Setting MILNET_PQ_SIGNATURE_ALG=ML-DSA-65
//! will cause a FATAL error and refuse startup.
//!
//! The active algorithm is selected via the `MILNET_PQ_SIGNATURE_ALG`
//! environment variable. Signatures are self-describing: each encoded
//! signature begins with a 1-byte algorithm tag so the verifier can
//! dispatch to the correct algorithm without out-of-band negotiation.

use common::error::MilnetError;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa87, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Type aliases for ML-DSA-87 key types.
pub type PqSigningKey = SigningKey<MlDsa87>;
pub type PqVerifyingKey = VerifyingKey<MlDsa87>;
pub type PqSignature = ml_dsa::Signature<MlDsa87>;

/// Encoded verifying key size for serialization.
pub type PqEncodedVerifyingKey = EncodedVerifyingKey<MlDsa87>;
pub type PqEncodedSignature = EncodedSignature<MlDsa87>;

/// Generate an ML-DSA-87 keypair from a random seed.
///
/// Uses `getrandom` (via the workspace crate) to obtain 32 bytes of entropy,
/// then derives the keypair deterministically via `from_seed`.
pub fn generate_pq_keypair() -> (PqSigningKey, PqVerifyingKey) {
    match generate_pq_keypair_checked() {
        Ok(kp) => kp,
        Err(_) => {
            // CSPRNG failure is unrecoverable — all crypto operations are unsafe.
            // The SIEM event has already been emitted by the checked variant.
            // Abort rather than continue with a system that cannot generate keys.
            std::process::abort();
        }
    }
}

/// Generate an ML-DSA-87 keypair with proper error handling and SIEM reporting.
///
/// Returns `Err` if the OS CSPRNG is unavailable. Prefer this over
/// `generate_pq_keypair()` in code paths that can propagate errors.
pub fn generate_pq_keypair_checked() -> Result<(PqSigningKey, PqVerifyingKey), String> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "OS CSPRNG unavailable — cannot generate PQ keypair",
            &format!("{e}"),
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        format!("OS CSPRNG failure: {e}")
    })?;
    let kp = MlDsa87::from_seed(&seed.into());
    // Zeroize the seed on the stack
    seed.zeroize();
    Ok((kp.signing_key().clone(), kp.verifying_key().clone()))
}

/// FIPS 204 context string for receipt signing (nested FROST + PQ).
const CTX_RECEIPT_SIGN: &[u8] = b"MILNET-RECEIPT-SIGN-v1";
/// FIPS 204 context string for raw/audit data signing (standalone PQ).
const CTX_RAW_SIGN: &[u8] = b"MILNET-RAW-SIGN-v1";

/// Sign with ML-DSA-87: signs `(message || frost_signature)`.
///
/// This nested construction ensures the PQ signature commits to both the
/// application payload and the classical FROST signature, preventing
/// stripping attacks.
///
/// Uses FIPS 204 context string `MILNET-RECEIPT-SIGN-v1` for domain separation.
pub fn pq_sign(signing_key: &PqSigningKey, message: &[u8], frost_sig: &[u8; 64]) -> Vec<u8> {
    let mut data = Vec::with_capacity(message.len() + 64);
    data.extend_from_slice(message);
    data.extend_from_slice(frost_sig);
    let sig: PqSignature = signing_key
        .sign_deterministic(&data, CTX_RECEIPT_SIGN)
        .expect("context string within 255-byte FIPS 204 limit");
    sig.encode().to_vec()
}

/// Verify ML-DSA-87 signature over `(message || frost_signature)`.
///
/// Uses FIPS 204 context string `MILNET-RECEIPT-SIGN-v1` for domain separation.
/// Returns `true` if the PQ signature is valid.
pub fn pq_verify(
    verifying_key: &PqVerifyingKey,
    message: &[u8],
    frost_sig: &[u8; 64],
    pq_sig: &[u8],
) -> bool {
    let sig = match PqSignature::try_from(pq_sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut data = Vec::with_capacity(message.len() + 64);
    data.extend_from_slice(message);
    data.extend_from_slice(frost_sig);
    verifying_key.verify_with_context(&data, CTX_RECEIPT_SIGN, &sig)
}

/// Sign raw bytes with ML-DSA-87 (no FROST nesting).
///
/// Used for audit entry signing, signed tree heads, and witness checkpoints
/// where a standalone post-quantum signature is needed.
///
/// Uses FIPS 204 context string `MILNET-RAW-SIGN-v1` for domain separation.
pub fn pq_sign_raw(signing_key: &PqSigningKey, data: &[u8]) -> Vec<u8> {
    let sig: PqSignature = signing_key
        .sign_deterministic(data, CTX_RAW_SIGN)
        .expect("context string within 255-byte FIPS 204 limit");
    sig.encode().to_vec()
}

/// Verify a raw ML-DSA-87 signature over `data`.
///
/// Uses FIPS 204 context string `MILNET-RAW-SIGN-v1` for domain separation.
/// Returns `true` if the signature is valid.
pub fn pq_verify_raw(verifying_key: &PqVerifyingKey, data: &[u8], sig_bytes: &[u8]) -> bool {
    let sig = match PqSignature::try_from(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify_with_context(data, CTX_RAW_SIGN, &sig)
}

// ── Crypto Agility: Runtime-Selectable Signature Algorithms ────────────────
//
// CNSA 2.0 and FIPS 140-3 require crypto agility — the ability to migrate
// to new algorithms without code changes. This section provides:
//
// 1. An enum of supported post-quantum signature algorithms.
// 2. A self-describing tagged signature format (1-byte tag + signature bytes).
// 3. Runtime algorithm selection via environment variable.
// 4. Tagged sign/verify functions that dispatch based on the tag byte.

/// Algorithm tag bytes for the self-describing signature format.
///
/// Each tagged signature is encoded as: `TAG(1 byte) || raw_signature_bytes`
/// This enables the verifier to determine the algorithm without out-of-band
/// negotiation or protocol-level algorithm indicators.
const ALGO_TAG_ML_DSA_87: u8 = 0x01;
const ALGO_TAG_ML_DSA_65: u8 = 0x02;
const ALGO_TAG_SLH_DSA_SHA2_256F: u8 = 0x03;

/// Supported post-quantum signature algorithms (CNSA 2.0 Level 5 only).
///
/// Ordered by security level (highest first). The default is ML-DSA-87
/// (FIPS 204, NIST Level 5) as mandated by CNSA 2.0 for classified systems.
///
/// **ML-DSA-65 is NOT included** — it provides only NIST Level 3 security,
/// which does not meet CNSA 2.0 Level 5 requirements. The tag byte 0x02 is
/// reserved so that signatures created by legacy systems can be identified
/// and rejected with a clear error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqSignatureAlgorithm {
    /// ML-DSA-87 (FIPS 204, Level 5) — default, CNSA 2.0 Level 5 mandated.
    /// Largest keys/signatures but highest security margin.
    MlDsa87,
    /// SLH-DSA-SHA2-256f (FIPS 205) — hash-based, conservative fallback.
    /// Security rests solely on hash function security (no lattice assumptions).
    /// Large signatures (~49KB) but maximum cryptographic diversity.
    /// Acceptable for CNSA 2.0 Level 5 (hash-based, zero math assumptions).
    SlhDsaSha2256f,
}

impl Default for PqSignatureAlgorithm {
    fn default() -> Self {
        Self::MlDsa87
    }
}

impl PqSignatureAlgorithm {
    /// Return the 1-byte algorithm tag for self-describing signatures.
    pub fn tag(self) -> u8 {
        match self {
            Self::MlDsa87 => ALGO_TAG_ML_DSA_87,
            Self::SlhDsaSha2256f => ALGO_TAG_SLH_DSA_SHA2_256F,
        }
    }

    /// Decode an algorithm from a 1-byte tag.
    ///
    /// Returns `None` for unknown tags AND for the legacy ML-DSA-65 tag (0x02),
    /// which is rejected under CNSA 2.0 Level 5 policy.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            ALGO_TAG_ML_DSA_87 => Some(Self::MlDsa87),
            ALGO_TAG_ML_DSA_65 => {
                tracing::error!(
                    "SIEM:FATAL ML-DSA-65 signature tag (0x02) rejected — \
                     CNSA 2.0 Level 5 requires ML-DSA-87 minimum"
                );
                None
            }
            ALGO_TAG_SLH_DSA_SHA2_256F => Some(Self::SlhDsaSha2256f),
            _ => None,
        }
    }

    /// Human-readable name for logging and diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsaSha2256f => "SLH-DSA-SHA2-256f",
        }
    }
}

/// Select the active post-quantum signature algorithm based on environment
/// configuration.
///
/// Reads the `MILNET_PQ_SIGNATURE_ALG` environment variable:
/// - `"SLH-DSA-SHA2-256f"` -> `PqSignatureAlgorithm::SlhDsaSha2256f`
/// - `"ML-DSA-65"` -> **FATAL: rejected** (Level 3 only, does not meet CNSA 2.0 Level 5)
/// - Anything else (or unset) -> `PqSignatureAlgorithm::MlDsa87` (default, Level 5)
///
/// This enables algorithm migration by changing a single environment variable
/// across all deployed services, without recompilation.
pub fn active_pq_signature_algorithm() -> PqSignatureAlgorithm {
    match std::env::var("MILNET_PQ_SIGNATURE_ALG").as_deref() {
        Ok("ML-DSA-65") => {
            tracing::error!(
                "SIEM:FATAL MILNET_PQ_SIGNATURE_ALG=ML-DSA-65 is REJECTED — \
                 ML-DSA-65 provides only NIST Level 3, which does not meet \
                 CNSA 2.0 Level 5 requirements. Use ML-DSA-87 or SLH-DSA-SHA2-256f."
            );
            std::process::exit(1);
        }
        Ok("SLH-DSA-SHA2-256f") => PqSignatureAlgorithm::SlhDsaSha2256f,
        _ => PqSignatureAlgorithm::MlDsa87, // Default: CNSA 2.0 Level 5
    }
}

/// Sign raw data with a self-describing tagged format using the active algorithm.
///
/// Output format: `ALGO_TAG(1 byte) || signature_bytes`
///
/// Currently, all algorithms use the ML-DSA-87 signing key because ML-DSA-65
/// and SLH-DSA use different key types. In a full deployment, the key store
/// would hold keys for each algorithm. This function serves as the dispatch
/// point for the tagged format.
///
/// SECURITY: The tag byte is included OUTSIDE the signature to enable
/// algorithm identification before verification. The signature itself
/// covers only the data (not the tag), preventing tag-stripping from
/// producing a valid signature under a different algorithm.
pub fn pq_sign_tagged(signing_key: &PqSigningKey, data: &[u8]) -> Result<Vec<u8>, MilnetError> {
    let algo = active_pq_signature_algorithm();
    let raw_sig = match algo {
        PqSignatureAlgorithm::MlDsa87 => {
            // Direct ML-DSA-87 signing (CNSA 2.0 Level 5) with FIPS 204 context.
            let sig: PqSignature = signing_key
                .sign_deterministic(data, CTX_RAW_SIGN)
                .map_err(|_| MilnetError::CryptoVerification(
                    "ML-DSA-87 deterministic signing failed".to_string(),
                ))?;
            sig.encode().to_vec()
        }
        PqSignatureAlgorithm::SlhDsaSha2256f => {
            return Err(MilnetError::CryptoVerification(
                "SLH-DSA-SHA2-256f requires a persistent key store. \
                 Cannot sign with ephemeral keys - signatures would be unverifiable. \
                 Use ML-DSA-87 or provide a persistent SLH-DSA signing key."
                    .to_string(),
            ));
        }
    };

    let mut tagged = Vec::with_capacity(1 + raw_sig.len());
    tagged.push(algo.tag());
    tagged.extend_from_slice(&raw_sig);
    Ok(tagged)
}

/// Verify a self-describing tagged signature.
///
/// Reads the 1-byte algorithm tag to determine which verification algorithm
/// to use, then dispatches accordingly.
///
/// Input format: `ALGO_TAG(1 byte) || signature_bytes`
///
/// Returns `true` if the signature is valid for the indicated algorithm.
pub fn pq_verify_tagged(verifying_key: &PqVerifyingKey, data: &[u8], tagged_sig: &[u8]) -> bool {
    if tagged_sig.is_empty() {
        return false;
    }

    let tag = tagged_sig[0];
    let sig_bytes = &tagged_sig[1..];

    let algo = match PqSignatureAlgorithm::from_tag(tag) {
        Some(a) => a,
        None => {
            tracing::warn!("Unknown signature algorithm tag: 0x{:02x}", tag);
            return false;
        }
    };

    match algo {
        PqSignatureAlgorithm::MlDsa87 => {
            // Verify with ML-DSA-87 (CNSA 2.0 Level 5)
            pq_verify_raw(verifying_key, data, sig_bytes)
        }
        PqSignatureAlgorithm::SlhDsaSha2256f => {
            // SLH-DSA uses a different key type. An ML-DSA-87 verifying key
            // cannot verify SLH-DSA signatures. Callers must use
            // pq_verify_tagged_with_slh_pk() with the correct SLH-DSA public key.
            tracing::warn!(
                "SLH-DSA-SHA2-256f verification requires SLH-DSA public key; \
                 ML-DSA-87 verifying key cannot verify SLH-DSA signatures. \
                 Use pq_verify_tagged_with_slh_pk() with the correct SLH-DSA public key."
            );
            false
        }
    }
}

/// Sign raw data with a self-describing tagged format using a persistent SLH-DSA signing key.
///
/// Output format: `ALGO_TAG_SLH_DSA_SHA2_256F(1 byte) || signature_bytes`
///
/// Use this instead of `pq_sign_tagged` when SLH-DSA is the active algorithm.
/// This accepts an existing SLH-DSA signing key from the key store, avoiding the
/// ephemeral key problem in `pq_sign_tagged`.
pub fn pq_sign_tagged_with_slh_key(
    slh_signing_key: &crate::slh_dsa::SlhDsaSigningKey,
    data: &[u8],
) -> Vec<u8> {
    let slh_sig = crate::slh_dsa::slh_dsa_sign(slh_signing_key, data);
    let sig_bytes = slh_sig.as_bytes();
    let mut tagged = Vec::with_capacity(1 + sig_bytes.len());
    tagged.push(ALGO_TAG_SLH_DSA_SHA2_256F);
    tagged.extend_from_slice(sig_bytes);
    tagged
}

/// Verify a self-describing tagged SLH-DSA signature using an SLH-DSA public key.
///
/// Input format: `ALGO_TAG(1 byte) || signature_bytes`
///
/// Returns `true` if the tag is `ALGO_TAG_SLH_DSA_SHA2_256F` and the signature
/// verifies against the provided SLH-DSA public key. Returns `false` for any
/// other algorithm tag (use `pq_verify_tagged` for ML-DSA-87 signatures).
pub fn pq_verify_tagged_with_slh_pk(
    slh_verifying_key: &crate::slh_dsa::SlhDsaVerifyingKey,
    data: &[u8],
    tagged_sig: &[u8],
) -> bool {
    if tagged_sig.is_empty() {
        return false;
    }

    let tag = tagged_sig[0];
    let sig_bytes = &tagged_sig[1..];

    if tag != ALGO_TAG_SLH_DSA_SHA2_256F {
        tracing::warn!(
            "pq_verify_tagged_with_slh_pk called with non-SLH-DSA tag: 0x{:02x}",
            tag
        );
        return false;
    }

    let sig = match crate::slh_dsa::SlhDsaSignature::from_bytes(sig_bytes.to_vec()) {
        Some(s) => s,
        None => {
            tracing::warn!("SLH-DSA signature decoding failed: invalid length");
            return false;
        }
    };

    crate::slh_dsa::slh_dsa_verify(slh_verifying_key, data, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ML-DSA-87 keys are large (~4KB signing key, ~2.5KB verifying key).
    // Spawn tests with 8MB stacks to prevent stack overflow.
    fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn test_pq_sign_and_verify() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_pq_keypair();
            let message = b"test message for PQ signing";
            let frost_sig = [0xABu8; 64];

            let sig = pq_sign(&sk, message, &frost_sig);
            assert!(!sig.is_empty());
            assert!(pq_verify(&vk, message, &frost_sig, &sig));
        });
    }

    #[test]
    fn test_pq_wrong_key_rejected() {
        run_with_large_stack(|| {
            let (sk, _vk) = generate_pq_keypair();
            let (_sk2, vk2) = generate_pq_keypair();
            let message = b"test message";
            let frost_sig = [0xCDu8; 64];

            let sig = pq_sign(&sk, message, &frost_sig);
            // Verification with a different key must fail
            assert!(!pq_verify(&vk2, message, &frost_sig, &sig));
        });
    }

    #[test]
    fn test_pq_wrong_message_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_pq_keypair();
            let frost_sig = [0x11u8; 64];

            let sig = pq_sign(&sk, b"original", &frost_sig);
            assert!(!pq_verify(&vk, b"tampered", &frost_sig, &sig));
        });
    }

    #[test]
    fn test_pq_wrong_frost_sig_rejected() {
        let (sk, vk) = generate_pq_keypair();
        let message = b"same message";
        let frost_sig = [0x22u8; 64];
        let wrong_frost_sig = [0x33u8; 64];

        let sig = pq_sign(&sk, message, &frost_sig);
        assert!(!pq_verify(&vk, message, &wrong_frost_sig, &sig));
    }

    // ── Crypto Agility Tests ─────────────────────────────────────────

    #[test]
    fn test_default_algorithm_is_ml_dsa_87() {
        // Without env var, default should be ML-DSA-87
        let algo = PqSignatureAlgorithm::default();
        assert_eq!(algo, PqSignatureAlgorithm::MlDsa87);
        assert_eq!(algo.tag(), ALGO_TAG_ML_DSA_87);
        assert_eq!(algo.name(), "ML-DSA-87");
    }

    #[test]
    fn test_algorithm_tag_roundtrip() {
        for algo in [
            PqSignatureAlgorithm::MlDsa87,
            PqSignatureAlgorithm::SlhDsaSha2256f,
        ] {
            let tag = algo.tag();
            let decoded = PqSignatureAlgorithm::from_tag(tag).unwrap();
            assert_eq!(algo, decoded);
        }
    }

    #[test]
    fn test_ml_dsa_65_tag_rejected() {
        // ML-DSA-65 (tag 0x02) MUST be rejected under CNSA 2.0 Level 5 policy
        assert!(PqSignatureAlgorithm::from_tag(ALGO_TAG_ML_DSA_65).is_none());
    }

    #[test]
    fn test_unknown_tag_returns_none() {
        assert!(PqSignatureAlgorithm::from_tag(0xFF).is_none());
        assert!(PqSignatureAlgorithm::from_tag(0x00).is_none());
    }

    #[test]
    fn test_tagged_sign_and_verify() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_pq_keypair();
            let data = b"tagged signature test data";

            let tagged_sig = pq_sign_tagged(&sk, data).expect("ML-DSA-87 signing should succeed");
            // First byte should be the algorithm tag
            assert_eq!(tagged_sig[0], ALGO_TAG_ML_DSA_87);
            // Verification should succeed
            assert!(pq_verify_tagged(&vk, data, &tagged_sig));
        });
    }

    #[test]
    fn test_tagged_verify_wrong_data_fails() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_pq_keypair();
            let tagged_sig = pq_sign_tagged(&sk, b"original data").expect("signing should succeed");
            assert!(!pq_verify_tagged(&vk, b"tampered data", &tagged_sig));
        });
    }

    #[test]
    fn test_tagged_verify_empty_sig_fails() {
        run_with_large_stack(|| {
            let (_sk, vk) = generate_pq_keypair();
            assert!(!pq_verify_tagged(&vk, b"data", &[]));
        });
    }

    #[test]
    fn test_tagged_verify_unknown_tag_fails() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_pq_keypair();
            let mut tagged_sig = pq_sign_tagged(&sk, b"data").expect("signing should succeed");
            // Corrupt the tag byte
            tagged_sig[0] = 0xFF;
            assert!(!pq_verify_tagged(&vk, b"data", &tagged_sig));
        });
    }
}
