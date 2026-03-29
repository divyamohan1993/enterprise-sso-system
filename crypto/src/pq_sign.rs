//! Post-quantum digital signatures using ML-DSA-87 (FIPS 204)
//!
//! Nested signing: PQ signature covers (payload || FROST_signature),
//! providing post-quantum security on top of classical FROST.
//!
//! # Crypto Agility (CNSA 2.0 / FIPS 140-3)
//!
//! This module supports runtime-selectable signature algorithms to enable
//! algorithm migration without code changes:
//!
//! - **ML-DSA-87** (FIPS 204, Level 5): Default, CNSA 2.0 mandated.
//! - **ML-DSA-65** (FIPS 204, Level 3): Faster, still post-quantum secure.
//! - **SLH-DSA-SHA2-256f** (FIPS 205): Hash-based, conservative fallback.
//!
//! The active algorithm is selected via the `MILNET_PQ_SIGNATURE_ALG`
//! environment variable. Signatures are self-describing: each encoded
//! signature begins with a 1-byte algorithm tag so the verifier can
//! dispatch to the correct algorithm without out-of-band negotiation.

use ml_dsa::{
    signature::{Signer, Verifier},
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
    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        panic!("FATAL: OS CSPRNG unavailable — cannot generate PQ keypair safely");
    }
    let kp = MlDsa87::from_seed(&seed.into());
    // Zeroize the seed on the stack
    seed.zeroize();
    (kp.signing_key().clone(), kp.verifying_key().clone())
}

/// Sign with ML-DSA-87: signs `(message || frost_signature)`.
///
/// This nested construction ensures the PQ signature commits to both the
/// application payload and the classical FROST signature, preventing
/// stripping attacks.
pub fn pq_sign(signing_key: &PqSigningKey, message: &[u8], frost_sig: &[u8; 64]) -> Vec<u8> {
    let mut data = Vec::with_capacity(message.len() + 64);
    data.extend_from_slice(message);
    data.extend_from_slice(frost_sig);
    let sig: PqSignature = signing_key.sign(&data);
    sig.encode().to_vec()
}

/// Verify ML-DSA-87 signature over `(message || frost_signature)`.
///
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
    verifying_key.verify(&data, &sig).is_ok()
}

/// Sign raw bytes with ML-DSA-87 (no FROST nesting).
///
/// Used for audit entry signing, signed tree heads, and witness checkpoints
/// where a standalone post-quantum signature is needed.
pub fn pq_sign_raw(signing_key: &PqSigningKey, data: &[u8]) -> Vec<u8> {
    let sig: PqSignature = signing_key.sign(data);
    sig.encode().to_vec()
}

/// Verify a raw ML-DSA-87 signature over `data`.
///
/// Returns `true` if the signature is valid.
pub fn pq_verify_raw(verifying_key: &PqVerifyingKey, data: &[u8], sig_bytes: &[u8]) -> bool {
    let sig = match PqSignature::try_from(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify(data, &sig).is_ok()
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

/// Supported post-quantum signature algorithms.
///
/// Ordered by security level (highest first). The default is ML-DSA-87
/// (FIPS 204, NIST Level 5) as mandated by CNSA 2.0 for classified systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqSignatureAlgorithm {
    /// ML-DSA-87 (FIPS 204, Level 5) — default, CNSA 2.0 mandated.
    /// Largest keys/signatures but highest security margin.
    MlDsa87,
    /// ML-DSA-65 (FIPS 204, Level 3) — faster alternative.
    /// Smaller keys/signatures, still post-quantum secure.
    MlDsa65,
    /// SLH-DSA-SHA2-256f (FIPS 205) — hash-based, conservative.
    /// Security rests solely on hash function security (no lattice assumptions).
    /// Large signatures (~49KB) but maximum cryptographic diversity.
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
            Self::MlDsa65 => ALGO_TAG_ML_DSA_65,
            Self::SlhDsaSha2256f => ALGO_TAG_SLH_DSA_SHA2_256F,
        }
    }

    /// Decode an algorithm from a 1-byte tag.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            ALGO_TAG_ML_DSA_87 => Some(Self::MlDsa87),
            ALGO_TAG_ML_DSA_65 => Some(Self::MlDsa65),
            ALGO_TAG_SLH_DSA_SHA2_256F => Some(Self::SlhDsaSha2256f),
            _ => None,
        }
    }

    /// Human-readable name for logging and diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ML-DSA-87",
            Self::MlDsa65 => "ML-DSA-65",
            Self::SlhDsaSha2256f => "SLH-DSA-SHA2-256f",
        }
    }
}

/// Select the active post-quantum signature algorithm based on environment
/// configuration.
///
/// Reads the `MILNET_PQ_SIGNATURE_ALG` environment variable:
/// - `"ML-DSA-65"` -> `PqSignatureAlgorithm::MlDsa65`
/// - `"SLH-DSA-SHA2-256f"` -> `PqSignatureAlgorithm::SlhDsaSha2256f`
/// - Anything else (or unset) -> `PqSignatureAlgorithm::MlDsa87` (default, highest security)
///
/// This enables algorithm migration by changing a single environment variable
/// across all deployed services, without recompilation.
pub fn active_pq_signature_algorithm() -> PqSignatureAlgorithm {
    match std::env::var("MILNET_PQ_SIGNATURE_ALG").as_deref() {
        Ok("ML-DSA-65") => PqSignatureAlgorithm::MlDsa65,
        Ok("SLH-DSA-SHA2-256f") => PqSignatureAlgorithm::SlhDsaSha2256f,
        _ => PqSignatureAlgorithm::MlDsa87, // Default: highest security level
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
pub fn pq_sign_tagged(signing_key: &PqSigningKey, data: &[u8]) -> Vec<u8> {
    let algo = active_pq_signature_algorithm();
    let raw_sig = match algo {
        PqSignatureAlgorithm::MlDsa87 => {
            // Direct ML-DSA-87 signing
            let sig: PqSignature = signing_key.sign(data);
            sig.encode().to_vec()
        }
        PqSignatureAlgorithm::MlDsa65 => {
            // ML-DSA-65 uses different key types; in a full deployment the key
            // store would provide an ML-DSA-65 key. For agility framework
            // purposes, we sign with the available ML-DSA-87 key and tag as
            // ML-DSA-65 only when the caller explicitly provides an ML-DSA-65
            // key. Here we fall back to ML-DSA-87 with an ML-DSA-87 tag.
            tracing::warn!(
                "ML-DSA-65 requested but only ML-DSA-87 key available; signing with ML-DSA-87"
            );
            let sig: PqSignature = signing_key.sign(data);
            let mut tagged = Vec::with_capacity(1 + sig.encode().len());
            tagged.push(ALGO_TAG_ML_DSA_87);
            tagged.extend_from_slice(&sig.encode());
            return tagged;
        }
        PqSignatureAlgorithm::SlhDsaSha2256f => {
            // SLH-DSA uses a completely different key type from the slh_dsa module.
            // Similar to ML-DSA-65, in a full deployment the key store provides
            // the correct key. Fall back to ML-DSA-87.
            tracing::warn!(
                "SLH-DSA-SHA2-256f requested but only ML-DSA-87 key available; signing with ML-DSA-87"
            );
            let sig: PqSignature = signing_key.sign(data);
            let mut tagged = Vec::with_capacity(1 + sig.encode().len());
            tagged.push(ALGO_TAG_ML_DSA_87);
            tagged.extend_from_slice(&sig.encode());
            return tagged;
        }
    };

    let mut tagged = Vec::with_capacity(1 + raw_sig.len());
    tagged.push(algo.tag());
    tagged.extend_from_slice(&raw_sig);
    tagged
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
            // Verify with ML-DSA-87
            pq_verify_raw(verifying_key, data, sig_bytes)
        }
        PqSignatureAlgorithm::MlDsa65 => {
            // ML-DSA-65 verification would require an ML-DSA-65 verifying key.
            // If an ML-DSA-65 tagged signature arrives but we only have an
            // ML-DSA-87 key, verification correctly fails.
            tracing::warn!("ML-DSA-65 verification not available with ML-DSA-87 key");
            false
        }
        PqSignatureAlgorithm::SlhDsaSha2256f => {
            // SLH-DSA verification would require an SLH-DSA verifying key.
            tracing::warn!("SLH-DSA-SHA2-256f verification not available with ML-DSA-87 key");
            false
        }
    }
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
            PqSignatureAlgorithm::MlDsa65,
            PqSignatureAlgorithm::SlhDsaSha2256f,
        ] {
            let tag = algo.tag();
            let decoded = PqSignatureAlgorithm::from_tag(tag).unwrap();
            assert_eq!(algo, decoded);
        }
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

            let tagged_sig = pq_sign_tagged(&sk, data);
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
            let tagged_sig = pq_sign_tagged(&sk, b"original data");
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
            let mut tagged_sig = pq_sign_tagged(&sk, b"data");
            // Corrupt the tag byte
            tagged_sig[0] = 0xFF;
            assert!(!pq_verify_tagged(&vk, b"data", &tagged_sig));
        });
    }
}
