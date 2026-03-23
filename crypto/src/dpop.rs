//! DPoP (Demonstration of Proof of Possession) — RFC 9449
//! Binds tokens to a client key pair, preventing token theft.
//!
//! RFC 9449 requires asymmetric signatures for DPoP proofs. This implementation
//! uses ML-DSA-65 (FIPS 204, CNSA 2.0 compliant) for proof generation and
//! verification. The dpop_key_hash function uses SHA-256 for thumbprint
//! computation per RFC 9449/RFC 7638 JWK Thumbprint interoperability requirements.

use ml_dsa::{
    signature::{Signer, Verifier},
    KeyGen, MlDsa65, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;
use common::domain;

/// Type aliases for ML-DSA-65 DPoP key types.
pub type DpopSigningKey = SigningKey<MlDsa65>;
pub type DpopVerifyingKey = VerifyingKey<MlDsa65>;
pub type DpopSignature = ml_dsa::Signature<MlDsa65>;

/// Generate an ML-DSA-65 keypair for DPoP proof generation.
///
/// Returns (signing_key, verifying_key).
pub fn generate_dpop_keypair() -> (DpopSigningKey, DpopVerifyingKey) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("getrandom failed");
    let kp = MlDsa65::from_seed(&seed.into());
    seed.zeroize();
    (kp.signing_key().clone(), kp.verifying_key().clone())
}

/// Generate a DPoP key hash from a client's public key bytes.
///
/// Uses SHA-256 per RFC 9449/RFC 7638 JWK Thumbprint (allowed exception).
pub fn dpop_key_hash(client_public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain::DPOP_PROOF);
    hasher.update(client_public_key);
    hasher.finalize().into()
}

/// Generate a DPoP proof using ML-DSA-65 (CNSA 2.0 compliant).
///
/// Signs SHA-256(claims_bytes || timestamp_bytes) with the provided ML-DSA-65
/// signing key. Returns the encoded ML-DSA-65 signature bytes.
pub fn generate_dpop_proof(
    signing_key: &DpopSigningKey,
    claims_bytes: &[u8],
    timestamp: i64,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(claims_bytes);
    hasher.update(&timestamp.to_le_bytes());
    let digest = hasher.finalize();
    let sig: DpopSignature = signing_key.sign(&digest);
    sig.encode().to_vec()
}

/// Verify a DPoP proof using ML-DSA-65 (CNSA 2.0 compliant).
///
/// Verifies the ML-DSA-65 signature over SHA-256(claims_bytes || timestamp_bytes)
/// against the provided verifying key bytes. Also checks the key hash matches.
pub fn verify_dpop_proof(
    verifying_key: &DpopVerifyingKey,
    proof: &[u8],
    claims_bytes: &[u8],
    timestamp: i64,
    expected_key_hash: &[u8; 32],
) -> bool {
    // 1. Verify the key hash matches
    let vk_bytes = verifying_key.encode();
    let hash = dpop_key_hash(vk_bytes.as_ref());
    if !crate::ct::ct_eq(&hash, expected_key_hash) {
        return false;
    }

    // 2. Parse the ML-DSA-65 signature
    let sig = match DpopSignature::try_from(proof) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 3. Recompute the digest and verify
    let mut hasher = Sha256::new();
    hasher.update(claims_bytes);
    hasher.update(&timestamp.to_le_bytes());
    let digest = hasher.finalize();

    verifying_key.verify(&digest, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn test_dpop_key_hash_deterministic() {
        let key = [0x42u8; 32];
        let h1 = dpop_key_hash(&key);
        let h2 = dpop_key_hash(&key);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_dpop_different_keys_different_hashes() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let ha = dpop_key_hash(&key_a);
        let hb = dpop_key_hash(&key_b);
        assert_ne!(ha, hb);
    }

    #[test]
    fn test_dpop_sign_and_verify() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let timestamp = 1000i64;
            let proof = generate_dpop_proof(&sk, claims, timestamp);
            assert!(verify_dpop_proof(&vk, &proof, claims, timestamp, &expected_hash));
        });
    }

    #[test]
    fn test_dpop_wrong_key_rejected() {
        run_with_large_stack(|| {
            let (sk, _vk) = generate_dpop_keypair();
            let (_sk2, vk2) = generate_dpop_keypair();
            let vk2_bytes = vk2.encode();
            let expected_hash = dpop_key_hash(vk2_bytes.as_ref());
            let claims = b"claims";
            let timestamp = 1000i64;
            let proof = generate_dpop_proof(&sk, claims, timestamp);
            // Signature was made with sk (whose vk != vk2), so verification fails
            assert!(!verify_dpop_proof(&vk2, &proof, claims, timestamp, &expected_hash));
        });
    }

    #[test]
    fn test_dpop_wrong_proof_rejected() {
        run_with_large_stack(|| {
            let (_sk, vk) = generate_dpop_keypair();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let bad_proof = vec![0u8; 64];
            assert!(!verify_dpop_proof(&vk, &bad_proof, b"claims", 1000, &expected_hash));
        });
    }

    #[test]
    fn test_dpop_wrong_timestamp_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let proof = generate_dpop_proof(&sk, claims, 1000);
            assert!(!verify_dpop_proof(&vk, &proof, claims, 9999, &expected_hash));
        });
    }

    #[test]
    fn test_dpop_wrong_key_hash_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair();
            let claims = b"claims";
            let timestamp = 1000i64;
            let proof = generate_dpop_proof(&sk, claims, timestamp);
            let wrong_hash = [0xFFu8; 32];
            assert!(!verify_dpop_proof(&vk, &proof, claims, timestamp, &wrong_hash));
        });
    }
}
