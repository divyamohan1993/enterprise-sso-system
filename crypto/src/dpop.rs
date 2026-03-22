//! DPoP (Demonstration of Proof of Possession) — RFC 9449
//! Binds tokens to a client key pair, preventing token theft.
//!
//! RFC 9449 requires asymmetric signatures for DPoP proofs. This implementation
//! uses ECDSA P-256 (NIST-approved, widely supported) for proof generation and
//! verification. The dpop_key_hash function uses SHA-256 for thumbprint
//! computation per RFC 9449/RFC 7638 JWK Thumbprint interoperability requirements.

use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use common::domain;

/// Generate a DPoP key hash from a client's public key bytes.
pub fn dpop_key_hash(client_public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain::DPOP_PROOF);
    hasher.update(client_public_key);
    hasher.finalize().into()
}

/// Generate a DPoP proof using ECDSA P-256.
///
/// Signs SHA-256(claims_bytes || timestamp_bytes) with the provided signing key.
/// Returns the ECDSA signature bytes (DER-encoded).
pub fn generate_dpop_proof(
    signing_key: &SigningKey,
    claims_bytes: &[u8],
    timestamp: i64,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(claims_bytes);
    hasher.update(&timestamp.to_le_bytes());
    let digest = hasher.finalize();
    let sig: Signature = signing_key.sign(&digest);
    sig.to_vec()
}

/// Verify a DPoP proof using ECDSA P-256.
///
/// Verifies the ECDSA signature over SHA-256(claims_bytes || timestamp_bytes)
/// against the provided verifying key. Also checks the key hash matches.
pub fn verify_dpop_proof(
    verifying_key: &VerifyingKey,
    proof: &[u8],
    claims_bytes: &[u8],
    timestamp: i64,
    expected_key_hash: &[u8; 32],
) -> bool {
    // 1. Verify the key hash matches
    let pk_bytes = verifying_key.to_encoded_point(false);
    let hash = dpop_key_hash(pk_bytes.as_bytes());
    if !crate::ct::ct_eq(&hash, expected_key_hash) {
        return false;
    }

    // 2. Parse the signature
    let sig = match Signature::from_slice(proof) {
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

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::random(&mut rand::rngs::OsRng);
        let vk = VerifyingKey::from(&sk);
        (sk, vk)
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
        let (sk, vk) = test_keypair();
        let pk_bytes = vk.to_encoded_point(false);
        let expected_hash = dpop_key_hash(pk_bytes.as_bytes());
        let claims = b"claims";
        let timestamp = 1000i64;
        let proof = generate_dpop_proof(&sk, claims, timestamp);
        assert!(verify_dpop_proof(&vk, &proof, claims, timestamp, &expected_hash));
    }

    #[test]
    fn test_dpop_wrong_key_rejected() {
        let (sk, _vk) = test_keypair();
        let (_sk2, vk2) = test_keypair();
        let pk_bytes = vk2.to_encoded_point(false);
        let expected_hash = dpop_key_hash(pk_bytes.as_bytes());
        let claims = b"claims";
        let timestamp = 1000i64;
        let proof = generate_dpop_proof(&sk, claims, timestamp);
        // Signature was made with sk (whose vk != vk2), so verification fails
        assert!(!verify_dpop_proof(&vk2, &proof, claims, timestamp, &expected_hash));
    }

    #[test]
    fn test_dpop_wrong_proof_rejected() {
        let (_sk, vk) = test_keypair();
        let pk_bytes = vk.to_encoded_point(false);
        let expected_hash = dpop_key_hash(pk_bytes.as_bytes());
        let bad_proof = vec![0u8; 64];
        assert!(!verify_dpop_proof(&vk, &bad_proof, b"claims", 1000, &expected_hash));
    }

    #[test]
    fn test_dpop_wrong_timestamp_rejected() {
        let (sk, vk) = test_keypair();
        let pk_bytes = vk.to_encoded_point(false);
        let expected_hash = dpop_key_hash(pk_bytes.as_bytes());
        let claims = b"claims";
        let proof = generate_dpop_proof(&sk, claims, 1000);
        assert!(!verify_dpop_proof(&vk, &proof, claims, 9999, &expected_hash));
    }

    #[test]
    fn test_dpop_wrong_key_hash_rejected() {
        let (sk, vk) = test_keypair();
        let claims = b"claims";
        let timestamp = 1000i64;
        let proof = generate_dpop_proof(&sk, claims, timestamp);
        let wrong_hash = [0xFFu8; 32];
        assert!(!verify_dpop_proof(&vk, &proof, claims, timestamp, &wrong_hash));
    }
}
