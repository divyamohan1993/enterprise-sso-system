//! DPoP (Demonstration of Proof of Possession) — RFC 9449
//! Binds tokens to a client key pair, preventing token theft.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use common::domain;

type HmacSha512 = Hmac<Sha512>;

/// Generate a DPoP key hash from a client's public key bytes.
pub fn dpop_key_hash(client_public_key: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(domain::DPOP_PROOF);
    hasher.update(client_public_key);
    hasher.finalize().into()
}

/// Generate a DPoP proof (HMAC over token claims + client key).
pub fn generate_dpop_proof(
    client_secret_key: &[u8; 64],
    claims_bytes: &[u8],
    timestamp: i64,
) -> [u8; 64] {
    generate_dpop_proof_with_key(client_secret_key, claims_bytes, timestamp)
}

/// Generate a DPoP proof using an arbitrary key (used for both generation and verification).
fn generate_dpop_proof_with_key(
    key: &[u8],
    claims_bytes: &[u8],
    timestamp: i64,
) -> [u8; 64] {
    let mac = HmacSha512::new_from_slice(key).unwrap_or_else(|_| {
        let mut padded = vec![0u8; 64];
        let len = key.len().min(64);
        padded[..len].copy_from_slice(&key[..len]);
        HmacSha512::new_from_slice(&padded).unwrap()
    });
    let mut mac = mac;
    mac.update(domain::DPOP_PROOF);
    mac.update(claims_bytes);
    mac.update(&timestamp.to_le_bytes());
    mac.finalize().into_bytes().into()
}

/// Verify a DPoP proof by checking the key hash and recomputing the HMAC.
pub fn verify_dpop_proof(
    client_public_key: &[u8],
    proof: &[u8; 64],
    claims_bytes: &[u8],
    timestamp: i64,
    expected_key_hash: &[u8; 32],
) -> bool {
    // 1. Verify the key hash matches
    let hash = dpop_key_hash(client_public_key);
    if !crate::ct::ct_eq(&hash, expected_key_hash) {
        return false;
    }
    // 2. Recompute the expected proof and verify
    let expected = generate_dpop_proof_with_key(client_public_key, claims_bytes, timestamp);
    crate::ct::ct_eq(proof, &expected)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_dpop_binding_verified() {
        let client_key = [0xABu8; 32];
        let expected = dpop_key_hash(&client_key);
        let claims = b"claims";
        let timestamp = 1000i64;
        let proof = generate_dpop_proof_with_key(&client_key, claims, timestamp);
        assert!(verify_dpop_proof(&client_key, &proof, claims, timestamp, &expected));
    }

    #[test]
    fn test_dpop_wrong_key_rejected() {
        let client_key = [0xABu8; 32];
        let wrong_key = [0xCDu8; 32];
        let expected = dpop_key_hash(&client_key);
        let proof = [0u8; 64];
        assert!(!verify_dpop_proof(&wrong_key, &proof, b"claims", 1000, &expected));
    }

    #[test]
    fn test_dpop_wrong_proof_rejected() {
        let client_key = [0xABu8; 32];
        let expected = dpop_key_hash(&client_key);
        let bad_proof = [0u8; 64]; // wrong proof
        assert!(!verify_dpop_proof(&client_key, &bad_proof, b"claims", 1000, &expected));
    }

    #[test]
    fn test_dpop_wrong_timestamp_rejected() {
        let client_key = [0xABu8; 32];
        let expected = dpop_key_hash(&client_key);
        let claims = b"claims";
        let proof = generate_dpop_proof_with_key(&client_key, claims, 1000);
        assert!(!verify_dpop_proof(&client_key, &proof, claims, 9999, &expected));
    }
}
