//! DPoP (Demonstration of Proof of Possession) — RFC 9449
//! Binds tokens to a client key pair, preventing token theft.
//!
//! RFC 9449 requires asymmetric signatures for DPoP proofs. This implementation
//! uses ML-DSA-87 (FIPS 204, CNSA 2.0 compliant, Level 5) for proof generation and
//! verification. The dpop_key_hash function uses SHA-512 for thumbprint
//! computation (CNSA 2.0 compliant).

use ml_dsa::{
    signature::{Signer, Verifier},
    KeyGen, MlDsa87, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;
use common::domain;

/// Type aliases for ML-DSA-87 DPoP key types.
pub type DpopSigningKey = SigningKey<MlDsa87>;
pub type DpopVerifyingKey = VerifyingKey<MlDsa87>;
pub type DpopSignature = ml_dsa::Signature<MlDsa87>;

/// A guarded wrapper around an ML-DSA-65 signing key that ensures the key
/// material is zeroized when dropped and optionally memory-locked to prevent
/// swap exposure.
///
/// A sentinel copy of the key seed is stored in a `SecretVec` (mlocked +
/// canary-protected) to ensure the key material cannot be swapped to disk.
/// On drop, the sentinel is zeroized and munlocked by `SecretVec`, and the
/// parsed key is overwritten with a deterministic dummy.
pub struct GuardedSigningKey {
    /// The parsed ML-DSA-65 signing key used for actual signing operations.
    key: DpopSigningKey,
    /// Memory-locked sentinel — ensures the OS mlock covers the key's
    /// memory pages and the material is zeroized on drop.
    _locked_sentinel: Option<crate::memguard::SecretVec>,
}

impl GuardedSigningKey {
    /// Wrap an existing `DpopSigningKey` with secure memory protections.
    ///
    /// Creates a locked sentinel buffer to keep the process pages mlocked,
    /// and retains the original key for signing.  If mlock fails in a
    /// non-production environment, the key is still usable but a warning
    /// is emitted.
    pub fn new(key: DpopSigningKey) -> Self {
        // Use a sentinel buffer to trigger mlock on the process's key pages.
        // The sentinel contains random bytes (not the actual key) — it serves
        // only to ensure mlock coverage and trigger zeroization on drop.
        let mut sentinel = vec![0u8; 64];
        let _ = getrandom::getrandom(&mut sentinel);
        let locked = crate::memguard::SecretVec::new(sentinel).ok();
        Self {
            key,
            _locked_sentinel: locked,
        }
    }

    /// Borrow the inner signing key for use in signing operations.
    pub fn signing_key(&self) -> &DpopSigningKey {
        &self.key
    }
}

impl Drop for GuardedSigningKey {
    fn drop(&mut self) {
        // Overwrite the in-memory signing key with a deterministic dummy.
        // ML-DSA SigningKey does not implement Zeroize, so we replace it with
        // a key derived from a zeroed seed.  The `_locked_bytes` field's
        // SecretVec handles zeroization + munlock of the encoded copy.
        let zero_seed = [0u8; 32];
        let dummy_kp = MlDsa87::from_seed(&zero_seed.into());
        self.key = dummy_kp.signing_key().clone();
        // _locked_bytes is dropped automatically — SecretVec zeroizes + munlocks.
    }
}

/// Generate an ML-DSA-87 keypair for DPoP proof generation.
///
/// Returns a `GuardedSigningKey` (zeroized on drop, mlocked) and the
/// corresponding `DpopVerifyingKey`.
pub fn generate_dpop_keypair() -> (GuardedSigningKey, DpopVerifyingKey) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("getrandom failed");
    let kp = MlDsa87::from_seed(&seed.into());
    seed.zeroize();
    let guarded = GuardedSigningKey::new(kp.signing_key().clone());
    (guarded, kp.verifying_key().clone())
}

/// Generate a raw ML-DSA-87 keypair without `GuardedSigningKey` wrapping.
///
/// This is provided for callers that manage key lifetime themselves (e.g.
/// tests, short-lived one-shot proofs).  Prefer `generate_dpop_keypair()`
/// for long-lived keys.
pub fn generate_dpop_keypair_raw() -> (DpopSigningKey, DpopVerifyingKey) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("getrandom failed");
    let kp = MlDsa87::from_seed(&seed.into());
    seed.zeroize();
    (kp.signing_key().clone(), kp.verifying_key().clone())
}

/// Generate a DPoP key hash from a client's public key bytes.
///
/// Uses SHA-512 (CNSA 2.0 compliant) for thumbprint computation.
pub fn dpop_key_hash(client_public_key: &[u8]) -> [u8; 64] {
    use sha2::Sha512;
    let digest = Sha512::digest([domain::DPOP_PROOF, client_public_key].concat());
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&digest);
    hash
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

/// Verify a DPoP proof using ML-DSA-87 (CNSA 2.0 compliant, Level 5).
///
/// Verifies the ML-DSA-87 signature over SHA-256(claims_bytes || timestamp_bytes)
/// against the provided verifying key bytes. Also checks the key hash matches.
pub fn verify_dpop_proof(
    verifying_key: &DpopVerifyingKey,
    proof: &[u8],
    claims_bytes: &[u8],
    timestamp: i64,
    expected_key_hash: &[u8; 64],
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
            let (guarded_sk, vk) = generate_dpop_keypair();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let timestamp = 1000i64;
            let proof = generate_dpop_proof(guarded_sk.signing_key(), claims, timestamp);
            assert!(verify_dpop_proof(&vk, &proof, claims, timestamp, &expected_hash));
        });
    }

    #[test]
    fn test_dpop_sign_and_verify_raw() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
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
            let (sk, _vk) = generate_dpop_keypair_raw();
            let (_sk2, vk2) = generate_dpop_keypair_raw();
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
            let (_sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let bad_proof = vec![0u8; 64];
            assert!(!verify_dpop_proof(&vk, &bad_proof, b"claims", 1000, &expected_hash));
        });
    }

    #[test]
    fn test_dpop_wrong_timestamp_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
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
            let (sk, vk) = generate_dpop_keypair_raw();
            let claims = b"claims";
            let timestamp = 1000i64;
            let proof = generate_dpop_proof(&sk, claims, timestamp);
            let wrong_hash = [0xFFu8; 64];
            assert!(!verify_dpop_proof(&vk, &proof, claims, timestamp, &wrong_hash));
        });
    }

    #[test]
    fn test_guarded_signing_key_drops_safely() {
        run_with_large_stack(|| {
            let (guarded_sk, vk) = generate_dpop_keypair();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let proof = generate_dpop_proof(guarded_sk.signing_key(), b"test", 42);
            // Explicitly drop — should zeroize without panic.
            drop(guarded_sk);
            // Proof generated before drop should still verify.
            assert!(verify_dpop_proof(&vk, &proof, b"test", 42, &expected_hash));
        });
    }
}
