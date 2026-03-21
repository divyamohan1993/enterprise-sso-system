//! Post-quantum digital signatures using ML-DSA-65 (FIPS 204)
//!
//! Nested signing: PQ signature covers (payload || FROST_signature),
//! providing post-quantum security on top of classical FROST.

use ml_dsa::{
    signature::{Signer, Verifier},
    EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa65, SigningKey, VerifyingKey,
};

/// Type aliases for ML-DSA-65 key types.
pub type PqSigningKey = SigningKey<MlDsa65>;
pub type PqVerifyingKey = VerifyingKey<MlDsa65>;
pub type PqSignature = ml_dsa::Signature<MlDsa65>;

/// Encoded verifying key size for serialization.
pub type PqEncodedVerifyingKey = EncodedVerifyingKey<MlDsa65>;
pub type PqEncodedSignature = EncodedSignature<MlDsa65>;

/// Generate an ML-DSA-65 keypair from a random seed.
///
/// Uses `getrandom` (via the workspace crate) to obtain 32 bytes of entropy,
/// then derives the keypair deterministically via `from_seed`.
pub fn generate_pq_keypair() -> (PqSigningKey, PqVerifyingKey) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("getrandom failed");
    let kp = MlDsa65::from_seed(&seed.into());
    // Zeroize the seed on the stack
    seed.fill(0);
    (kp.signing_key().clone(), kp.verifying_key().clone())
}

/// Sign with ML-DSA-65: signs `(message || frost_signature)`.
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

/// Verify ML-DSA-65 signature over `(message || frost_signature)`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_sign_and_verify() {
        let (sk, vk) = generate_pq_keypair();
        let message = b"test message for PQ signing";
        let frost_sig = [0xABu8; 64];

        let sig = pq_sign(&sk, message, &frost_sig);
        assert!(!sig.is_empty());
        assert!(pq_verify(&vk, message, &frost_sig, &sig));
    }

    #[test]
    fn test_pq_wrong_key_rejected() {
        let (sk, _vk) = generate_pq_keypair();
        let (_sk2, vk2) = generate_pq_keypair();
        let message = b"test message";
        let frost_sig = [0xCDu8; 64];

        let sig = pq_sign(&sk, message, &frost_sig);
        // Verification with a different key must fail
        assert!(!pq_verify(&vk2, message, &frost_sig, &sig));
    }

    #[test]
    fn test_pq_wrong_message_rejected() {
        let (sk, vk) = generate_pq_keypair();
        let frost_sig = [0x11u8; 64];

        let sig = pq_sign(&sk, b"original", &frost_sig);
        assert!(!pq_verify(&vk, b"tampered", &frost_sig, &sig));
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
}
