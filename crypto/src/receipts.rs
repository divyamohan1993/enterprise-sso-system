//! Receipt signing and chain validation (spec Section 6, E.15)
//!
//! Each ceremony step produces a Receipt signed by the issuing service.
//! Receipts form a hash chain: each includes H(previous_receipt).
//! The TSS validates the complete chain before signing a token.
//!
//! CNSA 2.0 compliance: All hashing upgraded from SHA-256 to SHA-512.
//! HMAC upgraded from HMAC-SHA256 to HMAC-SHA512.
//! Asymmetric receipt signing upgraded from Ed25519 to ML-DSA-87 (FIPS 204, Level 5).

use ml_dsa::{
    signature::{Signer, Verifier},
    EncodedVerifyingKey, KeyGen, MlDsa87, SigningKey, VerifyingKey,
};
use hmac::{Hmac, Mac};
use common::domain;
use common::types::Receipt;
use sha2::Sha512;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// Type aliases for ML-DSA-87 receipt key types.
pub type ReceiptSigningKey = SigningKey<MlDsa87>;
pub type ReceiptVerifyingKey = VerifyingKey<MlDsa87>;
pub type ReceiptSignature = ml_dsa::Signature<MlDsa87>;

/// Hash a receipt for chain linking (CNSA 2.0: SHA-512)
pub fn hash_receipt(receipt: &Receipt) -> [u8; 64] {
    use sha2::Digest;
    let mut hasher = sha2::Sha512::new();
    hasher.update(domain::RECEIPT_CHAIN);
    hasher.update(receipt.ceremony_session_id);
    hasher.update([receipt.step_id]);
    hasher.update(receipt.prev_receipt_hash);
    hasher.update(receipt.user_id.as_bytes());
    let ts_bytes = receipt.timestamp.to_le_bytes();
    hasher.update(ts_bytes);
    hasher.update(receipt.nonce);
    let result = hasher.finalize();
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&result);
    hash
}

fn mac_receipt_fields(mac: &mut HmacSha512, receipt: &Receipt) {
    mac.update(domain::RECEIPT_SIGN);
    mac.update(&receipt.ceremony_session_id);
    mac.update(&[receipt.step_id]);
    mac.update(&receipt.prev_receipt_hash);
    mac.update(receipt.user_id.as_bytes());
    mac.update(&receipt.timestamp.to_le_bytes());
    mac.update(&receipt.nonce);
}

/// Sign a receipt with HMAC-SHA512 (CNSA 2.0 compliant)
pub fn sign_receipt(receipt: &mut Receipt, signing_key: &[u8; 64]) {
    let mut mac = HmacSha512::new_from_slice(signing_key).expect("HMAC key length is always valid");
    mac_receipt_fields(&mut mac, receipt);
    receipt.signature = mac.finalize().into_bytes().to_vec();
}

/// Verify a receipt's signature (HMAC-SHA512)
pub fn verify_receipt_signature(receipt: &Receipt, signing_key: &[u8; 64]) -> bool {
    let mut mac = HmacSha512::new_from_slice(signing_key).expect("HMAC key length is always valid");
    mac_receipt_fields(&mut mac, receipt);
    let expected = mac.finalize().into_bytes();
    crate::ct::ct_eq(&receipt.signature, &expected)
}

/// A chain of receipts for one ceremony
pub struct ReceiptChain {
    session_id: [u8; 32],
    receipts: Vec<Receipt>,
}

impl ReceiptChain {
    pub fn new(session_id: [u8; 32]) -> Self {
        Self {
            session_id,
            receipts: Vec::new(),
        }
    }

    /// Add a receipt to the chain
    pub fn add_receipt(&mut self, receipt: Receipt) -> Result<(), String> {
        // Verify session ID matches
        if !crate::ct::ct_eq(&receipt.ceremony_session_id, &self.session_id) {
            return Err("ceremony_session_id mismatch".into());
        }

        // Verify hash chain linkage
        if self.receipts.is_empty() {
            // First receipt: prev_receipt_hash should be zeros
            if !crate::ct::ct_eq(&receipt.prev_receipt_hash, &[0u8; 64]) {
                return Err("first receipt must have zero prev_hash".into());
            }
        } else {
            let last = self.receipts.last().unwrap();
            let expected_hash = hash_receipt(last);
            if !crate::ct::ct_eq(&receipt.prev_receipt_hash, &expected_hash) {
                return Err("prev_receipt_hash does not match previous receipt".into());
            }
        }

        // Verify step_id is sequential
        let expected_step = self.receipts.len() as u8 + 1;
        if receipt.step_id != expected_step {
            return Err(format!(
                "expected step {}, got {}",
                expected_step, receipt.step_id
            ));
        }

        self.receipts.push(receipt);
        Ok(())
    }

    /// Validate the complete chain (structural check only, no signature verification).
    pub fn validate(&self) -> Result<(), String> {
        if self.receipts.is_empty() {
            return Err("empty receipt chain".into());
        }
        Ok(())
    }

    /// Validate the complete chain including signature verification against the
    /// provided signing key. This is the method that MUST be used for
    /// security-critical validation.
    pub fn validate_with_key(&self, signing_key: &[u8; 64]) -> Result<(), String> {
        if self.receipts.is_empty() {
            return Err("empty receipt chain".into());
        }
        for receipt in &self.receipts {
            if !verify_receipt_signature(receipt, signing_key) {
                return Err(format!(
                    "receipt step {} has invalid signature",
                    receipt.step_id
                ));
            }
        }
        Ok(())
    }

    /// Check all receipts are within TTL
    pub fn check_ttl(&self) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;

        for receipt in &self.receipts {
            // Reject future-timestamped receipts
            if receipt.timestamp > now {
                return Err(format!(
                    "receipt step {} has future timestamp",
                    receipt.step_id
                ));
            }
            let age_us = now - receipt.timestamp;
            let ttl_us = receipt.ttl_seconds as i64 * 1_000_000;
            if age_us > ttl_us {
                return Err(format!("receipt step {} expired", receipt.step_id));
            }
        }
        Ok(())
    }

    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Asymmetric receipt signing (ML-DSA-65, CNSA 2.0 compliant)
// ---------------------------------------------------------------------------

/// Generate an ML-DSA-87 keypair for asymmetric receipt signing.
///
/// Returns (signing_key, verifying_key) as ML-DSA-87 types.
pub fn generate_receipt_keypair() -> (ReceiptSigningKey, ReceiptVerifyingKey) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("getrandom failed");
    let kp = MlDsa87::from_seed(&seed.into());
    seed.zeroize();
    (kp.signing_key().clone(), kp.verifying_key().clone())
}

/// Serialize receipt fields (excluding signature) into a canonical byte
/// representation suitable for signing or verification.
pub fn receipt_signing_data(receipt: &Receipt) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(domain::RECEIPT_SIGN);
    data.extend_from_slice(&receipt.ceremony_session_id);
    data.push(receipt.step_id);
    data.extend_from_slice(&receipt.prev_receipt_hash);
    data.extend_from_slice(receipt.user_id.as_bytes());
    data.extend_from_slice(&receipt.timestamp.to_le_bytes());
    data.extend_from_slice(&receipt.nonce);
    data
}

/// Sign receipt data with an ML-DSA-87 signing key.
///
/// `signing_key` must be exactly 32 bytes (seed).
/// Returns the encoded ML-DSA-87 signature bytes.
pub fn sign_receipt_asymmetric(signing_key: &[u8], data: &[u8]) -> Vec<u8> {
    // Reconstruct the signing key from a 32-byte seed
    // ML-DSA-87 signing keys are encoded, but we accept a 32-byte
    // seed for ergonomic parity with the old Ed25519 API.
    let seed: [u8; 32] = signing_key
        .try_into()
        .expect("signing_key must be exactly 32 bytes (seed)");
    let sk = SigningKey::<MlDsa87>::from_seed(&seed.into());
    let sig: ReceiptSignature = sk.sign(data);
    sig.encode().to_vec()
}

/// Verify an ML-DSA-87 signature over receipt data.
///
/// `verifying_key` must be the encoded ML-DSA-87 verifying key bytes.
/// Uses ML-DSA-87 signature verification (CNSA 2.0 compliant, Level 5).
pub fn verify_receipt_asymmetric(verifying_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let vk_enc = match EncodedVerifyingKey::<MlDsa87>::try_from(verifying_key) {
        Ok(enc) => enc,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
    let sig = match ReceiptSignature::try_from(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(data, &sig).is_ok()
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
    fn test_generate_receipt_keypair() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_receipt_keypair();
            let vk2 = sk.verifying_key();
            assert_eq!(vk.encode(), vk2.encode());
        });
    }

    #[test]
    fn test_sign_and_verify_asymmetric() {
        run_with_large_stack(|| {
            // Use a seed for signing, and the encoded verifying key for verification
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).expect("getrandom failed");
            let kp = MlDsa87::from_seed(&seed.into());
            let vk = kp.verifying_key();
            let vk_bytes = vk.encode();

            let data = b"receipt data to sign";
            let sig = sign_receipt_asymmetric(&seed, data);
            assert!(verify_receipt_asymmetric(vk_bytes.as_ref(), data, &sig));
        });
    }

    #[test]
    fn test_asymmetric_wrong_key_rejected() {
        run_with_large_stack(|| {
            let mut seed1 = [0u8; 32];
            getrandom::getrandom(&mut seed1).expect("getrandom failed");
            let mut seed2 = [0u8; 32];
            getrandom::getrandom(&mut seed2).expect("getrandom failed");
            let kp2 = MlDsa87::from_seed(&seed2.into());
            let vk2_bytes = kp2.verifying_key().encode();

            let data = b"receipt data";
            let sig = sign_receipt_asymmetric(&seed1, data);
            assert!(!verify_receipt_asymmetric(vk2_bytes.as_ref(), data, &sig));
        });
    }

    #[test]
    fn test_asymmetric_tampered_data_rejected() {
        run_with_large_stack(|| {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).expect("getrandom failed");
            let kp = MlDsa87::from_seed(&seed.into());
            let vk_bytes = kp.verifying_key().encode();

            let data = b"original data";
            let sig = sign_receipt_asymmetric(&seed, data);
            assert!(!verify_receipt_asymmetric(vk_bytes.as_ref(), b"tampered data", &sig));
        });
    }

    #[test]
    fn test_asymmetric_bad_signature_rejected() {
        run_with_large_stack(|| {
            let (_sk, vk) = generate_receipt_keypair();
            let vk_bytes = vk.encode();
            let data = b"some data";
            let bad_sig = vec![0u8; 64];
            assert!(!verify_receipt_asymmetric(vk_bytes.as_ref(), data, &bad_sig));
        });
    }

    #[test]
    fn test_asymmetric_bad_verifying_key_rejected() {
        assert!(!verify_receipt_asymmetric(&[0u8; 32], b"data", &[0u8; 64]));
    }

    #[test]
    fn test_asymmetric_wrong_length_key_rejected() {
        assert!(!verify_receipt_asymmetric(&[0u8; 16], b"data", &[0u8; 64]));
    }
}
