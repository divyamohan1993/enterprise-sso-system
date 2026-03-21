//! Receipt signing and chain validation (spec Section 6, E.15)
//!
//! Each ceremony step produces a Receipt signed by the issuing service.
//! Receipts form a hash chain: each includes H(previous_receipt).
//! The TSS validates the complete chain before signing a token.

use hmac::{Hmac, Mac};
use milnet_common::domain;
use milnet_common::types::Receipt;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Hash a receipt for chain linking
pub fn hash_receipt(receipt: &Receipt) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(domain::RECEIPT_CHAIN);
    hasher.update(receipt.ceremony_session_id);
    hasher.update([receipt.step_id]);
    hasher.update(receipt.prev_receipt_hash);
    hasher.update(receipt.user_id.as_bytes());
    let ts_bytes = receipt.timestamp.to_le_bytes();
    hasher.update(ts_bytes);
    hasher.update(receipt.nonce);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

fn mac_receipt_fields(mac: &mut HmacSha256, receipt: &Receipt) {
    mac.update(domain::RECEIPT_SIGN);
    mac.update(&receipt.ceremony_session_id);
    mac.update(&[receipt.step_id]);
    mac.update(&receipt.prev_receipt_hash);
    mac.update(receipt.user_id.as_bytes());
    mac.update(&receipt.timestamp.to_le_bytes());
    mac.update(&receipt.nonce);
}

/// Sign a receipt with HMAC (placeholder for Ed25519 receipt key from HSM)
pub fn sign_receipt(receipt: &mut Receipt, signing_key: &[u8; 64]) {
    let mut mac = HmacSha256::new_from_slice(signing_key).expect("HMAC key length is always valid");
    mac_receipt_fields(&mut mac, receipt);
    receipt.signature = mac.finalize().into_bytes().to_vec();
}

/// Verify a receipt's signature
pub fn verify_receipt_signature(receipt: &Receipt, signing_key: &[u8; 64]) -> bool {
    let mut mac = HmacSha256::new_from_slice(signing_key).expect("HMAC key length is always valid");
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
            if receipt.prev_receipt_hash != [0u8; 32] {
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

    /// Validate the complete chain
    pub fn validate(&self) -> Result<(), String> {
        if self.receipts.is_empty() {
            return Err("empty receipt chain".into());
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
