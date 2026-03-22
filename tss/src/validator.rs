use common::error::MilnetError;
use common::types::Receipt;
use crypto::ct::ct_eq;
use crypto::receipts::{hash_receipt, verify_receipt_signature};

/// Specifies which receipt verification method(s) to use.
pub enum ReceiptVerificationKey<'a> {
    /// HMAC-SHA512 symmetric key (legacy).
    Hmac(&'a [u8; 64]),
    /// Ed25519 asymmetric public key (preferred).
    /// Another agent is adding `verify_receipt_asymmetric` to crypto/receipts.rs.
    Ed25519(&'a [u8; 32]),
    /// Both keys available — prefer Ed25519, fall back to HMAC.
    Both {
        hmac_key: &'a [u8; 64],
        ed25519_key: &'a [u8; 32],
    },
}

/// Verify a single receipt's signature using the specified key.
///
/// When `Both` keys are provided, Ed25519 is preferred.  HMAC is only
/// attempted if no Ed25519 key is available.
fn verify_receipt_with_key(receipt: &Receipt, key: &ReceiptVerificationKey<'_>) -> bool {
    match key {
        ReceiptVerificationKey::Hmac(hmac_key) => {
            verify_receipt_signature(receipt, hmac_key)
        }
        ReceiptVerificationKey::Ed25519(ed25519_key) => {
            let data = crypto::receipts::receipt_signing_data(receipt);
            crypto::receipts::verify_receipt_asymmetric(*ed25519_key, &data, &receipt.signature)
        }
        ReceiptVerificationKey::Both { hmac_key, ed25519_key } => {
            // Prefer Ed25519 when available; fall back to HMAC for
            // receipts that were signed before the Ed25519 migration.
            let data = crypto::receipts::receipt_signing_data(receipt);
            if crypto::receipts::verify_receipt_asymmetric(*ed25519_key, &data, &receipt.signature) {
                true
            } else {
                verify_receipt_signature(receipt, hmac_key)
            }
        }
    }
}

/// Validate a receipt chain for submission to the TSS.
///
/// Checks:
/// 1. At least one receipt is present.
/// 2. All receipts share the same `ceremony_session_id`.
/// 3. Sequential `prev_receipt_hash` chain (first is zeros, each subsequent =
///    hash_receipt of the previous receipt).
/// 4. All receipts have valid signatures against the provided key.
/// 5. All `dpop_key_hash` values match across receipts.
pub fn validate_receipt_chain(
    receipts: &[Receipt],
    receipt_signing_key: &[u8; 64],
) -> Result<(), MilnetError> {
    validate_receipt_chain_with_key(receipts, &ReceiptVerificationKey::Hmac(receipt_signing_key))
}

/// Validate a receipt chain with flexible key support (HMAC, Ed25519, or both).
///
/// This is the preferred entry point when Ed25519 receipt signing is available.
/// When `ReceiptVerificationKey::Both` is used, Ed25519 is tried first with
/// HMAC as a fallback, enabling a smooth migration from symmetric to asymmetric
/// receipt signatures.
pub fn validate_receipt_chain_with_key(
    receipts: &[Receipt],
    verification_key: &ReceiptVerificationKey<'_>,
) -> Result<(), MilnetError> {
    if receipts.is_empty() {
        return Err(MilnetError::ReceiptChain(
            "receipt chain must contain at least one receipt".into(),
        ));
    }

    let session_id = &receipts[0].ceremony_session_id;
    let dpop_hash = &receipts[0].dpop_key_hash;

    for (i, receipt) in receipts.iter().enumerate() {
        // Check session ID consistency (constant-time)
        if !ct_eq(&receipt.ceremony_session_id, session_id) {
            return Err(MilnetError::ReceiptChain(format!(
                "receipt {} has mismatched ceremony_session_id",
                i
            )));
        }

        // Check dpop_key_hash consistency (constant-time)
        if !ct_eq(&receipt.dpop_key_hash, dpop_hash) {
            return Err(MilnetError::ReceiptChain(format!(
                "receipt {} has mismatched dpop_key_hash",
                i
            )));
        }

        // Check hash chain linkage
        if i == 0 {
            if !ct_eq(&receipt.prev_receipt_hash, &[0u8; 64]) {
                return Err(MilnetError::ReceiptChain(
                    "first receipt must have zero prev_receipt_hash".into(),
                ));
            }
        } else {
            let expected_hash = hash_receipt(&receipts[i - 1]);
            if !ct_eq(&receipt.prev_receipt_hash, &expected_hash) {
                return Err(MilnetError::ReceiptChain(format!(
                    "receipt {} has invalid prev_receipt_hash",
                    i
                )));
            }
        }

        // Verify signature using the provided key method
        if !verify_receipt_with_key(receipt, verification_key) {
            return Err(MilnetError::ReceiptChain(format!(
                "receipt {} has invalid signature",
                i
            )));
        }
    }

    Ok(())
}
