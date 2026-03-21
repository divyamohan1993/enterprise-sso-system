use milnet_common::error::MilnetError;
use milnet_common::types::Receipt;
use milnet_crypto::receipts::{hash_receipt, verify_receipt_signature};

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
    if receipts.is_empty() {
        return Err(MilnetError::ReceiptChain(
            "receipt chain must contain at least one receipt".into(),
        ));
    }

    let session_id = &receipts[0].ceremony_session_id;
    let dpop_hash = &receipts[0].dpop_key_hash;

    for (i, receipt) in receipts.iter().enumerate() {
        // Check session ID consistency
        if receipt.ceremony_session_id != *session_id {
            return Err(MilnetError::ReceiptChain(format!(
                "receipt {} has mismatched ceremony_session_id",
                i
            )));
        }

        // Check dpop_key_hash consistency
        if receipt.dpop_key_hash != *dpop_hash {
            return Err(MilnetError::ReceiptChain(format!(
                "receipt {} has mismatched dpop_key_hash",
                i
            )));
        }

        // Check hash chain linkage
        if i == 0 {
            if receipt.prev_receipt_hash != [0u8; 32] {
                return Err(MilnetError::ReceiptChain(
                    "first receipt must have zero prev_receipt_hash".into(),
                ));
            }
        } else {
            let expected_hash = hash_receipt(&receipts[i - 1]);
            if receipt.prev_receipt_hash != expected_hash {
                return Err(MilnetError::ReceiptChain(format!(
                    "receipt {} has invalid prev_receipt_hash",
                    i
                )));
            }
        }

        // Verify signature
        if !verify_receipt_signature(receipt, receipt_signing_key) {
            return Err(MilnetError::ReceiptChain(format!(
                "receipt {} has invalid signature",
                i
            )));
        }
    }

    Ok(())
}
