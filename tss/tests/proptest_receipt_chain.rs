use proptest::prelude::*;
use common::types::Receipt;
use crypto::receipts::{hash_receipt, sign_receipt};
use tss::validator::validate_receipt_chain;
use uuid::Uuid;

fn build_signed_chain(len: usize, signing_key: &[u8; 64]) -> Vec<Receipt> {
    let session_id = [0x01; 32];
    let dpop_hash = [0x02; 64];
    let mut chain = Vec::with_capacity(len);

    for i in 0..len {
        let prev_hash = if i == 0 {
            [0u8; 64]
        } else {
            hash_receipt(&chain[i - 1])
        };

        let mut receipt = Receipt {
            ceremony_session_id: session_id,
            step_id: (i + 1) as u8,
            prev_receipt_hash: prev_hash,
            user_id: Uuid::nil(),
            dpop_key_hash: dpop_hash,
            timestamp: 1_700_000_000_000_000 + (i as i64 * 1_000_000),
            nonce: [i as u8; 32],
            signature: Vec::new(),
            ttl_seconds: 30,
        };
        sign_receipt(&mut receipt, signing_key).unwrap();
        chain.push(receipt);
    }

    chain
}

const KEY: [u8; 64] = [0xAB; 64];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))] // I20

    /// Valid chain always validates.
    #[test]
    fn valid_chain_validates(len in 1usize..6) {
        let chain = build_signed_chain(len, &KEY);
        let result = validate_receipt_chain(&chain, &KEY);
        prop_assert!(result.is_ok(), "valid chain of length {} must pass: {:?}", len, result);
    }

    /// Modifying any receipt in the chain breaks validation.
    #[test]
    fn modifying_receipt_breaks_chain(
        len in 2usize..5,
        target_idx in 0usize..4,
    ) {
        let mut chain = build_signed_chain(len, &KEY);
        let idx = target_idx % len;

        // Tamper with the nonce of the target receipt (invalidates signature)
        chain[idx].nonce[0] ^= 0xFF;

        let result = validate_receipt_chain(&chain, &KEY);
        prop_assert!(result.is_err(), "modified receipt at index {} must break chain", idx);
    }

    /// Reordering receipts breaks validation.
    #[test]
    fn reordering_breaks_chain(len in 3usize..6) {
        let mut chain = build_signed_chain(len, &KEY);

        // Swap first and second receipts
        chain.swap(0, 1);

        let result = validate_receipt_chain(&chain, &KEY);
        prop_assert!(result.is_err(), "reordered chain must fail validation");
    }

    /// Duplicate receipts are detected.
    #[test]
    fn duplicate_receipts_detected(len in 2usize..5) {
        let chain = build_signed_chain(len, &KEY);

        // Duplicate the last receipt
        let mut duped = chain.clone();
        duped.push(chain[len - 1].clone());

        let result = validate_receipt_chain(&duped, &KEY);
        prop_assert!(result.is_err(), "chain with duplicate receipt must fail");
    }

    /// Chain with mismatched ceremony_session_id fails.
    #[test]
    fn mismatched_session_id_fails(len in 2usize..5) {
        let mut chain = build_signed_chain(len, &KEY);

        // Change the last receipt's session ID (re-sign to have valid sig but wrong session)
        chain[len - 1].ceremony_session_id = [0xFF; 32];
        sign_receipt(&mut chain[len - 1], &KEY).unwrap();

        let result = validate_receipt_chain(&chain, &KEY);
        prop_assert!(result.is_err(), "mismatched session ID must fail");
        let err = format!("{}", result.unwrap_err());
        prop_assert!(err.contains("ceremony_session_id"), "error must mention session ID");
    }
}
