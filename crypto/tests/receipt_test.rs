use common::types::Receipt;
use crypto::receipts::{hash_receipt, sign_receipt, verify_receipt_signature, ReceiptChain};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const TEST_SESSION_ID: [u8; 32] = [0xAA; 32];
const TEST_USER_ID: Uuid = Uuid::nil();

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

fn make_receipt(step: u8, prev_hash: [u8; 64]) -> Receipt {
    Receipt {
        ceremony_session_id: TEST_SESSION_ID,
        step_id: step,
        prev_receipt_hash: prev_hash,
        user_id: TEST_USER_ID,
        dpop_key_hash: [0xBB; 32],
        timestamp: now_micros(),
        nonce: [step; 32],
        signature: Vec::new(),
        ttl_seconds: 30,
    }
}

fn make_chain_of_3() -> (Receipt, Receipt, Receipt) {
    let r1 = make_receipt(1, [0u8; 64]);
    let h1 = hash_receipt(&r1);
    let r2 = make_receipt(2, h1);
    let h2 = hash_receipt(&r2);
    let r3 = make_receipt(3, h2);
    (r1, r2, r3)
}

#[test]
fn valid_chain_validates() {
    let (r1, r2, r3) = make_chain_of_3();
    let mut chain = ReceiptChain::new(TEST_SESSION_ID);
    chain.add_receipt(r1).unwrap();
    chain.add_receipt(r2).unwrap();
    chain.add_receipt(r3).unwrap();
    chain.validate().unwrap();
    assert_eq!(chain.len(), 3);
}

#[test]
fn mismatched_session_id_rejected() {
    let mut r1 = make_receipt(1, [0u8; 64]);
    r1.ceremony_session_id = [0xFF; 32]; // wrong session
    let mut chain = ReceiptChain::new(TEST_SESSION_ID);
    let err = chain.add_receipt(r1).unwrap_err();
    assert!(err.contains("session_id mismatch"));
}

#[test]
fn broken_hash_chain_rejected() {
    let r1 = make_receipt(1, [0u8; 64]);
    // Intentionally use wrong prev_hash for step 2
    let r2 = make_receipt(2, [0xDE; 64]);
    let mut chain = ReceiptChain::new(TEST_SESSION_ID);
    chain.add_receipt(r1).unwrap();
    let err = chain.add_receipt(r2).unwrap_err();
    assert!(err.contains("prev_receipt_hash does not match"));
}

#[test]
fn wrong_step_order_rejected() {
    let r1 = make_receipt(1, [0u8; 64]);
    let h1 = hash_receipt(&r1);
    // Skip step 2, go straight to step 3
    let r3 = make_receipt(3, h1);
    let mut chain = ReceiptChain::new(TEST_SESSION_ID);
    chain.add_receipt(r1).unwrap();
    let err = chain.add_receipt(r3).unwrap_err();
    assert!(err.contains("expected step 2, got 3"));
}

#[test]
fn receipt_signature_roundtrip() {
    let signing_key: [u8; 64] = [0x42; 64];
    let mut receipt = make_receipt(1, [0u8; 64]);
    sign_receipt(&mut receipt, &signing_key);
    assert!(!receipt.signature.is_empty());
    assert!(verify_receipt_signature(&receipt, &signing_key));
}

#[test]
fn tampered_receipt_fails_verification() {
    let signing_key: [u8; 64] = [0x42; 64];
    let mut receipt = make_receipt(1, [0u8; 64]);
    sign_receipt(&mut receipt, &signing_key);
    // Tamper with the nonce after signing
    receipt.nonce[0] ^= 0xFF;
    assert!(!verify_receipt_signature(&receipt, &signing_key));
}

#[test]
fn empty_chain_fails() {
    let chain = ReceiptChain::new(TEST_SESSION_ID);
    let err = chain.validate().unwrap_err();
    assert!(err.contains("empty receipt chain"));
}
