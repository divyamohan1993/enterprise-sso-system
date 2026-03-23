//! Security property tests — verifying critical invariants of the crypto layer.

use crypto::ct::{ct_eq, ct_eq_32, ct_eq_64};
use crypto::entropy::{generate_key_64, generate_nonce};
use crypto::receipts::{hash_receipt, sign_receipt, verify_receipt_signature, ReceiptChain};
use common::types::Receipt;

// ── Constant-time comparison security properties ────────────────────────────

#[test]
fn ct_eq_single_bit_difference_detected() {
    let a = [0u8; 32];
    let mut b = [0u8; 32];
    b[15] = 1; // single bit flip in the middle
    assert!(!ct_eq(&a, &b));
}

#[test]
fn ct_eq_32_all_zeros_vs_all_ones() {
    let zeros = [0x00u8; 32];
    let ones = [0xFFu8; 32];
    assert!(!ct_eq_32(&zeros, &ones));
}

#[test]
fn ct_eq_64_single_byte_difference() {
    let a = [0xAAu8; 64];
    let mut b = [0xAAu8; 64];
    b[63] = 0xBB;
    assert!(!ct_eq_64(&a, &b));
}

// ── Entropy uniqueness ──────────────────────────────────────────────────────

#[test]
fn generate_nonce_produces_unique_values() {
    let n1 = generate_nonce();
    let n2 = generate_nonce();
    let n3 = generate_nonce();
    assert_ne!(n1, n2);
    assert_ne!(n2, n3);
    assert_ne!(n1, n3);
}

#[test]
fn generate_key_64_nonzero() {
    let key = generate_key_64();
    assert_ne!(key, [0u8; 64], "64-byte key must not be all zeros");
}

#[test]
fn generate_key_64_halves_differ() {
    let key = generate_key_64();
    // The two halves come from separate combined_entropy() calls
    // so they should differ (with overwhelming probability)
    assert_ne!(&key[..32], &key[32..], "key halves should differ");
}

// ── Receipt chain security properties ───────────────────────────────────────

#[test]
fn receipt_signature_verified() {
    let key = [0x42u8; 64];
    let mut receipt = Receipt::test_fixture();
    sign_receipt(&mut receipt, &key);
    assert!(verify_receipt_signature(&receipt, &key));
}

#[test]
fn receipt_signature_rejects_wrong_key() {
    let key = [0x42u8; 64];
    let wrong_key = [0x99u8; 64];
    let mut receipt = Receipt::test_fixture();
    sign_receipt(&mut receipt, &key);
    assert!(!verify_receipt_signature(&receipt, &wrong_key));
}

#[test]
fn receipt_signature_rejects_tampered_data() {
    let key = [0x42u8; 64];
    let mut receipt = Receipt::test_fixture();
    sign_receipt(&mut receipt, &key);
    // Tamper with the step_id
    receipt.step_id = 99;
    assert!(!verify_receipt_signature(&receipt, &key));
}

#[test]
fn receipt_hash_deterministic() {
    let receipt = Receipt::test_fixture();
    let h1 = hash_receipt(&receipt);
    let h2 = hash_receipt(&receipt);
    assert_eq!(h1, h2);
}

#[test]
fn receipt_hash_differs_for_different_steps() {
    let mut r1 = Receipt::test_fixture();
    let mut r2 = Receipt::test_fixture();
    r1.step_id = 1;
    r2.step_id = 2;
    assert_ne!(hash_receipt(&r1), hash_receipt(&r2));
}

#[test]
fn receipt_chain_rejects_wrong_session_id() {
    let session_id = [0x01; 32];
    let mut chain = ReceiptChain::new(session_id);
    let mut receipt = Receipt::test_fixture();
    receipt.ceremony_session_id = [0x02; 32]; // wrong session
    receipt.prev_receipt_hash = [0x00; 64];
    receipt.step_id = 1;
    assert!(chain.add_receipt(receipt).is_err());
}

#[test]
fn receipt_chain_rejects_out_of_order_steps() {
    let session_id = [0x01; 32];
    let mut chain = ReceiptChain::new(session_id);
    let mut receipt = Receipt::test_fixture();
    receipt.step_id = 2; // should be 1 for first receipt
    receipt.prev_receipt_hash = [0x00; 64];
    assert!(chain.add_receipt(receipt).is_err());
}

#[test]
fn receipt_chain_empty_validation_fails() {
    let chain = ReceiptChain::new([0x01; 32]);
    assert!(chain.validate().is_err());
}

#[test]
fn receipt_chain_valid_two_step() {
    let session_id = [0x01; 32];
    let key = [0x42u8; 64];
    let mut chain = ReceiptChain::new(session_id);

    // Step 1
    let mut r1 = Receipt::test_fixture();
    r1.ceremony_session_id = session_id;
    r1.step_id = 1;
    r1.prev_receipt_hash = [0x00; 64];
    sign_receipt(&mut r1, &key);
    chain.add_receipt(r1.clone()).unwrap();

    // Step 2
    let mut r2 = Receipt::test_fixture();
    r2.ceremony_session_id = session_id;
    r2.step_id = 2;
    r2.prev_receipt_hash = hash_receipt(&r1);
    sign_receipt(&mut r2, &key);
    chain.add_receipt(r2).unwrap();

    assert_eq!(chain.len(), 2);
    assert!(chain.validate().is_ok());
    assert!(chain.validate_with_key(&key).is_ok());
}

#[test]
fn receipt_chain_rejects_invalid_signature() {
    let session_id = [0x01; 32];
    let key = [0x42u8; 64];
    let wrong_key = [0x99u8; 64];
    let mut chain = ReceiptChain::new(session_id);

    let mut r1 = Receipt::test_fixture();
    r1.ceremony_session_id = session_id;
    r1.step_id = 1;
    r1.prev_receipt_hash = [0x00; 64];
    sign_receipt(&mut r1, &wrong_key); // signed with wrong key
    chain.add_receipt(r1).unwrap();

    assert!(chain.validate_with_key(&key).is_err());
}
