//! Tests for the TSS receipt chain validator (tss/src/validator.rs).
//!
//! Covers: validate_receipt_chain, validate_receipt_chain_with_key,
//! ReceiptVerificationKey variants (Hmac, MlDsa87, Both), chain linkage,
//! session/dpop consistency, empty chain rejection, signature verification,
//! and the PQ-only env var fallback gate.

use common::types::Receipt;
use crypto::receipts::{hash_receipt, sign_receipt};
use serial_test::serial;
use tss::validator::{validate_receipt_chain, validate_receipt_chain_with_key, ReceiptVerificationKey};
use uuid::Uuid;

// ── Constants ────────────────────────────────────────────────────────────

const SIGNING_KEY_A: [u8; 64] = [0x42u8; 64];
const SIGNING_KEY_B: [u8; 64] = [0x99u8; 64];

// ── Helpers ──────────────────────────────────────────────────────────────

fn build_chain(len: usize, key: &[u8; 64]) -> Vec<Receipt> {
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
        sign_receipt(&mut receipt, key).unwrap();
        chain.push(receipt);
    }
    chain
}

// ── validate_receipt_chain (HMAC path) ──────────────────────────────────

#[test]
fn empty_chain_rejected() {
    let result = validate_receipt_chain(&[], &SIGNING_KEY_A);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("at least one"), "expected empty chain error, got: {msg}");
}

#[test]
fn single_receipt_valid() {
    let chain = build_chain(1, &SIGNING_KEY_A);
    assert!(validate_receipt_chain(&chain, &SIGNING_KEY_A).is_ok());
}

#[test]
fn multi_receipt_valid() {
    let chain = build_chain(5, &SIGNING_KEY_A);
    assert!(validate_receipt_chain(&chain, &SIGNING_KEY_A).is_ok());
}

#[test]
fn wrong_signing_key_rejected() {
    let chain = build_chain(2, &SIGNING_KEY_A);
    let result = validate_receipt_chain(&chain, &SIGNING_KEY_B);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("invalid signature"), "got: {msg}");
}

#[test]
fn tampered_prev_hash_rejected() {
    let mut chain = build_chain(3, &SIGNING_KEY_A);
    // Break linkage at receipt 1 (set wrong prev hash, re-sign so sig is valid)
    chain[1].prev_receipt_hash = [0xFF; 64];
    sign_receipt(&mut chain[1], &SIGNING_KEY_A).unwrap();
    let result = validate_receipt_chain(&chain, &SIGNING_KEY_A);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("prev_receipt_hash"), "got: {msg}");
}

#[test]
fn first_receipt_nonzero_prev_hash_rejected() {
    let mut chain = build_chain(1, &SIGNING_KEY_A);
    chain[0].prev_receipt_hash = [0xAA; 64];
    sign_receipt(&mut chain[0], &SIGNING_KEY_A).unwrap();
    let result = validate_receipt_chain(&chain, &SIGNING_KEY_A);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("zero prev_receipt_hash"), "got: {msg}");
}

#[test]
fn mismatched_session_id_rejected() {
    let mut chain = build_chain(2, &SIGNING_KEY_A);
    chain[1].ceremony_session_id = [0xFF; 32];
    sign_receipt(&mut chain[1], &SIGNING_KEY_A).unwrap();
    let result = validate_receipt_chain(&chain, &SIGNING_KEY_A);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("ceremony_session_id"), "got: {msg}");
}

#[test]
fn mismatched_dpop_key_hash_rejected() {
    let mut chain = build_chain(2, &SIGNING_KEY_A);
    chain[1].dpop_key_hash = [0xFF; 64];
    sign_receipt(&mut chain[1], &SIGNING_KEY_A).unwrap();
    let result = validate_receipt_chain(&chain, &SIGNING_KEY_A);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("dpop_key_hash"), "got: {msg}");
}

#[test]
fn corrupted_signature_rejected() {
    let mut chain = build_chain(1, &SIGNING_KEY_A);
    chain[0].signature = vec![0xFF; 64];
    let result = validate_receipt_chain(&chain, &SIGNING_KEY_A);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("invalid signature"), "got: {msg}");
}

#[test]
fn empty_signature_rejected() {
    let mut chain = build_chain(1, &SIGNING_KEY_A);
    chain[0].signature = Vec::new();
    let result = validate_receipt_chain(&chain, &SIGNING_KEY_A);
    assert!(result.is_err());
}

// ── validate_receipt_chain_with_key (ReceiptVerificationKey variants) ────

#[test]
fn hmac_key_variant_works() {
    let chain = build_chain(2, &SIGNING_KEY_A);
    let key = ReceiptVerificationKey::Hmac(&SIGNING_KEY_A);
    assert!(validate_receipt_chain_with_key(&chain, &key).is_ok());
}

#[test]
fn hmac_key_variant_wrong_key_rejected() {
    let chain = build_chain(1, &SIGNING_KEY_A);
    let key = ReceiptVerificationKey::Hmac(&SIGNING_KEY_B);
    assert!(validate_receipt_chain_with_key(&chain, &key).is_err());
}

#[test]
#[serial]
fn both_key_variant_hmac_fallback() {
    // Receipts signed with HMAC only. When Both is provided with a bogus
    // ML-DSA-87 key, HMAC fallback should still validate in non-military mode.
    let chain = build_chain(1, &SIGNING_KEY_A);
    let bogus_mldsa = [0u8; 32]; // wrong size, will fail ML-DSA-87 verify
    let key = ReceiptVerificationKey::Both {
        hmac_key: &SIGNING_KEY_A,
        mldsa87_key: &bogus_mldsa,
    };
    // Ensure both env vars are NOT set for this test
    std::env::remove_var("MILNET_RECEIPT_PQ_ONLY");
    std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    assert!(validate_receipt_chain_with_key(&chain, &key).is_ok());
}

#[test]
#[serial]
fn both_key_pq_only_blocks_hmac_fallback() {
    // When MILNET_RECEIPT_PQ_ONLY is set, Both requires AND logic (both must pass).
    // With bogus ML-DSA key, PQ fails, so chain must be rejected.
    let chain = build_chain(1, &SIGNING_KEY_A);
    let bogus_mldsa = [0u8; 32];
    let key = ReceiptVerificationKey::Both {
        hmac_key: &SIGNING_KEY_A,
        mldsa87_key: &bogus_mldsa,
    };
    std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    std::env::set_var("MILNET_RECEIPT_PQ_ONLY", "1");
    let result = validate_receipt_chain_with_key(&chain, &key);
    std::env::remove_var("MILNET_RECEIPT_PQ_ONLY");
    assert!(result.is_err(), "PQ-only mode must require both signatures to pass");
}

#[test]
#[serial]
fn military_mode_defaults_pq_only() {
    // In military deployment mode, MILNET_RECEIPT_PQ_ONLY defaults to enforced.
    // With bogus ML-DSA key, chain must be rejected even without explicit PQ_ONLY.
    let chain = build_chain(1, &SIGNING_KEY_A);
    let bogus_mldsa = [0u8; 32];
    let key = ReceiptVerificationKey::Both {
        hmac_key: &SIGNING_KEY_A,
        mldsa87_key: &bogus_mldsa,
    };
    std::env::remove_var("MILNET_RECEIPT_PQ_ONLY");
    std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
    let result = validate_receipt_chain_with_key(&chain, &key);
    std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    assert!(result.is_err(), "military mode must default to PQ-only (AND logic)");
}

#[test]
#[serial]
fn military_mode_pq_only_override_disabled() {
    // Military mode with MILNET_RECEIPT_PQ_ONLY explicitly set to "0" disables PQ-only.
    // HMAC fallback should work in this case.
    let chain = build_chain(1, &SIGNING_KEY_A);
    let bogus_mldsa = [0u8; 32];
    let key = ReceiptVerificationKey::Both {
        hmac_key: &SIGNING_KEY_A,
        mldsa87_key: &bogus_mldsa,
    };
    std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
    std::env::set_var("MILNET_RECEIPT_PQ_ONLY", "0");
    let result = validate_receipt_chain_with_key(&chain, &key);
    std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
    std::env::remove_var("MILNET_RECEIPT_PQ_ONLY");
    assert!(result.is_ok(), "explicit PQ_ONLY=0 overrides military default");
}

#[test]
fn mldsa87_only_rejects_hmac_signed_receipts() {
    // Receipts signed with HMAC. Verifying with MlDsa87 variant (bogus key)
    // must fail because it only tries ML-DSA-87.
    let chain = build_chain(1, &SIGNING_KEY_A);
    let bogus_mldsa = [0u8; 32];
    let key = ReceiptVerificationKey::MlDsa87(&bogus_mldsa);
    assert!(validate_receipt_chain_with_key(&chain, &key).is_err());
}

// ── Edge cases ──────────────────────────────────────────────────────────

#[test]
fn long_chain_valid() {
    // 20-receipt chain
    let chain = build_chain(20, &SIGNING_KEY_A);
    assert!(validate_receipt_chain(&chain, &SIGNING_KEY_A).is_ok());
}

#[test]
fn chain_with_middle_receipt_tampered_rejected() {
    let mut chain = build_chain(5, &SIGNING_KEY_A);
    // Tamper with receipt index 2's nonce (changes its hash, breaking link at index 3)
    chain[2].nonce = [0xFF; 32];
    sign_receipt(&mut chain[2], &SIGNING_KEY_A).unwrap();
    // Receipt 2 itself has valid prev_receipt_hash and signature, but receipt 3's
    // prev_receipt_hash no longer matches hash_receipt(chain[2]).
    let result = validate_receipt_chain(&chain, &SIGNING_KEY_A);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("receipt 3") || msg.contains("prev_receipt_hash"), "got: {msg}");
}

#[test]
fn duplicate_receipts_break_chain() {
    // Duplicating a receipt breaks the hash chain linkage.
    let chain = build_chain(2, &SIGNING_KEY_A);
    let mut dup_chain = vec![chain[0].clone(), chain[0].clone()];
    // Second receipt has prev_hash = zeros (same as first), but should have
    // hash_receipt(chain[0]).
    let result = validate_receipt_chain(&dup_chain, &SIGNING_KEY_A);
    // The second receipt's prev_receipt_hash is [0;64] but hash_receipt(chain[0]) is not.
    assert!(result.is_err());
}

#[test]
fn reversed_chain_rejected() {
    let chain = build_chain(3, &SIGNING_KEY_A);
    let reversed: Vec<Receipt> = chain.into_iter().rev().collect();
    // First receipt in reversed chain has non-zero prev_receipt_hash.
    let result = validate_receipt_chain(&reversed, &SIGNING_KEY_A);
    assert!(result.is_err());
}
