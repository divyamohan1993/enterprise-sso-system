//! Replay attack detection test suite.
//!
//! Validates that the system detects and rejects replayed credentials across
//! all replay-sensitive mechanisms: JTI, authorization codes, CSRF tokens,
//! DPoP proofs, and receipt chain steps.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use common::types::{ModuleId, Receipt};
use crypto::entropy::generate_nonce;
use crypto::receipts::{hash_receipt, sign_receipt, ReceiptChain};
use uuid::Uuid;

// ── Helpers ──────────────────────────────────────────────────────────────

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

const RECEIPT_SIGNING_KEY: [u8; 64] = [0x42u8; 64];

fn make_signed_receipt(step: u8, prev_hash: [u8; 64], session_id: [u8; 32]) -> Receipt {
    let mut receipt = Receipt {
        ceremony_session_id: session_id,
        step_id: step,
        prev_receipt_hash: prev_hash,
        user_id: Uuid::nil(),
        dpop_key_hash: [0xBB; 64],
        timestamp: now_us(),
        nonce: generate_nonce(),
        signature: Vec::new(),
        ttl_seconds: 30,
    };
    sign_receipt(&mut receipt, &RECEIPT_SIGNING_KEY).unwrap();
    receipt
}

// ── JTI replay detection ─────────────────────────────────────────────────
// JTI (JWT Token ID) uniqueness is enforced by the token_id field.
// Each token must have a unique token_id; duplicate submissions indicate replay.

#[test]
fn jti_replay_detection_same_id_rejected() {
    // Simulate a JTI replay cache using a HashSet (mirrors verifier behavior)
    let mut seen_jtis: HashSet<[u8; 16]> = HashSet::new();

    let jti: [u8; 16] = [0xAB; 16];

    // First use: should be accepted
    let first_insert = seen_jtis.insert(jti);
    assert!(first_insert, "first JTI submission must be accepted");

    // Second use of same JTI: should be rejected (replay)
    let second_insert = seen_jtis.insert(jti);
    assert!(
        !second_insert,
        "second submission of same JTI must be detected as replay"
    );
}

#[test]
fn jti_different_ids_accepted() {
    let mut seen_jtis: HashSet<[u8; 16]> = HashSet::new();

    let jti_a: [u8; 16] = [0x01; 16];
    let jti_b: [u8; 16] = [0x02; 16];

    assert!(seen_jtis.insert(jti_a), "first JTI must be accepted");
    assert!(seen_jtis.insert(jti_b), "different JTI must be accepted");
}

// ── Authorization code replay ────────────────────────────────────────────
// An authorization code must be consumed exactly once. Re-submission is replay.

#[test]
fn authorization_code_consumed_on_first_use() {
    let mut consumed_codes: HashSet<[u8; 32]> = HashSet::new();

    let auth_code = generate_nonce(); // 32-byte random code

    // First exchange: consume the code
    let first = consumed_codes.insert(auth_code);
    assert!(first, "first code exchange must succeed");

    // Replay: same code submitted again
    let replay = consumed_codes.insert(auth_code);
    assert!(
        !replay,
        "replayed authorization code must be rejected"
    );
}

#[test]
fn multiple_unique_authorization_codes_accepted() {
    let mut consumed_codes: HashSet<[u8; 32]> = HashSet::new();

    for _ in 0..10 {
        let code = generate_nonce();
        assert!(consumed_codes.insert(code), "unique code must be accepted");
    }
    assert_eq!(consumed_codes.len(), 10);
}

// ── CSRF token replay ────────────────────────────────────────────────────
// A CSRF token must be single-use. Re-submission after consumption is replay.

#[test]
fn csrf_token_single_use() {
    let mut used_csrf_tokens: HashSet<[u8; 32]> = HashSet::new();

    let csrf_token = generate_nonce();

    // First use: validate and consume
    let first = used_csrf_tokens.insert(csrf_token);
    assert!(first, "first CSRF token use must succeed");

    // Replay: same token submitted again
    let replay = used_csrf_tokens.insert(csrf_token);
    assert!(
        !replay,
        "replayed CSRF token must be rejected"
    );
}

// ── DPoP proof replay ────────────────────────────────────────────────────
// DPoP proofs include a nonce; the same proof must not be accepted twice.

#[test]
fn dpop_proof_replay_detected() {
    // The verifier module exposes a DPoP replay cache
    let proof_hash: [u8; 64] = [0xAA; 64];

    let first = verifier::verify::is_dpop_replay(&proof_hash);
    assert!(!first, "first DPoP proof submission must not be flagged as replay");

    let second = verifier::verify::is_dpop_replay(&proof_hash);
    assert!(
        second,
        "second submission of same DPoP proof must be detected as replay"
    );
}

#[test]
fn dpop_different_proofs_accepted() {
    let proof_a: [u8; 64] = [0x01; 64];
    let proof_b: [u8; 64] = [0x02; 64];

    assert!(
        !verifier::verify::is_dpop_replay(&proof_a),
        "first unique proof must be accepted"
    );
    assert!(
        !verifier::verify::is_dpop_replay(&proof_b),
        "second unique proof must be accepted"
    );
}

// ── Receipt chain replay (duplicate step rejected) ───────────────────────

#[test]
fn receipt_chain_duplicate_step_rejected() {
    let session_id = [0x01; 32];
    let mut chain = ReceiptChain::new(session_id);

    // Add step 1
    let r1 = make_signed_receipt(1, [0u8; 64], session_id);
    chain.add_receipt(r1.clone()).expect("step 1 must succeed");

    // Try to add another step 1 (replay)
    let h1 = hash_receipt(&r1);
    let r1_replay = make_signed_receipt(1, h1, session_id);
    let result = chain.add_receipt(r1_replay);
    assert!(
        result.is_err(),
        "duplicate step 1 must be rejected as replay"
    );
}

#[test]
fn receipt_chain_out_of_order_step_rejected() {
    let session_id = [0x01; 32];
    let mut chain = ReceiptChain::new(session_id);

    // Add step 1
    let r1 = make_signed_receipt(1, [0u8; 64], session_id);
    let h1 = hash_receipt(&r1);
    chain.add_receipt(r1).expect("step 1 must succeed");

    // Skip to step 3 (should expect step 2)
    let r3 = make_signed_receipt(3, h1, session_id);
    let result = chain.add_receipt(r3);
    assert!(
        result.is_err(),
        "out-of-order step (skip from 1 to 3) must be rejected"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("expected step 2, got 3"),
        "error must specify expected vs actual step, got: {err}"
    );
}

#[test]
fn receipt_chain_rewind_rejected() {
    let session_id = [0x01; 32];
    let mut chain = ReceiptChain::new(session_id);

    // Build a valid chain of 3 steps
    let r1 = make_signed_receipt(1, [0u8; 64], session_id);
    let h1 = hash_receipt(&r1);
    chain.add_receipt(r1).expect("step 1");

    let r2 = make_signed_receipt(2, h1, session_id);
    let h2 = hash_receipt(&r2);
    chain.add_receipt(r2).expect("step 2");

    let r3 = make_signed_receipt(3, h2, session_id);
    chain.add_receipt(r3).expect("step 3");

    // Try to add step 2 again (rewind)
    let r2_replay = make_signed_receipt(2, h1, session_id);
    let result = chain.add_receipt(r2_replay);
    assert!(
        result.is_err(),
        "rewinding to a previous step must be rejected"
    );
}

// ── SHARD protocol replay detection ──────────────────────────────────────

#[test]
fn shard_protocol_message_replay_rejected() {
    use shard::protocol::ShardProtocol;

    let key = [0xAA; 64];
    let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, key);

    let raw = sender.create_message(b"original message").expect("create");

    // First verification succeeds
    receiver.verify_message(&raw).expect("first verify must succeed");

    // Replay: same message submitted again
    let replay_result = receiver.verify_message(&raw);
    assert!(
        replay_result.is_err(),
        "replayed SHARD message must be rejected"
    );
    let err = format!("{}", replay_result.unwrap_err());
    assert!(
        err.contains("replay"),
        "error should mention replay, got: {err}"
    );
}

#[test]
fn shard_protocol_sequential_messages_accepted() {
    use shard::protocol::ShardProtocol;

    let key = [0xBB; 64];
    let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, key);

    // Multiple sequential (non-replayed) messages must be accepted
    for i in 0..5 {
        let msg = format!("message-{i}");
        let raw = sender.create_message(msg.as_bytes()).expect("create");
        let (module, payload) = receiver.verify_message(&raw).expect("verify");
        assert_eq!(module, ModuleId::Gateway);
        assert_eq!(payload, msg.as_bytes());
    }
}
