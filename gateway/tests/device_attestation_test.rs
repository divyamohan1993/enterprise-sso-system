//! GW-ATTEST negative tests.
//!
//! Every reject path in `gateway::device_attestation::validate_assertion`
//! has an explicit test here. The happy path is covered by a positive
//! test at the bottom. All tests construct their own trust store via
//! `test_install_trust_store` so they do not touch the filesystem.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use gateway::device_attestation::{
    derive_session_nonce, sign_for_test, validate_assertion, AttestError,
    DeviceAttestationAssertion,
};

const SIGNER_ID: &str = "test-tpm-signer";

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn setup_trust() -> (crypto::pq_sign::PqSigningKey, Vec<u8>) {
    let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
    let encoded = vk.encode();
    let vk_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&encoded).to_vec();
    let mut store = HashMap::new();
    store.insert(SIGNER_ID.to_string(), vk_bytes.clone());
    gateway::device_attestation::test_install_trust_store(store);
    (sk, vk_bytes)
}

#[test]
fn happy_path_validates() {
    let (sk, _) = setup_trust();
    let session_key = b"happy-session-key-material";
    let nonce = derive_session_nonce(session_key);
    let a = sign_for_test(
        vec![1, 2, 3, 4],
        nonce,
        now_secs(),
        SIGNER_ID.into(),
        &sk,
    );
    let result = validate_assertion(&a, session_key);
    assert!(result.is_ok(), "expected Ok, got {:?}", result);
}

#[test]
fn rejects_stale_assertion() {
    let (sk, _) = setup_trust();
    let session_key = b"stale-session-key";
    let nonce = derive_session_nonce(session_key);
    // 1 hour old — well beyond the 300s default.
    let a = sign_for_test(
        vec![9; 16],
        nonce,
        now_secs().saturating_sub(3600),
        SIGNER_ID.into(),
        &sk,
    );
    let result = validate_assertion(&a, session_key);
    assert!(matches!(result, Err(AttestError::Stale { .. })));
}

#[test]
fn rejects_wrong_nonce() {
    let (sk, _) = setup_trust();
    let session_key = b"session-key-for-wrong-nonce";
    // Sign against a nonce from a DIFFERENT session key — replay attempt.
    let other_nonce = derive_session_nonce(b"some-other-session-key");
    let a = sign_for_test(
        vec![],
        other_nonce,
        now_secs(),
        SIGNER_ID.into(),
        &sk,
    );
    assert_eq!(validate_assertion(&a, session_key), Err(AttestError::WrongNonce));
}

#[test]
fn rejects_bad_signature() {
    let (sk, _) = setup_trust();
    let session_key = b"session-key-for-bad-sig";
    let nonce = derive_session_nonce(session_key);
    let mut a = sign_for_test(
        vec![0xab, 0xcd],
        nonce,
        now_secs(),
        SIGNER_ID.into(),
        &sk,
    );
    // Flip a signature bit.
    if let Some(b) = a.signature.first_mut() {
        *b ^= 0x01;
    }
    assert_eq!(validate_assertion(&a, session_key), Err(AttestError::BadSignature));
}

#[test]
fn rejects_unknown_signer() {
    let (sk, _) = setup_trust();
    let session_key = b"session-key-for-unknown-signer";
    let nonce = derive_session_nonce(session_key);
    let a = sign_for_test(
        vec![],
        nonce,
        now_secs(),
        "not-in-trust-store".into(),
        &sk,
    );
    match validate_assertion(&a, session_key) {
        Err(AttestError::UnknownSigner(id)) => assert_eq!(id, "not-in-trust-store"),
        other => panic!("expected UnknownSigner, got {:?}", other),
    }
}

#[test]
fn rejects_tampered_quote() {
    let (sk, _) = setup_trust();
    let session_key = b"session-key-for-tamper";
    let nonce = derive_session_nonce(session_key);
    let mut a = sign_for_test(
        vec![0x10, 0x20, 0x30],
        nonce,
        now_secs(),
        SIGNER_ID.into(),
        &sk,
    );
    // Mutate the quote AFTER signing — the signature no longer covers it.
    a.quote.push(0xff);
    assert_eq!(validate_assertion(&a, session_key), Err(AttestError::BadSignature));
}

#[test]
fn rejects_future_dated_assertion() {
    let (sk, _) = setup_trust();
    let session_key = b"session-key-for-future";
    let nonce = derive_session_nonce(session_key);
    // 10 minutes in the future — forgery or clock skew.
    let a = sign_for_test(
        vec![],
        nonce,
        now_secs().saturating_add(600),
        SIGNER_ID.into(),
        &sk,
    );
    assert!(matches!(validate_assertion(&a, session_key), Err(AttestError::Stale { .. })));
}

// Sanity check the canonical message builder is deterministic and
// collision-resistant across subtly-different assertions.
#[test]
fn assertion_struct_is_structurally_stable() {
    let a = DeviceAttestationAssertion {
        quote: vec![1, 2, 3],
        nonce: [0u8; 32],
        issued_at_secs: 1,
        signer_id: "x".into(),
        signature: vec![],
    };
    let b = DeviceAttestationAssertion {
        quote: vec![1, 2, 3],
        nonce: [0u8; 32],
        issued_at_secs: 2,
        signer_id: "x".into(),
        signature: vec![],
    };
    assert_ne!(
        gateway::device_attestation::canonical_message(&a),
        gateway::device_attestation::canonical_message(&b),
    );
}
