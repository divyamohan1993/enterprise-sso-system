//! Integration tests for the OPAQUE password service.

use crypto::receipts::verify_receipt_signature;
use opaque::messages::OpaqueRequest;
use opaque::service::handle_request;
use opaque::store::CredentialStore;

/// Fixed signing key matching the one in service.rs (Phase 2 placeholder).
const SIGNING_KEY: [u8; 64] = [0x42u8; 64];

#[test]
fn store_register_and_verify() {
    let mut store = CredentialStore::new();
    let password = b"correct-horse-battery-staple";
    let user_id = store.register("alice", password);

    let result = store.verify("alice", password);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), user_id);
}

#[test]
fn store_wrong_password_rejected() {
    let mut store = CredentialStore::new();
    store.register("bob", b"real-password");

    let result = store.verify("bob", b"wrong-password");
    assert!(result.is_err());
}

#[test]
fn store_unknown_user_rejected() {
    let store = CredentialStore::new();
    let result = store.verify("nonexistent", b"any-password");
    assert!(result.is_err());
}

#[test]
fn receipt_is_properly_signed() {
    let mut store = CredentialStore::new();
    let password = b"test-password";
    store.register("charlie", password);

    let request = OpaqueRequest {
        username: "charlie".into(),
        password: password.to_vec(),
        ceremony_session_id: [0xAA; 32],
        dpop_key_hash: [0xBB; 32],
    };

    let response = handle_request(&store, &request, &SIGNING_KEY);
    assert!(response.success);

    let receipt = response.receipt.expect("receipt should be present");
    assert!(
        verify_receipt_signature(&receipt, &SIGNING_KEY),
        "receipt signature must be valid"
    );
}

#[test]
fn receipt_has_correct_fields() {
    let mut store = CredentialStore::new();
    let password = b"field-test-pw";
    let user_id = store.register("diana", password);

    let session_id = [0xCC; 32];
    let dpop_hash = [0xDD; 32];

    let request = OpaqueRequest {
        username: "diana".into(),
        password: password.to_vec(),
        ceremony_session_id: session_id,
        dpop_key_hash: dpop_hash,
    };

    let response = handle_request(&store, &request, &SIGNING_KEY);
    assert!(response.success);

    let receipt = response.receipt.expect("receipt should be present");
    assert_eq!(receipt.step_id, 1, "step_id must be 1 (first in chain)");
    assert_eq!(
        receipt.prev_receipt_hash, [0u8; 32],
        "prev_receipt_hash must be zeros for first receipt"
    );
    assert_eq!(
        receipt.ceremony_session_id, session_id,
        "ceremony_session_id must match request"
    );
    assert_eq!(
        receipt.user_id, user_id,
        "user_id must match registered user"
    );
    assert_eq!(
        receipt.dpop_key_hash, dpop_hash,
        "dpop_key_hash must match request"
    );
    assert!(receipt.timestamp > 0, "timestamp must be set");
    assert!(!receipt.signature.is_empty(), "signature must not be empty");
}
