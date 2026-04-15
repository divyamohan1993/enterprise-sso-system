//! CAT-B hardening regression tests for FIDO2.
//!
//! Covers:
//!   * B6 — AAGUID allow-list rejects unknown authenticators in military mode.
//!   * B7 — sign-count rollback locks the credential.
//!   * B9 — "none"/"fido-u2f" attestation formats rejected in military mode.

use fido::policy::{enforce_aaguid, enforce_attestation_format, military_mode};
use fido::types::{AuthenticationResult, StoredCredential};
use fido::verification::verify_authentication_response_with_lockout;
use serial_test::serial;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn make_auth_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
    let h = Sha256::digest(rp_id.as_bytes());
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&h);
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    data
}

#[test]
#[serial]
fn b6_unknown_aaguid_rejected_in_military_mode() {
    std::env::remove_var("MILNET_FIDO_AAGUID_ALLOWLIST");
    std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
    assert!(military_mode());
    let unknown = [0x99u8; 16];
    assert!(enforce_aaguid(&unknown).is_err());
    std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
}

#[test]
#[serial]
fn b9_none_format_rejected_in_military_mode() {
    std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
    assert!(enforce_attestation_format("none").is_err());
    assert!(enforce_attestation_format("fido-u2f").is_err());
    assert!(enforce_attestation_format("packed").is_ok());
    std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
}

#[test]
#[serial]
fn b7_sign_count_rollback_locks_credential() {
    let rp_id = "sso.milnet.example";
    let user_id = Uuid::new_v4();
    // sign_count goes BACKWARDS: stored=10, authenticator reports 5.
    let auth_data = make_auth_data(rp_id, 0x05, 5);
    let auth_result = AuthenticationResult {
        credential_id: vec![1, 2, 3],
        authenticator_data: auth_data,
        client_data: b"x".to_vec(),
        signature: vec![0x30, 0x44],
    };
    let mut stored = StoredCredential {
        credential_id: vec![1, 2, 3],
        public_key: vec![0x04; 65],
        user_id,
        sign_count: 10,
        authenticator_type: "cross-platform".into(),
            aaguid: [0u8; 16],
        cloned_flag: false,
        backup_eligible: false,
        backup_state: false,
        pq_attestation: Vec::new()
    };
    let res = verify_authentication_response_with_lockout(&auth_result, &mut stored, rp_id, true);
    assert!(res.is_err(), "rollback must be rejected");
    assert!(stored.cloned_flag, "credential must be marked cloned");

    // Subsequent authentication must remain locked, even if the next request
    // carries a "valid" sign count.
    let auth_data2 = make_auth_data(rp_id, 0x05, 100);
    let mut auth2 = auth_result.clone();
    auth2.authenticator_data = auth_data2;
    let res2 =
        verify_authentication_response_with_lockout(&auth2, &mut stored, rp_id, true);
    assert!(res2.is_err(), "locked credential must keep refusing");
}
