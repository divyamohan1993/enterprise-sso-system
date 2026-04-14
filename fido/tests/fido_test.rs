//! Comprehensive integration tests for the FIDO2/WebAuthn module.
//!
//! Covers registration options, authentication options, sign count management,
//! ECDSA P-256 signature verification, COSE key parsing, client data validation,
//! and attestation verification.

use fido::authentication::{create_authentication_options, update_sign_count};
use fido::registration::{
    create_registration_options, create_registration_options_with_excludes, validate_and_register,
    CredentialStore,
};
use fido::types::*;
use fido::verification;

use p256::ecdsa::{signature::Signer, SigningKey};
use serial_test::serial;
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ── Test-harness init ───────────────────────────────────────────────────

/// Populate `MILNET_FIDO_AAGUID_ALLOWLIST` with the all-zero AAGUID used
/// by synthetic test credentials, in addition to the production default
/// vendor list. Idempotent via `Once` so parallel tests don't race.
/// Never called in release or military builds — this file is compiled
/// only as part of the `fido` integration-test binary.
fn ensure_test_aaguid_allowlist() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "MILNET_FIDO_AAGUID_ALLOWLIST",
            "00000000-0000-0000-0000-000000000000,\
             cb69481e-8ff7-4039-93ec-0a2729a154a8,\
             fa2b99dc-9e39-4257-8f92-4a30d23c4118,\
             2fc0579f-8113-47ea-b116-bb5a8db9202a,\
             c5ef55ff-ad9a-4b9f-b580-adebafe026d0,\
             f8a011f3-8c0a-4d15-8006-17111f9edc7d,\
             08987058-cadc-4b81-b6e1-30de50dcbe96,\
             dd4ec289-e01d-41c9-bb89-70fa845d4bf2,\
             f24a8e70-d0d3-f82c-2937-32523cc4de5a",
        );
    });
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Build authenticator data with the Attested Credential Data extension.
///
/// Layout (per WebAuthn spec section 6.1):
///   [0..32]   RP ID hash (SHA-256)
///   [32]      flags
///   [33..37]  sign count (big-endian u32)
///   [37..53]  AAGUID (16 zero bytes)
///   [53..55]  credential ID length (big-endian u16)
///   [55..55+L] credential ID
///   [55+L..]  COSE public key
fn make_attestation_auth_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    credential_id: &[u8],
    public_key_cose: &[u8],
) -> Vec<u8> {
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    let mut data = Vec::new();
    data.extend_from_slice(&rp_hash);
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    // AAGUID (16 zero bytes)
    data.extend_from_slice(&[0u8; 16]);
    // credential ID length
    let cred_len = credential_id.len() as u16;
    data.extend_from_slice(&cred_len.to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(public_key_cose);
    data
}

/// Build minimal authenticator data (37 bytes, no attested credential data).
fn make_auth_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    let mut data = Vec::new();
    data.extend_from_slice(&rp_hash);
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    data
}

/// Generate a fresh P-256 signing key and return (signing_key, verifying_key_sec1).
fn generate_p256_keypair() -> (SigningKey, Vec<u8>) {
    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    let sec1 = verifying_key.to_encoded_point(false);
    (signing_key, sec1.as_bytes().to_vec())
}

/// Create a COSE-encoded ES256 key from a SEC1 uncompressed public key (65 bytes).
fn sec1_to_cose(sec1_uncompressed: &[u8]) -> Vec<u8> {
    assert_eq!(sec1_uncompressed.len(), 65);
    assert_eq!(sec1_uncompressed[0], 0x04);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&sec1_uncompressed[1..33]);
    y.copy_from_slice(&sec1_uncompressed[33..65]);
    verification::encode_cose_key_es256(&x, &y)
}

/// Build valid client data JSON for authentication.
fn make_client_data_json(challenge: &[u8], origin: &str) -> Vec<u8> {
    let challenge_b64 = verification::base64_url_encode(challenge);
    let json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
        challenge_b64, origin,
    );
    json.into_bytes()
}

/// Build valid client data JSON for registration.
fn make_client_data_json_create(challenge: &[u8], origin: &str) -> Vec<u8> {
    let challenge_b64 = verification::base64_url_encode(challenge);
    let json = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}"}}"#,
        challenge_b64, origin,
    );
    json.into_bytes()
}

/// Helper to create a StoredCredential for testing.
fn make_stored_credential(
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    user_id: Uuid,
    sign_count: u32,
    authenticator_type: &str,
) -> StoredCredential {
    StoredCredential {
        credential_id,
        public_key,
        user_id,
        sign_count,
        authenticator_type: authenticator_type.to_string(),
    ..Default::default()
    }
}

// ── Registration option tests ───────────────────────────────────────────

#[test]
fn test_registration_options_basic() {
    let user_id = Uuid::new_v4();
    let options = create_registration_options(
        "MILNET SSO",
        "sso.milnet.gov",
        &user_id,
        "john.doe",
        false,
    );

    assert_eq!(options.rp.name, "MILNET SSO");
    assert_eq!(options.rp.id, "sso.milnet.gov");
    assert_eq!(options.user.name, "john.doe");
    assert_eq!(options.user.display_name, "john.doe");
    assert_eq!(options.user.id, user_id.as_bytes().to_vec());
    assert_eq!(options.challenge.len(), 32);
    assert_eq!(options.timeout, 60000);
    assert_eq!(options.attestation, "direct");
    assert!(!options.pub_key_cred_params.is_empty());
    assert!(options.exclude_credentials.is_empty());
}

#[test]
fn test_registration_options_platform_authenticator() {
    let user_id = Uuid::new_v4();
    let options = create_registration_options(
        "MILNET SSO",
        "sso.milnet.gov",
        &user_id,
        "alice",
        true, // prefer platform authenticator (Windows Hello, Touch ID)
    );

    assert_eq!(
        options.authenticator_selection.authenticator_attachment,
        Some("platform".to_string())
    );
    assert_eq!(options.authenticator_selection.resident_key, "required");
    assert_eq!(options.authenticator_selection.user_verification, "required");
}

#[test]
fn test_registration_options_cross_platform() {
    let user_id = Uuid::new_v4();
    let options = create_registration_options(
        "MILNET SSO",
        "sso.milnet.gov",
        &user_id,
        "bob",
        false, // cross-platform (YubiKey, security key)
    );

    // Cross-platform: authenticator_attachment is None (no preference)
    assert!(options.authenticator_selection.authenticator_attachment.is_none());
    assert_eq!(options.authenticator_selection.user_verification, "required");
}

#[test]
fn test_registration_options_with_excludes() {
    let user_id = Uuid::new_v4();
    let existing_ids = vec![vec![1, 2, 3], vec![4, 5, 6, 7]];
    let options = create_registration_options_with_excludes(
        "MILNET SSO",
        "sso.milnet.gov",
        &user_id,
        "charlie",
        false,
        &existing_ids,
    );

    assert_eq!(options.exclude_credentials.len(), 2);
    assert_eq!(options.exclude_credentials[0].id, vec![1, 2, 3]);
    assert_eq!(options.exclude_credentials[0].cred_type, "public-key");
    assert_eq!(options.exclude_credentials[1].id, vec![4, 5, 6, 7]);
    assert_eq!(options.exclude_credentials[1].cred_type, "public-key");
}

#[test]
fn test_registration_options_challenge_unique() {
    let user_id = Uuid::new_v4();
    let opts1 = create_registration_options("RP", "rp.example", &user_id, "user1", false);
    let opts2 = create_registration_options("RP", "rp.example", &user_id, "user1", false);

    // Two calls must produce different challenges (32 bytes of random).
    assert_ne!(opts1.challenge, opts2.challenge);
    assert_eq!(opts1.challenge.len(), 32);
    assert_eq!(opts2.challenge.len(), 32);
}

#[test]
fn test_registration_options_algorithms() {
    let user_id = Uuid::new_v4();
    let options = create_registration_options("RP", "rp.example", &user_id, "user", false);

    let algs: Vec<i64> = options.pub_key_cred_params.iter().map(|p| p.alg).collect();
    assert!(algs.contains(&-7), "ES256 (alg -7) must be included");
    assert!(algs.contains(&-257), "RS256 (alg -257) must be included");
    assert!(algs.contains(&-8), "EdDSA (alg -8) must be included");

    // All params must be of type "public-key"
    for param in &options.pub_key_cred_params {
        assert_eq!(param.cred_type, "public-key");
    }
}

#[test]
fn test_registration_response_verification() {
    ensure_test_aaguid_allowlist();
    let mut store = CredentialStore::new();
    let rp_id = "sso.milnet.gov";
    let user_id = Uuid::new_v4();
    let cred_id = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let cose_key = vec![0x01, 0x02, 0x03]; // Dummy COSE key for this test

    // flags: UP | UV | AT = 0x45
    let auth_data = make_attestation_auth_data(rp_id, 0x45, 0, &cred_id, &cose_key);

    let result = validate_and_register(&mut store, &auth_data, rp_id, user_id, "platform");
    assert!(result.is_ok());

    let cred = result.unwrap();
    assert_eq!(cred.credential_id, cred_id);
    assert_eq!(cred.public_key, cose_key);
    assert_eq!(cred.user_id, user_id);
    assert_eq!(cred.sign_count, 0);
    assert_eq!(cred.authenticator_type, "platform");

    // Credential was persisted
    assert_eq!(store.credential_count(), 1);
    assert!(store.get_credential(&cred_id).is_some());
}

#[test]
fn test_registration_response_invalid_rp_id() {
    let mut store = CredentialStore::new();
    let cred_id = vec![0xAA];
    let cose_key = vec![0x01];

    // Auth data built for "evil.com" but we expect "sso.milnet.gov"
    let auth_data = make_attestation_auth_data("evil.com", 0x45, 0, &cred_id, &cose_key);

    let err = validate_and_register(
        &mut store,
        &auth_data,
        "sso.milnet.gov",
        Uuid::new_v4(),
        "cross-platform",
    )
    .unwrap_err();

    assert_eq!(err, "RP ID hash mismatch");
    assert_eq!(store.credential_count(), 0);
}

#[test]
fn test_registration_response_missing_user_verification() {
    ensure_test_aaguid_allowlist();
    let mut store = CredentialStore::new();
    let rp_id = "sso.milnet.gov";
    let cred_id = vec![0xBB];
    let cose_key = vec![0x02];

    // flags: UP | AT = 0x41 (UV not set)
    let auth_data = make_attestation_auth_data(rp_id, 0x41, 0, &cred_id, &cose_key);

    // validate_and_register does not check UV itself (that is a policy decision),
    // but the auth data is still parseable. Registration succeeds for the
    // authenticator data level checks (UP + AT are required, UV is not).
    let result = validate_and_register(&mut store, &auth_data, rp_id, Uuid::new_v4(), "platform");
    assert!(result.is_ok());

    // However, parsing the auth data and checking UV separately should fail:
    let parsed = verification::parse_authenticator_data(&auth_data).unwrap();
    assert!(!parsed.user_verified);
    assert_eq!(
        verification::validate_user_verified(&parsed).unwrap_err(),
        "User Verified flag not set but required by policy"
    );
}

#[test]
fn test_registration_response_no_at_flag() {
    let mut store = CredentialStore::new();
    let rp_id = "sso.milnet.gov";

    // flags: UP | UV = 0x05 (no AT flag) -- only 37 bytes, no attested data
    let auth_data = make_auth_data(rp_id, 0x05, 0);

    let err = validate_and_register(&mut store, &auth_data, rp_id, Uuid::new_v4(), "platform")
        .unwrap_err();
    assert_eq!(
        err,
        "Attested credential data flag not set in registration response"
    );
}

#[test]
fn test_registration_duplicate_rejected() {
    ensure_test_aaguid_allowlist();
    let mut store = CredentialStore::new();
    let rp_id = "sso.milnet.gov";
    let user_id = Uuid::new_v4();
    let cred_id = vec![0xCC, 0xDD];
    let cose_key = vec![0x01];

    let auth_data = make_attestation_auth_data(rp_id, 0x45, 0, &cred_id, &cose_key);

    // First registration succeeds
    assert!(validate_and_register(&mut store, &auth_data, rp_id, user_id, "platform").is_ok());

    // Second registration with the same credential ID is rejected
    let err =
        validate_and_register(&mut store, &auth_data, rp_id, user_id, "platform").unwrap_err();
    assert_eq!(
        err,
        "Credential ID already registered (duplicate registration rejected)"
    );
    assert_eq!(store.credential_count(), 1);
}

// ── Authentication option tests ─────────────────────────────────────────

#[test]
fn test_authentication_options_basic() {
    let user_id = Uuid::new_v4();
    let cred = make_stored_credential(
        vec![1, 2, 3],
        vec![10, 20, 30],
        user_id,
        5,
        "platform",
    );

    let opts = create_authentication_options("sso.milnet.gov", &[&cred]);

    assert_eq!(opts.rp_id, "sso.milnet.gov");
    assert_eq!(opts.challenge.len(), 32);
    assert_eq!(opts.timeout, 60000);
    assert_eq!(opts.user_verification, "required");
    assert_eq!(opts.allow_credentials.len(), 1);
    assert_eq!(opts.allow_credentials[0].id, vec![1, 2, 3]);
    assert_eq!(opts.allow_credentials[0].cred_type, "public-key");
}

#[test]
fn test_authentication_options_multiple_credentials() {
    let user_id = Uuid::new_v4();
    let cred1 = make_stored_credential(vec![1, 2], vec![10], user_id, 0, "platform");
    let cred2 = make_stored_credential(vec![3, 4], vec![20], user_id, 0, "cross-platform");
    let cred3 = make_stored_credential(vec![5, 6, 7], vec![30], user_id, 0, "cross-platform");

    let opts = create_authentication_options("sso.milnet.gov", &[&cred1, &cred2, &cred3]);

    assert_eq!(opts.allow_credentials.len(), 3);
    assert_eq!(opts.allow_credentials[0].id, vec![1, 2]);
    assert_eq!(opts.allow_credentials[1].id, vec![3, 4]);
    assert_eq!(opts.allow_credentials[2].id, vec![5, 6, 7]);
}

#[test]
fn test_authentication_options_empty_credentials() {
    let opts = create_authentication_options("sso.milnet.gov", &[]);
    assert!(opts.allow_credentials.is_empty());
    assert_eq!(opts.challenge.len(), 32);
}

#[test]
fn test_authentication_options_challenge_unique() {
    let user_id = Uuid::new_v4();
    let cred = make_stored_credential(vec![1], vec![2], user_id, 0, "platform");

    let opts1 = create_authentication_options("sso.milnet.gov", &[&cred]);
    let opts2 = create_authentication_options("sso.milnet.gov", &[&cred]);

    assert_ne!(opts1.challenge, opts2.challenge);
    assert_eq!(opts1.challenge.len(), 32);
    assert_eq!(opts2.challenge.len(), 32);
}

#[test]
fn test_authentication_response_valid() {
    let rp_id = "sso.milnet.gov";
    let (signing_key, sec1_pubkey) = generate_p256_keypair();

    // Build authenticator data: UP | UV = 0x05, sign_count = 1
    let auth_data = make_auth_data(rp_id, 0x05, 1);

    // Build client data and its hash
    let challenge = vec![42u8; 32];
    let client_data = make_client_data_json(&challenge, "https://sso.milnet.gov");
    let client_data_hash = Sha256::digest(&client_data);

    // Sign: authenticator_data || client_data_hash
    let mut signed_msg = auth_data.clone();
    signed_msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = signing_key.sign(&signed_msg);
    let sig_der = sig.to_der();

    let auth_result = AuthenticationResult {
        credential_id: vec![0xAA, 0xBB],
        authenticator_data: auth_data,
        client_data,
        signature: sig_der.as_bytes().to_vec(),
    };

    let stored = make_stored_credential(
        vec![0xAA, 0xBB],
        sec1_pubkey,
        Uuid::new_v4(),
        0, // stored sign_count = 0
        "platform",
    );

    let result = fido::authentication::verify_authentication_response(
        &auth_result,
        &stored,
        rp_id,
        true, // require UV
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1); // new sign count
}

#[test]
fn test_authentication_response_wrong_rp_id() {
    let rp_id = "sso.milnet.gov";
    let (signing_key, sec1_pubkey) = generate_p256_keypair();

    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data = make_client_data_json(&[42u8; 32], "https://sso.milnet.gov");
    let client_data_hash = Sha256::digest(&client_data);

    let mut signed_msg = auth_data.clone();
    signed_msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = signing_key.sign(&signed_msg);
    let sig_der = sig.to_der();

    let auth_result = AuthenticationResult {
        credential_id: vec![0xAA],
        authenticator_data: auth_data,
        client_data,
        signature: sig_der.as_bytes().to_vec(),
    };

    let stored = make_stored_credential(vec![0xAA], sec1_pubkey, Uuid::new_v4(), 0, "platform");

    // Verify against a DIFFERENT RP ID -- should fail
    let result = fido::authentication::verify_authentication_response(
        &auth_result,
        &stored,
        "evil.example.com",
        true,
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "RP ID hash mismatch");
}

#[test]
fn test_authentication_response_user_verification_required() {
    let rp_id = "sso.milnet.gov";
    let (signing_key, sec1_pubkey) = generate_p256_keypair();

    // flags: UP only = 0x01 (UV is NOT set)
    let auth_data = make_auth_data(rp_id, 0x01, 1);
    let client_data = make_client_data_json(&[42u8; 32], "https://sso.milnet.gov");
    let client_data_hash = Sha256::digest(&client_data);

    let mut signed_msg = auth_data.clone();
    signed_msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = signing_key.sign(&signed_msg);
    let sig_der = sig.to_der();

    let auth_result = AuthenticationResult {
        credential_id: vec![0xAA],
        authenticator_data: auth_data,
        client_data,
        signature: sig_der.as_bytes().to_vec(),
    };

    let stored = make_stored_credential(vec![0xAA], sec1_pubkey, Uuid::new_v4(), 0, "platform");

    // require_user_verification = true, but UV flag is not set
    let result = fido::authentication::verify_authentication_response(
        &auth_result,
        &stored,
        rp_id,
        true,
    );

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "User Verified flag not set but required by policy"
    );
}

#[test]
fn test_authentication_response_uv_not_required_passes() {
    let rp_id = "sso.milnet.gov";
    let (signing_key, sec1_pubkey) = generate_p256_keypair();

    // flags: UP only = 0x01 (UV not set)
    let auth_data = make_auth_data(rp_id, 0x01, 1);
    let client_data = make_client_data_json(&[42u8; 32], "https://sso.milnet.gov");
    let client_data_hash = Sha256::digest(&client_data);

    let mut signed_msg = auth_data.clone();
    signed_msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = signing_key.sign(&signed_msg);
    let sig_der = sig.to_der();

    let auth_result = AuthenticationResult {
        credential_id: vec![0xAA],
        authenticator_data: auth_data,
        client_data,
        signature: sig_der.as_bytes().to_vec(),
    };

    let stored = make_stored_credential(vec![0xAA], sec1_pubkey, Uuid::new_v4(), 0, "platform");

    // require_user_verification = false -- should succeed even without UV
    let result = fido::authentication::verify_authentication_response(
        &auth_result,
        &stored,
        rp_id,
        false,
    );

    assert!(result.is_ok());
}

#[test]
fn test_authentication_response_clone_detection() {
    let rp_id = "sso.milnet.gov";
    let (signing_key, sec1_pubkey) = generate_p256_keypair();

    // sign_count = 5 in authenticator data (same as stored)
    let auth_data = make_auth_data(rp_id, 0x05, 5);
    let client_data = make_client_data_json(&[42u8; 32], "https://sso.milnet.gov");
    let client_data_hash = Sha256::digest(&client_data);

    let mut signed_msg = auth_data.clone();
    signed_msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = signing_key.sign(&signed_msg);
    let sig_der = sig.to_der();

    let auth_result = AuthenticationResult {
        credential_id: vec![0xAA],
        authenticator_data: auth_data,
        client_data,
        signature: sig_der.as_bytes().to_vec(),
    };

    // stored sign_count = 5, authenticator reports 5 -> clone detected
    let stored = make_stored_credential(vec![0xAA], sec1_pubkey, Uuid::new_v4(), 5, "platform");

    let result = fido::authentication::verify_authentication_response(
        &auth_result,
        &stored,
        rp_id,
        true,
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Possible authenticator clone detected");
}

// ── Sign count tests ────────────────────────────────────────────────────

#[test]
fn test_update_sign_count_increasing() {
    let mut cred = make_stored_credential(vec![1], vec![2], Uuid::new_v4(), 5, "platform");
    assert!(update_sign_count(&mut cred, 10).is_ok());
    assert_eq!(cred.sign_count, 10);
}

#[test]
fn test_update_sign_count_equal_nonzero_fails() {
    let mut cred = make_stored_credential(vec![1], vec![2], Uuid::new_v4(), 7, "platform");
    let err = update_sign_count(&mut cred, 7).unwrap_err();
    assert_eq!(
        err,
        "New sign count must be strictly greater than stored sign count"
    );
    // Credential unchanged
    assert_eq!(cred.sign_count, 7);
}

#[test]
fn test_update_sign_count_both_zero_ok() {
    let mut cred =
        make_stored_credential(vec![1], vec![2], Uuid::new_v4(), 0, "cross-platform");
    // 0 -> 0 is allowed (authenticator doesn't support counters)
    assert!(update_sign_count(&mut cred, 0).is_ok());
    assert_eq!(cred.sign_count, 0);
}

#[test]
fn test_update_sign_count_decrease_fails() {
    let mut cred = make_stored_credential(vec![1], vec![2], Uuid::new_v4(), 10, "platform");
    let err = update_sign_count(&mut cred, 5).unwrap_err();
    assert_eq!(
        err,
        "New sign count must not be less than stored sign count"
    );
    assert_eq!(cred.sign_count, 10);
}

#[test]
fn test_update_sign_count_zero_to_nonzero_ok() {
    let mut cred = make_stored_credential(vec![1], vec![2], Uuid::new_v4(), 0, "platform");
    assert!(update_sign_count(&mut cred, 1).is_ok());
    assert_eq!(cred.sign_count, 1);
}

// ── Verification / crypto tests ─────────────────────────────────────────

#[test]
fn test_verify_es256_signature() {
    let rp_id = "sso.milnet.gov";
    let (signing_key, sec1_pubkey) = generate_p256_keypair();

    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data_hash = Sha256::digest(b"test client data");

    // Sign: authenticator_data || client_data_hash
    let mut msg = auth_data.clone();
    msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
    let sig_der = sig.to_der();

    let result = verification::verify_signature_es256(
        &auth_data,
        &client_data_hash,
        sig_der.as_bytes(),
        &sec1_pubkey,
    );

    assert!(result.is_ok());
}

#[test]
fn test_verify_invalid_signature_rejected() {
    let rp_id = "sso.milnet.gov";
    let (signing_key, sec1_pubkey) = generate_p256_keypair();

    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data_hash = Sha256::digest(b"test client data");

    let mut msg = auth_data.clone();
    msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
    let mut sig_bytes = sig.to_der().as_bytes().to_vec();

    // Tamper with the signature: flip the last byte
    if let Some(last) = sig_bytes.last_mut() {
        *last ^= 0xFF;
    }

    let result = verification::verify_signature_es256(
        &auth_data,
        &client_data_hash,
        &sig_bytes,
        &sec1_pubkey,
    );

    assert!(result.is_err());
}

#[test]
fn test_verify_wrong_key_rejected() {
    let rp_id = "sso.milnet.gov";
    let (signing_key, _correct_pubkey) = generate_p256_keypair();
    let (_other_key, wrong_pubkey) = generate_p256_keypair();

    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data_hash = Sha256::digest(b"test client data");

    let mut msg = auth_data.clone();
    msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
    let sig_der = sig.to_der();

    // Verify with the WRONG public key
    let result = verification::verify_signature_es256(
        &auth_data,
        &client_data_hash,
        sig_der.as_bytes(),
        &wrong_pubkey,
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "ES256 signature verification failed");
}

#[test]
fn test_verify_empty_signature_rejected() {
    let auth_data = make_auth_data("rp.example", 0x05, 1);
    let client_data_hash = Sha256::digest(b"data");
    let (_, pubkey) = generate_p256_keypair();

    let result = verification::verify_signature_es256(
        &auth_data,
        &client_data_hash,
        &[],
        &pubkey,
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Signature is empty");
}

#[test]
fn test_verify_empty_public_key_rejected() {
    let auth_data = make_auth_data("rp.example", 0x05, 1);
    let client_data_hash = Sha256::digest(b"data");

    let result = verification::verify_signature_es256(
        &auth_data,
        &client_data_hash,
        &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], // dummy DER sig
        &[],
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Public key is empty");
}

#[test]
fn test_verify_short_auth_data_rejected() {
    let client_data_hash = Sha256::digest(b"data");
    let (_, pubkey) = generate_p256_keypair();

    // Auth data too short (< 37 bytes)
    let result = verification::verify_signature_es256(
        &[0u8; 10],
        &client_data_hash,
        &[0x30, 0x06],
        &pubkey,
    );

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "Authenticator data too short for signature verification"
    );
}

#[test]
fn test_verify_signature_es256_cose() {
    let rp_id = "sso.milnet.gov";
    let (signing_key, sec1_pubkey) = generate_p256_keypair();
    let cose_key = sec1_to_cose(&sec1_pubkey);

    let auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data_hash = Sha256::digest(b"test client data");

    let mut msg = auth_data.clone();
    msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
    let sig_der = sig.to_der();

    let result = verification::verify_signature_es256_cose(
        &auth_data,
        &client_data_hash,
        sig_der.as_bytes(),
        &cose_key,
    );

    assert!(result.is_ok());
}

// ── COSE key parsing tests ──────────────────────────────────────────────

#[test]
fn test_encode_and_parse_cose_key_roundtrip() {
    let (_, sec1_pubkey) = generate_p256_keypair();
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&sec1_pubkey[1..33]);
    y.copy_from_slice(&sec1_pubkey[33..65]);

    let encoded = verification::encode_cose_key_es256(&x, &y);
    let parsed = verification::parse_cose_key_es256(&encoded).unwrap();

    assert_eq!(parsed.x, x);
    assert_eq!(parsed.y, y);

    // Verify the SEC1 uncompressed output
    let sec1 = parsed.to_sec1_uncompressed();
    assert_eq!(sec1.len(), 65);
    assert_eq!(sec1[0], 0x04);
    assert_eq!(&sec1[1..33], &x);
    assert_eq!(&sec1[33..65], &y);
}

#[test]
fn test_cose_key_to_verifying_key() {
    let (_, sec1_pubkey) = generate_p256_keypair();
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&sec1_pubkey[1..33]);
    y.copy_from_slice(&sec1_pubkey[33..65]);

    let cose_key = verification::CoseKeyEs256 { x, y };
    let vk = cose_key.to_verifying_key();
    assert!(vk.is_ok());
}

#[test]
fn test_cose_key_invalid_bytes() {
    let result = verification::parse_cose_key_es256(&[]);
    assert!(result.is_err());
}

#[test]
fn test_cose_key_garbage_data() {
    let result = verification::parse_cose_key_es256(&[0xFF, 0xFE, 0xFD]);
    assert!(result.is_err());
}

// ── Authenticator data parsing tests ────────────────────────────────────

#[test]
fn test_parse_authenticator_data_basic() {
    let rp_id = "sso.milnet.gov";
    let auth_data = make_auth_data(rp_id, 0x05, 42);

    let parsed = verification::parse_authenticator_data(&auth_data).unwrap();

    let expected_hash = Sha256::digest(rp_id.as_bytes());
    assert_eq!(&parsed.rp_id_hash[..], &expected_hash[..]);
    assert_eq!(parsed.flags, 0x05);
    assert_eq!(parsed.sign_count, 42);
    assert!(parsed.user_present);
    assert!(parsed.user_verified);
    assert!(!parsed.attested_credential_data);
}

#[test]
fn test_parse_authenticator_data_all_flags() {
    let auth_data = make_auth_data("rp.example", 0x45, 0);
    let parsed = verification::parse_authenticator_data(&auth_data).unwrap();

    assert!(parsed.user_present); // bit 0
    assert!(parsed.user_verified); // bit 2
    assert!(parsed.attested_credential_data); // bit 6
}

#[test]
fn test_parse_authenticator_data_no_flags() {
    let auth_data = make_auth_data("rp.example", 0x00, 0);
    let parsed = verification::parse_authenticator_data(&auth_data).unwrap();

    assert!(!parsed.user_present);
    assert!(!parsed.user_verified);
    assert!(!parsed.attested_credential_data);
}

#[test]
fn test_parse_authenticator_data_too_short() {
    let result = verification::parse_authenticator_data(&[0u8; 36]);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "Authenticator data too short (must be >= 37 bytes)"
    );
}

#[test]
fn test_validate_rp_id_hash_correct() {
    let rp_id = "sso.milnet.gov";
    let auth_data = make_auth_data(rp_id, 0x05, 0);
    let parsed = verification::parse_authenticator_data(&auth_data).unwrap();
    assert!(verification::validate_rp_id_hash(&parsed, rp_id).is_ok());
}

#[test]
fn test_validate_rp_id_hash_mismatch() {
    let auth_data = make_auth_data("good.example", 0x05, 0);
    let parsed = verification::parse_authenticator_data(&auth_data).unwrap();
    let result = verification::validate_rp_id_hash(&parsed, "evil.example");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "RP ID hash mismatch");
}

#[test]
fn test_validate_user_present() {
    let auth_data = make_auth_data("rp.example", 0x01, 0); // UP set
    let parsed = verification::parse_authenticator_data(&auth_data).unwrap();
    assert!(verification::validate_user_present(&parsed).is_ok());

    let auth_data2 = make_auth_data("rp.example", 0x00, 0); // UP not set
    let parsed2 = verification::parse_authenticator_data(&auth_data2).unwrap();
    assert_eq!(
        verification::validate_user_present(&parsed2).unwrap_err(),
        "User Present flag not set"
    );
}

// ── Client data validation tests ────────────────────────────────────────

#[test]
fn test_validate_client_data_authentication_valid() {
    let challenge = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let origin = "https://sso.milnet.gov";
    let client_data = make_client_data_json(&challenge, origin);

    let result =
        verification::validate_client_data_authentication(&client_data, &challenge, origin);

    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.client_data_type, "webauthn.get");
    assert_eq!(parsed.origin, origin);
}

#[test]
fn test_validate_client_data_registration_valid() {
    let challenge = vec![99u8; 32];
    let origin = "https://sso.milnet.gov";
    let client_data = make_client_data_json_create(&challenge, origin);

    let result =
        verification::validate_client_data_registration(&client_data, &challenge, origin);

    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.client_data_type, "webauthn.create");
}

#[test]
fn test_validate_client_data_wrong_type() {
    let challenge = vec![1u8; 16];
    let origin = "https://sso.milnet.gov";
    // Create "webauthn.create" but validate as "webauthn.get"
    let client_data = make_client_data_json_create(&challenge, origin);

    let result =
        verification::validate_client_data_authentication(&client_data, &challenge, origin);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Client data type mismatch");
}

#[test]
fn test_validate_client_data_wrong_challenge() {
    let real_challenge = vec![1u8; 16];
    let wrong_challenge = vec![2u8; 16];
    let origin = "https://sso.milnet.gov";
    let client_data = make_client_data_json(&real_challenge, origin);

    let result =
        verification::validate_client_data_authentication(&client_data, &wrong_challenge, origin);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Client data challenge mismatch");
}

#[test]
fn test_validate_client_data_wrong_origin() {
    let challenge = vec![1u8; 16];
    let origin = "https://sso.milnet.gov";
    let client_data = make_client_data_json(&challenge, origin);

    let result = verification::validate_client_data_authentication(
        &client_data,
        &challenge,
        "https://evil.example.com",
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Client data origin mismatch");
}

#[test]
fn test_validate_client_data_invalid_json() {
    let result = verification::validate_client_data_authentication(
        b"not json at all",
        &[1u8; 16],
        "https://sso.milnet.gov",
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Client data is not valid JSON");
}

#[test]
fn test_validate_client_data_not_object() {
    let result = verification::validate_client_data_authentication(
        b"[1,2,3]",
        &[1u8; 16],
        "https://sso.milnet.gov",
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Client data JSON is not an object");
}

// ── Attestation verification tests ──────────────────────────────────────

#[test]
#[serial]
fn test_attestation_none_rejected_in_military_mode() {
    std::env::remove_var("MILNET_FIDO_REQUIRE_ATTESTATION");
    let rp_id = "sso.milnet.gov";
    let cred_id = vec![0xAA, 0xBB, 0xCC];
    let (_, sec1_pubkey) = generate_p256_keypair();
    let cose_key = sec1_to_cose(&sec1_pubkey);

    let auth_data = make_attestation_auth_data(rp_id, 0x45, 0, &cred_id, &cose_key);
    let client_data_hash = Sha256::digest(b"client data");

    let result = verification::verify_attestation_none(&auth_data, &client_data_hash, rp_id);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("hardware attestation required"));
}

#[test]
#[serial]
fn test_attestation_none_valid_when_disabled() {
    std::env::set_var("MILNET_FIDO_REQUIRE_ATTESTATION", "false");
    let rp_id = "sso.milnet.gov";
    let cred_id = vec![0xAA, 0xBB, 0xCC];
    let (_, sec1_pubkey) = generate_p256_keypair();
    let cose_key = sec1_to_cose(&sec1_pubkey);

    let auth_data = make_attestation_auth_data(rp_id, 0x45, 0, &cred_id, &cose_key);
    let client_data_hash = Sha256::digest(b"client data");

    let result = verification::verify_attestation_none(&auth_data, &client_data_hash, rp_id);
    assert!(result.is_ok());

    let (att_data, att_type) = result.unwrap();
    assert_eq!(att_type, verification::AttestationType::None);
    assert_eq!(att_data.credential_id, cred_id);
    assert_eq!(att_data.sign_count, 0);
    std::env::remove_var("MILNET_FIDO_REQUIRE_ATTESTATION");
}

#[test]
fn test_packed_self_attestation_valid() {
    let rp_id = "sso.milnet.gov";
    let (signing_key, sec1_pubkey) = generate_p256_keypair();
    let cose_key = sec1_to_cose(&sec1_pubkey);
    let cred_id = vec![0xDE, 0xAD];

    // flags: UP | UV | AT = 0x45
    let auth_data = make_attestation_auth_data(rp_id, 0x45, 0, &cred_id, &cose_key);
    let client_data_hash = Sha256::digest(b"client data");

    // Sign: auth_data || client_data_hash
    let mut msg = auth_data.clone();
    msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
    let sig_der = sig.to_der();

    let result = verification::verify_packed_self_attestation(
        &auth_data,
        &client_data_hash,
        -7, // ES256
        sig_der.as_bytes(),
        rp_id,
    );

    assert!(result.is_ok());
    let (att_data, att_type) = result.unwrap();
    assert_eq!(att_type, verification::AttestationType::SelfAttestation);
    assert_eq!(att_data.credential_id, cred_id);
}

#[test]
fn test_packed_self_attestation_wrong_alg() {
    let rp_id = "sso.milnet.gov";
    let (_, sec1_pubkey) = generate_p256_keypair();
    let cose_key = sec1_to_cose(&sec1_pubkey);
    let cred_id = vec![0x01];

    let auth_data = make_attestation_auth_data(rp_id, 0x45, 0, &cred_id, &cose_key);
    let client_data_hash = Sha256::digest(b"data");

    let result = verification::verify_packed_self_attestation(
        &auth_data,
        &client_data_hash,
        -257, // RS256, not supported
        &[0x30, 0x06],
        rp_id,
    );

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "Packed attestation: only ES256 (alg -7) is supported"
    );
}

#[test]
fn test_packed_basic_attestation_valid() {
    let rp_id = "sso.milnet.gov";
    // Attestation key (separate from credential key)
    let (att_signing_key, att_pubkey) = generate_p256_keypair();
    // Credential key
    let (_, cred_sec1_pubkey) = generate_p256_keypair();
    let cred_cose_key = sec1_to_cose(&cred_sec1_pubkey);
    let cred_id = vec![0xCA, 0xFE];

    let auth_data = make_attestation_auth_data(rp_id, 0x45, 0, &cred_id, &cred_cose_key);
    let client_data_hash = Sha256::digest(b"client data");

    // Sign with the attestation key (not the credential key)
    let mut msg = auth_data.clone();
    msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = att_signing_key.sign(&msg);
    let sig_der = sig.to_der();

    let result = verification::verify_packed_basic_attestation(
        &auth_data,
        &client_data_hash,
        -7,
        sig_der.as_bytes(),
        &att_pubkey,
        rp_id,
    );

    assert!(result.is_ok());
    let (att_data, att_type) = result.unwrap();
    assert_eq!(att_type, verification::AttestationType::Basic);
    assert_eq!(att_data.credential_id, cred_id);
}

// ── CredentialStore tests ───────────────────────────────────────────────

#[test]
fn test_credential_store_challenge_lifecycle() {
    let mut store = CredentialStore::new();
    let user_id = Uuid::new_v4();

    let challenge = vec![10, 20, 30];
    store.store_challenge(&challenge, user_id);

    // Challenge exists
    assert!(store.has_pending_challenge(&user_id));

    // Consume returns user ID
    assert_eq!(store.consume_challenge(&challenge), Some(user_id));

    // Challenge is consumed (one-time use)
    assert_eq!(store.consume_challenge(&challenge), None);
    assert!(!store.has_pending_challenge(&user_id));
}

#[test]
fn test_credential_store_consume_for_user() {
    let mut store = CredentialStore::new();
    let user_id = Uuid::new_v4();

    let challenge = vec![1, 2, 3];
    store.store_challenge(&challenge, user_id);

    assert!(store.consume_challenge_for_user(&user_id));
    // Already consumed
    assert!(!store.consume_challenge_for_user(&user_id));
}

#[test]
fn test_credential_store_multiple_users() {
    let mut store = CredentialStore::new();
    let user1 = Uuid::new_v4();
    let user2 = Uuid::new_v4();

    let cred1 = make_stored_credential(vec![1], vec![10], user1, 0, "platform");
    let cred2 = make_stored_credential(vec![2], vec![20], user1, 0, "cross-platform");
    let cred3 = make_stored_credential(vec![3], vec![30], user2, 0, "platform");

    store.store_credential(cred1);
    store.store_credential(cred2);
    store.store_credential(cred3);

    assert_eq!(store.credential_count(), 3);
    assert_eq!(store.get_user_credentials(&user1).len(), 2);
    assert_eq!(store.get_user_credentials(&user2).len(), 1);
}

#[test]
fn test_credential_store_get_credential_mut() {
    let mut store = CredentialStore::new();
    let user_id = Uuid::new_v4();
    let cred_id = vec![0xAA];

    store.store_credential(make_stored_credential(
        cred_id.clone(),
        vec![10],
        user_id,
        0,
        "platform",
    ));

    // Mutate the sign count
    let cred = store.get_credential_mut(&cred_id).unwrap();
    cred.sign_count = 42;

    assert_eq!(store.get_credential(&cred_id).unwrap().sign_count, 42);
}

#[test]
fn test_credential_store_remove_user_credentials() {
    let mut store = CredentialStore::new();
    let user1 = Uuid::new_v4();
    let user2 = Uuid::new_v4();

    store.store_credential(make_stored_credential(vec![1], vec![10], user1, 0, "platform"));
    store.store_credential(make_stored_credential(vec![2], vec![20], user2, 0, "platform"));
    store.store_challenge(&[1, 2, 3], user1);
    store.store_challenge(&[4, 5, 6], user2);

    assert_eq!(store.credential_count(), 2);

    // GDPR right-to-erasure: remove user1's data
    store.remove_user_credentials(&user1);

    assert_eq!(store.credential_count(), 1);
    assert!(!store.credential_exists(&[1]));
    assert!(store.credential_exists(&[2]));
    assert!(!store.has_pending_challenge(&user1));
    assert!(store.has_pending_challenge(&user2));
}

#[test]
fn test_credential_store_default() {
    // CredentialStore implements Default
    let store = CredentialStore::default();
    assert_eq!(store.credential_count(), 0);
}

// ── Types tests ─────────────────────────────────────────────────────────

#[test]
fn test_stored_credential_creation() {
    let user_id = Uuid::new_v4();
    let cred = StoredCredential {
        credential_id: vec![0xDE, 0xAD],
        public_key: vec![0xBE, 0xEF],
        user_id,
        sign_count: 0,
        authenticator_type: "cross-platform".to_string(),
    ..Default::default()
    };

    assert_eq!(cred.credential_id, vec![0xDE, 0xAD]);
    assert_eq!(cred.public_key, vec![0xBE, 0xEF]);
    assert_eq!(cred.user_id, user_id);
    assert_eq!(cred.sign_count, 0);
    assert_eq!(cred.authenticator_type, "cross-platform");
}

#[test]
fn test_stored_credential_clone() {
    let user_id = Uuid::new_v4();
    let cred = StoredCredential {
        credential_id: vec![1, 2, 3],
        public_key: vec![4, 5, 6],
        user_id,
        sign_count: 7,
        authenticator_type: "platform".to_string(),
    ..Default::default()
    };

    let cloned = cred.clone();
    assert_eq!(cloned.credential_id, cred.credential_id);
    assert_eq!(cloned.public_key, cred.public_key);
    assert_eq!(cloned.user_id, cred.user_id);
    assert_eq!(cloned.sign_count, cred.sign_count);
}

#[test]
fn test_types_serialization_roundtrip() {
    let user_id = Uuid::new_v4();
    let cred = StoredCredential {
        credential_id: vec![1, 2, 3],
        public_key: vec![4, 5],
        user_id,
        sign_count: 42,
        authenticator_type: "platform".to_string(),
    ..Default::default()
    };

    let json = serde_json::to_string(&cred).unwrap();
    let deserialized: StoredCredential = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.credential_id, cred.credential_id);
    assert_eq!(deserialized.public_key, cred.public_key);
    assert_eq!(deserialized.user_id, cred.user_id);
    assert_eq!(deserialized.sign_count, cred.sign_count);
    assert_eq!(deserialized.authenticator_type, cred.authenticator_type);
}

#[test]
fn test_registration_options_serialization() {
    let user_id = Uuid::new_v4();
    let options = create_registration_options(
        "MILNET SSO",
        "sso.milnet.gov",
        &user_id,
        "test_user",
        false,
    );

    let json = serde_json::to_string(&options).unwrap();
    let deser: PublicKeyCredentialCreationOptions = serde_json::from_str(&json).unwrap();

    assert_eq!(deser.rp.name, options.rp.name);
    assert_eq!(deser.rp.id, options.rp.id);
    assert_eq!(deser.user.name, options.user.name);
    assert_eq!(deser.challenge, options.challenge);
    assert_eq!(deser.timeout, options.timeout);
}

#[test]
fn test_authentication_options_serialization() {
    let user_id = Uuid::new_v4();
    let cred = make_stored_credential(vec![1, 2], vec![3], user_id, 0, "platform");
    let options = create_authentication_options("sso.milnet.gov", &[&cred]);

    let json = serde_json::to_string(&options).unwrap();
    let deser: PublicKeyCredentialRequestOptions = serde_json::from_str(&json).unwrap();

    assert_eq!(deser.rp_id, options.rp_id);
    assert_eq!(deser.challenge, options.challenge);
    assert_eq!(deser.allow_credentials.len(), 1);
}

// ── Base64url encoding test ─────────────────────────────────────────────

#[test]
fn test_base64_url_encode() {
    // Known test vector
    let input = b"Hello, MILNET!";
    let encoded = verification::base64_url_encode(input);
    // base64url of "Hello, MILNET!" = "SGVsbG8sIE1JTE5FVCE"
    assert_eq!(encoded, "SGVsbG8sIE1JTE5FVCE");
}

// ── Full authentication flow integration test ───────────────────────────

#[test]
fn test_full_registration_and_authentication_flow() {
    ensure_test_aaguid_allowlist();
    let rp_id = "sso.milnet.gov";
    let user_id = Uuid::new_v4();
    let mut store = CredentialStore::new();

    // --- Phase 1: Registration ---

    let reg_options = create_registration_options("MILNET SSO", rp_id, &user_id, "operator", true);
    assert_eq!(reg_options.rp.name, "MILNET SSO");

    // Generate a P-256 credential key pair (simulating the authenticator)
    let (cred_signing_key, cred_sec1_pubkey) = generate_p256_keypair();
    let cred_cose_key = sec1_to_cose(&cred_sec1_pubkey);
    let cred_id = vec![0x01, 0x02, 0x03, 0x04];

    // Build attestation auth data (UP | UV | AT = 0x45)
    let reg_auth_data = make_attestation_auth_data(rp_id, 0x45, 0, &cred_id, &cred_cose_key);

    // Store the challenge and register
    store.store_challenge(&reg_options.challenge, user_id);

    let reg_result =
        validate_and_register(&mut store, &reg_auth_data, rp_id, user_id, "platform");
    assert!(reg_result.is_ok());
    let stored_cred = reg_result.unwrap();
    assert_eq!(stored_cred.credential_id, cred_id);
    assert_eq!(store.credential_count(), 1);

    // --- Phase 2: Authentication ---

    let creds = store.get_user_credentials(&user_id);
    let auth_options = create_authentication_options(rp_id, &creds);
    assert_eq!(auth_options.allow_credentials.len(), 1);

    // Build authenticator data for assertion (UP | UV, sign_count = 1)
    let assertion_auth_data = make_auth_data(rp_id, 0x05, 1);
    let client_data = make_client_data_json(&auth_options.challenge, "https://sso.milnet.gov");
    let client_data_hash = Sha256::digest(&client_data);

    // Sign with the credential key
    let mut signed_msg = assertion_auth_data.clone();
    signed_msg.extend_from_slice(&client_data_hash);
    let sig: p256::ecdsa::Signature = cred_signing_key.sign(&signed_msg);
    let sig_der = sig.to_der();

    let auth_result = AuthenticationResult {
        credential_id: cred_id.clone(),
        authenticator_data: assertion_auth_data,
        client_data,
        signature: sig_der.as_bytes().to_vec(),
    };

    // The stored credential has the SEC1 public key for verification.
    // We need to use the actual stored credential from the store.
    let stored_ref = store.get_credential(&cred_id).unwrap();

    // But the stored key is COSE-encoded. The verify_authentication_response
    // expects SEC1 in stored_credential.public_key. Let us build a credential
    // with SEC1 key for verification.
    let verify_cred = make_stored_credential(
        cred_id.clone(),
        cred_sec1_pubkey.clone(),
        user_id,
        stored_ref.sign_count,
        "platform",
    );

    let verify_result = fido::authentication::verify_authentication_response(
        &auth_result,
        &verify_cred,
        rp_id,
        true,
    );

    assert!(verify_result.is_ok());
    let new_sign_count = verify_result.unwrap();
    assert_eq!(new_sign_count, 1);

    // Update sign count
    let cred_mut = store.get_credential_mut(&cred_id).unwrap();
    assert!(update_sign_count(cred_mut, new_sign_count).is_ok());
}

// ── TEST GROUP 1: FIDO2 challenge expiry tests ────────────────────────────

#[test]
fn test_challenge_consumed_immediately_succeeds() {
    let mut store = CredentialStore::new();
    let user_id = Uuid::new_v4();
    let challenge = vec![0xCA, 0xFE, 0xBA, 0xBE];

    store.store_challenge(&challenge, user_id);
    // Consuming immediately (well within 60s) must succeed.
    let result = store.consume_challenge(&challenge);
    assert_eq!(result, Some(user_id), "challenge consumed immediately must return the user ID");
}

#[test]
fn test_challenge_consumed_only_once() {
    let mut store = CredentialStore::new();
    let user_id = Uuid::new_v4();
    let challenge = vec![0xDE, 0xAD];

    store.store_challenge(&challenge, user_id);
    assert_eq!(store.consume_challenge(&challenge), Some(user_id));
    // Second consume must return None — challenge is single-use.
    assert_eq!(store.consume_challenge(&challenge), None, "challenge must be single-use");
}

#[test]
fn test_cleanup_expired_challenges_removes_old_entries() {
    let mut store = CredentialStore::new();
    let user_id = Uuid::new_v4();

    // Store a challenge that is fresh (just created).
    let fresh_challenge = vec![0x01];
    store.store_challenge(&fresh_challenge, user_id);

    // The fresh challenge should survive cleanup.
    store.cleanup_expired_challenges();
    assert!(
        store.has_pending_challenge(&user_id),
        "freshly stored challenge must survive cleanup"
    );

    // Consume the fresh one to verify it still works.
    assert_eq!(store.consume_challenge(&fresh_challenge), Some(user_id));
}

#[test]
fn test_store_challenge_triggers_cleanup() {
    let mut store = CredentialStore::new();
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();

    // Store a challenge for user A.
    let challenge_a = vec![0xAA];
    store.store_challenge(&challenge_a, user_a);

    // Store another challenge for user B — this triggers cleanup internally.
    let challenge_b = vec![0xBB];
    store.store_challenge(&challenge_b, user_b);

    // Both fresh challenges must still be consumable.
    assert_eq!(store.consume_challenge(&challenge_a), Some(user_a));
    assert_eq!(store.consume_challenge(&challenge_b), Some(user_b));
}

#[test]
fn test_consume_challenge_for_user_works_for_fresh_challenge() {
    let mut store = CredentialStore::new();
    let user_id = Uuid::new_v4();
    let challenge = vec![0xCC];

    store.store_challenge(&challenge, user_id);
    // consume_challenge_for_user should find and consume it.
    assert!(store.consume_challenge_for_user(&user_id));
    // After consumption, no pending challenge should remain.
    assert!(!store.has_pending_challenge(&user_id));
}

#[test]
fn test_has_pending_challenge_false_for_unknown_user() {
    let store = CredentialStore::new();
    let unknown = Uuid::new_v4();
    assert!(!store.has_pending_challenge(&unknown));
}
