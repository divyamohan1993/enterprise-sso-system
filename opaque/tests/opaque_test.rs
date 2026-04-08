//! Integration tests for the OPAQUE password service.
//!
//! Tests verify the real OPAQUE protocol: the server NEVER sees the plaintext
//! password, not during registration, not during login.

use opaque::opaque_impl::OpaqueCs;
use opaque::service::{handle_login_finish, handle_login_start};
use opaque::store::{CredentialStore, KSF_ARGON2ID, KSF_PBKDF2_SHA512};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters,
};
use rand::rngs::OsRng;

/// Fixed signing key for tests.
const SIGNING_KEY: [u8; 64] = [0x42u8; 64];

// ── Registration Tests ──────────────────────────────────────────────────

#[test]
fn register_with_password_creates_valid_record() {
    let mut store = CredentialStore::new();
    let user_id = store.register_with_password("alice", b"correct-horse-battery-staple").unwrap();

    // The store should have the user
    assert!(store.user_exists("alice"));
    assert_eq!(store.get_user_id("alice"), Some(user_id));

    // The registration should be deserializable
    let (reg, stored_id) = store.get_registration("alice").unwrap();
    assert_eq!(stored_id, user_id);
    // Verify the registration serializes back cleanly
    let _bytes = reg.serialize();
}

#[test]
fn stored_registration_contains_no_password_info() {
    let mut store = CredentialStore::new();
    let password = b"super-secret-password-12345";
    store.register_with_password("alice", password).unwrap();

    // Get the raw registration bytes
    let (reg, _) = store.get_registration("alice").unwrap();
    let reg_bytes = reg.serialize();

    // The registration bytes must NOT contain any substring of the password.
    // This is a fundamental OPAQUE guarantee.
    let reg_slice = reg_bytes.as_slice();
    for window_size in 4..=password.len() {
        for window in password.windows(window_size) {
            assert!(
                !reg_slice.windows(window.len()).any(|w| w == window),
                "registration bytes contain password substring of length {window_size}"
            );
        }
    }
}

#[test]
fn full_registration_flow_step_by_step() {
    let mut store = CredentialStore::new();
    let mut rng = OsRng;
    let password = b"test-password";
    let username = "bob";

    // Step 1: Client starts registration
    let client_start = ClientRegistration::<OpaqueCs>::start(&mut rng, password).unwrap();
    let reg_request_bytes = client_start.message.serialize().to_vec();

    // Step 2: Server processes registration request
    let server_start_response =
        opaque::service::handle_register_start(&store, username, &reg_request_bytes).unwrap();

    // Step 3: Client finishes registration
    let reg_response =
        opaque_ke::RegistrationResponse::<OpaqueCs>::deserialize(&server_start_response).unwrap();
    let client_finish = client_start
        .state
        .finish(
            &mut rng,
            password,
            reg_response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let reg_upload_bytes = client_finish.message.serialize().to_vec();

    // Step 4: Server finishes registration
    let user_id =
        opaque::service::handle_register_finish(&mut store, username, &reg_upload_bytes).unwrap();

    assert!(store.user_exists(username));
    assert_eq!(store.get_user_id(username), Some(user_id));
}

// ── Login Tests ─────────────────────────────────────────────────────────

#[test]
fn full_login_flow_succeeds_with_correct_password() {
    let mut store = CredentialStore::new();
    let password = b"correct-horse-battery-staple";
    let user_id = store.register_with_password("alice", password).unwrap();

    let mut rng = OsRng;
    let ceremony_session_id = [0xAA; 32];
    let dpop_key_hash = [0xBB; 64];

    // Login Step 1: Client starts login
    let client_login_start = ClientLogin::<OpaqueCs>::start(&mut rng, password).unwrap();
    let credential_request_bytes = client_login_start.message.serialize().to_vec();

    // Login Step 2: Server processes login start
    let (credential_response_bytes, server_login) =
        handle_login_start(&store, "alice", &credential_request_bytes).unwrap();

    // Login Step 3: Client finishes login
    let credential_response =
        opaque_ke::CredentialResponse::<OpaqueCs>::deserialize(&credential_response_bytes).unwrap();
    let client_login_finish = client_login_start
        .state
        .finish(
            &mut rng,
            password,
            credential_response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    let credential_finalization_bytes = client_login_finish.message.serialize().to_vec();

    // Login Step 4: Server finishes login
    let receipt_signer = opaque::service::ReceiptSigner::new(SIGNING_KEY);
    let response = handle_login_finish(
        server_login,
        &credential_finalization_bytes,
        &receipt_signer,
        user_id,
        ceremony_session_id,
        dpop_key_hash,
    );

    match response {
        opaque::messages::OpaqueResponse::LoginSuccess { receipt } => {
            assert_eq!(receipt.ceremony_session_id, ceremony_session_id);
            assert_eq!(receipt.dpop_key_hash, dpop_key_hash);
            assert_eq!(receipt.user_id, user_id);
            assert_eq!(receipt.step_id, 1);
            assert!(!receipt.signature.is_empty());

            // Verify the receipt signature using ML-DSA-87 (hardened signing).
            // The ReceiptSigner now signs with ML-DSA-87 asymmetric signatures
            // derived from the first 32 bytes of the signing key as a seed.
            let receipt_signer = opaque::service::ReceiptSigner::new(SIGNING_KEY);
            assert!(
                receipt_signer.verify(&receipt),
                "receipt signature must be valid (ML-DSA-87)"
            );
        }
        opaque::messages::OpaqueResponse::Error { message } => {
            panic!("login should succeed but got error: {message}");
        }
        _ => panic!("unexpected response type"),
    }
}

#[test]
fn login_fails_with_wrong_password() {
    let mut store = CredentialStore::new();
    store.register_with_password("bob", b"real-password").unwrap();

    let mut rng = OsRng;

    // Login with WRONG password
    let client_login_start = ClientLogin::<OpaqueCs>::start(&mut rng, b"wrong-password").unwrap();
    let credential_request_bytes = client_login_start.message.serialize().to_vec();

    // Server processes login start (this succeeds — server can't tell yet)
    let (credential_response_bytes, _server_login) =
        handle_login_start(&store, "bob", &credential_request_bytes).unwrap();

    // Client tries to finish login — this should fail because the OPRF
    // output won't match (wrong password produces wrong key)
    let credential_response =
        opaque_ke::CredentialResponse::<OpaqueCs>::deserialize(&credential_response_bytes).unwrap();
    let client_result = client_login_start.state.finish(
        &mut rng,
        b"wrong-password",
        credential_response,
        ClientLoginFinishParameters::default(),
    );

    // The OPAQUE protocol detects wrong password on the client side:
    // the envelope cannot be opened with the wrong key
    assert!(
        client_result.is_err(),
        "login with wrong password must fail at client finish"
    );
}

#[test]
fn login_unknown_user_does_not_leak_existence() {
    let store = CredentialStore::new();
    let mut rng = OsRng;

    // Login for a user that doesn't exist
    let client_login_start = ClientLogin::<OpaqueCs>::start(&mut rng, b"any-password").unwrap();
    let credential_request_bytes = client_login_start.message.serialize().to_vec();

    // Server handles login start — with None password_file (dummy response)
    // This should NOT error out — it returns a dummy CredentialResponse
    // to prevent username enumeration.
    let result = handle_login_start(&store, "nonexistent", &credential_request_bytes);

    // The server should still return a response (dummy) to prevent enumeration
    assert!(
        result.is_ok(),
        "login start for unknown user should not error (anti-enumeration)"
    );
}

// ── Receipt Tests ───────────────────────────────────────────────────────

#[test]
fn receipt_has_correct_fields() {
    let mut store = CredentialStore::new();
    let password = b"field-test-pw";
    let user_id = store.register_with_password("diana", password).unwrap();

    let mut rng = OsRng;
    let session_id = [0xCC; 32];
    let dpop_hash = [0xDD; 64];

    // Full login flow
    let client_start = ClientLogin::<OpaqueCs>::start(&mut rng, password).unwrap();
    let (resp_bytes, server_login) =
        handle_login_start(&store, "diana", &client_start.message.serialize().to_vec()).unwrap();

    let cred_resp = opaque_ke::CredentialResponse::<OpaqueCs>::deserialize(&resp_bytes).unwrap();
    let client_finish = client_start
        .state
        .finish(
            &mut rng,
            password,
            cred_resp,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    let receipt_signer2 = opaque::service::ReceiptSigner::new(SIGNING_KEY);
    let response = handle_login_finish(
        server_login,
        &client_finish.message.serialize().to_vec(),
        &receipt_signer2,
        user_id,
        session_id,
        dpop_hash,
    );

    match response {
        opaque::messages::OpaqueResponse::LoginSuccess { receipt } => {
            assert_eq!(receipt.step_id, 1, "step_id must be 1 (first in chain)");
            assert_eq!(
                receipt.prev_receipt_hash, [0u8; 64],
                "prev_receipt_hash must be zeros for first receipt"
            );
            assert_eq!(receipt.ceremony_session_id, session_id);
            assert_eq!(receipt.user_id, user_id);
            assert_eq!(receipt.dpop_key_hash, dpop_hash);
            assert!(receipt.timestamp > 0, "timestamp must be set");
            assert!(!receipt.signature.is_empty(), "signature must not be empty");
        }
        _ => panic!("expected LoginSuccess"),
    }
}

// ── Session Key Agreement ───────────────────────────────────────────────

#[test]
fn client_and_server_agree_on_session_key() {
    let mut store = CredentialStore::new();
    let password = b"session-key-test";
    let _user_id = store.register_with_password("eve", password).unwrap();

    let mut rng = OsRng;

    // Client starts login
    let client_start = ClientLogin::<OpaqueCs>::start(&mut rng, password).unwrap();
    let (resp_bytes, server_login) =
        handle_login_start(&store, "eve", &client_start.message.serialize().to_vec()).unwrap();

    // Client finishes login — gets session key
    let cred_resp = opaque_ke::CredentialResponse::<OpaqueCs>::deserialize(&resp_bytes).unwrap();
    let client_finish = client_start
        .state
        .finish(
            &mut rng,
            password,
            cred_resp,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    let client_session_key = client_finish.session_key.clone();

    // Server finishes login — gets session key
    let finalization =
        opaque_ke::CredentialFinalization::<OpaqueCs>::deserialize(
            &client_finish.message.serialize().to_vec(),
        )
        .unwrap();

    let server_finish = server_login
        .finish(finalization, opaque_ke::ServerLoginParameters::default())
        .unwrap();

    // Session keys must match
    assert_eq!(
        client_session_key, server_finish.session_key,
        "client and server session keys must be identical"
    );
}

// ── FIPS Cipher Suite Tests ──────────────────────────────────────────────

/// Helper to run a closure on a thread with 8 MiB stack (ML-DSA-87 needs it).
fn run_with_large_stack<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("join")
}

/// Register with FIPS cipher suite (PBKDF2-SHA512), then verify login succeeds.
#[test]
fn test_opaque_fips_registration() {
    run_with_large_stack(|| {
        let mut store = CredentialStore::new_dual();
        let password = b"fips-test-password-hunter42";

        // Register under FIPS cipher suite
        let user_id = store
            .register_with_password_fips("fips_alice", password)
            .expect("FIPS registration must succeed");

        assert!(store.user_exists("fips_alice"));
        assert_eq!(store.get_user_id("fips_alice"), Some(user_id));

        // The KSF algorithm field must record the FIPS cipher suite
        assert_eq!(
            store.get_ksf_algorithm("fips_alice"),
            Some(KSF_PBKDF2_SHA512),
            "FIPS registration must set ksf_algorithm to pbkdf2-sha512"
        );

        // Verify password via adaptive verify (FIPS mode off — still uses correct path)
        let (verified_id, needs_rereg) = store
            .verify_password_adaptive("fips_alice", password)
            .expect("FIPS login must succeed");

        assert_eq!(verified_id, user_id, "user_id must match after FIPS login");
        assert!(
            !needs_rereg,
            "FIPS-registered user does not need re-registration"
        );

        // Wrong password must fail
        let result = store.verify_password_adaptive("fips_alice", b"wrong-password");
        assert!(result.is_err(), "wrong password must fail for FIPS user");
    });
}

/// Register with Argon2id, enable FIPS mode, verify adaptive login still works.
/// The user should be flagged for re-registration.
#[test]
fn test_opaque_ksf_migration() {
    run_with_large_stack(|| {
        let mut store = CredentialStore::new_dual();
        let password = b"migration-test-password";

        // Register under Argon2id (non-FIPS)
        let user_id = store.register_with_password("legacy_bob", password).unwrap();

        assert_eq!(
            store.get_ksf_algorithm("legacy_bob"),
            Some(KSF_ARGON2ID),
            "Non-FIPS registration must record argon2id-v19"
        );

        // Enable FIPS mode
        common::fips::set_fips_mode_unchecked(true);

        // Adaptive verify must still succeed (uses Argon2id path for legacy user)
        let result = store.verify_password_adaptive("legacy_bob", password);

        // Restore FIPS mode before any assertions (avoids contaminating other tests)
        common::fips::set_fips_mode_unchecked(false);

        let (verified_id, needs_rereg) = result
            .expect("Argon2id user must still log in even when FIPS mode is active");

        assert_eq!(verified_id, user_id);
        assert!(
            needs_rereg,
            "Argon2id user in FIPS mode must be flagged for re-registration"
        );
    });
}

/// Verify that ksf_algorithm is set correctly for both cipher suites.
#[test]
fn test_opaque_adaptive_verify() {
    run_with_large_stack(|| {
        let mut store = CredentialStore::new_dual();

        // Register two users under different cipher suites
        store.register_with_password("argon2_user", b"pw1").unwrap();
        store
            .register_with_password_fips("fips_user", b"pw2")
            .expect("FIPS registration");

        // Verify ksf_algorithm is set correctly for each user
        assert_eq!(
            store.get_ksf_algorithm("argon2_user"),
            Some(KSF_ARGON2ID),
            "Argon2id user must have argon2id-v19 KSF"
        );
        assert_eq!(
            store.get_ksf_algorithm("fips_user"),
            Some(KSF_PBKDF2_SHA512),
            "FIPS user must have pbkdf2-sha512 KSF"
        );

        // Both users can log in adaptively with correct passwords (FIPS mode off)
        let (_, needs_rereg_argon2) = store
            .verify_password_adaptive("argon2_user", b"pw1")
            .expect("argon2 user login");
        let (_, needs_rereg_fips) = store
            .verify_password_adaptive("fips_user", b"pw2")
            .expect("fips user login");

        // Without FIPS mode active, Argon2id users do not need re-registration
        assert!(
            !needs_rereg_argon2,
            "No re-registration needed when FIPS mode is off"
        );
        assert!(
            !needs_rereg_fips,
            "FIPS user never needs re-registration"
        );

        // Unknown user must return an error
        assert!(
            store.verify_password_adaptive("nobody", b"pw").is_err(),
            "Unknown user must return error"
        );
    });
}
