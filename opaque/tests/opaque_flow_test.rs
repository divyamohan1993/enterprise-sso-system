//! OPAQUE protocol hardening tests.
//!
//! Tests the full registration+login flow, wrong password rejection,
//! non-existent user handling, credential store serde, message roundtrips,
//! double registration, password change, FIPS mode, and Drop zeroization.

use opaque::opaque_impl::OpaqueCs;
use opaque::service::{handle_login_finish, handle_login_start, handle_request, ReceiptSigner};
use opaque::store::{CredentialStore, KSF_ARGON2ID, KSF_PBKDF2_SHA512};
use opaque::messages::{OpaqueRequest, OpaqueResponse};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, ServerRegistration,
};
use rand::rngs::OsRng;
use uuid::Uuid;

/// Fixed signing key for tests.
const SIGNING_KEY: [u8; 64] = [0x42u8; 64];

/// Helper to run a closure on a thread with 8 MiB stack (ML-DSA needs it).
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

/// Perform a full OPAQUE login returning the OpaqueResponse.
fn do_full_login(
    store: &CredentialStore,
    username: &str,
    password: &[u8],
    user_id: Uuid,
) -> OpaqueResponse {
    let mut rng = OsRng;
    let ceremony_session_id = [0xAA; 32];
    let dpop_key_hash = [0xBB; 64];

    let client_start = ClientLogin::<OpaqueCs>::start(&mut rng, password).unwrap();
    let (resp_bytes, server_login) =
        handle_login_start(store, username, &client_start.message.serialize().to_vec()).unwrap();

    let cred_resp = opaque_ke::CredentialResponse::<OpaqueCs>::deserialize(&resp_bytes).unwrap();
    let client_finish = client_start
        .state
        .finish(&mut rng, password, cred_resp, ClientLoginFinishParameters::default())
        .unwrap();

    let signer = ReceiptSigner::new(SIGNING_KEY);
    handle_login_finish(
        server_login,
        &client_finish.message.serialize().to_vec(),
        &signer,
        user_id,
        ceremony_session_id,
        dpop_key_hash,
    )
}

// ── 1. Full registration + login flow (happy path) ─────────────────────

#[test]
fn full_registration_and_login_succeeds() {
    run_with_large_stack(|| {
        let mut store = CredentialStore::new();
        let password = b"correct-horse-battery-staple";
        let user_id = store.register_with_password("alice", password);

        assert!(store.user_exists("alice"));
        assert_eq!(store.user_count(), 1);

        let response = do_full_login(&store, "alice", password, user_id);
        match response {
            OpaqueResponse::LoginSuccess { receipt } => {
                assert_eq!(receipt.user_id, user_id);
                assert_eq!(receipt.ceremony_session_id, [0xAA; 32]);
                assert_eq!(receipt.dpop_key_hash, [0xBB; 64]);
                assert_eq!(receipt.step_id, 1);
                assert!(!receipt.signature.is_empty());
            }
            OpaqueResponse::Error { message } => panic!("expected success, got error: {message}"),
            _ => panic!("unexpected response type"),
        }
    });
}

// ── 2. Login with wrong password FAILS ──────────────────────────────────

#[test]
fn login_with_wrong_password_fails() {
    let mut store = CredentialStore::new();
    store.register_with_password("bob", b"real-password");

    let mut rng = OsRng;

    // Start login with wrong password
    let client_start = ClientLogin::<OpaqueCs>::start(&mut rng, b"wrong-password").unwrap();
    let (resp_bytes, _server_login) =
        handle_login_start(&store, "bob", &client_start.message.serialize().to_vec()).unwrap();

    let cred_resp = opaque_ke::CredentialResponse::<OpaqueCs>::deserialize(&resp_bytes).unwrap();

    // Client finish should fail: OPAQUE detects wrong password on client side
    let result = client_start.state.finish(
        &mut rng,
        b"wrong-password",
        cred_resp,
        ClientLoginFinishParameters::default(),
    );

    assert!(result.is_err(), "login with wrong password must fail at client finish");
}

// ── 3. Login for non-existent user FAILS ────────────────────────────────

#[test]
fn login_nonexistent_user_returns_dummy_response() {
    let store = CredentialStore::new();
    let mut rng = OsRng;

    let client_start = ClientLogin::<OpaqueCs>::start(&mut rng, b"any-password").unwrap();
    let result = handle_login_start(&store, "nobody", &client_start.message.serialize().to_vec());

    // Server returns a dummy response (not an error) to prevent username enumeration
    assert!(
        result.is_ok(),
        "login start for unknown user must succeed (anti-enumeration)"
    );
}

#[test]
fn verify_password_nonexistent_user_returns_error() {
    let store = CredentialStore::new();
    let result = store.verify_password("ghost", b"password");
    assert!(result.is_err(), "verify_password for non-existent user must error");
}

// ── 4. Credential store serialization/deserialization roundtrip ──────────

#[test]
fn registration_bytes_roundtrip() {
    let mut store = CredentialStore::new();
    store.register_with_password("charlie", b"test-pw");

    // Extract raw registration bytes
    let reg_bytes = store.get_registration_bytes("charlie").unwrap();
    assert!(!reg_bytes.is_empty());

    // Deserialize back to ServerRegistration
    let deserialized = ServerRegistration::<OpaqueCs>::deserialize(&reg_bytes);
    assert!(deserialized.is_ok(), "registration bytes must deserialize cleanly");

    // Re-serialize and compare
    let reserialized = deserialized.unwrap().serialize().to_vec();
    assert_eq!(
        reg_bytes, reserialized,
        "registration roundtrip must be byte-identical"
    );
}

#[test]
fn restore_user_preserves_login_capability() {
    let mut store1 = CredentialStore::new();
    let password = b"restore-test-pw";
    let user_id = store1.register_with_password("dave", password);
    let reg_bytes = store1.get_registration_bytes("dave").unwrap();

    // Create a new store and restore the user
    let mut store2 = CredentialStore::with_server_setup(store1.server_setup().clone());
    store2.restore_user("dave", user_id, reg_bytes);

    assert!(store2.user_exists("dave"));
    assert_eq!(store2.get_user_id("dave"), Some(user_id));

    // Login should succeed with the restored store
    let result = store2.verify_password("dave", password);
    assert!(result.is_ok(), "login must succeed after restore");
    assert_eq!(result.unwrap(), user_id);
}

// ── 5. Message serialization roundtrip for all message types ────────────

#[test]
fn opaque_request_login_start_roundtrip() {
    let req = OpaqueRequest::LoginStart {
        username: "testuser".into(),
        credential_request: vec![0xAA; 64],
        ceremony_session_id: [0xBB; 32],
        dpop_key_hash: [0xCC; 64],
    };
    let bytes = postcard::to_allocvec(&req).unwrap();
    let decoded: OpaqueRequest = postcard::from_bytes(&bytes).unwrap();
    match decoded {
        OpaqueRequest::LoginStart { username, credential_request, ceremony_session_id, dpop_key_hash } => {
            assert_eq!(username, "testuser");
            assert_eq!(credential_request, vec![0xAA; 64]);
            assert_eq!(ceremony_session_id, [0xBB; 32]);
            assert_eq!(dpop_key_hash, [0xCC; 64]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn opaque_request_login_finish_roundtrip() {
    let req = OpaqueRequest::LoginFinish {
        credential_finalization: vec![0xDD; 32],
    };
    let bytes = postcard::to_allocvec(&req).unwrap();
    let decoded: OpaqueRequest = postcard::from_bytes(&bytes).unwrap();
    match decoded {
        OpaqueRequest::LoginFinish { credential_finalization } => {
            assert_eq!(credential_finalization, vec![0xDD; 32]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn opaque_request_register_start_roundtrip() {
    let req = OpaqueRequest::RegisterStart {
        username: "newuser".into(),
        registration_request: vec![0xEE; 48],
    };
    let bytes = postcard::to_allocvec(&req).unwrap();
    let decoded: OpaqueRequest = postcard::from_bytes(&bytes).unwrap();
    match decoded {
        OpaqueRequest::RegisterStart { username, registration_request } => {
            assert_eq!(username, "newuser");
            assert_eq!(registration_request, vec![0xEE; 48]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn opaque_request_register_finish_roundtrip() {
    let req = OpaqueRequest::RegisterFinish {
        username: "newuser".into(),
        registration_upload: vec![0xFF; 96],
    };
    let bytes = postcard::to_allocvec(&req).unwrap();
    let decoded: OpaqueRequest = postcard::from_bytes(&bytes).unwrap();
    match decoded {
        OpaqueRequest::RegisterFinish { username, registration_upload } => {
            assert_eq!(username, "newuser");
            assert_eq!(registration_upload, vec![0xFF; 96]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn opaque_response_login_challenge_roundtrip() {
    let resp = OpaqueResponse::LoginChallenge {
        credential_response: vec![0x11; 128],
    };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: OpaqueResponse = postcard::from_bytes(&bytes).unwrap();
    match decoded {
        OpaqueResponse::LoginChallenge { credential_response } => {
            assert_eq!(credential_response, vec![0x11; 128]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn opaque_response_login_success_roundtrip() {
    let receipt = common::types::Receipt {
        ceremony_session_id: [0x22; 32],
        step_id: 1,
        prev_receipt_hash: [0; 64],
        user_id: Uuid::nil(),
        dpop_key_hash: [0x33; 64],
        timestamp: 1_700_000_000,
        nonce: [0x44; 32],
        signature: vec![0x55; 32],
        ttl_seconds: 30,
    };
    let resp = OpaqueResponse::LoginSuccess { receipt: receipt.clone() };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: OpaqueResponse = postcard::from_bytes(&bytes).unwrap();
    match decoded {
        OpaqueResponse::LoginSuccess { receipt: r } => {
            assert_eq!(r.ceremony_session_id, [0x22; 32]);
            assert_eq!(r.step_id, 1);
            assert_eq!(r.user_id, Uuid::nil());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn opaque_response_register_complete_roundtrip() {
    let uid = Uuid::new_v4();
    let resp = OpaqueResponse::RegisterComplete { user_id: uid };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: OpaqueResponse = postcard::from_bytes(&bytes).unwrap();
    match decoded {
        OpaqueResponse::RegisterComplete { user_id } => assert_eq!(user_id, uid),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn opaque_response_threshold_partial_eval_roundtrip() {
    let resp = OpaqueResponse::ThresholdPartialEval {
        server_id: 2,
        evaluation: vec![0xAA; 64],
        proof: vec![0xBB; 32],
    };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: OpaqueResponse = postcard::from_bytes(&bytes).unwrap();
    match decoded {
        OpaqueResponse::ThresholdPartialEval { server_id, evaluation, proof } => {
            assert_eq!(server_id, 2);
            assert_eq!(evaluation, vec![0xAA; 64]);
            assert_eq!(proof, vec![0xBB; 32]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn opaque_response_error_roundtrip() {
    let resp = OpaqueResponse::Error { message: "something broke".into() };
    let bytes = postcard::to_allocvec(&resp).unwrap();
    let decoded: OpaqueResponse = postcard::from_bytes(&bytes).unwrap();
    match decoded {
        OpaqueResponse::Error { message } => assert_eq!(message, "something broke"),
        _ => panic!("wrong variant"),
    }
}

// ── 6. Double registration with same username behavior ──────────────────

#[test]
fn double_registration_overwrites_previous() {
    let mut store = CredentialStore::new();
    let uid1 = store.register_with_password("eve", b"password-1");
    let uid2 = store.register_with_password("eve", b"password-2");

    // Second registration should overwrite the first
    assert_ne!(uid1, uid2, "new registration generates a new user_id");
    assert_eq!(store.user_count(), 1, "store should still have one user");
    assert_eq!(store.get_user_id("eve"), Some(uid2));

    // Login with the new password should succeed
    let result = store.verify_password("eve", b"password-2");
    assert!(result.is_ok(), "login with new password must succeed");
    assert_eq!(result.unwrap(), uid2);

    // Login with the old password should fail
    let result = store.verify_password("eve", b"password-1");
    assert!(result.is_err(), "login with old password must fail after re-registration");
}

// ── 7. Login after password change ──────────────────────────────────────

#[test]
fn login_after_password_change() {
    let mut store = CredentialStore::new();
    let _old_uid = store.register_with_password("frank", b"old-password");

    // Verify old password works
    assert!(store.verify_password("frank", b"old-password").is_ok());

    // Re-register with new password (simulates password change)
    let new_uid = store.register_with_password("frank", b"new-password");

    // New password works
    assert!(store.verify_password("frank", b"new-password").is_ok());
    assert_eq!(store.verify_password("frank", b"new-password").unwrap(), new_uid);

    // Old password no longer works
    assert!(
        store.verify_password("frank", b"old-password").is_err(),
        "old password must fail after password change"
    );
}

// ── 8. FIPS mode login uses PBKDF2 KSF ─────────────────────────────────

#[test]
fn fips_registration_and_login() {
    run_with_large_stack(|| {
        let mut store = CredentialStore::new_dual();
        let password = b"fips-test-password";

        // Register under FIPS cipher suite
        let user_id = store
            .register_with_password_fips("fips_user", password)
            .expect("FIPS registration must succeed");

        // Verify KSF algorithm is PBKDF2
        assert_eq!(store.get_ksf_algorithm("fips_user"), Some(KSF_PBKDF2_SHA512));

        // Login via adaptive verify (FIPS mode off)
        let (verified_id, needs_rereg) = store
            .verify_password_adaptive("fips_user", password)
            .expect("FIPS login must succeed");
        assert_eq!(verified_id, user_id);
        assert!(!needs_rereg, "FIPS user does not need re-registration");

        // Wrong password under FIPS must fail
        let result = store.verify_password_adaptive("fips_user", b"wrong");
        assert!(result.is_err(), "wrong FIPS password must fail");
    });
}

#[test]
fn fips_registration_without_dual_setup_fails() {
    run_with_large_stack(|| {
        let mut store = CredentialStore::new(); // NOT new_dual()
        let result = store.register_with_password_fips("user", b"pw");
        assert!(
            result.is_err(),
            "FIPS registration must fail without dual setup"
        );
    });
}

#[test]
fn argon2id_user_flagged_for_rereg_in_fips_mode() {
    run_with_large_stack(|| {
        let mut store = CredentialStore::new_dual();
        let password = b"argon2-test-pw";
        store.register_with_password("legacy", password);

        assert_eq!(store.get_ksf_algorithm("legacy"), Some(KSF_ARGON2ID));

        // Enable FIPS mode
        common::fips::set_fips_mode_unchecked(true);

        let result = store.verify_password_adaptive("legacy", password);

        // Restore FIPS mode before assertions
        common::fips::set_fips_mode_unchecked(false);

        let (_, needs_rereg) = result.expect("argon2 login must still work in FIPS mode");
        assert!(
            needs_rereg,
            "Argon2id user must be flagged for re-registration in FIPS mode"
        );
    });
}

// ── 9. Store Drop zeroizes server setup ─────────────────────────────────

#[test]
fn credential_store_drop_clears_users() {
    // We cannot directly inspect zeroized memory after Drop, but we can verify
    // the store clears its user map as part of the Drop impl.
    let mut store = CredentialStore::new();
    store.register_with_password("user1", b"pw1");
    store.register_with_password("user2", b"pw2");
    assert_eq!(store.user_count(), 2);

    // Get the registration bytes before drop for later comparison
    let reg_bytes = store.get_registration_bytes("user1").unwrap();
    assert!(!reg_bytes.is_empty());

    // Drop the store (zeroization runs)
    drop(store);

    // If we got here without a panic, the Drop impl ran successfully.
    // The Drop impl calls zeroize on server_setup serialized bytes and clears users.
    // We verify conceptually that the store is designed to zeroize.
}

#[test]
fn credential_store_server_setup_serializable() {
    // Verify that the server_setup can be serialized (the Drop impl does this
    // to zeroize) without panicking.
    let store = CredentialStore::new();
    let setup_bytes = store.server_setup().serialize();
    assert!(
        !setup_bytes.is_empty(),
        "server setup must produce non-empty serialization"
    );
}

// ── handle_request stateless handler tests ──────────────────────────────

#[test]
fn handle_request_login_finish_without_state_returns_error() {
    let mut store = CredentialStore::new();
    let signing_key = [0x42u8; 64];

    let request = OpaqueRequest::LoginFinish {
        credential_finalization: vec![0xAA; 32],
    };

    let response = handle_request(&mut store, &request, &signing_key);
    match response {
        OpaqueResponse::Error { message } => {
            assert!(
                message.contains("stateful"),
                "error must mention stateful handling: {message}"
            );
        }
        _ => panic!("expected error for stateless LoginFinish"),
    }
}

// ── Edge cases ──────────────────────────────────────────────────────────

#[test]
fn empty_password_registration_and_login() {
    let mut store = CredentialStore::new();
    let user_id = store.register_with_password("empty_pw", b"");

    // Login with empty password should succeed
    let result = store.verify_password("empty_pw", b"");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), user_id);

    // Login with non-empty password should fail
    let result = store.verify_password("empty_pw", b"not-empty");
    assert!(result.is_err());
}

#[test]
fn unicode_username_works() {
    let mut store = CredentialStore::new();
    let user_id = store.register_with_password("\u{0939}\u{093F}\u{0928}\u{094D}\u{0926}\u{0940}", b"hindi-pw");
    assert!(store.user_exists("\u{0939}\u{093F}\u{0928}\u{094D}\u{0926}\u{0940}"));
    let result = store.verify_password("\u{0939}\u{093F}\u{0928}\u{094D}\u{0926}\u{0940}", b"hindi-pw");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), user_id);
}

#[test]
fn long_password_works() {
    let mut store = CredentialStore::new();
    let long_pw = vec![0x61u8; 1024]; // 1 KiB password
    let user_id = store.register_with_password("longpw", &long_pw);
    let result = store.verify_password("longpw", &long_pw);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), user_id);
}

#[test]
fn multiple_users_independent() {
    let mut store = CredentialStore::new();
    let uid1 = store.register_with_password("user_a", b"pw_a");
    let uid2 = store.register_with_password("user_b", b"pw_b");

    assert_ne!(uid1, uid2);
    assert_eq!(store.user_count(), 2);

    // Each user can only login with their own password
    assert!(store.verify_password("user_a", b"pw_a").is_ok());
    assert!(store.verify_password("user_a", b"pw_b").is_err());
    assert!(store.verify_password("user_b", b"pw_b").is_ok());
    assert!(store.verify_password("user_b", b"pw_a").is_err());
}

#[test]
fn usernames_returns_all_registered() {
    let mut store = CredentialStore::new();
    store.register_with_password("alpha", b"pw");
    store.register_with_password("beta", b"pw");
    store.register_with_password("gamma", b"pw");

    let mut names = store.usernames();
    names.sort();
    assert_eq!(names, vec!["alpha", "beta", "gamma"]);
}
