// SECURITY / PERF NOTE (audit F1): `CredentialStore` now runs the OPAQUE KSF
// at military strength (Argon2id, 64 MiB / t=3 / p=4). Each `register` + `login`
// case therefore performs two ~64 MiB memory-hard hashes. At `with_cases(1000)`
// that is thousands of 64 MiB hashes — minutes of wall-clock and a large memory
// footprint — so these exhaustive property tests are marked `#[ignore]` and run
// deliberately on the C2 VM with `cargo test --release -- --ignored`. We did NOT
// weaken the production KSF to make the suite fast (that would defeat F1); we
// moved the heavy exhaustive sweep to an on-demand release run. The cheap,
// always-on coverage of the same invariants lives in
// `opaque/src/store.rs` unit tests and `opaque/tests/opaque_flow_test.rs`.
use proptest::prelude::*;
use opaque::store::CredentialStore;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))] // I20

    /// Registration then login with correct password succeeds.
    #[test]
    #[ignore = "heavy: 1000× military Argon2id (64 MiB) — run on C2 with --release -- --ignored"]
    fn register_then_login_correct_password(
        password in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut store = CredentialStore::new();
        let username = "proptest_user";
        let user_id = store.register_with_password(username, &password)
            .expect("registration must succeed");

        let result = store.verify_password(username, &password);
        prop_assert!(result.is_ok(), "login with correct password must succeed");
        prop_assert_eq!(result.unwrap(), user_id);
    }

    /// Registration then login with wrong password fails.
    #[test]
    #[ignore = "heavy: 1000× military Argon2id (64 MiB) — run on C2 with --release -- --ignored"]
    fn register_then_login_wrong_password(
        password in prop::collection::vec(any::<u8>(), 1..128),
        wrong_byte in any::<u8>(),
    ) {
        let mut store = CredentialStore::new();
        let username = "proptest_wrong";
        store.register_with_password(username, &password)
            .expect("registration must succeed");

        // Construct a different password by appending a byte
        let mut wrong_pw = password.clone();
        wrong_pw.push(wrong_byte);

        let result = store.verify_password(username, &wrong_pw);
        prop_assert!(result.is_err(), "login with wrong password must fail");
    }

    /// Different passwords produce different registrations.
    #[test]
    #[ignore = "heavy: 1000× military Argon2id (64 MiB) — run on C2 with --release -- --ignored"]
    fn different_passwords_different_registrations(
        pw1 in prop::collection::vec(any::<u8>(), 1..64),
        pw2 in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(pw1 != pw2);

        let mut store1 = CredentialStore::new();
        store1.register_with_password("user_a", &pw1).expect("reg1");
        let reg1 = store1.get_registration_bytes("user_a").expect("get reg1");

        let mut store2 = CredentialStore::new();
        store2.register_with_password("user_b", &pw2).expect("reg2");
        let reg2 = store2.get_registration_bytes("user_b").expect("get reg2");

        // Different passwords must produce different OPAQUE registrations
        // (with overwhelming probability -- same server setup would be needed
        // for identical registrations, and even then randomness differs).
        prop_assert_ne!(reg1, reg2, "different passwords should produce different registrations");
    }

    /// Server never learns the password: no password bytes present in registration.
    #[test]
    #[ignore = "heavy: 1000× military Argon2id (64 MiB) — run on C2 with --release -- --ignored"]
    fn server_state_does_not_contain_password_bytes(
        password in prop::collection::vec(any::<u8>(), 4..128),
    ) {
        let mut store = CredentialStore::new();
        store.register_with_password("secret_user", &password)
            .expect("registration must succeed");

        let reg_bytes = store.get_registration_bytes("secret_user")
            .expect("get registration");

        // The password (if longer than 3 bytes) must not appear as a substring
        // in the server's stored registration. OPAQUE's aPAKE guarantee.
        if password.len() >= 4 {
            let pw_slice = &password[..];
            for window_start in 0..reg_bytes.len().saturating_sub(pw_slice.len()) {
                let window = &reg_bytes[window_start..window_start + pw_slice.len()];
                prop_assert_ne!(
                    window, pw_slice,
                    "password bytes must never appear in server registration state"
                );
            }
        }
    }
}

// ── Always-on lightweight regression ──────────────────────────────────────
//
// The exhaustive 1000-case proptests above are `#[ignore]` because each case
// runs the 64 MiB military Argon2id KSF. To keep continuous coverage of the
// same core invariants in the default `cargo test` run, the following uses a
// SMALL fixed set of representative passwords (one store creation, a handful of
// strong-KSF hashes total). It exercises the real production KSF — it is not a
// weakened path.
#[test]
fn military_ksf_register_login_invariants_smoke() {
    let cases: &[&[u8]] = &[
        b"",                              // empty password edge case
        b"correct horse battery staple",  // passphrase
        &[0xFFu8; 72],                    // long, high-entropy binary
    ];
    let mut store = CredentialStore::new();
    for (i, pw) in cases.iter().enumerate() {
        let user = format!("smoke_user_{i}");
        let uid = store
            .register_with_password(&user, pw)
            .expect("registration must succeed under military KSF");

        // Correct password authenticates and returns the same user id.
        let ok = store.verify_password(&user, pw).expect("correct pw must verify");
        assert_eq!(ok, uid);

        // A modified password must fail.
        let mut wrong = pw.to_vec();
        wrong.push(0x00);
        assert!(
            store.verify_password(&user, &wrong).is_err(),
            "wrong password must fail under military KSF"
        );

        // Server registration must never contain the raw password (aPAKE).
        if pw.len() >= 4 {
            let reg = store.get_registration_bytes(&user).expect("reg bytes");
            let appears = reg.windows(pw.len()).any(|w| w == *pw);
            assert!(!appears, "password bytes must not appear in registration");
        }
    }
}
