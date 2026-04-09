use proptest::prelude::*;
use opaque::store::CredentialStore;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Registration then login with correct password succeeds.
    #[test]
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
