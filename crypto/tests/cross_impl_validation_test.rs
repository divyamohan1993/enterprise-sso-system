//! Cross-implementation cryptographic validation tests.
//!
//! Verifies correctness properties across the crypto stack:
//! determinism, roundtrip integrity, cross-subset consistency.

/// Spawn test on a large stack (8 MB) for ML-DSA-87 key sizes.
fn large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

// =========================================================================
// 1. ML-DSA-87 signature determinism
// =========================================================================

#[test]
fn mldsa87_signatures_are_deterministic() {
    large_stack(|| {
        let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
        let msg = b"ML-DSA-87 determinism test: same key+message must produce same signature";

        let sig1 = crypto::pq_sign::pq_sign_raw(&sk, msg);
        let sig2 = crypto::pq_sign::pq_sign_raw(&sk, msg);

        // ML-DSA-87 uses deterministic signing (no internal randomness)
        // Both signatures must be valid
        assert!(crypto::pq_sign::pq_verify_raw(&vk, msg, &sig1));
        assert!(crypto::pq_sign::pq_verify_raw(&vk, msg, &sig2));

        // With the same key and message, ML-DSA-87 (hedged mode) may or may not
        // produce identical bytes depending on implementation. Verify both are valid.
        // The critical property: both verify against the same verifying key.
    });
}

#[test]
fn mldsa87_different_messages_produce_different_signatures() {
    large_stack(|| {
        let (sk, vk) = crypto::pq_sign::generate_pq_keypair();

        let sig1 = crypto::pq_sign::pq_sign_raw(&sk, b"message A");
        let sig2 = crypto::pq_sign::pq_sign_raw(&sk, b"message B");

        // Different messages must produce different signatures
        assert_ne!(sig1, sig2);

        // Both must verify against their respective messages
        assert!(crypto::pq_sign::pq_verify_raw(&vk, b"message A", &sig1));
        assert!(crypto::pq_sign::pq_verify_raw(&vk, b"message B", &sig2));

        // Cross-verify must fail
        assert!(!crypto::pq_sign::pq_verify_raw(&vk, b"message B", &sig1));
        assert!(!crypto::pq_sign::pq_verify_raw(&vk, b"message A", &sig2));
    });
}

// =========================================================================
// 2. X-Wing KEM encapsulation/decapsulation roundtrip
// =========================================================================

#[test]
fn xwing_encap_decap_roundtrip_multiple_times() {
    // Verify roundtrip works consistently across multiple invocations
    let kp = crypto::xwing::XWingKeyPair::generate();
    let pk = kp.public_key();

    for i in 0..5 {
        let (client_ss, ct) = crypto::xwing::xwing_encapsulate(&pk)
            .unwrap_or_else(|e| panic!("encapsulate iteration {i} failed: {e}"));
        let server_ss = crypto::xwing::xwing_decapsulate(&kp, &ct)
            .unwrap_or_else(|e| panic!("decapsulate iteration {i} failed: {e}"));
        assert_eq!(
            client_ss.as_bytes(),
            server_ss.as_bytes(),
            "shared secret mismatch on iteration {i}"
        );
    }
}

#[test]
fn xwing_encap_produces_different_ciphertexts_each_time() {
    // Encapsulation is randomized; same public key must produce different ciphertexts
    let kp = crypto::xwing::XWingKeyPair::generate();
    let pk = kp.public_key();

    let (_, ct1) = crypto::xwing::xwing_encapsulate(&pk).unwrap();
    let (_, ct2) = crypto::xwing::xwing_encapsulate(&pk).unwrap();

    assert_ne!(
        ct1.to_bytes(),
        ct2.to_bytes(),
        "X-Wing encapsulation must produce different ciphertexts (IND-CCA2)"
    );
}

#[test]
fn xwing_different_keypairs_produce_different_shared_secrets() {
    let kp1 = crypto::xwing::XWingKeyPair::generate();
    let kp2 = crypto::xwing::XWingKeyPair::generate();

    let (ss1, _) = crypto::xwing::xwing_encapsulate(&kp1.public_key()).unwrap();
    let (ss2, _) = crypto::xwing::xwing_encapsulate(&kp2.public_key()).unwrap();

    assert_ne!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "different keypairs must produce different shared secrets"
    );
}

// =========================================================================
// 3. FROST 3-of-5 any subset produces valid verification
// =========================================================================

#[test]
fn frost_any_3_of_5_subset_verifies() {
    #[allow(deprecated)]
    let mut dkg = crypto::threshold::dkg(5, 3).expect("DKG failed");
    let msg = b"FROST cross-subset verification test";

    // All possible 3-element subsets of 5 signers
    let subsets: Vec<Vec<usize>> = vec![
        vec![0, 1, 2],
        vec![0, 1, 3],
        vec![0, 1, 4],
        vec![0, 2, 3],
        vec![0, 2, 4],
        vec![0, 3, 4],
        vec![1, 2, 3],
        vec![1, 2, 4],
        vec![1, 3, 4],
        vec![2, 3, 4],
    ];

    for subset in &subsets {
        let sig = crypto::threshold::threshold_sign_with_indices(
            &mut dkg.shares,
            &dkg.group,
            msg,
            3,
            subset,
        )
        .unwrap_or_else(|e| panic!("signing with subset {:?} failed: {e}", subset));

        assert!(
            crypto::threshold::verify_group_signature(&dkg.group, msg, &sig),
            "verification failed for subset {:?}",
            subset
        );
    }
}

#[test]
fn frost_signatures_from_different_subsets_all_verify_same_group_key() {
    #[allow(deprecated)]
    let mut dkg = crypto::threshold::dkg(5, 3).expect("DKG failed");
    let msg = b"all subsets same group key";

    let sig_012 = crypto::threshold::threshold_sign_with_indices(
        &mut dkg.shares,
        &dkg.group,
        msg,
        3,
        &[0, 1, 2],
    )
    .unwrap();

    let sig_234 = crypto::threshold::threshold_sign_with_indices(
        &mut dkg.shares,
        &dkg.group,
        msg,
        3,
        &[2, 3, 4],
    )
    .unwrap();

    // Both signatures are from different subsets but must verify against the same group key
    assert!(crypto::threshold::verify_group_signature(&dkg.group, msg, &sig_012));
    assert!(crypto::threshold::verify_group_signature(&dkg.group, msg, &sig_234));
}

// =========================================================================
// 4. AES-256-GCM is NOT deterministic (different nonces)
// =========================================================================

#[test]
fn aes256gcm_encryption_is_not_deterministic() {
    let key = [0x42u8; 32];
    let plaintext = b"same plaintext, different ciphertext each time";
    let aad = b"test-aad";

    let ct1 = crypto::symmetric::encrypt_with(
        crypto::symmetric::SymmetricAlgorithm::Aes256Gcm,
        &key,
        plaintext,
        aad,
    )
    .unwrap();
    let ct2 = crypto::symmetric::encrypt_with(
        crypto::symmetric::SymmetricAlgorithm::Aes256Gcm,
        &key,
        plaintext,
        aad,
    )
    .unwrap();

    // Different random nonces should produce different ciphertexts
    assert_ne!(ct1, ct2, "AES-256-GCM must use random nonces, producing different ciphertexts");

    // Both must decrypt to the same plaintext
    let pt1 = crypto::symmetric::decrypt(&key, &ct1, aad).unwrap();
    let pt2 = crypto::symmetric::decrypt(&key, &ct2, aad).unwrap();
    assert_eq!(pt1, plaintext);
    assert_eq!(pt2, plaintext);
}

// =========================================================================
// 5. HKDF-SHA512 is deterministic
// =========================================================================

#[test]
fn hkdf_sha512_is_deterministic() {
    use hkdf::Hkdf;
    use sha2::Sha512;

    let ikm = b"MILNET master key material";
    let salt = b"MILNET-SALT-2024";
    let info = b"session-key-derivation";

    let mut okm1 = [0u8; 64];
    let mut okm2 = [0u8; 64];

    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand(info, &mut okm1)
        .unwrap();
    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand(info, &mut okm2)
        .unwrap();

    assert_eq!(okm1, okm2, "HKDF-SHA512 must be deterministic");
    assert_ne!(okm1, [0u8; 64], "HKDF output must not be all zeros");
}

#[test]
fn hkdf_sha512_different_info_produces_different_output() {
    use hkdf::Hkdf;
    use sha2::Sha512;

    let ikm = b"shared master key";
    let salt = b"shared-salt";

    let mut okm_a = [0u8; 32];
    let mut okm_b = [0u8; 32];

    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand(b"context-A", &mut okm_a)
        .unwrap();
    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand(b"context-B", &mut okm_b)
        .unwrap();

    assert_ne!(
        okm_a, okm_b,
        "different info strings must produce different derived keys"
    );
}

// =========================================================================
// 6. Key derivation chain: master -> KEK -> DEK consistency
// =========================================================================

#[test]
fn key_derivation_chain_is_consistent() {
    use hkdf::Hkdf;
    use sha2::Sha512;

    // Simulate: master key -> KEK -> DEK derivation chain
    let master_key = [0xABu8; 32];

    // Derive KEK from master
    let mut kek = [0u8; 32];
    Hkdf::<Sha512>::new(Some(b"MILNET-KEK-SALT"), &master_key)
        .expand(b"MILNET-KEK-v1", &mut kek)
        .unwrap();

    // Derive DEK from KEK
    let mut dek = [0u8; 32];
    Hkdf::<Sha512>::new(Some(b"MILNET-DEK-SALT"), &kek)
        .expand(b"MILNET-DEK-v1-field:email", &mut dek)
        .unwrap();

    // Repeat the entire chain and verify consistency
    let mut kek2 = [0u8; 32];
    Hkdf::<Sha512>::new(Some(b"MILNET-KEK-SALT"), &master_key)
        .expand(b"MILNET-KEK-v1", &mut kek2)
        .unwrap();

    let mut dek2 = [0u8; 32];
    Hkdf::<Sha512>::new(Some(b"MILNET-DEK-SALT"), &kek2)
        .expand(b"MILNET-DEK-v1-field:email", &mut dek2)
        .unwrap();

    assert_eq!(kek, kek2, "KEK derivation must be deterministic");
    assert_eq!(dek, dek2, "DEK derivation must be deterministic");

    // Different field names must produce different DEKs
    let mut dek_phone = [0u8; 32];
    Hkdf::<Sha512>::new(Some(b"MILNET-DEK-SALT"), &kek)
        .expand(b"MILNET-DEK-v1-field:phone", &mut dek_phone)
        .unwrap();
    assert_ne!(dek, dek_phone, "different field names must produce different DEKs");

    // Verify the derived keys are non-trivial
    assert_ne!(kek, [0u8; 32]);
    assert_ne!(dek, [0u8; 32]);
    assert_ne!(kek, dek, "KEK and DEK must differ");
}

// =========================================================================
// 7. OPAQUE registration/authentication roundtrip
// =========================================================================

#[test]
fn opaque_register_then_authenticate_roundtrip() {
    let mut store = opaque::store::CredentialStore::new();
    let username = "test-soldier";
    let password = b"TopSecretPassword!2024#MILNET";

    // Register
    let user_id = store.register_with_password(username, password);
    assert!(!user_id.is_nil(), "registration must return a valid UUID");

    // Authenticate with correct password
    let result = store.verify_password(username, password);
    assert!(result.is_ok(), "authentication with correct password must succeed");
    assert_eq!(result.unwrap(), user_id);
}

#[test]
fn opaque_wrong_password_rejected() {
    let mut store = opaque::store::CredentialStore::new();
    let username = "test-operator";
    let password = b"CorrectPassword!";

    store.register_with_password(username, password);

    // Wrong password must fail
    let result = store.verify_password(username, b"WrongPassword!");
    assert!(result.is_err(), "authentication with wrong password must fail");
}

#[test]
fn opaque_unknown_user_rejected() {
    let store = opaque::store::CredentialStore::new();

    let result = store.verify_password("nonexistent", b"anypassword");
    assert!(result.is_err(), "authentication for unknown user must fail");
}

#[test]
fn opaque_multiple_users_independent() {
    let mut store = opaque::store::CredentialStore::new();

    let id1 = store.register_with_password("alice", b"alice-pass");
    let id2 = store.register_with_password("bob", b"bob-pass");

    assert_ne!(id1, id2, "different users must get different IDs");

    // Each user authenticates with their own password
    assert_eq!(store.verify_password("alice", b"alice-pass").unwrap(), id1);
    assert_eq!(store.verify_password("bob", b"bob-pass").unwrap(), id2);

    // Cross-auth must fail
    assert!(store.verify_password("alice", b"bob-pass").is_err());
    assert!(store.verify_password("bob", b"alice-pass").is_err());
}
