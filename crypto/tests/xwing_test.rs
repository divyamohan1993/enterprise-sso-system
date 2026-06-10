use crypto::xwing::{
    xwing_decapsulate, xwing_decapsulate_tagged, xwing_encapsulate, xwing_encapsulate_tagged,
    Ciphertext, KemAlgorithm, XWingKeyPair,
};

#[test]
fn xwing_key_exchange_produces_shared_secret() {
    let server_kp = XWingKeyPair::generate();
    let server_pk = server_kp.public_key();

    let (client_ss, ciphertext) = xwing_encapsulate(&server_pk).expect("encapsulate");
    let server_ss = xwing_decapsulate(&server_kp, &ciphertext)
        .expect("decapsulation should succeed");

    assert_eq!(
        client_ss.as_bytes(),
        server_ss.as_bytes(),
        "encapsulate and decapsulate must produce the same shared secret"
    );
}

#[test]
fn xwing_different_sessions_different_secrets() {
    let server_kp = XWingKeyPair::generate();
    let server_pk = server_kp.public_key();

    let (ss1, _ct1) = xwing_encapsulate(&server_pk).expect("encapsulate");
    let (ss2, _ct2) = xwing_encapsulate(&server_pk).expect("encapsulate");

    assert_ne!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "two independent encapsulations must produce different shared secrets"
    );
}

#[test]
fn xwing_wrong_key_fails() {
    let server_kp = XWingKeyPair::generate();
    let wrong_kp = XWingKeyPair::generate();
    let server_pk = server_kp.public_key();

    let (client_ss, ciphertext) = xwing_encapsulate(&server_pk).expect("encapsulate");
    // Decapsulating with wrong key should either error or produce a different secret
    // (ML-KEM uses implicit rejection which returns a pseudorandom value).
    match xwing_decapsulate(&wrong_kp, &ciphertext) {
        Ok(wrong_ss) => assert_ne!(
            client_ss.as_bytes(),
            wrong_ss.as_bytes(),
            "decapsulating with the wrong key must produce a different shared secret"
        ),
        Err(_) => { /* decapsulation correctly rejected */ }
    }
}

/// IETF X-Wing combiner BINDING (MAL-BIND-K-CT): the transmitted X25519
/// ephemeral key `ct_X` (the first 32 bytes of the ciphertext) is bound into
/// the derived shared secret. Mutating it MUST change the secret (or be
/// rejected). The previous `HKDF(x25519_ss || mlkem_ss)` combiner dropped
/// `ct_X`/`pk_X` entirely and so lacked this binding.
#[test]
fn xwing_binding_mutating_ct_x_changes_secret() {
    let server_kp = XWingKeyPair::generate();
    let server_pk = server_kp.public_key();

    let (client_ss, ciphertext) = xwing_encapsulate(&server_pk).expect("encapsulate");

    // Flip a bit in the X25519 ephemeral public key (ct_X = first 32 bytes).
    let mut ct_bytes = ciphertext.to_bytes();
    ct_bytes[5] ^= 0x01; // within the 32-byte X25519 ephemeral key region
    let mutated = Ciphertext::from_bytes(&ct_bytes).expect("ciphertext reconstruction");

    match xwing_decapsulate(&server_kp, &mutated) {
        Ok(ss) => assert_ne!(
            client_ss.as_bytes(),
            ss.as_bytes(),
            "mutating ct_X (X25519 ephemeral key) must change the derived secret"
        ),
        Err(_) => { /* low-order/rejection path is also acceptable */ }
    }
}

/// IETF X-Wing combiner BINDING (MAL-BIND-K-PK): the recipient X25519 public
/// key `pk_X` is bound into the derived secret. Two server keypairs that share
/// the SAME ML-KEM key but differ in their X25519 key would derive different
/// secrets for the same ciphertext. We approximate this at the public-API
/// level: a ciphertext produced for one server, decapsulated by a server whose
/// X25519 static key differs, must not reproduce the encapsulator's secret.
/// (The isolated `combine()` unit test in src/xwing.rs proves pk_X binding
/// directly while holding the sub-secrets fixed.)
#[test]
fn xwing_binding_distinct_recipient_keys_distinct_secrets() {
    let server_a = XWingKeyPair::generate();
    let server_b = XWingKeyPair::generate();

    let (ss_a, ct) = xwing_encapsulate(&server_a.public_key()).expect("encapsulate to A");

    // B has a different X25519 (and ML-KEM) key; decapsulating A's ciphertext
    // must not yield A's secret.
    match xwing_decapsulate(&server_b, &ct) {
        Ok(ss_b) => assert_ne!(
            ss_a.as_bytes(),
            ss_b.as_bytes(),
            "different recipient (pk_X) must not reproduce the encapsulator's secret"
        ),
        Err(_) => { /* rejection is also acceptable */ }
    }
}

/// The default tagged path (X-Wing hybrid) must agree byte-for-byte with the
/// untagged path's round-trip property: tagged encap/decap derives the same
/// shared secret on both sides and reports the X-Wing algorithm tag.
///
/// Serialized: mutates the process-global `MILNET_PQ_KEM_ONLY` env var.
#[test]
#[serial_test::serial]
fn xwing_tagged_and_untagged_paths_consistent() {
    // Ensure default (no KEM-only downgrade) so the tagged path selects X-Wing.
    std::env::remove_var("MILNET_PQ_KEM_ONLY");

    let server_kp = XWingKeyPair::generate();
    let server_pk = server_kp.public_key();

    let (client_ss, tagged_ct) =
        xwing_encapsulate_tagged(&server_pk).expect("tagged encapsulate");
    assert_eq!(
        tagged_ct.algorithm().expect("algorithm"),
        KemAlgorithm::XWing,
        "default tagged encapsulation must use X-Wing hybrid"
    );

    let server_ss =
        xwing_decapsulate_tagged(&server_kp, &tagged_ct).expect("tagged decapsulate");
    assert_eq!(
        client_ss.as_bytes(),
        server_ss.as_bytes(),
        "tagged X-Wing round-trip must produce matching shared secrets"
    );
}
