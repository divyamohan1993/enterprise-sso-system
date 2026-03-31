//! Post-quantum cryptography hardened tests.
//!
//! Exercises ML-DSA-87, X-Wing (ML-KEM-1024 + X25519), SLH-DSA, memory
//! protection, FIPS KATs, and crypto agility dispatch — all with real
//! cryptographic operations.

// ML-DSA-87 keys are ~4 KB.  Spawn tests on threads with 8 MB stacks.
fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

// ── ML-DSA-87 (FIPS 204) ────────────────────────────────────────────────────

use crypto::pq_sign::{
    generate_pq_keypair, pq_sign_raw, pq_verify_raw,
    PqSignatureAlgorithm, pq_sign_tagged, pq_verify_tagged,
};

#[test]
fn mldsa87_sign_verify_roundtrip() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let message = b"ML-DSA-87 roundtrip test payload";
        let sig = pq_sign_raw(&sk, message);
        assert!(
            pq_verify_raw(&vk, message, &sig),
            "ML-DSA-87 sign/verify roundtrip must succeed"
        );
    });
}

#[test]
fn mldsa87_wrong_key_rejects() {
    run_with_large_stack(|| {
        let (sk_a, _vk_a) = generate_pq_keypair();
        let (_sk_b, vk_b) = generate_pq_keypair();
        let message = b"wrong-key rejection test";
        let sig = pq_sign_raw(&sk_a, message);
        assert!(
            !pq_verify_raw(&vk_b, message, &sig),
            "verification with a different key must fail"
        );
    });
}

#[test]
fn mldsa87_tampered_message_rejects() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let sig = pq_sign_raw(&sk, b"original message");
        assert!(
            !pq_verify_raw(&vk, b"tampered message", &sig),
            "tampered message must fail verification"
        );
    });
}

#[test]
fn mldsa87_tampered_signature_rejects() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let message = b"bit-flip in signature test";
        let mut sig = pq_sign_raw(&sk, message);
        // Flip a bit in the middle of the signature
        let mid = sig.len() / 2;
        sig[mid] ^= 0x01;
        assert!(
            !pq_verify_raw(&vk, message, &sig),
            "signature with flipped bit must fail verification"
        );
    });
}

// ── X-Wing (ML-KEM-1024 + X25519) ──────────────────────────────────────────

use crypto::xwing::{
    xwing_keygen, xwing_encapsulate, xwing_decapsulate,
    XWingKeyPair, xwing_encapsulate_tagged, xwing_decapsulate_tagged,
    KemAlgorithm,
};

#[test]
fn xwing_encapsulate_decapsulate_roundtrip() {
    let (pk, kp) = xwing_keygen();
    let (client_ss, ct) = xwing_encapsulate(&pk);
    let server_ss = xwing_decapsulate(&kp, &ct)
        .expect("X-Wing decapsulation must succeed");
    assert_eq!(
        client_ss.as_bytes(),
        server_ss.as_bytes(),
        "encapsulator and decapsulator must derive the same shared secret"
    );
}

#[test]
fn xwing_wrong_key_decap_fails() {
    let (pk, _kp) = xwing_keygen();
    let (client_ss, ct) = xwing_encapsulate(&pk);

    // Decapsulate with a completely different keypair
    let wrong_kp = XWingKeyPair::generate();
    match xwing_decapsulate(&wrong_kp, &ct) {
        Ok(wrong_ss) => assert_ne!(
            client_ss.as_bytes(),
            wrong_ss.as_bytes(),
            "wrong key must produce a different shared secret (implicit rejection)"
        ),
        Err(_) => { /* decapsulation correctly rejected */ }
    }
}

#[test]
fn xwing_tampered_ciphertext_fails() {
    let (pk, kp) = xwing_keygen();
    let (client_ss, ct) = xwing_encapsulate(&pk);

    // Tamper with the ML-KEM portion of the ciphertext
    let mut ct_bytes = ct.to_bytes();
    // Flip a bit well into the ML-KEM ciphertext region (past X25519 PK)
    let tamper_pos = 32 + 100; // past the 32-byte X25519 public key
    ct_bytes[tamper_pos] ^= 0x01;

    let ct_tampered = crypto::xwing::Ciphertext::from_bytes(&ct_bytes)
        .expect("tampered ciphertext must still parse (format is preserved)");
    match xwing_decapsulate(&kp, &ct_tampered) {
        Ok(wrong_ss) => assert_ne!(
            client_ss.as_bytes(),
            wrong_ss.as_bytes(),
            "tampered ciphertext must produce a different shared secret"
        ),
        Err(_) => { /* decapsulation correctly rejected */ }
    }
}

#[test]
fn xwing_mlkem_only_mode_works() {
    // Use the tagged API which supports ML-KEM-1024-only mode
    // Set the environment variable to activate ML-KEM-only mode
    std::env::set_var("MILNET_PQ_KEM_ONLY", "1");

    let kp = XWingKeyPair::generate();
    let pk = kp.public_key();

    let (client_ss, tagged_ct) = xwing_encapsulate_tagged(&pk);
    assert_eq!(
        tagged_ct.algorithm(),
        KemAlgorithm::MlKem1024Only,
        "must use ML-KEM-1024-only mode when MILNET_PQ_KEM_ONLY is set"
    );

    let server_ss = xwing_decapsulate_tagged(&kp, &tagged_ct)
        .expect("ML-KEM-1024-only decapsulation must succeed");
    assert_eq!(
        client_ss.as_bytes(),
        server_ss.as_bytes(),
        "ML-KEM-1024-only roundtrip must produce matching shared secrets"
    );

    // Clean up
    std::env::remove_var("MILNET_PQ_KEM_ONLY");
}

// ── SLH-DSA (FIPS 205) ─────────────────────────────────────────────────────

use crypto::slh_dsa::{slh_dsa_keygen, slh_dsa_sign, slh_dsa_verify};

#[test]
fn slhdsa_sign_verify_roundtrip() {
    let (sk, vk) = slh_dsa_keygen();
    let message = b"SLH-DSA roundtrip test payload";
    let sig = slh_dsa_sign(&sk, message);
    assert!(
        slh_dsa_verify(&vk, message, &sig),
        "SLH-DSA sign/verify roundtrip must succeed"
    );
}

#[test]
fn slhdsa_wrong_key_rejects() {
    let (sk_a, _vk_a) = slh_dsa_keygen();
    let (_sk_b, vk_b) = slh_dsa_keygen();
    let message = b"SLH-DSA wrong-key rejection test";
    let sig = slh_dsa_sign(&sk_a, message);
    assert!(
        !slh_dsa_verify(&vk_b, message, &sig),
        "SLH-DSA verification with wrong key must fail"
    );
}

#[test]
fn slhdsa_tampered_message_rejects() {
    let (sk, vk) = slh_dsa_keygen();
    let sig = slh_dsa_sign(&sk, b"original SLH-DSA message");
    assert!(
        !slh_dsa_verify(&vk, b"tampered SLH-DSA message", &sig),
        "SLH-DSA verification with tampered message must fail"
    );
}

// ── Memory Protection ───────────────────────────────────────────────────────

use crypto::memguard::{SecretBuffer, SecretVec};

#[test]
fn secret_buffer_canary_verification() {
    let data = [0xABu8; 32];
    let buf = SecretBuffer::<32>::new(data).expect("SecretBuffer::new must succeed");
    assert!(
        buf.verify_canaries(),
        "canaries must be intact on a freshly constructed buffer"
    );
    assert_eq!(
        buf.as_bytes(),
        &[0xABu8; 32],
        "data must survive write/read roundtrip through SecretBuffer"
    );
}

#[test]
fn secret_buffer_zeroize_on_drop() {
    // Verify that Drop runs without panic and that the buffer is usable
    // up until the point of drop.  We cannot read freed memory to confirm
    // zeroization without UB, but the zeroize crate guarantees volatile
    // writes that the compiler cannot elide.
    let data = [0xFFu8; 64];
    let buf = Box::new(SecretBuffer::<64>::new(data).expect("SecretBuffer::new must succeed"));

    // Data accessible before drop
    assert_eq!(buf.as_bytes(), &[0xFFu8; 64]);

    // Drop triggers zeroize + munlock.  If Drop panics, this test fails.
    drop(buf);
}

#[test]
fn secret_buffer_debug_redacted() {
    let buf = SecretBuffer::<32>::new([0xCC; 32]).expect("SecretBuffer::new must succeed");
    let dbg = format!("{:?}", buf);
    assert!(
        !dbg.contains("0xCC") && !dbg.contains("204"),
        "Debug output must not contain the secret bytes"
    );
    assert!(
        dbg.contains("SecretBuffer"),
        "Debug output must include the type name"
    );
}

#[test]
fn secret_vec_operations() {
    let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let sv = SecretVec::new(data).expect("SecretVec::new must succeed");
    assert_eq!(sv.len(), 8);
    assert!(!sv.is_empty());
    assert!(sv.verify_canary(), "canary must be intact");
    assert_eq!(
        sv.as_bytes(),
        &[1, 2, 3, 4, 5, 6, 7, 8],
        "SecretVec data must survive construction roundtrip"
    );

    // Debug must not leak contents
    let dbg = format!("{:?}", sv);
    assert!(dbg.contains("SecretVec"));
    assert!(!dbg.contains("[1, 2, 3"));
}

// ── FIPS KAT Verification ───────────────────────────────────────────────────

use crypto::fips_kat;

#[test]
fn fips_kats_all_pass() {
    run_with_large_stack(|| {
        fips_kat::run_startup_kats()
            .expect("FIPS 140-3 startup KATs must all pass");
    });
}

#[test]
fn fips_kat_aes256gcm_matches_nist() {
    // NIST SP 800-38D test case #16 (AES-256-GCM, no AAD)
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let key: [u8; 32] = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    ];
    let nonce_bytes: [u8; 12] = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
    ];
    let plaintext: [u8; 64] = [
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
    ];
    let expected_ct_tag: [u8; 80] = [
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad,
        0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd,
        0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c,
    ];

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("AES-256-GCM encryption must succeed");

    assert_eq!(
        ct.as_slice(),
        &expected_ct_tag,
        "AES-256-GCM ciphertext+tag must match NIST SP 800-38D test vector"
    );
}

#[test]
fn fips_kat_sha512_matches_nist() {
    use sha2::{Digest, Sha512};

    let expected: [u8; 64] = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
    ];

    let mut hasher = Sha512::new();
    hasher.update(b"abc");
    let result = hasher.finalize();

    assert_eq!(
        result.as_slice(),
        &expected,
        "SHA-512 hash of 'abc' must match NIST CAVP test vector"
    );
}

// ── Crypto Agility ──────────────────────────────────────────────────────────

#[test]
fn signature_algorithm_tag_dispatch() {
    // Verify that PqSignatureAlgorithm tags correctly round-trip and
    // dispatch to the expected algorithm names.
    let cases = [
        (PqSignatureAlgorithm::MlDsa87, 0x01, "ML-DSA-87"),
        (PqSignatureAlgorithm::MlDsa65, 0x02, "ML-DSA-65"),
        (PqSignatureAlgorithm::SlhDsaSha2256f, 0x03, "SLH-DSA-SHA2-256f"),
    ];
    for (algo, expected_tag, expected_name) in cases {
        let tag = algo.tag();
        assert_eq!(tag, expected_tag, "tag for {} must be 0x{:02x}", expected_name, expected_tag);
        let decoded = PqSignatureAlgorithm::from_tag(tag)
            .expect("valid tag must decode");
        assert_eq!(decoded, algo);
        assert_eq!(decoded.name(), expected_name);
    }
    // Unknown tags must return None
    assert!(PqSignatureAlgorithm::from_tag(0x00).is_none());
    assert!(PqSignatureAlgorithm::from_tag(0xFF).is_none());

    // Verify tagged sign/verify actually dispatches correctly for ML-DSA-87
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let data = b"agility dispatch test";
        let tagged_sig = pq_sign_tagged(&sk, data);
        assert_eq!(
            tagged_sig[0], 0x01,
            "default tagged signature must use ML-DSA-87 tag (0x01)"
        );
        assert!(
            pq_verify_tagged(&vk, data, &tagged_sig),
            "tagged signature must verify with the matching key"
        );
    });
}

#[test]
fn kem_algorithm_tag_dispatch() {
    // Verify that KemAlgorithm tags correctly round-trip and dispatch
    let cases = [
        (KemAlgorithm::XWing, 0x01, "X-Wing (ML-KEM-1024 + X25519)"),
        (KemAlgorithm::MlKem1024Only, 0x02, "ML-KEM-1024 Only"),
    ];
    for (algo, expected_tag, expected_name) in cases {
        let tag = algo.tag();
        assert_eq!(tag, expected_tag, "tag for {} must be 0x{:02x}", expected_name, expected_tag);
        let decoded = KemAlgorithm::from_tag(tag)
            .expect("valid tag must decode");
        assert_eq!(decoded, algo);
        assert_eq!(decoded.name(), expected_name);
    }
    // Unknown tags must return None
    assert!(KemAlgorithm::from_tag(0x00).is_none());
    assert!(KemAlgorithm::from_tag(0xFF).is_none());

    // Verify tagged encapsulate actually produces X-Wing mode by default
    // (ensure MILNET_PQ_KEM_ONLY is not set)
    std::env::remove_var("MILNET_PQ_KEM_ONLY");
    let kp = XWingKeyPair::generate();
    let pk = kp.public_key();
    let (client_ss, tagged_ct) = xwing_encapsulate_tagged(&pk);
    assert_eq!(
        tagged_ct.algorithm(),
        KemAlgorithm::XWing,
        "default tagged encapsulation must use X-Wing mode"
    );
    let server_ss = xwing_decapsulate_tagged(&kp, &tagged_ct)
        .expect("tagged decapsulation must succeed");
    assert_eq!(
        client_ss.as_bytes(),
        server_ss.as_bytes(),
        "tagged X-Wing roundtrip must produce matching shared secrets"
    );
}
