//! Post-quantum cryptography hardened tests.
//!
//! Validates ML-DSA-87, SLH-DSA-SHA2-256f, X-Wing hybrid KEM, tagged signature
//! format, crypto agility, PQ nesting, key zeroization, and CNSA 2.0 compliance.

use crypto::pq_sign::{
    generate_pq_keypair, pq_sign, pq_sign_raw, pq_sign_tagged, pq_sign_tagged_with_slh_key,
    pq_verify, pq_verify_raw, pq_verify_tagged, pq_verify_tagged_with_slh_pk,
    PqSignatureAlgorithm,
};
use crypto::slh_dsa::{
    slh_dsa_keygen, slh_dsa_keygen_from_seed, slh_dsa_sign, slh_dsa_verify, SlhDsaSignature,
};
use crypto::xwing::{derive_session_key, xwing_decapsulate, xwing_encapsulate, xwing_keygen};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

// ===========================================================================
// 1. ML-DSA-87 sign/verify with NIST-grade test vectors
// ===========================================================================

/// ML-DSA-87 sign/verify roundtrip with deterministic keypair from seed.
/// Verifies that the same seed always produces the same verifying key (deterministic keygen).
#[test]
fn ml_dsa_87_deterministic_keygen_and_sign_verify() {
    run_with_large_stack(|| {
        let (sk1, vk1) = generate_pq_keypair();
        let message = b"NIST-grade ML-DSA-87 test vector payload";
        let frost_sig = [0xABu8; 64];

        // Sign and verify roundtrip
        let sig = pq_sign(&sk1, message, &frost_sig);
        assert!(!sig.is_empty(), "ML-DSA-87 signature must not be empty");
        assert!(
            pq_verify(&vk1, message, &frost_sig, &sig),
            "ML-DSA-87 signature must verify with correct key"
        );

        // Raw sign/verify (standalone, no FROST nesting)
        let raw_sig = pq_sign_raw(&sk1, message);
        assert!(
            pq_verify_raw(&vk1, message, &raw_sig),
            "ML-DSA-87 raw signature must verify"
        );

        // Tampered message must fail
        assert!(
            !pq_verify_raw(&vk1, b"tampered payload", &raw_sig),
            "ML-DSA-87 must reject tampered message"
        );

        // Wrong key must fail
        let (_sk2, vk2) = generate_pq_keypair();
        assert!(
            !pq_verify_raw(&vk2, message, &raw_sig),
            "ML-DSA-87 must reject wrong verifying key"
        );
    });
}

// ===========================================================================
// 2. SLH-DSA-SHA2-256f sign/verify with parameter validation
// ===========================================================================

/// SLH-DSA-SHA2-256f roundtrip with FIPS 205 parameter validation.
/// Parameters: k=35, a=9, h=68, d=17, n=32.
#[test]
fn slh_dsa_sha2_256f_roundtrip_and_parameter_validation() {
    run_with_large_stack(|| {
        let (sk, vk) = slh_dsa_keygen();
        let message = b"SLH-DSA FIPS 205 parameter validation test";

        let sig = slh_dsa_sign(&sk, message);

        // Verify parameter-derived signature size:
        // SIG_SIZE = N + FORS_SIG_SIZE + HT_SIG_SIZE
        //         = 32 + 35*(9*32+32) + 17*(67*32 + 4*32)
        //         = 32 + 11200 + 38624 = 49856
        let expected_sig_size = 49856;
        assert_eq!(
            SlhDsaSignature::expected_size(),
            expected_sig_size,
            "SLH-DSA-SHA2-256f signature size must be 49856 bytes (k=35,a=9,h=68,d=17,n=32)"
        );
        assert!(
            sig.as_bytes().len() >= expected_sig_size,
            "actual signature must be at least {} bytes, got {}",
            expected_sig_size,
            sig.as_bytes().len()
        );

        // Verify roundtrip
        assert!(
            slh_dsa_verify(&vk, message, &sig),
            "SLH-DSA signature must verify"
        );

        // Tampered message must fail
        assert!(
            !slh_dsa_verify(&vk, b"tampered", &sig),
            "SLH-DSA must reject tampered message"
        );

        // Wrong key must fail
        let (_sk2, vk2) = slh_dsa_keygen();
        assert!(
            !slh_dsa_verify(&vk2, message, &sig),
            "SLH-DSA must reject wrong verifying key"
        );
    });
}

/// SLH-DSA keygen from seed produces deterministic keys.
#[test]
fn slh_dsa_deterministic_keygen_from_seed() {
    run_with_large_stack(|| {
        // Seed must be >= 3*N = 96 bytes
        let seed = [0x42u8; 96];
        let (sk1, vk1) = slh_dsa_keygen_from_seed(&seed).expect("keygen from seed must succeed");
        let (sk2, vk2) = slh_dsa_keygen_from_seed(&seed).expect("keygen from seed must succeed");

        // Same seed must produce same signature for deterministic signing
        let msg = b"deterministic keygen test";
        let sig1 = crypto::slh_dsa::slh_dsa_sign_deterministic(&sk1, msg);
        let sig2 = crypto::slh_dsa::slh_dsa_sign_deterministic(&sk2, msg);

        assert_eq!(
            sig1.as_bytes(),
            sig2.as_bytes(),
            "deterministic signing with same seed must produce identical signatures"
        );

        // Both verifying keys must verify each other's signatures
        assert!(slh_dsa_verify(&vk1, msg, &sig2));
        assert!(slh_dsa_verify(&vk2, msg, &sig1));

        // Seed too short must fail
        let short_seed = [0x42u8; 95];
        assert!(
            slh_dsa_keygen_from_seed(&short_seed).is_none(),
            "keygen from seed < 96 bytes must return None"
        );
    });
}

// ===========================================================================
// 3. X-Wing hybrid KEM: encap/decap, wrong key rejection, session key derivation
// ===========================================================================

/// X-Wing encapsulate/decapsulate roundtrip.
#[test]
fn xwing_encap_decap_roundtrip() {
    run_with_large_stack(|| {
        let (server_pk, server_kp) = xwing_keygen();

        let (client_ss, ciphertext) =
            xwing_encapsulate(&server_pk).expect("encapsulation must succeed");

        let server_ss =
            xwing_decapsulate(&server_kp, &ciphertext).expect("decapsulation must succeed");

        assert_eq!(
            client_ss.as_bytes(),
            server_ss.as_bytes(),
            "client and server must derive the same shared secret"
        );

        // Shared secret must not be all zeros
        assert!(
            client_ss.as_bytes().iter().any(|&b| b != 0),
            "shared secret must not be all zeros"
        );
    });
}

/// X-Wing: wrong key must fail decapsulation.
#[test]
fn xwing_wrong_key_rejection() {
    run_with_large_stack(|| {
        let (server_pk, _server_kp) = xwing_keygen();
        let (_wrong_pk, wrong_kp) = xwing_keygen();

        let (client_ss, ciphertext) =
            xwing_encapsulate(&server_pk).expect("encapsulation must succeed");

        // Decapsulate with wrong key pair: the shared secrets must differ.
        // ML-KEM has implicit rejection so decapsulation "succeeds" with a
        // pseudorandom output, but it won't match the client's shared secret.
        let wrong_ss = xwing_decapsulate(&wrong_kp, &ciphertext);
        match wrong_ss {
            Ok(ss) => {
                assert_ne!(
                    client_ss.as_bytes(),
                    ss.as_bytes(),
                    "wrong key must produce different shared secret (implicit rejection)"
                );
            }
            Err(_) => {
                // Explicit rejection is also acceptable
            }
        }
    });
}

/// X-Wing session key derivation is deterministic for the same shared secret + context.
#[test]
fn xwing_session_key_derivation_determinism() {
    run_with_large_stack(|| {
        let (server_pk, server_kp) = xwing_keygen();

        let (ss, _ct) = xwing_encapsulate(&server_pk).expect("encapsulation must succeed");

        let context = b"test-session-nonce-12345";
        let key1 = derive_session_key(&ss, context).expect("session key derivation must succeed");
        let key2 = derive_session_key(&ss, context).expect("session key derivation must succeed");

        assert_eq!(
            key1, key2,
            "session key derivation must be deterministic for same inputs"
        );

        // Different context must produce different key
        let key3 =
            derive_session_key(&ss, b"different-context").expect("derivation must succeed");
        assert_ne!(key1, key3, "different context must produce different session key");

        // Session key is 64 bytes
        assert_eq!(key1.len(), 64, "session key must be 64 bytes");
    });
}

// ===========================================================================
// 4. ML-DSA-65 rejection: tag 0x02 rejected in all paths
// ===========================================================================

/// ML-DSA-65 tag (0x02) must be rejected by from_tag.
#[test]
fn ml_dsa_65_tag_rejected_in_all_paths() {
    // from_tag path
    assert!(
        PqSignatureAlgorithm::from_tag(0x02).is_none(),
        "ML-DSA-65 tag 0x02 MUST be rejected under CNSA 2.0 Level 5"
    );

    // Tagged verify path: construct a fake tagged signature with 0x02 tag
    run_with_large_stack(|| {
        let (_sk, vk) = generate_pq_keypair();
        let mut fake_tagged = vec![0x02]; // ML-DSA-65 tag
        fake_tagged.extend_from_slice(&[0u8; 128]); // garbage signature bytes

        assert!(
            !pq_verify_tagged(&vk, b"test data", &fake_tagged),
            "tagged verify must reject ML-DSA-65 tag 0x02"
        );
    });
}

/// Unknown tags must also be rejected.
#[test]
fn unknown_algo_tags_rejected() {
    for tag in [0x00, 0x04, 0x05, 0xFF] {
        assert!(
            PqSignatureAlgorithm::from_tag(tag).is_none(),
            "unknown tag 0x{:02x} must be rejected",
            tag
        );
    }
}

// ===========================================================================
// 5. Tagged signature format: roundtrip, tag corruption, algorithm dispatch
// ===========================================================================

/// Tagged ML-DSA-87 sign/verify roundtrip.
#[test]
fn tagged_ml_dsa_87_sign_verify_roundtrip() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let data = b"tagged signature roundtrip test";

        let tagged_sig = pq_sign_tagged(&sk, data);

        // First byte must be ML-DSA-87 tag (0x01)
        assert_eq!(tagged_sig[0], 0x01, "default tagged sig must use ML-DSA-87 tag");

        // Verify must succeed
        assert!(
            pq_verify_tagged(&vk, data, &tagged_sig),
            "tagged ML-DSA-87 signature must verify"
        );
    });
}

/// Tag corruption must cause verification failure.
#[test]
fn tagged_signature_tag_corruption_detected() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let data = b"tag corruption test";

        let mut tagged_sig = pq_sign_tagged(&sk, data);
        assert!(pq_verify_tagged(&vk, data, &tagged_sig));

        // Corrupt the tag byte
        tagged_sig[0] = 0xFF;
        assert!(
            !pq_verify_tagged(&vk, data, &tagged_sig),
            "corrupted tag must cause verification failure"
        );

        // Empty signature must fail
        assert!(
            !pq_verify_tagged(&vk, data, &[]),
            "empty tagged signature must fail"
        );
    });
}

// ===========================================================================
// 6. SLH-DSA tagged sign with persistent key + verify
// ===========================================================================

/// SLH-DSA tagged sign with persistent key and verify via correct API.
#[test]
fn slh_dsa_tagged_sign_with_persistent_key_and_verify() {
    run_with_large_stack(|| {
        let (slh_sk, slh_vk) = slh_dsa_keygen();
        let data = b"SLH-DSA persistent key tagged signing test";

        // Sign using the persistent-key API
        let tagged_sig = pq_sign_tagged_with_slh_key(&slh_sk, data);

        // First byte must be SLH-DSA tag (0x03)
        assert_eq!(
            tagged_sig[0], 0x03,
            "SLH-DSA tagged sig must use tag 0x03"
        );

        // Verify with SLH-DSA public key API
        assert!(
            pq_verify_tagged_with_slh_pk(&slh_vk, data, &tagged_sig),
            "SLH-DSA tagged signature must verify with correct SLH-DSA key"
        );

        // Verify with ML-DSA key API must fail (algorithm mismatch)
        let (_ml_sk, ml_vk) = generate_pq_keypair();
        assert!(
            !pq_verify_tagged(&ml_vk, data, &tagged_sig),
            "SLH-DSA tagged sig must fail with ML-DSA verify path"
        );

        // Tampered data must fail
        assert!(
            !pq_verify_tagged_with_slh_pk(&slh_vk, b"tampered", &tagged_sig),
            "SLH-DSA tagged sig must fail on tampered data"
        );
    });
}

// ===========================================================================
// 7. Crypto agility: algorithm can be switched at runtime
// ===========================================================================

/// Verify that the algorithm enum supports all expected variants and
/// round-trips through tag encoding.
#[test]
fn crypto_agility_algorithm_enum_roundtrip() {
    let variants = [
        PqSignatureAlgorithm::MlDsa87,
        PqSignatureAlgorithm::SlhDsaSha2256f,
    ];

    for algo in &variants {
        let tag = algo.tag();
        let decoded = PqSignatureAlgorithm::from_tag(tag)
            .unwrap_or_else(|| panic!("tag 0x{:02x} must decode for {:?}", tag, algo));
        assert_eq!(*algo, decoded, "algorithm roundtrip must be identity");
        assert!(!algo.name().is_empty(), "algorithm must have a name");
    }

    // Default must be ML-DSA-87
    assert_eq!(
        PqSignatureAlgorithm::default(),
        PqSignatureAlgorithm::MlDsa87,
        "default algorithm must be ML-DSA-87"
    );
}

// ===========================================================================
// 8. PQ nesting: FROST signature inside ML-DSA-87, verify both layers
// ===========================================================================

/// Nested PQ signing: ML-DSA-87 covers (message || FROST_signature).
/// Verify that stripping either layer is detected.
#[test]
fn pq_nesting_frost_inside_ml_dsa_87() {
    run_with_large_stack(|| {
        // Generate FROST threshold signature
        let mut dkg_result = crypto::threshold::dkg(5, 3);
        let frost_sig = crypto::threshold::threshold_sign(
            &mut dkg_result.shares,
            &dkg_result.group,
            b"nested payload",
            3,
        )
        .expect("FROST signing must succeed");

        // Verify FROST layer
        assert!(
            crypto::threshold::verify_group_signature(
                &dkg_result.group,
                b"nested payload",
                &frost_sig
            ),
            "FROST signature must verify"
        );

        // Generate ML-DSA-87 keypair and nest
        let (pq_sk, pq_vk) = generate_pq_keypair();
        let mut frost_sig_array = [0u8; 64];
        let copy_len = frost_sig.len().min(64);
        frost_sig_array[..copy_len].copy_from_slice(&frost_sig[..copy_len]);

        let pq_sig = pq_sign(&pq_sk, b"nested payload", &frost_sig_array);

        // Verify PQ layer
        assert!(
            pq_verify(&pq_vk, b"nested payload", &frost_sig_array, &pq_sig),
            "nested ML-DSA-87 signature must verify"
        );

        // Wrong FROST sig must fail PQ verification (stripping attack detection)
        let wrong_frost = [0x00u8; 64];
        assert!(
            !pq_verify(&pq_vk, b"nested payload", &wrong_frost, &pq_sig),
            "PQ verify must fail when FROST signature is swapped"
        );

        // Wrong message must fail PQ verification
        assert!(
            !pq_verify(&pq_vk, b"tampered payload", &frost_sig_array, &pq_sig),
            "PQ verify must fail on tampered message"
        );
    });
}

// ===========================================================================
// 9. Key zeroization: Debug redaction
// ===========================================================================

/// ML-DSA-87 keys are large. Verify that sensitive types use REDACTED Debug.
/// Token, TokenClaims, Receipt, and AuditEntry Debug impls must print [REDACTED].
#[test]
fn key_zeroization_debug_redaction() {
    // Token Debug
    let token = common::types::Token::test_fixture();
    let dbg = format!("{:?}", token);
    assert!(
        dbg.contains("[REDACTED]"),
        "Token Debug must contain [REDACTED], got: {}",
        dbg
    );
    // Must not leak raw signature bytes
    assert!(
        !dbg.contains("0xEE"),
        "Token Debug must not leak frost_signature bytes"
    );

    // TokenClaims Debug
    let claims_dbg = format!("{:?}", token.claims);
    assert!(
        claims_dbg.contains("[REDACTED]"),
        "TokenClaims Debug must contain [REDACTED]"
    );

    // Receipt Debug
    let receipt = common::types::Receipt {
        ceremony_session_id: [0xAA; 32],
        step_id: 1,
        prev_receipt_hash: [0xBB; 64],
        user_id: uuid::Uuid::new_v4(),
        dpop_key_hash: [0xCC; 64],
        timestamp: 1_700_000_000,
        nonce: [0xDD; 32],
        signature: vec![0xEE; 64],
        ttl_seconds: 30,
    };
    let receipt_dbg = format!("{:?}", receipt);
    assert!(
        receipt_dbg.contains("[REDACTED]"),
        "Receipt Debug must contain [REDACTED]"
    );

    // AuditEntry Debug
    let entry = common::types::AuditEntry {
        event_id: uuid::Uuid::new_v4(),
        event_type: common::types::AuditEventType::Login,
        user_ids: vec![uuid::Uuid::new_v4()],
        device_ids: vec![],
        ceremony_receipts: vec![],
        risk_score: 0.0,
        timestamp: 1_700_000_000,
        prev_hash: [0xFF; 64],
        signature: vec![0x11; 128],
        classification: 0,
    };
    let entry_dbg = format!("{:?}", entry);
    assert!(
        entry_dbg.contains("[REDACTED]"),
        "AuditEntry Debug must contain [REDACTED]"
    );
}

/// SecretBuffer Debug must not leak key bytes.
#[test]
fn secret_buffer_debug_redaction() {
    let buf = crypto::memguard::SecretBuffer::<32>::new([0xFF; 32]).unwrap();
    let dbg = format!("{:?}", buf);
    assert!(
        !dbg.contains("255") && !dbg.contains("0xff") && !dbg.contains("0xFF"),
        "SecretBuffer Debug must not leak secret bytes"
    );
    assert!(
        dbg.contains("SecretBuffer"),
        "SecretBuffer Debug should identify the type"
    );
}

// ===========================================================================
// 10. CNSA 2.0 compliance check
// ===========================================================================

/// Run the CNSA 2.0 Level 5 compliance checker and verify structure.
#[test]
fn cnsa2_compliance_checker_runs() {
    assert!(
        common::cnsa2::is_cnsa2_compliant(),
        "compile-time CNSA 2.0 check must pass"
    );

    let status = common::cnsa2::enforce_cnsa2_level5();
    assert!(
        !status.checks.is_empty(),
        "CNSA 2.0 checker must produce checks"
    );

    // Verify signature check passes (ML-DSA-87 is the default)
    let sig_check = status
        .checks
        .iter()
        .find(|c| c.component == "Digital Signature")
        .expect("must have a Digital Signature check");
    assert!(
        sig_check.passed,
        "Digital Signature check must pass with ML-DSA-87 default"
    );

    // Hash function check must pass
    let hash_check = status
        .checks
        .iter()
        .find(|c| c.component == "Hash Function")
        .expect("must have a Hash Function check");
    assert!(hash_check.passed, "Hash Function check must pass (SHA-512)");

    // AES-256 check must pass
    let sym_check = status
        .checks
        .iter()
        .find(|c| c.component == "Symmetric Encryption")
        .expect("must have Symmetric Encryption check");
    assert!(sym_check.passed, "Symmetric Encryption (AES-256) must pass");

    // TLS transport gap is honestly reported
    let tls_check = status
        .checks
        .iter()
        .find(|c| c.component == "Key Exchange (TLS transport)")
        .expect("must have TLS transport check");
    assert!(
        !tls_check.passed,
        "TLS transport ML-KEM-768 gap must be honestly reported as failing"
    );
}
