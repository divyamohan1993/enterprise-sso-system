//! Post-quantum algorithm agility tests.
//!
//! Verifies the PQ signature and KEM modules correctly:
//!   - ML-DSA-87 sign/verify round-trip
//!   - SLH-DSA sign/verify round-trip
//!   - Wrong key rejection
//!   - Tampered message rejection
//!   - X-Wing (ML-KEM-1024 + X25519) KEM round-trip
//!   - Shared secret derivation

use crypto::pq_sign::*;
use crypto::slh_dsa::*;
use crypto::xwing::*;

/// ML-DSA-87 keys are large (~4KB). Tests run on a thread with 8MB stack.
fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

// ── ML-DSA-87 Sign/Verify ─────────────────────────────────────────────────

/// Security property: ML-DSA-87 sign/verify round-trip succeeds.
/// This is the primary post-quantum signature algorithm for the system.
#[test]
fn mldsa87_sign_verify_roundtrip() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let message = b"critical authentication token payload";
        let frost_sig = [0xAA; 64];

        let sig = pq_sign(&sk, message, &frost_sig);
        assert!(!sig.is_empty(), "signature must not be empty");
        assert!(
            pq_verify(&vk, message, &frost_sig, &sig),
            "valid ML-DSA-87 signature must verify"
        );
    });
}

/// Security property: ML-DSA-87 raw sign/verify round-trip succeeds.
/// Used for audit entries, witness checkpoints, and standalone PQ signatures.
#[test]
fn mldsa87_raw_sign_verify_roundtrip() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let data = b"audit log entry hash for cryptographic binding";

        let sig = pq_sign_raw(&sk, data);
        assert!(!sig.is_empty());
        assert!(
            pq_verify_raw(&vk, data, &sig),
            "valid raw ML-DSA-87 signature must verify"
        );
    });
}

/// Security property: Verification with the WRONG key MUST fail.
/// This prevents impersonation by a party with a different keypair.
#[test]
fn mldsa87_wrong_key_rejected() {
    run_with_large_stack(|| {
        let (sk1, _vk1) = generate_pq_keypair();
        let (_sk2, vk2) = generate_pq_keypair();
        let message = b"message signed by key 1";
        let frost_sig = [0xBB; 64];

        let sig = pq_sign(&sk1, message, &frost_sig);
        assert!(
            !pq_verify(&vk2, message, &frost_sig, &sig),
            "verification with wrong key MUST fail"
        );
    });
}

/// Security property: Tampered message causes verification failure.
/// ML-DSA-87 commits to the exact message bytes.
#[test]
fn mldsa87_tampered_message_rejected() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let frost_sig = [0xCC; 64];

        let sig = pq_sign(&sk, b"original message", &frost_sig);
        assert!(
            !pq_verify(&vk, b"tampered message", &frost_sig, &sig),
            "tampered message MUST fail verification"
        );
    });
}

/// Security property: Modified FROST signature causes PQ verification failure.
/// The nested construction commits to both the message AND the FROST signature,
/// preventing stripping attacks.
#[test]
fn mldsa87_modified_frost_sig_rejected() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let message = b"same message";
        let frost_sig = [0x11; 64];
        let wrong_frost = [0x22; 64];

        let sig = pq_sign(&sk, message, &frost_sig);
        assert!(
            !pq_verify(&vk, message, &wrong_frost, &sig),
            "modified FROST sig MUST fail PQ verification"
        );
    });
}

/// Security property: Invalid (garbage) signature bytes are rejected.
#[test]
fn mldsa87_garbage_signature_rejected() {
    run_with_large_stack(|| {
        let (_sk, vk) = generate_pq_keypair();
        let message = b"test";
        let frost_sig = [0x00; 64];

        assert!(
            !pq_verify(&vk, message, &frost_sig, &[0xFF; 100]),
            "garbage signature MUST be rejected"
        );
        assert!(
            !pq_verify(&vk, message, &frost_sig, &[]),
            "empty signature MUST be rejected"
        );
    });
}

/// Security property: Raw ML-DSA-87 rejects wrong key and tampered data.
#[test]
fn mldsa87_raw_rejects_wrong_key_and_tampered_data() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let (_sk2, vk2) = generate_pq_keypair();
        let data = b"audit entry data";

        let sig = pq_sign_raw(&sk, data);

        // Wrong key
        assert!(!pq_verify_raw(&vk2, data, &sig), "wrong key must fail");

        // Tampered data
        assert!(!pq_verify_raw(&vk, b"different data", &sig), "tampered data must fail");

        // Garbage sig
        assert!(!pq_verify_raw(&vk, data, &[0xAB; 50]), "garbage sig must fail");
    });
}

// ── SLH-DSA Sign/Verify ──────────────────────────────────────────────────

/// Security property: SLH-DSA sign/verify round-trip succeeds.
/// SLH-DSA provides lattice-independent security based solely on hash functions.
#[test]
fn slh_dsa_sign_verify_roundtrip() {
    let (sk, vk) = slh_dsa_keygen();
    let message = b"firmware update payload for signature verification";

    let sig = slh_dsa_sign(&sk, message);
    assert!(
        slh_dsa_verify(&vk, message, &sig),
        "valid SLH-DSA signature must verify"
    );
}

/// Security property: SLH-DSA deterministic signing produces consistent results.
#[test]
fn slh_dsa_deterministic_signing_consistent() {
    let (sk, vk) = slh_dsa_keygen();
    let message = b"deterministic test message";

    let sig1 = slh_dsa_sign_deterministic(&sk, message);
    let sig2 = slh_dsa_sign_deterministic(&sk, message);

    // Deterministic signing should produce the same signature
    assert_eq!(sig1.as_bytes(), sig2.as_bytes(), "deterministic signing must be consistent");
    assert!(slh_dsa_verify(&vk, message, &sig1));
    assert!(slh_dsa_verify(&vk, message, &sig2));
}

/// Security property: SLH-DSA rejects tampered messages.
#[test]
fn slh_dsa_tampered_message_rejected() {
    let (sk, vk) = slh_dsa_keygen();
    let sig = slh_dsa_sign(&sk, b"original");
    assert!(
        !slh_dsa_verify(&vk, b"tampered", &sig),
        "SLH-DSA must reject tampered messages"
    );
}

/// Security property: SLH-DSA rejects verification with wrong key.
#[test]
fn slh_dsa_wrong_key_rejected() {
    let (sk1, _vk1) = slh_dsa_keygen();
    let (_sk2, vk2) = slh_dsa_keygen();
    let sig = slh_dsa_sign(&sk1, b"signed by key 1");
    assert!(
        !slh_dsa_verify(&vk2, b"signed by key 1", &sig),
        "SLH-DSA must reject verification with wrong key"
    );
}

/// Security property: SLH-DSA keygen from seed is deterministic.
#[test]
fn slh_dsa_keygen_from_seed_deterministic() {
    let seed = [0x42u8; 96]; // 3 * N = 96 bytes
    let (sk1, vk1) = slh_dsa_keygen_from_seed(&seed).expect("keygen from seed must work");
    let (sk2, vk2) = slh_dsa_keygen_from_seed(&seed).expect("keygen from seed must work");

    // Same seed should produce same keys
    assert_eq!(vk1.to_bytes(), vk2.to_bytes(), "same seed must produce same verifying key");

    // Sign with both and cross-verify
    let msg = b"deterministic keygen test";
    let sig1 = slh_dsa_sign_deterministic(&sk1, msg);
    let sig2 = slh_dsa_sign_deterministic(&sk2, msg);
    assert!(slh_dsa_verify(&vk1, msg, &sig2));
    assert!(slh_dsa_verify(&vk2, msg, &sig1));
}

/// Security property: SLH-DSA keygen from undersized seed is rejected.
#[test]
fn slh_dsa_keygen_from_short_seed_rejected() {
    let short_seed = [0x42u8; 32]; // too short (need 96)
    assert!(
        slh_dsa_keygen_from_seed(&short_seed).is_none(),
        "undersized seed must be rejected"
    );
}

// ── X-Wing KEM (ML-KEM-1024 + X25519) ────────────────────────────────────

/// Security property: X-Wing KEM encapsulate/decapsulate round-trip produces
/// matching shared secrets on both sides.
#[test]
fn xwing_kem_roundtrip() {
    let (pk, kp) = xwing_keygen();

    // Encapsulate (client side)
    let (client_ss, ct) = xwing_encapsulate(&pk);

    // Decapsulate (server side)
    let server_ss = xwing_decapsulate(&kp, &ct).expect("decapsulation must succeed");

    assert_eq!(
        client_ss.as_bytes(),
        server_ss.as_bytes(),
        "both sides must derive the same shared secret"
    );
}

/// Security property: Different keypairs produce different shared secrets.
/// This ensures key isolation between sessions.
#[test]
fn xwing_different_keypairs_different_secrets() {
    let (pk1, _kp1) = xwing_keygen();
    let (pk2, _kp2) = xwing_keygen();

    let (ss1, _ct1) = xwing_encapsulate(&pk1);
    let (ss2, _ct2) = xwing_encapsulate(&pk2);

    assert_ne!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "different keypairs must produce different shared secrets"
    );
}

/// Security property: Session key derivation from shared secret is deterministic.
#[test]
fn xwing_session_key_derivation_deterministic() {
    let (pk, kp) = xwing_keygen();
    let (ss, ct) = xwing_encapsulate(&pk);
    let server_ss = xwing_decapsulate(&kp, &ct).unwrap();

    let context = b"session-nonce-12345";
    let key1 = derive_session_key(&ss, context);
    let key2 = derive_session_key(&server_ss, context);

    assert_eq!(key1, key2, "session keys from same shared secret must match");
    assert_eq!(key1.len(), SESSION_KEY_LEN, "session key must be {} bytes", SESSION_KEY_LEN);
}

/// Security property: Different contexts produce different session keys.
#[test]
fn xwing_different_contexts_different_session_keys() {
    let (pk, _kp) = xwing_keygen();
    let (ss, _ct) = xwing_encapsulate(&pk);

    let key1 = derive_session_key(&ss, b"context-1");
    let key2 = derive_session_key(&ss, b"context-2");

    assert_ne!(key1, key2, "different contexts must produce different session keys");
}

/// Security property: X-Wing public key serialization round-trip.
#[test]
fn xwing_public_key_serialization_roundtrip() {
    let (pk, _kp) = xwing_keygen();
    let bytes = pk.to_bytes();
    let pk2 = XWingPublicKey::from_bytes(&bytes).expect("deserialization must succeed");

    // Verify the round-tripped key produces the same X25519 component
    assert_eq!(pk.x25519_bytes(), pk2.x25519_bytes());
}

/// Security property: X-Wing ciphertext serialization round-trip.
#[test]
fn xwing_ciphertext_serialization_roundtrip() {
    let (pk, kp) = xwing_keygen();
    let (client_ss, ct) = xwing_encapsulate(&pk);

    let ct_bytes = ct.to_bytes();
    let ct2 = Ciphertext::from_bytes(&ct_bytes).expect("ciphertext deserialization must succeed");

    // Decapsulate with round-tripped ciphertext
    let server_ss = xwing_decapsulate(&kp, &ct2).expect("decapsulation must succeed");
    assert_eq!(client_ss.as_bytes(), server_ss.as_bytes());
}

/// Security property: Truncated public key is rejected.
#[test]
fn xwing_truncated_public_key_rejected() {
    assert!(
        XWingPublicKey::from_bytes(&[0u8; 10]).is_none(),
        "truncated public key must be rejected"
    );
}

/// Security property: Truncated ciphertext is rejected.
#[test]
fn xwing_truncated_ciphertext_rejected() {
    assert!(
        Ciphertext::from_bytes(&[0u8; 10]).is_none(),
        "truncated ciphertext must be rejected"
    );
}
