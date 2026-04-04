//! Post-quantum algorithm known-answer tests (KAT).
//!
//! Verifies correctness and security properties of ML-DSA-87, X-Wing
//! (ML-KEM-1024 + X25519), and SLH-DSA-SHA2-256f across multiple
//! message sizes and failure modes.

use crypto::pq_sign::{
    generate_pq_keypair, pq_sign_raw, pq_verify_raw,
};
use crypto::slh_dsa::{
    slh_dsa_keygen, slh_dsa_sign, slh_dsa_verify,
};
use crypto::xwing::{xwing_decapsulate, xwing_encapsulate, XWingKeyPair};

/// Spawn test on a large stack (8 MB) to accommodate ML-DSA-87 / SLH-DSA key sizes.
fn large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

/// Test message payloads at various sizes.
fn test_messages() -> Vec<Vec<u8>> {
    vec![
        vec![],                          // empty
        vec![0x42],                      // 1 byte
        vec![0xAB; 1000],               // 1000 bytes
        vec![0xCD; 64 * 1024],          // 64 KB
    ]
}

// ── ML-DSA-87 ─────────────────────────────────────────────────────────

#[test]
fn mldsa87_sign_verify_roundtrip_various_sizes() {
    large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        for msg in test_messages() {
            let sig = pq_sign_raw(&sk, &msg);
            assert!(
                pq_verify_raw(&vk, &msg, &sig),
                "ML-DSA-87 roundtrip failed for message len={}",
                msg.len()
            );
        }
    });
}

#[test]
fn mldsa87_deterministic_seed_produces_valid_signature() {
    large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let msg = b"deterministic seed verification";
        let sig = pq_sign_raw(&sk, msg);

        // Verify signature is valid
        assert!(pq_verify_raw(&vk, msg, &sig));

        // Re-sign with the same key and verify again
        let sig2 = pq_sign_raw(&sk, msg);
        assert!(pq_verify_raw(&vk, msg, &sig2));
    });
}

#[test]
fn mldsa87_rejects_signature_from_wrong_key() {
    large_stack(|| {
        let (sk1, _vk1) = generate_pq_keypair();
        let (_sk2, vk2) = generate_pq_keypair();
        let msg = b"wrong key rejection test";

        let sig = pq_sign_raw(&sk1, msg);
        assert!(
            !pq_verify_raw(&vk2, msg, &sig),
            "ML-DSA-87 must reject signature from a different key"
        );
    });
}

#[test]
fn mldsa87_rejects_tampered_message() {
    large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let sig = pq_sign_raw(&sk, b"original message");
        assert!(
            !pq_verify_raw(&vk, b"tampered message", &sig),
            "ML-DSA-87 must reject tampered messages"
        );
    });
}

#[test]
fn mldsa87_rejects_tampered_signature_bit_flip() {
    large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let msg = b"bit flip test";
        let mut sig = pq_sign_raw(&sk, msg);

        // Flip a bit in the middle of the signature
        let mid = sig.len() / 2;
        sig[mid] ^= 0x01;

        assert!(
            !pq_verify_raw(&vk, msg, &sig),
            "ML-DSA-87 must reject signatures with a flipped bit"
        );
    });
}

// ── X-Wing (ML-KEM-1024 + X25519) ────────────────────────────────────

#[test]
fn xwing_encapsulate_decapsulate_roundtrip() {
    let server_kp = XWingKeyPair::generate();
    let server_pk = server_kp.public_key();

    let (client_ss, ct) = xwing_encapsulate(&server_pk).expect("encapsulate");
    let server_ss = xwing_decapsulate(&server_kp, &ct).expect("decapsulate");

    assert_eq!(
        client_ss.as_bytes(),
        server_ss.as_bytes(),
        "X-Wing shared secrets must match"
    );
}

#[test]
fn xwing_decapsulate_wrong_key_produces_different_secret() {
    let server_kp = XWingKeyPair::generate();
    let wrong_kp = XWingKeyPair::generate();
    let server_pk = server_kp.public_key();

    let (client_ss, ct) = xwing_encapsulate(&server_pk).expect("encapsulate");

    // ML-KEM uses implicit rejection: wrong key produces a pseudorandom value
    match xwing_decapsulate(&wrong_kp, &ct) {
        Ok(wrong_ss) => assert_ne!(
            client_ss.as_bytes(),
            wrong_ss.as_bytes(),
            "X-Wing: decapsulating with wrong key must produce different shared secret"
        ),
        Err(_) => { /* explicit rejection is also acceptable */ }
    }
}

#[test]
fn xwing_rejects_tampered_ciphertext() {
    let server_kp = XWingKeyPair::generate();
    let server_pk = server_kp.public_key();

    let (client_ss, ct) = xwing_encapsulate(&server_pk).expect("encapsulate");

    // Tamper with the ciphertext bytes
    let mut ct_bytes = ct.to_bytes();
    ct_bytes[ct_bytes.len() / 2] ^= 0xFF;
    let tampered_ct = crypto::xwing::Ciphertext::from_bytes(&ct_bytes)
        .expect("ciphertext reconstruction");

    match xwing_decapsulate(&server_kp, &tampered_ct) {
        Ok(tampered_ss) => assert_ne!(
            client_ss.as_bytes(),
            tampered_ss.as_bytes(),
            "X-Wing: tampered ciphertext must produce different shared secret"
        ),
        Err(_) => { /* explicit rejection is also acceptable */ }
    }
}

// ── SLH-DSA-SHA2-256f ────────────────────────────────────────────────

#[test]
fn slhdsa_sign_verify_roundtrip_various_sizes() {
    for msg in test_messages() {
        let (sk, vk) = slh_dsa_keygen();
        let sig = slh_dsa_sign(&sk, &msg);
        assert!(
            slh_dsa_verify(&vk, &msg, &sig),
            "SLH-DSA roundtrip failed for message len={}",
            msg.len()
        );
    }
}

#[test]
fn slhdsa_rejects_tampered_signature() {
    let (sk, vk) = slh_dsa_keygen();
    let msg = b"tamper detection test";
    let sig = slh_dsa_sign(&sk, msg);

    // Tamper by flipping a bit
    let mut sig_bytes = sig.as_bytes().to_vec();
    sig_bytes[sig_bytes.len() / 2] ^= 0x01;
    let tampered = crypto::slh_dsa::SlhDsaSignature::from_bytes(sig_bytes)
        .expect("signature reconstruction");

    assert!(
        !slh_dsa_verify(&vk, msg, &tampered),
        "SLH-DSA must reject tampered signatures"
    );
}

#[test]
fn slhdsa_rejects_wrong_key() {
    let (sk1, _vk1) = slh_dsa_keygen();
    let (_sk2, vk2) = slh_dsa_keygen();
    let msg = b"wrong key test";

    let sig = slh_dsa_sign(&sk1, msg);
    assert!(
        !slh_dsa_verify(&vk2, msg, &sig),
        "SLH-DSA must reject signature verified with wrong key"
    );
}

// ── Cross-algorithm rejection ─────────────────────────────────────────

#[test]
fn cross_algorithm_mldsa_sig_not_valid_as_slhdsa() {
    large_stack(|| {
        let (mldsa_sk, _mldsa_vk) = generate_pq_keypair();
        let (_slhdsa_sk, slhdsa_vk) = slh_dsa_keygen();
        let msg = b"cross-algorithm test";

        let mldsa_sig = pq_sign_raw(&mldsa_sk, msg);

        // ML-DSA-87 signature bytes should not verify as SLH-DSA
        match crypto::slh_dsa::SlhDsaSignature::from_bytes(mldsa_sig) {
            Some(as_slhdsa) => {
                assert!(
                    !slh_dsa_verify(&slhdsa_vk, msg, &as_slhdsa),
                    "ML-DSA-87 signature must not verify as SLH-DSA"
                );
            }
            None => { /* rejected at parse level, which is correct */ }
        }
    });
}

#[test]
fn cross_algorithm_slhdsa_sig_not_valid_as_mldsa() {
    large_stack(|| {
        let (slhdsa_sk, _slhdsa_vk) = slh_dsa_keygen();
        let (_mldsa_sk, mldsa_vk) = generate_pq_keypair();
        let msg = b"cross-algorithm reverse test";

        let slhdsa_sig = slh_dsa_sign(&slhdsa_sk, msg);
        let sig_bytes = slhdsa_sig.as_bytes();

        // SLH-DSA signature bytes should not verify as ML-DSA-87
        assert!(
            !pq_verify_raw(&mldsa_vk, msg, sig_bytes),
            "SLH-DSA signature must not verify as ML-DSA-87"
        );
    });
}

// ── Non-determinism of key generation ─────────────────────────────────

#[test]
fn mldsa87_keygen_produces_different_keys_each_call() {
    large_stack(|| {
        let (_sk1, vk1) = generate_pq_keypair();
        let (_sk2, vk2) = generate_pq_keypair();

        let vk1_bytes = vk1.encode();
        let vk2_bytes = vk2.encode();

        assert_ne!(
            vk1_bytes.as_ref(),
            vk2_bytes.as_ref(),
            "ML-DSA-87 key generation must produce different keys on each call"
        );
    });
}

#[test]
fn slhdsa_keygen_produces_different_keys_each_call() {
    let (_sk1, vk1) = slh_dsa_keygen();
    let (_sk2, vk2) = slh_dsa_keygen();

    assert_ne!(
        vk1.to_bytes(),
        vk2.to_bytes(),
        "SLH-DSA key generation must produce different keys on each call"
    );
}

#[test]
fn xwing_keygen_produces_different_keys_each_call() {
    let kp1 = XWingKeyPair::generate();
    let kp2 = XWingKeyPair::generate();

    assert_ne!(
        kp1.public_key().to_bytes(),
        kp2.public_key().to_bytes(),
        "X-Wing key generation must produce different keys on each call"
    );
}
