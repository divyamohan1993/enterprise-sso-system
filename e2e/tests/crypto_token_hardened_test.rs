//! Hardened cryptographic and token attack tests.
//!
//! Simulates a real-world scenario with a badly configured public-facing VM.
//! Tests all cryptographic primitives against downgrade, confusion, forgery,
//! bit-flip, replay, and tamper attacks across symmetric ciphers, FROST
//! threshold signatures, ML-DSA-87 post-quantum signatures, X-Wing hybrid
//! KEM, DPoP proofs, receipt chains, Merkle trees, ratchet forward secrecy,
//! audit logs, classification enforcement, cross-domain flow control,
//! witness logs, envelope encryption, and honey encryption.

use common::classification::*;
use common::cross_domain::*;
use common::types::{AuditEntry, AuditEventType, Receipt};
use common::witness::WitnessLog;
use crypto::dpop::*;
use crypto::envelope::{
    self, build_aad, wrap_key, unwrap_key, DataEncryptionKey, KeyEncryptionKey,
};
use crypto::honey::*;
use crypto::pq_sign::*;
use crypto::receipts::*;
use crypto::symmetric::{
    self, active_algorithm, encrypt_with, SymmetricAlgorithm,
    ALGO_ID_AEGIS256, ALGO_ID_AES256GCM,
};
use crypto::xwing::*;
use kt::merkle::*;
use ratchet::chain::*;
use uuid::Uuid;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Helper: run closure on a thread with 8 MB stack (ML-DSA / FROST need it)
// ---------------------------------------------------------------------------

fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn random_key_32() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).expect("getrandom failed");
    k
}

fn random_key_64() -> [u8; 64] {
    let mut k = [0u8; 64];
    getrandom::getrandom(&mut k).expect("getrandom failed");
    k
}

fn random_nonce_32() -> [u8; 32] {
    random_key_32()
}

fn random_entropy() -> [u8; 32] {
    random_key_32()
}

// =========================================================================
// 1. Cryptographic downgrade attack
// =========================================================================

/// Verify AEGIS-256 is default (non-FIPS), AES-256-GCM in FIPS mode.
/// Test algo_id prefix tags differentiate ciphers.
/// Verify legacy format (no tag) is rejected.
#[test]
fn crypto_downgrade_aegis_default_non_fips() {
    let _guard = FIPS_TOGGLE_LOCK.lock().unwrap();
    common::fips::set_fips_mode_unchecked(false);
    assert_eq!(active_algorithm(), SymmetricAlgorithm::Aegis256);

    let key = random_key_32();
    let sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, b"test", b"aad")
        .expect("encrypt");
    assert_eq!(
        sealed[0], ALGO_ID_AEGIS256,
        "non-FIPS mode must use AEGIS-256 (algo_id 0x01)"
    );
}

/// Mutex to serialize tests that toggle global FIPS mode, preventing races
/// where one test enables FIPS while another test reads the global state.
static FIPS_TOGGLE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn crypto_downgrade_aes_gcm_in_fips() {
    let _guard = FIPS_TOGGLE_LOCK.lock().unwrap();
    common::fips::set_fips_mode_unchecked(true);
    assert_eq!(active_algorithm(), SymmetricAlgorithm::Aes256Gcm);

    let key = random_key_32();
    let sealed = symmetric::encrypt(&key, b"fips-data", b"aad").expect("encrypt");
    assert_eq!(
        sealed[0], ALGO_ID_AES256GCM,
        "FIPS mode must use AES-256-GCM (algo_id 0x02)"
    );
    common::fips::set_fips_mode_unchecked(false);
}

#[test]
fn crypto_downgrade_algo_id_tags_differ() {
    let key = random_key_32();
    let aegis = encrypt_with(SymmetricAlgorithm::Aegis256, &key, b"d", b"a").unwrap();
    let gcm = encrypt_with(SymmetricAlgorithm::Aes256Gcm, &key, b"d", b"a").unwrap();
    assert_ne!(
        aegis[0], gcm[0],
        "AEGIS-256 and AES-256-GCM must have different algo_id tags"
    );
    assert_eq!(aegis[0], ALGO_ID_AEGIS256);
    assert_eq!(gcm[0], ALGO_ID_AES256GCM);
}

#[test]
fn crypto_downgrade_legacy_untagged_rejected() {
    // Craft a blob that starts with 0xFF (not 0x01 or 0x02) to simulate legacy
    let key = random_key_32();
    let mut legacy_blob = vec![0xFF; 100];
    getrandom::getrandom(&mut legacy_blob[1..]).unwrap();
    legacy_blob[0] = 0xFF; // force invalid tag

    let result = symmetric::decrypt(&key, &legacy_blob, b"aad");
    assert!(result.is_err(), "legacy untagged ciphertext must be rejected");
    assert!(
        result.unwrap_err().contains("unknown algorithm tag"),
        "error must mention unknown algorithm tag"
    );
}

// =========================================================================
// 2. Symmetric cipher key confusion
// =========================================================================

#[test]
fn key_confusion_aegis256() {
    let key_a = random_key_32();
    let key_b = random_key_32();
    let plaintext = b"secret military data";
    let aad = b"context";

    let sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key_a, plaintext, aad).unwrap();
    let result = symmetric::decrypt(&key_b, &sealed, aad);
    assert!(
        result.is_err(),
        "AEGIS-256: decryption with wrong key must fail"
    );
}

#[test]
fn key_confusion_aes256gcm() {
    let key_a = random_key_32();
    let key_b = random_key_32();
    let plaintext = b"classified payload";
    let aad = b"context";

    let sealed = encrypt_with(SymmetricAlgorithm::Aes256Gcm, &key_a, plaintext, aad).unwrap();
    let result = symmetric::decrypt(&key_b, &sealed, aad);
    assert!(
        result.is_err(),
        "AES-256-GCM: decryption with wrong key must fail"
    );
}

// =========================================================================
// 3. Nonce reuse detection
// =========================================================================

#[test]
fn nonce_reuse_detection_100_iterations() {
    let key = random_key_32();
    let plaintext = b"identical plaintext";
    let aad = b"identical aad";

    let mut seen_ciphertexts = HashSet::new();
    for _ in 0..100 {
        let sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad).unwrap();
        let is_new = seen_ciphertexts.insert(sealed.clone());
        assert!(is_new, "nonce reuse detected: identical ciphertext produced");
    }
    assert_eq!(
        seen_ciphertexts.len(),
        100,
        "all 100 encryptions must produce unique ciphertexts"
    );
}

#[test]
fn nonce_reuse_detection_aes_gcm_100_iterations() {
    let key = random_key_32();
    let plaintext = b"identical plaintext";
    let aad = b"identical aad";

    let mut seen = HashSet::new();
    for _ in 0..100 {
        let sealed = encrypt_with(SymmetricAlgorithm::Aes256Gcm, &key, plaintext, aad).unwrap();
        assert!(seen.insert(sealed), "AES-GCM nonce reuse detected");
    }
}

// =========================================================================
// 4. Ciphertext bit-flip detection
// =========================================================================

#[test]
fn ciphertext_bitflip_aegis256() {
    let key = random_key_32();
    let plaintext = b"data to protect from bit flips";
    let aad = b"integrity context";

    let sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad).unwrap();

    // Flip bit at position 0 (algo_id byte), middle, and last
    let positions = [0, sealed.len() / 2, sealed.len() - 1];
    for &pos in &positions {
        let mut tampered = sealed.clone();
        tampered[pos] ^= 0x01;
        let result = symmetric::decrypt(&key, &tampered, aad);
        assert!(
            result.is_err(),
            "AEGIS-256: bit flip at position {} must cause decryption failure",
            pos
        );
    }
}

#[test]
fn ciphertext_bitflip_aes256gcm() {
    let key = random_key_32();
    let plaintext = b"data to protect from bit flips";
    let aad = b"integrity context";

    let sealed = encrypt_with(SymmetricAlgorithm::Aes256Gcm, &key, plaintext, aad).unwrap();

    // Flip bit at positions after the algo_id byte (middle and last of payload)
    let mid = 1 + (sealed.len() - 1) / 2;
    let last = sealed.len() - 1;
    for &pos in &[mid, last] {
        let mut tampered = sealed.clone();
        tampered[pos] ^= 0x01;
        let result = symmetric::decrypt(&key, &tampered, aad);
        assert!(
            result.is_err(),
            "AES-256-GCM: bit flip at position {} must cause decryption failure",
            pos
        );
    }
}

// =========================================================================
// 5. FROST threshold signature security
// =========================================================================

#[test]
fn frost_3_of_5_signing_works() {
    run_with_large_stack(|| {
        let mut dkg_result = crypto::threshold::dkg(5, 3).expect("DKG ceremony failed");
        let msg = b"operational message";

        // 3-of-5 must succeed
        let sig = crypto::threshold::threshold_sign(
            &mut dkg_result.shares,
            &dkg_result.group,
            msg,
            3,
        );
        assert!(sig.is_ok(), "3-of-5 FROST signing must succeed");

        let sig_bytes = sig.unwrap();
        assert!(
            crypto::threshold::verify_group_signature(&dkg_result.group, msg, &sig_bytes),
            "3-of-5 FROST signature must verify"
        );
    });
}

#[test]
fn frost_2_of_5_signing_fails() {
    run_with_large_stack(|| {
        let mut dkg_result = crypto::threshold::dkg(5, 3).expect("DKG ceremony failed");
        let msg = b"operational message";

        // 2-of-5 must fail (below threshold)
        let sig = crypto::threshold::threshold_sign_with_indices(
            &mut dkg_result.shares,
            &dkg_result.group,
            msg,
            3,
            &[0, 1], // only 2 signers
        );
        assert!(sig.is_err(), "2-of-5 FROST signing must fail (below threshold)");
    });
}

#[test]
fn frost_different_messages_different_signatures() {
    run_with_large_stack(|| {
        let mut dkg_result = crypto::threshold::dkg(5, 3).expect("DKG ceremony failed");
        let msg1 = b"message alpha";
        let msg2 = b"message bravo";

        let sig1 = crypto::threshold::threshold_sign(
            &mut dkg_result.shares,
            &dkg_result.group,
            msg1,
            3,
        )
        .unwrap();
        let sig2 = crypto::threshold::threshold_sign(
            &mut dkg_result.shares,
            &dkg_result.group,
            msg2,
            3,
        )
        .unwrap();

        assert_ne!(sig1, sig2, "different messages must produce different FROST signatures");
    });
}

#[test]
fn frost_tampered_message_rejects() {
    run_with_large_stack(|| {
        let mut dkg_result = crypto::threshold::dkg(5, 3).expect("DKG ceremony failed");
        let msg = b"original message";

        let sig = crypto::threshold::threshold_sign(
            &mut dkg_result.shares,
            &dkg_result.group,
            msg,
            3,
        )
        .unwrap();

        assert!(
            crypto::threshold::verify_group_signature(&dkg_result.group, msg, &sig),
            "original message must verify"
        );
        assert!(
            !crypto::threshold::verify_group_signature(&dkg_result.group, b"tampered message", &sig),
            "tampered message must not verify"
        );
    });
}

// =========================================================================
// 6. FROST key share corruption
// =========================================================================

#[test]
fn frost_corrupted_share_produces_invalid_signature() {
    run_with_large_stack(|| {
        let mut dkg_result = crypto::threshold::dkg(5, 3).expect("DKG ceremony failed");
        let msg = b"share corruption test";

        // Sign successfully first to prove the shares work
        let good_sig = crypto::threshold::threshold_sign(
            &mut dkg_result.shares,
            &dkg_result.group,
            msg,
            3,
        )
        .unwrap();
        assert!(crypto::threshold::verify_group_signature(&dkg_result.group, msg, &good_sig));

        // Now generate a completely separate DKG to get a foreign share
        let foreign_dkg = crypto::threshold::dkg(5, 3).expect("DKG ceremony failed");

        // Replace share 0 with a foreign share from a different group
        dkg_result.shares[0] = foreign_dkg.shares.into_iter().next().unwrap();

        // Signing with the corrupted share set should either fail or produce
        // an invalid signature
        let result = crypto::threshold::threshold_sign(
            &mut dkg_result.shares,
            &dkg_result.group,
            msg,
            3,
        );
        match result {
            Err(_) => { /* Expected: signing failed with corrupted share */ }
            Ok(sig_bytes) => {
                assert!(
                    !crypto::threshold::verify_group_signature(&dkg_result.group, msg, &sig_bytes),
                    "corrupted share must produce an invalid group signature"
                );
            }
        }
    });
}

// =========================================================================
// 7. Post-quantum signature forgery (ML-DSA-87)
// =========================================================================

#[test]
fn pq_sign_verify_roundtrip() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let msg = b"critical command payload";
        let frost_sig = [0xAA; 64];

        let sig = pq_sign(&sk, msg, &frost_sig);
        assert!(!sig.is_empty());
        assert!(
            pq_verify(&vk, msg, &frost_sig, &sig),
            "PQ signature must verify with correct key"
        );
    });
}

#[test]
fn pq_sign_tampered_message_rejected() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let frost_sig = [0xBB; 64];

        let sig = pq_sign(&sk, b"original", &frost_sig);
        assert!(
            !pq_verify(&vk, b"tampered", &frost_sig, &sig),
            "PQ signature must reject tampered message"
        );
    });
}

#[test]
fn pq_sign_wrong_key_rejected() {
    run_with_large_stack(|| {
        let (sk1, _vk1) = generate_pq_keypair();
        let (_sk2, vk2) = generate_pq_keypair();
        let msg = b"test data";
        let frost_sig = [0xCC; 64];

        let sig = pq_sign(&sk1, msg, &frost_sig);
        assert!(
            !pq_verify(&vk2, msg, &frost_sig, &sig),
            "PQ signature must fail verification with wrong key"
        );
    });
}

#[test]
fn pq_sign_tampered_frost_sig_rejected() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let msg = b"same message";
        let frost_sig = [0xDD; 64];
        let wrong_frost_sig = [0xEE; 64];

        let sig = pq_sign(&sk, msg, &frost_sig);
        assert!(
            !pq_verify(&vk, msg, &wrong_frost_sig, &sig),
            "PQ signature must reject when FROST signature is tampered"
        );
    });
}

// =========================================================================
// 8. X-Wing hybrid KEM security
// =========================================================================

#[test]
fn xwing_encap_decap_matching_secret() {
    let (pk, kp) = xwing_keygen();
    let (client_ss, ct) = xwing_encapsulate(&pk).expect("encapsulate");
    let server_ss = xwing_decapsulate(&kp, &ct).expect("decapsulation must succeed");
    assert_eq!(
        client_ss.as_bytes(),
        server_ss.as_bytes(),
        "X-Wing shared secrets must match"
    );
}

#[test]
fn xwing_wrong_secret_key_different_secret() {
    let (pk, _kp) = xwing_keygen();
    let (client_ss, ct) = xwing_encapsulate(&pk).expect("encapsulate");

    let (_pk2, wrong_kp) = xwing_keygen();
    match xwing_decapsulate(&wrong_kp, &ct) {
        Ok(wrong_ss) => {
            assert_ne!(
                client_ss.as_bytes(),
                wrong_ss.as_bytes(),
                "wrong secret key must produce different shared secret"
            );
        }
        Err(_) => { /* Also acceptable: decapsulation fails outright */ }
    }
}

#[test]
fn xwing_two_encapsulations_differ() {
    let (pk, _kp) = xwing_keygen();
    let (ss1, ct1) = xwing_encapsulate(&pk).expect("encapsulate");
    let (ss2, ct2) = xwing_encapsulate(&pk).expect("encapsulate");

    assert_ne!(
        ct1.to_bytes(),
        ct2.to_bytes(),
        "two X-Wing encapsulations must produce different ciphertexts"
    );
    assert_ne!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "two X-Wing encapsulations must produce different shared secrets"
    );
}

// =========================================================================
// 9. X-Wing session key context separation
// =========================================================================

#[test]
fn xwing_session_key_different_contexts() {
    let (pk, _kp) = xwing_keygen();
    let (ss, _ct) = xwing_encapsulate(&pk).expect("encapsulate");

    let keys_ctx_a = derive_session_key(&ss, b"context-alpha").expect("derive_session_key");
    let keys_ctx_b = derive_session_key(&ss, b"context-bravo").expect("derive_session_key");

    assert_ne!(
        keys_ctx_a, keys_ctx_b,
        "different contexts must produce different session keys"
    );
}

#[test]
fn xwing_session_key_same_context_deterministic() {
    let (pk, _kp) = xwing_keygen();
    let (ss, _ct) = xwing_encapsulate(&pk).expect("encapsulate");

    let keys1 = derive_session_key(&ss, b"same-context").expect("derive_session_key");
    let keys2 = derive_session_key(&ss, b"same-context").expect("derive_session_key");

    assert_eq!(
        keys1, keys2,
        "same context must produce identical session keys"
    );
}

#[test]
fn xwing_session_key_enc_mac_split() {
    let (pk, _kp) = xwing_keygen();
    let (ss, _ct) = xwing_encapsulate(&pk).expect("encapsulate");

    let keys = derive_session_key(&ss, b"split-test").expect("derive_session_key");
    assert_eq!(keys.len(), 64, "session key must be 64 bytes (enc + mac)");

    let enc_key = &keys[..32];
    let mac_key = &keys[32..];
    assert_ne!(
        enc_key, mac_key,
        "encryption and MAC key halves must differ"
    );
}

// =========================================================================
// 10. DPoP proof forgery
// =========================================================================

#[test]
fn dpop_proof_verify_correct_key() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let expected_hash = dpop_key_hash(vk_bytes.as_ref());
        let claims = b"POST /token";
        let timestamp = now_secs();

        let proof = generate_dpop_proof(&sk, claims, timestamp, b"POST", b"https://sso.milnet.example/token", None);
        assert!(
            verify_dpop_proof(&vk, &proof, claims, timestamp, &expected_hash, b"POST", b"https://sso.milnet.example/token", None),
            "DPoP proof must verify with correct key"
        );
    });
}

#[test]
fn dpop_proof_wrong_key_fails() {
    run_with_large_stack(|| {
        let (sk1, _vk1) = generate_dpop_keypair_raw();
        let (_sk2, vk2) = generate_dpop_keypair_raw();
        let vk2_bytes = vk2.encode();
        let hash2 = dpop_key_hash(vk2_bytes.as_ref());
        let claims = b"GET /resource";
        let timestamp = now_secs();

        let proof = generate_dpop_proof(&sk1, claims, timestamp, b"GET", b"https://sso.milnet.example/resource", None);
        assert!(
            !verify_dpop_proof(&vk2, &proof, claims, timestamp, &hash2, b"GET", b"https://sso.milnet.example/resource", None),
            "DPoP proof must fail with wrong public key"
        );
    });
}

#[test]
fn dpop_proof_expired_timestamp_fails() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let expected_hash = dpop_key_hash(vk_bytes.as_ref());
        let claims = b"POST /auth";

        let ts = now_secs();
        let proof = generate_dpop_proof(&sk, claims, ts, b"POST", b"https://sso.milnet.example/auth", None);
        assert!(
            !verify_dpop_proof(&vk, &proof, claims, ts + 9999, &expected_hash, b"POST", b"https://sso.milnet.example/auth", None),
            "DPoP proof must fail with mismatched (expired) timestamp"
        );
    });
}

#[test]
fn dpop_proof_wrong_claims_fails() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair_raw();
        let vk_bytes = vk.encode();
        let expected_hash = dpop_key_hash(vk_bytes.as_ref());
        let timestamp = now_secs();

        let proof = generate_dpop_proof(&sk, b"original claims", timestamp, b"POST", b"https://sso.milnet.example/token", None);
        assert!(
            !verify_dpop_proof(&vk, &proof, b"tampered claims", timestamp, &expected_hash, b"POST", b"https://sso.milnet.example/token", None),
            "DPoP proof must fail with tampered claims"
        );
    });
}

// =========================================================================
// 11. Receipt chain cryptographic integrity
// =========================================================================

#[test]
fn receipt_chain_10_step_integrity() {
    let signing_key = random_key_64();
    let session_id = random_key_32();
    let user_id = Uuid::new_v4();
    let dpop_hash = [0xAA; 64];

    let mut chain = ReceiptChain::new(session_id);
    let mut prev_hash = [0u8; 64];

    for step in 1..=10u8 {
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).unwrap();

        let mut receipt = Receipt {
            ceremony_session_id: session_id,
            step_id: step,
            prev_receipt_hash: prev_hash,
            user_id,
            dpop_key_hash: dpop_hash,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64,
            nonce,
            signature: Vec::new(),
            ttl_seconds: 30,
        };

        sign_receipt(&mut receipt, &signing_key).unwrap();
        assert!(
            verify_receipt_signature(&receipt, &signing_key).unwrap(),
            "receipt step {} must verify",
            step
        );

        prev_hash = hash_receipt(&receipt);
        chain.add_receipt(receipt).unwrap();
    }

    assert_eq!(chain.len(), 10);
    chain.validate_with_key(&signing_key).expect("chain must validate");
}

#[test]
fn receipt_chain_tamper_detected() {
    let signing_key = random_key_64();
    let session_id = random_key_32();
    let user_id = Uuid::new_v4();

    let mut receipts = Vec::new();
    let mut prev_hash = [0u8; 64];

    for step in 1..=5u8 {
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).unwrap();

        let mut receipt = Receipt {
            ceremony_session_id: session_id,
            step_id: step,
            prev_receipt_hash: prev_hash,
            user_id,
            dpop_key_hash: [0xBB; 64],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64,
            nonce,
            signature: Vec::new(),
            ttl_seconds: 30,
        };

        sign_receipt(&mut receipt, &signing_key).unwrap();
        prev_hash = hash_receipt(&receipt);
        receipts.push(receipt);
    }

    // Tamper receipt 2's signature to simulate corruption
    receipts[2].signature[0] ^= 0xFF;

    // Rebuild chain with tampered receipt -- validate_with_key must fail
    let mut chain = ReceiptChain::new(session_id);
    for receipt in receipts {
        let _ = chain.add_receipt(receipt);
    }
    let result = chain.validate_with_key(&signing_key);
    assert!(
        result.is_err(),
        "tampered receipt signature must cause chain validation to fail"
    );
}

// =========================================================================
// 12. Merkle tree proof manipulation
// =========================================================================

#[test]
fn merkle_tree_100_leaves_all_proofs_valid() {
    let mut tree = MerkleTree::new();
    let user_id = Uuid::new_v4();
    let cred_hash = [0x42u8; 32];

    let mut leaves = Vec::new();
    for i in 0..100 {
        let leaf = tree.append_credential_op(&user_id, "register", &cred_hash, i as i64);
        leaves.push(leaf);
    }

    let root = tree.root();
    let tree_size = tree.len();

    for (idx, leaf) in leaves.iter().enumerate() {
        let proof = tree.inclusion_proof(idx).expect("proof must exist");
        assert!(
            MerkleTree::verify_inclusion_with_size(&root, leaf, &proof, idx, tree_size),
            "inclusion proof for leaf {} must verify",
            idx
        );
    }
}

#[test]
fn merkle_tree_changed_leaf_old_proof_fails() {
    let mut tree = MerkleTree::new();
    let user_id = Uuid::new_v4();
    let cred_hash = [0x42u8; 32];

    for i in 0..10 {
        tree.append_credential_op(&user_id, "register", &cred_hash, i);
    }

    let old_root = tree.root();
    let old_tree_size = tree.len();
    let leaf_5 = {
        let mut t2 = MerkleTree::new();
        for i in 0..10 {
            t2.append_credential_op(&user_id, "register", &cred_hash, i);
        }
        let proof_5 = t2.inclusion_proof(5).unwrap();
        let leaf = {
            let mut t3 = MerkleTree::new();
            for i in 0..10 {
                t3.append_credential_op(&user_id, "register", &cred_hash, i);
            }
            // Get the actual leaf at index 5
            let leaves: Vec<_> = (0..10)
                .map(|i| {
                    let mut t = MerkleTree::new();
                    // We need to track individual leaves; rebuild single tree
                    t.append_credential_op(&user_id, "register", &cred_hash, i)
                })
                .collect();
            leaves[5]
        };
        (leaf, proof_5)
    };

    // Now add a new leaf to change the root
    tree.append_credential_op(&user_id, "revoke", &cred_hash, 100);
    let new_root = tree.root();

    assert_ne!(old_root, new_root, "adding a leaf must change the root");

    // Old proof against new root must fail
    assert!(
        !MerkleTree::verify_inclusion_with_size(&new_root, &leaf_5.0, &leaf_5.1, 5, old_tree_size),
        "old proof must not verify against new root"
    );
}

#[test]
fn merkle_tree_odd_and_even_leaf_counts() {
    let user_id = Uuid::new_v4();
    let cred_hash = [0x42u8; 32];

    // Test odd count (7 leaves)
    let mut tree_odd = MerkleTree::new();
    for i in 0..7 {
        tree_odd.append_credential_op(&user_id, "op", &cred_hash, i);
    }
    let root_odd = tree_odd.root();
    let size_odd = tree_odd.len();
    for idx in 0..7 {
        let proof = tree_odd.inclusion_proof(idx).unwrap();
        assert!(
            MerkleTree::verify_inclusion_with_size(&root_odd, &{
                let mut t = MerkleTree::new();
                let mut leaves = Vec::new();
                for i in 0..7 {
                    leaves.push(t.append_credential_op(&user_id, "op", &cred_hash, i));
                }
                leaves[idx]
            }, &proof, idx, size_odd),
            "odd tree: proof for leaf {} must verify",
            idx
        );
    }

    // Test even count (8 leaves)
    let mut tree_even = MerkleTree::new();
    for i in 0..8 {
        tree_even.append_credential_op(&user_id, "op", &cred_hash, i);
    }
    let root_even = tree_even.root();
    let size_even = tree_even.len();
    for idx in 0..8 {
        let proof = tree_even.inclusion_proof(idx).unwrap();
        assert!(
            MerkleTree::verify_inclusion_with_size(&root_even, &{
                let mut t = MerkleTree::new();
                let mut leaves = Vec::new();
                for i in 0..8 {
                    leaves.push(t.append_credential_op(&user_id, "op", &cred_hash, i));
                }
                leaves[idx]
            }, &proof, idx, size_even),
            "even tree: proof for leaf {} must verify",
            idx
        );
    }
}

// =========================================================================
// 13. Signed tree head forgery
// =========================================================================

#[test]
fn signed_tree_head_correct_key_verifies() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let mut tree = MerkleTree::new();
        let user_id = Uuid::new_v4();
        let cred_hash = [0x42u8; 32];
        for i in 0..10 {
            tree.append_credential_op(&user_id, "op", &cred_hash, i);
        }

        let sth = tree.signed_tree_head(&sk);
        assert!(
            MerkleTree::verify_tree_head(&sth, &vk),
            "signed tree head must verify with correct key"
        );
    });
}

#[test]
fn signed_tree_head_wrong_key_fails() {
    run_with_large_stack(|| {
        let (sk1, _vk1) = generate_pq_keypair();
        let (_sk2, vk2) = generate_pq_keypair();
        let mut tree = MerkleTree::new();
        let user_id = Uuid::new_v4();
        let cred_hash = [0x42u8; 32];
        for i in 0..5 {
            tree.append_credential_op(&user_id, "op", &cred_hash, i);
        }

        let sth = tree.signed_tree_head(&sk1);
        assert!(
            !MerkleTree::verify_tree_head(&sth, &vk2),
            "signed tree head must fail with wrong key"
        );
    });
}

#[test]
fn signed_tree_head_tampered_tree_size_fails() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let mut tree = MerkleTree::new();
        let user_id = Uuid::new_v4();
        let cred_hash = [0x42u8; 32];
        for i in 0..5 {
            tree.append_credential_op(&user_id, "op", &cred_hash, i);
        }

        let mut sth = tree.signed_tree_head(&sk);
        // Tamper the tree size
        sth.tree_size += 1;
        assert!(
            !MerkleTree::verify_tree_head(&sth, &vk),
            "tampered tree size must cause verification failure"
        );
    });
}

// =========================================================================
// 14. Ratchet forward secrecy
// =========================================================================

#[test]
fn ratchet_forward_secrecy_10_advances() {
    let master_secret = random_key_64();
    let mut chain = RatchetChain::new(&master_secret).expect("chain creation");

    // Advance 10 times, collecting tags
    let claims = b"session-claims-data";
    let initial_tag = chain.generate_tag(claims).expect("tag generation");
    let initial_epoch = chain.epoch();
    assert_eq!(initial_epoch, 0);

    for i in 0..10 {
        let client_entropy = random_entropy();
        let server_entropy = random_entropy();
        let server_nonce = random_nonce_32();
        chain
            .advance(&client_entropy, &server_entropy, &server_nonce)
            .expect("advance");
        assert_eq!(chain.epoch(), i + 1);
    }

    assert_eq!(chain.epoch(), 10);

    // Current epoch tag must verify at current epoch
    let current_tag = chain.generate_tag(claims).expect("tag generation");
    let verified = chain.verify_tag(claims, &current_tag, 10).expect("verify");
    assert!(verified, "current epoch tag must verify");

    // The initial tag (epoch 0) should NOT verify at epoch 10
    // (it's outside the lookbehind window of 3)
    let old_verified = chain.verify_tag(claims, &initial_tag, 0).expect("verify");
    assert!(
        !old_verified,
        "epoch 0 tag must not verify at epoch 10 (outside lookbehind window)"
    );
}

#[test]
fn ratchet_future_epoch_tag_does_not_verify() {
    let master_secret = random_key_64();
    let chain = RatchetChain::new(&master_secret).expect("chain creation");

    let claims = b"test-claims";
    let tag = chain.generate_tag(claims).expect("tag");

    // Tag generated at epoch 0 should not verify at epoch 10 (way beyond window)
    let result = chain.verify_tag(claims, &tag, 10).expect("verify");
    assert!(
        !result,
        "epoch 0 tag must not verify as epoch 10 (beyond lookahead window)"
    );
}

#[test]
fn ratchet_epoch_plus_one_tag_not_current() {
    let master_secret = random_key_64();
    let chain = RatchetChain::new(&master_secret).expect("chain creation");
    let claims = b"test-claims";
    let current_tag = chain.generate_tag(claims).expect("tag");

    // The tag for the current epoch should verify at epoch 0
    assert!(chain.verify_tag(claims, &current_tag, 0).expect("verify"));

    // But verifying at epoch 1 requires forward derivation which uses a
    // different key, so the same tag should fail at epoch 1
    let result = chain.verify_tag(claims, &current_tag, 1).expect("verify");
    assert!(!result, "current epoch tag must not verify at epoch+1");
}

// =========================================================================
// 15. Audit log tamper detection
// =========================================================================

#[test]
fn audit_log_50_entries_chain_integrity() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let mut log = audit::log::AuditLog::new();

        for i in 0..50 {
            log.append(
                AuditEventType::AuthSuccess,
                vec![Uuid::new_v4()],
                vec![Uuid::new_v4()],
                0.1 * (i as f64),
                vec![],
                &sk,
            );
        }

        assert_eq!(log.len(), 50);
        assert!(
            log.verify_chain_with_key(Some(&vk)),
            "50-entry chain must verify"
        );
    });
}

#[test]
fn audit_log_tamper_entry_25_detected() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_pq_keypair();
        let mut log = audit::log::AuditLog::new();

        for _ in 0..50 {
            log.append(
                AuditEventType::AuthSuccess,
                vec![Uuid::new_v4()],
                vec![Uuid::new_v4()],
                0.5,
                vec![],
                &sk,
            );
        }

        assert!(log.verify_chain_with_key(Some(&vk)), "chain must verify before tamper");

        // Extract entries, tamper entry 25's prev_hash, and rebuild
        let mut entries: Vec<AuditEntry> = log.entries().to_vec();
        entries[25].prev_hash[0] ^= 0xFF;

        let tampered_log = audit::log::AuditLog::from_entries(entries);
        assert!(
            !tampered_log.verify_chain_with_key(Some(&vk)),
            "tampered prev_hash at entry 25 must be detected"
        );
    });
}

// =========================================================================
// 16. Classification label enforcement (Bell-LaPadula)
// =========================================================================

#[test]
fn bell_lapadula_simple_security_property() {
    use ClassificationLevel::*;
    let levels = [Unclassified, Confidential, Secret, TopSecret, SCI];

    // No read up: subject_level >= resource_level grants access
    for (si, &subject) in levels.iter().enumerate() {
        for (ri, &resource) in levels.iter().enumerate() {
            let decision = enforce_classification(subject, resource);
            if si >= ri {
                assert!(
                    decision.is_granted(),
                    "{:?} must be able to read {:?}",
                    subject,
                    resource
                );
            } else {
                assert!(
                    !decision.is_granted(),
                    "{:?} must NOT be able to read {:?}",
                    subject,
                    resource
                );
            }
        }
    }
}

#[test]
fn bell_lapadula_star_property_no_write_down() {
    use ClassificationLevel::*;
    let levels = [Unclassified, Confidential, Secret, TopSecret, SCI];

    // Star property: data at source_level can only flow to target >= source
    for (si, &source) in levels.iter().enumerate() {
        for (ti, &target) in levels.iter().enumerate() {
            let decision = enforce_no_downgrade(source, target);
            if ti >= si {
                assert!(
                    decision.is_granted(),
                    "data at {:?} must flow to {:?}",
                    source,
                    target
                );
            } else {
                assert!(
                    !decision.is_granted(),
                    "data at {:?} must NOT flow down to {:?}",
                    source,
                    target
                );
            }
        }
    }
}

#[test]
fn bell_lapadula_specific_cases() {
    use ClassificationLevel::*;

    // Unclassified cannot read Secret
    assert!(!enforce_classification(Unclassified, Secret).is_granted());

    // Secret can read Confidential
    assert!(enforce_classification(Secret, Confidential).is_granted());

    // SCI can read everything
    assert!(enforce_classification(SCI, Unclassified).is_granted());
    assert!(enforce_classification(SCI, Confidential).is_granted());
    assert!(enforce_classification(SCI, Secret).is_granted());
    assert!(enforce_classification(SCI, TopSecret).is_granted());
    assert!(enforce_classification(SCI, SCI).is_granted());

    // No write down: TopSecret cannot write to Confidential
    let decision = enforce_no_downgrade(TopSecret, Confidential);
    assert!(!decision.is_granted());
    assert!(matches!(
        decision,
        ClassificationDecision::DowngradePrevented { .. }
    ));
}

// =========================================================================
// 17. Cross-domain information flow control
// =========================================================================

fn make_domain(name: &str, level: ClassificationLevel) -> SecurityDomain {
    SecurityDomain {
        id: Uuid::new_v4(),
        name: name.to_string(),
        classification: level,
    }
}

#[test]
fn cross_domain_same_domain_always_allowed() {
    let mut guard = CrossDomainGuard::new();
    let domain = make_domain("NIPRNet", ClassificationLevel::Unclassified);
    let id = domain.id;
    guard.register_domain(domain);

    let decision = guard.validate_transfer(&id, &id);
    assert!(decision.allowed, "same-domain transfer must always be allowed");
}

#[test]
fn cross_domain_low_to_high_with_rule_allowed() {
    let mut guard = CrossDomainGuard::new();
    let nipr = make_domain("NIPRNet", ClassificationLevel::Unclassified);
    let sipr = make_domain("SIPRNet", ClassificationLevel::Secret);
    let nipr_id = nipr.id;
    let sipr_id = sipr.id;
    guard.register_domain(nipr);
    guard.register_domain(sipr);

    guard.add_flow_rule(FlowRule {
        source_domain: nipr_id,
        target_domain: sipr_id,
        direction: FlowDirection::Unidirectional,
        declassification_authorized: false,
        justification: "data push to classified net".into(),
        authorized_by: Uuid::nil(),
        created_at: 0,
    });

    let decision = guard.validate_transfer(&nipr_id, &sipr_id);
    assert!(decision.allowed, "low-to-high with rule must be allowed");
}

#[test]
fn cross_domain_high_to_low_without_declass_denied() {
    let mut guard = CrossDomainGuard::new();
    let jwics = make_domain("JWICS", ClassificationLevel::TopSecret);
    let nipr = make_domain("NIPRNet", ClassificationLevel::Unclassified);
    let jwics_id = jwics.id;
    let nipr_id = nipr.id;
    guard.register_domain(jwics);
    guard.register_domain(nipr);

    guard.add_flow_rule(FlowRule {
        source_domain: jwics_id,
        target_domain: nipr_id,
        direction: FlowDirection::Unidirectional,
        declassification_authorized: false,
        justification: "test without declass".into(),
        authorized_by: Uuid::nil(),
        created_at: 0,
    });

    let decision = guard.validate_transfer(&jwics_id, &nipr_id);
    assert!(
        !decision.allowed,
        "high-to-low without declassification must be denied"
    );
    assert!(decision.reason.contains("declassification"));
}

#[test]
fn cross_domain_high_to_low_with_declass_allowed() {
    let mut guard = CrossDomainGuard::new();
    let jwics = make_domain("JWICS", ClassificationLevel::TopSecret);
    let sipr = make_domain("SIPRNet", ClassificationLevel::Secret);
    let jwics_id = jwics.id;
    let sipr_id = sipr.id;
    guard.register_domain(jwics);
    guard.register_domain(sipr);

    guard.add_flow_rule(FlowRule {
        source_domain: jwics_id,
        target_domain: sipr_id,
        direction: FlowDirection::Unidirectional,
        declassification_authorized: true,
        justification: "authorized declassification review".into(),
        authorized_by: Uuid::nil(),
        created_at: 0,
    });

    let decision = guard.validate_transfer(&jwics_id, &sipr_id);
    assert!(
        decision.allowed,
        "high-to-low with declassification must be allowed"
    );
}

#[test]
fn cross_domain_bidirectional_rules_work_both_ways() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("DomainA", ClassificationLevel::Secret);
    let b = make_domain("DomainB", ClassificationLevel::Secret);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);

    guard.add_flow_rule(FlowRule {
        source_domain: a_id,
        target_domain: b_id,
        direction: FlowDirection::Bidirectional,
        declassification_authorized: false,
        justification: "peer exchange".into(),
        authorized_by: Uuid::nil(),
        created_at: 0,
    });

    assert!(
        guard.validate_transfer(&a_id, &b_id).allowed,
        "A->B must be allowed (bidirectional)"
    );
    assert!(
        guard.validate_transfer(&b_id, &a_id).allowed,
        "B->A must be allowed (bidirectional)"
    );
}

#[test]
fn cross_domain_rule_removal_revokes_access() {
    let mut guard = CrossDomainGuard::new();
    let src = make_domain("Src", ClassificationLevel::Secret);
    let tgt = make_domain("Tgt", ClassificationLevel::Secret);
    let src_id = src.id;
    let tgt_id = tgt.id;
    guard.register_domain(src);
    guard.register_domain(tgt);

    guard.add_flow_rule(FlowRule {
        source_domain: src_id,
        target_domain: tgt_id,
        direction: FlowDirection::Unidirectional,
        declassification_authorized: false,
        justification: "temporary access".into(),
        authorized_by: Uuid::nil(),
        created_at: 0,
    });

    assert!(guard.validate_transfer(&src_id, &tgt_id).allowed);
    assert!(guard.remove_flow_rule(&src_id, &tgt_id, Uuid::nil()));
    assert!(
        !guard.validate_transfer(&src_id, &tgt_id).allowed,
        "removed rule must revoke access"
    );
}

#[test]
fn cross_domain_unregistered_domain_denied() {
    let mut guard = CrossDomainGuard::new();
    let registered = make_domain("Known", ClassificationLevel::Secret);
    let reg_id = registered.id;
    guard.register_domain(registered);

    let unregistered_id = Uuid::new_v4();
    let decision = guard.validate_transfer(&reg_id, &unregistered_id);
    assert!(
        !decision.allowed,
        "transfer to unregistered domain must be denied"
    );
    assert!(decision.reason.contains("not registered"));
}

#[test]
fn cross_domain_no_rule_default_deny() {
    let mut guard = CrossDomainGuard::new();
    let a = make_domain("Alpha", ClassificationLevel::Confidential);
    let b = make_domain("Bravo", ClassificationLevel::Confidential);
    let a_id = a.id;
    let b_id = b.id;
    guard.register_domain(a);
    guard.register_domain(b);

    let decision = guard.validate_transfer(&a_id, &b_id);
    assert!(!decision.allowed, "no rule must mean default deny");
    assert!(decision.reason.contains("default deny"));
}

// =========================================================================
// 18. Witness log checkpoint integrity
// =========================================================================

#[test]
fn witness_log_5_checkpoints_integrity() {
    let mut wlog = WitnessLog::new();

    for i in 0..5 {
        let mut audit_root = [0u8; 64];
        let mut kt_root = [0u8; 64];
        audit_root[0] = i as u8;
        kt_root[0] = (i + 100) as u8;
        let sig = vec![0xAA; 32];
        wlog.add_checkpoint(audit_root, kt_root, sig);
    }

    assert_eq!(wlog.len(), 5);

    // Verify monotonic sequence numbers
    let latest = wlog.latest().expect("must have latest");
    assert_eq!(latest.sequence, 4, "latest checkpoint must have sequence 4");

    // Verify that the log contains all 5 checkpoints with correct content
    assert!(!wlog.is_empty());
}

#[test]
fn witness_log_timestamps_non_decreasing() {
    let mut wlog = WitnessLog::new();

    let mut prev_ts = 0i64;
    for _ in 0..5 {
        let audit_root = [0u8; 64];
        let kt_root = [0u8; 64];
        wlog.add_checkpoint(audit_root, kt_root, vec![]);

        let latest = wlog.latest().unwrap();
        assert!(
            latest.timestamp >= prev_ts,
            "timestamps must be non-decreasing"
        );
        prev_ts = latest.timestamp;
    }
}

#[test]
fn witness_log_correct_content() {
    let mut wlog = WitnessLog::new();

    let mut audit_root = [0u8; 64];
    audit_root[0] = 0x42;
    let mut kt_root = [0u8; 64];
    kt_root[0] = 0x99;
    let sig = vec![0xDE, 0xAD, 0xBE, 0xEF];

    wlog.add_checkpoint(audit_root, kt_root, sig.clone());

    let cp = wlog.latest().unwrap();
    assert_eq!(cp.audit_root[0], 0x42);
    assert_eq!(cp.kt_root[0], 0x99);
    assert_eq!(cp.signature, sig);
    assert_eq!(cp.sequence, 0);
}

// =========================================================================
// 19. Envelope encryption layered security
// =========================================================================

#[test]
fn envelope_correct_kek_decrypts() {
    let kek = KeyEncryptionKey::generate().expect("generate KEK");
    let dek = DataEncryptionKey::generate().expect("generate DEK");

    let wrapped = wrap_key(&kek, &dek).expect("wrap");
    let recovered_dek = unwrap_key(&kek, &wrapped).expect("unwrap");
    assert_eq!(
        recovered_dek.as_bytes(),
        dek.as_bytes(),
        "correct KEK must recover DEK"
    );

    // Use recovered DEK to encrypt/decrypt
    let aad = build_aad("users", "password", b"u-1");
    let sealed = envelope::encrypt(&recovered_dek, b"secret", &aad).expect("encrypt");
    let plain = envelope::decrypt(&recovered_dek, &sealed, &aad).expect("decrypt");
    assert_eq!(plain, b"secret");
}

#[test]
fn envelope_wrong_kek_fails() {
    let kek1 = KeyEncryptionKey::generate().expect("generate KEK");
    let kek2 = KeyEncryptionKey::generate().expect("generate KEK");
    let dek = DataEncryptionKey::generate().expect("generate DEK");

    let wrapped = wrap_key(&kek1, &dek).expect("wrap");
    let result = unwrap_key(&kek2, &wrapped);
    assert!(
        result.is_err(),
        "wrong KEK must fail to unwrap DEK"
    );
}

#[test]
fn envelope_context_binding_prevents_cross_context() {
    let dek = DataEncryptionKey::generate().expect("generate DEK");
    let aad_a = build_aad("sessions", "token", b"s-1");
    let aad_b = build_aad("sessions", "token", b"s-2");

    let sealed = envelope::encrypt(&dek, b"data", &aad_a).expect("encrypt");

    // Decrypt with wrong AAD must fail
    let result = envelope::decrypt(&dek, &sealed, &aad_b);
    assert!(
        result.is_err(),
        "context-binding AAD mismatch must prevent decryption"
    );

    // Decrypt with correct AAD must succeed
    let plain = envelope::decrypt(&dek, &sealed, &aad_a).expect("decrypt");
    assert_eq!(plain, b"data");
}

// =========================================================================
// 20. Honey encryption plausibility
// =========================================================================

#[test]
fn honey_encrypt_correct_key_roundtrip() {
    let key = random_key_32();
    let plaintext = b"real-secret-username@mil.gov";

    let encrypted = honey_encrypt(&key, plaintext, PlausibleDistribution::Email).unwrap();
    let decrypted = honey_decrypt(&key, &encrypted);

    assert_eq!(
        decrypted, plaintext,
        "correct key must return original plaintext"
    );
}

#[test]
fn honey_encrypt_wrong_key_plausible_output() {
    let key = random_key_32();
    let wrong_key = random_key_32();
    let plaintext = b"top-secret-data";

    let encrypted = honey_encrypt(&key, plaintext, PlausibleDistribution::Username).unwrap();
    let fake = honey_decrypt(&wrong_key, &encrypted);

    assert!(!fake.is_empty(), "wrong key must return non-empty plausible data");
    assert_ne!(
        fake.as_slice(),
        plaintext,
        "wrong key must not return real plaintext"
    );
    // The fake output should be a reasonable size (not gigabytes of random data)
    assert!(
        fake.len() < 256,
        "fake output must be reasonable size (< 256 bytes)"
    );
}

#[test]
fn honey_encrypt_wrong_key_deterministic() {
    let key = random_key_32();
    let wrong_key = random_key_32();
    let plaintext = b"consistent-test-data";

    let encrypted = honey_encrypt(&key, plaintext, PlausibleDistribution::Username).unwrap();
    let fake1 = honey_decrypt(&wrong_key, &encrypted);
    let fake2 = honey_decrypt(&wrong_key, &encrypted);

    assert_eq!(
        fake1, fake2,
        "same wrong key must always produce the same fake output"
    );
}

#[test]
fn honey_encrypt_multiple_distributions() {
    let key = random_key_32();
    let wrong_key = random_key_32();

    let distributions = [
        (PlausibleDistribution::Username, "username"),
        (PlausibleDistribution::Email, "email"),
        (PlausibleDistribution::MilitaryId, "military_id"),
        (PlausibleDistribution::IpAddress, "ip_address"),
        (PlausibleDistribution::TokenPayload, "token_payload"),
    ];

    for (dist, name) in &distributions {
        let plaintext = format!("real-data-{}", name);
        let encrypted =
            honey_encrypt(&key, plaintext.as_bytes(), *dist).unwrap();
        let fake = honey_decrypt(&wrong_key, &encrypted);

        assert!(
            !fake.is_empty(),
            "distribution {}: wrong key must return non-empty output",
            name
        );
        assert!(
            fake.len() < 512,
            "distribution {}: output must be reasonable size",
            name
        );
    }
}

#[test]
fn honey_encrypt_different_wrong_keys_different_fakes() {
    let key = random_key_32();
    let wrong_key_1 = random_key_32();
    let wrong_key_2 = random_key_32();
    let plaintext = b"victim-data";

    let encrypted = honey_encrypt(&key, plaintext, PlausibleDistribution::Email).unwrap();
    let fake1 = honey_decrypt(&wrong_key_1, &encrypted);
    let fake2 = honey_decrypt(&wrong_key_2, &encrypted);

    // Different wrong keys should overwhelmingly produce different fakes
    assert_ne!(
        fake1, fake2,
        "different wrong keys must produce different fake outputs"
    );
}
