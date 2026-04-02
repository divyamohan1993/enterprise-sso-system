//! Security property tests — verifying critical invariants of the crypto layer.

use crypto::ct::{ct_eq, ct_eq_32, ct_eq_64};
use crypto::entropy::{generate_key_64, generate_nonce};
use crypto::receipts::{hash_receipt, sign_receipt, verify_receipt_signature, ReceiptChain};
use common::types::Receipt;

// ── Constant-time comparison security properties ────────────────────────────

#[test]
fn ct_eq_single_bit_difference_detected() {
    let a = [0u8; 32];
    let mut b = [0u8; 32];
    b[15] = 1; // single bit flip in the middle
    assert!(!ct_eq(&a, &b));
}

#[test]
fn ct_eq_32_all_zeros_vs_all_ones() {
    let zeros = [0x00u8; 32];
    let ones = [0xFFu8; 32];
    assert!(!ct_eq_32(&zeros, &ones));
}

#[test]
fn ct_eq_64_single_byte_difference() {
    let a = [0xAAu8; 64];
    let mut b = [0xAAu8; 64];
    b[63] = 0xBB;
    assert!(!ct_eq_64(&a, &b));
}

// ── Entropy uniqueness ──────────────────────────────────────────────────────

#[test]
fn generate_nonce_produces_unique_values() {
    let n1 = generate_nonce();
    let n2 = generate_nonce();
    let n3 = generate_nonce();
    assert_ne!(n1, n2);
    assert_ne!(n2, n3);
    assert_ne!(n1, n3);
}

#[test]
fn generate_key_64_nonzero() {
    let key = generate_key_64();
    assert_ne!(key, [0u8; 64], "64-byte key must not be all zeros");
}

#[test]
fn generate_key_64_halves_differ() {
    let key = generate_key_64();
    // The two halves come from separate combined_entropy() calls
    // so they should differ (with overwhelming probability)
    assert_ne!(&key[..32], &key[32..], "key halves should differ");
}

// ── Receipt chain security properties ───────────────────────────────────────

#[test]
fn receipt_signature_verified() {
    let key = [0x42u8; 64];
    let mut receipt = Receipt::test_fixture();
    sign_receipt(&mut receipt, &key);
    assert!(verify_receipt_signature(&receipt, &key));
}

#[test]
fn receipt_signature_rejects_wrong_key() {
    let key = [0x42u8; 64];
    let wrong_key = [0x99u8; 64];
    let mut receipt = Receipt::test_fixture();
    sign_receipt(&mut receipt, &key);
    assert!(!verify_receipt_signature(&receipt, &wrong_key));
}

#[test]
fn receipt_signature_rejects_tampered_data() {
    let key = [0x42u8; 64];
    let mut receipt = Receipt::test_fixture();
    sign_receipt(&mut receipt, &key);
    // Tamper with the step_id
    receipt.step_id = 99;
    assert!(!verify_receipt_signature(&receipt, &key));
}

#[test]
fn receipt_hash_deterministic() {
    let receipt = Receipt::test_fixture();
    let h1 = hash_receipt(&receipt);
    let h2 = hash_receipt(&receipt);
    assert_eq!(h1, h2);
}

#[test]
fn receipt_hash_differs_for_different_steps() {
    let mut r1 = Receipt::test_fixture();
    let mut r2 = Receipt::test_fixture();
    r1.step_id = 1;
    r2.step_id = 2;
    assert_ne!(hash_receipt(&r1), hash_receipt(&r2));
}

#[test]
fn receipt_chain_rejects_wrong_session_id() {
    let session_id = [0x01; 32];
    let mut chain = ReceiptChain::new(session_id);
    let mut receipt = Receipt::test_fixture();
    receipt.ceremony_session_id = [0x02; 32]; // wrong session
    receipt.prev_receipt_hash = [0x00; 64];
    receipt.step_id = 1;
    assert!(chain.add_receipt(receipt).is_err());
}

#[test]
fn receipt_chain_rejects_out_of_order_steps() {
    let session_id = [0x01; 32];
    let mut chain = ReceiptChain::new(session_id);
    let mut receipt = Receipt::test_fixture();
    receipt.step_id = 2; // should be 1 for first receipt
    receipt.prev_receipt_hash = [0x00; 64];
    assert!(chain.add_receipt(receipt).is_err());
}

#[test]
fn receipt_chain_empty_validation_fails() {
    let chain = ReceiptChain::new([0x01; 32]);
    assert!(chain.validate().is_err());
}

#[test]
fn receipt_chain_valid_two_step() {
    let session_id = [0x01; 32];
    let key = [0x42u8; 64];
    let mut chain = ReceiptChain::new(session_id);

    // Step 1
    let mut r1 = Receipt::test_fixture();
    r1.ceremony_session_id = session_id;
    r1.step_id = 1;
    r1.prev_receipt_hash = [0x00; 64];
    sign_receipt(&mut r1, &key);
    chain.add_receipt(r1.clone()).unwrap();

    // Step 2
    let mut r2 = Receipt::test_fixture();
    r2.ceremony_session_id = session_id;
    r2.step_id = 2;
    r2.prev_receipt_hash = hash_receipt(&r1);
    sign_receipt(&mut r2, &key);
    chain.add_receipt(r2).unwrap();

    assert_eq!(chain.len(), 2);
    // validate() without key always returns Err (unsafe without signature check)
    assert!(chain.validate().is_err());
    assert!(chain.validate_with_key(&key).is_ok());
}

#[test]
fn receipt_chain_rejects_invalid_signature() {
    let session_id = [0x01; 32];
    let key = [0x42u8; 64];
    let wrong_key = [0x99u8; 64];
    let mut chain = ReceiptChain::new(session_id);

    let mut r1 = Receipt::test_fixture();
    r1.ceremony_session_id = session_id;
    r1.step_id = 1;
    r1.prev_receipt_hash = [0x00; 64];
    sign_receipt(&mut r1, &wrong_key); // signed with wrong key
    chain.add_receipt(r1).unwrap();

    assert!(chain.validate_with_key(&key).is_err());
}

// ── ZKP security audit tests ─────────────────────────────────────────────

use crypto::zkp::{prove_range_gte, verify_range_gte};

/// SECURITY AUDIT: ZKP reveals exact committed value — not zero-knowledge
///
/// The range proof embeds `delta = value - min_value` in plaintext inside
/// `proof_data[32..40]`.  Anyone who reads the proof transcript can recover
/// the exact value, which defeats the purpose of a zero-knowledge proof.
#[test]
fn zkp_range_proof_leaks_exact_value() {
    let mut blinding = [0u8; 32];
    getrandom::getrandom(&mut blinding).expect("getrandom");

    let value: u64 = 100;
    let min_value: u64 = 50;

    let proof = prove_range_gte(value, min_value, &blinding)
        .expect("prove_range_gte must succeed for value >= min_value");

    // The proof is valid — verification passes.
    assert!(verify_range_gte(&proof), "proof must verify");

    // Extract the plaintext delta from proof_data bytes 32..40 (LE u64).
    let delta_bytes: [u8; 8] = proof.proof_data[32..40]
        .try_into()
        .expect("delta slice must be 8 bytes");
    let delta = u64::from_le_bytes(delta_bytes);

    // SECURITY AUDIT: ZKP reveals exact committed value — not zero-knowledge
    // A verifier can trivially compute: value = min_value + delta = 50 + 50 = 100
    assert_eq!(
        delta, 50,
        "delta in proof transcript must equal value - min_value, proving the \
         'zero-knowledge' proof leaks the exact committed value"
    );
}

/// SECURITY AUDIT: Classification proof leaks exact clearance level to verifier
///
/// Because the classification proof wraps the range proof, the same delta
/// leak applies: the verifier learns the prover's exact clearance level,
/// not just that it exceeds the minimum.
#[test]
fn zkp_classification_proof_leaks_clearance_level() {
    let mut blinding = [0u8; 32];
    getrandom::getrandom(&mut blinding).expect("getrandom");

    // SCI clearance (level 4), Secret required (min 2)
    let level: u64 = 4;
    let min_required: u64 = 2;

    let proof = prove_range_gte(level, min_required, &blinding)
        .expect("prove_range_gte must succeed for level >= min_required");

    assert!(verify_range_gte(&proof), "proof must verify");

    let delta_bytes: [u8; 8] = proof.proof_data[32..40]
        .try_into()
        .expect("delta slice must be 8 bytes");
    let delta = u64::from_le_bytes(delta_bytes);

    // SECURITY AUDIT: Classification proof leaks exact clearance level to verifier
    // Verifier learns: clearance = min_required + delta = 2 + 2 = 4 (SCI)
    assert_eq!(
        delta, 2,
        "classification proof leaks exact clearance level delta to verifier"
    );
}

// ── SLH-DSA parameter audit tests ────────────────────────────────────────

use crypto::slh_dsa::{slh_dsa_keygen, slh_dsa_sign, slh_dsa_verify};

/// SECURITY AUDIT: SLH-DSA uses non-standard params, not FIPS 205 compliant
///
/// FIPS 205 SLH-DSA-SHA2-256f specifies h=66, d=22, producing 49,856-byte
/// signatures.  This implementation uses H=8, D=1, FORS_K=14, FORS_A=6,
/// yielding a much smaller (5,568-byte) signature that does NOT conform to
/// any standardized parameter set.
#[test]
fn slh_dsa_parameters_deviate_from_fips205() {
    let (sk, vk) = slh_dsa_keygen();
    let message = b"FIPS 205 parameter compliance test";

    let sig = slh_dsa_sign(&sk, message);
    assert!(
        slh_dsa_verify(&vk, message, &sig),
        "sign/verify roundtrip must succeed"
    );

    // FIPS 205 SLH-DSA-SHA2-256f mandates 49,856-byte signatures.
    const FIPS205_SHA2_256F_SIG_SIZE: usize = 49_856;

    // SECURITY AUDIT: SLH-DSA uses non-standard params, not FIPS 205 compliant
    // Actual signature size is 5,568 bytes (H=8,D=1,K=14,A=6), far smaller
    // than the 49,856 bytes required by the standardized parameter set.
    assert_ne!(
        sig.as_bytes().len(),
        FIPS205_SHA2_256F_SIG_SIZE,
        "signature size must NOT match FIPS 205 SHA2-256f — impl uses non-standard params"
    );
    assert_eq!(
        sig.as_bytes().len(),
        5568,
        "actual signature size should be 5568 bytes (N=32 + FORS=3136 + HT=2400)"
    );
}

// ── FIPS KAT audit tests ─────────────────────────────────────────────────

use crypto::fips_kat;

/// SECURITY AUDIT: ML-KEM, ML-DSA, X-Wing KATs are roundtrip-only, not true NIST KAT vectors
///
/// The startup KATs pass, but the post-quantum algorithm tests (ML-KEM-1024,
/// ML-DSA-87, X-Wing, SLH-DSA) only verify encrypt-decrypt or sign-verify
/// roundtrips.  They do NOT compare against hardcoded NIST CAVP test vectors,
/// so a subtly broken implementation would still pass these "KATs".
#[test]
fn fips_kat_pq_algorithms_lack_hardcoded_vectors() {
    // The KATs pass — the algorithms are internally consistent.
    fips_kat::run_startup_kats()
        .expect("FIPS 140-3 startup KATs must pass");

    // SECURITY AUDIT: ML-KEM, ML-DSA, X-Wing KATs are roundtrip-only, not true NIST KAT vectors
    // A roundtrip test (keygen -> sign -> verify, or keygen -> encap -> decap)
    // proves internal consistency but NOT correctness against the standard.
    // True FIPS 140-3 compliance requires comparison against NIST CAVP vectors
    // with deterministic seeding, which is not implemented here.
}

// ── KSF Argon2id iteration count hardening ──────────────────────────────

/// Verify that Argon2id KSF uses 4 iterations (hardened from 3).
/// The test stretches a password with 4 iterations (current) and 3 iterations
/// (old), and confirms the outputs differ. This proves the iteration count
/// change took effect and passwords stretched with the old params produce
/// different derived keys.
#[test]
fn ksf_argon2id_4_iterations_differs_from_3() {
    use argon2::{Algorithm, Argon2, Params, Version};

    let password = b"test-password-for-iteration-count";
    let salt = b"fixed-salt-for-determinism-00000";

    // Current production params: memory=65536 KiB, iterations=4, parallelism=4, output=32
    let params_4 = Params::new(65536, 4, 4, Some(32)).expect("params_4");
    let argon2_4 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params_4);
    let mut output_4 = vec![0u8; 32];
    argon2_4
        .hash_password_into(password, salt, &mut output_4)
        .expect("argon2id with 4 iterations");

    // Old params: same but iterations=3
    let params_3 = Params::new(65536, 3, 4, Some(32)).expect("params_3");
    let argon2_3 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params_3);
    let mut output_3 = vec![0u8; 32];
    argon2_3
        .hash_password_into(password, salt, &mut output_3)
        .expect("argon2id with 3 iterations");

    assert_ne!(
        output_4, output_3,
        "4-iteration Argon2id must produce different output from 3-iteration \
         (proves the hardened iteration count took effect)"
    );

    // Also verify the production KSF API produces the same 4-iteration output
    use crypto::kdf::{Argon2idKsf, KeyStretchingFunction};
    let ksf = Argon2idKsf;
    let ksf_output = ksf.stretch(password, salt).expect("KSF stretch");
    assert_eq!(
        ksf_output, output_4,
        "Argon2idKsf must use exactly 4 iterations (matching params_4)"
    );
}

/// Verify the KSF algorithm ID is correct.
#[test]
fn ksf_argon2id_algorithm_id() {
    use crypto::kdf::{Argon2idKsf, KeyStretchingFunction};
    let ksf = Argon2idKsf;
    assert_eq!(ksf.algorithm_id(), "argon2id-v19");
    assert!(!ksf.is_fips_approved(), "Argon2id is not FIPS approved");
}

// ── Entropy health audit tests ───────────────────────────────────────────

use crypto::entropy::combined_entropy_checked;

/// Verify that the entropy source never produces duplicate 32-byte outputs
/// across multiple invocations (repetition count sanity check).
#[test]
fn entropy_repetition_count_detects_stuck_source() {
    let mut samples = Vec::with_capacity(20);
    for _ in 0..20 {
        let sample = combined_entropy_checked()
            .expect("combined_entropy_checked must succeed on a healthy system");
        samples.push(sample);
    }

    // Every sample must be unique — a collision in 256-bit outputs would
    // indicate a catastrophic entropy source failure.
    for i in 0..samples.len() {
        for j in (i + 1)..samples.len() {
            assert_ne!(
                samples[i], samples[j],
                "entropy samples {} and {} must differ — stuck source detected",
                i, j
            );
        }
    }
}

// ── Constant-time comparison audit tests ─────────────────────────────────

/// Verify that ct_eq returns false for slices of different lengths,
/// documenting the timing leak potential: when lengths differ, the
/// function returns immediately (before comparing any bytes), which
/// reveals that the lengths are different via timing.
#[test]
fn ct_eq_different_lengths_returns_false() {
    use crypto::ct::ct_eq;

    let short = [0xAAu8; 16];
    let long = [0xAAu8; 32];

    // ct_eq must reject different-length slices even if the shorter
    // slice is a prefix of the longer one.
    assert!(
        !ct_eq(&short, &long),
        "ct_eq must return false for different-length slices"
    );
    assert!(
        !ct_eq(&long, &short),
        "ct_eq must return false for different-length slices (reversed)"
    );

    // Edge case: empty vs non-empty
    let empty: [u8; 0] = [];
    assert!(
        !ct_eq(&empty, &short),
        "ct_eq must return false for empty vs non-empty"
    );

    // Edge case: both empty should be equal
    let empty2: [u8; 0] = [];
    assert!(
        ct_eq(&empty, &empty2),
        "ct_eq must return true for two empty slices"
    );
}

// ── Memguard canary detection ─────────────────────────────────────────

#[test]
fn test_memguard_secret_buffer_canary_protection() {
    // Memory protection: canary words detect buffer overflow/corruption
    use crypto::memguard::SecretBuffer;

    let data = [0xABu8; 32];
    let buf = SecretBuffer::<32>::new(data).expect("SecretBuffer::new must succeed");

    // Canaries must be intact after construction
    assert!(buf.verify_canaries(), "canaries must be intact on fresh buffer");

    // Read back the data and verify correctness
    let read_back = buf.as_bytes();
    assert_eq!(read_back, &[0xABu8; 32], "data must survive write/read roundtrip");

    // Write new data via mutable access, then verify
    drop(buf);
    let mut buf2 = SecretBuffer::<32>::new([0x00u8; 32]).expect("SecretBuffer::new must succeed");
    {
        let writable = buf2.as_bytes_mut();
        for (i, b) in writable.iter_mut().enumerate() {
            *b = (i * 3) as u8;
        }
    }
    let expected: Vec<u8> = (0..32).map(|i| (i * 3) as u8).collect();
    assert_eq!(
        buf2.as_bytes().as_slice(),
        expected.as_slice(),
        "mutable write must be readable after canary check"
    );
    assert!(buf2.verify_canaries(), "canaries must remain intact after mutation");
}

// ── Symmetric AEAD security properties ────────────────────────────────

#[test]
fn test_symmetric_aead_roundtrip_aes256gcm() {
    // AES-256-GCM AEAD: authenticated encryption with associated data
    use crypto::symmetric::{encrypt_with, decrypt, SymmetricAlgorithm};

    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).expect("getrandom");

    let plaintext = b"classified payload for AEAD roundtrip test";
    let aad = b"mission-context-alpha";

    let sealed = encrypt_with(SymmetricAlgorithm::Aes256Gcm, &key, plaintext, aad)
        .expect("AES-256-GCM encryption must succeed");
    let recovered = decrypt(&key, &sealed, aad)
        .expect("AES-256-GCM decryption must succeed");

    assert_eq!(
        recovered.as_slice(),
        plaintext,
        "plaintext must match after encrypt/decrypt roundtrip"
    );
}

#[test]
fn test_symmetric_aead_rejects_tampered_ciphertext() {
    // AEAD authentication: any ciphertext modification detected
    use crypto::symmetric::{encrypt_with, decrypt, SymmetricAlgorithm};

    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).expect("getrandom");

    let plaintext = b"tamper-detection test payload";
    let aad = b"integrity-context";

    let mut sealed = encrypt_with(SymmetricAlgorithm::Aes256Gcm, &key, plaintext, aad)
        .expect("encryption must succeed");

    // Flip a byte in the ciphertext region (after algo_id byte + 12-byte nonce)
    let tamper_pos = 1 + 12 + 1; // algo_id(1) + nonce(12) + offset into ciphertext
    assert!(
        tamper_pos < sealed.len(),
        "sealed blob must be large enough to tamper with"
    );
    sealed[tamper_pos] ^= 0xFF;

    let result = decrypt(&key, &sealed, aad);
    assert!(
        result.is_err(),
        "decryption must fail when ciphertext has been tampered with"
    );
}

// ── Envelope encryption AAD binding ───────────────────────────────────

#[test]
fn test_envelope_encryption_binds_to_context() {
    // Envelope encryption AAD prevents ciphertext transplantation attacks
    use crypto::envelope::{encrypt, decrypt, DataEncryptionKey, build_aad};

    let dek = DataEncryptionKey::generate().expect("generate DEK");
    let plaintext = b"secret data bound to specific context";

    let aad_original = build_aad("users", "password_hash", b"user-42");
    let aad_different = build_aad("users", "password_hash", b"user-99");

    let sealed = encrypt(&dek, plaintext, &aad_original)
        .expect("envelope encryption must succeed");

    // Decryption with the original AAD must succeed
    let recovered = decrypt(&dek, &sealed, &aad_original)
        .expect("decryption with correct AAD must succeed");
    assert_eq!(recovered.as_slice(), plaintext);

    // Decryption with a different AAD must fail — prevents transplantation
    let result = decrypt(&dek, &sealed, &aad_different);
    assert!(
        result.is_err(),
        "decryption with wrong AAD must fail — ciphertext is bound to its original context"
    );
}
