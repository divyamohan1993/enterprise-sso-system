use crypto::dpop::*;

fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

#[test]
fn test_dpop_key_hash_deterministic() {
    let key = [42u8; 32];
    let h1 = dpop_key_hash(&key);
    let h2 = dpop_key_hash(&key);
    assert_eq!(h1, h2);
}

#[test]
fn test_dpop_key_hash_different_keys_differ() {
    let h1 = dpop_key_hash(&[1u8; 32]);
    let h2 = dpop_key_hash(&[2u8; 32]);
    assert_ne!(h1, h2);
}

#[test]
fn test_dpop_proof_generation_and_verification() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair();
        let claims = b"test-claims";
        let timestamp = 12345i64;
        let proof = generate_dpop_proof(&sk, claims, timestamp);
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        assert!(verify_dpop_proof(&vk, &proof, claims, timestamp, &key_hash));
    });
}

#[test]
fn test_dpop_proof_rejects_wrong_key() {
    run_with_large_stack(|| {
        let (sk1, _vk1) = generate_dpop_keypair();
        let (_sk2, vk2) = generate_dpop_keypair();
        let claims = b"test-claims";
        let timestamp = 12345i64;
        let proof = generate_dpop_proof(&sk1, claims, timestamp);
        let vk2_bytes = vk2.encode();
        let key_hash = dpop_key_hash(vk2_bytes.as_ref());
        // vk2 won't match the signature made with sk1
        assert!(!verify_dpop_proof(&vk2, &proof, claims, timestamp, &key_hash));
    });
}

#[test]
fn test_dpop_proof_rejects_wrong_claims() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair();
        let timestamp = 12345i64;
        let proof = generate_dpop_proof(&sk, b"original", timestamp);
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        assert!(!verify_dpop_proof(&vk, &proof, b"tampered", timestamp, &key_hash));
    });
}

#[test]
fn test_dpop_key_hash_length_is_32() {
    let key = [0xFFu8; 32];
    let hash = dpop_key_hash(&key);
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_dpop_proof_rejects_wrong_timestamp() {
    run_with_large_stack(|| {
        let (sk, vk) = generate_dpop_keypair();
        let claims = b"claims-data";
        let proof = generate_dpop_proof(&sk, claims, 1000);
        let vk_bytes = vk.encode();
        let key_hash = dpop_key_hash(vk_bytes.as_ref());
        assert!(!verify_dpop_proof(&vk, &proof, claims, 2000, &key_hash));
    });
}
