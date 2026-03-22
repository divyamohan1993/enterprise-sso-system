use crypto::dpop::*;

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
    let key = [7u8; 64];
    let claims = b"test-claims";
    let timestamp = 12345i64;
    let proof = generate_dpop_proof(&key, claims, timestamp);
    let key_hash = dpop_key_hash(&key);
    assert!(verify_dpop_proof(&key, &proof, claims, timestamp, &key_hash));
}

#[test]
fn test_dpop_proof_rejects_wrong_key() {
    let key1 = [7u8; 64];
    let key2 = [8u8; 64];
    let claims = b"test-claims";
    let timestamp = 12345i64;
    let proof = generate_dpop_proof(&key1, claims, timestamp);
    let key_hash = dpop_key_hash(&key1);
    // key2 won't match the key_hash derived from key1
    assert!(!verify_dpop_proof(&key2, &proof, claims, timestamp, &key_hash));
}

#[test]
fn test_dpop_proof_rejects_wrong_claims() {
    let key = [7u8; 64];
    let timestamp = 12345i64;
    let proof = generate_dpop_proof(&key, b"original", timestamp);
    let key_hash = dpop_key_hash(&key);
    assert!(!verify_dpop_proof(&key, &proof, b"tampered", timestamp, &key_hash));
}

#[test]
fn test_dpop_key_hash_length_is_32() {
    let key = [0xFFu8; 32];
    let hash = dpop_key_hash(&key);
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_dpop_proof_rejects_wrong_timestamp() {
    let key = [9u8; 64];
    let claims = b"claims-data";
    let proof = generate_dpop_proof(&key, claims, 1000);
    let key_hash = dpop_key_hash(&key);
    assert!(!verify_dpop_proof(&key, &proof, claims, 2000, &key_hash));
}
