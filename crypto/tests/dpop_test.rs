use crypto::dpop::*;
use p256::ecdsa::{SigningKey, VerifyingKey};

fn test_keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::random(&mut rand::rngs::OsRng);
    let vk = VerifyingKey::from(&sk);
    (sk, vk)
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
    let (sk, vk) = test_keypair();
    let claims = b"test-claims";
    let timestamp = 12345i64;
    let proof = generate_dpop_proof(&sk, claims, timestamp);
    let pk_bytes = vk.to_encoded_point(false);
    let key_hash = dpop_key_hash(pk_bytes.as_bytes());
    assert!(verify_dpop_proof(&vk, &proof, claims, timestamp, &key_hash));
}

#[test]
fn test_dpop_proof_rejects_wrong_key() {
    let (sk1, vk1) = test_keypair();
    let (_sk2, vk2) = test_keypair();
    let claims = b"test-claims";
    let timestamp = 12345i64;
    let proof = generate_dpop_proof(&sk1, claims, timestamp);
    let pk_bytes = vk2.to_encoded_point(false);
    let key_hash = dpop_key_hash(pk_bytes.as_bytes());
    // vk2 won't match the signature made with sk1
    assert!(!verify_dpop_proof(&vk2, &proof, claims, timestamp, &key_hash));
}

#[test]
fn test_dpop_proof_rejects_wrong_claims() {
    let (sk, vk) = test_keypair();
    let timestamp = 12345i64;
    let proof = generate_dpop_proof(&sk, b"original", timestamp);
    let pk_bytes = vk.to_encoded_point(false);
    let key_hash = dpop_key_hash(pk_bytes.as_bytes());
    assert!(!verify_dpop_proof(&vk, &proof, b"tampered", timestamp, &key_hash));
}

#[test]
fn test_dpop_key_hash_length_is_32() {
    let key = [0xFFu8; 32];
    let hash = dpop_key_hash(&key);
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_dpop_proof_rejects_wrong_timestamp() {
    let (sk, vk) = test_keypair();
    let claims = b"claims-data";
    let proof = generate_dpop_proof(&sk, claims, 1000);
    let pk_bytes = vk.to_encoded_point(false);
    let key_hash = dpop_key_hash(pk_bytes.as_bytes());
    assert!(!verify_dpop_proof(&vk, &proof, claims, 2000, &key_hash));
}
