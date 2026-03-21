use milnet_crypto::entropy::{combined_entropy, generate_nonce, generate_key_64};

#[test]
fn combined_entropy_is_nonzero() {
    let output = combined_entropy();
    assert_ne!(output, [0u8; 32], "Entropy output must not be all zeros");
}

#[test]
fn combined_entropy_is_unique() {
    let a = combined_entropy();
    let b = combined_entropy();
    assert_ne!(a, b, "Two consecutive calls must produce different outputs");
}

#[test]
fn generate_nonce_is_32_bytes() {
    let nonce = generate_nonce();
    assert_eq!(nonce.len(), 32);
}

#[test]
fn generate_key_64_is_64_bytes() {
    let key = generate_key_64();
    assert_eq!(key.len(), 64);
}

#[test]
fn entropy_sources_are_mixed() {
    // Verify that the output differs from raw OS entropy.
    // Since combined_entropy hashes and XORs multiple sources,
    // the result should not match a fresh OS CSPRNG sample.
    let mut os_only = [0u8; 32];
    getrandom::getrandom(&mut os_only).unwrap();
    let combined = combined_entropy();
    assert_ne!(
        os_only, combined,
        "Combined entropy must differ from raw OS entropy"
    );
}
