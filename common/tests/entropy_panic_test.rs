//! Tests that key generation never returns zero keys.

#[test]
fn test_generate_random_bytes_32_is_nonzero() {
    let result = common::persistence::generate_random_bytes_32();
    assert!(
        result.is_ok(),
        "key generation should succeed on healthy system: {:?}",
        result.err()
    );
    let k = result.unwrap();
    assert!(
        k.iter().any(|&b| b != 0),
        "generated 32-byte key must not be all-zero — got {:02x?}",
        &k[..8]
    );
}

#[test]
fn test_generate_random_bytes_64_is_nonzero() {
    let result = common::persistence::generate_random_bytes_64();
    assert!(
        result.is_ok(),
        "key generation should succeed on healthy system: {:?}",
        result.err()
    );
    let k = result.unwrap();
    assert!(
        k.iter().any(|&b| b != 0),
        "generated 64-byte key must not be all-zero — got {:02x?}",
        &k[..8]
    );
}
