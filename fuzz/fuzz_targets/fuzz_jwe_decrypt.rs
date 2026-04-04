#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use common::types::EncryptedClaims;
use crypto::jwe::decrypt_claims;

#[derive(Arbitrary, Debug)]
struct Input {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    key: [u8; 32],
}

fuzz_target!(|input: Input| {
    let encrypted = EncryptedClaims {
        nonce: input.nonce,
        ciphertext: input.ciphertext,
    };

    // Fuzz JWE decryption with random nonce, ciphertext, and key
    // Must never panic regardless of input
    let _ = decrypt_claims(&encrypted, &input.key);
});
