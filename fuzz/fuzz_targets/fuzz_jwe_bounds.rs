#![no_main]
//! I9 [HIGH] JWE/OPAQUE length-bounds fuzz: oversized/undersized ciphertexts,
//! mismatched share lengths, malformed nonces.

use arbitrary::Arbitrary;
use common::types::EncryptedClaims;
use crypto::jwe::decrypt_claims;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    nonce: [u8; 12],
    key: [u8; 32],
    declared_len: u32,
    real_payload: Vec<u8>,
    pad_byte: u8,
    pad_count: u16,
}

fuzz_target!(|input: Input| {
    // Construct ciphertexts whose length is wildly inconsistent with what an
    // honest serializer would produce.
    let declared = (input.declared_len as usize) & 0x000F_FFFF;
    let mut ct: Vec<u8> = input.real_payload.iter().take(8192).copied().collect();
    if declared > ct.len() {
        ct.resize(declared.min(1 << 20), input.pad_byte);
    } else if declared < ct.len() {
        ct.truncate(declared);
    }
    for _ in 0..(input.pad_count as usize % 256) {
        ct.push(input.pad_byte);
    }

    // Empty / single-byte / mismatched-nonce ciphertexts must never panic.
    let encrypted = EncryptedClaims { nonce: input.nonce, ciphertext: ct };
    let _ = decrypt_claims(&encrypted, &input.key);

    let zero_ct = EncryptedClaims { nonce: input.nonce, ciphertext: vec![] };
    let _ = decrypt_claims(&zero_ct, &input.key);

    let single = EncryptedClaims { nonce: input.nonce, ciphertext: vec![input.pad_byte] };
    let _ = decrypt_claims(&single, &input.key);
});
