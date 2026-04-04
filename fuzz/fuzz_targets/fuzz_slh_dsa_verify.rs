#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypto::slh_dsa::{slh_dsa_keygen, slh_dsa_verify, SlhDsaSignature, SlhDsaVerifyingKey};

static VK: std::sync::LazyLock<SlhDsaVerifyingKey> = std::sync::LazyLock::new(|| {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| slh_dsa_keygen().1)
        .unwrap()
        .join()
        .unwrap()
});

#[derive(Arbitrary, Debug)]
struct Input {
    message: Vec<u8>,
    sig_bytes: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Attempt to parse raw bytes as an SLH-DSA signature and verify
    if let Some(sig) = SlhDsaSignature::from_bytes(input.sig_bytes) {
        let _ = slh_dsa_verify(&*VK, &input.message, &sig);
    }

    // Also fuzz verifying key deserialization from random bytes
    let _ = SlhDsaVerifyingKey::from_bytes(&input.message);
});
