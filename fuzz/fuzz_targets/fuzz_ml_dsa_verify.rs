#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypto::pq_sign::{generate_pq_keypair, pq_verify, pq_verify_raw, pq_verify_tagged, PqVerifyingKey};

static VK: std::sync::LazyLock<PqVerifyingKey> = std::sync::LazyLock::new(|| {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| generate_pq_keypair().1)
        .unwrap()
        .join()
        .unwrap()
});

#[derive(Arbitrary, Debug)]
struct Input {
    message: Vec<u8>,
    sig_bytes: Vec<u8>,
    frost_sig: [u8; 64],
}

fuzz_target!(|input: Input| {
    // Fuzz nested verify (message + FROST signature + PQ signature)
    let _ = pq_verify(&*VK, &input.message, &input.frost_sig, &input.sig_bytes);

    // Fuzz raw verify (message + raw signature bytes)
    let _ = pq_verify_raw(&*VK, &input.message, &input.sig_bytes);

    // Fuzz tagged verify (self-describing algorithm tag)
    let _ = pq_verify_tagged(&*VK, &input.message, &input.sig_bytes);
});
