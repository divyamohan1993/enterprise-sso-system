#![no_main]
use libfuzzer_sys::fuzz_target;
use crypto::pq_sign::generate_pq_keypair;

static VK: std::sync::LazyLock<crypto::pq_sign::PqVerifyingKey> =
    std::sync::LazyLock::new(|| {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| generate_pq_keypair().1)
            .unwrap()
            .join()
            .unwrap()
    });

fuzz_target!(|data: &[u8]| {
    let token_str = String::from_utf8_lossy(data);
    // Fuzz the full token verification pipeline
    let _ = sso_protocol::tokens::verify_id_token(&token_str, &VK);
    // Also try with a fake audience
    let _ = sso_protocol::tokens::verify_id_token_with_audience(
        &token_str,
        &VK,
        "fuzz-audience",
        false,
    );
});
