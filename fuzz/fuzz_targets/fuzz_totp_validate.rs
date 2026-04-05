#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use common::totp::{verify_totp, verify_totp_with_algorithm, generate_totp, TotpAlgorithm};

#[derive(Arbitrary, Debug)]
struct TotpInput {
    secret: Vec<u8>,
    code: Vec<u8>,
    time: u64,
    window: u32,
    use_sha256: bool,
}

#[allow(deprecated)]
fuzz_target!(|input: TotpInput| {
    if input.secret.len() > 128 || input.code.len() > 16 {
        return; // Bound input size
    }

    let code_str = match std::str::from_utf8(&input.code) {
        Ok(s) => s,
        Err(_) => return, // TOTP codes are ASCII digit strings
    };

    // Path 1: Verify arbitrary code against arbitrary secret/time
    let algo = if input.use_sha256 {
        TotpAlgorithm::Sha256
    } else {
        TotpAlgorithm::Sha512
    };
    let _ = verify_totp_with_algorithm(&input.secret, code_str, input.time, input.window, algo);

    // Path 2: Generate then verify (should always succeed for window=0 with valid secret)
    if !input.secret.is_empty() {
        let generated = generate_totp(&input.secret, input.time);
        let _ = verify_totp(&input.secret, &generated, input.time, 0);
    }
});
