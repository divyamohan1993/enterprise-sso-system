#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use common::totp::{
    generate_totp, generate_totp_with_algorithm, verify_totp, verify_totp_with_algorithm,
    TotpAlgorithm,
};

#[derive(Arbitrary, Debug)]
struct FuzzTotpInput {
    /// Arbitrary secret bytes (TOTP accepts any key length per RFC 2104).
    secret: Vec<u8>,
    /// Arbitrary bytes to use as a TOTP code string.
    code_bytes: Vec<u8>,
    /// Unix timestamp for TOTP computation.
    time: u64,
    /// Verification window.
    window: u8,
    /// Algorithm selector: 0 = SHA-256, 1 = SHA-512.
    algo_selector: u8,
}

#[allow(deprecated)]
fuzz_target!(|input: FuzzTotpInput| {
    // Bound input sizes to prevent excessive computation.
    if input.secret.len() > 256 || input.code_bytes.len() > 32 {
        return;
    }

    let algo = if input.algo_selector % 2 == 0 {
        TotpAlgorithm::Sha256
    } else {
        TotpAlgorithm::Sha512
    };

    let window = (input.window % 3) as u32; // cap at 2

    // ── Path 1: Generate TOTP with boundary timestamps ─────────────────
    // Test time=0, time=u64::MAX, and wrapping boundaries.
    let boundary_times = [0u64, 1, 29, 30, 31, u64::MAX - 1, u64::MAX, input.time];
    for &t in &boundary_times {
        if !input.secret.is_empty() {
            let code = generate_totp_with_algorithm(&input.secret, t, algo);
            // Generated code must always be 6 digits or "000000" (SHA-1 rejection).
            assert_eq!(code.len(), 6, "TOTP code must be exactly 6 chars");
            assert!(
                code.chars().all(|c| c.is_ascii_digit()),
                "TOTP code must be all digits"
            );
        }
    }

    // ── Path 2: Verify arbitrary code strings ──────────────────────────
    if let Ok(code_str) = std::str::from_utf8(&input.code_bytes) {
        // Must not panic regardless of input.
        let _ = verify_totp_with_algorithm(&input.secret, code_str, input.time, window, algo);
    }

    // ── Path 3: Generate-then-verify roundtrip ─────────────────────────
    if !input.secret.is_empty() {
        let generated = generate_totp_with_algorithm(&input.secret, input.time, algo);
        // Note: verify may return false due to replay cache in the same process,
        // but it must never panic.
        let _ = verify_totp_with_algorithm(&input.secret, &generated, input.time, 0, algo);
    }

    // ── Path 4: SHA-1 rejection path ───────────────────────────────────
    if !input.secret.is_empty() {
        let sha1_code = generate_totp_with_algorithm(&input.secret, input.time, TotpAlgorithm::Sha1);
        assert_eq!(sha1_code, "000000", "SHA-1 must be rejected");
        let sha1_verify = verify_totp_with_algorithm(
            &input.secret,
            "123456",
            input.time,
            window,
            TotpAlgorithm::Sha1,
        );
        assert!(!sha1_verify, "SHA-1 verification must always fail");
    }

    // ── Path 5: Empty secret handling ──────────────────────────────────
    {
        let code = generate_totp(&[], input.time);
        assert_eq!(code.len(), 6);
        let _ = verify_totp(&[], &code, input.time, 0);
    }
});
