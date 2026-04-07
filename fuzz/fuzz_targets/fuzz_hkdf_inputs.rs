#![no_main]
use libfuzzer_sys::fuzz_target;
use hkdf::Hkdf;
use sha2::Sha512;

fuzz_target!(|data: &[u8]| {
    // Split fuzzed data into IKM, salt, and info segments.
    // Any split point is valid; we test that HKDF never panics.
    let third = data.len() / 3;
    let ikm = &data[..third];
    let salt = &data[third..third * 2];
    let info = &data[third * 2..];

    // Extract + expand with arbitrary inputs
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut okm_32 = [0u8; 32];
    let _ = hk.expand(info, &mut okm_32);

    let mut okm_64 = [0u8; 64];
    let _ = hk.expand(info, &mut okm_64);

    // Also test with no salt (None)
    let hk_no_salt = Hkdf::<Sha512>::new(None, ikm);
    let mut okm2 = [0u8; 32];
    let _ = hk_no_salt.expand(info, &mut okm2);
});
