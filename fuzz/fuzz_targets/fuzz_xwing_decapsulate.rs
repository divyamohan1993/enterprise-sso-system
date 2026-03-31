#![no_main]
use libfuzzer_sys::fuzz_target;
use crypto::xwing::{xwing_keygen, xwing_decapsulate, Ciphertext};
static KP: std::sync::LazyLock<crypto::xwing::XWingKeyPair> = std::sync::LazyLock::new(|| { std::thread::Builder::new().stack_size(16*1024*1024).spawn(|| xwing_keygen().1).unwrap().join().unwrap() });
fuzz_target!(|data: &[u8]| { if let Some(ct) = Ciphertext::from_bytes(data) { let _ = xwing_decapsulate(&KP, &ct); } });
