#![no_main]
use libfuzzer_sys::fuzz_target;
use crypto::dpop::{generate_dpop_keypair, verify_dpop_proof};
static VK: std::sync::LazyLock<crypto::dpop::DpopVerifyingKey> = std::sync::LazyLock::new(|| { std::thread::Builder::new().stack_size(16*1024*1024).spawn(|| generate_dpop_keypair().1).unwrap().join().unwrap() });
fuzz_target!(|data: &[u8]| { let hash = [0x42u8; 64]; let _ = verify_dpop_proof(&VK, data, data, 0, &hash); });
