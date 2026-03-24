#![no_main]
use libfuzzer_sys::fuzz_target;
use crypto::envelope::{DataEncryptionKey, SealedData, decrypt};
fuzz_target!(|data: &[u8]| { let d = DataEncryptionKey::from_bytes([0x42u8; 32]); if let Ok(s) = SealedData::from_bytes(data.to_vec()) { let _ = decrypt(&d, &s, b"fuzz"); } });
