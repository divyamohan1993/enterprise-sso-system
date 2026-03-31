#![no_main]
use libfuzzer_sys::fuzz_target;
use common::backup::import_backup;
fuzz_target!(|data: &[u8]| { let key = [0x42u8; 32]; let _ = import_backup(&key, data); });
