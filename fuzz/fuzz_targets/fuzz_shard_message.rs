#![no_main]
use libfuzzer_sys::fuzz_target;
use common::types::ModuleId;
use shard::protocol::ShardProtocol;
fuzz_target!(|data: &[u8]| { let mut p = ShardProtocol::new(ModuleId::Gateway, [0x42u8; 64]); let _ = p.verify_message(data); });
