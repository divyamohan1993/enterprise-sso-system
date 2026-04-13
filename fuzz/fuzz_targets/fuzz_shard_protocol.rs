#![no_main]
//! I8 [HIGH] Structured SHARD protocol fuzz with field reordering / type
//! confusion via postcard mutation.

use arbitrary::Arbitrary;
use common::types::ModuleId;
use libfuzzer_sys::fuzz_target;
use shard::protocol::ShardProtocol;

#[derive(Debug, Arbitrary)]
struct Input {
    seed: [u8; 64],
    module_tag: u8,
    payload: Vec<u8>,
    mutate_at: Vec<u16>,
    duplicate_prefix: bool,
    swap_bytes: bool,
}

fn pick_module(tag: u8) -> ModuleId {
    match tag % 6 {
        0 => ModuleId::Gateway,
        1 => ModuleId::Orchestrator,
        2 => ModuleId::Audit,
        3 => ModuleId::Verifier,
        4 => ModuleId::Tss,
        _ => ModuleId::Opaque,
    }
}

fuzz_target!(|input: Input| {
    let mut p = ShardProtocol::new(pick_module(input.module_tag), input.seed);

    // First produce a "legit" frame, then mutate it.
    let raw = match p.create_message(&input.payload) {
        Ok(b) => b,
        Err(_) => return,
    };
    let mut mutated = raw.clone();

    // Bit-flip and field reorder.
    for &i in input.mutate_at.iter().take(64) {
        if mutated.is_empty() { break; }
        let idx = (i as usize) % mutated.len();
        mutated[idx] = mutated[idx].wrapping_add(0x91);
    }
    if input.swap_bytes && mutated.len() > 4 {
        mutated.swap(0, mutated.len() - 1);
        mutated.swap(1, mutated.len() - 2);
    }
    if input.duplicate_prefix && mutated.len() > 8 {
        let head: Vec<u8> = mutated.iter().take(8).copied().collect();
        mutated.splice(0..0, head);
    }

    // Verifier must never panic on adversarial wire bytes.
    let _ = p.verify_message(&mutated);
    let _ = p.verify_message(&input.payload);
});
