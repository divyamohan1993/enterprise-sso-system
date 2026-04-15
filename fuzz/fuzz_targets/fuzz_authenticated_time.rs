#![no_main]
//! CAT-M: Roughtime response parser / verifier fuzz.
//!
//! The on-wire Roughtime binding is done by an external service; in-process
//! MILNET consumes a `RoughtimeResponse` struct (JSON/postcard deserialized)
//! and then calls `common::secure_time::verify_roughtime_response_hybrid`.
//! This fuzz target drives BOTH the deserializer (arbitrary JSON) and the
//! verifier (arbitrary field contents) to ensure:
//!
//!   1. No panic on malformed input.
//!   2. `deny_unknown_fields` is honored (caught by serde, not us).
//!   3. Signature/pubkey length validation rejects short/long byte arrays.
//!   4. The hybrid verifier never returns `true` for a response with
//!      mismatched signature and pubkey lengths.

use arbitrary::Arbitrary;
use common::secure_time::{verify_roughtime_response_hybrid, RoughtimeResponse};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct TimeInput {
    server: String,
    timestamp: u64,
    radius: u32,
    signature: Vec<u8>,
    pubkey: Vec<u8>,
    include_pq: bool,
    pq_signature: Vec<u8>,
    pq_pubkey: Vec<u8>,
    raw_json: Vec<u8>,
}

fuzz_target!(|input: TimeInput| {
    // 1. JSON deserializer path — feed raw bytes directly.
    if !input.raw_json.is_empty() {
        let _ = serde_json::from_slice::<RoughtimeResponse>(&input.raw_json);
    }

    // 2. Structured path — build the struct from arbitrary fields.
    let resp = RoughtimeResponse {
        server: input.server.chars().take(256).collect(),
        timestamp: input.timestamp,
        radius: input.radius,
        signature: input.signature.iter().take(256).copied().collect(),
        pubkey: input.pubkey.iter().take(256).copied().collect(),
        pq_signature: if input.include_pq {
            Some(input.pq_signature.iter().take(8192).copied().collect())
        } else {
            None
        },
        pq_pubkey: if input.include_pq {
            Some(input.pq_pubkey.iter().take(8192).copied().collect())
        } else {
            None
        },
    };

    // Verifier must never panic.
    let ok = verify_roughtime_response_hybrid(&resp);

    // Length invariants: Ed25519 sig = 64, pubkey = 32. Anything else MUST be
    // rejected. This catches the case where an attacker sends a truncated
    // signature and hopes the verifier short-circuits to true.
    if resp.signature.len() != 64 || resp.pubkey.len() != 32 {
        assert!(!ok, "verifier accepted invalid Ed25519 lengths");
    }
});
