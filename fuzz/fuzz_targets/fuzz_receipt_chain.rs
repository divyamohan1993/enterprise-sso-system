#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypto::receipts::ReceiptChain;
use common::types::Receipt;
use uuid::Uuid;
#[derive(Arbitrary, Debug)] struct FR { sid: [u8;32], step: u8, prev: [u8;64], uid: [u8;16], dpop: [u8;32], ts: i64, nonce: [u8;32], sig: Vec<u8>, ttl: u8 }
#[derive(Arbitrary, Debug)] struct FI { sid: [u8;32], rs: Vec<FR> }
fuzz_target!(|i: FI| { let mut c = ReceiptChain::new(i.sid); for r in &i.rs { let _ = c.add_receipt(Receipt { ceremony_session_id: r.sid, step_id: r.step, prev_receipt_hash: r.prev, user_id: Uuid::from_bytes(r.uid), dpop_key_hash: r.dpop, timestamp: r.ts, nonce: r.nonce, signature: r.sig.clone(), ttl_seconds: r.ttl }); } let _ = c.validate(); });
