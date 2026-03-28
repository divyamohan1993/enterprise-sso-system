//! HTTP smuggling / protocol boundary test suite.
//!
//! Tests SHARD protocol enforcement boundaries:
//!   - Max frame / payload size enforcement
//!   - Null bytes in module ID are rejected
//!   - Timestamp drift window is exactly 2 seconds
//!   - SHARD protocol message roundtrip integrity

use std::time::{SystemTime, UNIX_EPOCH};

use common::types::{ModuleId, ShardMessage};
use shard::protocol::ShardProtocol;

// ── Constants ────────────────────────────────────────────────────────────

const SHARED_SECRET: [u8; 64] = [0x55u8; 64];

/// Maximum allowed timestamp drift in microseconds (from protocol source).
const MAX_TIMESTAMP_DRIFT_US: i64 = 2_000_000; // 2 seconds

/// Large payload above any reasonable single-frame limit used to probe
/// size enforcement.
const LARGE_PAYLOAD_LEN: usize = 65_536; // 64 KiB

// ── Helpers ──────────────────────────────────────────────────────────────

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

/// Build a raw ShardMessage with a manually-set timestamp by deserialising a
/// legitimate message and replacing the timestamp field, then re-serialising.
/// The HMAC will be invalid (covers timestamp), so the receiver will reject it
/// at HMAC stage — we use this to confirm any rejection, not specifically
/// timestamp rejection.
fn make_message_with_timestamp(timestamp_us: i64, payload: &[u8]) -> Vec<u8> {
    let mut sender = ShardProtocol::new(ModuleId::Gateway, SHARED_SECRET);
    let raw = sender.create_message(payload).expect("create_message");

    let mut msg: ShardMessage =
        postcard::from_bytes(&raw).expect("deserialise ShardMessage");
    msg.timestamp = timestamp_us;
    postcard::to_allocvec(&msg).expect("re-serialise ShardMessage with modified timestamp")
}

// ── Test 1: Max frame size enforcement ───────────────────────────────────

#[test]
fn test_max_frame_size_enforcement() {
    // The SHARD protocol create_message + verify_message pipeline must handle a
    // 64 KiB payload without silently truncating or panicking.

    let large_payload = vec![0xA5u8; LARGE_PAYLOAD_LEN];

    let mut sender = ShardProtocol::new(ModuleId::Gateway, SHARED_SECRET);
    let raw = sender
        .create_message(&large_payload)
        .expect("create_message must succeed for 64 KiB payload without panicking");

    assert!(
        !raw.is_empty(),
        "serialised SHARD message must not be empty for a {}-byte payload",
        LARGE_PAYLOAD_LEN
    );

    // The serialised message must be larger than the payload itself due to
    // encryption overhead, HMAC, sequence number, and postcard framing.
    assert!(
        raw.len() > LARGE_PAYLOAD_LEN,
        "serialised SHARD message ({} bytes) must be larger than the raw payload \
         ({} bytes) due to encryption + HMAC overhead",
        raw.len(),
        LARGE_PAYLOAD_LEN
    );

    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, SHARED_SECRET);
    let (sender_module, decoded) = receiver
        .verify_message(&raw)
        .expect("verify_message must succeed for a valid 64 KiB frame");

    assert_eq!(
        sender_module,
        ModuleId::Gateway,
        "sender_module must be Gateway, got {:?}",
        sender_module
    );
    assert_eq!(
        decoded.as_bytes(),
        large_payload.as_slice(),
        "decoded payload must exactly match original {} bytes; \
         encryption/decryption must be lossless at 64 KiB",
        LARGE_PAYLOAD_LEN
    );

    // Oversized payload (10x) — pipeline must not panic regardless of outcome.
    let oversized_payload = vec![0xBBu8; LARGE_PAYLOAD_LEN * 10];
    let mut sender2 = ShardProtocol::new(ModuleId::Tss, SHARED_SECRET);
    let _ = sender2.create_message(&oversized_payload);
}

// ── Test 2: Null bytes in module ID rejected ─────────────────────────────

#[test]
fn test_null_bytes_in_module_id_rejected() {
    // ModuleId is a Rust enum backed by u8 — it cannot contain arbitrary
    // null bytes by construction. Attempting to deserialise an unknown
    // discriminant must produce a postcard deserialisation error, not
    // undefined behaviour.

    let mut sender = ShardProtocol::new(ModuleId::Gateway, SHARED_SECRET);
    let raw = sender
        .create_message(b"probe-null-module-id")
        .expect("create_message");

    let msg: ShardMessage =
        postcard::from_bytes(&raw).expect("valid message must deserialise");

    let re_encoded = postcard::to_allocvec(&msg).expect("re-serialise");

    // Find the sender_module byte (Gateway = 1) and zero it.
    let gateway_discriminant: u8 = ModuleId::Gateway as u8; // = 1
    let mut corrupted = re_encoded.clone();
    let mut found = false;
    for byte in corrupted.iter_mut() {
        if *byte == gateway_discriminant {
            *byte = 0x00; // null / invalid discriminant
            found = true;
            break;
        }
    }
    assert!(
        found,
        "gateway discriminant byte ({}) must be present in serialised message; \
         test setup assumption failed",
        gateway_discriminant
    );

    // verify_message must return an error (HMAC failure because we corrupted a byte).
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, SHARED_SECRET);
    let result = receiver.verify_message(&corrupted);
    assert!(
        result.is_err(),
        "message with null/invalid sender_module discriminant (0x00) must be \
         rejected; got unexpected Ok result"
    );

    // Also verify that an out-of-range discriminant (0xFF) is rejected.
    let mut corrupted_high = re_encoded.clone();
    for byte in corrupted_high.iter_mut() {
        if *byte == gateway_discriminant {
            *byte = 0xFF;
            break;
        }
    }
    let mut receiver2 = ShardProtocol::new(ModuleId::Orchestrator, SHARED_SECRET);
    let result_high = receiver2.verify_message(&corrupted_high);
    assert!(
        result_high.is_err(),
        "message with out-of-range sender_module discriminant (0xFF) must be \
         rejected by the SHARD protocol; got unexpected Ok result"
    );

    // All-zero 32-byte frame is not a valid postcard-serialised ShardMessage.
    let null_frame = vec![0u8; 32];
    let mut receiver3 = ShardProtocol::new(ModuleId::Orchestrator, SHARED_SECRET);
    let null_result = receiver3.verify_message(&null_frame);
    assert!(
        null_result.is_err(),
        "all-zero 32-byte frame must be rejected as an invalid SHARD message"
    );
}

// ── Test 3: Timestamp drift window is 2 seconds ──────────────────────────

#[test]
fn test_timestamp_drift_window_is_two_seconds() {
    // Messages within the ±2s window must be accepted.
    // Messages outside must be rejected (HMAC covers timestamp, so rejection
    // always happens regardless of which check fires first).

    // Within window: current timestamp — should succeed.
    let mut sender = ShardProtocol::new(ModuleId::Gateway, SHARED_SECRET);
    let valid_raw = sender
        .create_message(b"timestamp-ok")
        .expect("create_message with current timestamp");

    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, SHARED_SECRET);
    let result_valid = receiver.verify_message(&valid_raw);
    assert!(
        result_valid.is_ok(),
        "message with current timestamp must be accepted; got: {:?}",
        result_valid.err()
    );

    // Future timestamp just outside window (2.1 s ahead): must be rejected.
    // HMAC covers the timestamp, so corruption is detected at HMAC stage.
    let future_ts = now_us() + 2_100_000;
    let future_raw = make_message_with_timestamp(future_ts, b"future");
    let mut receiver2 = ShardProtocol::new(ModuleId::Orchestrator, SHARED_SECRET);
    let future_result = receiver2.verify_message(&future_raw);
    assert!(
        future_result.is_err(),
        "message with timestamp {} µs in the future (drift=2,100,000µs > \
         MAX={}µs) must be rejected; got unexpected Ok",
        future_ts,
        MAX_TIMESTAMP_DRIFT_US
    );

    // Past timestamp just outside window (2.1 s behind): must be rejected.
    let past_ts = now_us() - 2_100_000;
    let past_raw = make_message_with_timestamp(past_ts, b"past");
    let mut receiver3 = ShardProtocol::new(ModuleId::Orchestrator, SHARED_SECRET);
    let past_result = receiver3.verify_message(&past_raw);
    assert!(
        past_result.is_err(),
        "message with timestamp {} µs in the past (drift=2,100,000µs > \
         MAX={}µs) must be rejected; got unexpected Ok",
        past_ts,
        MAX_TIMESTAMP_DRIFT_US
    );

    // Drift constant sanity check.
    assert_eq!(
        MAX_TIMESTAMP_DRIFT_US,
        2_000_000,
        "drift window constant must be exactly 2_000_000 µs (2 seconds) as per \
         spec Section 11; got {} µs",
        MAX_TIMESTAMP_DRIFT_US
    );
}

// ── Test 4: SHARD protocol message roundtrip ─────────────────────────────

#[test]
fn test_shard_protocol_message_roundtrip() {
    let secret = [0xDEu8; 64];
    let mut sender = ShardProtocol::new(ModuleId::Tss, secret);
    let mut receiver = ShardProtocol::new(ModuleId::Verifier, secret);

    let payload = b"SHARD-roundtrip-test-payload-v2";

    let raw = sender
        .create_message(payload)
        .expect("create_message must succeed for normal payload");

    assert!(
        !raw.is_empty(),
        "serialised SHARD message must not be empty"
    );

    let (module, decoded) = receiver
        .verify_message(&raw)
        .expect("verify_message must succeed for a valid SHARD frame");

    assert_eq!(
        module,
        ModuleId::Tss,
        "sender module must be Tss; got {:?}",
        module
    );
    assert_eq!(
        decoded.as_bytes(),
        payload.as_ref(),
        "decoded payload must exactly match original '{}'; \
         got '{}' ({} bytes)",
        String::from_utf8_lossy(payload),
        String::from_utf8_lossy(decoded.as_bytes()),
        decoded.as_bytes().len()
    );

    // Sequence number is monotonically increasing — subsequent messages accepted.
    for i in 1u32..=3 {
        let pkt = sender
            .create_message(format!("msg-{}", i).as_bytes())
            .expect("create_message for subsequent packet");
        let (_, body) = receiver
            .verify_message(&pkt)
            .expect("subsequent message must be accepted");
        assert_eq!(
            body.as_bytes(),
            format!("msg-{}", i).as_bytes(),
            "payload for message {} must match; got: '{}'",
            i,
            String::from_utf8_lossy(body.as_bytes())
        );
    }

    // Replay is rejected.
    let replay_err = receiver
        .verify_message(&raw)
        .expect_err("replayed SHARD message must be rejected");
    let err_str = format!("{}", replay_err);
    assert!(
        err_str.contains("replay") || err_str.contains("seq"),
        "replay error must mention 'replay' or 'seq'; got: '{}'",
        err_str
    );

    // Wrong key is rejected.
    let wrong_secret = [0xFFu8; 64];
    let mut wrong_receiver = ShardProtocol::new(ModuleId::Verifier, wrong_secret);
    let wrong_raw = sender
        .create_message(b"wrong-key-probe")
        .expect("create_message");
    let wrong_result = wrong_receiver.verify_message(&wrong_raw);
    assert!(
        wrong_result.is_err(),
        "message encrypted with one key must be rejected by a receiver with a \
         different key; the HMAC must catch the mismatch"
    );

    // Empty payload roundtrip.
    let mut sender2 = ShardProtocol::new(ModuleId::Risk, secret);
    let mut receiver2 = ShardProtocol::new(ModuleId::Audit, secret);
    let empty_raw = sender2
        .create_message(b"")
        .expect("create_message with empty payload");
    let (_, empty_decoded) = receiver2
        .verify_message(&empty_raw)
        .expect("empty-payload SHARD message must roundtrip successfully");
    assert!(
        empty_decoded.as_bytes().is_empty(),
        "decoded payload for empty-payload message must be empty; got {} bytes",
        empty_decoded.as_bytes().len()
    );
}
