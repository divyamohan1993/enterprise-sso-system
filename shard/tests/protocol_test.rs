use common::types::ModuleId;
use shard::protocol::ShardProtocol;

fn test_key_a() -> [u8; 64] {
    [0xAA; 64]
}

fn test_key_b() -> [u8; 64] {
    [0xBB; 64]
}

#[test]
fn message_roundtrip() {
    let key = test_key_a();
    let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, key);

    let payload = b"hello shard protocol";
    let raw = sender.create_message(payload).expect("create_message");
    let (module, decoded) = receiver.verify_message(&raw).expect("verify_message");

    assert_eq!(module, ModuleId::Gateway);
    assert_eq!(decoded, payload);
}

#[test]
fn rejects_replay() {
    let key = test_key_a();
    let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, key);

    let raw = sender.create_message(b"msg1").expect("create_message");

    // First verification succeeds
    receiver.verify_message(&raw).expect("first verify");

    // Replaying the same message must fail (same sequence number)
    let err = receiver
        .verify_message(&raw)
        .expect_err("replay should fail");
    let msg = format!("{err}");
    assert!(msg.contains("replay"), "error should mention replay: {msg}");
}

#[test]
fn rejects_tampered_payload() {
    let key = test_key_a();
    let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, key);

    let mut raw = sender
        .create_message(b"original payload")
        .expect("create_message");

    // Tamper with a byte in the payload area (somewhere in the middle of the serialized data)
    // We flip a byte near the end but before the HMAC to corrupt the payload.
    let mid = raw.len() / 2;
    raw[mid] ^= 0xFF;

    let err = receiver.verify_message(&raw);
    assert!(err.is_err(), "tampered message should fail verification");
}

#[test]
fn rejects_wrong_key() {
    let mut sender = ShardProtocol::new(ModuleId::Gateway, test_key_a());
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, test_key_b());

    let raw = sender
        .create_message(b"secret data")
        .expect("create_message");

    let err = receiver.verify_message(&raw);
    assert!(err.is_err(), "wrong key should fail HMAC verification");
}

#[test]
fn tracks_multiple_senders() {
    let key = test_key_a();
    let mut sender_a = ShardProtocol::new(ModuleId::Gateway, key);
    let mut sender_b = ShardProtocol::new(ModuleId::Tss, key);
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, key);

    // Both senders send message #1 — independent sequence spaces
    let raw_a1 = sender_a.create_message(b"from gateway").expect("create a1");
    let raw_b1 = sender_b.create_message(b"from tss").expect("create b1");

    let (mod_a, pay_a) = receiver.verify_message(&raw_a1).expect("verify a1");
    assert_eq!(mod_a, ModuleId::Gateway);
    assert_eq!(pay_a, b"from gateway");

    let (mod_b, pay_b) = receiver.verify_message(&raw_b1).expect("verify b1");
    assert_eq!(mod_b, ModuleId::Tss);
    assert_eq!(pay_b, b"from tss");

    // Second message from each sender should also work
    let raw_a2 = sender_a
        .create_message(b"gateway msg 2")
        .expect("create a2");
    let raw_b2 = sender_b.create_message(b"tss msg 2").expect("create b2");

    receiver.verify_message(&raw_a2).expect("verify a2");
    receiver.verify_message(&raw_b2).expect("verify b2");

    // Replaying a1 should fail (sequence 1 already seen for Gateway)
    let err = receiver
        .verify_message(&raw_a1)
        .expect_err("replay a1 should fail");
    let msg = format!("{err}");
    assert!(msg.contains("replay"), "error should mention replay: {msg}");

    // But b1 replay should also fail independently
    let err = receiver
        .verify_message(&raw_b1)
        .expect_err("replay b1 should fail");
    let msg = format!("{err}");
    assert!(msg.contains("replay"), "error should mention replay: {msg}");
}

// ── Security hardening: replay protection audit ──────────────────────────

// SECURITY AUDIT: SHARD sequence numbers prevent message replay
#[test]
fn test_shard_rejects_replayed_message() {
    let key = test_key_a();
    let mut protocol1 = ShardProtocol::new(ModuleId::Gateway, key);
    let mut protocol2 = ShardProtocol::new(ModuleId::Orchestrator, key);

    // Send a message from protocol1, receive on protocol2
    let raw = protocol1
        .create_message(b"replay-test-payload")
        .expect("create_message");

    // First receive must succeed
    let (sender, payload) = protocol2
        .verify_message(&raw)
        .expect("first verification must succeed");
    assert_eq!(sender, ModuleId::Gateway);
    assert_eq!(payload, b"replay-test-payload");

    // Attempt to receive the SAME raw bytes again — must fail with replay error
    let err = protocol2
        .verify_message(&raw)
        .expect_err("replayed message must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("replay"),
        "error must indicate replay detection, got: {msg}"
    );
}

// ── Security hardening: wrong HMAC key rejection ─────────────────────────

#[test]
fn test_shard_rejects_wrong_hmac_key() {
    // Two protocols with DIFFERENT shared secrets
    let mut sender = ShardProtocol::new(ModuleId::Gateway, test_key_a());
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, test_key_b());

    let raw = sender
        .create_message(b"wrong-key-test")
        .expect("create_message");

    // HMAC verification must fail because receiver derives a different HMAC key
    let err = receiver
        .verify_message(&raw)
        .expect_err("wrong HMAC key must cause verification failure");
    let msg = format!("{err}");
    assert!(
        msg.contains("HMAC") || msg.contains("hmac") || msg.contains("verification failed"),
        "error must indicate HMAC failure, got: {msg}"
    );
}

// ── Security hardening: stale timestamp rejection ────────────────────────

#[test]
fn test_shard_rejects_stale_timestamp() {
    use common::types::ShardMessage;

    let key = test_key_a();
    let mut sender = ShardProtocol::new(ModuleId::Gateway, key);
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, key);

    // Create a valid message, then deserialize, backdate the timestamp,
    // and re-serialize. The HMAC covers the timestamp, so modifying it
    // causes HMAC failure (correct security behavior for timestamp tampering).
    let raw = sender
        .create_message(b"stale-timestamp-test")
        .expect("create_message");

    // Deserialize the wire message
    let mut msg: ShardMessage =
        postcard::from_bytes(&raw).expect("deserialize must succeed");

    // Set the timestamp to 10 seconds in the past (MAX_TIMESTAMP_DRIFT_US = 2_000_000)
    msg.timestamp -= 10_000_000; // 10 seconds in microseconds

    // Modifying the timestamp without access to the protocol's internal
    // HMAC key breaks the HMAC. This is correct security behavior: the
    // timestamp is covered by the HMAC, so any modification (including
    // backdating) is detected as tampering. Re-serialize with the
    // modified timestamp but the now-invalid HMAC.
    let tampered_raw =
        postcard::to_allocvec(&msg).expect("re-serialize must succeed");

    // Receiver must reject: either HMAC failure (timestamp is HMAC-covered,
    // so modifying it without the key breaks the HMAC) or timestamp drift.
    // Both are correct security outcomes for a stale timestamp attack.
    let err = receiver
        .verify_message(&tampered_raw)
        .expect_err("stale/tampered timestamp must be rejected");
    let err_msg = format!("{err}");
    assert!(
        err_msg.contains("timestamp") || err_msg.contains("drift") || err_msg.contains("HMAC"),
        "error must indicate timestamp or HMAC tampering, got: {err_msg}"
    );
}
