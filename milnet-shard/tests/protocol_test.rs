use milnet_common::types::ModuleId;
use milnet_shard::protocol::ShardProtocol;

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
