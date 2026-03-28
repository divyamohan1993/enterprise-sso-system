use common::types::ModuleId;

#[test]
fn test_sequence_file_hmac_rejects_tampered() {
    let secret = [0x42u8; 64];
    let mut proto = shard::protocol::ShardProtocol::new(ModuleId::Gateway, secret);

    // Advance sequence by creating a message
    let _msg = proto.create_message(b"hello")
        .expect("create_message should succeed");

    let dir = std::env::temp_dir().join(format!("shard_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("shard_sequences.bin");

    // Export with HMAC
    proto.export_sequences_authenticated(&path, &secret)
        .expect("export should succeed");

    // Tamper with the file
    let mut data = std::fs::read(&path)
        .expect("should read file");
    assert!(!data.is_empty(), "exported file should not be empty");
    data[0] ^= 0xFF; // flip one byte
    std::fs::write(&path, &data).unwrap();

    // Import should fail
    let mut proto2 = shard::protocol::ShardProtocol::new(ModuleId::Gateway, secret);
    let result = proto2.import_sequences_authenticated(&path, &secret);
    assert!(
        result.is_err(),
        "tampered sequence file must be rejected, got: {:?}",
        result
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_sequence_file_hmac_accepts_valid() {
    let secret = [0x42u8; 64];
    let mut proto = shard::protocol::ShardProtocol::new(ModuleId::Gateway, secret);
    let _msg = proto.create_message(b"hello")
        .expect("create_message should succeed");

    let dir = std::env::temp_dir().join(format!("shard_test2_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("shard_sequences.bin");

    proto.export_sequences_authenticated(&path, &secret)
        .expect("export should succeed");

    let mut proto2 = shard::protocol::ShardProtocol::new(ModuleId::Gateway, secret);
    proto2.import_sequences_authenticated(&path, &secret)
        .expect("valid file must be accepted");

    assert!(
        proto2.send_sequence() >= 1,
        "imported send_sequence must be >= 1, got {}",
        proto2.send_sequence()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_sequence_file_wrong_key_rejected() {
    let secret = [0x42u8; 64];
    let wrong_key = [0x99u8; 64];
    let mut proto = shard::protocol::ShardProtocol::new(ModuleId::Gateway, secret);
    let _msg = proto.create_message(b"hello").unwrap();

    let dir = std::env::temp_dir().join(format!("shard_test3_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("shard_sequences.bin");

    proto.export_sequences_authenticated(&path, &secret).unwrap();

    let mut proto2 = shard::protocol::ShardProtocol::new(ModuleId::Gateway, secret);
    let result = proto2.import_sequences_authenticated(&path, &wrong_key);
    assert!(
        result.is_err(),
        "wrong HMAC key must cause rejection, got: {:?}",
        result
    );

    let _ = std::fs::remove_dir_all(&dir);
}
