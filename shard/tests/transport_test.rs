use common::types::ModuleId;
use shard::transport::{connect, ShardListener};

/// Shared HMAC key for tests.
fn test_key() -> [u8; 64] {
    [0xAB; 64]
}

#[tokio::test]
async fn transport_roundtrip() {
    let listener = ShardListener::bind("127.0.0.1:0", ModuleId::Verifier, test_key())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let handle = tokio::spawn(async move {
        let mut server = listener.accept().await.unwrap();
        server.recv().await.unwrap()
    });

    let mut client = connect(&addr, ModuleId::Gateway, test_key()).await.unwrap();
    client.send(b"hello shard").await.unwrap();

    let (sender, payload) = handle.await.unwrap();
    assert_eq!(sender, ModuleId::Gateway);
    assert_eq!(payload, b"hello shard");
}

#[tokio::test]
async fn transport_replay_rejected() {
    let listener = ShardListener::bind("127.0.0.1:0", ModuleId::Verifier, test_key())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    // Server side: receive the first message normally, then capture raw bytes
    // of a second message, and try to replay them on a new connection.
    let handle = tokio::spawn(async move {
        let mut server = listener.accept().await.unwrap();
        // First message — receive and verify (advances sequence to 1)
        let (sender, payload) = server.recv().await.unwrap();
        assert_eq!(sender, ModuleId::Gateway);
        assert_eq!(payload, b"legit message");

        // Second message — read raw bytes without verifying
        let raw = server.recv_raw().await.unwrap();

        // Third message — receive and verify (advances sequence to 3)
        let (_sender, _payload) = server.recv().await.unwrap();

        // Now replay the raw bytes of message 2 (sequence=2, but server
        // already saw sequence up to 3). This should fail replay detection.
        let result = server.protocol.verify_message(&raw);
        assert!(result.is_err(), "replay should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("replay"),
            "error should mention replay, got: {err}"
        );
    });

    let mut client = connect(&addr, ModuleId::Gateway, test_key()).await.unwrap();
    client.send(b"legit message").await.unwrap();
    client.send(b"message to replay").await.unwrap();
    client.send(b"third message").await.unwrap();

    handle.await.unwrap();
}

#[tokio::test]
async fn transport_multiple_messages() {
    let listener = ShardListener::bind("127.0.0.1:0", ModuleId::Orchestrator, test_key())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let handle = tokio::spawn(async move {
        let mut server = listener.accept().await.unwrap();
        let mut results = Vec::new();
        for _ in 0..5 {
            let (sender, payload) = server.recv().await.unwrap();
            results.push((sender, payload));
        }
        results
    });

    let mut client = connect(&addr, ModuleId::Gateway, test_key()).await.unwrap();
    for i in 0..5u8 {
        let msg = format!("message-{i}");
        client.send(msg.as_bytes()).await.unwrap();
    }

    let results = handle.await.unwrap();
    assert_eq!(results.len(), 5);
    for (i, (sender, payload)) in results.iter().enumerate() {
        assert_eq!(*sender, ModuleId::Gateway);
        assert_eq!(*payload, format!("message-{i}").as_bytes());
    }
}

#[tokio::test]
async fn transport_bidirectional() {
    let listener = ShardListener::bind("127.0.0.1:0", ModuleId::Verifier, test_key())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let server_handle = tokio::spawn(async move {
        let mut server = listener.accept().await.unwrap();

        // Receive from client
        let (sender, payload) = server.recv().await.unwrap();
        assert_eq!(sender, ModuleId::Gateway);
        assert_eq!(payload, b"ping");

        // Send back to client
        server.send(b"pong").await.unwrap();
    });

    let mut client = connect(&addr, ModuleId::Gateway, test_key()).await.unwrap();

    // Send to server
    client.send(b"ping").await.unwrap();

    // Receive from server
    let (sender, payload) = client.recv().await.unwrap();
    assert_eq!(sender, ModuleId::Verifier);
    assert_eq!(payload, b"pong");

    server_handle.await.unwrap();
}
