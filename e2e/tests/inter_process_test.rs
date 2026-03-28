//! Inter-process integration tests with real mTLS connections.
//!
//! These tests boot full TLS listeners and connect real TlsShardTransport
//! pairs to verify end-to-end message framing, HMAC authentication, and
//! concurrent connection handling between module identities.

use std::time::Duration;

use common::types::ModuleId;
use shard::tls_transport;

const SHARD_HMAC_KEY: [u8; 64] = [0xAAu8; 64];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_real_mtls_connection_between_modules() {
    // Boot a TSS-like TLS service.
    let (listener, ca, _server_cert) = tls_transport::tls_bind(
        "127.0.0.1:0",
        ModuleId::Tss,
        SHARD_HMAC_KEY,
        "localhost",
    )
    .await
    .expect("tls_bind should succeed for TSS module");

    let addr = listener
        .local_addr()
        .expect("local_addr should succeed")
        .to_string();

    // Server: accept one connection, receive a message, echo it back.
    let server = tokio::spawn(async move {
        let mut transport = listener
            .accept()
            .await
            .expect("server accept should succeed");
        let (_sender, payload) = transport
            .recv()
            .await
            .expect("server recv should succeed — client sent a message");
        transport
            .send(&payload)
            .await
            .expect("server echo send should succeed");
    });

    // Build a client connector that trusts the server's CA.
    let client_cert = shard::tls::generate_module_cert("client", &ca);
    let client_cfg = shard::tls::client_tls_config(&client_cert, &ca);
    let connector = shard::tls::tls_connector(client_cfg);

    // Give the server a moment to reach accept().
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Client: connect as Orchestrator, send a payload, receive the echo.
    let mut client = tls_transport::tls_connect(
        &addr,
        ModuleId::Orchestrator,
        SHARD_HMAC_KEY,
        &connector,
        "localhost",
    )
    .await
    .expect("client TLS connect should succeed — server was listening");

    let test_payload: &[u8] = b"signing_request_payload_12345";
    client
        .send(test_payload)
        .await
        .expect("client send should succeed");

    let (_sender, response) = tokio::time::timeout(Duration::from_secs(5), client.recv())
        .await
        .expect("recv should not timeout within 5 seconds — server should echo promptly")
        .expect("recv should succeed — server echoed the payload");

    assert_eq!(
        response.as_ref(),
        test_payload,
        "echoed response must match the sent payload exactly: got {} bytes, expected {} bytes",
        response.len(),
        test_payload.len()
    );

    server
        .await
        .expect("server task should complete without panic");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_concurrent_mtls_connections() {
    const CLIENT_COUNT: usize = 3;

    // Boot a Verifier-like TLS service.
    let (listener, ca, _server_cert) = tls_transport::tls_bind(
        "127.0.0.1:0",
        ModuleId::Verifier,
        SHARD_HMAC_KEY,
        "localhost",
    )
    .await
    .expect("tls_bind should succeed for Verifier module");

    let addr = listener
        .local_addr()
        .expect("local_addr should succeed")
        .to_string();

    // Server: accept CLIENT_COUNT connections, each handled in its own task.
    let server = tokio::spawn(async move {
        for _ in 0..CLIENT_COUNT {
            match listener.accept().await {
                Ok(mut transport) => {
                    tokio::spawn(async move {
                        if let Ok((_sender, payload)) = transport.recv().await {
                            let _ = transport.send(&payload).await;
                        }
                    });
                }
                Err(e) => {
                    eprintln!("server accept error: {e}");
                }
            }
        }
    });

    // Build a shared client connector — all clients trust the same server CA.
    let client_cert = shard::tls::generate_module_cert("client", &ca);
    let client_cfg = shard::tls::client_tls_config(&client_cert, &ca);
    let connector = shard::tls::tls_connector(client_cfg);

    // Give the server a moment to reach accept().
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Launch CLIENT_COUNT concurrent client tasks.
    let mut handles = Vec::with_capacity(CLIENT_COUNT);
    for i in 0..CLIENT_COUNT {
        let addr_clone = addr.clone();
        let connector_clone = connector.clone();
        let handle = tokio::spawn(async move {
            let mut client = tls_transport::tls_connect(
                &addr_clone,
                ModuleId::Orchestrator,
                SHARD_HMAC_KEY,
                &connector_clone,
                "localhost",
            )
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "concurrent client {i} TLS connect should succeed, got error: {e}"
                )
            });

            // Each client sends a unique 32-byte pattern so we can detect cross-wiring.
            let msg = vec![i as u8; 32];
            client.send(&msg).await.unwrap_or_else(|e| {
                panic!("concurrent client {i} send should succeed, got error: {e}")
            });

            let (_sender, resp) = tokio::time::timeout(Duration::from_secs(5), client.recv())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "concurrent client {i} recv timed out after 5 seconds — \
                         server did not echo in time"
                    )
                })
                .unwrap_or_else(|e| {
                    panic!(
                        "concurrent client {i} recv returned an error: {e}"
                    )
                });

            assert_eq!(
                resp.as_ref(),
                msg.as_slice(),
                "client {i}: echoed response must match sent payload exactly — \
                 got {} bytes, expected {} bytes (possible cross-connection mixing)",
                resp.len(),
                msg.len()
            );
        });
        handles.push(handle);
    }

    for (i, h) in handles.into_iter().enumerate() {
        h.await.unwrap_or_else(|e| panic!("concurrent client {i} task panicked: {e}"));
    }

    server.abort();
}
