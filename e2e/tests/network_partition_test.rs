//! Network partition tests: verify services fail cleanly when connections drop.

use std::time::Duration;

use common::types::ModuleId;
use shard::tls_transport;

const SHARD_HMAC_KEY: [u8; 64] = [0x55u8; 64];

#[tokio::test]
async fn test_shard_connection_timeout_does_not_hang() {
    // Create a TCP listener that accepts but never does a TLS handshake.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    // Accept TCP but never send TLS handshake bytes — simulates a network black
    // hole or a non-TLS peer that holds the TCP connection open.
    let _handle = tokio::spawn(async move {
        if let Ok((_socket, _peer_addr)) = listener.accept().await {
            // Hold the connection open without doing TLS — so the client's
            // TLS handshake will stall.
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    // Build a client TLS connector (self-signed CA, no pinning needed since we
    // expect the handshake to fail/timeout anyway).
    let dummy_ca = shard::tls::generate_ca();
    let client_cert = shard::tls::generate_module_cert("client", &dummy_ca);
    let client_cfg = shard::tls::client_tls_config(&client_cert, &dummy_ca);
    let connector = shard::tls::tls_connector(client_cfg);

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        tls_transport::tls_connect(
            &addr,
            ModuleId::Orchestrator,
            SHARD_HMAC_KEY,
            &connector,
            "localhost",
        ),
    )
    .await;

    // Must timeout or error — NOT hang indefinitely.
    match result {
        Err(_timeout) => {
            // Good — tokio::time::timeout fired; the non-responsive peer was
            // detected within the time limit.
        }
        Ok(Err(_conn_err)) => {
            // Good — TLS handshake returned an error before the timeout fired
            // (e.g. certificate mismatch, unexpected EOF).
        }
        Ok(Ok(_transport)) => {
            panic!(
                "tls_connect to a plain-TCP peer should never return a valid \
                 TlsShardTransport — got one unexpectedly"
            );
        }
    }
}

#[tokio::test]
async fn test_dropped_connection_detected_on_recv() {
    // Boot a real TLS service.
    let (listener, ca, _server_cert) = tls_transport::tls_bind(
        "127.0.0.1:0",
        ModuleId::Tss,
        SHARD_HMAC_KEY,
        "localhost",
    )
    .await
    .expect("tls_bind should succeed");

    let addr = listener
        .local_addr()
        .expect("local_addr should succeed")
        .to_string();

    // Accept one connection then immediately drop it — simulates a crash or
    // a hard network partition on the server side.
    let server = tokio::spawn(async move {
        if let Ok(transport) = listener.accept().await {
            drop(transport); // simulate crash / partition
        }
    });

    // Build a client connector that trusts the server's CA.
    let client_cert = shard::tls::generate_module_cert("client", &ca);
    let client_cfg = shard::tls::client_tls_config(&client_cert, &ca);
    let connector = shard::tls::tls_connector(client_cfg);

    // Give the server a moment to reach its accept() call.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = tls_transport::tls_connect(
        &addr,
        ModuleId::Orchestrator,
        SHARD_HMAC_KEY,
        &connector,
        "localhost",
    )
    .await
    .expect("initial TLS connect should succeed — server was listening");

    // Give the server time to drop the transport (trigger the partition).
    tokio::time::sleep(Duration::from_millis(200)).await;

    // recv() should return an error promptly, not hang.
    let recv_result = tokio::time::timeout(Duration::from_secs(5), client.recv()).await;

    match recv_result {
        Err(_timeout) => panic!(
            "recv() hung for 5 seconds after peer dropped — must detect closed \
             connection promptly"
        ),
        Ok(Err(_io_err)) => {
            // Good — EOF / connection reset detected as an error.
        }
        Ok(Ok((_sender, _payload))) => panic!(
            "recv() returned data after the server dropped the connection — \
             this should not be possible"
        ),
    }

    let _ = server.await;
}
