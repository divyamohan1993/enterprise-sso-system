//! TLS-wrapped async transport for SHARD messages.
//!
//! Same API and framing as [`crate::transport`] but runs over rustls TLS
//! instead of plain TCP.

use std::sync::Arc;

use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use common::error::MilnetError;
use common::types::ModuleId;

use crate::protocol::ShardProtocol;

/// Maximum SHARD frame payload size (16 MiB). Prevents allocation bombs.
const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Generic read/write helpers over AsyncRead + AsyncWrite
// ---------------------------------------------------------------------------

async fn send_on<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    protocol: &mut ShardProtocol,
    payload: &[u8],
) -> Result<(), MilnetError> {
    let msg = protocol.create_message(payload)?;
    let len = msg.len() as u32;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| MilnetError::Shard(format!("tls write length: {e}")))?;
    writer
        .write_all(&msg)
        .await
        .map_err(|e| MilnetError::Shard(format!("tls write payload: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| MilnetError::Shard(format!("tls flush: {e}")))?;
    Ok(())
}

async fn recv_on<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    protocol: &mut ShardProtocol,
) -> Result<(ModuleId, Vec<u8>), MilnetError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| MilnetError::Shard(format!("tls read length: {e}")))?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(MilnetError::Shard(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_LEN})"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| MilnetError::Shard(format!("tls read payload: {e}")))?;
    protocol.verify_message(&buf)
}

// ---------------------------------------------------------------------------
// Server-side TLS transport
// ---------------------------------------------------------------------------

/// A TLS transport wrapping the server side of a connection.
pub struct TlsShardTransport {
    stream: TlsTransportStream,
    pub protocol: ShardProtocol,
}

/// Unifies the server and client TLS stream types so that
/// `TlsShardTransport` can be used from either end.
enum TlsTransportStream {
    Server(ServerTlsStream<TcpStream>),
    Client(ClientTlsStream<TcpStream>),
}

impl TlsShardTransport {
    fn from_server(stream: ServerTlsStream<TcpStream>, protocol: ShardProtocol) -> Self {
        Self {
            stream: TlsTransportStream::Server(stream),
            protocol,
        }
    }

    fn from_client(stream: ClientTlsStream<TcpStream>, protocol: ShardProtocol) -> Self {
        Self {
            stream: TlsTransportStream::Client(stream),
            protocol,
        }
    }

    /// Send an authenticated SHARD message over TLS.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MilnetError> {
        match &mut self.stream {
            TlsTransportStream::Server(s) => send_on(s, &mut self.protocol, payload).await,
            TlsTransportStream::Client(s) => send_on(s, &mut self.protocol, payload).await,
        }
    }

    /// Receive and verify an authenticated SHARD message over TLS.
    pub async fn recv(&mut self) -> Result<(ModuleId, Vec<u8>), MilnetError> {
        match &mut self.stream {
            TlsTransportStream::Server(s) => recv_on(s, &mut self.protocol).await,
            TlsTransportStream::Client(s) => recv_on(s, &mut self.protocol).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

/// Accepts incoming TCP+TLS connections and wraps them in [`TlsShardTransport`].
pub struct TlsShardListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    module_id: ModuleId,
    hmac_key: [u8; 64],
}

impl TlsShardListener {
    /// Bind to the given address with TLS enabled.
    pub async fn bind(
        addr: &str,
        module_id: ModuleId,
        hmac_key: [u8; 64],
        tls_config: Arc<ServerConfig>,
    ) -> Result<Self, MilnetError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| MilnetError::Shard(format!("bind {addr}: {e}")))?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(tls_config),
            module_id,
            hmac_key,
        })
    }

    /// Return the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, MilnetError> {
        self.listener
            .local_addr()
            .map_err(|e| MilnetError::Shard(format!("local_addr: {e}")))
    }

    /// Accept a single inbound TLS connection and return a [`TlsShardTransport`].
    pub async fn accept(&self) -> Result<TlsShardTransport, MilnetError> {
        let (tcp_stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| MilnetError::Shard(format!("accept: {e}")))?;
        let tls_stream = self
            .acceptor
            .accept(tcp_stream)
            .await
            .map_err(|e| MilnetError::Shard(format!("tls accept: {e}")))?;
        let protocol = ShardProtocol::new(self.module_id, self.hmac_key);
        Ok(TlsShardTransport::from_server(tls_stream, protocol))
    }
}

// ---------------------------------------------------------------------------
// Client connect
// ---------------------------------------------------------------------------

/// Connect to a remote SHARD peer over TLS and return a [`TlsShardTransport`].
pub async fn tls_connect(
    addr: &str,
    module_id: ModuleId,
    hmac_key: [u8; 64],
    connector: &TlsConnector,
    server_name: &str,
) -> Result<TlsShardTransport, MilnetError> {
    let tcp_stream = TcpStream::connect(addr)
        .await
        .map_err(|e| MilnetError::Shard(format!("connect {addr}: {e}")))?;

    let dns_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| MilnetError::Shard(format!("invalid server name: {e}")))?;

    let tls_stream = connector
        .connect(dns_name, tcp_stream)
        .await
        .map_err(|e| MilnetError::Shard(format!("tls connect: {e}")))?;

    let protocol = ShardProtocol::new(module_id, hmac_key);
    Ok(TlsShardTransport::from_client(tls_stream, protocol))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{client_tls_config, generate_module_cert, server_tls_config, tls_connector};

    fn test_hmac_key() -> [u8; 64] {
        [0x42u8; 64]
    }

    #[tokio::test]
    async fn test_tls_shard_roundtrip() {
        let cert = generate_module_cert("localhost");
        let server_cfg = server_tls_config(&cert);
        let client_cfg = client_tls_config(&cert);

        let listener = TlsShardListener::bind(
            "127.0.0.1:0",
            ModuleId::Orchestrator,
            test_hmac_key(),
            server_cfg,
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();

        let connector = tls_connector(client_cfg);

        let server_handle = tokio::spawn(async move {
            let mut transport = listener.accept().await.unwrap();
            let (sender, payload) = transport.recv().await.unwrap();
            assert_eq!(sender, ModuleId::Gateway);
            assert_eq!(payload, b"hello over TLS");
            transport.send(b"ack").await.unwrap();
        });

        let mut client = tls_connect(
            &addr.to_string(),
            ModuleId::Gateway,
            test_hmac_key(),
            &connector,
            "localhost",
        )
        .await
        .unwrap();

        client.send(b"hello over TLS").await.unwrap();
        let (sender, payload) = client.recv().await.unwrap();
        assert_eq!(sender, ModuleId::Orchestrator);
        assert_eq!(payload, b"ack");

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tls_shard_rejects_plaintext_client() {
        let cert = generate_module_cert("localhost");
        let server_cfg = server_tls_config(&cert);

        let listener = TlsShardListener::bind(
            "127.0.0.1:0",
            ModuleId::Orchestrator,
            test_hmac_key(),
            server_cfg,
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a plain TCP client that sends garbage
        let client_handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            // Send plaintext (not a TLS ClientHello)
            let _ = stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await;
            let _ = stream.flush().await;
        });

        // The TLS accept should fail because the client did not perform a TLS handshake
        let result = listener.accept().await;
        assert!(result.is_err(), "TLS listener should reject plaintext client");

        client_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tls_multiple_messages() {
        let cert = generate_module_cert("localhost");
        let server_cfg = server_tls_config(&cert);
        let client_cfg = client_tls_config(&cert);

        let listener = TlsShardListener::bind(
            "127.0.0.1:0",
            ModuleId::Orchestrator,
            test_hmac_key(),
            server_cfg,
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();

        let connector = tls_connector(client_cfg);

        let server_handle = tokio::spawn(async move {
            let mut transport = listener.accept().await.unwrap();
            for i in 0u32..10 {
                let (sender, payload) = transport.recv().await.unwrap();
                assert_eq!(sender, ModuleId::Gateway);
                let expected = format!("message-{i}");
                assert_eq!(payload, expected.as_bytes());
                transport.send(format!("ack-{i}").as_bytes()).await.unwrap();
            }
        });

        let mut client = tls_connect(
            &addr.to_string(),
            ModuleId::Gateway,
            test_hmac_key(),
            &connector,
            "localhost",
        )
        .await
        .unwrap();

        for i in 0u32..10 {
            client
                .send(format!("message-{i}").as_bytes())
                .await
                .unwrap();
            let (sender, payload) = client.recv().await.unwrap();
            assert_eq!(sender, ModuleId::Orchestrator);
            let expected = format!("ack-{i}");
            assert_eq!(payload, expected.as_bytes());
        }

        server_handle.await.unwrap();
    }
}
