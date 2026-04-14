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

// ---------------------------------------------------------------------------
// C10: App-layer PQ key exchange + double-AEAD
//
// Rationale: the underlying TLS session may use classical X25519 key
// exchange (where `tls_pq_level5` is disabled). Even if today's session
// survives, an adversary who records traffic and later recovers the X25519
// shared secret (harvest-now-decrypt-later) would then recover every
// SHARD payload. We defeat that by running a SECOND key exchange *inside*
// the established TLS session using X-Wing (X25519 + ML-KEM-1024 hybrid)
// and re-encrypting each SHARD payload with AES-256-GCM under the resulting
// session key. The pubkey used for X-Wing is pinned to the mTLS peer
// certificate's SHA-512 fingerprint to block key-substitution attacks.
// ---------------------------------------------------------------------------

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

/// Session state for the app-layer PQ layer. Holds the AEAD key and a
/// monotonically increasing nonce counter.
pub struct PqSessionState {
    aead_key: [u8; 32],
    send_counter: u64,
    recv_counter: u64,
    /// SHA-512 fingerprint of the mTLS peer certificate we bound to.
    peer_cert_fp: [u8; 64],
}

impl PqSessionState {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, MilnetError> {
        let counter = self.send_counter;
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or_else(|| MilnetError::Shard("PQ session counter overflow".into()))?;
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        let cipher = Aes256Gcm::new_from_slice(&self.aead_key)
            .map_err(|e| MilnetError::Shard(format!("AES key: {e}")))?;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| MilnetError::Shard("PQ outer encrypt failed".into()))?;
        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn decrypt(&mut self, blob: &[u8]) -> Result<Vec<u8>, MilnetError> {
        if blob.len() < 8 {
            return Err(MilnetError::Shard("PQ blob too short".into()));
        }
        let counter = u64::from_be_bytes(blob[..8].try_into().unwrap());
        if counter <= self.recv_counter && self.recv_counter != 0 {
            return Err(MilnetError::Shard(format!(
                "PQ replay detected: counter {counter} <= last {}",
                self.recv_counter
            )));
        }
        self.recv_counter = counter;
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        let cipher = Aes256Gcm::new_from_slice(&self.aead_key)
            .map_err(|e| MilnetError::Shard(format!("AES key: {e}")))?;
        cipher
            .decrypt(Nonce::from_slice(&nonce), &blob[8..])
            .map_err(|_| MilnetError::Shard("PQ outer decrypt failed".into()))
    }
}

impl Drop for PqSessionState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.aead_key.zeroize();
    }
}

/// Derive the app-layer AEAD key from the X-Wing shared secret AND the
/// pinned mTLS peer certificate fingerprint. Pinning the KDF input to the
/// cert fingerprint defeats attacks where an adversary substitutes a
/// different X-Wing public key during the handshake.
fn derive_pq_session_key(
    xwing_shared: &[u8],
    peer_cert_fp: &[u8; 64],
) -> Result<[u8; 32], MilnetError> {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-SHARD-PQ-APPLAYER-v1"), xwing_shared);
    let mut okm = [0u8; 32];
    hk.expand(peer_cert_fp, &mut okm)
        .map_err(|e| MilnetError::Shard(format!("HKDF: {e}")))?;
    Ok(okm)
}

/// Maximum SHARD frame payload size (16 MiB). Accommodates ML-DSA-87 signatures,
/// FROST threshold shares, OPAQUE ceremony payloads, and concurrent e2e flows.
const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// Timeout for a single recv operation. Prevents slowloris attacks where an
/// attacker sends 1 byte/minute to hold connection slots indefinitely.
const SHARD_TLS_RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
) -> Result<(ModuleId, super::protocol::SecurePayload), MilnetError> {
    // Wrap entire recv in timeout to prevent slowloris attacks.
    tokio::time::timeout(SHARD_TLS_RECV_TIMEOUT, recv_on_inner(reader, protocol))
        .await
        .map_err(|_| MilnetError::Shard("SHARD TLS recv timed out after 30s".into()))?
}

async fn recv_on_inner<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    protocol: &mut ShardProtocol,
) -> Result<(ModuleId, super::protocol::SecurePayload), MilnetError> {
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
    let buf_len = usize::try_from(len).map_err(|_| MilnetError::Shard("frame size overflows usize".to_string()))?;
    let mut buf = vec![0u8; buf_len];
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
    /// C10: optional app-layer PQ session established AFTER the mTLS handshake.
    /// When present, `send_pq`/`recv_pq` double-encrypt payloads under a
    /// X-Wing-derived key bound to the peer cert fingerprint.
    pq_session: Option<PqSessionState>,
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
            pq_session: None,
        }
    }

    fn from_client(stream: ClientTlsStream<TcpStream>, protocol: ShardProtocol) -> Self {
        Self {
            stream: TlsTransportStream::Client(stream),
            protocol,
            pq_session: None,
        }
    }

    /// C10: Install an app-layer PQ session state (derived from a prior
    /// [`crypto::xwing`] exchange). `peer_cert_fp` must be the SHA-512
    /// fingerprint of the mTLS peer certificate used during the handshake;
    /// pinning here defeats X-Wing public-key substitution.
    pub fn install_pq_session(
        &mut self,
        xwing_shared_secret: &[u8],
        peer_cert_fp: [u8; 64],
    ) -> Result<(), MilnetError> {
        let aead_key = derive_pq_session_key(xwing_shared_secret, &peer_cert_fp)?;
        self.pq_session = Some(PqSessionState {
            aead_key,
            send_counter: 0,
            recv_counter: 0,
            peer_cert_fp,
        });
        tracing::info!(
            "C10: installed app-layer PQ session (X-Wing-derived AEAD) bound to peer cert fingerprint"
        );
        Ok(())
    }

    /// C10: Return a reference to the installed PQ session fingerprint, if any.
    pub fn pq_peer_fingerprint(&self) -> Option<&[u8; 64]> {
        self.pq_session.as_ref().map(|s| &s.peer_cert_fp)
    }

    /// C10: Send a payload with the full double-AEAD wrapping. The outer
    /// AEAD is the installed PQ session key; the inner is the existing
    /// SHARD AEAD. Falls back to [`Self::send`] if no PQ session is installed
    /// (documented harvest-now-decrypt-later hole in that configuration).
    pub async fn send_pq(&mut self, payload: &[u8]) -> Result<(), MilnetError> {
        if let Some(ref mut pq) = self.pq_session {
            let outer = pq.encrypt(payload)?;
            self.send_inner(&outer).await
        } else {
            tracing::warn!(
                "C10: send_pq called without installed PQ session — falling back to single-layer AEAD"
            );
            self.send_inner(payload).await
        }
    }

    /// C10: Receive and unwrap both AEAD layers.
    pub async fn recv_pq(
        &mut self,
    ) -> Result<(ModuleId, Vec<u8>), MilnetError> {
        let (sender, inner_payload) = self.recv_inner().await?;
        let bytes: Vec<u8> = inner_payload.0.clone();
        if let Some(ref mut pq) = self.pq_session {
            let plaintext = pq.decrypt(&bytes)?;
            Ok((sender, plaintext))
        } else {
            Ok((sender, bytes))
        }
    }

    async fn send_inner(&mut self, payload: &[u8]) -> Result<(), MilnetError> {
        match &mut self.stream {
            TlsTransportStream::Server(s) => send_on(s, &mut self.protocol, payload).await,
            TlsTransportStream::Client(s) => send_on(s, &mut self.protocol, payload).await,
        }
    }

    async fn recv_inner(
        &mut self,
    ) -> Result<(ModuleId, super::protocol::SecurePayload), MilnetError> {
        match &mut self.stream {
            TlsTransportStream::Server(s) => recv_on(s, &mut self.protocol).await,
            TlsTransportStream::Client(s) => recv_on(s, &mut self.protocol).await,
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
    pub async fn recv(&mut self) -> Result<(ModuleId, super::protocol::SecurePayload), MilnetError> {
        match &mut self.stream {
            TlsTransportStream::Server(s) => recv_on(s, &mut self.protocol).await,
            TlsTransportStream::Client(s) => recv_on(s, &mut self.protocol).await,
        }
    }

    /// Read raw framed bytes from the TLS stream without verification.
    /// Restricted to crate-internal use to prevent bypassing SHARD authentication.
    /// Available externally only with `test-internals` feature for integration tests.
    #[cfg_attr(not(feature = "test-internals"), doc(hidden))]
    #[cfg(feature = "test-internals")]
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>, MilnetError> {
        let mut len_buf = [0u8; 4];
        match &mut self.stream {
            TlsTransportStream::Server(s) => s.read_exact(&mut len_buf).await,
            TlsTransportStream::Client(s) => s.read_exact(&mut len_buf).await,
        }
        .map_err(|e| MilnetError::Shard(format!("tls read length: {e}")))?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_LEN {
            return Err(MilnetError::Shard(format!(
                "frame too large: {len} bytes (max {MAX_FRAME_LEN})"
            )));
        }
        let buf_len = usize::try_from(len).map_err(|_| MilnetError::Shard("frame size overflows usize".to_string()))?;
        let mut buf = vec![0u8; buf_len];
        match &mut self.stream {
            TlsTransportStream::Server(s) => s.read_exact(&mut buf).await,
            TlsTransportStream::Client(s) => s.read_exact(&mut buf).await,
        }
        .map_err(|e| MilnetError::Shard(format!("tls read payload: {e}")))?;
        Ok(buf)
    }

    /// Write raw pre-framed bytes to the TLS stream (length prefix + payload).
    /// Restricted to crate-internal use to prevent bypassing SHARD authentication.
    /// Available externally only with `test-internals` feature for integration tests.
    #[cfg_attr(not(feature = "test-internals"), doc(hidden))]
    #[cfg(feature = "test-internals")]
    pub async fn send_raw(&mut self, raw: &[u8]) -> Result<(), MilnetError> {
        let len = raw.len() as u32;
        match &mut self.stream {
            TlsTransportStream::Server(s) => {
                s.write_all(&len.to_be_bytes()).await
                    .map_err(|e| MilnetError::Shard(format!("tls write length: {e}")))?;
                s.write_all(raw).await
                    .map_err(|e| MilnetError::Shard(format!("tls write payload: {e}")))?;
                s.flush().await
                    .map_err(|e| MilnetError::Shard(format!("tls flush: {e}")))?;
            }
            TlsTransportStream::Client(s) => {
                s.write_all(&len.to_be_bytes()).await
                    .map_err(|e| MilnetError::Shard(format!("tls write length: {e}")))?;
                s.write_all(raw).await
                    .map_err(|e| MilnetError::Shard(format!("tls write payload: {e}")))?;
                s.flush().await
                    .map_err(|e| MilnetError::Shard(format!("tls flush: {e}")))?;
            }
        }
        Ok(())
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
// Convenience helpers
// ---------------------------------------------------------------------------

/// Ensure the rustls crypto provider is installed (idempotent).
fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Create a TLS-enabled SHARD listener for the given module with mTLS.
///
/// Generates a self-signed CA and module certificate at startup. The server
/// enforces mutual TLS (client must present a valid certificate signed by the
/// CA). For additional certificate pinning, use [`tls_bind_pinned`].
///
/// Returns (listener, ca, cert_key) for the caller to share the CA with clients.
pub async fn tls_bind(
    addr: &str,
    module_id: ModuleId,
    hmac_key: [u8; 64],
    module_name: &str,
) -> Result<(TlsShardListener, crate::tls::CertificateAuthority, rcgen::CertifiedKey), common::error::MilnetError> {
    ensure_crypto_provider();
    let ca = crate::tls::generate_ca();
    let cert_key = crate::tls::generate_module_cert(module_name, &ca);

    // Use mTLS with CA chain verification. For explicit certificate pinning
    // (defense against CA compromise), use tls_bind_pinned() with a known
    // set of peer certificate fingerprints.
    let server_config = crate::tls::server_tls_config(&cert_key, &ca);

    tracing::warn!(
        module = module_name,
        "mTLS without explicit certificate pinning — consider tls_bind_pinned() for CA compromise defense"
    );

    let listener = TlsShardListener::bind(addr, module_id, hmac_key, server_config).await?;
    Ok((listener, ca, cert_key))
}

/// Create a TLS connector for a client module with mTLS.
///
/// Generates its own CA and certificate. For additional certificate pinning,
/// use [`tls_client_setup_pinned`].
///
/// Returns (connector, ca, cert_key) so the caller can share the CA with servers.
pub fn tls_client_setup(
    module_name: &str,
) -> (TlsConnector, crate::tls::CertificateAuthority, rcgen::CertifiedKey) {
    ensure_crypto_provider();
    let ca = crate::tls::generate_ca();
    let cert_key = crate::tls::generate_module_cert(module_name, &ca);
    let client_config = crate::tls::client_tls_config(&cert_key, &ca);
    let connector = crate::tls::tls_connector(client_config);
    (connector, ca, cert_key)
}

/// Create a TLS-enabled SHARD listener with certificate pinning.
///
/// Like [`tls_bind`] but enforces that connecting clients present a certificate
/// whose SHA-256 fingerprint is in `pin_set`.
pub async fn tls_bind_pinned(
    addr: &str,
    module_id: ModuleId,
    hmac_key: [u8; 64],
    module_name: &str,
    pin_set: crate::tls::CertificatePinSet,
) -> Result<(TlsShardListener, crate::tls::CertificateAuthority, rcgen::CertifiedKey), common::error::MilnetError> {
    ensure_crypto_provider();
    let ca = crate::tls::generate_ca();
    let cert_key = crate::tls::generate_module_cert(module_name, &ca);
    let server_config = crate::tls::server_tls_config_pinned(&cert_key, &ca, pin_set);
    let listener = TlsShardListener::bind(addr, module_id, hmac_key, server_config).await?;
    Ok((listener, ca, cert_key))
}

/// Create a TLS connector for a client module with certificate pinning.
///
/// Like [`tls_client_setup`] but enforces that the server presents a certificate
/// whose SHA-256 fingerprint is in `pin_set`.
pub fn tls_client_setup_pinned(
    module_name: &str,
    pin_set: crate::tls::CertificatePinSet,
) -> (TlsConnector, crate::tls::CertificateAuthority, rcgen::CertifiedKey) {
    ensure_crypto_provider();
    let ca = crate::tls::generate_ca();
    let cert_key = crate::tls::generate_module_cert(module_name, &ca);
    let client_config = crate::tls::client_tls_config_pinned(&cert_key, &ca, pin_set);
    let connector = crate::tls::tls_connector(client_config);
    (connector, ca, cert_key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{
        build_pin_set_from_certs, client_tls_config, client_tls_config_pinned,
        generate_ca, generate_module_cert, server_tls_config,
        server_tls_config_pinned, tls_connector, CertificatePinSet,
    };

    fn test_hmac_key() -> [u8; 64] {
        [0x42u8; 64]
    }

    #[tokio::test]
    async fn test_tls_shard_roundtrip() {
        let ca = generate_ca();
        let server_cert = generate_module_cert("localhost", &ca);
        let client_cert = generate_module_cert("client", &ca);
        let server_cfg = server_tls_config(&server_cert, &ca);
        let client_cfg = client_tls_config(&client_cert, &ca);

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
        let ca = generate_ca();
        let cert = generate_module_cert("localhost", &ca);
        let server_cfg = server_tls_config(&cert, &ca);

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
        let ca = generate_ca();
        let server_cert = generate_module_cert("localhost", &ca);
        let client_cert = generate_module_cert("client", &ca);
        let server_cfg = server_tls_config(&server_cert, &ca);
        let client_cfg = client_tls_config(&client_cert, &ca);

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

    #[tokio::test]
    async fn test_tls_pinned_roundtrip() {
        // Generate shared CA and certs.
        let ca = generate_ca();
        let server_cert = generate_module_cert("localhost", &ca);
        let client_cert = generate_module_cert("client", &ca);

        // Build pin set from both certs.
        let pin_set = build_pin_set_from_certs(&[&server_cert, &client_cert]);

        let server_cfg = server_tls_config_pinned(&server_cert, &ca, pin_set.clone());
        let client_cfg = client_tls_config_pinned(&client_cert, &ca, pin_set);

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
            assert_eq!(payload, b"pinned hello");
            transport.send(b"pinned ack").await.unwrap();
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

        client.send(b"pinned hello").await.unwrap();
        let (sender, payload) = client.recv().await.unwrap();
        assert_eq!(sender, ModuleId::Orchestrator);
        assert_eq!(payload, b"pinned ack");

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tls_pinned_rejects_unpinned_client() {
        // Generate shared CA and certs.
        let ca = generate_ca();
        let server_cert = generate_module_cert("localhost", &ca);
        let client_cert = generate_module_cert("client", &ca);

        // Pin set contains ONLY the server cert — client is not pinned.
        let mut server_pin_set = CertificatePinSet::new();
        server_pin_set.add_certificate(server_cert.cert.der().as_ref());

        // Client-side pin set has the server cert so it will accept the server.
        let mut client_pin_set = CertificatePinSet::new();
        client_pin_set.add_certificate(server_cert.cert.der().as_ref());

        let server_cfg = server_tls_config_pinned(&server_cert, &ca, server_pin_set);
        let client_cfg = client_tls_config_pinned(&client_cert, &ca, client_pin_set);

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
            // The accept should fail because the client cert is not in the server's pin set.
            let result = listener.accept().await;
            assert!(result.is_err(), "server should reject unpinned client certificate");
        });

        // The client connect may succeed or fail depending on handshake ordering,
        // but the overall exchange should not complete successfully.
        let _client_result = tls_connect(
            &addr.to_string(),
            ModuleId::Gateway,
            test_hmac_key(),
            &connector,
            "localhost",
        )
        .await;

        server_handle.await.unwrap();
    }
}
