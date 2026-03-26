//! Async transport for SHARD messages with length-prefixed framing.
//!
//! Provides [`ShardTransport`] for sending/receiving authenticated SHARD
//! messages over TCP or mTLS, and [`ShardListener`] for accepting inbound
//! connections.
//!
//! **TLS enforcement**: mTLS with certificate pinning is ALWAYS required for
//! all inter-service communication, regardless of environment. Plain TCP is
//! permanently disabled.

use std::sync::Arc;

use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use common::error::MilnetError;
use common::types::ModuleId;

use crate::protocol::ShardProtocol;
use crate::tls::CertificatePinSet;

/// Maximum SHARD frame payload size (16 MiB). Prevents allocation bombs.
const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// Default timeout for SHARD transport recv operations (120 seconds).
/// Set higher to accommodate Argon2id KSF and sequential request processing
/// under concurrent load. Still prevents indefinite blocking (H9).
const SHARD_RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Default timeout for SHARD transport send operations (30 seconds).
const SHARD_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

// ---------------------------------------------------------------------------
// TLS enforcement
// ---------------------------------------------------------------------------

/// TLS is ALWAYS required for inter-service communication.
/// Plain TCP is no longer permitted in any deployment mode.
/// The MILNET_PRODUCTION env var check has been removed — mTLS
/// is mandatory regardless of environment to prevent accidental
/// plaintext traffic in any configuration.
pub fn require_tls() -> bool {
    true
}

// ---------------------------------------------------------------------------
// TLS configuration for transport layer
// ---------------------------------------------------------------------------

/// TLS configuration for the server (listener) side.
///
/// Wraps a [`TlsAcceptor`] with an optional [`CertificatePinSet`] and a
/// module identity map for post-handshake peer verification.
#[derive(Clone)]
pub struct ServerTlsConfig {
    acceptor: TlsAcceptor,
    pin_set: Option<CertificatePinSet>,
    /// Maps certificate SHA-256 fingerprints to expected `ModuleId` values.
    /// After TLS handshake, the peer certificate fingerprint is looked up
    /// in this map to verify the connecting module's identity.
    identity_map: Option<ModuleIdentityMap>,
}

/// TLS configuration for the client (connector) side.
///
/// Wraps a [`TlsConnector`] with an optional [`CertificatePinSet`] and a
/// module identity map for post-handshake peer verification.
#[derive(Clone)]
pub struct ClientTlsConfig {
    connector: TlsConnector,
    pin_set: Option<CertificatePinSet>,
    /// Maps certificate SHA-256 fingerprints to expected `ModuleId` values.
    identity_map: Option<ModuleIdentityMap>,
    /// The DNS name to use for the TLS handshake.
    server_name: String,
}

/// Maps certificate SHA-256 fingerprints to module identities.
///
/// Used for post-handshake verification: after the TLS connection is
/// established, the peer certificate's fingerprint is looked up in this map
/// to verify that the peer is the expected module.
#[derive(Clone, Debug)]
pub struct ModuleIdentityMap {
    entries: Vec<([u8; 32], ModuleId)>,
}

impl ModuleIdentityMap {
    /// Create a new empty identity map.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a module's certificate fingerprint.
    pub fn add(&mut self, fingerprint: [u8; 32], module_id: ModuleId) {
        self.entries.push((fingerprint, module_id));
    }

    /// Register a module's certificate (DER-encoded) by computing its fingerprint.
    pub fn add_cert_der(&mut self, cert_der: &[u8], module_id: ModuleId) {
        let fingerprint = crate::tls::compute_cert_fingerprint(cert_der);
        self.entries.push((fingerprint, module_id));
    }

    /// Look up the module identity for a given certificate fingerprint.
    pub fn lookup(&self, fingerprint: &[u8; 32]) -> Option<ModuleId> {
        self.entries
            .iter()
            .find(|(fp, _)| fp == fingerprint)
            .map(|(_, id)| *id)
    }

    /// Verify that a certificate (DER-encoded) belongs to the expected module.
    /// Returns the verified `ModuleId` or an error.
    pub fn verify_identity(
        &self,
        cert_der: &[u8],
        expected: Option<ModuleId>,
    ) -> Result<ModuleId, MilnetError> {
        let fingerprint = crate::tls::compute_cert_fingerprint(cert_der);
        let actual = self.lookup(&fingerprint).ok_or_else(|| {
            MilnetError::Shard(format!(
                "peer certificate fingerprint {:x?} not found in module identity map",
                &fingerprint[..8]
            ))
        })?;
        if let Some(expected_id) = expected {
            if actual != expected_id {
                return Err(MilnetError::Shard(format!(
                    "module identity mismatch: expected {expected_id:?}, got {actual:?}"
                )));
            }
        }
        Ok(actual)
    }
}

impl Default for ModuleIdentityMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerTlsConfig {
    /// Create a new server TLS config from a rustls `ServerConfig`.
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            acceptor: TlsAcceptor::from(config),
            pin_set: None,
            identity_map: None,
        }
    }

    /// Create a server TLS config with certificate pinning.
    pub fn with_pin_set(mut self, pin_set: CertificatePinSet) -> Self {
        self.pin_set = Some(pin_set);
        self
    }

    /// Create a server TLS config with module identity verification.
    pub fn with_identity_map(mut self, map: ModuleIdentityMap) -> Self {
        self.identity_map = Some(map);
        self
    }
}

impl ClientTlsConfig {
    /// Create a new client TLS config from a rustls `ClientConfig`.
    pub fn new(config: Arc<rustls::ClientConfig>, server_name: &str) -> Self {
        Self {
            connector: TlsConnector::from(config),
            pin_set: None,
            identity_map: None,
            server_name: server_name.to_string(),
        }
    }

    /// Create a client TLS config with certificate pinning.
    pub fn with_pin_set(mut self, pin_set: CertificatePinSet) -> Self {
        self.pin_set = Some(pin_set);
        self
    }

    /// Create a client TLS config with module identity verification.
    pub fn with_identity_map(mut self, map: ModuleIdentityMap) -> Self {
        self.identity_map = Some(map);
        self
    }
}

// ---------------------------------------------------------------------------
// Unified stream type
// ---------------------------------------------------------------------------

/// Unified stream that can be either a plain TCP connection or a TLS connection.
enum TransportStream {
    /// Plain TCP (test/development only).
    Plain {
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
    },
    /// TLS server-side (accepted connection).
    TlsServer(ServerTlsStream<TcpStream>),
    /// TLS client-side (outgoing connection).
    TlsClient(ClientTlsStream<TcpStream>),
}

// ---------------------------------------------------------------------------
// ShardTransport
// ---------------------------------------------------------------------------

/// A transport that sends and receives SHARD-authenticated messages
/// using 4-byte big-endian length-prefixed framing over either plain TCP
/// or mTLS.
pub struct ShardTransport {
    stream: TransportStream,
    /// The underlying SHARD protocol instance (public for advanced use cases
    /// such as offline verification of captured frames).
    pub protocol: ShardProtocol,
    /// The verified module identity of the peer (set after TLS handshake
    /// identity verification, if a `ModuleIdentityMap` was provided).
    peer_module: Option<ModuleId>,
}

impl ShardTransport {
    /// Wrap an already-connected plain TCP stream with a [`ShardProtocol`] instance.
    ///
    /// # Security warning
    /// Plain TCP is permanently disabled for security hardening.
    /// All inter-service communication MUST use mTLS with certificate pinning.
    /// This constructor logs a security violation error; prefer
    /// [`ShardTransport::connect_tls()`] instead.
    pub fn new(stream: TcpStream, protocol: ShardProtocol) -> Self {
        // Plain TCP is permanently disabled for security hardening.
        // All inter-service communication MUST use mTLS with certificate pinning.
        tracing::error!(
            "SECURITY: Plain TCP ShardTransport created — this is a security violation. \
             All inter-service communication must use mTLS."
        );
        let (reader, writer) = stream.into_split();
        Self {
            stream: TransportStream::Plain { reader, writer },
            protocol,
            peer_module: None,
        }
    }

    /// Wrap a TLS server stream with a [`ShardProtocol`] instance.
    fn from_tls_server(stream: ServerTlsStream<TcpStream>, protocol: ShardProtocol) -> Self {
        Self {
            stream: TransportStream::TlsServer(stream),
            protocol,
            peer_module: None,
        }
    }

    /// Wrap a TLS client stream with a [`ShardProtocol`] instance.
    fn from_tls_client(stream: ClientTlsStream<TcpStream>, protocol: ShardProtocol) -> Self {
        Self {
            stream: TransportStream::TlsClient(stream),
            protocol,
            peer_module: None,
        }
    }

    /// Set the verified peer module identity.
    fn set_peer_module(&mut self, module_id: ModuleId) {
        self.peer_module = Some(module_id);
    }

    /// Get the verified peer module identity, if available.
    ///
    /// This is only set when TLS is used with a `ModuleIdentityMap` and
    /// the peer certificate was successfully verified against it.
    pub fn peer_module(&self) -> Option<ModuleId> {
        self.peer_module
    }

    /// Returns `true` if this transport is using TLS.
    pub fn is_tls(&self) -> bool {
        !matches!(self.stream, TransportStream::Plain { .. })
    }

    /// Create an authenticated SHARD message from `payload`, frame it with a
    /// 4-byte big-endian length prefix, and write it to the stream.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MilnetError> {
        tokio::time::timeout(SHARD_SEND_TIMEOUT, self.send_inner(payload))
            .await
            .map_err(|_| MilnetError::Shard("SHARD send timed out after 30s".into()))?
    }

    async fn send_inner(&mut self, payload: &[u8]) -> Result<(), MilnetError> {
        let msg = self.protocol.create_message(payload)?;
        let len = msg.len() as u32;
        let len_bytes = len.to_be_bytes();

        match &mut self.stream {
            TransportStream::Plain { writer, .. } => {
                writer
                    .write_all(&len_bytes)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("write length: {e}")))?;
                writer
                    .write_all(&msg)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("write payload: {e}")))?;
                writer
                    .flush()
                    .await
                    .map_err(|e| MilnetError::Shard(format!("flush: {e}")))?;
            }
            TransportStream::TlsServer(s) => {
                s.write_all(&len_bytes)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls write length: {e}")))?;
                s.write_all(&msg)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls write payload: {e}")))?;
                s.flush()
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls flush: {e}")))?;
            }
            TransportStream::TlsClient(s) => {
                s.write_all(&len_bytes)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls write length: {e}")))?;
                s.write_all(&msg)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls write payload: {e}")))?;
                s.flush()
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls flush: {e}")))?;
            }
        }
        Ok(())
    }

    /// Read a length-prefixed frame from the stream, verify the SHARD
    /// authentication, and return `(sender_module, payload)`.
    pub async fn recv(&mut self) -> Result<(ModuleId, super::protocol::SecurePayload), MilnetError> {
        tokio::time::timeout(SHARD_RECV_TIMEOUT, self.recv_inner())
            .await
            .map_err(|_| MilnetError::Shard("SHARD recv timed out after 30s".into()))?
    }

    async fn recv_inner(&mut self) -> Result<(ModuleId, super::protocol::SecurePayload), MilnetError> {
        let mut len_buf = [0u8; 4];
        self.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_LEN {
            return Err(MilnetError::Shard(format!(
                "frame too large: {len} bytes (max {MAX_FRAME_LEN})"
            )));
        }
        let buf_len = usize::try_from(len)
            .map_err(|_| MilnetError::Shard("frame size overflows usize".to_string()))?;
        let mut buf = vec![0u8; buf_len];
        self.read_exact(&mut buf).await?;
        self.protocol.verify_message(&buf)
    }

    /// Read raw framed bytes from the stream without verification.
    /// Useful for testing replay scenarios.
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>, MilnetError> {
        let mut len_buf = [0u8; 4];
        self.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_LEN {
            return Err(MilnetError::Shard(format!(
                "frame too large: {len} bytes (max {MAX_FRAME_LEN})"
            )));
        }
        let buf_len = usize::try_from(len)
            .map_err(|_| MilnetError::Shard("frame size overflows usize".to_string()))?;
        let mut buf = vec![0u8; buf_len];
        self.read_exact(&mut buf).await?;
        Ok(buf)
    }

    /// Write raw pre-framed bytes to the stream (length prefix + payload).
    /// Useful for testing replay scenarios.
    pub async fn send_raw(&mut self, raw: &[u8]) -> Result<(), MilnetError> {
        let len = raw.len() as u32;
        let len_bytes = len.to_be_bytes();

        match &mut self.stream {
            TransportStream::Plain { writer, .. } => {
                writer
                    .write_all(&len_bytes)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("write length: {e}")))?;
                writer
                    .write_all(raw)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("write payload: {e}")))?;
                writer
                    .flush()
                    .await
                    .map_err(|e| MilnetError::Shard(format!("flush: {e}")))?;
            }
            TransportStream::TlsServer(s) => {
                s.write_all(&len_bytes)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls write length: {e}")))?;
                s.write_all(raw)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls write payload: {e}")))?;
                s.flush()
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls flush: {e}")))?;
            }
            TransportStream::TlsClient(s) => {
                s.write_all(&len_bytes)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls write length: {e}")))?;
                s.write_all(raw)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls write payload: {e}")))?;
                s.flush()
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls flush: {e}")))?;
            }
        }
        Ok(())
    }

    /// Internal helper: read exact bytes from the underlying stream.
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), MilnetError> {
        match &mut self.stream {
            TransportStream::Plain { reader, .. } => {
                reader
                    .read_exact(buf)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("read: {e}")))?;
            }
            TransportStream::TlsServer(s) => {
                s.read_exact(buf)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls read: {e}")))?;
            }
            TransportStream::TlsClient(s) => {
                s.read_exact(buf)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls read: {e}")))?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Server-side peer certificate extraction
// ---------------------------------------------------------------------------

/// Extract the first peer certificate (DER-encoded) from a TLS server stream.
fn extract_server_side_peer_cert(stream: &ServerTlsStream<TcpStream>) -> Option<Vec<u8>> {
    let (_, server_conn) = stream.get_ref();
    server_conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref().to_vec())
}

/// Extract the first peer certificate (DER-encoded) from a TLS client stream.
fn extract_client_side_peer_cert(stream: &ClientTlsStream<TcpStream>) -> Option<Vec<u8>> {
    let (_, client_conn) = stream.get_ref();
    client_conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref().to_vec())
}

/// Verify peer certificate pinning and module identity on a server-accepted TLS stream.
///
/// 1. If `pin_set` is provided, verifies the peer cert fingerprint is in the set.
/// 2. If `identity_map` is provided, verifies the peer cert maps to the expected module.
///
/// Returns the verified `ModuleId` (if identity map was used) or `None`.
fn verify_server_side_peer(
    stream: &ServerTlsStream<TcpStream>,
    pin_set: &Option<CertificatePinSet>,
    identity_map: &Option<ModuleIdentityMap>,
    expected_peer: Option<ModuleId>,
) -> Result<Option<ModuleId>, MilnetError> {
    let peer_cert_der = match extract_server_side_peer_cert(stream) {
        Some(der) => der,
        None => {
            // mTLS should always provide a peer cert, but if rustls config
            // doesn't require client auth this could be None.
            if pin_set.is_some() || identity_map.is_some() {
                return Err(MilnetError::Shard(
                    "no peer certificate presented but pinning/identity verification required"
                        .into(),
                ));
            }
            return Ok(None);
        }
    };

    // Certificate pinning check (on top of CA chain verification done by rustls).
    if let Some(ps) = pin_set {
        ps.verify_pin(&peer_cert_der).map_err(|e| {
            MilnetError::Shard(format!("post-handshake certificate pin check failed: {e}"))
        })?;
    }

    // Module identity verification.
    if let Some(map) = identity_map {
        let verified_id = map.verify_identity(&peer_cert_der, expected_peer)?;
        return Ok(Some(verified_id));
    }

    Ok(None)
}

/// Verify peer certificate pinning and module identity on a client TLS stream.
fn verify_client_side_peer(
    stream: &ClientTlsStream<TcpStream>,
    pin_set: &Option<CertificatePinSet>,
    identity_map: &Option<ModuleIdentityMap>,
    expected_peer: Option<ModuleId>,
) -> Result<Option<ModuleId>, MilnetError> {
    let peer_cert_der = match extract_client_side_peer_cert(stream) {
        Some(der) => der,
        None => {
            if pin_set.is_some() || identity_map.is_some() {
                return Err(MilnetError::Shard(
                    "no server certificate presented but pinning/identity verification required"
                        .into(),
                ));
            }
            return Ok(None);
        }
    };

    // Certificate pinning check.
    if let Some(ps) = pin_set {
        ps.verify_pin(&peer_cert_der).map_err(|e| {
            MilnetError::Shard(format!("post-handshake server certificate pin check failed: {e}"))
        })?;
    }

    // Module identity verification.
    if let Some(map) = identity_map {
        let verified_id = map.verify_identity(&peer_cert_der, expected_peer)?;
        return Ok(Some(verified_id));
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// ShardListener
// ---------------------------------------------------------------------------

/// Accepts incoming connections and wraps them in [`ShardTransport`].
///
/// In production mode (`MILNET_PRODUCTION` set), connections are always
/// accepted over mTLS. In development/test mode, plain TCP is permitted
/// when no TLS config is provided.
pub struct ShardListener {
    listener: TcpListener,
    module_id: ModuleId,
    hmac_key: [u8; 64],
    /// TLS configuration. `None` means plain TCP (only allowed outside production).
    tls_config: Option<ServerTlsConfig>,
}

impl ShardListener {
    /// Bind to the given address and prepare to accept SHARD connections.
    ///
    /// This always returns an error because plain TCP is permanently disabled.
    /// Use [`ShardListener::tls_bind`] instead, or provide a `ServerTlsConfig`
    /// via [`ShardListener::bind_with_optional_tls`].
    pub async fn bind(
        addr: &str,
        module_id: ModuleId,
        hmac_key: [u8; 64],
    ) -> Result<Self, MilnetError> {
        if require_tls() {
            return Err(MilnetError::Shard(
                "Plain TCP bind permanently disabled — all inter-service \
                 communication requires mTLS. Use ShardListener::tls_bind()."
                    .into(),
            ));
        }
        eprintln!(
            "WARNING: ShardListener binding without TLS on {addr} (module {:?}). \
             Non-TLS connections are only safe for testing.",
            module_id
        );
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| MilnetError::Shard(format!("bind {addr}: {e}")))?;
        Ok(Self {
            listener,
            module_id,
            hmac_key,
            tls_config: None,
        })
    }

    /// Bind to the given address with mandatory mTLS.
    ///
    /// All accepted connections will be TLS-wrapped with mutual certificate
    /// verification, optional certificate pinning, and optional module identity
    /// verification.
    pub async fn tls_bind(
        addr: &str,
        module_id: ModuleId,
        hmac_key: [u8; 64],
        tls_config: ServerTlsConfig,
    ) -> Result<Self, MilnetError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| MilnetError::Shard(format!("tls bind {addr}: {e}")))?;
        Ok(Self {
            listener,
            module_id,
            hmac_key,
            tls_config: Some(tls_config),
        })
    }

    /// Bind with optional TLS. If `tls_config` is `Some`, use mTLS.
    /// If `None`, fall back to plain TCP (forbidden in production).
    pub async fn bind_with_optional_tls(
        addr: &str,
        module_id: ModuleId,
        hmac_key: [u8; 64],
        tls_config: Option<ServerTlsConfig>,
    ) -> Result<Self, MilnetError> {
        match tls_config {
            Some(cfg) => Self::tls_bind(addr, module_id, hmac_key, cfg).await,
            None => Self::bind(addr, module_id, hmac_key).await,
        }
    }

    /// Return the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, MilnetError> {
        self.listener
            .local_addr()
            .map_err(|e| MilnetError::Shard(format!("local_addr: {e}")))
    }

    /// Returns `true` if this listener is configured with TLS.
    pub fn is_tls(&self) -> bool {
        self.tls_config.is_some()
    }

    /// Accept a single inbound connection and return a [`ShardTransport`].
    ///
    /// If TLS is configured, the connection is accepted over mTLS with
    /// certificate pinning and module identity verification (if configured).
    /// If TLS is not configured (test mode only), accepts a plain TCP connection.
    pub async fn accept(&self) -> Result<ShardTransport, MilnetError> {
        let (tcp_stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| MilnetError::Shard(format!("accept: {e}")))?;

        match &self.tls_config {
            Some(cfg) => {
                let tls_stream = cfg
                    .acceptor
                    .accept(tcp_stream)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls accept: {e}")))?;

                // Post-handshake: verify peer certificate pinning and module identity.
                let peer_module = verify_server_side_peer(
                    &tls_stream,
                    &cfg.pin_set,
                    &cfg.identity_map,
                    None,
                )?;

                let protocol = ShardProtocol::new(self.module_id, self.hmac_key);
                let mut transport = ShardTransport::from_tls_server(tls_stream, protocol);
                if let Some(module_id) = peer_module {
                    transport.set_peer_module(module_id);
                }
                Ok(transport)
            }
            None => {
                let protocol = ShardProtocol::new(self.module_id, self.hmac_key);
                Ok(ShardTransport::new(tcp_stream, protocol))
            }
        }
    }

    /// Accept a single inbound connection with communication matrix enforcement.
    ///
    /// Validates that `sender_module` is permitted to communicate with this
    /// listener's module before returning the transport. If TLS with an identity
    /// map is configured, also verifies that the peer certificate matches the
    /// expected sender module.
    pub async fn accept_checked(
        &self,
        sender_module: ModuleId,
    ) -> Result<ShardTransport, MilnetError> {
        common::network::enforce_channel(sender_module, self.module_id).map_err(|e| {
            MilnetError::Shard(format!(
                "channel {sender_module:?} -> {:?} denied: {e}",
                self.module_id
            ))
        })?;

        let (tcp_stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| MilnetError::Shard(format!("accept: {e}")))?;

        match &self.tls_config {
            Some(cfg) => {
                let tls_stream = cfg
                    .acceptor
                    .accept(tcp_stream)
                    .await
                    .map_err(|e| MilnetError::Shard(format!("tls accept: {e}")))?;

                // Post-handshake: verify peer identity matches the expected sender.
                let peer_module = verify_server_side_peer(
                    &tls_stream,
                    &cfg.pin_set,
                    &cfg.identity_map,
                    Some(sender_module),
                )?;

                let protocol = ShardProtocol::new(self.module_id, self.hmac_key);
                let mut transport = ShardTransport::from_tls_server(tls_stream, protocol);
                if let Some(module_id) = peer_module {
                    transport.set_peer_module(module_id);
                }
                Ok(transport)
            }
            None => {
                let protocol = ShardProtocol::new(self.module_id, self.hmac_key);
                Ok(ShardTransport::new(tcp_stream, protocol))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Client connect functions
// ---------------------------------------------------------------------------

/// Connect to a remote SHARD peer over plain TCP and return a [`ShardTransport`].
///
/// In production mode (`MILNET_PRODUCTION` set), this returns an error
/// because TLS is mandatory. Use [`tls_connect`] instead.
///
/// Validates the communication channel against the module communication
/// matrix before establishing the connection. `module_id` is the local
/// (sender) module; `peer_module` is the remote (receiver) module.
pub async fn connect(
    addr: &str,
    module_id: ModuleId,
    hmac_key: [u8; 64],
) -> Result<ShardTransport, MilnetError> {
    if require_tls() {
        return Err(MilnetError::Shard(
            "MILNET_PRODUCTION is set: plain TCP connect refused. \
             Use tls_connect() for mTLS connections."
                .into(),
        ));
    }
    eprintln!(
        "WARNING: Plain TCP SHARD connection to {addr} (module {:?}). \
         Non-TLS connections are only safe for testing.",
        module_id
    );
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| MilnetError::Shard(format!("connect {addr}: {e}")))?;
    let protocol = ShardProtocol::new(module_id, hmac_key);
    Ok(ShardTransport::new(stream, protocol))
}

/// Connect to a remote SHARD peer over mTLS and return a [`ShardTransport`].
///
/// Performs TLS handshake, then verifies the server certificate against the
/// pin set and module identity map (if configured).
pub async fn tls_connect(
    addr: &str,
    module_id: ModuleId,
    hmac_key: [u8; 64],
    tls_config: &ClientTlsConfig,
) -> Result<ShardTransport, MilnetError> {
    tls_connect_expecting(addr, module_id, hmac_key, tls_config, None).await
}

/// Connect to a remote SHARD peer over mTLS, verifying the server is the expected module.
///
/// Like [`tls_connect`], but additionally verifies that the server certificate
/// maps to `expected_peer` in the identity map.
pub async fn tls_connect_expecting(
    addr: &str,
    module_id: ModuleId,
    hmac_key: [u8; 64],
    tls_config: &ClientTlsConfig,
    expected_peer: Option<ModuleId>,
) -> Result<ShardTransport, MilnetError> {
    let tcp_stream = TcpStream::connect(addr)
        .await
        .map_err(|e| MilnetError::Shard(format!("connect {addr}: {e}")))?;

    let dns_name =
        rustls::pki_types::ServerName::try_from(tls_config.server_name.clone())
            .map_err(|e| MilnetError::Shard(format!("invalid server name: {e}")))?;

    let tls_stream = tls_config
        .connector
        .connect(dns_name, tcp_stream)
        .await
        .map_err(|e| MilnetError::Shard(format!("tls connect: {e}")))?;

    // Post-handshake: verify server certificate pinning and module identity.
    let peer_module = verify_client_side_peer(
        &tls_stream,
        &tls_config.pin_set,
        &tls_config.identity_map,
        expected_peer,
    )?;

    let protocol = ShardProtocol::new(module_id, hmac_key);
    let mut transport = ShardTransport::from_tls_client(tls_stream, protocol);
    if let Some(mid) = peer_module {
        transport.set_peer_module(mid);
    }
    Ok(transport)
}

/// Connect to a remote SHARD peer with communication matrix enforcement.
///
/// Like [`connect`], but additionally validates that `sender_module` is
/// permitted to communicate with `receiver_module` per the module
/// communication matrix before establishing the TCP connection.
///
/// In production mode, returns an error (use [`tls_connect_checked`] instead).
pub async fn connect_checked(
    addr: &str,
    sender_module: ModuleId,
    receiver_module: ModuleId,
    hmac_key: [u8; 64],
) -> Result<ShardTransport, MilnetError> {
    common::network::enforce_channel(sender_module, receiver_module).map_err(|e| {
        MilnetError::Shard(format!(
            "channel {sender_module:?} -> {receiver_module:?} denied: {e}"
        ))
    })?;
    connect(addr, sender_module, hmac_key).await
}

/// Connect to a remote SHARD peer over mTLS with communication matrix enforcement.
///
/// Validates the communication matrix, establishes mTLS, verifies certificate
/// pinning and module identity, then returns the transport.
pub async fn tls_connect_checked(
    addr: &str,
    sender_module: ModuleId,
    receiver_module: ModuleId,
    hmac_key: [u8; 64],
    tls_config: &ClientTlsConfig,
) -> Result<ShardTransport, MilnetError> {
    common::network::enforce_channel(sender_module, receiver_module).map_err(|e| {
        MilnetError::Shard(format!(
            "channel {sender_module:?} -> {receiver_module:?} denied: {e}"
        ))
    })?;
    tls_connect_expecting(addr, sender_module, hmac_key, tls_config, Some(receiver_module)).await
}

/// Connect with TLS if available, otherwise fall back to plain TCP (test only).
///
/// In production mode, `tls_config` must be `Some` or an error is returned.
pub async fn connect_auto(
    addr: &str,
    module_id: ModuleId,
    hmac_key: [u8; 64],
    tls_config: Option<&ClientTlsConfig>,
) -> Result<ShardTransport, MilnetError> {
    match tls_config {
        Some(cfg) => tls_connect(addr, module_id, hmac_key, cfg).await,
        None => connect(addr, module_id, hmac_key).await,
    }
}
