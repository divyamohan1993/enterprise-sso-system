//! Bastion Gateway TCP server.
//!
//! Accepts client connections, issues a hash puzzle challenge, verifies
//! the solution, reads an authentication request, and forwards to the
//! orchestrator via SHARD for real authentication.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn, debug};

use common::types::ModuleId;
use shard::tls_transport::tls_connect;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::distributed_rate_limit::DistributedRateLimiter;
use crate::puzzle::{generate_challenge, get_adaptive_difficulty, verify_solution, PuzzleSolution};
use crate::wire::{AuthRequest, AuthResponse, OrchestratorRequest, OrchestratorResponse};

/// Maximum wire frame payload size (1 MiB) — absolute upper bound.
const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// Per-endpoint request size limits.
/// Auth and token endpoints use a tighter limit to prevent abuse.
/// Admin endpoints allow larger payloads for bulk operations.
pub const MAX_AUTH_REQUEST_SIZE: u32 = 16 * 1024;      // 16 KiB
pub const MAX_TOKEN_REQUEST_SIZE: u32 = 16 * 1024;     // 16 KiB
pub const MAX_ADMIN_REQUEST_SIZE: u32 = 256 * 1024;    // 256 KiB
pub const MAX_DEFAULT_REQUEST_SIZE: u32 = 64 * 1024;   // 64 KiB

/// Maximum connections per IP within the rate-limit window.
/// Override with MILNET_MAX_CONN_PER_IP for load testing (default: 10).
fn max_connections_per_ip() -> u32 {
    std::env::var("MILNET_MAX_CONN_PER_IP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
}

/// Rate-limit window duration (60 seconds).
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Global maximum concurrent connections.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 1000;

/// Read/write timeout for TCP operations (30 seconds).
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// TLS handshake timeout for outbound connections to the orchestrator.
///
/// Prevents a slow or unresponsive orchestrator from holding gateway connection
/// slots indefinitely.  Without this, a degraded orchestrator can exhaust all
/// `MAX_CONCURRENT_CONNECTIONS` slots via stalled TLS handshakes, causing a
/// complete authentication blackout for legitimate users.
pub const TLS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// AES-256-GCM nonce size (96 bits / 12 bytes).
const AES_GCM_NONCE_LEN: usize = 12;

/// Maximum concurrent HTTP/2 streams per connection.
///
/// Applied when the gateway is fronted by an HTTP/2 reverse proxy.  Limits
/// the number of in-flight requests a single TCP connection can multiplex,
/// preventing a single client from monopolising server resources.
pub const MAX_CONCURRENT_STREAMS: u32 = 100;

/// Maximum HTTP/2 header list size in bytes (64 KiB).
///
/// Prevents oversized HPACK-encoded header blocks from consuming excessive
/// memory.  Applied via HTTP/2 SETTINGS frame when using hyper/axum.
pub const MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;

/// Constant-time floor for all authentication responses (100 ms).
///
/// Every authentication code path (success, failure, orchestrator error,
/// username-not-found in OPAQUE) is padded to at least this duration to
/// prevent timing-based username enumeration.
pub const AUTH_RESPONSE_FLOOR: std::time::Duration = std::time::Duration::from_millis(100);

/// Configuration for orchestrator forwarding.
#[derive(Clone)]
pub struct OrchestratorConfig {
    pub addr: String,
    pub hmac_key: [u8; 64],
    /// TLS connector for mTLS connections to the orchestrator.
    pub tls_connector: tokio_rustls::TlsConnector,
}

impl Drop for OrchestratorConfig {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
    }
}

/// Per-IP rate-limit state: (connection count, window start).
type RateLimitMap = HashMap<IpAddr, (u32, Instant)>;

/// Compute the SHA-256 fingerprint of an X-Wing public key.
///
/// The fingerprint is the first 32 bytes of SHA-256 over the full serialized
/// public key, hex-encoded.  Clients pin this fingerprint and verify it
/// against the value received in the puzzle challenge.
fn xwing_pk_fingerprint(pk_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"MILNET-XWING-PIN-v1");
    hasher.update(pk_bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Load trusted X-Wing public key fingerprints from the `MILNET_GATEWAY_KEY_PINS`
/// environment variable.
///
/// The env var should contain a comma-separated list of hex-encoded SHA-256
/// fingerprints.  If the env var is not set, returns an empty set (pinning
/// disabled — clients will accept any server key).
fn load_key_pins() -> Vec<String> {
    match std::env::var("MILNET_GATEWAY_KEY_PINS") {
        Ok(val) if !val.is_empty() => {
            let pins: Vec<String> = val
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            info!(
                "X-Wing key pinning enabled: {} pin(s) loaded from MILNET_GATEWAY_KEY_PINS",
                pins.len()
            );
            pins
        }
        _ => {
            warn!("X-Wing key pinning DISABLED — set MILNET_GATEWAY_KEY_PINS for production");
            Vec::new()
        }
    }
}

/// Verify that the server's X-Wing public key fingerprint matches at least
/// one of the pinned fingerprints.  If pinning is disabled (empty pin list),
/// always returns true.
///
/// Emits a CRITICAL SIEM event and returns false if the fingerprint does not
/// match any pinned value, indicating a potential key substitution attack.
fn verify_key_pin(server_fingerprint: &str, pinned: &[String]) -> bool {
    if pinned.is_empty() {
        return true; // Pinning not configured
    }

    for pin in pinned {
        if pin == server_fingerprint {
            return true;
        }
    }

    // Key mismatch — possible key substitution or MitM attack
    error!(
        server_fingerprint = server_fingerprint,
        "SIEM:CRITICAL X-Wing public key fingerprint does NOT match any pinned value — \
         possible key substitution attack"
    );
    common::siem::SecurityEvent::tamper_detected(
        &format!(
            "X-Wing server key fingerprint mismatch: {} does not match any configured pin. \
             Possible key substitution or MitM attack on gateway.",
            server_fingerprint
        ),
    );
    false
}

/// The Bastion Gateway server.
///
/// Holds a long-lived X-Wing keypair generated once at startup.  The public
/// key is sent to every connecting client as part of the puzzle challenge so
/// clients can perform hybrid post-quantum key exchange.  The server retains
/// the full keypair so it can decapsulate ciphertexts returned by clients.
pub struct GatewayServer {
    listener: TcpListener,
    difficulty: u8,
    orchestrator: Option<Arc<OrchestratorConfig>>,
    active_connections: Arc<AtomicUsize>,
    /// Server-side X-Wing public key bytes, shared across connections via Arc.
    xwing_server_pk: Arc<Vec<u8>>,
    /// Server-side X-Wing full keypair, used for decapsulation.
    xwing_server_kp: Arc<crypto::xwing::XWingKeyPair>,
    /// Per-IP connection rate limiter.
    rate_limits: Arc<Mutex<RateLimitMap>>,
    /// SHA-256 fingerprint of the server's X-Wing public key (hex-encoded).
    /// Included in puzzle challenges so clients can verify against pinned values.
    xwing_fingerprint: Arc<String>,
    /// Trusted X-Wing public key fingerprints loaded from MILNET_GATEWAY_KEY_PINS.
    /// If empty, pinning is disabled.
    key_pins: Arc<Vec<String>>,
    /// Optional TLS acceptor for TLS termination on the external listener.
    /// When set, all accepted TCP connections are upgraded to TLS before processing.
    tls_acceptor: Option<TlsAcceptor>,
    /// Optional distributed rate limiter (Redis-backed with local fallback).
    distributed_limiter: Option<Arc<DistributedRateLimiter>>,
}

impl GatewayServer {
    /// Bind the gateway to the given address.
    pub async fn bind(addr: &str, difficulty: u8) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!("Gateway listening on {}", listener.local_addr()?);
        let xwing_kp = tokio::task::spawn_blocking(crypto::xwing::XWingKeyPair::generate)
            .await
            .map_err(|e| std::io::Error::other(format!("XWing keygen: {e}")))?;
        let xwing_server_pk = Arc::new(xwing_kp.public_key().to_bytes());
        let fingerprint = xwing_pk_fingerprint(&xwing_server_pk);
        info!(
            "X-Wing server keypair generated ({} byte public key, fingerprint={})",
            xwing_server_pk.len(),
            &fingerprint[..16]
        );
        let key_pins = load_key_pins();
        if !verify_key_pin(&fingerprint, &key_pins) {
            return Err(std::io::Error::other(
                "FATAL: X-Wing server key fingerprint does not match any pinned value. \
                 Update MILNET_GATEWAY_KEY_PINS or investigate key compromise.",
            ));
        }
        let xwing_server_kp = Arc::new(xwing_kp);
        Ok(Self {
            listener,
            difficulty,
            orchestrator: None,
            active_connections: Arc::new(AtomicUsize::new(0)),
            xwing_server_pk,
            xwing_server_kp,
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            xwing_fingerprint: Arc::new(fingerprint),
            key_pins: Arc::new(key_pins),
            tls_acceptor: None,
            distributed_limiter: None,
        })
    }

    /// Bind the gateway with TLS termination on the external listener.
    ///
    /// This is REQUIRED for production deployments. The `tls_config` should
    /// enforce TLS 1.3 with CNSA 2.0 compliant cipher suites.
    pub async fn bind_tls(
        addr: &str,
        difficulty: u8,
        tls_config: Arc<ServerConfig>,
    ) -> std::io::Result<Self> {
        let mut server = Self::bind(addr, difficulty).await?;
        server.tls_acceptor = Some(TlsAcceptor::from(tls_config));
        info!("TLS termination enabled on external listener");
        Ok(server)
    }

    /// Bind the gateway with orchestrator forwarding enabled.
    pub async fn bind_with_orchestrator(
        addr: &str,
        difficulty: u8,
        orchestrator_config: OrchestratorConfig,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!("Gateway listening on {}", listener.local_addr()?);
        let xwing_kp = tokio::task::spawn_blocking(crypto::xwing::XWingKeyPair::generate)
            .await
            .map_err(|e| std::io::Error::other(format!("XWing keygen: {e}")))?;
        let xwing_server_pk = Arc::new(xwing_kp.public_key().to_bytes());
        let fingerprint = xwing_pk_fingerprint(&xwing_server_pk);
        info!(
            "X-Wing server keypair generated ({} byte public key, fingerprint={})",
            xwing_server_pk.len(),
            &fingerprint[..16]
        );
        let key_pins = load_key_pins();
        if !verify_key_pin(&fingerprint, &key_pins) {
            return Err(std::io::Error::other(
                "FATAL: X-Wing server key fingerprint does not match any pinned value. \
                 Update MILNET_GATEWAY_KEY_PINS or investigate key compromise.",
            ));
        }
        let xwing_server_kp = Arc::new(xwing_kp);
        Ok(Self {
            listener,
            difficulty,
            orchestrator: Some(Arc::new(orchestrator_config)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            xwing_server_pk,
            xwing_server_kp,
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            xwing_fingerprint: Arc::new(fingerprint),
            key_pins: Arc::new(key_pins),
            tls_acceptor: None,
            distributed_limiter: None,
        })
    }

    /// Set a TLS acceptor on an existing server instance.
    ///
    /// This allows combining TLS with orchestrator forwarding:
    /// ```ignore
    /// let mut server = GatewayServer::bind_with_orchestrator(addr, difficulty, orch).await?;
    /// server.set_tls(tls_config);
    /// ```
    pub fn set_tls(&mut self, tls_config: Arc<ServerConfig>) {
        self.tls_acceptor = Some(TlsAcceptor::from(tls_config));
        info!("TLS termination enabled on external listener");
    }

    /// Return the local address the server is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Attach a distributed rate limiter (Redis-backed with local fallback).
    ///
    /// When set, every incoming connection is checked against the distributed
    /// rate limiter *in addition to* the existing per-IP local rate limiter.
    pub fn set_distributed_limiter(&mut self, limiter: Arc<DistributedRateLimiter>) {
        info!("distributed rate limiter attached to gateway");
        self.distributed_limiter = Some(limiter);
    }

    /// Check and update per-IP rate limits.  Returns `true` if the
    /// connection should be allowed, `false` if it exceeds the limit.
    async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let mut limits = self.rate_limits.lock().await;
        let now = Instant::now();
        let entry = limits.entry(ip).or_insert((0, now));

        // Reset the window if it has expired
        if now.duration_since(entry.1).as_secs() >= RATE_LIMIT_WINDOW_SECS {
            *entry = (0, now);
        }

        entry.0 += 1;
        entry.0 < max_connections_per_ip()
    }

    /// Run the server loop, accepting connections forever.
    ///
    /// Uses adaptive puzzle difficulty based on the current number of active
    /// connections.  The per-instance `self.difficulty` field acts as the
    /// *minimum* difficulty; the adaptive function may raise it under load.
    pub async fn run(&self) -> std::io::Result<()> {
        loop {
            let (tcp_stream, addr) = self.listener.accept().await?;

            // Enforce global concurrent connection cap
            let active = self.active_connections.load(Ordering::Relaxed);
            if active >= MAX_CONCURRENT_CONNECTIONS {
                warn!("rejecting connection from {addr}: global connection limit ({MAX_CONCURRENT_CONNECTIONS}) reached");
                drop(tcp_stream);
                continue;
            }

            // Enforce per-IP rate limit
            if !self.check_rate_limit(addr.ip()).await {
                warn!("rejecting connection from {addr}: per-IP rate limit exceeded ({} per {RATE_LIMIT_WINDOW_SECS}s)", max_connections_per_ip());
                drop(tcp_stream);
                continue;
            }

            // Distributed rate limiting check (per-IP + per-user via Redis)
            if let Some(ref limiter) = self.distributed_limiter {
                let result = limiter.check_ip(addr.ip()).await;
                if !result.allowed {
                    let client_ip = addr.ip().to_string();
                    warn!(ip = %client_ip, "distributed rate limit exceeded — rejecting connection");
                    drop(tcp_stream);
                    continue;
                }
            }

            let active = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
            let difficulty = get_adaptive_difficulty(active).max(self.difficulty);
            let orch = self.orchestrator.clone();
            let counter = self.active_connections.clone();
            let server_pk = self.xwing_server_pk.clone();
            let server_kp = self.xwing_server_kp.clone();
            let fingerprint = self.xwing_fingerprint.clone();
            let tls_acceptor = self.tls_acceptor.clone();
            // Verbose logging: log incoming connection details
            common::error_response::verbose_log_fields(
                "gateway",
                "incoming connection",
                &[
                    ("source_ip", &addr.ip().to_string()),
                    ("source_port", &addr.port().to_string()),
                    ("active_connections", &active.to_string()),
                    ("puzzle_difficulty", &difficulty.to_string()),
                ],
            );
            tokio::spawn(async move {
                // If TLS is configured, upgrade the TCP stream before processing
                let result = if let Some(acceptor) = tls_acceptor {
                    match acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => {
                            debug!("TLS handshake completed for {addr}");
                            handle_connection(tls_stream, difficulty, orch, server_pk, server_kp, fingerprint).await
                        }
                        Err(e) => {
                            warn!("TLS handshake failed from {addr}: {e}");
                            Err(format!("TLS handshake failed: {e}"))
                        }
                    }
                } else {
                    handle_connection(tcp_stream, difficulty, orch, server_pk, server_kp, fingerprint).await
                };

                if let Err(e) = result {
                    // In production, mask the error; always log internally
                    let internal_msg = common::error_response::log_error_with_location(&e);
                    warn!("connection from {addr} failed: {internal_msg}");
                }
                counter.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    /// Accept and handle exactly one connection (useful for tests).
    pub async fn accept_one(&self) -> std::io::Result<()> {
        let (tcp_stream, addr) = self.listener.accept().await?;

        if let Some(ref acceptor) = self.tls_acceptor {
            let tls_stream = acceptor.accept(tcp_stream).await.map_err(|e| {
                error!("TLS handshake from {addr} failed: {e}");
                std::io::Error::other(format!("TLS handshake failed: {e}"))
            })?;
            handle_connection(
                tls_stream,
                self.difficulty,
                self.orchestrator.clone(),
                self.xwing_server_pk.clone(),
                self.xwing_server_kp.clone(),
                self.xwing_fingerprint.clone(),
            )
            .await
            .map_err(|e| {
                error!("connection from {addr} failed: {e}");
                std::io::Error::other(e)
            })
        } else {
            handle_connection(
                tcp_stream,
                self.difficulty,
                self.orchestrator.clone(),
                self.xwing_server_pk.clone(),
                self.xwing_server_kp.clone(),
                self.xwing_fingerprint.clone(),
            )
            .await
            .map_err(|e| {
                error!("connection from {addr} failed: {e}");
                std::io::Error::other(e)
            })
        }
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM frame encryption helpers
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` using AES-256-GCM with the given 32-byte key.
///
/// A random 12-byte nonce is generated and prepended to the ciphertext,
/// yielding: `nonce (12 bytes) || ciphertext+tag`.
fn encrypt_frame(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("AES-256-GCM key init: {e}"))?;

    let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("generate nonce: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("AES-256-GCM encrypt: {e}"))?;

    let mut out = Vec::with_capacity(AES_GCM_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `ciphertext` (nonce || ciphertext+tag) using AES-256-GCM with
/// the given 32-byte key.
fn decrypt_frame(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < AES_GCM_NONCE_LEN {
        return Err("encrypted frame too short (missing nonce)".into());
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("AES-256-GCM key init: {e}"))?;

    let nonce = Nonce::from_slice(&data[..AES_GCM_NONCE_LEN]);
    let ciphertext = &data[AES_GCM_NONCE_LEN..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES-256-GCM decrypt: {e}"))
}

/// Handle a single client connection through the full puzzle + KEM + auth flow.
///
/// Protocol steps (proper client-server X-Wing KEM flow):
///   1. Server -> Client: `PuzzleChallenge` (includes server X-Wing public key)
///   2. Client -> Server: `PuzzleSolution` + `KemCiphertext`
///      Client encapsulates against server's X-Wing PK, producing a shared
///      secret and ciphertext.  The ciphertext is sent alongside the puzzle
///      solution.
///   3. Server verifies puzzle solution
///   4. Server decapsulates the received ciphertext with its own secret key
///   5. Both sides now share the same hybrid PQ + classical secret
///   6. Both derive session key via HKDF-SHA512 over the shared secret
///   7. Client -> Server: `AuthRequest` (AES-256-GCM encrypted with session key)
///   8. Server -> Client: `AuthResponse` (AES-256-GCM encrypted with session key)
async fn handle_connection(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    difficulty: u8,
    orchestrator: Option<Arc<OrchestratorConfig>>,
    server_xwing_pk: Arc<Vec<u8>>,
    server_xwing_kp: Arc<crypto::xwing::XWingKeyPair>,
    server_xwing_fingerprint: Arc<String>,
) -> Result<(), String> {
    let conn_start = Instant::now();

    // 1. Send puzzle challenge with the server's X-Wing public key and fingerprint.
    //    The client uses this key to encapsulate and produce a ciphertext.
    //    The fingerprint allows clients to verify against pinned values before
    //    encapsulating, detecting key substitution attacks.
    let mut challenge = generate_challenge(difficulty);
    challenge.xwing_server_pk = Some((*server_xwing_pk).clone());
    challenge.xwing_server_pk_fingerprint = Some((*server_xwing_fingerprint).clone());
    send_frame_with_timeout(&mut stream, &challenge).await?;
    common::error_response::verbose_log("gateway", "puzzle challenge sent");

    // 2. Read puzzle solution (contains the client's KEM ciphertext)
    let solution: PuzzleSolution = recv_frame_with_timeout(&mut stream, MAX_AUTH_REQUEST_SIZE).await?;

    // 3. Verify puzzle solution.  All verification failures go through the
    //    timing floor to prevent distinguishing failure modes.
    let auth_start = tokio::time::Instant::now();

    common::error_response::verbose_log("gateway", "puzzle solution received, verifying");
    if !crypto::ct::ct_eq_32(&solution.nonce, &challenge.nonce) {
        let resp = AuthResponse {
            success: false,
            token: None,
            error: Some(common::error_response::sanitize("nonce mismatch")),
        };
        enforce_timing_floor(auth_start).await;
        send_frame_with_timeout(&mut stream, &resp).await?;
        return Err("nonce mismatch".into());
    }

    if !verify_solution(&challenge, &solution.solution) {
        let resp = AuthResponse {
            success: false,
            token: None,
            error: Some(common::error_response::sanitize("invalid puzzle solution")),
        };
        enforce_timing_floor(auth_start).await;
        send_frame_with_timeout(&mut stream, &resp).await?;
        return Err("invalid puzzle solution".into());
    }

    common::error_response::log_crypto_operation("puzzle_verify", "SHA-512", "puzzle");
    common::error_response::verbose_log_fields(
        "gateway",
        "puzzle solution verified",
        &[("elapsed_ms", &conn_start.elapsed().as_millis().to_string())],
    );

    // 4. X-Wing hybrid KEM key exchange (ML-KEM-1024 + X25519)
    //
    // The client has encapsulated against the server's X-Wing public key
    // (sent in step 1) and returned the ciphertext in the puzzle solution.
    // The server now decapsulates with its secret key to derive the same
    // shared secret.
    let kem_ct_bytes = solution.xwing_kem_ciphertext.ok_or(
        "client did not provide X-Wing KEM ciphertext in puzzle solution",
    )?;
    let kem_ct = crypto::xwing::Ciphertext::from_bytes(&kem_ct_bytes)
        .ok_or("invalid X-Wing KEM ciphertext from client")?;

    // ML-KEM-1024 decapsulation uses significant stack space; run on a blocking
    // thread to avoid overflowing the async task stack in debug builds.
    let shared_secret = {
        let kp = server_xwing_kp.clone();
        tokio::task::spawn_blocking(move || crypto::xwing::xwing_decapsulate(&kp, &kem_ct))
            .await
            .map_err(|e| format!("KEM decapsulate task: {e}"))?
            .map_err(|e| format!("KEM decapsulation failed: {e}"))?
    };

    common::error_response::log_crypto_operation("kem_decapsulate", "X-Wing (ML-KEM-1024 + X25519)", "server_sk");

    // 5. Derive session key via HKDF-SHA512
    //    Context binds to this specific handshake via the puzzle nonce.
    //    The derived key is 64 bytes; we use the first 32 bytes for AES-256-GCM.
    let session_key = crypto::xwing::derive_session_key(&shared_secret, &challenge.nonce)
        .map_err(|e| format!("session key derivation failed: {e}"))?;
    let enc_key: [u8; 32] = session_key[..32].try_into()
        .map_err(|_| "session key derivation produced fewer than 32 bytes".to_string())?;
    common::error_response::log_crypto_operation("key_derive", "HKDF-SHA512", "session_key");
    debug!("X-Wing KEM: session key established (hybrid PQ + classical)");

    // 6. Read encrypted auth request (enforce auth endpoint size limit)
    let encrypted_auth = tokio::time::timeout(
        IO_TIMEOUT,
        recv_raw_frame_limited(&mut stream, MAX_AUTH_REQUEST_SIZE),
    )
    .await
    .map_err(|_| "read timeout".to_string())?
    .map_err(|e| {
        if e.contains("payload too large") {
            warn!("auth request rejected: {e}");
        }
        e
    })?;
    let auth_plaintext = decrypt_frame(&enc_key, &encrypted_auth)?;
    let auth_req: AuthRequest = postcard::from_bytes(&auth_plaintext)
        .map_err(|e| format!("deserialize auth request: {e}"))?;

    common::error_response::log_crypto_operation("decrypt_frame", "AES-256-GCM", "session_key");
    common::error_response::verbose_log("gateway", "auth request decrypted and deserialized");

    // 7. Forward to orchestrator via SHARD (or stub if not configured).
    //    The timing floor is measured from auth_start to cover the entire
    //    authentication path including username lookup, OPAQUE processing,
    //    and orchestrator round-trip.

    // DPoP channel binding: hash the KEM ciphertext (the client proved
    // possession of knowledge of the shared secret through successful
    // encrypted communication).
    let client_binding_hash = crypto::dpop::dpop_key_hash(&kem_ct_bytes);

    let resp = if let Some(orch) = orchestrator {
        match forward_to_orchestrator(&auth_req, &orch, client_binding_hash).await {
            Ok(r) => r,
            Err(e) => {
                let internal_msg = common::error_response::log_error_with_location(&e);
                tracing::warn!("orchestrator error: {internal_msg}");
                AuthResponse {
                    success: false,
                    token: None,
                    error: Some(common::error_response::sanitize(&e)),
                }
            }
        }
    } else {
        // No orchestrator configured -- return error instead of placeholder token
        AuthResponse {
            success: false,
            token: None,
            error: Some("no orchestrator configured".to_string()),
        }
    };

    // Enforce constant-time floor on ALL auth responses (success, failure,
    // orchestrator error, username-not-found) to prevent timing-based
    // username enumeration via OPAQUE.
    enforce_timing_floor(auth_start).await;

    // Encrypt the response with the session key before sending
    let resp_plaintext = postcard::to_allocvec(&resp)
        .map_err(|e| format!("serialize auth response: {e}"))?;
    let encrypted_resp = encrypt_frame(&enc_key, &resp_plaintext)?;
    send_raw_frame_with_timeout(&mut stream, &encrypted_resp).await?;

    Ok(())
}

/// Pad elapsed time to the constant `AUTH_RESPONSE_FLOOR` to prevent
/// timing-based information leakage across all authentication paths.
async fn enforce_timing_floor(start: tokio::time::Instant) {
    let elapsed = start.elapsed();
    if elapsed < AUTH_RESPONSE_FLOOR {
        tokio::time::sleep(AUTH_RESPONSE_FLOOR - elapsed).await;
    }
}

/// Forward an auth request to the orchestrator via SHARD and return the response.
///
/// `client_binding_hash` is SHA-512 of the client's KEM ciphertext, used as
/// the DPoP channel binding.  The client proved knowledge of the shared
/// secret through the encrypted channel.
async fn forward_to_orchestrator(
    auth_req: &AuthRequest,
    config: &OrchestratorConfig,
    client_binding_hash: [u8; 64],
) -> Result<AuthResponse, String> {
    let orch_req = OrchestratorRequest {
        username: auth_req.username.clone(),
        password: auth_req.password.clone(),
        dpop_key_hash: client_binding_hash,
        tier: 0,                  // Orchestrator decides tier
        audience: auth_req.audience.clone(),
        ceremony_id: [0u8; 32],   // Assigned by orchestrator during ceremony
        device_attestation_age_secs: None,
        geo_velocity_kmh: None,
        is_unusual_network: None,
        is_unusual_time: None,
        unusual_access_score: None,
        recent_failed_attempts: None,
    };

    let req_bytes = postcard::to_allocvec(&orch_req)
        .map_err(|e| format!("serialize orchestrator request: {e}"))?;

    // Derive TLS SNI hostname from the orchestrator address.
    // Self-signed certs use DNS names (not IP SANs), so when connecting
    // to a bare IP address like 127.0.0.1, fall back to "localhost" as SNI.
    // For real hostnames (e.g., orchestrator.milnet.internal), use the actual hostname.
    let raw_hostname = config.addr
        .split(':')
        .next()
        .unwrap_or(&config.addr);
    let orch_hostname = if raw_hostname.parse::<std::net::IpAddr>().is_ok() {
        "localhost"
    } else {
        raw_hostname
    };
    let mut transport = tokio::time::timeout(
            TLS_CONNECT_TIMEOUT,
            tls_connect(
                &config.addr,
                ModuleId::Gateway,
                config.hmac_key,
                &config.tls_connector,
                orch_hostname,
            ),
        )
        .await
        .map_err(|_| "TLS handshake to orchestrator timed out (5s limit)".to_string())?
        .map_err(|e| format!("connect to orchestrator: {e}"))?;

    transport
        .send(&req_bytes)
        .await
        .map_err(|e| format!("send to orchestrator: {e}"))?;

    let (_sender, resp_bytes) = transport
        .recv()
        .await
        .map_err(|e| format!("recv from orchestrator: {e}"))?;

    let orch_resp: OrchestratorResponse = postcard::from_bytes(&resp_bytes)
        .map_err(|e| format!("deserialize orchestrator response: {e}"))?;

    Ok(AuthResponse {
        success: orch_resp.success,
        token: orch_resp.token_bytes,
        error: orch_resp.error,
    })
}

// ---------------------------------------------------------------------------
// Frame I/O helpers with timeout enforcement
// ---------------------------------------------------------------------------

/// Send a postcard-serialized value with 4-byte BE length prefix, with timeout.
async fn send_frame_with_timeout<T: serde::Serialize>(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    value: &T,
) -> Result<(), String> {
    tokio::time::timeout(IO_TIMEOUT, send_frame(stream, value))
        .await
        .map_err(|_| "write timeout".to_string())?
}

/// Read a length-prefixed frame and deserialize with postcard, with timeout.
///
/// `max_size` enforces the per-endpoint payload cap *before* any allocation.
async fn recv_frame_with_timeout<T: serde::de::DeserializeOwned>(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    max_size: u32,
) -> Result<T, String> {
    tokio::time::timeout(IO_TIMEOUT, recv_frame(stream, max_size))
        .await
        .map_err(|_| "read timeout".to_string())?
}

/// Read a raw length-prefixed frame (bytes only), with timeout.
///
/// `max_size` enforces the per-endpoint payload cap *before* any allocation.
async fn recv_raw_frame_with_timeout(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), max_size: u32) -> Result<Vec<u8>, String> {
    tokio::time::timeout(IO_TIMEOUT, recv_raw_frame_limited(stream, max_size))
        .await
        .map_err(|_| "read timeout".to_string())?
}

/// Send a raw byte payload with 4-byte BE length prefix, with timeout.
async fn send_raw_frame_with_timeout(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    data: &[u8],
) -> Result<(), String> {
    tokio::time::timeout(IO_TIMEOUT, send_raw_frame(stream, data))
        .await
        .map_err(|_| "write timeout".to_string())?
}

/// Send a postcard-serialized value with 4-byte BE length prefix.
async fn send_frame<T: serde::Serialize>(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), value: &T) -> Result<(), String> {
    let payload = postcard::to_allocvec(value).map_err(|e| format!("serialize: {e}"))?;
    let len = payload.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("write length: {e}"))?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| format!("write payload: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

/// Read a length-prefixed frame and deserialize with postcard.
///
/// `max_size` enforces the per-endpoint payload cap *before* any allocation.
async fn recv_frame<T: serde::de::DeserializeOwned>(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), max_size: u32) -> Result<T, String> {
    let buf = recv_raw_frame_limited(stream, max_size).await?;
    postcard::from_bytes(&buf).map_err(|e| format!("deserialize: {e}"))
}

/// Read a raw length-prefixed frame with a caller-specified size limit.
///
/// Returns `Err("payload too large: … bytes (limit …)")` if the declared
/// frame length exceeds `max_size`, which the gateway maps to 413 Payload
/// Too Large when surfaced to HTTP clients.
///
/// Reads in chunks of up to 64 KiB to avoid allocating the full declared
/// frame size upfront.  This prevents a slow-send attacker from exhausting
/// heap memory: only the bytes actually received consume memory.
async fn recv_raw_frame_limited(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    max_size: u32,
) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("read length: {e}"))?;
    let len = u32::from_be_bytes(len_buf);
    if len > max_size {
        return Err(format!(
            "payload too large: {len} bytes (limit {max_size} bytes)"
        ));
    }
    if len > MAX_FRAME_LEN {
        return Err(format!("frame too large: {len} bytes"));
    }
    let total = usize::try_from(len).map_err(|_| "frame size overflows usize".to_string())?;

    // Chunked read: allocate incrementally in 64 KiB chunks instead of the
    // full declared size.  A slow-send attacker declaring 1 MiB but sending
    // 1 byte/sec will only cause 64 KiB of allocation, not 1 MiB.
    const CHUNK: usize = 64 * 1024;
    let initial_cap = total.min(CHUNK);
    let mut buf = Vec::with_capacity(initial_cap);
    let mut remaining = total;
    while remaining > 0 {
        let to_read = remaining.min(CHUNK);
        let start = buf.len();
        buf.resize(start + to_read, 0);
        stream
            .read_exact(&mut buf[start..start + to_read])
            .await
            .map_err(|e| format!("read payload: {e}"))?;
        remaining -= to_read;
    }
    Ok(buf)
}

/// Send a raw byte payload with 4-byte BE length prefix.
async fn send_raw_frame(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), data: &[u8]) -> Result<(), String> {
    let len = data.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("write length: {e}"))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| format!("write payload: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}
