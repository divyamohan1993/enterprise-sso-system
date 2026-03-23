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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use common::types::ModuleId;
use shard::tls_transport::tls_connect;

use crate::puzzle::{generate_challenge, get_adaptive_difficulty, verify_solution, PuzzleSolution};
use crate::wire::{AuthRequest, AuthResponse, KemCiphertext, OrchestratorRequest, OrchestratorResponse};

/// Maximum wire frame payload size (1 MiB).
const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// Maximum connections per IP within the rate-limit window.
const MAX_CONNECTIONS_PER_IP: u32 = 10;

/// Rate-limit window duration (60 seconds).
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Global maximum concurrent connections.
const MAX_CONCURRENT_CONNECTIONS: usize = 1000;

/// Read/write timeout for TCP operations (30 seconds).
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// AES-256-GCM nonce size (96 bits / 12 bytes).
const AES_GCM_NONCE_LEN: usize = 12;

/// Configuration for orchestrator forwarding.
#[derive(Clone)]
pub struct OrchestratorConfig {
    pub addr: String,
    pub hmac_key: [u8; 64],
    /// TLS connector for mTLS connections to the orchestrator.
    pub tls_connector: tokio_rustls::TlsConnector,
}

/// Per-IP rate-limit state: (connection count, window start).
type RateLimitMap = HashMap<IpAddr, (u32, Instant)>;

/// The Bastion Gateway server.
///
/// Holds a long-lived X-Wing keypair generated once at startup.  The public
/// key is sent to every connecting client as part of the puzzle challenge so
/// clients can perform hybrid post-quantum key exchange.
pub struct GatewayServer {
    listener: TcpListener,
    difficulty: u8,
    orchestrator: Option<Arc<OrchestratorConfig>>,
    active_connections: Arc<AtomicUsize>,
    /// Server-side X-Wing public key bytes, shared across connections via Arc.
    xwing_server_pk: Arc<Vec<u8>>,
    /// Per-IP connection rate limiter.
    rate_limits: Arc<Mutex<RateLimitMap>>,
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
        info!("X-Wing server keypair generated ({} byte public key)", xwing_server_pk.len());
        Ok(Self {
            listener,
            difficulty,
            orchestrator: None,
            active_connections: Arc::new(AtomicUsize::new(0)),
            xwing_server_pk,
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
        })
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
        info!("X-Wing server keypair generated ({} byte public key)", xwing_server_pk.len());
        Ok(Self {
            listener,
            difficulty,
            orchestrator: Some(Arc::new(orchestrator_config)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            xwing_server_pk,
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Return the local address the server is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
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
        entry.0 <= MAX_CONNECTIONS_PER_IP
    }

    /// Run the server loop, accepting connections forever.
    ///
    /// Uses adaptive puzzle difficulty based on the current number of active
    /// connections.  The per-instance `self.difficulty` field acts as the
    /// *minimum* difficulty; the adaptive function may raise it under load.
    pub async fn run(&self) -> std::io::Result<()> {
        loop {
            let (stream, addr) = self.listener.accept().await?;

            // Enforce global concurrent connection cap
            let active = self.active_connections.load(Ordering::Relaxed);
            if active >= MAX_CONCURRENT_CONNECTIONS {
                warn!("rejecting connection from {addr}: global connection limit ({MAX_CONCURRENT_CONNECTIONS}) reached");
                drop(stream);
                continue;
            }

            // Enforce per-IP rate limit
            if !self.check_rate_limit(addr.ip()).await {
                warn!("rejecting connection from {addr}: per-IP rate limit exceeded ({MAX_CONNECTIONS_PER_IP} per {RATE_LIMIT_WINDOW_SECS}s)");
                drop(stream);
                continue;
            }

            let active = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
            let difficulty = get_adaptive_difficulty(active).max(self.difficulty);
            let orch = self.orchestrator.clone();
            let counter = self.active_connections.clone();
            let server_pk = self.xwing_server_pk.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, difficulty, orch, server_pk).await {
                    warn!("connection from {addr} failed: {e}");
                }
                counter.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    /// Accept and handle exactly one connection (useful for tests).
    pub async fn accept_one(&self) -> std::io::Result<()> {
        let (stream, addr) = self.listener.accept().await?;
        handle_connection(stream, self.difficulty, self.orchestrator.clone(), self.xwing_server_pk.clone())
            .await
            .map_err(|e| {
                error!("connection from {addr} failed: {e}");
                std::io::Error::other(e)
            })
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

/// Handle a single client connection through the full puzzle + auth flow.
///
/// Protocol steps:
///   1. Server -> Client: `PuzzleChallenge` (includes server X-Wing public key)
///   2. Client -> Server: `PuzzleSolution`  (includes client X-Wing public key)
///   3. Server verifies puzzle solution
///   4. Server encapsulates against client's X-Wing public key
///   5. Server -> Client: `KemCiphertext`
///   6. Both sides derive session key via HKDF-SHA512 over the shared secret
///   7. Client -> Server: `AuthRequest` (AES-256-GCM encrypted with session key)
///   8. Server -> Client: `AuthResponse` (AES-256-GCM encrypted with session key)
async fn handle_connection(
    mut stream: TcpStream,
    difficulty: u8,
    orchestrator: Option<Arc<OrchestratorConfig>>,
    server_xwing_pk: Arc<Vec<u8>>,
) -> Result<(), String> {
    // 1. Send puzzle challenge with the server's X-Wing public key
    let mut challenge = generate_challenge(difficulty);
    challenge.xwing_server_pk = Some((*server_xwing_pk).clone());
    send_frame_with_timeout(&mut stream, &challenge).await?;

    // 2. Read puzzle solution (expected to contain the client's X-Wing public key)
    let solution: PuzzleSolution = recv_frame_with_timeout(&mut stream).await?;

    // 3. Verify solution
    if !crypto::ct::ct_eq_32(&solution.nonce, &challenge.nonce) {
        let resp = AuthResponse {
            success: false,
            token: None,
            error: Some("nonce mismatch".into()),
        };
        send_frame_with_timeout(&mut stream, &resp).await?;
        return Err("nonce mismatch".into());
    }

    if !verify_solution(&challenge, &solution.solution) {
        let resp = AuthResponse {
            success: false,
            token: None,
            error: Some("invalid puzzle solution".into()),
        };
        send_frame_with_timeout(&mut stream, &resp).await?;
        return Err("invalid puzzle solution".into());
    }

    // 4. X-Wing hybrid KEM key exchange (ML-KEM-1024 + X25519)
    //
    // The client sends its X-Wing public key alongside the puzzle solution.
    // The server encapsulates against the *client's* key, producing a shared
    // secret and a ciphertext.  The ciphertext is sent to the client so it
    // can decapsulate with its private key and arrive at the same secret.
    let client_pk_bytes = solution.xwing_client_pk.ok_or(
        "client did not provide X-Wing public key in puzzle solution",
    )?;
    let client_pk = crypto::xwing::XWingPublicKey::from_bytes(&client_pk_bytes)
        .ok_or("invalid X-Wing public key from client")?;

    // ML-KEM-1024 encapsulation uses significant stack space; run on a blocking
    // thread to avoid overflowing the async task stack in debug builds.
    let (shared_secret, kem_ct) = {
        let pk = client_pk;
        tokio::task::spawn_blocking(move || crypto::xwing::xwing_encapsulate(&pk))
            .await
            .map_err(|e| format!("KEM encapsulate task: {e}"))?
    };

    // 5. Send the KEM ciphertext to the client so it can decapsulate
    let kem_msg = KemCiphertext {
        ciphertext: kem_ct.to_bytes(),
    };
    send_frame_with_timeout(&mut stream, &kem_msg).await?;

    // 6. Derive session key via HKDF-SHA512
    //    Context binds to this specific handshake via the puzzle nonce.
    //    The derived key is 64 bytes; we use the first 32 bytes for AES-256-GCM.
    let session_key = crypto::xwing::derive_session_key(&shared_secret, &challenge.nonce);
    let enc_key: [u8; 32] = session_key[..32].try_into().expect("session key >= 32 bytes");
    tracing::debug!("X-Wing KEM: session key established (hybrid PQ + classical)");

    // 7. Read encrypted auth request
    let encrypted_auth = recv_raw_frame_with_timeout(&mut stream).await?;
    let auth_plaintext = decrypt_frame(&enc_key, &encrypted_auth)?;
    let auth_req: AuthRequest = postcard::from_bytes(&auth_plaintext)
        .map_err(|e| format!("deserialize auth request: {e}"))?;

    // 8. Forward to orchestrator via SHARD (or stub if not configured)
    // Record the start time before processing the auth request so we can
    // enforce a constant-time floor on the response, preventing timing-based
    // username enumeration attacks.
    let auth_start = tokio::time::Instant::now();

    // DPoP channel binding: hash the client's X-Wing public key.
    // The client proved possession of the private key via the KEM exchange.
    let client_pk_hash = crypto::dpop::dpop_key_hash(&client_pk_bytes);

    let resp = if let Some(orch) = orchestrator {
        match forward_to_orchestrator(&auth_req, &orch, client_pk_hash).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("orchestrator error: {e}");
                AuthResponse {
                    success: false,
                    token: None,
                    error: Some("authentication failed".to_string()),
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

    // Constant-time delay: pad response to a fixed minimum duration (100ms)
    // to prevent timing-based username enumeration via OPAQUE.
    const AUTH_RESPONSE_FLOOR: std::time::Duration = std::time::Duration::from_millis(100);
    let elapsed = auth_start.elapsed();
    if elapsed < AUTH_RESPONSE_FLOOR {
        tokio::time::sleep(AUTH_RESPONSE_FLOOR - elapsed).await;
    }

    // Encrypt the response with the session key before sending
    let resp_plaintext = postcard::to_allocvec(&resp)
        .map_err(|e| format!("serialize auth response: {e}"))?;
    let encrypted_resp = encrypt_frame(&enc_key, &resp_plaintext)?;
    send_raw_frame_with_timeout(&mut stream, &encrypted_resp).await?;

    Ok(())
}

/// Forward an auth request to the orchestrator via SHARD and return the response.
///
/// `client_pk_hash` is SHA-256 of the client's X-Wing public key, used as the
/// DPoP channel binding.  The client proved possession of the corresponding
/// private key through the X-Wing KEM exchange.
async fn forward_to_orchestrator(
    auth_req: &AuthRequest,
    config: &OrchestratorConfig,
    client_pk_hash: [u8; 32],
) -> Result<AuthResponse, String> {
    let orch_req = OrchestratorRequest {
        username: auth_req.username.clone(),
        password: auth_req.password.clone(),
        dpop_key_hash: client_pk_hash,
        tier: 0,                  // Orchestrator decides tier
        audience: None,
        device_attestation_age_secs: None,
        geo_velocity_kmh: None,
        is_unusual_network: None,
        is_unusual_time: None,
        unusual_access_score: None,
        recent_failed_attempts: None,
    };

    let req_bytes = postcard::to_allocvec(&orch_req)
        .map_err(|e| format!("serialize orchestrator request: {e}"))?;

    let mut transport = tls_connect(
            &config.addr,
            ModuleId::Gateway,
            config.hmac_key,
            &config.tls_connector,
            "localhost",
        )
        .await
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
    stream: &mut TcpStream,
    value: &T,
) -> Result<(), String> {
    tokio::time::timeout(IO_TIMEOUT, send_frame(stream, value))
        .await
        .map_err(|_| "write timeout".to_string())?
}

/// Read a length-prefixed frame and deserialize with postcard, with timeout.
async fn recv_frame_with_timeout<T: serde::de::DeserializeOwned>(
    stream: &mut TcpStream,
) -> Result<T, String> {
    tokio::time::timeout(IO_TIMEOUT, recv_frame(stream))
        .await
        .map_err(|_| "read timeout".to_string())?
}

/// Read a raw length-prefixed frame (bytes only), with timeout.
async fn recv_raw_frame_with_timeout(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    tokio::time::timeout(IO_TIMEOUT, recv_raw_frame(stream))
        .await
        .map_err(|_| "read timeout".to_string())?
}

/// Send a raw byte payload with 4-byte BE length prefix, with timeout.
async fn send_raw_frame_with_timeout(
    stream: &mut TcpStream,
    data: &[u8],
) -> Result<(), String> {
    tokio::time::timeout(IO_TIMEOUT, send_raw_frame(stream, data))
        .await
        .map_err(|_| "write timeout".to_string())?
}

/// Send a postcard-serialized value with 4-byte BE length prefix.
async fn send_frame<T: serde::Serialize>(stream: &mut TcpStream, value: &T) -> Result<(), String> {
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
async fn recv_frame<T: serde::de::DeserializeOwned>(stream: &mut TcpStream) -> Result<T, String> {
    let buf = recv_raw_frame(stream).await?;
    postcard::from_bytes(&buf).map_err(|e| format!("deserialize: {e}"))
}

/// Read a raw length-prefixed frame (bytes without deserialization).
async fn recv_raw_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("read length: {e}"))?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(format!("frame too large: {len} bytes"));
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("read payload: {e}"))?;
    Ok(buf)
}

/// Send a raw byte payload with 4-byte BE length prefix.
async fn send_raw_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
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
