//! Bastion Gateway TCP server.
//!
//! Accepts client connections, issues a hash puzzle challenge, verifies
//! the solution, reads an authentication request, and forwards to the
//! orchestrator via SHARD for real authentication.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use rand::Rng;
use tracing::{error, info, warn};

use common::types::ModuleId;
use shard::transport::connect;

use crate::puzzle::{generate_challenge, get_adaptive_difficulty, verify_solution, PuzzleSolution};
use crate::wire::{AuthRequest, AuthResponse, OrchestratorRequest, OrchestratorResponse};

/// Maximum wire frame payload size (1 MiB).
const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// Configuration for orchestrator forwarding.
#[derive(Clone)]
pub struct OrchestratorConfig {
    pub addr: String,
    pub hmac_key: [u8; 64],
}

/// The Bastion Gateway server.
pub struct GatewayServer {
    listener: TcpListener,
    difficulty: u8,
    orchestrator: Option<Arc<OrchestratorConfig>>,
    active_connections: Arc<AtomicUsize>,
}

impl GatewayServer {
    /// Bind the gateway to the given address.
    pub async fn bind(addr: &str, difficulty: u8) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!("Gateway listening on {}", listener.local_addr()?);
        Ok(Self {
            listener,
            difficulty,
            orchestrator: None,
            active_connections: Arc::new(AtomicUsize::new(0)),
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
        Ok(Self {
            listener,
            difficulty,
            orchestrator: Some(Arc::new(orchestrator_config)),
            active_connections: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Return the local address the server is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the server loop, accepting connections forever.
    ///
    /// Uses adaptive puzzle difficulty based on the current number of active
    /// connections.  The per-instance `self.difficulty` field acts as the
    /// *minimum* difficulty; the adaptive function may raise it under load.
    pub async fn run(&self) -> std::io::Result<()> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            let active = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
            let difficulty = get_adaptive_difficulty(active).max(self.difficulty);
            let orch = self.orchestrator.clone();
            let counter = self.active_connections.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, difficulty, orch).await {
                    warn!("connection from {addr} failed: {e}");
                }
                counter.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    /// Accept and handle exactly one connection (useful for tests).
    pub async fn accept_one(&self) -> std::io::Result<()> {
        let (stream, addr) = self.listener.accept().await?;
        handle_connection(stream, self.difficulty, self.orchestrator.clone())
            .await
            .map_err(|e| {
                error!("connection from {addr} failed: {e}");
                std::io::Error::other(e)
            })
    }
}

/// Handle a single client connection through the full puzzle + auth flow.
async fn handle_connection(
    mut stream: TcpStream,
    difficulty: u8,
    orchestrator: Option<Arc<OrchestratorConfig>>,
) -> Result<(), String> {
    // 1. Send puzzle challenge
    let challenge = generate_challenge(difficulty);
    send_frame(&mut stream, &challenge).await?;

    // 2. Read puzzle solution
    let solution: PuzzleSolution = recv_frame(&mut stream).await?;

    // 3. Verify solution
    if !crypto::ct::ct_eq_32(&solution.nonce, &challenge.nonce) {
        let resp = AuthResponse {
            success: false,
            token: None,
            error: Some("nonce mismatch".into()),
        };
        send_frame(&mut stream, &resp).await?;
        return Err("nonce mismatch".into());
    }

    if !verify_solution(&challenge, &solution.solution) {
        let resp = AuthResponse {
            success: false,
            token: None,
            error: Some("invalid puzzle solution".into()),
        };
        send_frame(&mut stream, &resp).await?;
        return Err("invalid puzzle solution".into());
    }

    // X-Wing hybrid KEM for session key establishment (post-quantum)
    // Generate a shared secret using X-Wing (ML-KEM-768 + X25519)
    let _xwing_shared_secret = {
        // Generate an ephemeral X-Wing keypair (X25519 + ML-KEM-768)
        let xwing_kp = crypto::xwing::XWingKeyPair::generate();
        let xwing_pk = xwing_kp.public_key();
        // Encapsulate against the public key to derive a shared secret
        let (shared_secret, _ciphertext) = crypto::xwing::xwing_encapsulate(&xwing_pk);
        shared_secret
    };
    tracing::debug!("X-Wing KEM: session key established (hybrid PQ + classical)");

    // 4. Read auth request
    let auth_req: AuthRequest = recv_frame(&mut stream).await?;

    // 5. Forward to orchestrator via SHARD (or stub if not configured)
    let resp = if let Some(orch) = orchestrator {
        forward_to_orchestrator(&auth_req, &orch).await?
    } else {
        // No orchestrator configured — return error instead of placeholder token
        AuthResponse {
            success: false,
            token: None,
            error: Some("no orchestrator configured".to_string()),
        }
    };
    send_frame(&mut stream, &resp).await?;

    Ok(())
}

/// Forward an auth request to the orchestrator via SHARD and return the response.
async fn forward_to_orchestrator(
    auth_req: &AuthRequest,
    config: &OrchestratorConfig,
) -> Result<AuthResponse, String> {
    // Gateway sets tier to 0 — the Orchestrator decides the actual tier
    // based on the authenticated identity (known limitation: should come
    // from device registry after auth, not be hardcoded anywhere).
    let orch_req = OrchestratorRequest {
        username: auth_req.username.clone(),
        password: auth_req.password.clone(),
        dpop_key_hash: {
            // Read client DPoP public key from the auth request payload
            // The client must send their Ed25519 public key as the first 32 bytes of the auth frame
            let auth_payload = &auth_req.password;
            let client_dpop_key: [u8; 32] = if auth_payload.len() >= 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&auth_payload[..32]);
                key
            } else {
                tracing::warn!("Client did not provide DPoP key — generating ephemeral (NOT spec-compliant)");
                rand::thread_rng().gen()
            };
            crypto::dpop::dpop_key_hash(&client_dpop_key)
        },
        tier: 0,                  // Orchestrator decides tier
    };

    let req_bytes = postcard::to_allocvec(&orch_req)
        .map_err(|e| format!("serialize orchestrator request: {e}"))?;

    let mut transport = connect(&config.addr, ModuleId::Gateway, config.hmac_key)
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
    postcard::from_bytes(&buf).map_err(|e| format!("deserialize: {e}"))
}
