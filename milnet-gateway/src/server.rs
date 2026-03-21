//! Bastion Gateway TCP server.
//!
//! Accepts client connections, issues a hash puzzle challenge, verifies
//! the solution, reads an authentication request, and forwards to the
//! orchestrator via SHARD for real authentication.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use milnet_common::types::ModuleId;
use milnet_shard::transport::connect;

use crate::puzzle::{generate_challenge, verify_solution, PuzzleSolution};
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
        })
    }

    /// Return the local address the server is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the server loop, accepting connections forever.
    pub async fn run(&self) -> std::io::Result<()> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            let difficulty = self.difficulty;
            let orch = self.orchestrator.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, difficulty, orch).await {
                    warn!("connection from {addr} failed: {e}");
                }
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
    if !milnet_crypto::ct::ct_eq_32(&solution.nonce, &challenge.nonce) {
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

    // 4. Read auth request
    let auth_req: AuthRequest = recv_frame(&mut stream).await?;

    // 5. Forward to orchestrator via SHARD (or stub if not configured)
    let resp = if let Some(orch) = orchestrator {
        forward_to_orchestrator(&auth_req, &orch).await?
    } else {
        // Stub response when no orchestrator is configured
        AuthResponse {
            success: true,
            token: Some(vec![0xAA; 32]), // placeholder token
            error: None,
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
        password_hash: auth_req.password_hash,
        dpop_key_hash: [0u8; 32], // Gateway does not have DPoP yet
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
