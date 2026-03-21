//! Auth Orchestrator service — coordinates Gateway, OPAQUE, and TSS.

use milnet_common::types::{ModuleId, TokenClaims};
use milnet_crypto::entropy::generate_nonce;
use milnet_opaque::messages::{OpaqueRequest, OpaqueResponse};
use milnet_shard::transport::{connect, ShardListener, ShardTransport};
use milnet_tss::messages::{SigningRequest, SigningResponse};
use uuid::Uuid;

use crate::ceremony::CeremonySession;
use crate::messages::{OrchestratorRequest, OrchestratorResponse};

/// The orchestrator service that coordinates authentication ceremonies.
pub struct OrchestratorService {
    pub hmac_key: [u8; 64],
    pub opaque_addr: String,
    pub tss_addr: String,
    pub receipt_signing_key: [u8; 64],
}

impl OrchestratorService {
    /// Create a new orchestrator service.
    pub fn new(
        hmac_key: [u8; 64],
        opaque_addr: String,
        tss_addr: String,
        receipt_signing_key: [u8; 64],
    ) -> Self {
        Self {
            hmac_key,
            opaque_addr,
            tss_addr,
            receipt_signing_key,
        }
    }

    /// Connect to the OPAQUE service via SHARD.
    async fn connect_opaque(&self) -> Result<ShardTransport, String> {
        connect(&self.opaque_addr, ModuleId::Orchestrator, self.hmac_key)
            .await
            .map_err(|e| format!("connect to OPAQUE: {e}"))
    }

    /// Connect to the TSS service via SHARD.
    async fn connect_tss(&self) -> Result<ShardTransport, String> {
        connect(&self.tss_addr, ModuleId::Orchestrator, self.hmac_key)
            .await
            .map_err(|e| format!("connect to TSS: {e}"))
    }

    /// Process a single authentication request end-to-end.
    pub async fn process_auth(&self, request: &OrchestratorRequest) -> OrchestratorResponse {
        match self.process_auth_inner(request).await {
            Ok(token_bytes) => OrchestratorResponse {
                success: true,
                token_bytes: Some(token_bytes),
                error: None,
            },
            Err(e) => OrchestratorResponse {
                success: false,
                token_bytes: None,
                error: Some(e),
            },
        }
    }

    /// Inner implementation that returns Result for ergonomic error handling.
    async fn process_auth_inner(&self, request: &OrchestratorRequest) -> Result<Vec<u8>, String> {
        // 1. Generate ceremony session ID
        let session_id = generate_nonce();
        let mut session = CeremonySession::new(session_id);

        // 2. Build and send OPAQUE request
        let opaque_req = OpaqueRequest {
            username: request.username.clone(),
            password: request.password.clone(),
            ceremony_session_id: session_id,
            dpop_key_hash: request.dpop_key_hash,
        };

        let opaque_bytes = postcard::to_allocvec(&opaque_req)
            .map_err(|e| format!("serialize opaque request: {e}"))?;

        let mut opaque_transport = self.connect_opaque().await?;
        opaque_transport
            .send(&opaque_bytes)
            .await
            .map_err(|e| format!("send to OPAQUE: {e}"))?;

        let (_sender, opaque_resp_bytes) = opaque_transport
            .recv()
            .await
            .map_err(|e| format!("recv from OPAQUE: {e}"))?;

        let opaque_resp: OpaqueResponse = postcard::from_bytes(&opaque_resp_bytes)
            .map_err(|e| format!("deserialize opaque response: {e}"))?;

        if !opaque_resp.success {
            session
                .fail(opaque_resp.error.clone().unwrap_or_default())
                .ok();
            return Err(opaque_resp
                .error
                .unwrap_or_else(|| "OPAQUE auth failed".into()));
        }

        // 3. Add receipt to chain
        let receipt = opaque_resp.receipt.ok_or("OPAQUE success but no receipt")?;
        session.user_id = Some(receipt.user_id);
        session
            .receipt_chain
            .add_receipt(receipt)
            .map_err(|e| format!("receipt chain: {e}"))?;
        session.opaque_complete()?;

        // 4. Build and send TSS signing request
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;

        let claims = TokenClaims {
            sub: session.user_id.unwrap_or(Uuid::nil()),
            iss: [0xAA; 32],
            iat: now,
            exp: now + 30_000_000, // 30 seconds
            scope: 0x0000_000F,
            dpop_hash: request.dpop_key_hash,
            ceremony_id: session_id,
            tier: if request.tier == 0 { 2 } else { request.tier },
            ratchet_epoch: 0,
        };

        let signing_req = SigningRequest {
            receipts: session.receipt_chain.receipts().to_vec(),
            claims,
        };

        let signing_bytes = postcard::to_allocvec(&signing_req)
            .map_err(|e| format!("serialize signing request: {e}"))?;

        let mut tss_transport = self.connect_tss().await?;
        tss_transport
            .send(&signing_bytes)
            .await
            .map_err(|e| format!("send to TSS: {e}"))?;

        let (_sender, tss_resp_bytes) = tss_transport
            .recv()
            .await
            .map_err(|e| format!("recv from TSS: {e}"))?;

        let tss_resp: SigningResponse = postcard::from_bytes(&tss_resp_bytes)
            .map_err(|e| format!("deserialize signing response: {e}"))?;

        if !tss_resp.success {
            session
                .fail(tss_resp.error.clone().unwrap_or_default())
                .ok();
            return Err(tss_resp
                .error
                .unwrap_or_else(|| "TSS signing failed".into()));
        }

        session.tss_complete()?;

        tss_resp
            .token
            .ok_or_else(|| "TSS success but no token".into())
    }

    /// Start the orchestrator as a SHARD listener, processing auth requests
    /// from the Gateway.
    pub async fn run(&self, listen_addr: &str) -> Result<(), String> {
        let listener = ShardListener::bind(listen_addr, ModuleId::Orchestrator, self.hmac_key)
            .await
            .map_err(|e| format!("bind orchestrator listener: {e}"))?;

        tracing::info!("Orchestrator listening on {}", listen_addr);

        loop {
            let mut transport = listener
                .accept()
                .await
                .map_err(|e| format!("accept: {e}"))?;

            let (_sender, req_bytes) = transport
                .recv()
                .await
                .map_err(|e| format!("recv from gateway: {e}"))?;

            let request: OrchestratorRequest = match postcard::from_bytes(&req_bytes) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("bad request from gateway: {e}");
                    continue;
                }
            };

            let response = self.process_auth(&request).await;

            let resp_bytes =
                postcard::to_allocvec(&response).map_err(|e| format!("serialize response: {e}"))?;

            transport
                .send(&resp_bytes)
                .await
                .map_err(|e| format!("send to gateway: {e}"))?;
        }
    }
}
