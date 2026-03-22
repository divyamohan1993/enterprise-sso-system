//! Auth Orchestrator service — coordinates Gateway, OPAQUE, and TSS.

use common::types::{ModuleId, TokenClaims};
use crypto::entropy::{generate_key_64, generate_nonce};
use opaque::messages::{OpaqueRequest, OpaqueResponse};
use shard::transport::{connect, ShardListener, ShardTransport};
use tss::messages::{SigningRequest, SigningResponse};
use uuid::Uuid;

use crate::ceremony::CeremonySession;
use crate::messages::{OrchestratorRequest, OrchestratorResponse};

/// The orchestrator service that coordinates authentication ceremonies.
pub struct OrchestratorService {
    pub hmac_key: [u8; 64],
    pub opaque_addr: String,
    pub tss_addr: String,
    pub receipt_signing_key: [u8; 64],
    pub risk_engine: risk::scoring::RiskEngine,
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
            risk_engine: risk::scoring::RiskEngine::new(),
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
    ///
    /// The orchestrator acts as the OPAQUE client: it receives the password
    /// from the gateway and runs the client side of the OPAQUE protocol.
    /// The OPAQUE service (server side) never sees the plaintext password.
    async fn process_auth_inner(&self, request: &OrchestratorRequest) -> Result<Vec<u8>, String> {
        use opaque::opaque_impl::OpaqueCs;
        use opaque_ke::{ClientLogin, ClientLoginFinishParameters};
        use rand::rngs::OsRng;

        // 1. Generate ceremony session ID
        let session_id = generate_nonce();
        let mut session = CeremonySession::new(session_id);

        // 2. OPAQUE Login Round 1: Client starts, sends CredentialRequest
        let mut rng = OsRng;
        let client_login_start = ClientLogin::<OpaqueCs>::start(&mut rng, &request.password)
            .map_err(|e| format!("OPAQUE client login start: {e}"))?;

        let credential_request_bytes = client_login_start.message.serialize().to_vec();

        let login_start_req = OpaqueRequest::LoginStart {
            username: request.username.clone(),
            credential_request: credential_request_bytes,
            ceremony_session_id: session_id,
            dpop_key_hash: request.dpop_key_hash,
        };

        let login_start_bytes = postcard::to_allocvec(&login_start_req)
            .map_err(|e| format!("serialize login start: {e}"))?;

        let mut opaque_transport = self.connect_opaque().await?;
        opaque_transport
            .send(&login_start_bytes)
            .await
            .map_err(|e| format!("send login start to OPAQUE: {e}"))?;

        let (_sender, opaque_resp1_bytes) = opaque_transport
            .recv()
            .await
            .map_err(|e| format!("recv login challenge from OPAQUE: {e}"))?;

        let opaque_resp1: OpaqueResponse = postcard::from_bytes(&opaque_resp1_bytes)
            .map_err(|e| format!("deserialize login challenge: {e}"))?;

        let credential_response_bytes = match opaque_resp1 {
            OpaqueResponse::LoginChallenge {
                credential_response,
            } => credential_response,
            OpaqueResponse::Error { message } => {
                session.fail(message.clone()).ok();
                return Err(message);
            }
            _ => {
                session.fail("unexpected OPAQUE response".into()).ok();
                return Err("unexpected OPAQUE response to LoginStart".into());
            }
        };

        // 3. OPAQUE Login Round 2: Client finishes, sends CredentialFinalization
        let credential_response =
            opaque_ke::CredentialResponse::<OpaqueCs>::deserialize(&credential_response_bytes)
                .map_err(|e| format!("deserialize credential response: {e}"))?;

        let client_login_finish = client_login_start
            .state
            .finish(
                &mut rng,
                &request.password,
                credential_response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|e| {
                session.fail(format!("OPAQUE login finish: {e}")).ok();
                format!("OPAQUE client login finish: {e}")
            })?;

        let credential_finalization_bytes = client_login_finish.message.serialize().to_vec();

        let login_finish_req = OpaqueRequest::LoginFinish {
            credential_finalization: credential_finalization_bytes,
        };

        let login_finish_bytes = postcard::to_allocvec(&login_finish_req)
            .map_err(|e| format!("serialize login finish: {e}"))?;

        opaque_transport
            .send(&login_finish_bytes)
            .await
            .map_err(|e| format!("send login finish to OPAQUE: {e}"))?;

        let (_sender, opaque_resp2_bytes) = opaque_transport
            .recv()
            .await
            .map_err(|e| format!("recv login result from OPAQUE: {e}"))?;

        let opaque_resp2: OpaqueResponse = postcard::from_bytes(&opaque_resp2_bytes)
            .map_err(|e| format!("deserialize login result: {e}"))?;

        let receipt = match opaque_resp2 {
            OpaqueResponse::LoginSuccess { receipt } => receipt,
            OpaqueResponse::Error { message } => {
                session.fail(message.clone()).ok();
                return Err(message);
            }
            _ => {
                session.fail("unexpected OPAQUE response".into()).ok();
                return Err("unexpected OPAQUE response to LoginFinish".into());
            }
        };

        // 4. Add receipt to chain
        session.user_id = Some(receipt.user_id);
        session
            .receipt_chain
            .add_receipt(receipt)
            .map_err(|e| format!("receipt chain: {e}"))?;
        session.opaque_complete()?;

        // 5. Risk evaluation
        let user_id = session.user_id.unwrap_or(Uuid::nil());
        let risk_signals = risk::scoring::RiskSignals {
            device_attestation_age_secs: 0.0,
            geo_velocity_kmh: 0.0,
            is_unusual_network: false,
            is_unusual_time: false,
            unusual_access_score: 0.0,
            recent_failed_attempts: 0,
        };
        let risk_score = self.risk_engine.compute_score(&user_id, &risk_signals);
        if self.risk_engine.requires_termination(risk_score) {
            return Err("risk: session terminated — critical risk score".into());
        }
        if self.risk_engine.requires_step_up(risk_score) {
            tracing::warn!("Risk score {risk_score} >= 0.6 — step-up re-auth required");
        }

        // 6. Build and send TSS signing request
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;

        // Use SecurityConfig for tier-based token lifetimes (spec Section 5)
        let security_config = common::config::SecurityConfig::default();
        let tier = if request.tier == 0 { 2 } else { request.tier };
        let token_lifetime_us = security_config.token_lifetime_for_tier(tier) as i64 * 1_000_000;

        let claims = TokenClaims {
            sub: session.user_id.unwrap_or(Uuid::nil()),
            iss: [0xAA; 32],
            iat: now,
            exp: now + token_lifetime_us,
            scope: 0x0000_000F,
            dpop_hash: request.dpop_key_hash,
            ceremony_id: session_id,
            tier,
            ratchet_epoch: 0,
        };

        // TODO: Use X-Wing shared secret from gateway as ratchet initial key
        // For now: generate random initial key
        let ratchet_key = generate_key_64();

        let signing_req = SigningRequest {
            receipts: session.receipt_chain.receipts().to_vec(),
            claims,
            ratchet_key,
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
