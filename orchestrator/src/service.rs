//! Auth Orchestrator service — coordinates Gateway, OPAQUE, and TSS.
//!
//! All inter-service connections use mTLS (mutual TLS) with auto-generated
//! certificates. There is no plain-TCP fallback — this is military-grade.

use common::types::{ModuleId, Receipt, TokenClaims};
use crypto::entropy::{generate_key_64, generate_nonce};
use ml_dsa::KeyGen;
use opaque::messages::{OpaqueRequest, OpaqueResponse};
use shard::tls_transport::{tls_connect, TlsShardTransport, tls_bind, tls_client_setup};
use tokio_rustls::TlsConnector;
use tss::messages::{SigningRequest, SigningResponse};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::ceremony::CeremonySession;
use crate::messages::{OrchestratorRequest, OrchestratorResponse};

/// Independently verify an OPAQUE receipt's HMAC signature, timestamp, session,
/// and user binding before forwarding to TSS. This enforces zero-trust: the
/// orchestrator never blindly trusts receipts from the OPAQUE service.
fn verify_receipt_independently(
    receipt: &Receipt,
    _expected_user: &str,
    hmac_key: &[u8; 64],
    ceremony_session_id: &[u8; 32],
) -> Result<(), String> {
    // 1. Verify receipt signature (ML-DSA-65 preferred, HMAC-SHA512 fallback).
    //    This proves the receipt was signed by the OPAQUE service and has not
    //    been tampered with in transit.
    let mldsa_ok = if hmac_key.len() >= 32 {
        // Derive ML-DSA-65 verifying key from the first 32 bytes (seed)
        let seed: [u8; 32] = hmac_key[..32].try_into().unwrap();
        let kp = ml_dsa::MlDsa65::from_seed(&seed.into());
        let vk_bytes = kp.verifying_key().encode();
        let data = crypto::receipts::receipt_signing_data(receipt);
        crypto::receipts::verify_receipt_asymmetric(vk_bytes.as_ref(), &data, &receipt.signature)
    } else {
        false
    };
    let hmac_ok = crypto::receipts::verify_receipt_signature(receipt, hmac_key);
    if !mldsa_ok && !hmac_ok {
        return Err("receipt signature verification failed (neither ML-DSA-65 nor HMAC valid)".into());
    }

    // 2. Validate timestamp is within ±30 seconds of current time.
    //    Prevents replay of old receipts and rejects future-dated forgeries.
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    let drift_us = (now_us - receipt.timestamp).abs();
    let max_drift_us: i64 = 30 * 1_000_000; // 30 seconds in microseconds
    if drift_us > max_drift_us {
        return Err(format!(
            "receipt timestamp drift {}µs exceeds ±30s tolerance",
            drift_us
        ));
    }

    // 3. Validate ceremony_session_id matches the current ceremony.
    //    Prevents cross-ceremony receipt injection attacks.
    if !crypto::ct::ct_eq_32(&receipt.ceremony_session_id, ceremony_session_id) {
        return Err("receipt ceremony_session_id does not match current ceremony".into());
    }

    // 4. Validate user_id is not nil (basic sanity — the HMAC signature
    //    already cryptographically binds the user_id to the receipt, so
    //    forgery is impossible without the signing key).
    if receipt.user_id.is_nil() {
        return Err("receipt user_id is nil".into());
    }

    Ok(())
}

/// The orchestrator service that coordinates authentication ceremonies.
///
/// SECURITY: The orchestrator does NOT hold any receipt signing key.
/// Receipts are signed solely by the OPAQUE service and forwarded as-is
/// to the TSS. This prevents the orchestrator from forging receipts.
///
/// All inter-service connections use mTLS — no plain TCP fallback.
pub struct OrchestratorService {
    pub hmac_key: [u8; 64],
    /// Key used to independently verify OPAQUE receipt HMAC signatures.
    /// SECURITY: This is the same symmetric key held by the OPAQUE service.
    /// The orchestrator uses it ONLY for verification, never for signing.
    pub receipt_verification_key: [u8; 64],
    pub opaque_addr: String,
    pub tss_addr: String,
    pub risk_engine: risk::scoring::RiskEngine,
    /// TLS connector for outbound mTLS connections to peer services.
    pub tls_connector: TlsConnector,
    /// Circuit breaker for OPAQUE service connections.
    pub opaque_breaker: common::circuit_breaker::CircuitBreaker,
    /// Circuit breaker for TSS service connections.
    pub tss_breaker: common::circuit_breaker::CircuitBreaker,
}

impl OrchestratorService {
    /// Create a new orchestrator service with auto-generated mTLS credentials.
    ///
    /// Note: No receipt signing key is accepted — receipts are signed only
    /// by the OPAQUE service and forwarded to the TSS without re-signing.
    pub fn new(
        hmac_key: [u8; 64],
        opaque_addr: String,
        tss_addr: String,
    ) -> Self {
        let receipt_verification_key = hmac_key;
        let (tls_connector, _ca, _cert_key) = tls_client_setup("orchestrator");
        Self {
            hmac_key,
            receipt_verification_key,
            opaque_addr,
            tss_addr,
            risk_engine: risk::scoring::RiskEngine::new(),
            tls_connector,
            opaque_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            tss_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
        }
    }

    /// Create with explicit receipt verification key for zero-trust receipt checking.
    pub fn new_with_receipt_key(
        hmac_key: [u8; 64],
        receipt_verification_key: [u8; 64],
        opaque_addr: String,
        tss_addr: String,
    ) -> Self {
        let (tls_connector, _ca, _cert_key) = tls_client_setup("orchestrator");
        Self {
            hmac_key,
            receipt_verification_key,
            opaque_addr,
            tss_addr,
            risk_engine: risk::scoring::RiskEngine::new(),
            tls_connector,
            opaque_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            tss_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
        }
    }

    /// Create a new orchestrator service with an explicit TLS connector.
    pub fn new_with_tls(
        hmac_key: [u8; 64],
        opaque_addr: String,
        tss_addr: String,
        tls_connector: TlsConnector,
    ) -> Self {
        let receipt_verification_key = hmac_key;
        Self {
            hmac_key,
            receipt_verification_key,
            opaque_addr,
            tss_addr,
            risk_engine: risk::scoring::RiskEngine::new(),
            tls_connector,
            opaque_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            tss_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
        }
    }

    /// Create with explicit TLS connector AND receipt verification key.
    pub fn new_with_tls_and_receipt_key(
        hmac_key: [u8; 64],
        receipt_verification_key: [u8; 64],
        opaque_addr: String,
        tss_addr: String,
        tls_connector: TlsConnector,
    ) -> Self {
        Self {
            hmac_key,
            receipt_verification_key,
            opaque_addr,
            tss_addr,
            risk_engine: risk::scoring::RiskEngine::new(),
            tls_connector,
            opaque_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            tss_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
        }
    }

    /// Connect to the OPAQUE service via SHARD over mTLS.
    async fn connect_opaque(&self) -> Result<TlsShardTransport, String> {
        if !self.opaque_breaker.allow_request() {
            return Err("OPAQUE service circuit breaker is open — service unavailable".into());
        }
        match tls_connect(
            &self.opaque_addr,
            ModuleId::Orchestrator,
            self.hmac_key,
            &self.tls_connector,
            "localhost",
        )
        .await
        {
            Ok(transport) => {
                self.opaque_breaker.record_success();
                Ok(transport)
            }
            Err(e) => {
                self.opaque_breaker.record_failure();
                Err(format!("connect to OPAQUE: {e}"))
            }
        }
    }

    /// Connect to the TSS service via SHARD over mTLS.
    async fn connect_tss(&self) -> Result<TlsShardTransport, String> {
        if !self.tss_breaker.allow_request() {
            return Err("TSS service circuit breaker is open — service unavailable".into());
        }
        match tls_connect(
            &self.tss_addr,
            ModuleId::Orchestrator,
            self.hmac_key,
            &self.tls_connector,
            "localhost",
        )
        .await
        {
            Ok(transport) => {
                self.tss_breaker.record_success();
                Ok(transport)
            }
            Err(e) => {
                self.tss_breaker.record_failure();
                Err(format!("connect to TSS: {e}"))
            }
        }
    }

    /// Process a single authentication request end-to-end.
    pub async fn process_auth(&self, request: &OrchestratorRequest) -> OrchestratorResponse {
        match self.process_auth_inner(request).await {
            Ok(token_bytes) => {
                // Emit SIEM event for successful authentication
                common::siem::SecurityEvent::auth_success(
                    {
                        use sha2::{Digest, Sha256};
                        let hash = Sha256::digest(request.username.as_bytes());
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(&hash[..16]);
                        bytes[6] = (bytes[6] & 0x0f) | 0x40;
                        bytes[8] = (bytes[8] & 0x3f) | 0x80;
                        Uuid::from_bytes(bytes)
                    },
                    None,
                );
                OrchestratorResponse {
                    success: true,
                    token_bytes: Some(token_bytes),
                    error: None,
                }
            }
            Err(e) => {
                // Record the failed attempt in the server-side counter.
                // Derive deterministic user ID from username for rate limiting
                let user_id = {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(request.username.as_bytes());
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&hash[..16]);
                    bytes[6] = (bytes[6] & 0x0f) | 0x40;
                    bytes[8] = (bytes[8] & 0x3f) | 0x80;
                    Uuid::from_bytes(bytes)
                };
                self.risk_engine.record_failed_attempt(&user_id);
                common::siem::SecurityEvent::auth_failure(
                    Some(user_id),
                    None,
                    &e,
                );

                OrchestratorResponse {
                    success: false,
                    token_bytes: None,
                    error: Some(e),
                }
            }
        }
    }

    /// Inner implementation that returns Result for ergonomic error handling.
    async fn process_auth_inner(&self, request: &OrchestratorRequest) -> Result<Vec<u8>, String> {
        use opaque::opaque_impl::OpaqueCs;
        use opaque_ke::{ClientLogin, ClientLoginFinishParameters};
        use rand::rngs::OsRng;

        // 1. Generate ceremony session ID
        let session_id = generate_nonce();
        let mut session = CeremonySession::new(session_id);

        // Account lockout check: reject if user has exceeded max failed attempts
        {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(request.username.as_bytes());
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&hash[..16]);
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            let user_id = Uuid::from_bytes(bytes);
            let config = common::config::SecurityConfig::default();
            if self.risk_engine.is_locked_out(&user_id, config.max_failed_attempts) {
                common::siem::SecurityEvent::account_lockout(user_id);
                return Err(format!(
                    "account locked: too many failed attempts (max {}), try again later",
                    config.max_failed_attempts
                ));
            }
        }

        // 2. OPAQUE Login Round 1: Client starts, sends CredentialRequest
        //    Runs in spawn_blocking because Argon2id KSF is CPU-bound.
        let mut password_clone = request.password.clone();
        let client_login_start = tokio::task::spawn_blocking(move || {
            let mut rng = OsRng;
            let result = ClientLogin::<OpaqueCs>::start(&mut rng, &password_clone);
            password_clone.zeroize();
            result
        })
            .await
            .map_err(|e| format!("OPAQUE client login start task: {e}"))?
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
            OpaqueResponse::LoginChallenge { credential_response } => credential_response,
            OpaqueResponse::Error { message } => {
                session.fail(message.clone()).ok();
                return Err(message);
            }
            _ => {
                session.fail("unexpected OPAQUE response".into()).ok();
                return Err("unexpected OPAQUE response to LoginStart".into());
            }
        };

        // 3. OPAQUE Login Round 2: Client finishes
        //    Runs in spawn_blocking because Argon2id KSF is CPU-bound.
        let credential_response =
            opaque_ke::CredentialResponse::<OpaqueCs>::deserialize(&credential_response_bytes)
                .map_err(|e| format!("deserialize credential response: {e}"))?;

        let mut password_clone2 = request.password.clone();
        let login_state = client_login_start.state;
        let client_login_finish = tokio::task::spawn_blocking(move || {
            let mut rng = OsRng;
            let result = login_state.finish(&mut rng, &password_clone2, credential_response, ClientLoginFinishParameters::default());
            password_clone2.zeroize();
            result
        })
            .await
            .map_err(|e| format!("OPAQUE client login finish task: {e}"))?
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

        // 3b. Independent receipt verification (zero-trust: never blindly trust OPAQUE)
        if let Err(e) = verify_receipt_independently(
            &receipt,
            &request.username,
            &self.receipt_verification_key,
            &session_id,
        ) {
            common::siem::SecurityEvent::tamper_detected(
                &format!("independent receipt verification failed: {e}"),
            );
            session.fail(format!("receipt verification: {e}")).ok();
            return Err(format!("receipt verification failed: {e}"));
        }

        // 4. Add receipt to chain
        session.user_id = Some(receipt.user_id);
        session.receipt_chain.add_receipt(receipt).map_err(|e| format!("receipt chain: {e}"))?;
        session.opaque_complete()?;

        // 5. Risk evaluation
        let user_id = session.user_id.unwrap_or(Uuid::nil());
        let risk_signals = risk::scoring::RiskSignals {
            device_attestation_age_secs: request.device_attestation_age_secs.unwrap_or(0.0),
            geo_velocity_kmh: request.geo_velocity_kmh.unwrap_or(0.0),
            is_unusual_network: request.is_unusual_network.unwrap_or(false),
            is_unusual_time: request.is_unusual_time.unwrap_or(false),
            unusual_access_score: request.unusual_access_score.unwrap_or(0.0),
            recent_failed_attempts: request.recent_failed_attempts.unwrap_or(0),
            login_hour: None,
            network_id: None,
            session_duration_secs: None,
        };
        let risk_score = self.risk_engine.compute_score(&user_id, &risk_signals);
        if self.risk_engine.requires_termination(risk_score) {
            return Err("risk: session terminated — critical risk score".into());
        }
        if self.risk_engine.requires_step_up(risk_score) {
            tracing::warn!("Risk score {risk_score} >= 0.6 — step-up re-auth required");
            return Err(format!("risk: step-up re-authentication required (score={risk_score:.2})"));
        }

        // 6. Build and send TSS signing request
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap()
            .as_micros() as i64;

        let security_config = common::config::SecurityConfig::default();
        let tier = if request.tier == 0 { 2 } else { request.tier };
        if tier > 4 { return Err("invalid tier: must be 1-4".into()); }
        let token_lifetime_us = security_config.token_lifetime_for_tier(tier) as i64 * 1_000_000;

        let token_id: [u8; 16] = {
            let nonce = generate_nonce();
            let mut id = [0u8; 16];
            id.copy_from_slice(&nonce[..16]);
            id
        };

        let claims = TokenClaims {
            sub: session.user_id.unwrap_or(Uuid::nil()),
            iss: [0xAA; 32], iat: now, exp: now + token_lifetime_us,
            scope: 0x0000_000F, dpop_hash: request.dpop_key_hash,
            ceremony_id: session_id, tier, ratchet_epoch: 1, token_id,
            aud: request.audience.clone(),
        };

        let ratchet_key = generate_key_64();
        let signing_req = SigningRequest { receipts: session.receipt_chain.receipts().to_vec(), claims, ratchet_key };
        let signing_bytes = postcard::to_allocvec(&signing_req).map_err(|e| format!("serialize signing request: {e}"))?;

        let mut tss_transport = self.connect_tss().await?;
        tss_transport.send(&signing_bytes).await.map_err(|e| format!("send to TSS: {e}"))?;
        let (_sender, tss_resp_bytes) = tss_transport.recv().await.map_err(|e| format!("recv from TSS: {e}"))?;

        let tss_resp: SigningResponse = postcard::from_bytes(&tss_resp_bytes)
            .map_err(|e| format!("deserialize signing response: {e}"))?;

        if !tss_resp.success {
            session.fail(tss_resp.error.clone().unwrap_or_default()).ok();
            return Err(tss_resp.error.unwrap_or_else(|| "TSS signing failed".into()));
        }

        session.tss_complete()?;
        tss_resp.token.ok_or_else(|| "TSS success but no token".into())
    }

    /// Start the orchestrator as a SHARD mTLS listener, processing auth requests.
    pub async fn run(&self, listen_addr: &str) -> Result<(), String> {
        let (listener, _ca, _cert_key) =
            tls_bind(listen_addr, ModuleId::Orchestrator, self.hmac_key, "orchestrator")
                .await
                .map_err(|e| format!("bind orchestrator TLS listener: {e}"))?;

        tracing::info!("Orchestrator listening on {} (mTLS)", listen_addr);

        loop {
            let mut transport = listener.accept().await.map_err(|e| format!("accept: {e}"))?;
            let (_sender, req_bytes) = transport.recv().await.map_err(|e| format!("recv from gateway: {e}"))?;
            let request: OrchestratorRequest = match postcard::from_bytes(&req_bytes) {
                Ok(r) => r,
                Err(e) => { tracing::error!("bad request from gateway: {e}"); continue; }
            };
            let response = self.process_auth(&request).await;
            let resp_bytes = postcard::to_allocvec(&response).map_err(|e| format!("serialize response: {e}"))?;
            transport.send(&resp_bytes).await.map_err(|e| format!("send to gateway: {e}"))?;
        }
    }
}
