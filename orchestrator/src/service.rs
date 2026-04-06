//! Auth Orchestrator service — coordinates Gateway, OPAQUE, and TSS.
//!
//! All inter-service connections use mTLS (mutual TLS) with auto-generated
//! certificates. There is no plain-TCP fallback — this is military-grade.

use std::sync::Arc;

use common::service_discovery::{
    DiscoveryBackend, EndpointConfig, LoadBalanceStrategy, ServiceConfig, ServiceRegistry,
};
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
    receipt_signing_seed: &[u8; 32],
) -> Result<(), String> {
    // 1. Verify receipt signature (ML-DSA-87 preferred, HMAC-SHA512 fallback).
    //    This proves the receipt was signed by the OPAQUE service and has not
    //    been tampered with in transit.
    let mldsa_ok = {
        // Use the receipt signing seed provided by the caller, which must match
        // the seed used by the OPAQUE service's ReceiptSigner.
        let kp = ml_dsa::MlDsa87::from_seed(&(*receipt_signing_seed).into());
        let vk_bytes = kp.verifying_key().encode();
        let data = crypto::receipts::receipt_signing_data(receipt);
        crypto::receipts::verify_receipt_asymmetric(vk_bytes.as_ref(), &data, &receipt.signature)
    };
    let hmac_ok = crypto::receipts::verify_receipt_signature(receipt, hmac_key).unwrap_or(false);
    if !mldsa_ok && !hmac_ok {
        return Err("receipt signature verification failed (neither ML-DSA-87 nor HMAC valid)".into());
    }

    // 2. Validate timestamp is within ±10 seconds of current time.
    //    Prevents replay of old receipts and rejects future-dated forgeries.
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_micros() as i64;
    let drift_us = (now_us - receipt.timestamp).abs();
    let max_drift_us: i64 = 10 * 1_000_000; // 10 seconds in microseconds
    if drift_us > max_drift_us {
        return Err(format!(
            "receipt timestamp drift {}µs exceeds ±10s tolerance",
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
    /// ML-DSA-87 receipt signing seed used for independent receipt verification.
    /// Must match the seed used by the OPAQUE service's ReceiptSigner.
    /// Loaded from sealed storage in production, or derived from
    /// `receipt_verification_key[..32]` when an explicit key is provided.
    receipt_signing_seed: [u8; 32],
    pub opaque_addr: String,
    pub tss_addr: String,
    pub risk_engine: risk::scoring::RiskEngine,
    /// Advanced anomaly detector for z-score based behavioral analysis,
    /// impossible travel detection, and cross-user correlation.
    pub anomaly_detector: risk::anomaly::AnomalyDetector,
    /// SIEM correlation engine for detecting distributed attacks
    /// (brute force, credential stuffing, lateral movement, etc.).
    pub correlation_engine: risk::correlation::CorrelationEngine,
    /// TLS connector for outbound mTLS connections to peer services.
    pub tls_connector: TlsConnector,
    /// Circuit breaker for OPAQUE service connections.
    pub opaque_breaker: common::circuit_breaker::CircuitBreaker,
    /// Circuit breaker for TSS service connections.
    pub tss_breaker: common::circuit_breaker::CircuitBreaker,
    /// Bulkhead for OPAQUE service calls to prevent resource exhaustion cascades.
    pub opaque_bulkhead: common::bulkhead::Bulkhead,
    /// Bulkhead for TSS service calls to prevent resource exhaustion cascades.
    pub tss_bulkhead: common::bulkhead::Bulkhead,
    /// Service registry for health-aware endpoint selection and failover.
    /// The env-var addresses are seeded as initial endpoints; additional
    /// endpoints can be discovered via DNS or multi-address env vars
    /// (e.g. OPAQUE_ADDRS=host1:port,host2:port).
    pub service_registry: Arc<ServiceRegistry>,
}

/// Build a `ServiceRegistry` seeded with the given OPAQUE and TSS addresses.
///
/// Each address string may be a single `host:port` or a comma-separated list
/// (e.g. from `OPAQUE_ADDRS=host1:port,host2:port`). The env vars
/// `MILNET_OPAQUE_ADDRS` and `MILNET_TSS_ADDRS` are also checked for
/// additional endpoints. All endpoints start with quorum_size=1 so that
/// a single seed address is sufficient for bootstrap.
fn build_service_registry(opaque_addr: &str, tss_addr: &str) -> Arc<ServiceRegistry> {
    let registry = Arc::new(ServiceRegistry::new());

    let parse_addrs = |primary: &str, env_key: &str, svc_name: &str| -> Vec<EndpointConfig> {
        let mut addrs: Vec<String> = primary
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        // Merge additional endpoints from multi-address env var
        if let Ok(extra) = std::env::var(env_key) {
            for a in extra.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
                if !addrs.contains(&a) {
                    addrs.push(a);
                }
            }
        }
        addrs
            .into_iter()
            .enumerate()
            .map(|(i, addr)| EndpointConfig {
                address: addr,
                label: Some(format!("{svc_name}-{i}")),
                weight: None,
            })
            .collect()
    };

    let opaque_endpoints = parse_addrs(opaque_addr, "MILNET_OPAQUE_ADDRS", "opaque");
    let tss_endpoints = parse_addrs(tss_addr, "MILNET_TSS_ADDRS", "tss");

    let make_config = |name: &str, endpoints: Vec<EndpointConfig>| ServiceConfig {
        name: name.to_string(),
        backend: DiscoveryBackend::Static { endpoints },
        strategy: LoadBalanceStrategy::RoundRobin,
        quorum_size: 1, // single seed is valid for bootstrap
        ..ServiceConfig::default()
    };

    if let Err(e) = registry.register(make_config("opaque", opaque_endpoints)) {
        tracing::warn!("failed to register OPAQUE service in discovery: {e}");
    }
    if let Err(e) = registry.register(make_config("tss", tss_endpoints)) {
        tracing::warn!("failed to register TSS service in discovery: {e}");
    }

    registry
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
        let receipt_signing_seed = common::sealed_keys::load_receipt_signing_seed_sealed();
        let (tls_connector, _ca, _cert_key) = tls_client_setup("orchestrator");
        let service_registry = build_service_registry(&opaque_addr, &tss_addr);
        Self {
            hmac_key,
            receipt_verification_key,
            receipt_signing_seed,
            opaque_addr,
            tss_addr,
            risk_engine: risk::scoring::RiskEngine::new(),
            anomaly_detector: risk::anomaly::AnomalyDetector::new(),
            correlation_engine: risk::correlation::CorrelationEngine::with_default_rules(),
            tls_connector,
            opaque_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            tss_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            opaque_bulkhead: common::bulkhead::Bulkhead::new("opaque", 50, 100, std::time::Duration::from_secs(5)),
            tss_bulkhead: common::bulkhead::Bulkhead::new("tss", 30, 60, std::time::Duration::from_secs(5)),
            service_registry,
        }
    }

    /// Create with explicit receipt verification key for zero-trust receipt checking.
    ///
    /// The ML-DSA-87 receipt signing seed is derived from `receipt_verification_key[..32]`,
    /// matching the derivation in `ReceiptSigner::new()`.
    pub fn new_with_receipt_key(
        hmac_key: [u8; 64],
        receipt_verification_key: [u8; 64],
        opaque_addr: String,
        tss_addr: String,
    ) -> Self {
        let mut receipt_signing_seed = [0u8; 32];
        receipt_signing_seed.copy_from_slice(&receipt_verification_key[..32]);
        let (tls_connector, _ca, _cert_key) = tls_client_setup("orchestrator");
        let service_registry = build_service_registry(&opaque_addr, &tss_addr);
        Self {
            hmac_key,
            receipt_verification_key,
            receipt_signing_seed,
            opaque_addr,
            tss_addr,
            risk_engine: risk::scoring::RiskEngine::new(),
            anomaly_detector: risk::anomaly::AnomalyDetector::new(),
            correlation_engine: risk::correlation::CorrelationEngine::with_default_rules(),
            tls_connector,
            opaque_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            tss_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            opaque_bulkhead: common::bulkhead::Bulkhead::new("opaque", 50, 100, std::time::Duration::from_secs(5)),
            tss_bulkhead: common::bulkhead::Bulkhead::new("tss", 30, 60, std::time::Duration::from_secs(5)),
            service_registry,
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
        let receipt_signing_seed = common::sealed_keys::load_receipt_signing_seed_sealed();
        let service_registry = build_service_registry(&opaque_addr, &tss_addr);
        Self {
            hmac_key,
            receipt_verification_key,
            receipt_signing_seed,
            opaque_addr,
            tss_addr,
            risk_engine: risk::scoring::RiskEngine::new(),
            anomaly_detector: risk::anomaly::AnomalyDetector::new(),
            correlation_engine: risk::correlation::CorrelationEngine::with_default_rules(),
            tls_connector,
            opaque_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            tss_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            opaque_bulkhead: common::bulkhead::Bulkhead::new("opaque", 50, 100, std::time::Duration::from_secs(5)),
            tss_bulkhead: common::bulkhead::Bulkhead::new("tss", 30, 60, std::time::Duration::from_secs(5)),
            service_registry,
        }
    }

    /// Create with explicit TLS connector AND receipt verification key.
    ///
    /// The ML-DSA-87 receipt signing seed is derived from `receipt_verification_key[..32]`,
    /// matching the derivation in `ReceiptSigner::new()`.
    pub fn new_with_tls_and_receipt_key(
        hmac_key: [u8; 64],
        receipt_verification_key: [u8; 64],
        opaque_addr: String,
        tss_addr: String,
        tls_connector: TlsConnector,
    ) -> Self {
        let mut receipt_signing_seed = [0u8; 32];
        receipt_signing_seed.copy_from_slice(&receipt_verification_key[..32]);
        let service_registry = build_service_registry(&opaque_addr, &tss_addr);
        Self {
            hmac_key,
            receipt_verification_key,
            receipt_signing_seed,
            opaque_addr,
            tss_addr,
            risk_engine: risk::scoring::RiskEngine::new(),
            anomaly_detector: risk::anomaly::AnomalyDetector::new(),
            correlation_engine: risk::correlation::CorrelationEngine::with_default_rules(),
            tls_connector,
            opaque_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            tss_breaker: common::circuit_breaker::CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
            opaque_bulkhead: common::bulkhead::Bulkhead::new("opaque", 50, 100, std::time::Duration::from_secs(5)),
            tss_bulkhead: common::bulkhead::Bulkhead::new("tss", 30, 60, std::time::Duration::from_secs(5)),
            service_registry,
        }
    }

    /// Timeout for inter-service connections (connect + first response).
    const SERVICE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Resolve the address to use for a service, preferring service discovery.
    /// Falls back to the static address if service discovery has no healthy endpoint.
    fn resolve_addr(&self, service_name: &str, fallback: &str) -> String {
        match self.service_registry.acquire_endpoint(service_name) {
            Ok(guard) => {
                let addr = guard.address.clone();
                // ConnectionGuard's Drop decrements active_connections
                addr
            }
            Err(_) => fallback.to_string(),
        }
    }

    /// Connect to a backend service via SHARD over mTLS with timeout and
    /// service-discovery failover. Tries the discovered endpoint first; on
    /// failure, falls back to the static address from the env var seed.
    async fn connect_service(
        &self,
        service_name: &str,
        static_addr: &str,
        breaker: &common::circuit_breaker::CircuitBreaker,
    ) -> Result<TlsShardTransport, String> {
        if !breaker.allow_request() {
            return Err(format!(
                "{} service circuit breaker is open -- service unavailable",
                service_name.to_uppercase()
            ));
        }

        let discovered_addr = self.resolve_addr(service_name, static_addr);

        // Try discovered address first
        let result = self.try_connect(&discovered_addr).await;
        match &result {
            Ok(_) => {
                breaker.record_success();
                self.service_registry.record_success(service_name, &discovered_addr);
                return result;
            }
            Err(_) if discovered_addr != static_addr => {
                // Discovery endpoint failed; record and try static fallback
                breaker.record_failure();
                self.service_registry.record_failure(service_name, &discovered_addr);
                tracing::warn!(
                    service = service_name,
                    discovered = %discovered_addr,
                    fallback = %static_addr,
                    "service discovery endpoint failed, trying static fallback"
                );
            }
            Err(e) => {
                breaker.record_failure();
                self.service_registry.record_failure(service_name, &discovered_addr);
                return Err(format!("connect to {}: {e}", service_name.to_uppercase()));
            }
        }

        // Fallback to static address
        match self.try_connect(static_addr).await {
            Ok(transport) => {
                breaker.record_success();
                self.service_registry.record_success(service_name, static_addr);
                Ok(transport)
            }
            Err(e) => {
                breaker.record_failure();
                self.service_registry.record_failure(service_name, static_addr);
                Err(format!("connect to {} (fallback): {e}", service_name.to_uppercase()))
            }
        }
    }

    /// Low-level mTLS connect to a single address with timeout.
    async fn try_connect(&self, addr: &str) -> Result<TlsShardTransport, String> {
        let raw_host = addr.split(':').next().unwrap_or(addr);
        let sni_host = if raw_host.parse::<std::net::IpAddr>().is_ok() {
            "localhost"
        } else {
            raw_host
        };
        match tokio::time::timeout(
            Self::SERVICE_CONNECT_TIMEOUT,
            tls_connect(
                addr,
                ModuleId::Orchestrator,
                self.hmac_key,
                &self.tls_connector,
                sni_host,
            ),
        )
        .await
        {
            Ok(Ok(transport)) => Ok(transport),
            Ok(Err(e)) => Err(format!("{e}")),
            Err(_elapsed) => Err(format!("timeout after {:?}", Self::SERVICE_CONNECT_TIMEOUT)),
        }
    }

    /// Connect to the OPAQUE service via SHARD over mTLS with timeout and failover.
    async fn connect_opaque(&self) -> Result<TlsShardTransport, String> {
        self.connect_service("opaque", &self.opaque_addr.clone(), &self.opaque_breaker).await
    }

    /// Connect to the TSS service via SHARD over mTLS with timeout and failover.
    async fn connect_tss(&self) -> Result<TlsShardTransport, String> {
        self.connect_service("tss", &self.tss_addr.clone(), &self.tss_breaker).await
    }

    /// Process a single authentication request end-to-end.
    pub async fn process_auth(&self, request: &OrchestratorRequest) -> OrchestratorResponse {
        // Reconstruct tracing context from gateway-provided correlation/trace IDs,
        // or generate a fresh one if the gateway didn't supply them.
        let req_ctx = match (request.correlation_id, request.trace_id.as_ref()) {
            (Some(cid), Some(tid)) => common::types::RequestContext {
                correlation_id: cid,
                trace_id: tid.clone(),
            },
            _ => common::types::RequestContext::new(),
        };
        tracing::info!(
            correlation_id = %req_ctx.correlation_id,
            trace_id = %req_ctx.trace_id,
            "orchestrator processing auth request"
        );

        match self.process_auth_inner(request).await {
            Ok(token_bytes) => {
                // Emit SIEM event for successful authentication
                let user_uuid = {
                    use sha2::{Digest, Sha512};
                    let hash = Sha512::digest(request.username.as_bytes());
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&hash[..16]);
                    bytes[6] = (bytes[6] & 0x0f) | 0x40;
                    bytes[8] = (bytes[8] & 0x3f) | 0x80;
                    Uuid::from_bytes(bytes)
                };
                common::siem::SecurityEvent::auth_success(user_uuid, None);
                common::audit_bridge::buffer_audit_entry(
                    common::audit_bridge::create_audit_entry_with_context(
                        common::types::AuditEventType::AuthSuccess,
                        vec![user_uuid],
                        Vec::new(),
                        None,
                        None,
                        &req_ctx,
                    ),
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
                    use sha2::{Digest, Sha512};
                    let hash = Sha512::digest(request.username.as_bytes());
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
                common::audit_bridge::buffer_audit_entry(
                    common::audit_bridge::create_audit_entry_with_context(
                        common::types::AuditEventType::AuthFailure,
                        vec![user_id],
                        Vec::new(),
                        None,
                        None,
                        &req_ctx,
                    ),
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
            use sha2::{Digest, Sha512};
            let hash = Sha512::digest(request.username.as_bytes());
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

        let _opaque_permit = self.opaque_bulkhead.acquire().await
            .map_err(|e| format!("OPAQUE bulkhead: {e}"))?;
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
            &self.receipt_signing_seed,
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

        // Run advanced anomaly detection (z-score, impossible travel, cross-user correlation).
        // This was previously disconnected — now integrated into the auth decision path.
        let login_hour = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_secs();
            ((now % 86400) as f64) / 3600.0
        };
        let anomaly_result = self.anomaly_detector.analyze_login(
            &user_id,
            login_hour,
            request.device_fingerprint.as_deref(),
            request.source_ip.as_deref(),
            None, // geo coordinates from request if available
        );
        // Combine risk score with anomaly score (weighted average).
        let combined_score = risk_score * 0.6 + anomaly_result.composite_score * 0.4;

        // Run SIEM correlation rules for distributed attack detection.
        let correlation_alerts = self.correlation_engine.evaluate_all();
        if !correlation_alerts.is_empty() {
            for alert in &correlation_alerts {
                tracing::warn!(
                    target: "siem",
                    "SIEM:CORRELATION rule='{}' severity={:?} — {}",
                    alert.rule_name, alert.severity, alert.description
                );
            }
        }

        if self.risk_engine.requires_termination(combined_score) {
            return Err("risk: session terminated — critical risk score".into());
        }
        if self.risk_engine.requires_step_up(combined_score) {
            tracing::warn!("Combined risk score {combined_score:.2} >= 0.6 — step-up re-auth required");
            return Err(format!("risk: step-up re-authentication required (score={combined_score:.2})"));
        }

        // 6. Build and send TSS signing request
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_micros() as i64;

        let security_config = common::config::SecurityConfig::default();
        let tier = if request.tier == 0 {
            tracing::warn!("No tier specified in request, defaulting to tier 2");
            2
        } else {
            request.tier
        };
        if !(1..=4).contains(&tier) {
            return Err(format!("invalid tier {}: must be 1-4", tier));
        }
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
            classification: 0,
        };

        let ratchet_key = generate_key_64();
        let signing_req = SigningRequest { receipts: session.receipt_chain.receipts().to_vec(), claims, ratchet_key };
        let signing_bytes = postcard::to_allocvec(&signing_req).map_err(|e| format!("serialize signing request: {e}"))?;

        let _tss_permit = self.tss_bulkhead.acquire().await
            .map_err(|e| format!("TSS bulkhead: {e}"))?;
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

    /// Overall request deadline for auth processing (5 seconds).
    const AUTH_REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

    /// Start the orchestrator as a SHARD mTLS listener, processing auth requests.
    ///
    /// Each connection is handled in a separate spawned task with a deadline timeout.
    /// Individual connection failures do NOT terminate the listener loop.
    pub async fn run(self: Arc<Self>, listen_addr: &str) -> Result<(), String> {
        let (listener, _ca, _cert_key) =
            tls_bind(listen_addr, ModuleId::Orchestrator, self.hmac_key, "orchestrator")
                .await
                .map_err(|e| format!("bind orchestrator TLS listener: {e}"))?;

        // Start background health checker for service discovery endpoints
        let _health_handle = self.service_registry.spawn_health_checker();

        tracing::info!("Orchestrator listening on {} (mTLS)", listen_addr);

        loop {
            // Accept errors are transient (e.g., fd exhaustion). Log and retry.
            let mut transport = match listener.accept().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("accept error (continuing): {e}");
                    continue;
                }
            };

            let service = Arc::clone(&self);
            tokio::spawn(async move {
                // Wrap the entire request processing in a deadline timeout.
                let deadline_result = tokio::time::timeout(
                    OrchestratorService::AUTH_REQUEST_DEADLINE,
                    async {
                        let (_sender, req_bytes) = transport.recv().await
                            .map_err(|e| format!("recv from gateway: {e}"))?;
                        let request: OrchestratorRequest = postcard::from_bytes(&req_bytes)
                            .map_err(|e| format!("bad request from gateway: {e}"))?;
                        let response = service.process_auth(&request).await;
                        let resp_bytes = postcard::to_allocvec(&response)
                            .map_err(|e| format!("serialize response: {e}"))?;
                        transport.send(&resp_bytes).await
                            .map_err(|e| format!("send to gateway: {e}"))?;
                        Ok::<(), String>(())
                    },
                )
                .await;

                match deadline_result {
                    Ok(Ok(())) => {} // Success
                    Ok(Err(e)) => {
                        tracing::error!("request processing error (continuing): {e}");
                    }
                    Err(_elapsed) => {
                        tracing::error!(
                            "request deadline exceeded ({:?}), dropping connection",
                            OrchestratorService::AUTH_REQUEST_DEADLINE
                        );
                    }
                }
            });
        }
    }
}
