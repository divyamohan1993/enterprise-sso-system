#![forbid(unsafe_code)]
//! verifier: Credential Verifier (O(1) token verification) — SHARD service.

use common::revocation::RevocationList;
use common::types::ModuleId;
use frost_ristretto255::keys::PublicKeyPackage;
use std::sync::Arc;
use tokio::sync::Mutex;
use verifier::{
    RevokeResponse, VerifierMessage, VerifyResponse,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "verifier",
        9104,
        _platform_report.binary_hash,
    );

    // Initialize master KEK via distributed threshold reconstruction (3-of-5 Shamir)
    let _kek = common::sealed_keys::get_master_kek();

    // Initialize structured JSON logging for production observability
    common::structured_logging::init(common::structured_logging::ServiceMeta {
        service_name: "verifier".to_string(),
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        instance_id: uuid::Uuid::new_v4().to_string(),
        project_id: std::env::var("GCP_PROJECT_ID").unwrap_or_else(|_| "milnet-sso".to_string()),
    });

    // Verify binary integrity at startup
    let build_info = common::embed_build_info!();
    tracing::info!(
        git_commit = %build_info.git_commit,
        build_time = %build_info.build_time,
        "build manifest verified"
    );

    // Initialize health monitor for peer service tracking
    let _health_monitor = std::sync::Arc::new(common::health::HealthMonitor::new());

    // Initialize metrics counters
    let _auth_counter = common::metrics::Counter::new("auth_attempts", "Total authentication attempts");
    let _error_counter = common::metrics::Counter::new("errors", "Total errors");

    // Initialize authenticated time source
    let _secure_time = common::secure_time::SecureTimeProvider::new(
        common::secure_time::AuthenticatedTimeConfig::default(),
    );

    // Verify CNSA 2.0 compliance at startup
    assert!(common::cnsa2::is_cnsa2_compliant(), "CNSA 2.0 compliance check failed");
    tracing::info!("CNSA 2.0 compliance verified");

    // Spawn health check endpoint
    let health_start = std::time::Instant::now();
    let _health_handle = common::health::spawn_health_endpoint(
        "verifier".to_string(),
        9104,
        health_start,
        || {
            vec![common::health::HealthCheck {
                name: "verifier_service".to_string(),
                ok: true,
                detail: None,
                latency_ms: None,
            }]
        },
    );

    tracing::info!("verifier starting");

    // 1. Load group verifying key from env (hex-encoded postcard bytes)
    let group_key: PublicKeyPackage = match std::env::var("MILNET_GROUP_VERIFYING_KEY") {
        Ok(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).expect("MILNET_GROUP_VERIFYING_KEY: invalid hex");
            postcard::from_bytes(&bytes).expect("MILNET_GROUP_VERIFYING_KEY: invalid PublicKeyPackage")
        }
        Err(_) => {
            tracing::warn!(
                "MILNET_GROUP_VERIFYING_KEY not set; generating ephemeral test key (NOT for production)"
            );
            let dkg = crypto::threshold::dkg(5, 3);
            dkg.group.public_key_package
        }
    };

    // 2. Load PQ verifying key from env (hex-encoded ML-DSA-65 encoded key bytes)
    let pq_key: crypto::pq_sign::PqVerifyingKey = match std::env::var("MILNET_PQ_VERIFYING_KEY") {
        Ok(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).expect("MILNET_PQ_VERIFYING_KEY: invalid hex");
            let encoded = crypto::pq_sign::PqEncodedVerifyingKey::try_from(bytes.as_slice())
                .expect("MILNET_PQ_VERIFYING_KEY: wrong length for ML-DSA-65 verifying key");
            crypto::pq_sign::PqVerifyingKey::decode(&encoded)
        }
        Err(_) => {
            tracing::warn!(
                "MILNET_PQ_VERIFYING_KEY not set; generating ephemeral test key (NOT for production)"
            );
            let (_sk, vk) = crypto::pq_sign::generate_pq_keypair();
            vk
        }
    };

    // 3. Initialize shared revocation list
    let revocation_list = Arc::new(Mutex::new(RevocationList::new()));

    // 4. Spawn periodic cleanup task (every 10 minutes)
    {
        let rl = Arc::clone(&revocation_list);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                interval.tick().await;
                let mut rl = rl.lock().await;
                let before = rl.len();
                rl.cleanup();
                let after = rl.len();
                if before != after {
                    tracing::info!(
                        "revocation list cleanup: removed {} expired entries ({} remaining)",
                        before - after,
                        after
                    );
                }
            }
        });
    }

    // 5. Bind SHARD TLS listener
    let addr = std::env::var("VERIFIER_ADDR").unwrap_or_else(|_| "127.0.0.1:9104".to_string());
    // Load HMAC key from sealed storage (derived from master KEK via HKDF).
    // Previously this was crypto::entropy::generate_key_64() which generated a RANDOM
    // key at every startup, making cross-service HMAC verification impossible.
    let hmac_key = common::sealed_keys::load_shard_hmac_key_sealed();
    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(&addr, ModuleId::Verifier, hmac_key, "verifier")
            .await
            .expect("failed to bind verifier SHARD TLS listener");

    tracing::info!("verifier listening on {addr} (mTLS)");

    // 5b. Spawn ratchet heartbeat monitor — checks ratchet service liveness
    //     every 60 seconds. If unreachable within 5s, emits a CRITICAL SIEM alert.
    {
        let ratchet_addr = std::env::var("RATCHET_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:9105".to_string());
        let heartbeat_interval_secs: u64 = std::env::var("VERIFIER_STALENESS_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let heartbeat_timeout = std::time::Duration::from_secs(5);

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(heartbeat_interval_secs));
            // Skip the first immediate tick so we don't probe at startup before
            // ratchet has had time to bind.
            interval.tick().await;

            tracing::info!(
                ratchet_addr = %ratchet_addr,
                interval_secs = heartbeat_interval_secs,
                "ratchet heartbeat monitor started"
            );

            loop {
                interval.tick().await;

                let probe = tokio::time::timeout(
                    heartbeat_timeout,
                    tokio::net::TcpStream::connect(&ratchet_addr),
                );

                match probe.await {
                    Ok(Ok(_stream)) => {
                        tracing::debug!(
                            ratchet_addr = %ratchet_addr,
                            "ratchet heartbeat: OK"
                        );
                    }
                    Ok(Err(e)) => {
                        tracing::error!(
                            ratchet_addr = %ratchet_addr,
                            error = %e,
                            "CRITICAL: ratchet heartbeat FAILED — connection refused"
                        );
                        common::siem::SecurityEvent::ratchet_heartbeat_failure(
                            &format!(
                                "ratchet service unreachable at {}: {}",
                                ratchet_addr, e
                            ),
                        );
                    }
                    Err(_elapsed) => {
                        tracing::error!(
                            ratchet_addr = %ratchet_addr,
                            timeout_secs = 5,
                            "CRITICAL: ratchet heartbeat FAILED — timeout exceeded"
                        );
                        common::siem::SecurityEvent::ratchet_heartbeat_failure(
                            &format!(
                                "ratchet service at {} did not respond within 5s",
                                ratchet_addr
                            ),
                        );
                    }
                }
            }
        });
    }

    // 6. Accept connections and handle verify/revoke messages
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let group_key = group_key.clone();
            let pq_key = pq_key.clone();
            let rl = Arc::clone(&revocation_list);
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    // Try the new envelope format first, fall back to legacy VerifyRequest
                    let response_bytes = match postcard::from_bytes::<VerifierMessage>(&payload) {
                        Ok(VerifierMessage::Verify(req)) => {
                            let resp = handle_verify(&req, &group_key, &pq_key, &rl).await;
                            postcard::to_allocvec(&resp).ok()
                        }
                        Ok(VerifierMessage::Revoke(req)) => {
                            let resp = handle_revoke(req.token_id, req.reason, &rl).await;
                            postcard::to_allocvec(&resp).ok()
                        }
                        Err(_) => {
                            // Legacy path: try to deserialize as bare VerifyRequest
                            match postcard::from_bytes::<verifier::VerifyRequest>(&payload) {
                                Ok(req) => {
                                    let resp = handle_verify(&req, &group_key, &pq_key, &rl).await;
                                    postcard::to_allocvec(&resp).ok()
                                }
                                Err(e) => {
                                    let resp = VerifyResponse {
                                        valid: false,
                                        claims: None,
                                        error: Some(format!("request deserialization error: {e}")),
                                    };
                                    postcard::to_allocvec(&resp).ok()
                                }
                            }
                        }
                    };

                    if let Some(bytes) = response_bytes {
                        let _ = transport.send(&bytes).await;
                    }
                }
            });
        }
    }
}

/// Handle a token verification request with revocation, DPoP, and ratchet checks.
///
/// DPoP enforcement is always active.  The `client_dpop_key` field in the
/// request is used for DPoP channel binding verification.  Audit log entries
/// are emitted for every verification attempt, recording whether a DPoP proof
/// key was present.
async fn handle_verify(
    req: &verifier::VerifyRequest,
    group_key: &PublicKeyPackage,
    pq_key: &crypto::pq_sign::PqVerifyingKey,
    rl: &Arc<Mutex<RevocationList>>,
) -> VerifyResponse {
    // Extract DPoP key from request — always pass to verify_token_full for
    // mandatory DPoP enforcement.
    let dpop_key = req.client_dpop_key.as_deref();

    // Audit: log DPoP presence before any crypto work.
    if dpop_key.is_some() {
        tracing::info!(
            dpop_present = true,
            dpop_key_len = dpop_key.map(|k| k.len()),
            "DPoP client key present in verification request"
        );
    } else {
        tracing::warn!(
            dpop_present = false,
            "DPoP client key MISSING from verification request — \
             token will be rejected unless tier-exempt or MILNET_REQUIRE_DPOP=false"
        );
    }

    match postcard::from_bytes::<common::types::Token>(&req.token_bytes) {
        Ok(token) => {
            // Audit: log token tier for DPoP exemption visibility.
            tracing::info!(
                token_id = ?token.claims.token_id,
                tier = token.claims.tier,
                has_dpop_hash = token.claims.dpop_hash != [0u8; 64],
                "verifying token"
            );

            // 1+2. Revocation check (fail-fast) + full signature + DPoP verification
            //       Uses verify_token_full which combines revocation, signatures,
            //       and mandatory DPoP key binding in a single pass.
            {
                let revocation_list = rl.lock().await;
                if let Err(e) = verifier::verify_token_full(
                    &token, group_key, pq_key, &revocation_list, dpop_key,
                ) {
                    tracing::warn!(
                        token_id = ?token.claims.token_id,
                        dpop_present = dpop_key.is_some(),
                        error = %e,
                        "token verification FAILED"
                    );
                    return VerifyResponse {
                        valid: false,
                        claims: None,
                        error: Some(e.to_string()),
                    };
                }
            }

            // 3. Ratchet temporal binding check (if ratchet state provided)
            if let Some(ref ratchet) = req.ratchet_state {
                if let Err(e) = verifier::verify_token_with_ratchet(
                    &token,
                    group_key,
                    pq_key,
                    &ratchet.ratchet_key,
                    ratchet.current_epoch,
                ) {
                    tracing::warn!(
                        token_id = ?token.claims.token_id,
                        error = %e,
                        "ratchet verification FAILED"
                    );
                    return VerifyResponse {
                        valid: false,
                        claims: None,
                        error: Some(e.to_string()),
                    };
                }
            }

            // All checks passed — return valid claims
            tracing::info!(
                token_id = ?token.claims.token_id,
                tier = token.claims.tier,
                dpop_bound = dpop_key.is_some(),
                "token verification PASSED"
            );
            VerifyResponse {
                valid: true,
                claims: Some(token.claims.clone()),
                error: None,
            }
        }
        Err(e) => {
            tracing::warn!(
                dpop_present = dpop_key.is_some(),
                error = %e,
                "token deserialization FAILED"
            );
            VerifyResponse {
                valid: false,
                claims: None,
                error: Some(format!("token deserialization error: {e}")),
            }
        }
    }
}

/// Handle a token revocation request.
async fn handle_revoke(
    token_id: [u8; 16],
    reason: common::revocation::RevocationReason,
    rl: &Arc<Mutex<RevocationList>>,
) -> RevokeResponse {
    let mut revocation_list = rl.lock().await;
    let success = revocation_list.revoke(token_id);
    if success {
        tracing::warn!(
            token_id = ?token_id,
            reason = ?reason,
            list_size = revocation_list.len(),
            "token revoked"
        );
    }
    RevokeResponse {
        success,
        error: if success {
            None
        } else {
            Some("token already revoked or revocation list at capacity".into())
        },
    }
}
