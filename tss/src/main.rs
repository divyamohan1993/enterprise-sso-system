#![forbid(unsafe_code)]
//! tss: Threshold Signer (FROST 3-of-5).
//!
//! At startup, runs DKG to establish the threshold group, then distributes
//! shares across separate signer nodes. The coordinator holds NO signing
//! keys -- it only aggregates partial signatures.
//!
//! ## Operation
//!
//! Set `MILNET_TSS_ROLE=coordinator` or `MILNET_TSS_ROLE=signer` to run
//! a single role per process. Each process runs on its own VM/container.
//! In-process mode is forbidden -- it collapses 3-of-5 threshold security
//! to effective 1-of-1.
//!
//! - **Coordinator**: loads `PublicKeyPackage` and signer addresses from env,
//!   accepts signing requests from the Orchestrator, coordinates the FROST
//!   ceremony over SHARD/mTLS with remote signer processes.
//!
//! - **Signer**: loads exactly ONE sealed key share from
//!   `MILNET_TSS_SHARE_SEALED`, listens on `MILNET_TSS_SIGNER_ADDR` for
//!   coordinator requests.

use std::sync::Arc;

use crypto::pq_sign::generate_pq_keypair;
use tss::distributed::DistributedSigningCoordinator;
use tss::messages::{SigningRequest, SigningResponse};
use tss::token_builder::prepare_claims_with_audience;
use tss::validator::validate_receipt_chain;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Anchor monotonic time before any crypto/auth operations.
    common::secure_time::init_time_anchor();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "tss",
        9103,
        _platform_report.binary_hash,
    );

    // Initialize master KEK via distributed threshold reconstruction (3-of-5 Shamir)
    let _kek = common::sealed_keys::get_master_kek();

    // Spawn health check endpoint
    let health_start = std::time::Instant::now();
    let _health_handle = common::health::spawn_health_endpoint(
        "tss".to_string(),
        9103,
        health_start,
        || {
            vec![common::health::HealthCheck {
                name: "tss_service".to_string(),
                ok: true,
                detail: None,
                latency_ms: None,
            }]
        },
    );

    // ── Distributed cluster coordination ──
    // In production mode, cluster membership is MANDATORY — panics if unavailable.
    let tss_addr = std::env::var("TSS_ADDR").unwrap_or_else(|_| "127.0.0.1:9103".into());
    let cluster = common::cluster::require_cluster(
        common::cluster::ServiceType::TssCoordinator,
        &tss_addr,
    ).await;

    // Log leader elections
    if let Some(ref node) = cluster {
        let mut watcher = node.leader_watch();
        tokio::spawn(async move {
            while watcher.changed().await.is_ok() {
                if let Some(lid) = *watcher.borrow() {
                    tracing::info!(%lid, "TSS coordinator leader elected");
                }
            }
        });
    }

    // Wire auto-response pipeline to Raft for distributed quarantine enforcement
    if let Some(ref c) = cluster {
        _defense.connect_to_cluster(c.clone());
    }

    // SECURITY: Remove ALL sensitive env vars from /proc/PID/environ IMMEDIATELY
    // after the last env var read. Secrets must not linger in the process environment
    // any longer than necessary to prevent leakage via /proc/PID/environ or
    // child process inheritance.
    common::startup_checks::sanitize_environment();

    // SECURITY: Verify kernel security posture (ptrace_scope, BPF restrictions)
    common::startup_checks::verify_kernel_security_posture();

    // SECURITY: Verify process hardening flags and apply anti-ptrace
    crypto::seccomp::apply_anti_ptrace();
    crypto::seccomp::verify_process_hardening();

    // SECURITY: Graceful shutdown on SIGTERM/SIGINT.
    // - Stops accepting new signing requests
    // - Waits for in-flight FROST ceremonies to complete (30s timeout)
    // - Shuts down Raft cluster membership cleanly
    // - Zeroizes sensitive key material before exit
    let shutdown_signal = async {
        let mut sigterm = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("FATAL: failed to install SIGTERM handler: {e}");
                std::process::exit(1);
            }
        };
        let mut sigint = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::interrupt(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("FATAL: failed to install SIGINT handler: {e}");
                std::process::exit(1);
            }
        };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("received SIGTERM, initiating graceful shutdown"),
            _ = sigint.recv() => tracing::info!("received SIGINT, initiating graceful shutdown"),
        }
    };

    // --- Role-based dispatch with graceful shutdown ---
    let role_future = async {
        match std::env::var("MILNET_TSS_ROLE").ok().as_deref() {
            Some("coordinator") => {
                tracing::info!("TSS starting in COORDINATOR role (truly distributed)");
                run_coordinator_role().await;
            }
            Some("signer") => {
                tracing::info!("TSS starting in SIGNER role (truly distributed)");
                run_signer_role().await;
            }
            Some(other) => {
                tracing::error!(
                    "FATAL: unknown MILNET_TSS_ROLE={other:?}. Use 'coordinator' or 'signer'."
                );
                std::process::exit(1);
            }
            None => {
                eprintln!(
                    "FATAL: MILNET_TSS_ROLE not set. \
                     Each TSS process MUST run exactly one role: 'coordinator' or 'signer'. \
                     In-process mode is forbidden — it collapses 3-of-5 \
                     threshold security to effective 1-of-1."
                );
                std::process::exit(1);
            }
        }
    };

    tokio::select! {
        _ = role_future => {}
        _ = shutdown_signal => {
            tracing::info!("tss: waiting up to 30s for in-flight signing ceremonies...");
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if let Some(c) = cluster {
                c.shutdown().await;
            }
            tracing::info!("tss: graceful shutdown complete");
        }
    }
}

// ===========================================================================
// Truly Distributed: Coordinator Role
// ===========================================================================

async fn run_coordinator_role() {
    // Load coordinator config from env (public key package, threshold, signer addrs, HMAC key)
    let (public_key_package, threshold, signer_addrs, hmac_key) =
        match tss::distributed::load_coordinator_config_from_env() {
            Ok(config) => config,
            Err(e) => {
                tracing::error!("FATAL: failed to load coordinator config: {e}");
                std::process::exit(1);
            }
        };

    tracing::info!(
        threshold = threshold,
        signers = signer_addrs.len(),
        "Coordinator loaded config from env (holds NO signing keys)"
    );

    for (id, addr) in &signer_addrs {
        tracing::info!("  remote signer {:?} at {}", id, addr);
    }

    // Build the remote coordinator
    let dist_coordinator = Arc::new(DistributedSigningCoordinator::new(
        public_key_package,
        threshold,
        signer_addrs,
        hmac_key,
    ));

    // Generate PQ signing key at startup (in production, loaded from HSM).
    let (pq_signing_key, _pq_verifying_key) = generate_pq_keypair();
    let pq_signing_key = Arc::new(pq_signing_key);

    // Load the shared receipt signing key
    let receipt_signing_key = common::shared_keys::load_receipt_signing_key();

    // Coordinator listener (accepts signing requests from the Orchestrator)
    let addr = std::env::var("MILNET_TSS_LISTEN_ADDR")
        .or_else(|_| std::env::var("TSS_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1:9103".to_string());
    let coord_hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        match shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Tss, coord_hmac_key, "tss")
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("FATAL: TSS service failed to bind TLS listener: {e}");
                std::process::exit(1);
            }
        };
    tracing::info!("TSS coordinator listening on {addr} (mTLS, truly distributed mode)");

    loop {
        if let Ok(mut transport) = listener.accept().await {
            tracing::info!("TSS coordinator accepted connection");

            let dist_coordinator = Arc::clone(&dist_coordinator);
            let pq_signing_key = Arc::clone(&pq_signing_key);

            tokio::spawn(async move {
                while let Ok((sender, payload)) = transport.recv().await {
                    // C11: Validate sender identity — only Orchestrator may request signing
                    if sender != common::types::ModuleId::Orchestrator {
                        tracing::warn!(
                            "TSS: rejecting signing request from unauthorized sender {:?}",
                            sender
                        );
                        let resp = SigningResponse {
                            success: false,
                            token: None,
                            error: Some(format!(
                                "unauthorized sender: {:?} (only Orchestrator permitted)",
                                sender
                            )),
                        };
                        let resp_bytes = match postcard::to_allocvec(&resp) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("TSS: failed to serialize response: {e}");
                                continue;
                            }
                        };
                        if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("TSS: failed to send response: {e}");
                        }
                        continue;
                    }

                    tracing::info!("TSS received signing request (coordinator role)");

                    // 1. Deserialize the signing request
                    let request: SigningRequest = match postcard::from_bytes(&payload) {
                        Ok(req) => req,
                        Err(e) => {
                            tracing::error!("failed to deserialize signing request: {e}");
                            let resp = SigningResponse {
                                success: false,
                                token: None,
                                error: Some(format!("deserialization error: {e}")),
                            };
                            let resp_bytes = match postcard::to_allocvec(&resp) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("TSS: failed to serialize response: {e}");
                                continue;
                            }
                        };
                            if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("TSS: failed to send response: {e}");
                        }
                            continue;
                        }
                    };

                    // 2. Validate receipt chain
                    if let Err(e) =
                        validate_receipt_chain(&request.receipts, &receipt_signing_key.0)
                    {
                        tracing::warn!("receipt chain validation failed: {e}");
                        let resp = SigningResponse {
                            success: false,
                            token: None,
                            error: Some(format!("receipt chain invalid: {e}")),
                        };
                        let resp_bytes = match postcard::to_allocvec(&resp) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("TSS: failed to serialize response: {e}");
                                continue;
                            }
                        };
                        if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("TSS: failed to send response: {e}");
                        }
                        continue;
                    }

                    // 3. Prepare claims with audience
                    let claims = prepare_claims_with_audience(
                        &request.claims,
                        request.claims.aud.clone(),
                    );

                    // Domain-separated message for FROST signing
                    let claims_bytes = match postcard::to_allocvec(&claims) {
                        Ok(b) => b,
                        Err(e) => {
                            let resp = SigningResponse {
                                success: false,
                                token: None,
                                error: Some(format!("claims serialization: {e}")),
                            };
                            let resp_bytes = match postcard::to_allocvec(&resp) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("TSS: failed to serialize response: {e}");
                                continue;
                            }
                        };
                            if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("TSS: failed to send response: {e}");
                        }
                            continue;
                        }
                    };
                    let msg = [common::domain::FROST_TOKEN, claims_bytes.as_slice()].concat();

                    // 4. Distributed FROST signing via remote signer nodes
                    let frost_result = dist_coordinator.coordinate_signing_remote(&msg).await;

                    let resp = match frost_result {
                        Ok(frost_signature) => {
                            // Compute ratchet tag
                            use hmac::{Hmac, Mac};
                            use sha2::Sha512;
                            type HmacSha512 = Hmac<Sha512>;

                            let mut mac = match HmacSha512::new_from_slice(&request.ratchet_key) {
                                Ok(m) => m,
                                Err(e) => {
                                    tracing::error!("TSS: HMAC-SHA512 key init failed: {e}");
                                    continue;
                                }
                            };
                            mac.update(common::domain::TOKEN_TAG);
                            mac.update(&claims_bytes);
                            mac.update(&claims.ratchet_epoch.to_le_bytes());
                            let ratchet_tag: [u8; 64] = mac.finalize().into_bytes().into();

                            // PQ signature
                            let pq_signature =
                                crypto::pq_sign::pq_sign(&pq_signing_key, &msg, &frost_signature);

                            let token = common::types::Token {
                                header: common::types::TokenHeader {
                                    version: 1,
                                    algorithm: 1,
                                    tier: claims.tier,
                                },
                                claims,
                                ratchet_tag,
                                frost_signature,
                                pq_signature,
                            };

                            let token_bytes = match postcard::to_allocvec(&token) {
                                Ok(b) => b,
                                Err(e) => {
                                    tracing::error!("TSS: failed to serialize token: {e}");
                                    continue;
                                }
                            };
                            tracing::info!(
                                "token built successfully via distributed signing ({} bytes)",
                                token_bytes.len()
                            );
                            SigningResponse {
                                success: true,
                                token: Some(token_bytes),
                                error: None,
                            }
                        }
                        Err(e) => {
                            tracing::error!("distributed signing failed: {e}");
                            SigningResponse {
                                success: false,
                                token: None,
                                error: Some(format!("distributed signing failed: {e}")),
                            }
                        }
                    };

                    // 5. Send response back
                    let resp_bytes = match postcard::to_allocvec(&resp) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("TSS: failed to serialize response: {e}");
                                continue;
                            }
                        };
                    if let Err(e) = transport.send(&resp_bytes).await {
                        tracing::error!("failed to send signing response: {e}");
                        break;
                    }
                }
            });
        }
    }
}

// ===========================================================================
// Truly Distributed: Signer Role
// ===========================================================================

async fn run_signer_role() {
    // Load the signer's sealed key share from env
    let (node, _public_key_package, _threshold) =
        match tss::distributed::load_signer_share_from_env() {
            Ok(result) => result,
            Err(e) => {
                tracing::error!(
                    "FATAL: failed to load sealed signer share: {e}. \
                     Set MILNET_TSS_SHARE_SEALED to a valid sealed share hex blob."
                );
                std::process::exit(1);
            }
        };

    let signer_addr = std::env::var("MILNET_TSS_SIGNER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9110".to_string());

    tracing::info!(
        identifier = ?node.identifier(),
        addr = %signer_addr,
        "Signer loaded sealed key share (holds exactly 1 share)"
    );

    // Load the SHARD HMAC key for coordinator-signer authentication
    let hmac_key = common::sealed_keys::load_shard_hmac_key_sealed();

    // Run the signer process (blocks forever, serving coordinator requests)
    if let Err(e) = tss::distributed::run_signer_process(node, &signer_addr, hmac_key).await {
        tracing::error!("Signer process failed: {e}");
        std::process::exit(1);
    }
}

