#![forbid(unsafe_code)]
//! tss: Threshold Signer (FROST 3-of-5).
//!
//! At startup, runs DKG to establish the threshold group, then distributes
//! shares across separate signer nodes. The coordinator holds NO signing
//! keys -- it only aggregates partial signatures.
//!
//! ## Modes
//!
//! ### Truly Distributed Mode (production)
//!
//! Set `MILNET_TSS_ROLE=coordinator` or `MILNET_TSS_ROLE=signer` to run
//! a single role per process. Each process runs on its own VM/container.
//!
//! - **Coordinator**: loads `PublicKeyPackage` and signer addresses from env,
//!   accepts signing requests from the Orchestrator, coordinates the FROST
//!   ceremony over SHARD/mTLS with remote signer processes.
//!
//! - **Signer**: loads exactly ONE sealed key share from
//!   `MILNET_TSS_SHARE_SEALED`, listens on `MILNET_TSS_SIGNER_ADDR` for
//!   coordinator requests.
//!
//! ### Legacy In-Process Mode (dev/test only)
//!
//! If `MILNET_TSS_ROLE` is not set AND `MILNET_PRODUCTION` is not `1`,
//! falls back to the original in-process mode where all signers run as
//! tokio tasks. A loud warning is emitted.
//!
//! In production (`MILNET_PRODUCTION=1`), the in-process mode is rejected
//! with a hard exit.

use std::sync::Arc;
use tokio::sync::RwLock;

use crypto::pq_sign::generate_pq_keypair;
use crypto::threshold::dkg;
use tss::distributed::{
    distribute_shares, DistributedSigningCoordinator, SignerNode,
};
use tss::messages::{SigningRequest, SigningResponse};
use tss::token_builder::{build_token_distributed, prepare_claims_with_audience};
use tss::validator::validate_receipt_chain;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    let is_production = common::sealed_keys::is_production();

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
    let tss_addr = std::env::var("TSS_ADDR").unwrap_or_else(|_| "127.0.0.1:9103".into());
    let cluster = match common::cluster::ClusterConfig::from_env_with_defaults(
        common::cluster::ServiceType::TssCoordinator,
        &tss_addr,
    ) {
        Ok(config) => {
            tracing::info!(
                node_id = %config.node_id,
                peers = config.peers.len(),
                "starting TSS cluster node"
            );
            match common::cluster::ClusterNode::start(config).await {
                Ok(node) => {
                    let mut watcher = node.leader_watch();
                    tokio::spawn(async move {
                        while watcher.changed().await.is_ok() {
                            if let Some(lid) = *watcher.borrow() {
                                tracing::info!(%lid, "TSS coordinator leader elected");
                            }
                        }
                    });
                    Some(node)
                }
                Err(e) => {
                    tracing::warn!("TSS cluster start failed (standalone): {e}");
                    None
                }
            }
        }
        Err(_) => None,
    };

    // --- Role-based dispatch ---
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
            // No role set — check if we can fall back to legacy in-process mode
            if is_production {
                eprintln!(
                    "FATAL: MILNET_TSS_ROLE not set in production mode. \
                     Each TSS process MUST run exactly one role: 'coordinator' or 'signer'. \
                     In-process mode is forbidden in production — it collapses 3-of-5 \
                     threshold security to effective 1-of-1."
                );
                std::process::exit(1);
            }

            tracing::warn!(
                "========================================================================="
            );
            tracing::warn!(
                "WARNING: MILNET_TSS_ROLE not set. Falling back to LEGACY IN-PROCESS MODE."
            );
            tracing::warn!(
                "WARNING: All 5 signer shares exist in the SAME process memory."
            );
            tracing::warn!(
                "WARNING: This defeats threshold security. Set MILNET_TSS_ROLE for production."
            );
            tracing::warn!(
                "========================================================================="
            );

            run_legacy_inprocess_mode().await;
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
    let addr = std::env::var("TSS_ADDR").unwrap_or_else(|_| "127.0.0.1:9103".to_string());
    let coord_hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Tss, coord_hmac_key, "tss")
            .await
            .unwrap();
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
                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
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
                            let resp_bytes = postcard::to_allocvec(&resp).unwrap();
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
                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
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
                            let resp_bytes = postcard::to_allocvec(&resp).unwrap();
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

                            let mut mac = HmacSha512::new_from_slice(&request.ratchet_key)
                                .expect("HMAC-SHA512 accepts any key length");
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

                            let token_bytes = postcard::to_allocvec(&token).unwrap();
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
                    let resp_bytes = postcard::to_allocvec(&resp).unwrap();
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

// ===========================================================================
// Legacy in-process mode (dev/test only — NOT for production)
// ===========================================================================

async fn run_legacy_inprocess_mode() {
    // Run DKG at startup (3-of-5 threshold)
    let mut dkg_result = dkg(5, 3);
    tracing::info!(
        threshold = dkg_result.group.threshold,
        total = dkg_result.group.total,
        "DKG ceremony complete"
    );

    // Distribute shares: each SignerNode gets exactly ONE key share.
    // The coordinator holds NO signing keys.
    let (coordinator, nodes) = distribute_shares(&mut dkg_result);

    let threshold = coordinator.threshold;
    let total = nodes.len();

    tracing::info!(
        "tss: legacy in-process — coordinator (no keys) + {} signer nodes (1 share each)",
        total
    );
    tracing::info!(
        "tss: threshold = {}, total = {}",
        threshold,
        total
    );

    for (i, node) in nodes.iter().enumerate() {
        tracing::info!(
            "  signer node {}: identifier = {:?}",
            i + 1,
            node.identifier()
        );
    }

    // Generate PQ signing key at startup (in production, loaded from HSM).
    let (pq_signing_key, _pq_verifying_key) = generate_pq_keypair();
    let pq_signing_key = Arc::new(pq_signing_key);

    // Load the shared receipt signing key (same key OPAQUE uses to sign receipts).
    let receipt_signing_key = common::shared_keys::load_receipt_signing_key();

    // --- Mode switch ---
    let tss_mode = std::env::var("MILNET_TSS_MODE").unwrap_or_else(|_| "distributed".to_string());

    match tss_mode.as_str() {
        "distributed" => {
            run_distributed_mode(
                coordinator,
                nodes,
                pq_signing_key,
                receipt_signing_key,
            )
            .await;
        }
        "single-process" => {
            run_single_process_mode(
                coordinator,
                nodes,
                pq_signing_key,
                receipt_signing_key,
            )
            .await;
        }
        other => {
            tracing::error!(
                "FATAL: unknown MILNET_TSS_MODE={other:?}. Use 'distributed' or 'single-process'."
            );
            std::process::exit(1);
        }
    }
}

// ===========================================================================
// Distributed mode: each signer on its own SHARD port (legacy in-process)
// ===========================================================================

async fn run_distributed_mode(
    coordinator: tss::distributed::SigningCoordinator,
    nodes: Vec<SignerNode>,
    pq_signing_key: Arc<crypto::pq_sign::PqSigningKey>,
    receipt_signing_key: common::shared_keys::ReceiptSigningKey,
) {
    let base_port: u16 = std::env::var("TSS_SIGNER_BASE_PORT")
        .unwrap_or_else(|_| "9110".to_string())
        .parse()
        .unwrap_or(9110);

    let signer_hmac_key = crypto::entropy::generate_key_64();
    let mut signer_addrs: Vec<(frost_ristretto255::Identifier, String)> = Vec::new();

    let node_count = nodes.len();

    for (i, node) in nodes.into_iter().enumerate() {
        let addr = format!("127.0.0.1:{}", base_port + i as u16);
        signer_addrs.push((node.identifier(), addr.clone()));
        let hmac = signer_hmac_key;
        tokio::spawn(async move {
            if let Err(e) = tss::distributed::run_signer_process(node, &addr, hmac).await {
                tracing::error!("Signer node {} failed: {e}", i + 1);
            }
        });
    }

    tracing::info!(
        "TSS distributed: {} signer nodes spawned on ports {}-{}",
        node_count,
        base_port,
        base_port + node_count as u16 - 1
    );

    // Give signer tasks a moment to bind their ports.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Build the remote coordinator (holds NO signing keys).
    let dist_coordinator = Arc::new(DistributedSigningCoordinator::new(
        coordinator.public_key_package.clone(),
        coordinator.threshold,
        signer_addrs,
        signer_hmac_key,
    ));

    // Coordinator listener (accepts signing requests from the Orchestrator).
    let addr = std::env::var("TSS_ADDR").unwrap_or_else(|_| "127.0.0.1:9103".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Tss, hmac_key, "tss")
            .await
            .unwrap();
    tracing::info!("TSS coordinator listening on {addr} (mTLS, distributed mode)");

    loop {
        if let Ok(mut transport) = listener.accept().await {
            tracing::info!("TSS accepted connection (distributed mode)");

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
                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                        if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("TSS: failed to send response: {e}");
                        }
                        continue;
                    }

                    tracing::info!("TSS received signing request (distributed)");

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
                            let resp_bytes = postcard::to_allocvec(&resp).unwrap();
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
                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
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
                            let resp_bytes = postcard::to_allocvec(&resp).unwrap();
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

                            let mut mac = HmacSha512::new_from_slice(&request.ratchet_key)
                                .expect("HMAC-SHA512 accepts any key length");
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

                            let token_bytes = postcard::to_allocvec(&token).unwrap();
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
                    let resp_bytes = postcard::to_allocvec(&resp).unwrap();
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
// Single-process mode (dev/test only — NOT for production)
// ===========================================================================

async fn run_single_process_mode(
    coordinator: tss::distributed::SigningCoordinator,
    nodes: Vec<SignerNode>,
    pq_signing_key: Arc<crypto::pq_sign::PqSigningKey>,
    receipt_signing_key: common::shared_keys::ReceiptSigningKey,
) {
    // SECURITY: Production deployment guard — refuse single-process mode in production.
    // All signer shares in a single process reduces N-of-M threshold to effective 1-of-1.
    // The MILNET_TSS_SINGLE_PROCESS_OVERRIDE escape hatch has been permanently removed.
    if std::env::var("MILNET_PRODUCTION").is_ok() {
        panic!(
            "FATAL: TSS single-process mode is not permitted in production. \
             Deploy 5 separate TSS instances for real 3-of-5 threshold security. \
             The MILNET_TSS_SINGLE_PROCESS_OVERRIDE escape hatch has been permanently removed."
        );
    }

    let total = nodes.len();
    let threshold = coordinator.threshold;

    #[cfg(target_os = "linux")]
    {
        tracing::warn!(
            target: "siem",
            event = "tss_single_process_warning",
            severity = 8,
            "ALL {} TSS signer shares are in a single process. \
             For military-grade deployment, each signer MUST run in a separate \
             process/VM/enclave. Single-process mode reduces {}-of-{} threshold to 1-of-1.",
            total, threshold, total
        );
    }

    // Wrap coordinator and signer nodes for shared access across connections.
    let coordinator = Arc::new(coordinator);
    let nodes = Arc::new(RwLock::new(nodes));

    let addr = std::env::var("TSS_ADDR").unwrap_or_else(|_| "127.0.0.1:9103".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Tss, hmac_key, "tss")
            .await
            .unwrap();
    tracing::info!("TSS service listening on {addr} (mTLS, single-process mode)");

    loop {
        if let Ok(mut transport) = listener.accept().await {
            tracing::info!("TSS accepted connection");

            let coordinator = Arc::clone(&coordinator);
            let nodes = Arc::clone(&nodes);
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
                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                        if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("TSS: failed to send response: {e}");
                        }
                        continue;
                    }

                    tracing::info!("TSS received signing request");

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
                            let resp_bytes = postcard::to_allocvec(&resp).unwrap();
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
                        let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                        if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("TSS: failed to send response: {e}");
                        }
                        continue;
                    }

                    // 3. Build token with distributed FROST signing (in-process)
                    let token_result = {
                        let mut nodes_guard = nodes.write().await;
                        let mut signers: Vec<&mut SignerNode> =
                            nodes_guard.iter_mut().take(coordinator.threshold).collect();
                        build_token_distributed(
                            &request.claims,
                            &coordinator,
                            &mut signers,
                            &request.ratchet_key,
                            &pq_signing_key,
                            request.claims.aud.clone(),
                        )
                    };

                    let resp = match token_result {
                        Ok(token) => {
                            let token_bytes = postcard::to_allocvec(&token).unwrap();
                            tracing::info!(
                                "token built successfully ({} bytes)",
                                token_bytes.len()
                            );
                            SigningResponse {
                                success: true,
                                token: Some(token_bytes),
                                error: None,
                            }
                        }
                        Err(e) => {
                            tracing::error!("token building failed: {e}");
                            SigningResponse {
                                success: false,
                                token: None,
                                error: Some(format!("token building failed: {e}")),
                            }
                        }
                    };

                    // 4. Send response back
                    let resp_bytes = postcard::to_allocvec(&resp).unwrap();
                    if let Err(e) = transport.send(&resp_bytes).await {
                        tracing::error!("failed to send signing response: {e}");
                        break;
                    }
                }
            });
        }
    }
}
