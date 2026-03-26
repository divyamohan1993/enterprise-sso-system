#![forbid(unsafe_code)]
//! tss: Threshold Signer (FROST 3-of-5).
//!
//! At startup, runs DKG to establish the threshold group, then distributes
//! shares across separate signer nodes. The coordinator holds NO signing
//! keys -- it only aggregates partial signatures.
//!
//! ## Modes
//!
//! - `distributed` (default): Each signer runs in its own tokio task on a
//!   separate SHARD/mTLS port. The coordinator communicates via network IPC.
//!   Compromising any single task only yields 1 share.
//!
//! - `single-process` (dev only): All signers in one process for local
//!   development. **NOT permitted in production.**

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
        "tss: distributed — coordinator (no keys) + {} signer nodes (1 share each)",
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
// Distributed mode: each signer on its own SHARD port
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
    let dist_coordinator = Arc::new(DistributedSigningCoordinator {
        public_key_package: coordinator.public_key_package.clone(),
        threshold: coordinator.threshold,
        signer_addrs,
        hmac_key: signer_hmac_key,
    });

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
                        let _ = transport.send(&resp_bytes).await;
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
                            let _ = transport.send(&resp_bytes).await;
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
                        let _ = transport.send(&resp_bytes).await;
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
                            let _ = transport.send(&resp_bytes).await;
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
    if std::env::var("MILNET_PRODUCTION").is_ok()
        && std::env::var("MILNET_TSS_SINGLE_PROCESS_OVERRIDE").is_err()
    {
        tracing::error!(
            "FATAL: TSS single-process mode is not permitted in production. \
             Deploy each signer in a separate process (use MILNET_TSS_MODE=distributed). \
             Set MILNET_TSS_SINGLE_PROCESS_OVERRIDE=1 to bypass (NOT RECOMMENDED)."
        );
        std::process::exit(1);
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
                        let _ = transport.send(&resp_bytes).await;
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
                            let _ = transport.send(&resp_bytes).await;
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
                        let _ = transport.send(&resp_bytes).await;
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
