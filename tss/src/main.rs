#![forbid(unsafe_code)]
//! tss: Threshold Signer (FROST 3-of-5).
//!
//! At startup, runs DKG to establish the threshold group, then distributes
//! shares across separate signer nodes. The coordinator holds NO signing
//! keys -- it only aggregates partial signatures.

use std::sync::Arc;
use tokio::sync::RwLock;

use crypto::pq_sign::generate_pq_keypair;
use crypto::threshold::dkg;
use tss::distributed::{distribute_shares, SignerNode};
use tss::messages::{SigningRequest, SigningResponse};
use tss::token_builder::build_token_distributed;
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

    tracing::info!(
        "tss: distributed — coordinator (no keys) + {} signer nodes (1 share each)",
        nodes.len()
    );
    tracing::info!(
        "tss: threshold = {}, total = {}",
        coordinator.threshold,
        nodes.len()
    );

    // In production, each `node` would be sent to a separate process:
    //   Node 1 → process/container 1  (holds share 1)
    //   Node 2 → process/container 2  (holds share 2)
    //   Node 3 → process/container 3  (holds share 3)
    //   Node 4 → process/container 4  (holds share 4)
    //   Node 5 → process/container 5  (holds share 5)
    //
    // The coordinator runs here and communicates via SHARD IPC.
    for (i, node) in nodes.iter().enumerate() {
        tracing::info!(
            "  signer node {}: identifier = {:?}",
            i + 1,
            node.identifier()
        );
    }

    // Wrap coordinator and signer nodes for shared access across connections.
    let coordinator = Arc::new(coordinator);
    let nodes = Arc::new(RwLock::new(nodes));

    // Generate PQ signing key at startup (in production, loaded from HSM).
    let (pq_signing_key, _pq_verifying_key) = generate_pq_keypair();
    let pq_signing_key = Arc::new(pq_signing_key);

    // Load the shared receipt signing key (same key OPAQUE uses to sign receipts).
    let receipt_signing_key = common::shared_keys::load_receipt_signing_key();

    let addr = std::env::var("TSS_ADDR").unwrap_or_else(|_| "127.0.0.1:9103".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Tss, hmac_key, "tss")
            .await
            .unwrap();
    tracing::info!("TSS service listening on {addr} (mTLS)");

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
                        tracing::warn!("TSS: rejecting signing request from unauthorized sender {:?}", sender);
                        let resp = SigningResponse {
                            success: false,
                            token: None,
                            error: Some(format!("unauthorized sender: {:?} (only Orchestrator permitted)", sender)),
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
                        validate_receipt_chain(&request.receipts, &receipt_signing_key)
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

                    // 3. Build token with distributed FROST signing
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
