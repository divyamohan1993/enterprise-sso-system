#![forbid(unsafe_code)]
//! audit: Audit Log (BFT) service entry point.

use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use audit::log::{AuditRequest, AuditResponse};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Harden process: disable core dumps, prevent ptrace escalation
    crypto::memguard::harden_process();

    tracing::info!("Audit service starting");

    // Generate ML-DSA-65 keypair for signing audit entries.
    let (pq_signing_key, _pq_verifying_key) = crypto::pq_sign::generate_pq_keypair();

    // Generate a separate ML-DSA-65 keypair for witness checkpoint signing.
    let (witness_signing_key, _witness_verifying_key) = crypto::pq_sign::generate_pq_keypair();

    let audit_cluster = audit::bft::BftAuditCluster::new_with_signing_key(7, pq_signing_key);
    let cluster = Arc::new(RwLock::new(audit_cluster));

    // Witness checkpoint log for periodic ML-DSA-65 signed snapshots (spec Section 15).
    let witness_log = Arc::new(Mutex::new(common::witness::WitnessLog::new()));

    // Spawn periodic witness checkpoint generation every 300 seconds (5 min).
    {
        let cluster = cluster.clone();
        let witness_log = witness_log.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let c = cluster.read().await;
                // Find the first honest (non-Byzantine) node with at least one log entry.
                let audit_root = c.nodes.iter()
                    .find(|n| !n.is_byzantine && !n.log.is_empty())
                    .map(|n| audit::log::hash_entry(&n.log.entries()[n.log.len() - 1]));

                if let Some(audit_root) = audit_root {
                    // KT root placeholder: the Key Transparency tree lives in a separate service.
                    // TODO: fetch real KT root from the KT service once integrated.
                    let kt_root = [0u8; 32];

                    let mut wl = witness_log.lock().await;
                    wl.add_signed_checkpoint(audit_root, kt_root, |data| {
                        crypto::pq_sign::pq_sign_raw(&witness_signing_key, data)
                    });
                    tracing::info!(
                        "Witness checkpoint #{} generated (audit_root={}, kt_root=placeholder)",
                        wl.len(),
                        hex::encode(audit_root),
                    );
                } else {
                    tracing::debug!("Witness checkpoint skipped: no audit entries yet");
                }
            }
        });
    }

    let addr = std::env::var("AUDIT_ADDR").unwrap_or_else(|_| "127.0.0.1:9108".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let listener = shard::transport::ShardListener::bind(&addr, common::types::ModuleId::Audit, hmac_key)
        .await
        .unwrap();

    tracing::info!("Audit service listening on {addr}");
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let cluster = cluster.clone();
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    let response = match postcard::from_bytes::<AuditRequest>(&payload) {
                        Ok(req) => {
                            let mut c = cluster.write().await;
                            match c.propose_entry(
                                req.event_type,
                                req.user_ids,
                                req.device_ids,
                                req.risk_score,
                                vec![],
                            ) {
                                Ok(_entry_hash) => AuditResponse {
                                    success: true,
                                    event_id: Some(uuid::Uuid::new_v4()),
                                    error: None,
                                },
                                Err(e) => AuditResponse {
                                    success: false,
                                    event_id: None,
                                    error: Some(e),
                                },
                            }
                        }
                        Err(e) => AuditResponse {
                            success: false,
                            event_id: None,
                            error: Some(format!("deserialization error: {e}")),
                        },
                    };
                    if let Ok(resp_bytes) = postcard::to_allocvec(&response) {
                        let _ = transport.send(&resp_bytes).await;
                    }
                }
            });
        }
    }
}
