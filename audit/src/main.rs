#![forbid(unsafe_code)]
//! audit: Audit Log (BFT) service entry point.

use std::sync::Arc;
use tokio::sync::RwLock;

use audit::log::{AuditRequest, AuditResponse};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("Audit service starting");

    // Generate ML-DSA-65 keypair for signing audit entries.
    let (pq_signing_key, _pq_verifying_key) = crypto::pq_sign::generate_pq_keypair();

    let audit_cluster = audit::bft::BftAuditCluster::new_with_signing_key(7, pq_signing_key);
    let cluster = Arc::new(RwLock::new(audit_cluster));

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
