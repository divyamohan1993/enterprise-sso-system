#![forbid(unsafe_code)]
//! audit: Audit Log (BFT) service entry point.

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Full audit request with metadata.
#[derive(Debug, Serialize, Deserialize)]
struct AuditRequest {
    event_type: common::types::AuditEventType,
    user_ids: Vec<Uuid>,
    device_ids: Vec<Uuid>,
    risk_score: f64,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("Audit service starting");

    let audit_cluster = audit::bft::BftAuditCluster::new(7);
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
                    if let Ok(req) = postcard::from_bytes::<AuditRequest>(&payload) {
                        let mut c = cluster.write().await;
                        let _ = c.propose_entry(
                            req.event_type,
                            req.user_ids,
                            req.device_ids,
                            req.risk_score,
                            vec![],
                        );
                    }
                }
            });
        }
    }
}
