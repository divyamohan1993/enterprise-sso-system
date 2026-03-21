#![forbid(unsafe_code)]
//! risk: Risk Scoring Engine service entry point.

use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("Risk Scoring service starting");

    let engine = Arc::new(RwLock::new(risk::scoring::RiskEngine::new()));
    let registry = Arc::new(RwLock::new(risk::tiers::DeviceRegistry::new()));

    let addr = std::env::var("RISK_ADDR").unwrap_or_else(|_| "127.0.0.1:9106".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let listener = shard::transport::ShardListener::bind(&addr, common::types::ModuleId::Risk, hmac_key)
        .await
        .unwrap();

    tracing::info!("Risk Scoring service listening on {addr}");
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let _engine = engine.clone();
            let _registry = registry.clone();
            tokio::spawn(async move {
                while let Ok((_sender, _payload)) = transport.recv().await {
                    // Compute risk scores for incoming requests
                }
            });
        }
    }
}
