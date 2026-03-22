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
            let engine_handle = engine.clone();
            let _registry = registry.clone();
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    let request: risk::scoring::RiskRequest = match postcard::from_bytes(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::error!("Failed to deserialize RiskRequest: {e}");
                            continue;
                        }
                    };

                    let eng = engine_handle.read().await;
                    let score = eng.compute_score(&request.user_id, &request.signals);
                    let classification = format!("{:?}", eng.classify(score));
                    let step_up_required = eng.requires_step_up(score);
                    let session_terminate = eng.requires_termination(score);
                    drop(eng);

                    let response = risk::scoring::RiskResponse {
                        score,
                        classification,
                        step_up_required,
                        session_terminate,
                    };

                    let resp_bytes = match postcard::to_allocvec(&response) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::error!("Failed to serialize RiskResponse: {e}");
                            continue;
                        }
                    };

                    if let Err(e) = transport.send(&resp_bytes).await {
                        tracing::error!("Failed to send RiskResponse: {e}");
                        break;
                    }
                }
            });
        }
    }
}
