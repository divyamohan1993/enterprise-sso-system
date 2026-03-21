#![forbid(unsafe_code)]
//! ratchet: Ratchet Session Manager service entry point.

use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("Ratchet Session Manager starting");

    let manager = Arc::new(RwLock::new(ratchet::manager::SessionManager::new()));

    let addr = std::env::var("RATCHET_ADDR").unwrap_or_else(|_| "127.0.0.1:9105".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let listener = shard::transport::ShardListener::bind(&addr, common::types::ModuleId::Ratchet, hmac_key)
        .await
        .unwrap();

    tracing::info!("Ratchet Session Manager listening on {addr}");
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let _manager = manager.clone();
            tokio::spawn(async move {
                while let Ok((_sender, _payload)) = transport.recv().await {
                    // Manage ratchet sessions
                }
            });
        }
    }
}
