#![forbid(unsafe_code)]
//! kt: Key Transparency Log service entry point.

use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("Key Transparency service starting");

    let tree = Arc::new(RwLock::new(kt::merkle::MerkleTree::new()));

    let addr = std::env::var("KT_ADDR").unwrap_or_else(|_| "127.0.0.1:9107".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let listener = shard::transport::ShardListener::bind(&addr, common::types::ModuleId::Kt, hmac_key)
        .await
        .unwrap();

    tracing::info!("Key Transparency service listening on {addr}");
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let _tree = tree.clone();
            tokio::spawn(async move {
                while let Ok((_sender, _payload)) = transport.recv().await {
                    // Handle KT operations (insert/lookup/proof)
                }
            });
        }
    }
}
