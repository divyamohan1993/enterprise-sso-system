#![forbid(unsafe_code)]
//! kt: Key Transparency Log service entry point.

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Requests handled by the Key Transparency service.
#[derive(Debug, Serialize, Deserialize)]
enum KtRequest {
    AppendOp {
        user_id: Uuid,
        operation: String,
        credential_hash: [u8; 32],
        timestamp: i64,
    },
    GetRoot,
}

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
            let tree = tree.clone();
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    if let Ok(request) = postcard::from_bytes::<KtRequest>(&payload) {
                        match request {
                            KtRequest::AppendOp { user_id, operation, credential_hash, timestamp } => {
                                let mut tree = tree.write().await;
                                tree.append_credential_op(&user_id, &operation, &credential_hash, timestamp);
                            }
                            KtRequest::GetRoot => {
                                let tree = tree.read().await;
                                let root = tree.root();
                                let _ = transport.send(&root).await;
                            }
                        }
                    }
                }
            });
        }
    }
}
