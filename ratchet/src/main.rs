#![forbid(unsafe_code)]
//! ratchet: Ratchet Session Manager service entry point.

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Requests handled by the Ratchet Session Manager.
#[derive(Debug, Serialize, Deserialize)]
enum RatchetRequest {
    CreateSession {
        session_id: Uuid,
        /// 64-byte master secret sent as a Vec since serde doesn't support [u8; 64].
        master_secret: Vec<u8>,
    },
    Advance {
        session_id: Uuid,
        client_entropy: [u8; 32],
        server_entropy: [u8; 32],
    },
}

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
            let manager = manager.clone();
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    if let Ok(request) = postcard::from_bytes::<RatchetRequest>(&payload) {
                        match request {
                            RatchetRequest::CreateSession { session_id, master_secret } => {
                                if master_secret.len() == 64 {
                                    let mut secret = [0u8; 64];
                                    secret.copy_from_slice(&master_secret);
                                    let mut mgr = manager.write().await;
                                    let epoch = mgr.create_session(session_id, &secret);
                                    let _ = transport.send(&postcard::to_allocvec(&epoch).unwrap()).await;
                                }
                            }
                            RatchetRequest::Advance { session_id, client_entropy, server_entropy } => {
                                let mut mgr = manager.write().await;
                                if let Ok(epoch) = mgr.advance_session(&session_id, &client_entropy, &server_entropy) {
                                    let _ = transport.send(&postcard::to_allocvec(&epoch).unwrap()).await;
                                }
                            }
                        }
                    }
                }
            });
        }
    }
}
