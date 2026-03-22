#![forbid(unsafe_code)]
//! ratchet: Ratchet Session Manager service entry point.

use std::sync::Arc;
use tokio::sync::RwLock;

use ratchet::manager::{RatchetAction, RatchetRequest, RatchetResponse};

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
                    let response = match postcard::from_bytes::<RatchetRequest>(&payload) {
                        Ok(request) => handle_request(&manager, request).await,
                        Err(e) => RatchetResponse {
                            success: false,
                            epoch: None,
                            tag: None,
                            error: Some(format!("deserialize error: {e}")),
                        },
                    };
                    let encoded = postcard::to_allocvec(&response)
                        .expect("RatchetResponse must serialize");
                    let _ = transport.send(&encoded).await;
                }
            });
        }
    }
}

async fn handle_request(
    manager: &Arc<RwLock<ratchet::manager::SessionManager>>,
    request: RatchetRequest,
) -> RatchetResponse {
    match request.action {
        RatchetAction::CreateSession { session_id, initial_key } => {
            if initial_key.len() != 64 {
                return RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some("initial_key must be exactly 64 bytes".into()),
                };
            }
            let mut secret = [0u8; 64];
            secret.copy_from_slice(&initial_key);
            let mut mgr = manager.write().await;
            let epoch = mgr.create_session(session_id, &secret);
            RatchetResponse {
                success: true,
                epoch: Some(epoch),
                tag: None,
                error: None,
            }
        }
        RatchetAction::Advance { session_id, client_entropy, server_entropy } => {
            let mut mgr = manager.write().await;
            match mgr.advance_session(&session_id, &client_entropy, &server_entropy) {
                Ok(epoch) => RatchetResponse {
                    success: true,
                    epoch: Some(epoch),
                    tag: None,
                    error: None,
                },
                Err(e) => RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some(e),
                },
            }
        }
        RatchetAction::GetTag { session_id, claims_bytes } => {
            let mgr = manager.read().await;
            match mgr.generate_tag(&session_id, &claims_bytes) {
                Ok(tag) => RatchetResponse {
                    success: true,
                    epoch: None,
                    tag: Some(tag.to_vec()),
                    error: None,
                },
                Err(e) => RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some(e),
                },
            }
        }
        RatchetAction::Destroy { session_id } => {
            let mut mgr = manager.write().await;
            mgr.destroy_session(&session_id);
            RatchetResponse {
                success: true,
                epoch: None,
                tag: None,
                error: None,
            }
        }
    }
}
