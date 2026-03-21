//! OPAQUE service: listens for SHARD connections and processes auth requests.

use std::time::{SystemTime, UNIX_EPOCH};

use milnet_common::types::{ModuleId, Receipt};
use milnet_crypto::entropy::generate_nonce;
use milnet_crypto::receipts::sign_receipt;
use milnet_shard::transport::ShardListener;
use tracing::{error, info};

use crate::messages::{OpaqueRequest, OpaqueResponse};
use crate::store::CredentialStore;

/// Fixed 64-byte signing key for Phase 2 (HSM-backed in production).
const RECEIPT_SIGNING_KEY: [u8; 64] = [0x42u8; 64];

/// HMAC key for SHARD transport authentication.
const SHARD_HMAC_KEY: [u8; 64] = [0x37u8; 64];

/// Default listen address for the OPAQUE service.
const DEFAULT_ADDR: &str = "127.0.0.1:9005";

/// Process a single OPAQUE authentication request.
/// On success, creates and signs a Receipt (step_id=1, first in chain).
pub fn handle_request(
    store: &CredentialStore,
    request: &OpaqueRequest,
    signing_key: &[u8; 64],
) -> OpaqueResponse {
    match store.verify(&request.username, &request.password_hash) {
        Ok(user_id) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64;

            let mut receipt = Receipt {
                ceremony_session_id: request.ceremony_session_id,
                step_id: 1,
                prev_receipt_hash: [0u8; 32], // First in chain
                user_id,
                dpop_key_hash: request.dpop_key_hash,
                timestamp: now,
                nonce: generate_nonce(),
                signature: Vec::new(),
                ttl_seconds: 30,
            };

            sign_receipt(&mut receipt, signing_key);

            OpaqueResponse {
                success: true,
                receipt: Some(receipt),
                error: None,
            }
        }
        Err(e) => OpaqueResponse {
            success: false,
            receipt: None,
            error: Some(e.to_string()),
        },
    }
}

/// Run the OPAQUE service, listening for SHARD connections.
pub async fn run(store: CredentialStore) -> Result<(), Box<dyn std::error::Error>> {
    let listener = ShardListener::bind(DEFAULT_ADDR, ModuleId::Opaque, SHARD_HMAC_KEY).await?;
    info!("OPAQUE service listening on {}", DEFAULT_ADDR);

    loop {
        let mut transport = listener.accept().await?;
        info!("Accepted SHARD connection");

        let (_sender, payload) = transport.recv().await?;

        let request: OpaqueRequest =
            postcard::from_bytes(&payload).map_err(|e| format!("deserialize request: {e}"))?;

        let response = handle_request(&store, &request, &RECEIPT_SIGNING_KEY);

        let response_bytes =
            postcard::to_allocvec(&response).map_err(|e| format!("serialize response: {e}"))?;

        transport.send(&response_bytes).await?;

        if response.success {
            info!("Authentication succeeded for user '{}'", request.username);
        } else {
            error!(
                "Authentication failed for user '{}': {}",
                request.username,
                response.error.as_deref().unwrap_or("unknown")
            );
        }
    }
}
