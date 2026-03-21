//! OPAQUE service: listens for SHARD connections and processes auth requests.

use std::time::{SystemTime, UNIX_EPOCH};

use common::types::{ModuleId, Receipt};
use crypto::entropy::generate_nonce;
use crypto::receipts::sign_receipt;
use shard::transport::ShardListener;
use tracing::{error, info};

use crate::messages::{OpaqueRequest, OpaqueResponse};
use crate::store::CredentialStore;

/// Load receipt signing key: generate random key at startup with a warning.
/// In production, this MUST be loaded from an HSM or secure key store.
fn load_receipt_signing_key() -> [u8; 64] {
    eprintln!("WARNING: RECEIPT_SIGNING_KEY generated randomly at startup (NOT FOR PRODUCTION — use HSM)");
    crypto::entropy::generate_key_64()
}

/// Load SHARD HMAC key: generate random key at startup with a warning.
/// In production, this MUST be loaded from a secure configuration store.
fn load_shard_hmac_key() -> [u8; 64] {
    eprintln!("WARNING: SHARD_HMAC_KEY generated randomly at startup (NOT FOR PRODUCTION — use secure config)");
    crypto::entropy::generate_key_64()
}

/// Default listen address for the OPAQUE service.
const DEFAULT_ADDR: &str = "127.0.0.1:9005";

/// Process a single OPAQUE authentication request.
/// On success, creates and signs a Receipt (step_id=1, first in chain).
pub fn handle_request(
    store: &CredentialStore,
    request: &OpaqueRequest,
    signing_key: &[u8; 64],
) -> OpaqueResponse {
    match store.verify(&request.username, &request.password) {
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
    let shard_hmac_key = load_shard_hmac_key();
    let receipt_signing_key = load_receipt_signing_key();

    let listener = ShardListener::bind(DEFAULT_ADDR, ModuleId::Opaque, shard_hmac_key).await?;
    info!("OPAQUE service listening on {}", DEFAULT_ADDR);

    loop {
        let mut transport = listener.accept().await?;
        info!("Accepted SHARD connection");

        let (_sender, payload) = transport.recv().await?;

        let request: OpaqueRequest =
            postcard::from_bytes(&payload).map_err(|e| format!("deserialize request: {e}"))?;

        let response = handle_request(&store, &request, &receipt_signing_key);

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
