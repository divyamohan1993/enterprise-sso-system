//! Wire messages for the OPAQUE password service.

use milnet_common::types::Receipt;
use serde::{Deserialize, Serialize};

/// Request from the Orchestrator to authenticate a user.
#[derive(Serialize, Deserialize)]
pub struct OpaqueRequest {
    pub username: String,
    pub password_hash: [u8; 32],
    pub ceremony_session_id: [u8; 32],
    pub dpop_key_hash: [u8; 32],
}

/// Response from the OPAQUE service after authentication attempt.
#[derive(Serialize, Deserialize)]
pub struct OpaqueResponse {
    pub success: bool,
    pub receipt: Option<Receipt>,
    pub error: Option<String>,
}
