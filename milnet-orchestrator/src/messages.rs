//! Wire messages for the Auth Orchestrator.

use serde::{Deserialize, Serialize};

/// Request from the Gateway to the Orchestrator to authenticate a user.
#[derive(Serialize, Deserialize)]
pub struct OrchestratorRequest {
    pub username: String,
    pub password_hash: [u8; 32],
    pub dpop_key_hash: [u8; 32],
}

/// Response from the Orchestrator to the Gateway.
#[derive(Serialize, Deserialize)]
pub struct OrchestratorResponse {
    pub success: bool,
    pub token_bytes: Option<Vec<u8>>,
    pub error: Option<String>,
}
