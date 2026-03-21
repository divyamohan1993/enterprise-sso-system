//! Wire messages for the Auth Orchestrator.

use serde::{Deserialize, Serialize};

/// Request from the Gateway to the Orchestrator to authenticate a user.
#[derive(Serialize, Deserialize)]
pub struct OrchestratorRequest {
    pub username: String,
    pub password: Vec<u8>,
    pub dpop_key_hash: [u8; 32],
    /// Requested authentication tier (1-4). Defaults to 2 if 0.
    pub tier: u8,
}

/// Response from the Orchestrator to the Gateway.
#[derive(Serialize, Deserialize)]
pub struct OrchestratorResponse {
    pub success: bool,
    pub token_bytes: Option<Vec<u8>>,
    pub error: Option<String>,
}
