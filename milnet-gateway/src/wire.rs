//! Wire protocol types for client-gateway communication.

use serde::{Deserialize, Serialize};

/// Authentication request sent by a client after solving the puzzle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password_hash: [u8; 32],
}

/// Authentication response returned by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub token: Option<Vec<u8>>,
    pub error: Option<String>,
}
