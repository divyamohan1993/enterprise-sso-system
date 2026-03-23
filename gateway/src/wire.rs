//! Wire protocol types for client-gateway communication.

use serde::{Deserialize, Serialize};

/// X-Wing KEM ciphertext sent from server to client after puzzle verification.
///
/// The client decapsulates this against their private key to obtain the same
/// shared secret the server derived during encapsulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemCiphertext {
    /// Serialized `crypto::xwing::Ciphertext` (X25519 ephemeral PK || ML-KEM-1024 CT).
    pub ciphertext: Vec<u8>,
}

/// Authentication request sent by a client after solving the puzzle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: Vec<u8>,
}

/// Authentication response returned by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub token: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// Request from the Gateway to the Orchestrator (mirrors orchestrator message type).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorRequest {
    pub username: String,
    pub password: Vec<u8>,
    pub dpop_key_hash: [u8; 32],
    /// Requested authentication tier (1-4). Defaults to 2 if 0.
    pub tier: u8,
    /// Target audience for the token (passed through to the TSS for inclusion
    /// in the token's `aud` claim).
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub device_attestation_age_secs: Option<f64>,
    #[serde(default)]
    pub geo_velocity_kmh: Option<f64>,
    #[serde(default)]
    pub is_unusual_network: Option<bool>,
    #[serde(default)]
    pub is_unusual_time: Option<bool>,
    #[serde(default)]
    pub unusual_access_score: Option<f64>,
    #[serde(default)]
    pub recent_failed_attempts: Option<u32>,
}

/// Response from the Orchestrator to the Gateway (mirrors orchestrator message type).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorResponse {
    pub success: bool,
    pub token_bytes: Option<Vec<u8>>,
    pub error: Option<String>,
}
