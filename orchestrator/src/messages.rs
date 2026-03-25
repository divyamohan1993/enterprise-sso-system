//! Wire messages for the Auth Orchestrator.

use serde::{Deserialize, Serialize};

/// Serde helper for `[u8; 64]` — serde only supports arrays up to 32 natively.
mod byte_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(de)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })
    }
}

/// Request from the Gateway to the Orchestrator to authenticate a user.
#[derive(Serialize, Deserialize)]
pub struct OrchestratorRequest {
    pub username: String,
    pub password: Vec<u8>,
    #[serde(with = "byte_array_64")]
    pub dpop_key_hash: [u8; 64],
    /// Requested authentication tier (1-4). Defaults to 2 if 0.
    pub tier: u8,
    /// Target audience for the token (passed through to the TSS for inclusion
    /// in the token's `aud` claim). If `None`, the TSS uses a default audience.
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

/// Response from the Orchestrator to the Gateway.
#[derive(Serialize, Deserialize)]
pub struct OrchestratorResponse {
    pub success: bool,
    pub token_bytes: Option<Vec<u8>>,
    pub error: Option<String>,
}
