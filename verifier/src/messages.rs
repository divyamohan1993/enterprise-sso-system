use common::revocation::RevocationReason;
use common::types::TokenClaims;
use serde::{Deserialize, Serialize};

/// Envelope for all messages the verifier can receive over SHARD.
#[derive(Serialize, Deserialize)]
pub enum VerifierMessage {
    /// Standard token verification request.
    Verify(VerifyRequest),
    /// Revoke a token by its token_id.
    Revoke(RevokeRequest),
}

#[derive(Serialize, Deserialize)]
pub struct VerifyRequest {
    pub token_bytes: Vec<u8>, // postcard-serialized Token
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub claims: Option<TokenClaims>,
    pub error: Option<String>,
}

/// Request to revoke a token.
#[derive(Serialize, Deserialize)]
pub struct RevokeRequest {
    pub token_id: [u8; 16],
    pub reason: RevocationReason,
}

/// Response to a revocation request.
#[derive(Serialize, Deserialize)]
pub struct RevokeResponse {
    pub success: bool,
    pub error: Option<String>,
}
