use common::revocation::RevocationReason;
use common::types::TokenClaims;
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
    /// Optional DPoP client public key for channel binding verification.
    /// If provided, the verifier will check that the token's dpop_hash
    /// matches the hash of this key.
    pub client_dpop_key: Option<Vec<u8>>,
    /// Optional ratchet state for temporal binding verification.
    /// If provided (key + current epoch), the verifier will verify
    /// the token's ratchet tag and epoch window.
    pub ratchet_state: Option<RatchetState>,
}

/// Ratchet verification state carried in a verify request.
#[derive(Serialize, Deserialize)]
pub struct RatchetState {
    /// The 64-byte HMAC-SHA512 ratchet key for the session.
    #[serde(with = "byte_array_64")]
    pub ratchet_key: [u8; 64],
    /// The current ratchet epoch (verifier checks +/-3 window).
    pub current_epoch: u64,
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
