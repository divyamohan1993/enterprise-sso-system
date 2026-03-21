use common::types::{Receipt, TokenClaims};
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

/// A request to the TSS to validate a receipt chain and produce a threshold-signed token.
#[derive(Serialize, Deserialize)]
pub struct SigningRequest {
    pub receipts: Vec<Receipt>,
    pub claims: TokenClaims,
    /// Ratchet key for computing the token's HMAC-SHA512 ratchet tag.
    #[serde(with = "byte_array_64")]
    pub ratchet_key: [u8; 64],
}

/// The TSS response containing either a serialized token or an error.
#[derive(Serialize, Deserialize)]
pub struct SigningResponse {
    pub success: bool,
    /// Serialized [`Token`] on success.
    pub token: Option<Vec<u8>>,
    pub error: Option<String>,
}
