use common::types::{Receipt, TokenClaims};
use serde::{Deserialize, Serialize};

/// A request to the TSS to validate a receipt chain and produce a threshold-signed token.
#[derive(Serialize, Deserialize)]
pub struct SigningRequest {
    pub receipts: Vec<Receipt>,
    pub claims: TokenClaims,
}

/// The TSS response containing either a serialized token or an error.
#[derive(Serialize, Deserialize)]
pub struct SigningResponse {
    pub success: bool,
    /// Serialized [`Token`] on success.
    pub token: Option<Vec<u8>>,
    pub error: Option<String>,
}
