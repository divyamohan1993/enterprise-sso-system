use sso_common::types::TokenClaims;
use serde::{Deserialize, Serialize};

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
