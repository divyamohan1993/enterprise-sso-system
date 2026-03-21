use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
    pub auth_time: i64,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub id_token: String,
    pub scope: String,
}

/// Create a simple HMAC-signed JWT (for the OIDC layer)
pub fn create_id_token(
    issuer: &str,
    user_id: &Uuid,
    client_id: &str,
    nonce: Option<String>,
    signing_key: &[u8; 64],
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let header = serde_json::json!({"alg": "HS512", "typ": "JWT"});
    let claims = IdTokenClaims {
        iss: issuer.to_string(),
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        exp: now + 3600,
        iat: now,
        nonce,
        auth_time: now,
    };

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let mut mac = Hmac::<Sha512>::new_from_slice(signing_key).unwrap();
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

    format!("{signing_input}.{sig_b64}")
}
