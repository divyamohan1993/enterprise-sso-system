use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto::pq_sign::{PqSigningKey, PqVerifyingKey, generate_pq_keypair, pq_sign_raw, pq_verify_raw};
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
    pub tier: u8,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub id_token: String,
    pub scope: String,
}

/// Wrapper around an ML-DSA-87 keypair used for signing OIDC ID tokens.
pub struct OidcSigningKey {
    signing_key: PqSigningKey,
    verifying_key: PqVerifyingKey,
    kid: String,
}

impl OidcSigningKey {
    /// Generate a new ML-DSA-87 signing key for OIDC.
    pub fn generate() -> Self {
        let (signing_key, verifying_key) = generate_pq_keypair();
        Self {
            signing_key,
            verifying_key,
            kid: "milnet-mldsa87-v1".to_string(),
        }
    }

    /// Return the verifying key for signature verification.
    pub fn verifying_key(&self) -> &PqVerifyingKey {
        &self.verifying_key
    }

    /// Key ID for JWK `kid` field.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Build the JWKS JSON value for this key.
    pub fn jwks_json(&self) -> serde_json::Value {
        let vk_bytes = self.verifying_key.encode();
        let vk_b64 = URL_SAFE_NO_PAD.encode(AsRef::<[u8]>::as_ref(&vk_bytes));
        serde_json::json!({
            "keys": [{
                "kty": "ML-DSA",
                "alg": "ML-DSA-87",
                "use": "sig",
                "kid": self.kid,
                "pub": vk_b64
            }]
        })
    }
}

/// Create an ML-DSA-87-signed JWT (for the OIDC layer)
pub fn create_id_token(
    issuer: &str,
    user_id: &Uuid,
    client_id: &str,
    nonce: Option<String>,
    signing_key: &OidcSigningKey,
) -> String {
    create_id_token_with_tier(issuer, user_id, client_id, nonce, signing_key, 2)
}

/// Create an ML-DSA-87-signed JWT with an explicit tier claim
pub fn create_id_token_with_tier(
    issuer: &str,
    user_id: &Uuid,
    client_id: &str,
    nonce: Option<String>,
    signing_key: &OidcSigningKey,
    tier: u8,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let header = serde_json::json!({
        "alg": "ML-DSA-87",
        "typ": "JWT",
        "kid": signing_key.kid()
    });
    let claims = IdTokenClaims {
        iss: issuer.to_string(),
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        exp: now + 3600,
        iat: now,
        nonce,
        auth_time: now,
        tier,
    };

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let signature = pq_sign_raw(&signing_key.signing_key, signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

    format!("{signing_input}.{sig_b64}")
}

/// Verify an ML-DSA-87-signed JWT using the verifying key.
///
/// This performs signature verification only. Use `verify_id_token_with_audience`
/// for full audience-bound verification in production.
pub fn verify_id_token(token: &str, verifying_key: &PqVerifyingKey) -> Result<IdTokenClaims, String> {
    verify_id_token_inner(token, verifying_key, None, false)
}

/// Verify an ML-DSA-87-signed JWT with mandatory audience binding.
///
/// When `require_audience` is true (recommended for production, controlled by
/// `REQUIRE_TOKEN_AUDIENCE` env var, default true), the token's `aud` field
/// MUST be present and match `expected_audience`.
pub fn verify_id_token_with_audience(
    token: &str,
    verifying_key: &PqVerifyingKey,
    expected_audience: &str,
    require_audience: bool,
) -> Result<IdTokenClaims, String> {
    verify_id_token_inner(token, verifying_key, Some(expected_audience), require_audience)
}

/// Returns whether audience enforcement is enabled via environment config.
/// Defaults to true (audience required) unless `REQUIRE_TOKEN_AUDIENCE=false`.
pub fn is_audience_required() -> bool {
    std::env::var("REQUIRE_TOKEN_AUDIENCE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true)
}

fn verify_id_token_inner(
    token: &str,
    verifying_key: &PqVerifyingKey,
    expected_audience: Option<&str>,
    require_audience: bool,
) -> Result<IdTokenClaims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT: expected 3 parts".into());
    }

    // Validate algorithm header to prevent algorithm confusion attacks
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| format!("base64 decode header: {e}"))?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("parse header: {e}"))?;
    match header.get("alg").and_then(|v| v.as_str()) {
        Some("ML-DSA-87") => {}
        Some(other) => return Err(format!("unsupported algorithm: {other}")),
        None => return Err("missing alg in JWT header".into()),
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("base64 decode sig: {e}"))?;

    if !pq_verify_raw(verifying_key, signing_input.as_bytes(), &sig_bytes) {
        return Err("ML-DSA-87 verification failed".into());
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("base64 decode claims: {e}"))?;
    let claims: IdTokenClaims =
        serde_json::from_slice(&claims_bytes).map_err(|e| format!("parse claims: {e}"))?;

    // Audience validation
    if let Some(expected) = expected_audience {
        if claims.aud != expected {
            return Err(format!(
                "audience mismatch: expected '{}', got '{}'",
                expected, claims.aud
            ));
        }
    } else if require_audience && claims.aud.is_empty() {
        return Err("token audience (aud) is required but missing or empty".into());
    }

    Ok(claims)
}

/// Verify an ML-DSA-87-signed JWT with audience and optional nonce validation.
///
/// Performs full signature verification, audience check, and — when
/// `expected_nonce` is `Some` — verifies that the token's nonce matches
/// using constant-time comparison.
pub fn verify_id_token_full(
    token: &str,
    verifying_key: &PqVerifyingKey,
    expected_audience: &str,
    expected_nonce: Option<&str>,
) -> Result<IdTokenClaims, String> {
    let claims = verify_id_token_with_audience(token, verifying_key, expected_audience, true)?;

    if let Some(nonce) = expected_nonce {
        match &claims.nonce {
            Some(token_nonce) => {
                if !crypto::ct::ct_eq(token_nonce.as_bytes(), nonce.as_bytes()) {
                    return Err("nonce mismatch: token nonce does not match expected nonce".into());
                }
            }
            None => {
                return Err("expected nonce but token has no nonce claim".into());
            }
        }
    }

    Ok(claims)
}
