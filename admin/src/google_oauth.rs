//! Google OAuth 2.0 / OpenID Connect integration.
//!
//! Provides configuration, pending-auth state management, token exchange,
//! and JWT ID-token claim extraction and verification for Google sign-in.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Google OAuth application credentials.
#[derive(Clone, Debug)]
pub struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

// ---------------------------------------------------------------------------
// Pending auth state
// ---------------------------------------------------------------------------

/// Captures the original MILNET OAuth parameters so we can resume the flow
/// after the user completes Google sign-in.
#[derive(Clone, Debug)]
pub struct PendingGoogleAuth {
    pub milnet_client_id: String,
    pub milnet_redirect_uri: String,
    pub milnet_scope: String,
    pub milnet_state: String,
    pub milnet_nonce: Option<String>,
    pub milnet_code_challenge: Option<String>,
    pub created_at: i64,
}

/// In-memory store for pending Google OAuth flows keyed by a random state token.
/// Entries expire after 10 minutes.
pub struct PendingGoogleStore {
    map: HashMap<String, PendingGoogleAuth>,
}

impl PendingGoogleStore {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, state: String, pending: PendingGoogleAuth) {
        self.map.insert(state, pending);
    }

    /// Consume and return the pending auth entry if it exists and has not expired.
    /// The 10-minute TTL is measured from `created_at`.
    pub fn consume(&mut self, state: &str, now: i64) -> Option<PendingGoogleAuth> {
        if let Some(entry) = self.map.remove(state) {
            const TTL_SECS: i64 = 600; // 10 minutes
            if now - entry.created_at <= TTL_SECS {
                return Some(entry);
            }
        }
        None
    }

    /// Remove all entries older than 10 minutes.
    pub fn cleanup_expired(&mut self, now: i64) {
        const TTL_SECS: i64 = 600;
        self.map.retain(|_, v| now - v.created_at <= TTL_SECS);
    }
}

impl Default for PendingGoogleStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Token response
// ---------------------------------------------------------------------------

/// Response from Google's token endpoint.
#[derive(Debug, Deserialize)]
pub struct GoogleTokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub token_type: String,
}

// ---------------------------------------------------------------------------
// ID token claims
// ---------------------------------------------------------------------------

/// Claims extracted from a Google ID token JWT payload.
#[derive(Debug, Deserialize)]
pub struct GoogleIdTokenClaims {
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
}

// ---------------------------------------------------------------------------
// URL builder
// ---------------------------------------------------------------------------

/// Build the Google authorization URL the browser should be redirected to.
pub fn build_google_auth_url(config: &GoogleOAuthConfig, state_token: &str) -> String {
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&access_type=offline&prompt=consent",
        urlencoding::encode(&config.client_id),
        urlencoding::encode(&config.redirect_uri),
        urlencoding::encode("openid email profile"),
        urlencoding::encode(state_token),
    )
}

// ---------------------------------------------------------------------------
// Token exchange
// ---------------------------------------------------------------------------

/// Exchange an authorization code for tokens via Google's token endpoint.
pub async fn exchange_code_for_tokens(
    config: &GoogleOAuthConfig,
    code: &str,
    http_client: &reqwest::Client,
) -> Result<GoogleTokenResponse, String> {
    let params = [
        ("code", code),
        ("client_id", &config.client_id),
        ("client_secret", &config.client_secret),
        ("redirect_uri", &config.redirect_uri),
        ("grant_type", "authorization_code"),
    ];

    let resp = http_client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("token request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("token endpoint returned {status}: {body}"));
    }

    resp.json::<GoogleTokenResponse>()
        .await
        .map_err(|e| format!("failed to parse token response: {e}"))
}

// ---------------------------------------------------------------------------
// JWT claim extraction
// ---------------------------------------------------------------------------

/// JWT header claims used for algorithm validation.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
}

/// Decode and validate the structure of a Google ID token (a JWT).
///
/// Performs the following security checks:
/// 1. Token has exactly 3 parts (header.payload.signature)
/// 2. Header specifies RS256 algorithm
/// 3. Signature part is present and non-empty (format validation)
/// 4. Issuer is accounts.google.com or https://accounts.google.com
/// 5. Token has not expired (exp claim vs current time)
/// 6. Audience matches the expected client_id
///
/// NOTE: Full RS256 cryptographic signature verification against Google's JWKS
/// keys (https://www.googleapis.com/oauth2/v3/certs) is not implemented here.
/// The token is received directly from Google's token endpoint over TLS, which
/// provides transport-level authenticity. For defense-in-depth, a production
/// deployment should fetch and cache Google's JWKS and verify the RSA signature.
pub fn extract_google_claims(id_token: &str, expected_client_id: &str) -> Result<GoogleIdTokenClaims, String> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err("id_token is not a valid JWT (expected 3 parts)".into());
    }

    // Validate that the signature part is non-empty (structural check)
    if parts[2].is_empty() {
        return Err("id_token has an empty signature".into());
    }

    // Decode and validate the JWT header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| format!("base64 decode error on header: {e}"))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("failed to parse JWT header: {e}"))?;

    if header.alg != "RS256" {
        return Err(format!(
            "unexpected JWT algorithm: expected RS256, got {}",
            header.alg
        ));
    }

    // Validate that the signature is valid base64url (well-formed)
    URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("signature is not valid base64url: {e}"))?;

    // Decode the payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("base64 decode error on payload: {e}"))?;

    let claims: GoogleIdTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("failed to parse id_token claims: {e}"))?;

    // Validate issuer
    if claims.iss != "https://accounts.google.com" && claims.iss != "accounts.google.com" {
        return Err(format!("unexpected issuer: {}", claims.iss));
    }

    // Validate audience matches our client_id
    if claims.aud != expected_client_id {
        return Err(format!(
            "audience mismatch: expected {}, got {}",
            expected_client_id, claims.aud
        ));
    }

    // Validate expiry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Allow 5 minutes of clock skew
    if claims.exp < now - 300 {
        return Err("id_token has expired".into());
    }

    Ok(claims)
}

// ---------------------------------------------------------------------------
// Claim verification
// ---------------------------------------------------------------------------

/// Verify essential fields of the Google ID token claims.
pub fn verify_google_id_token(
    claims: &GoogleIdTokenClaims,
    expected_aud: &str,
) -> Result<(), String> {
    // Issuer must be Google
    if claims.iss != "https://accounts.google.com" && claims.iss != "accounts.google.com" {
        return Err(format!("unexpected issuer: {}", claims.iss));
    }

    // Audience must match our client_id
    if claims.aud != expected_aud {
        return Err(format!(
            "audience mismatch: expected {expected_aud}, got {}",
            claims.aud
        ));
    }

    // Token must not be expired
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if claims.exp < now {
        return Err("id_token has expired".into());
    }

    // Email must be verified
    if !claims.email_verified {
        return Err("email is not verified".into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_google_auth_url() {
        let config = GoogleOAuthConfig {
            client_id: "my-client-id".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://example.com/callback".into(),
        };
        let url = build_google_auth_url(&config, "rand-state-123");
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(url.contains("client_id=my-client-id"));
        assert!(url.contains("state=rand-state-123"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
    }

    #[test]
    fn test_pending_store_insert_and_consume() {
        let mut store = PendingGoogleStore::new();
        let now = 1000i64;
        store.insert(
            "state1".into(),
            PendingGoogleAuth {
                milnet_client_id: "c1".into(),
                milnet_redirect_uri: "https://r".into(),
                milnet_scope: "openid".into(),
                milnet_state: "s".into(),
                milnet_nonce: None,
                milnet_code_challenge: None,
                created_at: now,
            },
        );

        // Consume within TTL
        let entry = store.consume("state1", now + 300);
        assert!(entry.is_some());

        // Already consumed
        let entry = store.consume("state1", now + 300);
        assert!(entry.is_none());
    }

    #[test]
    fn test_pending_store_expired() {
        let mut store = PendingGoogleStore::new();
        let now = 1000i64;
        store.insert(
            "state1".into(),
            PendingGoogleAuth {
                milnet_client_id: "c1".into(),
                milnet_redirect_uri: "https://r".into(),
                milnet_scope: "openid".into(),
                milnet_state: "s".into(),
                milnet_nonce: None,
                milnet_code_challenge: None,
                created_at: now,
            },
        );

        // Consume after TTL expires
        let entry = store.consume("state1", now + 601);
        assert!(entry.is_none());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut store = PendingGoogleStore::new();
        store.insert(
            "old".into(),
            PendingGoogleAuth {
                milnet_client_id: "c".into(),
                milnet_redirect_uri: "r".into(),
                milnet_scope: "s".into(),
                milnet_state: "st".into(),
                milnet_nonce: None,
                milnet_code_challenge: None,
                created_at: 100,
            },
        );
        store.insert(
            "new".into(),
            PendingGoogleAuth {
                milnet_client_id: "c".into(),
                milnet_redirect_uri: "r".into(),
                milnet_scope: "s".into(),
                milnet_state: "st".into(),
                milnet_nonce: None,
                milnet_code_challenge: None,
                created_at: 1000,
            },
        );
        store.cleanup_expired(1100);
        assert!(store.map.get("old").is_none());
        assert!(store.map.get("new").is_some());
    }

    #[test]
    fn test_extract_google_claims() {
        // Build a fake JWT with a valid base64url-encoded header and payload
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let header_json = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let header = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());

        let claims_json = serde_json::json!({
            "sub": "12345",
            "email": "user@example.com",
            "email_verified": true,
            "name": "Test User",
            "iss": "https://accounts.google.com",
            "aud": "my-client-id",
            "exp": 9999999999i64,
        });
        let payload = URL_SAFE_NO_PAD.encode(claims_json.to_string().as_bytes());
        // Use a non-empty base64url signature stub (structural validation only)
        let fake_sig = URL_SAFE_NO_PAD.encode(b"fake-signature-bytes");
        let fake_jwt = format!("{header}.{payload}.{fake_sig}");

        let claims = extract_google_claims(&fake_jwt, "my-client-id").unwrap();
        assert_eq!(claims.sub, "12345");
        assert_eq!(claims.email, "user@example.com");
        assert!(claims.email_verified);
        assert_eq!(claims.iss, "https://accounts.google.com");
    }

    #[test]
    fn test_extract_google_claims_rejects_wrong_alg() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let header_json = serde_json::json!({"alg": "HS256", "typ": "JWT"});
        let header = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());

        let claims_json = serde_json::json!({
            "sub": "12345", "email": "user@example.com", "email_verified": true,
            "iss": "https://accounts.google.com", "aud": "my-client-id", "exp": 9999999999i64,
        });
        let payload = URL_SAFE_NO_PAD.encode(claims_json.to_string().as_bytes());
        let fake_sig = URL_SAFE_NO_PAD.encode(b"sig");
        let fake_jwt = format!("{header}.{payload}.{fake_sig}");

        let result = extract_google_claims(&fake_jwt, "my-client-id");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("RS256"));
    }

    #[test]
    fn test_extract_google_claims_rejects_wrong_audience() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let header_json = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let header = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());

        let claims_json = serde_json::json!({
            "sub": "12345", "email": "user@example.com", "email_verified": true,
            "iss": "https://accounts.google.com", "aud": "wrong-client-id", "exp": 9999999999i64,
        });
        let payload = URL_SAFE_NO_PAD.encode(claims_json.to_string().as_bytes());
        let fake_sig = URL_SAFE_NO_PAD.encode(b"sig");
        let fake_jwt = format!("{header}.{payload}.{fake_sig}");

        let result = extract_google_claims(&fake_jwt, "my-client-id");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("audience mismatch"));
    }

    #[test]
    fn test_extract_google_claims_rejects_expired() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let header_json = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let header = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());

        let claims_json = serde_json::json!({
            "sub": "12345", "email": "user@example.com", "email_verified": true,
            "iss": "https://accounts.google.com", "aud": "my-client-id", "exp": 1000000i64,
        });
        let payload = URL_SAFE_NO_PAD.encode(claims_json.to_string().as_bytes());
        let fake_sig = URL_SAFE_NO_PAD.encode(b"sig");
        let fake_jwt = format!("{header}.{payload}.{fake_sig}");

        let result = extract_google_claims(&fake_jwt, "my-client-id");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn test_extract_google_claims_rejects_empty_signature() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let header_json = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let header = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());

        let claims_json = serde_json::json!({
            "sub": "12345", "email": "user@example.com", "email_verified": true,
            "iss": "https://accounts.google.com", "aud": "my-client-id", "exp": 9999999999i64,
        });
        let payload = URL_SAFE_NO_PAD.encode(claims_json.to_string().as_bytes());
        let fake_jwt = format!("{header}.{payload}.");

        let result = extract_google_claims(&fake_jwt, "my-client-id");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty signature"));
    }

    #[test]
    fn test_verify_google_id_token_valid() {
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600;

        let claims = GoogleIdTokenClaims {
            sub: "12345".into(),
            email: "user@example.com".into(),
            email_verified: true,
            name: Some("Test".into()),
            iss: "https://accounts.google.com".into(),
            aud: "my-client-id".into(),
            exp: future_exp,
        };
        assert!(verify_google_id_token(&claims, "my-client-id").is_ok());
    }

    #[test]
    fn test_verify_google_id_token_bad_iss() {
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600;

        let claims = GoogleIdTokenClaims {
            sub: "12345".into(),
            email: "user@example.com".into(),
            email_verified: true,
            name: None,
            iss: "https://evil.com".into(),
            aud: "my-client-id".into(),
            exp: future_exp,
        };
        assert!(verify_google_id_token(&claims, "my-client-id").is_err());
    }

    #[test]
    fn test_verify_google_id_token_email_not_verified() {
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600;

        let claims = GoogleIdTokenClaims {
            sub: "12345".into(),
            email: "user@example.com".into(),
            email_verified: false,
            name: None,
            iss: "https://accounts.google.com".into(),
            aud: "my-client-id".into(),
            exp: future_exp,
        };
        assert!(verify_google_id_token(&claims, "my-client-id").is_err());
    }
}
