//! Google OAuth 2.0 / OpenID Connect integration.
//!
//! Provides configuration, pending-auth state management, token exchange,
//! and JWT ID-token claim extraction and verification for Google sign-in.
//! Includes JWKS-based RS256 signature verification against Google's public keys.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::VerifyingKey;
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde::Deserialize;
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Google JWKS endpoint URL.
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// JWKS cache TTL: 1 hour.
const JWKS_CACHE_TTL: Duration = Duration::from_secs(3600);

/// HTTP request timeout for external calls.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

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
// JWKS cache
// ---------------------------------------------------------------------------

/// A single RSA public key from the JWKS response, indexed by key ID.
#[derive(Clone, Debug)]
struct CachedRsaKey {
    pub key: RsaPublicKey,
}

/// Thread-safe cache for Google's JWKS public keys.
/// Keys are refreshed when the TTL expires.
pub struct GoogleJwksCache {
    inner: RwLock<JwksCacheInner>,
}

struct JwksCacheInner {
    /// Map from key ID (`kid`) to parsed RSA public key.
    keys: HashMap<String, CachedRsaKey>,
    /// When the cache was last populated.
    fetched_at: Option<Instant>,
}

/// A single JWK entry from Google's JWKS response.
#[derive(Debug, Deserialize)]
struct JwkEntry {
    kid: String,
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    /// RSA modulus, base64url-encoded.
    n: String,
    /// RSA exponent, base64url-encoded.
    e: String,
}

/// The top-level JWKS response from Google.
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkEntry>,
}

impl GoogleJwksCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(JwksCacheInner {
                keys: HashMap::new(),
                fetched_at: None,
            }),
        }
    }

    /// Return the cached RSA public key for the given `kid`, refreshing the
    /// cache from Google's JWKS endpoint if it is stale or missing the key.
    async fn get_key(
        &self,
        kid: &str,
        http_client: &reqwest::Client,
    ) -> Result<RsaPublicKey, String> {
        // Fast path: read lock, check if cached and fresh.
        {
            let cache = self.inner.read().await;
            if let Some(fetched_at) = cache.fetched_at {
                if fetched_at.elapsed() < JWKS_CACHE_TTL {
                    if let Some(entry) = cache.keys.get(kid) {
                        return Ok(entry.key.clone());
                    }
                    // kid not found but cache is fresh — this is an error,
                    // but we will try one refresh in case Google rotated keys.
                }
            }
        }

        // Slow path: fetch and update.
        self.refresh(http_client).await?;

        let cache = self.inner.read().await;
        cache
            .keys
            .get(kid)
            .map(|e| e.key.clone())
            .ok_or_else(|| format!("no JWKS key found for kid: {kid}"))
    }

    /// Fetch Google's JWKS and replace the cache contents.
    async fn refresh(&self, http_client: &reqwest::Client) -> Result<(), String> {
        let resp = http_client
            .get(GOOGLE_JWKS_URL)
            .timeout(HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(format!("JWKS endpoint returned HTTP {status}"));
        }

        let jwks: JwksResponse = resp
            .json()
            .await
            .map_err(|e| format!("failed to parse JWKS response: {e}"))?;

        let mut new_keys = HashMap::new();
        for entry in &jwks.keys {
            if entry.kty != "RSA" {
                continue;
            }
            // If algorithm is specified, it must be RS256.
            if let Some(ref alg) = entry.alg {
                if alg != "RS256" {
                    continue;
                }
            }
            let n_bytes = URL_SAFE_NO_PAD
                .decode(&entry.n)
                .map_err(|e| format!("bad base64url in JWKS n for kid {}: {e}", entry.kid))?;
            let e_bytes = URL_SAFE_NO_PAD
                .decode(&entry.e)
                .map_err(|e| format!("bad base64url in JWKS e for kid {}: {e}", entry.kid))?;

            let n = BigUint::from_bytes_be(&n_bytes);
            let e = BigUint::from_bytes_be(&e_bytes);

            let pubkey = RsaPublicKey::new(n, e)
                .map_err(|err| format!("invalid RSA key for kid {}: {err}", entry.kid))?;

            new_keys.insert(
                entry.kid.clone(),
                CachedRsaKey { key: pubkey },
            );
        }

        if new_keys.is_empty() {
            return Err("JWKS response contained no usable RSA keys".into());
        }

        let mut cache = self.inner.write().await;
        cache.keys = new_keys;
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }
}

impl Default for GoogleJwksCache {
    fn default() -> Self {
        Self::new()
    }
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
///
/// **Production Note:** This in-memory store is suitable for single-instance
/// deployments only. In production with horizontal scaling, replace this with a
/// distributed store (Redis or PostgreSQL) to ensure state tokens are accessible
/// across all instances and survive process restarts.
pub struct PendingGoogleStore {
    map: HashMap<String, PendingGoogleAuth>,
}

/// Maximum number of pending OAuth entries before the store rejects new inserts.
/// Protects against state-flooding denial-of-service attacks.
const MAX_PENDING_ENTRIES: usize = 10_000;

/// Capacity threshold (80%) at which a SIEM warning is emitted.
const CAPACITY_WARNING_THRESHOLD: usize = MAX_PENDING_ENTRIES * 80 / 100;

/// Entry TTL in seconds (10 minutes).
const PENDING_TTL_SECS: i64 = 600;

impl PendingGoogleStore {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Insert a new pending auth entry. Returns `Err` if the store is at
    /// capacity (10,000 entries) even after evicting expired entries.
    pub fn insert(&mut self, state: String, pending: PendingGoogleAuth) -> Result<(), &'static str> {
        // Proactive cleanup before capacity check
        if self.map.len() >= CAPACITY_WARNING_THRESHOLD {
            self.cleanup_expired(pending.created_at);
        }

        // Emit SIEM capacity warning at 80% threshold
        if self.map.len() >= CAPACITY_WARNING_THRESHOLD {
            tracing::warn!(
                target: "siem",
                event_type = "capacity_warning",
                current = self.map.len(),
                max = MAX_PENDING_ENTRIES,
                "PendingGoogleStore at {}% capacity ({}/{})",
                self.map.len() * 100 / MAX_PENDING_ENTRIES,
                self.map.len(),
                MAX_PENDING_ENTRIES
            );
        }

        // Hard capacity limit: reject if full after cleanup
        if self.map.len() >= MAX_PENDING_ENTRIES {
            tracing::error!(
                target: "siem",
                event_type = "capacity_warning",
                "PendingGoogleStore at capacity ({MAX_PENDING_ENTRIES}), rejecting new entry"
            );
            return Err("pending OAuth store at capacity — try again later");
        }

        self.map.insert(state, pending);
        Ok(())
    }

    /// Consume and return the pending auth entry if it exists and has not expired.
    /// The 10-minute TTL is measured from `created_at`.
    pub fn consume(&mut self, state: &str, now: i64) -> Option<PendingGoogleAuth> {
        if let Some(entry) = self.map.remove(state) {
            if now - entry.created_at <= PENDING_TTL_SECS {
                return Some(entry);
            }
        }
        None
    }

    /// Remove all entries older than 10 minutes.
    pub fn cleanup_expired(&mut self, now: i64) {
        self.map.retain(|_, v| now - v.created_at <= PENDING_TTL_SECS);
    }

    /// Current number of pending entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
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
        .timeout(HTTP_TIMEOUT)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("token request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        // Sanitize: do not leak the response body which may contain tokens or
        // sensitive error details to upstream callers.
        let _body = resp.text().await.unwrap_or_default();
        tracing::error!("Google token endpoint returned {status}");
        return Err(format!("token endpoint returned {status}"));
    }

    resp.json::<GoogleTokenResponse>()
        .await
        .map_err(|e| format!("failed to parse token response: {e}"))
}

// ---------------------------------------------------------------------------
// JWT claim extraction with JWKS signature verification
// ---------------------------------------------------------------------------

/// JWT header claims used for algorithm and key-id validation.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    #[allow(dead_code)]
    typ: Option<String>,
    /// Key ID used to select the correct key from the JWKS.
    #[serde(default)]
    kid: Option<String>,
}

/// Decode and validate a Google ID token (a JWT), including full RS256
/// cryptographic signature verification against Google's JWKS public keys.
///
/// Performs the following security checks:
/// 1. Token has exactly 3 parts (header.payload.signature)
/// 2. Header specifies RS256 algorithm
/// 3. `kid` header is present and maps to a Google JWKS key
/// 4. RS256 signature is cryptographically verified against the JWKS public key
/// 5. Issuer is accounts.google.com or https://accounts.google.com
/// 6. Token has not expired (exp claim vs current time, 5-min skew allowed)
/// 7. Audience matches the expected client_id
pub async fn extract_google_claims(
    id_token: &str,
    expected_client_id: &str,
    jwks_cache: &GoogleJwksCache,
    http_client: &reqwest::Client,
) -> Result<GoogleIdTokenClaims, String> {
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

    let kid = header
        .kid
        .as_deref()
        .ok_or("JWT header missing required 'kid' field")?;

    // -----------------------------------------------------------------------
    // RS256 signature verification against Google JWKS
    // -----------------------------------------------------------------------
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("signature is not valid base64url: {e}"))?;

    let rsa_pubkey = jwks_cache.get_key(kid, http_client).await?;
    let verifying_key = VerifyingKey::<Sha256>::new(rsa_pubkey);
    let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| format!("invalid RSA signature encoding: {e}"))?;

    // SECURITY: RUSTSEC-2023-0071 (Marvin Attack) mitigation.
    //
    // The `rsa` crate's PKCS#1 v1.5 verification is vulnerable to timing
    // side-channels that can leak information about the private key via
    // observable differences in verification duration between valid and
    // invalid signatures.  Because Google mandates RS256 (PKCS#1 v1.5 +
    // SHA-256) for JWKS ID-token verification, we cannot switch to PSS.
    //
    // Mitigation: impose a constant-time floor of 50 ms on the entire
    // verification operation so that an attacker cannot distinguish fast
    // rejection from slow success.  The result is captured *before* the
    // floor elapses and only inspected *after*, ensuring no early-return
    // timing leak.
    let verify_start = std::time::Instant::now();
    let verify_result = verifying_key.verify(signing_input.as_bytes(), &signature);
    let verify_elapsed = verify_start.elapsed();
    let verify_floor = Duration::from_millis(50);
    if verify_elapsed < verify_floor {
        tokio::time::sleep(verify_floor - verify_elapsed).await;
    }
    verify_result.map_err(|_| "RS256 signature verification failed".to_string())?;

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
        .unwrap_or(std::time::Duration::ZERO)
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
        .unwrap_or(std::time::Duration::ZERO)
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
        ).unwrap();

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
        ).unwrap();

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
        ).unwrap();
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
        ).unwrap();
        store.cleanup_expired(1100);
        assert!(store.map.get("old").is_none());
        assert!(store.map.get("new").is_some());
    }

    #[test]
    fn test_pending_store_capacity_limit() {
        let mut store = PendingGoogleStore::new();
        // Fill to capacity
        for i in 0..10_000 {
            store.insert(
                format!("state-{i}"),
                PendingGoogleAuth {
                    milnet_client_id: "c".into(),
                    milnet_redirect_uri: "r".into(),
                    milnet_scope: "s".into(),
                    milnet_state: "st".into(),
                    milnet_nonce: None,
                    milnet_code_challenge: None,
                    created_at: 1000,
                },
            ).unwrap();
        }
        assert_eq!(store.len(), 10_000);
        // Next insert should fail
        let result = store.insert(
            "overflow".into(),
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
        assert!(result.is_err());
    }

    /// Test that the JWT header parsing extracts the `kid` field.
    #[test]
    fn test_jwt_header_parses_kid() {
        let hdr_json = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": "abc123"});
        let hdr: JwtHeader = serde_json::from_value(hdr_json).unwrap();
        assert_eq!(hdr.alg, "RS256");
        assert_eq!(hdr.kid.as_deref(), Some("abc123"));
    }

    /// Test that JWKS entry deserialization works.
    #[test]
    fn test_jwks_entry_deserialize() {
        let json = serde_json::json!({
            "kid": "key1",
            "kty": "RSA",
            "alg": "RS256",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        });
        let entry: JwkEntry = serde_json::from_value(json).unwrap();
        assert_eq!(entry.kid, "key1");
        assert_eq!(entry.kty, "RSA");
    }

    /// Test that GoogleJwksCache can be constructed.
    #[test]
    fn test_jwks_cache_new() {
        let cache = GoogleJwksCache::new();
        // Just verify it can be created without panic.
        drop(cache);
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

    /// Integration-style test: verify RS256 signature with a locally generated key.
    #[tokio::test]
    async fn test_extract_google_claims_verifies_rs256() {
        use rsa::pkcs1v15::SigningKey;

        // Generate a test RSA key pair
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let kid = "test-kid-001";

        // Build JWT header
        let header_json = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": kid});
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());

        // Build JWT payload
        let claims_json = serde_json::json!({
            "sub": "12345",
            "email": "user@example.com",
            "email_verified": true,
            "name": "Test User",
            "iss": "https://accounts.google.com",
            "aud": "my-client-id",
            "exp": 9999999999i64,
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(claims_json.to_string().as_bytes());

        // Sign
        let signing_input = format!("{header_b64}.{payload_b64}");
        let mut signing_key = SigningKey::<Sha256>::new(private_key);
        let sig = rsa::signature::SignerMut::sign(&mut signing_key, signing_input.as_bytes());
        use rsa::signature::SignatureEncoding;
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        let jwt = format!("{header_b64}.{payload_b64}.{sig_b64}");

        // Pre-populate the JWKS cache with our test key (no HTTP needed)
        let cache = GoogleJwksCache::new();
        {
            let mut inner = cache.inner.write().await;
            inner.keys.insert(
                kid.to_string(),
                CachedRsaKey {
                    key: public_key.clone(),
                },
            );
            inner.fetched_at = Some(Instant::now());
        }

        // The HTTP client won't be used since the cache is populated
        let http_client = reqwest::Client::new();
        let claims = extract_google_claims(&jwt, "my-client-id", &cache, &http_client)
            .await
            .unwrap();
        assert_eq!(claims.sub, "12345");
        assert_eq!(claims.email, "user@example.com");
        assert!(claims.email_verified);
    }

    /// Verify that a token with an invalid signature is rejected.
    #[tokio::test]
    async fn test_extract_google_claims_rejects_bad_signature() {
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let kid = "test-kid-002";

        let header_json = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": kid});
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());

        let claims_json = serde_json::json!({
            "sub": "12345",
            "email": "user@example.com",
            "email_verified": true,
            "iss": "https://accounts.google.com",
            "aud": "my-client-id",
            "exp": 9999999999i64,
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(claims_json.to_string().as_bytes());

        // Use garbage signature bytes (valid base64url but not a real RS256 sig)
        let fake_sig = URL_SAFE_NO_PAD.encode(&[0xDEu8; 64]);

        let jwt = format!("{header_b64}.{payload_b64}.{fake_sig}");

        let cache = GoogleJwksCache::new();
        {
            let mut inner = cache.inner.write().await;
            inner.keys.insert(
                kid.to_string(),
                CachedRsaKey {
                    key: public_key,
                },
            );
            inner.fetched_at = Some(Instant::now());
        }

        let http_client = reqwest::Client::new();
        let result = extract_google_claims(&jwt, "my-client-id", &cache, &http_client).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("signature") || err.contains("Signature"),
            "error should mention signature, got: {err}"
        );
    }

    /// Verify wrong algorithm is rejected (before any JWKS lookup).
    #[tokio::test]
    async fn test_extract_rejects_wrong_alg() {
        let header_json = serde_json::json!({"alg": "HS256", "typ": "JWT", "kid": "k"});
        let header = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());

        let claims_json = serde_json::json!({
            "sub": "12345", "email": "user@example.com", "email_verified": true,
            "iss": "https://accounts.google.com", "aud": "my-client-id", "exp": 9999999999i64,
        });
        let payload = URL_SAFE_NO_PAD.encode(claims_json.to_string().as_bytes());
        let fake_sig = URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{fake_sig}");

        let cache = GoogleJwksCache::new();
        let http_client = reqwest::Client::new();
        let result = extract_google_claims(&jwt, "my-client-id", &cache, &http_client).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("RS256"));
    }

    /// Verify missing kid is rejected.
    #[tokio::test]
    async fn test_extract_rejects_missing_kid() {
        let header_json = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let header = URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes());

        let claims_json = serde_json::json!({
            "sub": "12345", "email": "user@example.com", "email_verified": true,
            "iss": "https://accounts.google.com", "aud": "my-client-id", "exp": 9999999999i64,
        });
        let payload = URL_SAFE_NO_PAD.encode(claims_json.to_string().as_bytes());
        let fake_sig = URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{fake_sig}");

        let cache = GoogleJwksCache::new();
        let http_client = reqwest::Client::new();
        let result = extract_google_claims(&jwt, "my-client-id", &cache, &http_client).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("kid"));
    }
}
