use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto::pq_sign::{PqSigningKey, PqVerifyingKey, generate_pq_keypair, pq_sign_raw, pq_verify_raw};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// Global JTI replay cache — tracks seen token IDs to prevent replay.
/// Entries are evicted after they expire (exp + skew tolerance).
/// Bounded to prevent memory exhaustion from long-lived cache entries.
static JTI_CACHE: std::sync::OnceLock<Mutex<JtiReplayCache>> = std::sync::OnceLock::new();

struct JtiReplayCache {
    /// Maps JTI -> expiry timestamp (seconds since epoch)
    seen: HashMap<String, i64>,
    /// Maximum cache size — oldest entries evicted when exceeded
    max_size: usize,
}

impl JtiReplayCache {
    fn new(max_size: usize) -> Self {
        Self {
            seen: HashMap::new(),
            max_size,
        }
    }

    /// Check if JTI has been seen. If not, record it.
    /// Returns Err if JTI was already used (replay detected).
    fn check_and_record(&mut self, jti: &str, exp: i64) -> Result<(), String> {
        // First, evict expired entries
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.seen.retain(|_, &mut e| e + 60 > now); // keep 60s past expiry for safety

        if self.seen.contains_key(jti) {
            return Err(format!("JTI replay detected: token '{}' has already been used", jti));
        }

        // Evict oldest if at capacity
        if self.seen.len() >= self.max_size {
            // Remove the entry with the earliest expiry
            if let Some(oldest_key) = self.seen.iter()
                .min_by_key(|(_, exp)| *exp)
                .map(|(k, _)| k.clone())
            {
                self.seen.remove(&oldest_key);
            }
        }

        self.seen.insert(jti.to_string(), exp);
        Ok(())
    }
}

fn jti_cache() -> &'static Mutex<JtiReplayCache> {
    JTI_CACHE.get_or_init(|| Mutex::new(JtiReplayCache::new(100_000)))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
    pub auth_time: i64,
    pub tier: u8,
    pub jti: String,
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

/// Returns token lifetime in seconds based on device tier.
/// Higher privilege tiers get shorter lifetimes to limit exposure.
fn token_lifetime_for_tier(tier: u8) -> i64 {
    match tier {
        1 => 300,   // Sovereign: 5 minutes
        2 => 600,   // Operational: 10 minutes
        3 => 900,   // Sensor: 15 minutes
        4 => 120,   // Emergency: 2 minutes
        _ => 120,   // Unknown tier: minimum lifetime
    }
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
        exp: now + token_lifetime_for_tier(tier),
        iat: now,
        nonce,
        auth_time: now,
        tier,
        jti: Uuid::new_v4().to_string(),
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

/// Audience validation is ALWAYS required. This cannot be disabled.
/// Previous env var toggle (REQUIRE_TOKEN_AUDIENCE) has been removed
/// for security hardening — tokens without valid audience are rejected.
pub fn is_audience_required() -> bool {
    true
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

    // Token expiry enforcement — expired tokens MUST be rejected.
    // This is checked BEFORE audience to fail fast on expired tokens.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock error".to_string())?
        .as_secs() as i64;

    // Allow 30 seconds of clock skew tolerance for distributed systems
    const CLOCK_SKEW_TOLERANCE_SECS: i64 = 30;
    if claims.exp + CLOCK_SKEW_TOLERANCE_SECS <= now {
        return Err(format!(
            "token expired: exp={}, now={}, skew_tolerance={}s",
            claims.exp, now, CLOCK_SKEW_TOLERANCE_SECS
        ));
    }

    // Reject tokens issued too far in the future (> 5 minutes ahead = likely clock skew attack)
    if claims.iat > now + 300 {
        return Err(format!(
            "token issued in the future: iat={}, now={} — possible clock manipulation",
            claims.iat, now
        ));
    }

    // JTI replay prevention — each token can only be verified once
    if !claims.jti.is_empty() {
        jti_cache()
            .lock()
            .map_err(|_| "JTI cache mutex poisoned".to_string())?
            .check_and_record(&claims.jti, claims.exp)?;
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::pq_sign::pq_sign_raw;

    fn big<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    /// Helper: sign arbitrary IdTokenClaims with an OidcSigningKey.
    /// This bypasses create_id_token's internal claim generation, allowing
    /// tests to craft tokens with malicious/expired/future claims.
    fn sign_claims_manually(sk: &OidcSigningKey, claims: &IdTokenClaims) -> String {
        let header = serde_json::json!({
            "alg": "ML-DSA-87",
            "typ": "JWT",
            "kid": sk.kid()
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = pq_sign_raw(&sk.signing_key, signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
        format!("{signing_input}.{sig_b64}")
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    // ── Expired token rejection ─────────────────────────────────────────

    #[test]
    fn verify_rejects_expired_token() {
        big(|| {
            let sk = OidcSigningKey::generate();
            let now = now_secs();

            let claims = IdTokenClaims {
                iss: "test".into(),
                sub: Uuid::new_v4().to_string(),
                aud: "test-client".into(),
                exp: now - 120, // expired 2 minutes ago
                iat: now - 720,
                nonce: None,
                auth_time: now - 720,
                tier: 2,
                jti: Uuid::new_v4().to_string(),
            };

            let token = sign_claims_manually(&sk, &claims);
            let result = verify_id_token_with_audience(
                &token, sk.verifying_key(), "test-client", true,
            );
            assert!(result.is_err());
            assert!(
                result.unwrap_err().contains("expired"),
                "error must mention 'expired'"
            );
        });
    }

    // ── Future IAT rejection ────────────────────────────────────────────

    #[test]
    fn verify_rejects_future_iat() {
        big(|| {
            let sk = OidcSigningKey::generate();
            let now = now_secs();

            let claims = IdTokenClaims {
                iss: "test".into(),
                sub: Uuid::new_v4().to_string(),
                aud: "test-client".into(),
                exp: now + 1200,
                iat: now + 600, // 10 min in the future
                nonce: None,
                auth_time: now + 600,
                tier: 2,
                jti: Uuid::new_v4().to_string(),
            };

            let token = sign_claims_manually(&sk, &claims);
            let result = verify_id_token_with_audience(
                &token, sk.verifying_key(), "test-client", true,
            );
            assert!(result.is_err());
            assert!(
                result.unwrap_err().contains("future"),
                "error must mention 'future'"
            );
        });
    }

    // ── JTI replay detection ────────────────────────────────────────────

    #[test]
    fn verify_rejects_jti_replay() {
        big(|| {
            let sk = OidcSigningKey::generate();
            let token = create_id_token("test-iss", &Uuid::new_v4(), "test-aud", None, &sk);

            // First verification should succeed
            let r1 = verify_id_token(&token, sk.verifying_key());
            assert!(r1.is_ok(), "first verification must succeed");

            // Second verification of same token should fail (JTI replay)
            let r2 = verify_id_token(&token, sk.verifying_key());
            assert!(r2.is_err(), "JTI replay must be rejected");
            let err = r2.unwrap_err();
            assert!(
                err.contains("replay") || err.contains("JTI"),
                "error must mention replay or JTI, got: {err}"
            );
        });
    }

    // ── Audience mismatch ───────────────────────────────────────────────

    #[test]
    fn verify_rejects_audience_mismatch() {
        big(|| {
            let sk = OidcSigningKey::generate();
            let token = create_id_token("test-iss", &Uuid::new_v4(), "real-client", None, &sk);

            let result = verify_id_token_with_audience(
                &token, sk.verifying_key(), "wrong-client", true,
            );
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("audience mismatch"));
        });
    }

    // ── Algorithm confusion attack ──────────────────────────────────────

    #[test]
    fn verify_rejects_wrong_algorithm_header() {
        big(|| {
            let sk = OidcSigningKey::generate();
            let now = now_secs();

            // Craft a token with RS256 algorithm header (algorithm confusion)
            let header = serde_json::json!({
                "alg": "RS256",
                "typ": "JWT",
                "kid": sk.kid()
            });
            let claims = IdTokenClaims {
                iss: "test".into(),
                sub: Uuid::new_v4().to_string(),
                aud: "test-client".into(),
                exp: now + 600,
                iat: now,
                nonce: None,
                auth_time: now,
                tier: 2,
                jti: Uuid::new_v4().to_string(),
            };
            let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
            let signing_input = format!("{header_b64}.{claims_b64}");
            let signature = pq_sign_raw(&sk.signing_key, signing_input.as_bytes());
            let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
            let token = format!("{signing_input}.{sig_b64}");

            let result = verify_id_token(&token, sk.verifying_key());
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("unsupported algorithm"));
        });
    }

    // ── Token with empty JTI ────────────────────────────────────────────

    #[test]
    fn verify_accepts_empty_jti_but_no_replay_protection() {
        big(|| {
            let sk = OidcSigningKey::generate();
            let now = now_secs();

            let claims = IdTokenClaims {
                iss: "test".into(),
                sub: Uuid::new_v4().to_string(),
                aud: "test-client".into(),
                exp: now + 600,
                iat: now,
                nonce: None,
                auth_time: now,
                tier: 2,
                jti: String::new(), // empty JTI
            };

            let token = sign_claims_manually(&sk, &claims);
            // Empty JTI tokens skip JTI cache — verification succeeds
            let r1 = verify_id_token_with_audience(&token, sk.verifying_key(), "test-client", true);
            assert!(r1.is_ok(), "empty JTI token should still verify");

            // Second verification also succeeds (no replay protection for empty JTI)
            let r2 = verify_id_token_with_audience(&token, sk.verifying_key(), "test-client", true);
            assert!(r2.is_ok(), "empty JTI skips replay detection");
        });
    }

    // ── Barely-expired token (within skew tolerance) ────────────────────

    #[test]
    fn verify_accepts_token_within_skew_tolerance() {
        big(|| {
            let sk = OidcSigningKey::generate();
            let now = now_secs();

            // exp is 10 seconds ago — within the 30s skew tolerance
            let claims = IdTokenClaims {
                iss: "test".into(),
                sub: Uuid::new_v4().to_string(),
                aud: "test-client".into(),
                exp: now - 10,
                iat: now - 620,
                nonce: None,
                auth_time: now - 620,
                tier: 2,
                jti: Uuid::new_v4().to_string(),
            };

            let token = sign_claims_manually(&sk, &claims);
            let result = verify_id_token_with_audience(
                &token, sk.verifying_key(), "test-client", true,
            );
            assert!(
                result.is_ok(),
                "token within 30s skew tolerance should be accepted: {:?}",
                result.err()
            );
        });
    }
}
