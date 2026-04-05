use crate::pkce;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// HMAC key for blinding PKCE code_challenge values at rest.
/// In production this MUST be loaded from a KMS / HSM — this static key is
/// for the in-memory store only. The persistent store should use envelope
/// encryption via the `crypto::seal` module.
static PKCE_BLIND_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

fn pkce_blind_key() -> &'static [u8; 32] {
    PKCE_BLIND_KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        if getrandom::getrandom(&mut key).is_err() {
            common::siem::emit_runtime_error(
                common::siem::category::CRYPTO_FAILURE,
                "OS CSPRNG unavailable — cannot generate PKCE blind key",
                "getrandom failed",
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            // Abort: operating without a PKCE blind key would leave code
            // challenges in plaintext, which is a security violation.
            std::process::abort();
        }
        key
    })
}

/// Compute HMAC-SHA256 blind index of a code_challenge so it is never stored
/// in plaintext. Verification recomputes the HMAC and uses constant-time
/// comparison (HMAC equality).
fn blind_code_challenge(code_challenge: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    // Key length is always 32 bytes which is valid for HMAC — unwrap is safe here,
    // but we defend against it anyway for defense-in-depth.
    let mac = match HmacSha256::new_from_slice(pkce_blind_key()) {
        Ok(m) => m,
        Err(_) => {
            common::siem::emit_runtime_error(
                common::siem::category::CRYPTO_FAILURE,
                "HMAC-SHA256 key init failed for PKCE blind",
                "invalid key length",
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            // Return a distinguishable error value rather than panicking.
            // Verification will always fail since no real blind matches this.
            return String::from("HMAC_KEY_INIT_FAILED");
        }
    };
    let mut mac = mac;
    mac.update(code_challenge.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Hash an authorization code with SHA-256 for storage keying.
/// The raw code is never stored — only its hash is used as the map key.
fn hash_code(code: &str) -> String {
    let digest = Sha256::digest(code.as_bytes());
    hex::encode(digest)
}

/// Authorization code expiry in seconds. Set to 30s for tighter security
/// (OAuth 2.0 recommends a maximum of 10 minutes; 30s limits replay window).
const CODE_EXPIRY_SECS: i64 = 30;

/// Maximum failed code consumption attempts per client_id within the rate limit window.
const MAX_CODE_ATTEMPTS_PER_CLIENT: u32 = 10;

/// Rate limit window for code consumption attempts (60 seconds).
const CODE_ATTEMPT_WINDOW_SECS: u64 = 60;

// ── OAuth Redirect URI Validation (CRITICAL — prevents authorization code theft) ──

/// Validate a redirect_uri against the set of registered redirect URIs for a client.
///
/// SECURITY: Uses EXACT STRING MATCH only. No wildcard matching, no partial
/// matching, no path traversal, no open redirects. This prevents authorization
/// code interception via manipulated redirect URIs (OAuth 2.0 mix-up attacks,
/// open redirect chains).
///
/// Additionally enforces HTTPS requirement for all redirect URIs with no
/// exceptions.  Military-grade systems must never allow plaintext redirects.
pub fn validate_redirect_uri(
    redirect_uri: &str,
    registered_uris: &[String],
) -> Result<(), &'static str> {
    // SECURITY: Reject empty redirect URIs immediately.
    if redirect_uri.is_empty() {
        return Err("redirect_uri must not be empty");
    }

    // SECURITY: Enforce HTTPS for ALL redirect URIs — no exceptions.
    // Per OAuth 2.1 Section 1.4.1 and NIST SP 800-63B.
    if !redirect_uri.starts_with("https://") {
        return Err("redirect_uri must use https://");
    }

    // SECURITY: EXACT STRING MATCH against registered redirect URIs.
    // No normalization, no wildcard expansion, no subdomain matching.
    // Constant-time comparison to prevent timing side-channels on URI values.
    let matched = registered_uris
        .iter()
        .any(|registered| crypto::ct::ct_eq(redirect_uri.as_bytes(), registered.as_bytes()));

    if matched {
        Ok(())
    } else {
        Err("redirect_uri does not match any registered redirect URI (exact match required)")
    }
}

// ── OAuth State Parameter CSRF Protection ──────────────────────────────────

/// HMAC key for binding OAuth state parameters to sessions.
/// Derived from the master KEK via HKDF-SHA512 for cross-instance consistency.
/// Falls back to random key if KEK is not yet available (startup race).
static STATE_HMAC_KEY: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();

fn state_hmac_key() -> &'static [u8; 64] {
    STATE_HMAC_KEY.get_or_init(|| {
        // Try to derive from master KEK for cross-instance consistency.
        let result = std::panic::catch_unwind(|| {
            common::sealed_keys::cached_master_kek()
        });
        if let Ok(master_kek) = result {
            let hk = hkdf::Hkdf::<Sha512>::new(None, master_kek);
            let mut key = [0u8; 64];
            if hk.expand(b"MILNET-OAUTH-STATE-HMAC-v1", &mut key).is_ok() {
                return key;
            }
            common::siem::emit_runtime_error(
                common::siem::category::CRYPTO_FAILURE,
                "HKDF expand failed for OAuth state HMAC key derivation from KEK",
                "HKDF expand error",
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
        }
        // SECURITY: In military deployment, KEK MUST be available. Fail-closed.
        if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok() {
            tracing::error!("FATAL: Master KEK unavailable for OAuth state HMAC -- cannot start in military mode");
            std::process::exit(1);
        }
        // Fallback: KEK not available (startup race). Use random key but warn.
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "Master KEK not available for OAuth state HMAC key derivation, falling back to random key. Cross-instance state verification will fail.",
            "KEK unavailable at init",
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        let mut key = [0u8; 64];
        if getrandom::getrandom(&mut key).is_err() {
            common::siem::emit_runtime_error(
                common::siem::category::CRYPTO_FAILURE,
                "OS CSPRNG unavailable -- cannot generate OAuth state HMAC key",
                "getrandom failed",
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            std::process::abort();
        }
        key
    })
}

/// Generate a cryptographically-bound OAuth state parameter.
///
/// SECURITY: The state parameter is HMAC-SHA512(session_id, random_nonce),
/// which cryptographically binds it to the user's session. This prevents
/// CSRF attacks on the authorization code exchange (an attacker cannot
/// forge a valid state for a victim's session).
///
/// Returns (state_value, nonce) — the nonce must be stored server-side
/// alongside the session to verify the state on callback.
pub fn generate_oauth_state(session_id: &str) -> Result<(String, String), &'static str> {
    let mut nonce_bytes = [0u8; 32];
    if getrandom::getrandom(&mut nonce_bytes).is_err() {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "OS CSPRNG unavailable — cannot generate OAuth state nonce",
            "getrandom failed",
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        return Err("OS CSPRNG failure during state generation");
    }
    let nonce = hex::encode(nonce_bytes);

    type HmacSha512 = Hmac<Sha512>;
    let mut mac = match HmacSha512::new_from_slice(state_hmac_key()) {
        Ok(m) => m,
        Err(_) => {
            common::siem::emit_runtime_error(
                common::siem::category::CRYPTO_FAILURE,
                "HMAC-SHA512 key init failed for OAuth state",
                "invalid key length",
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            return Err("HMAC key initialization failed");
        }
    };
    mac.update(session_id.as_bytes());
    mac.update(nonce.as_bytes());
    let state = hex::encode(mac.finalize().into_bytes());

    Ok((state, nonce))
}

/// Verify an OAuth state parameter against the session and stored nonce.
///
/// SECURITY: Uses constant-time comparison to prevent timing attacks.
/// Rejects missing or invalid state parameters immediately.
pub fn verify_oauth_state(
    state: &str,
    session_id: &str,
    stored_nonce: &str,
) -> Result<(), &'static str> {
    if state.is_empty() {
        return Err("OAuth state parameter is missing (CSRF protection)");
    }
    if stored_nonce.is_empty() {
        return Err("No stored nonce for state verification (session expired or invalid)");
    }

    // Recompute the expected state from session_id + stored nonce.
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = match HmacSha512::new_from_slice(state_hmac_key()) {
        Ok(m) => m,
        Err(_) => {
            common::siem::emit_runtime_error(
                common::siem::category::CRYPTO_FAILURE,
                "HMAC-SHA512 key init failed for OAuth state verification",
                "invalid key length",
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            return Err("HMAC key initialization failed during state verification");
        }
    };
    mac.update(session_id.as_bytes());
    mac.update(stored_nonce.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // SECURITY: Constant-time comparison to prevent timing side-channels.
    if crypto::ct::ct_eq(state.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err("OAuth state parameter does not match session (possible CSRF attack)")
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String, // "code"
    pub scope: String,
    pub state: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Clone)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: Uuid,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub nonce: Option<String>,
    pub tier: u8,
    pub expires_at: i64,
    /// Whether this code has already been consumed (redeemed for a token).
    pub consumed: bool,
}

/// Authorization code store.
///
/// **IMPORTANT: Production Deployment**
/// This in-memory store is suitable for single-instance development only.
/// In production, this store MUST be backed by persistent storage (Redis or PostgreSQL)
/// to support horizontal scaling, crash recovery, and cross-instance code consumption
/// tracking. Without persistent storage, authorization codes may be replayed across
/// different instances or lost on restart.
pub struct AuthorizationStore {
    codes: HashMap<String, AuthorizationCode>,
    /// Tracks total number of code consumption attempts (including double-consumption).
    /// Used to detect replay attacks — if consume_count exceeds issued code count,
    /// an attack may be underway.
    consume_count: AtomicU64,
    /// Tracks failed code consumption attempts per client_id for rate limiting.
    /// Maps client_id -> (failed_attempt_count, window_start).
    code_attempt_tracker: HashMap<String, (u32, Instant)>,
}

impl AuthorizationStore {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
            consume_count: AtomicU64::new(0),
            code_attempt_tracker: HashMap::new(),
        }
    }

    /// Create an authorization code with the default tier (2).
    ///
    /// Returns `Err` if `code_challenge` is `None` — PKCE is mandatory per OAuth 2.1.
    ///
    /// SECURITY: This method skips redirect_uri validation. Internal use only.
    /// External callers MUST use `create_code_validated()` which validates the
    /// redirect_uri against registered URIs before issuing a code.
    pub(crate) fn create_code(
        &mut self,
        client_id: &str,
        redirect_uri: &str,
        user_id: Uuid,
        scope: &str,
        code_challenge: Option<String>,
        nonce: Option<String>,
    ) -> Result<String, &'static str> {
        self.create_code_with_tier(client_id, redirect_uri, user_id, scope, code_challenge, nonce, 2)
    }

    /// Create an authorization code with redirect_uri validation against registered URIs.
    ///
    /// SECURITY: This is the preferred method — it validates the redirect_uri
    /// against the client's registered URIs BEFORE issuing a code, preventing
    /// authorization code theft via open redirects.
    pub fn create_code_validated(
        &mut self,
        client_id: &str,
        redirect_uri: &str,
        registered_redirect_uris: &[String],
        user_id: Uuid,
        scope: &str,
        code_challenge: Option<String>,
        nonce: Option<String>,
    ) -> Result<String, &'static str> {
        // SECURITY: Validate redirect_uri BEFORE issuing any authorization code.
        // This prevents authorization code interception via unregistered redirect URIs.
        validate_redirect_uri(redirect_uri, registered_redirect_uris)?;
        self.create_code_with_tier(client_id, redirect_uri, user_id, scope, code_challenge, nonce, 2)
    }

    /// Create an authorization code with an explicit tier.
    ///
    /// Returns `Err` if `code_challenge` is `None` — PKCE is mandatory per OAuth 2.1.
    pub fn create_code_with_tier(
        &mut self,
        client_id: &str,
        redirect_uri: &str,
        user_id: Uuid,
        scope: &str,
        code_challenge: Option<String>,
        nonce: Option<String>,
        tier: u8,
    ) -> Result<String, &'static str> {
        // PKCE is mandatory per OAuth 2.1 — reject requests without code_challenge.
        pkce::require_pkce(code_challenge.as_deref())?;

        let code = Uuid::new_v4().to_string();
        let hashed_key = hash_code(&code);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Blind the code_challenge with HMAC-SHA256 so it is never stored
        // in plaintext. PKCE verification recomputes the blind before comparing.
        let blinded_challenge = code_challenge.as_deref().map(blind_code_challenge);

        self.codes.insert(
            hashed_key,
            AuthorizationCode {
                code: String::new(), // never store the raw code
                client_id: client_id.to_string(),
                redirect_uri: redirect_uri.to_string(),
                user_id,
                scope: scope.to_string(),
                code_challenge: blinded_challenge,
                nonce,
                tier,
                consumed: false,
                expires_at: now + CODE_EXPIRY_SECS, // 30 second expiry for tighter security
            },
        );
        Ok(code)
    }

    pub fn consume_code(&mut self, code: &str) -> Option<AuthorizationCode> {
        self.consume_count.fetch_add(1, Ordering::SeqCst);

        // Hash the incoming code to look up in the store (codes are stored by hash).
        let hashed_key = hash_code(code);

        // Determine the client_id for rate limiting before mutating the code.
        // If the code exists, use its client_id; otherwise we cannot rate-limit
        // (the code is unknown and will return None anyway).
        let client_id = self.codes.get(&hashed_key).map(|c| c.client_id.clone());

        // Check rate limit for this client_id (if known).
        if let Some(ref cid) = client_id {
            let now = Instant::now();
            let entry = self.code_attempt_tracker.entry(cid.clone()).or_insert((0, now));
            // Reset window if expired
            if now.duration_since(entry.1).as_secs() >= CODE_ATTEMPT_WINDOW_SECS {
                *entry = (0, now);
            }
            if entry.0 >= MAX_CODE_ATTEMPTS_PER_CLIENT {
                return None;
            }
        }

        // Evict stale rate limit entries to prevent unbounded growth
        if self.code_attempt_tracker.len() > 10_000 {
            let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(60);
            self.code_attempt_tracker.retain(|_, (_, ts)| *ts > cutoff);
        }

        let auth_code = self.codes.get_mut(&hashed_key)?;

        // Reject already-consumed codes (replay detection)
        if auth_code.consumed {
            // Track failed attempt for rate limiting
            if let Some(ref cid) = client_id {
                if let Some(entry) = self.code_attempt_tracker.get_mut(cid) {
                    entry.0 += 1;
                }
            }
            // Remove the code entirely on double-consumption attempt (per RFC 6749 sec 4.1.2:
            // "If an authorization code is used more than once, the authorization server MUST
            // deny the request and SHOULD revoke all tokens previously issued based on that code.")
            self.codes.remove(&hashed_key);
            return None;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if now > auth_code.expires_at {
            // Track failed attempt for rate limiting
            if let Some(ref cid) = client_id {
                if let Some(entry) = self.code_attempt_tracker.get_mut(cid) {
                    entry.0 += 1;
                }
            }
            self.codes.remove(&hashed_key);
            return None;
        }

        // Mark as consumed, then remove and return
        auth_code.consumed = true;

        // Auto-cleanup: prune expired codes when map grows large
        if self.codes.len() > 1000 {
            self.cleanup_expired();
        }

        self.codes.remove(&hashed_key)
    }

    /// Check whether a code has already been consumed (redeemed).
    pub fn is_code_consumed(&self, code: &str) -> bool {
        let hashed_key = hash_code(code);
        self.codes
            .get(&hashed_key)
            .map(|c| c.consumed)
            // If the code is not in the store, treat it as consumed/invalid
            .unwrap_or(true)
    }

    /// Verify a PKCE code_verifier against the blinded code_challenge stored
    /// for this authorization code. The stored value is an HMAC-SHA256 blind
    /// index, so we recompute the blind of the S256(verifier) and compare.
    pub fn verify_pkce_for_code(&self, code: &str, code_verifier: &str) -> bool {
        let hashed_key = hash_code(code);
        let Some(auth_code) = self.codes.get(&hashed_key) else { return false };
        let Some(ref stored_blind) = auth_code.code_challenge else { return false };
        // Compute the S256 challenge from the verifier, then blind it.
        let challenge = crate::pkce::generate_challenge(code_verifier);
        let recomputed_blind = blind_code_challenge(&challenge);
        crypto::ct::ct_eq(stored_blind.as_bytes(), recomputed_blind.as_bytes())
    }

    /// Remove all expired codes older than 2x the expiry time.
    /// Should be called periodically (e.g., every 30 seconds) to prevent unbounded growth.
    pub fn cleanup_expired(&mut self) {
        let now_sys = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let cutoff = now_sys - (CODE_EXPIRY_SECS * 2);
        self.codes.retain(|_, auth_code| auth_code.expires_at > cutoff);

        // Purge stale rate-limit tracker entries whose window has expired.
        let now_inst = Instant::now();
        self.code_attempt_tracker.retain(|_, (_, window_start)| {
            now_inst.duration_since(*window_start).as_secs() < CODE_ATTEMPT_WINDOW_SECS
        });
    }
}

impl Default for AuthorizationStore {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PersistentAuthorizationStore { memory: AuthorizationStore, pool: sqlx::PgPool }
impl PersistentAuthorizationStore {
    pub async fn new(pool: sqlx::PgPool) -> Result<Self, String> {
        let mut s = Self { memory: AuthorizationStore::new(), pool }; s.load_from_db().await?; Ok(s)
    }
    async fn load_from_db(&mut self) -> Result<(), String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        // DB stores hashed code keys and blinded code_challenges — load them directly.
        let rows: Vec<(String, String, String, Uuid, Option<String>, i32, Option<String>, i64, bool)> =
            sqlx::query_as("SELECT code_hash, client_id, redirect_uri, user_id, code_challenge_blind, tier, nonce, created_at, consumed FROM authorization_codes WHERE created_at > $1")
            .bind(now - (CODE_EXPIRY_SECS * 2)).fetch_all(&self.pool).await.map_err(|e| format!("load codes: {e}"))?;
        for (code_hash, cid, ruri, uid, cc_blind, tier, nonce, cat, consumed) in rows {
            self.memory.codes.insert(code_hash, AuthorizationCode { code: String::new(), client_id: cid, redirect_uri: ruri, user_id: uid, scope: String::new(), code_challenge: cc_blind, nonce, tier: tier as u8, expires_at: cat + CODE_EXPIRY_SECS, consumed });
        }
        Ok(())
    }
    pub async fn create_code_with_tier(&mut self, client_id: &str, redirect_uri: &str, user_id: Uuid, scope: &str, code_challenge: Option<String>, nonce: Option<String>, tier: u8) -> Result<String, String> {
        let code = self.memory.create_code_with_tier(client_id, redirect_uri, user_id, scope, code_challenge.clone(), nonce.clone(), tier).map_err(|e| e.to_string())?;
        let hashed_key = hash_code(&code);
        let blinded_challenge = code_challenge.as_deref().map(blind_code_challenge);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        // Store hashed code and blinded challenge in DB — never plaintext.
        sqlx::query("INSERT INTO authorization_codes (code_hash, client_id, redirect_uri, user_id, code_challenge_blind, tier, nonce, created_at, consumed) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE)")
            .bind(&hashed_key).bind(client_id).bind(redirect_uri).bind(user_id).bind(blinded_challenge.as_deref()).bind(tier as i32).bind(nonce.as_deref()).bind(now)
            .execute(&self.pool).await.map_err(|e| format!("persist code: {e}"))?;
        Ok(code)
    }
    pub async fn create_code(&mut self, client_id: &str, redirect_uri: &str, user_id: Uuid, scope: &str, code_challenge: Option<String>, nonce: Option<String>) -> Result<String, String> {
        self.create_code_with_tier(client_id, redirect_uri, user_id, scope, code_challenge, nonce, 2).await
    }
    /// Consume an authorization code with atomic database protection.
    ///
    /// Uses `UPDATE ... WHERE consumed = FALSE` to prevent cross-instance replay:
    /// even if two instances race on the same code, only one will succeed because
    /// the atomic UPDATE returns rows_affected=0 for the loser.
    pub async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, String> {
        let hashed_key = hash_code(code);

        // Atomic DB update: only succeeds if the code has NOT been consumed yet.
        // This is the source of truth for cross-instance replay prevention.
        let result = sqlx::query(
            "UPDATE authorization_codes SET consumed = TRUE \
             WHERE code_hash = $1 AND consumed = FALSE"
        )
        .bind(&hashed_key)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("atomic consume: {e}"))?;

        if result.rows_affected() == 0 {
            // Either the code doesn't exist or was already consumed by another instance.
            // Ensure the in-memory cache is consistent: try consuming (which will also
            // fail if already consumed) and then clean up.
            if self.memory.consume_code(code).is_none() {
                tracing::debug!(
                    target: "siem",
                    "Authorization code not found in memory cache during DB-authoritative consume — expected for cross-instance scenarios"
                );
            }
            sqlx::query("DELETE FROM authorization_codes WHERE code_hash = $1 AND consumed = TRUE")
                .bind(&hashed_key)
                .execute(&self.pool)
                .await
                .map_err(|e| format!("cleanup consumed code: {e}"))?;
            return Ok(None);
        }

        // DB confirmed this instance won the race — now consume from in-memory cache.
        let r = self.memory.consume_code(code);
        if r.is_none() {
            // Edge case: in-memory cache was stale (e.g., code expired in cache but
            // not in DB). The DB update already marked it consumed, which is correct.
            tracing::warn!(
                "Authorization code consumed in DB but not in memory cache — cache was stale"
            );
        }
        Ok(r)
    }
    pub fn is_code_consumed(&self, code: &str) -> bool { self.memory.is_code_consumed(code) }
    pub async fn cleanup_expired(&mut self) -> Result<(), String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        sqlx::query("DELETE FROM authorization_codes WHERE created_at <= $1").bind(now - (CODE_EXPIRY_SECS * 2)).execute(&self.pool).await.map_err(|e| format!("cleanup: {e}"))?;
        self.memory.cleanup_expired(); Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_create_and_consume() { let mut s = AuthorizationStore::new(); let uid = Uuid::new_v4(); let c = s.create_code("c1","https://ex.com/cb",uid,"openid",Some("ch".into()),None).unwrap(); assert!(!s.is_code_consumed(&c)); let r = s.consume_code(&c).unwrap(); assert_eq!(r.client_id,"c1"); }
    #[test] fn test_double_consume() { let mut s = AuthorizationStore::new(); let c = s.create_code("c1","https://ex.com/cb",Uuid::new_v4(),"openid",Some("ch".into()),None).unwrap(); assert!(s.consume_code(&c).is_some()); assert!(s.consume_code(&c).is_none()); }
    #[test] fn test_pkce_required() { let mut s = AuthorizationStore::new(); assert!(s.create_code("c1","https://ex.com/cb",Uuid::new_v4(),"openid",None,None).is_err()); }
    #[test] fn test_with_tier() { let mut s = AuthorizationStore::new(); let c = s.create_code_with_tier("c1","https://ex.com/cb",Uuid::new_v4(),"openid",Some("ch".into()),Some("n".into()),3).unwrap(); assert_eq!(s.consume_code(&c).unwrap().tier, 3); }
    #[test] fn test_unknown_consumed() { assert!(AuthorizationStore::new().is_code_consumed("nope")); }
    #[test] fn test_code_not_stored_plaintext() {
        let mut s = AuthorizationStore::new();
        let code = s.create_code("c1","https://ex.com/cb",Uuid::new_v4(),"openid",Some("ch".into()),None).unwrap();
        // The raw code must not appear as a key in the map (it is stored by SHA-256 hash).
        assert!(!s.codes.contains_key(&code));
        // The hashed key must exist.
        assert!(s.codes.contains_key(&hash_code(&code)));
    }
    #[test] fn test_code_challenge_not_stored_plaintext() {
        let mut s = AuthorizationStore::new();
        let challenge = "test_challenge_value";
        let code = s.create_code("c1","https://ex.com/cb",Uuid::new_v4(),"openid",Some(challenge.into()),None).unwrap();
        let hashed_key = hash_code(&code);
        let stored = s.codes.get(&hashed_key).unwrap();
        // The stored code_challenge must be a blind (HMAC), not the original value.
        assert_ne!(stored.code_challenge.as_deref(), Some(challenge));
        assert!(stored.code_challenge.is_some());
    }
    #[test] fn test_pkce_blind_verification() {
        let mut s = AuthorizationStore::new();
        let verifier = "a".repeat(43);
        let challenge = crate::pkce::generate_challenge(&verifier);
        let code = s.create_code("c1","https://ex.com/cb",Uuid::new_v4(),"openid",Some(challenge),None).unwrap();
        assert!(s.verify_pkce_for_code(&code, &verifier));
        assert!(!s.verify_pkce_for_code(&code, "wrong_verifier_that_is_long_enough_43chars_padding"));
    }
}
