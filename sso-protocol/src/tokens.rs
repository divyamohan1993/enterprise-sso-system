use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto::pq_sign::{PqSigningKey, PqVerifyingKey, generate_pq_keypair, pq_sign_raw, pq_verify_raw};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// JTI Replay Cache — distributed with L1 in-memory + L2 database backend
// ---------------------------------------------------------------------------

/// Trait for pluggable JTI replay storage backends.
///
/// Implementations must be safe to call from synchronous contexts (the default
/// in-memory cache) or async contexts (the database-backed store).
pub trait JtiReplayStore: Send + Sync {
    /// Mark a JTI as used with its expiry timestamp.
    /// Returns `Ok(true)` if the JTI was freshly inserted (not a replay).
    /// Returns `Ok(false)` if the JTI was already present (replay detected).
    fn mark_used(&self, jti: &str, expires_at: i64) -> Result<bool, String>;

    /// Check whether a JTI has already been used.
    fn is_used(&self, jti: &str) -> bool;
}

/// In-memory JTI store — used as L1 cache and as standalone fallback
/// when no database is configured.
pub struct LocalJtiStore {
    seen: Mutex<HashMap<String, i64>>,
    max_size: usize,
}

impl LocalJtiStore {
    pub fn new(max_size: usize) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            max_size,
        }
    }

    fn evict_expired(seen: &mut HashMap<String, i64>, now: i64) {
        seen.retain(|_, &mut e| e + 60 > now); // keep 60s past expiry for safety
    }
}

impl JtiReplayStore for LocalJtiStore {
    fn mark_used(&self, jti: &str, expires_at: i64) -> Result<bool, String> {
        let mut seen = self.seen.lock().map_err(|_| "JTI local store mutex poisoned".to_string())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        Self::evict_expired(&mut seen, now);

        if seen.contains_key(jti) {
            return Ok(false); // replay
        }

        // Evict oldest if at capacity
        if seen.len() >= self.max_size {
            if let Some(oldest_key) = seen.iter()
                .min_by_key(|(_, exp)| *exp)
                .map(|(k, _)| k.clone())
            {
                seen.remove(&oldest_key);
            }
        }

        seen.insert(jti.to_string(), expires_at);
        Ok(true)
    }

    fn is_used(&self, jti: &str) -> bool {
        self.seen
            .lock()
            .map(|seen| seen.contains_key(jti))
            .unwrap_or(false)
    }
}

/// Database-backed JTI store using PostgreSQL via sqlx.
///
/// Uses the `jti_replay` table with columns: `jti TEXT PRIMARY KEY, expires_at BIGINT`.
/// Provides distributed replay detection across multiple SSO instances.
/// Wraps a `LocalJtiStore` as an L1 cache for fast lookups — writes go to both
/// the L1 cache and the database (write-through).
pub struct DatabaseJtiStore {
    /// L1 in-memory cache for fast path
    local: LocalJtiStore,
    /// PostgreSQL connection pool
    pool: sqlx::PgPool,
}

impl DatabaseJtiStore {
    pub fn new(pool: sqlx::PgPool, max_local_size: usize) -> Self {
        Self {
            local: LocalJtiStore::new(max_local_size),
            pool,
        }
    }

    /// Ensure the `jti_replay` table exists. Call once at startup.
    pub async fn ensure_table(&self) -> Result<(), String> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS jti_replay (\
                jti TEXT PRIMARY KEY, \
                expires_at BIGINT NOT NULL\
            )"
        )
        .execute(&self.pool)
        .await
        .map_err(|e| format!("create jti_replay table: {e}"))?;
        Ok(())
    }

    /// Evict expired entries from the database. Call periodically.
    pub async fn cleanup_expired(&self) -> Result<u64, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let result = sqlx::query("DELETE FROM jti_replay WHERE expires_at + 60 <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("cleanup jti_replay: {e}"))?;
        Ok(result.rows_affected())
    }
}

impl JtiReplayStore for DatabaseJtiStore {
    fn mark_used(&self, jti: &str, expires_at: i64) -> Result<bool, String> {
        // Check L1 cache first (fast path)
        if self.local.is_used(jti) {
            return Ok(false);
        }

        // Write-through to database using a blocking spawn since we are in sync context.
        // Use INSERT ... ON CONFLICT to atomically check+insert.
        let pool = self.pool.clone();
        let jti_owned = jti.to_string();
        let db_result = std::thread::scope(|_| {
            // Build a minimal tokio runtime for the blocking DB call
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("tokio runtime: {e}"))?;
            rt.block_on(async {
                let result = sqlx::query(
                    "INSERT INTO jti_replay (jti, expires_at) VALUES ($1, $2) \
                     ON CONFLICT (jti) DO NOTHING"
                )
                .bind(&jti_owned)
                .bind(expires_at)
                .execute(&pool)
                .await
                .map_err(|e| format!("insert jti_replay: {e}"))?;
                // rows_affected == 1 means fresh insert, 0 means conflict (replay)
                Ok::<bool, String>(result.rows_affected() == 1)
            })
        });

        let was_fresh = db_result?;
        if was_fresh {
            // Update L1 cache
            let _ = self.local.mark_used(jti, expires_at);
        }
        Ok(was_fresh)
    }

    fn is_used(&self, jti: &str) -> bool {
        // Check L1 first
        if self.local.is_used(jti) {
            return true;
        }
        // Fall through to DB
        let pool = self.pool.clone();
        let jti_owned = jti.to_string();
        std::thread::scope(|_| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok();
            rt.map(|rt| {
                rt.block_on(async {
                    sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM jti_replay WHERE jti = $1"
                    )
                    .bind(&jti_owned)
                    .fetch_one(&pool)
                    .await
                    .unwrap_or(0) > 0
                })
            })
            .unwrap_or(false)
        })
    }
}

/// Global JTI replay cache — tracks seen token IDs to prevent replay.
/// Entries are evicted after they expire (exp + skew tolerance).
/// Bounded to prevent memory exhaustion from long-lived cache entries.
///
/// Configurable via `set_jti_store` at startup; defaults to `LocalJtiStore`.
static JTI_STORE: std::sync::OnceLock<Box<dyn JtiReplayStore>> = std::sync::OnceLock::new();

/// Set a custom JTI replay store (e.g., `DatabaseJtiStore` for distributed deployments).
/// Must be called before the first token verification. Returns `Err` if already set.
pub fn set_jti_store(store: Box<dyn JtiReplayStore>) -> Result<(), Box<dyn JtiReplayStore>> {
    JTI_STORE.set(store)
}

fn jti_store() -> &'static dyn JtiReplayStore {
    JTI_STORE
        .get_or_init(|| {
            // SECURITY: In military deployment, a distributed JTI store MUST be configured
            // via set_jti_store() before first use. Per-process LocalJtiStore allows
            // cross-instance token replay.
            if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok() {
                tracing::error!(
                    "FATAL: No distributed JTI store configured in military deployment mode. \
                     Call set_jti_store() with a DatabaseJtiStore at startup."
                );
                std::process::exit(1);
            }
            Box::new(LocalJtiStore::new(100_000))
        })
        .as_ref()
}

// ---------------------------------------------------------------------------
// Refresh Tokens
// ---------------------------------------------------------------------------

/// Refresh token lifetime: 8 hours (in seconds).
const REFRESH_TOKEN_LIFETIME_SECS: i64 = 8 * 3600;

/// Clock skew tolerance for distributed military deployments.
///
/// SECURITY: In distributed systems (especially air-gapped or satellite-linked
/// military networks), system clocks can drift. This tolerance prevents spurious
/// token rejections due to minor clock differences between issuing and verifying
/// nodes, while remaining tight enough to limit replay window exposure.
/// 10 seconds is the recommended value per NIST SP 800-63B for networked systems.
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 10;

/// Maximum token lifetime for AAL2 sessions (SP 800-63B: 12 hours).
pub const AAL2_MAX_SESSION_SECS: i64 = 12 * 3600;

/// AAL3 inactivity timeout per NIST SP 800-63B Section 4.3.1 / DISA STIG V-222977.
///
/// SECURITY: Sovereign/Tier1 tokens (AAL3) MUST enforce a 15-minute inactivity
/// timeout regardless of the token's own `exp` field. This prevents long-lived
/// tokens from remaining valid after the user has left the terminal, which is
/// critical in SCIF and tactical environments where unattended sessions pose
/// an insider threat risk.
pub const AAL3_INACTIVITY_TIMEOUT_SECS: i64 = 15 * 60;

/// Default token lifetime: 1 hour for access tokens.
pub const ACCESS_TOKEN_LIFETIME_SECS: i64 = 3600;

/// Maximum token lifetime ceiling -- no token may exceed 24 hours regardless of AAL.
pub const MAX_TOKEN_LIFETIME_SECS: i64 = 24 * 3600;

/// A refresh token bound to a specific user and client.
///
/// Implements single-use guarantee via the `used` flag and rotation:
/// each time a refresh token is redeemed, a new one is issued and the
/// old one is invalidated.
///
/// SECURITY: `family_id` tracks the token lineage — all tokens descended from
/// the same initial grant share a family ID. On double-consumption (token reuse),
/// the ENTIRE family is revoked to mitigate stolen refresh token attacks per
/// RFC 6749 Section 10.4 and NIST SP 800-63B.
#[derive(Clone)]
pub struct RefreshToken {
    pub token: String,
    pub user_id: Uuid,
    pub client_id: String,
    pub scope: String,
    pub expires_at: i64,
    pub used: bool,
    /// Family identifier for token lineage tracking. All tokens rotated from
    /// the same initial grant share this ID. Used for family-wide revocation
    /// on token reuse detection.
    pub family_id: String,
}

/// In-memory refresh token store with rotation and single-use enforcement.
///
/// WARNING: This store is volatile. All refresh tokens are lost on process
/// restart. In production, set `persistence_backend` to a durable store.
pub struct RefreshTokenStore {
    tokens: HashMap<String, RefreshToken>,
    /// Optional persistence backend name for operational awareness.
    /// When None, the store is purely in-memory (volatile).
    pub persistence_backend: Option<String>,
}

impl RefreshTokenStore {
    pub fn new() -> Self {
        common::siem::emit_runtime_error(
            common::siem::category::RUNTIME_ERROR,
            "RefreshTokenStore initialized with in-memory backend only. All refresh tokens will be lost on restart. Configure a persistent backend for production.",
            "no persistence backend configured",
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        Self {
            tokens: HashMap::new(),
            persistence_backend: None,
        }
    }

    /// Issue a new refresh token for a user/client pair.
    ///
    /// Creates a new token family (each initial grant starts a new lineage).
    /// For rotated tokens that inherit an existing family, use `issue_in_family`.
    pub fn issue(&mut self, user_id: Uuid, client_id: &str, scope: &str) -> String {
        let family_id = format!("fam_{}", Uuid::new_v4());
        self.issue_in_family(user_id, client_id, scope, &family_id)
    }

    /// Issue a new refresh token within an existing token family.
    ///
    /// The `family_id` is inherited from the parent token during rotation,
    /// enabling family-wide revocation on reuse detection.
    fn issue_in_family(&mut self, user_id: Uuid, client_id: &str, scope: &str, family_id: &str) -> String {
        let token_value = format!("rt_{}", Uuid::new_v4());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.tokens.insert(
            token_value.clone(),
            RefreshToken {
                token: token_value.clone(),
                user_id,
                client_id: client_id.to_string(),
                scope: scope.to_string(),
                expires_at: now + REFRESH_TOKEN_LIFETIME_SECS,
                used: false,
                family_id: family_id.to_string(),
            },
        );
        token_value
    }

    /// Redeem a refresh token: validates it, marks as used, and issues a
    /// rotated replacement. Returns `(old_token_data, new_refresh_token_string)`.
    ///
    /// Enforces:
    /// - Token existence
    /// - Expiry
    /// - Single-use (reuse of a consumed token revokes the entire family)
    /// - Client binding (the requesting client must match the original)
    pub fn redeem(
        &mut self,
        token: &str,
        client_id: &str,
    ) -> Result<(RefreshToken, String), String> {
        let rt = self.tokens.get(token).cloned()
            .ok_or_else(|| "refresh token not found".to_string())?;

        // SECURITY: Detect replay — if already used, this indicates token theft.
        // Revoke the ENTIRE token family (all tokens descended from the same grant)
        // per RFC 6749 Section 10.4 to limit the blast radius of stolen tokens.
        if rt.used {
            let family = rt.family_id.clone();
            common::siem::emit_runtime_error(
                common::siem::category::AUTH_FAILURE,
                &format!("Refresh token replay detected for family '{}', client '{}'. Revoking entire family.", family, rt.client_id),
                "token reuse / theft indicator",
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            self.revoke_family(&family);
            return Err(format!(
                "refresh token already used -- token theft detected, \
                 revoked entire family '{}' ({} tokens destroyed)",
                family,
                0 // family already revoked above
            ));
        }

        // Check expiry
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if now > rt.expires_at {
            self.tokens.remove(token);
            return Err("refresh token expired".to_string());
        }

        // Client binding check — constant-time to prevent timing side-channels
        if !crypto::ct::ct_eq(rt.client_id.as_bytes(), client_id.as_bytes()) {
            return Err("refresh token client_id mismatch".to_string());
        }

        // Mark old token as used
        if let Some(entry) = self.tokens.get_mut(token) {
            entry.used = true;
        }

        // Issue rotated replacement within the same family lineage
        let new_token = self.issue_in_family(rt.user_id, &rt.client_id, &rt.scope, &rt.family_id);

        Ok((rt, new_token))
    }

    /// Revoke ALL refresh tokens belonging to a given family.
    ///
    /// SECURITY: Called on token reuse detection to destroy the entire lineage.
    /// This is critical for mitigating stolen refresh token attacks — if an
    /// attacker replays a used token, both the attacker's and the legitimate
    /// user's subsequent tokens are invalidated, forcing re-authentication.
    pub fn revoke_family(&mut self, family_id: &str) {
        let count_before = self.tokens.len();
        self.tokens.retain(|_, rt| rt.family_id != family_id);
        let revoked = count_before - self.tokens.len();
        common::siem::emit_runtime_error(
            common::siem::category::AUTH_FAILURE,
            &format!("Revoked {} refresh tokens in family '{}'", revoked, family_id),
            "family revocation",
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
    }

    /// Remove all expired refresh tokens.
    pub fn cleanup_expired(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.tokens.retain(|_, rt| rt.expires_at > now);
    }
}

impl Default for RefreshTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

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
    pub jti: String,
}

/// Custom Debug for IdTokenClaims — redacts subject, nonce, and JTI to prevent
/// accidental log exposure of identity-correlated or replay-sensitive values.
impl std::fmt::Debug for IdTokenClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdTokenClaims")
            .field("iss", &self.iss)
            .field("sub", &"[REDACTED]")
            .field("aud", &self.aud)
            .field("exp", &self.exp)
            .field("iat", &self.iat)
            .field("nonce", &"[REDACTED]")
            .field("auth_time", &self.auth_time)
            .field("tier", &self.tier)
            .field("jti", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub id_token: String,
    pub scope: String,
    /// Refresh token for obtaining new access tokens without re-authentication.
    /// Rotated on each use (old token invalidated, new one issued).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Custom Debug for TokenResponse — redacts all bearer credentials.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("id_token", &"[REDACTED]")
            .field("scope", &self.scope)
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}

/// A single OIDC signing keypair slot with its key ID and verifying key.
struct KeySlot {
    signing_key: PqSigningKey,
    verifying_key: PqVerifyingKey,
    kid: String,
}

/// Wrapper around an ML-DSA-87 keypair used for signing OIDC ID tokens.
///
/// Supports key rotation: maintains a current key and an optional previous
/// key. Both keys are served in the JWKS endpoint during the overlap window
/// so that tokens signed with the previous key can still be verified while
/// new tokens are signed with the current key.
pub struct OidcSigningKey {
    current: KeySlot,
    /// Previous key retained for graceful rotation -- tokens signed before
    /// the last rotation can still be verified against this key.
    previous: Option<KeySlot>,
    /// Monotonically increasing generation counter. Incremented on each
    /// rotation and encoded in the `kid` to ensure key uniqueness.
    generation: u64,
}

impl OidcSigningKey {
    /// Generate a new ML-DSA-87 signing key for OIDC (generation 1).
    pub fn generate() -> Self {
        let (signing_key, verifying_key) = generate_pq_keypair();
        let generation = 1u64;
        Self {
            current: KeySlot {
                signing_key,
                verifying_key,
                kid: format!("milnet-mldsa87-v{}", generation),
            },
            previous: None,
            generation,
        }
    }

    /// Rotate the signing key: generates a new keypair, moves the current
    /// key to the previous slot, and increments the generation counter.
    ///
    /// The previous key is retained in the JWKS endpoint so tokens signed
    /// before the rotation can still be verified until they expire. Only
    /// one previous key is kept -- the key before that is discarded.
    pub fn rotate_signing_key(&mut self) {
        self.generation += 1;
        let (signing_key, verifying_key) = generate_pq_keypair();
        let new_slot = KeySlot {
            signing_key,
            verifying_key,
            kid: format!("milnet-mldsa87-v{}", self.generation),
        };
        // Move current -> previous, discard old previous
        let old_current = std::mem::replace(&mut self.current, new_slot);
        self.previous = Some(old_current);
    }

    /// Return the current generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the verifying key for the current signing key.
    pub fn verifying_key(&self) -> &PqVerifyingKey {
        &self.current.verifying_key
    }

    /// Return the previous verifying key (if a rotation has occurred).
    pub fn previous_verifying_key(&self) -> Option<&PqVerifyingKey> {
        self.previous.as_ref().map(|slot| &slot.verifying_key)
    }

    /// Key ID for JWK `kid` field (current key).
    pub fn kid(&self) -> &str {
        &self.current.kid
    }

    /// Key ID for the previous key (if present).
    pub fn previous_kid(&self) -> Option<&str> {
        self.previous.as_ref().map(|slot| slot.kid.as_str())
    }

    /// Build the JWKS JSON value containing both current and previous keys.
    ///
    /// During a rotation window, both keys are served so verifiers can
    /// validate tokens signed with either key. Once all old tokens expire,
    /// the previous key can be dropped on the next rotation.
    pub fn jwks_json(&self) -> serde_json::Value {
        let mut keys = Vec::with_capacity(2);

        // Current key (always present)
        let vk_bytes = self.current.verifying_key.encode();
        let vk_b64 = URL_SAFE_NO_PAD.encode(AsRef::<[u8]>::as_ref(&vk_bytes));
        keys.push(serde_json::json!({
            "kty": "ML-DSA",
            "alg": "ML-DSA-87",
            "use": "sig",
            "kid": self.current.kid,
            "pub": vk_b64
        }));

        // Previous key (present during rotation overlap window)
        if let Some(ref prev) = self.previous {
            let prev_vk_bytes = prev.verifying_key.encode();
            let prev_vk_b64 = URL_SAFE_NO_PAD.encode(AsRef::<[u8]>::as_ref(&prev_vk_bytes));
            keys.push(serde_json::json!({
                "kty": "ML-DSA",
                "alg": "ML-DSA-87",
                "use": "sig",
                "kid": prev.kid,
                "pub": prev_vk_b64
            }));
        }

        serde_json::json!({ "keys": keys })
    }
}

impl Drop for OidcSigningKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Zeroize current key slot signing key bytes
        let mut current_bytes = self.current.signing_key.encode();
        current_bytes.as_mut().zeroize();
        // Zeroize previous key slot if present
        if let Some(ref prev) = self.previous {
            let mut prev_bytes = prev.signing_key.encode();
            prev_bytes.as_mut().zeroize();
        }
        self.generation = 0;
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
        .unwrap_or_default()
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

    let header_bytes = match serde_json::to_vec(&header) {
        Ok(b) => b,
        Err(e) => {
            common::siem::emit_runtime_error(
                common::siem::category::AUTH_FAILURE,
                "JWT header serialization failed",
                &format!("{e}"),
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            // Return an empty token that will fail verification — never panic.
            return String::new();
        }
    };
    let claims_bytes = match serde_json::to_vec(&claims) {
        Ok(b) => b,
        Err(e) => {
            common::siem::emit_runtime_error(
                common::siem::category::AUTH_FAILURE,
                "JWT claims serialization failed",
                &format!("{e}"),
                file!(),
                line!(),
                column!(),
                module_path!(),
            );
            return String::new();
        }
    };
    let header_b64 = URL_SAFE_NO_PAD.encode(&header_bytes);
    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_bytes);
    let signing_input = format!("{header_b64}.{claims_b64}");

    let signature = pq_sign_raw(&signing_key.current.signing_key, signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

    format!("{signing_input}.{sig_b64}")
}

/// Verify an ML-DSA-87-signed JWT using the verifying key.
///
/// SECURITY: Audience-less verification is forbidden. All tokens MUST be
/// verified with an explicit audience via `verify_id_token_with_audience`.
/// This function exists only for backward API compatibility and always fails
/// because skipping audience validation enables token misuse attacks.
pub fn verify_id_token(token: &str, verifying_key: &PqVerifyingKey) -> Result<IdTokenClaims, String> {
    // SECURITY: require_audience = true and expected_audience = None will cause
    // the inner function to reject any token — audience-less verification is
    // forbidden for military-grade deployments.
    verify_id_token_inner(token, verifying_key, None, true)
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

    // SECURITY: Clock skew tolerance for distributed military deployments.
    // Uses the module-level CLOCK_SKEW_TOLERANCE_SECS (10s) instead of a
    // hardcoded 30s — tighter window reduces replay exposure while still
    // accommodating NTP drift in air-gapped/satellite-linked networks.
    if claims.exp + CLOCK_SKEW_TOLERANCE_SECS <= now {
        return Err(format!(
            "token expired: exp={}, now={}, skew_tolerance={}s",
            claims.exp, now, CLOCK_SKEW_TOLERANCE_SECS
        ));
    }

    // SECURITY: Reject tokens issued too far in the future.
    // Allow CLOCK_SKEW_TOLERANCE_SECS grace for distributed clock drift,
    // but anything beyond 5 minutes + tolerance indicates clock manipulation.
    if claims.iat > now + 300 + CLOCK_SKEW_TOLERANCE_SECS {
        return Err(format!(
            "token issued in the future: iat={}, now={} — possible clock manipulation",
            claims.iat, now
        ));
    }

    // SECURITY: AAL3 inactivity timeout enforcement per NIST SP 800-63B.
    // Sovereign (tier 1) and Emergency (tier 4) tokens enforce a hard 15-minute
    // timeout from issuance, regardless of the token's own `exp` field.
    // This prevents long-lived tokens from remaining valid in SCIF/tactical
    // environments where unattended sessions are an insider threat vector.
    if (claims.tier == 1 || claims.tier == 4) &&
       claims.iat + AAL3_INACTIVITY_TIMEOUT_SECS < now {
        return Err(format!(
            "AAL3 inactivity timeout: tier={}, iat={}, now={}, max_inactive={}s — \
             re-authentication required per NIST SP 800-63B",
            claims.tier, claims.iat, now, AAL3_INACTIVITY_TIMEOUT_SECS
        ));
    }

    // JTI replay prevention — each token can only be verified once.
    // SECURITY: Empty JTI is rejected unconditionally. Every token MUST carry
    // a unique identifier to prevent replay attacks across instances.
    if claims.jti.is_empty() {
        return Err("token jti is required but empty — all tokens must carry a unique JTI".into());
    }
    let was_fresh = jti_store()
        .mark_used(&claims.jti, claims.exp)?;
    if !was_fresh {
        return Err(format!(
            "JTI replay detected: token '{}' has already been used",
            claims.jti
        ));
    }

    // SECURITY: Audience validation is mandatory. Verifying a token without an
    // expected audience is forbidden — it allows token misuse across services.
    if require_audience {
        match expected_audience {
            Some(expected) => {
                if !crypto::ct::ct_eq(claims.aud.as_bytes(), expected.as_bytes()) {
                    return Err(format!(
                        "audience mismatch: expected '{}', got '{}'",
                        expected, claims.aud
                    ));
                }
            }
            None => {
                // No expected audience was provided but audience checking is
                // required — this is a caller error. Fail-closed.
                return Err(
                    "audience verification is required but no expected audience was provided \
                     — audience-less token verification is forbidden".into()
                );
            }
        }
    } else if let Some(expected) = expected_audience {
        // Even when not strictly required, if an audience was provided, enforce it.
        if !crypto::ct::ct_eq(claims.aud.as_bytes(), expected.as_bytes()) {
            return Err(format!(
                "audience mismatch: expected '{}', got '{}'",
                expected, claims.aud
            ));
        }
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
        let signature = pq_sign_raw(&sk.current.signing_key, signing_input.as_bytes());
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
            let r1 = verify_id_token_with_audience(&token, sk.verifying_key(), "test-aud", true);
            assert!(r1.is_ok(), "first verification must succeed");

            // Second verification of same token should fail (JTI replay)
            let r2 = verify_id_token_with_audience(&token, sk.verifying_key(), "test-aud", true);
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
            let signature = pq_sign_raw(&sk.current.signing_key, signing_input.as_bytes());
            let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
            let token = format!("{signing_input}.{sig_b64}");

            let result = verify_id_token_with_audience(&token, sk.verifying_key(), "test-client", true);
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("unsupported algorithm"));
        });
    }

    // ── Token with empty JTI ────────────────────────────────────────────

    #[test]
    fn verify_rejects_empty_jti() {
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
            // SECURITY: Empty JTI tokens are now rejected unconditionally.
            let r1 = verify_id_token_with_audience(&token, sk.verifying_key(), "test-client", true);
            assert!(r1.is_err(), "empty JTI token must be rejected");
            assert!(
                r1.unwrap_err().contains("jti is required"),
                "error must mention JTI requirement"
            );
        });
    }

    // ── Barely-expired token (within skew tolerance) ──────────────���─────

    #[test]
    fn verify_accepts_token_within_skew_tolerance() {
        big(|| {
            let sk = OidcSigningKey::generate();
            let now = now_secs();

            // exp is 5 seconds ago ��� within the 10s skew tolerance
            let claims = IdTokenClaims {
                iss: "test".into(),
                sub: Uuid::new_v4().to_string(),
                aud: "test-client".into(),
                exp: now - 5,
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
                "token within 10s skew tolerance should be accepted: {:?}",
                result.err()
            );
        });
    }
}
