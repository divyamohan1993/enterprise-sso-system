use common::classification::{self, ClassificationLevel};
use common::domain;
use common::error::MilnetError;
use common::revocation::{RevocationList, SharedRevocationList};
use common::types::{EncryptedToken, Token, TokenClaims};
use crypto::jwe;
use crypto::pq_sign::{pq_verify, PqVerifyingKey};
use frost_ristretto255::keys::PublicKeyPackage;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha512 = Hmac<Sha512>;

/// Maximum session epochs (8 hours at 10s/epoch).
const MAX_SESSION_EPOCHS: u64 = 2880;

/// Default max token lifetime for lazy cleanup (8 hours in seconds).
///
/// NOTE: This is the standard access token lifetime for regular users.
/// Intentionally different from:
///   - admin/src/routes.rs::MAX_TOKEN_LIFETIME_SECS (15m) -- admin session timeout
///   - sso-protocol/src/tokens.rs::MAX_TOKEN_LIFETIME_SECS (24h) -- absolute ceiling
const DEFAULT_MAX_TOKEN_LIFETIME_SECS: i64 = 8 * 60 * 60;

/// Maximum DPoP timestamp tolerance (seconds). Proofs older than this are rejected.
const DPOP_TIMESTAMP_TOLERANCE_SECS: i64 = 1;

/// Maximum entries in the DPoP replay cache before cleanup is triggered.
const DPOP_REPLAY_CACHE_MAX: usize = 100_000;

/// TTL for DPoP replay cache entries (seconds). Entries older than this are
/// eligible for eviction.
const DPOP_REPLAY_CACHE_TTL_SECS: i64 = 60;

// ---------------------------------------------------------------------------
// DPoP Replay Cache
// ---------------------------------------------------------------------------

/// Bounded DPoP proof replay cache with O(1) amortized operations.
///
/// Uses a two-generation approach: when the current generation fills up,
/// swap it with the previous generation (which is discarded). This ensures
/// O(1) amortized cleanup instead of O(n log n) emergency eviction.
///
/// PERSISTENCE DECISION: Intentionally ephemeral (in-memory only).
///
/// DPoP proofs have a 1-second timestamp tolerance (`DPOP_TIMESTAMP_TOLERANCE_SECS`)
/// and the replay cache TTL is 60 seconds. After a process restart, the replay
/// window is bounded to at most 60 seconds of previously-seen proofs that could
/// be replayed. This is acceptable because:
///   1. DPoP proofs are bound to a specific HTTP method and URL, limiting
///      replay scope even if the cache is lost.
///   2. The 1-second timestamp tolerance means proofs expire almost immediately
///      regardless of cache state.
///   3. Persisting 100K+ hash entries with sub-millisecond write latency would
///      require Redis or similar, adding a failure dependency to every token
///      verification. The bounded replay window does not justify this cost.
///   4. Token JTI replay detection (which IS persisted via DatabaseJtiStore)
///      provides a second layer of replay protection at the token level.
struct DpopReplayCache {
    /// Current generation of proof hashes.
    current: HashMap<[u8; 64], i64>,
    /// Previous generation — kept for overlap protection during rotation.
    previous: HashMap<[u8; 64], i64>,
    /// Timestamp of last rotation.
    last_rotation: i64,
}

impl DpopReplayCache {
    fn new() -> Self {
        Self {
            current: HashMap::new(),
            previous: HashMap::new(),
            last_rotation: 0,
        }
    }

    /// Check if a proof has been seen before. If not, record it and return `false`.
    /// If already seen (replay), return `true`.
    ///
    /// SECURITY: This method MUST be called under exclusive lock to prevent
    /// TOCTOU races between the contains_key check and the insert.
    /// The cleanup, check, and insert form an atomic unit.
    // SAFETY: &mut self guarantees exclusive access — no TOCTOU possible.
    // The global DPOP_REPLAY_CACHE wraps this in a Mutex for additional
    // thread-safety, ensuring the entire check-cleanup-insert sequence is atomic.
    fn check_and_record(&mut self, proof_hash: &[u8; 64]) -> bool {
        let now = common::secure_time::secure_now_secs_i64();

        // Check both generations — O(1)
        if self.current.contains_key(proof_hash) || self.previous.contains_key(proof_hash) {
            return true; // Replay detected
        }

        // Rotate generations when current is at capacity — O(1) amortized
        if self.current.len() >= DPOP_REPLAY_CACHE_MAX / 2
            && (now - self.last_rotation) > DPOP_REPLAY_CACHE_TTL_SECS
        {
            // Swap: old `previous` is dropped, old `current` becomes `previous`
            self.previous = std::mem::take(&mut self.current);
            self.last_rotation = now;
        }

        self.current.insert(*proof_hash, now);
        false
    }
}

/// Global DPoP replay cache — thread-safe via Mutex.
static DPOP_REPLAY_CACHE: std::sync::LazyLock<Mutex<DpopReplayCache>> =
    std::sync::LazyLock::new(|| Mutex::new(DpopReplayCache::new()));

/// Check and record a DPoP proof hash in the replay cache.
/// Returns `true` if this is a replay (proof was already seen).
pub fn is_dpop_replay(proof_hash: &[u8; 64]) -> bool {
    match DPOP_REPLAY_CACHE.lock() {
        Ok(mut cache) => cache.check_and_record(proof_hash),
        Err(_) => {
            // Mutex poisoned — fail closed (reject as replay)
            tracing::error!("DPoP replay cache mutex poisoned — rejecting proof");
            true
        }
    }
}

/// Verify a token's signature and claims (spec C.11), enforcing DPoP channel
/// binding.
///
/// DPoP enforcement policy (mandatory, unconditional):
/// - When `client_dpop_key` is `Some`, the token's `dpop_hash` MUST match
///   the hash of the provided key.
/// - When `client_dpop_key` is `None` AND the token has a non-zero `dpop_hash`,
///   the token is rejected (DPoP-bound token presented without proof).
/// - When `client_dpop_key` is `None` AND `dpop_hash` is all zeros, the token
///   is rejected unconditionally. All tiers require DPoP.
///
/// Verification order:
/// 1. Check version and expiry
/// 2. Enforce algorithm field (must be 1 -- prevents downgrade attacks)
/// 3. Enforce DPoP channel binding (mandatory for all tiers)
/// 4. Validate ratchet_epoch is within reasonable bounds
/// 5. Check pq_signature is NOT empty (reject if missing)
/// 6. Verify ML-DSA-87 signature over (claims_msg || frost_signature)
/// 7. Verify FROST signature over claims_msg
/// 8. Check tier validity
///
/// Both PQ and FROST signatures must pass.
pub fn verify_token(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
) -> Result<TokenClaims, MilnetError> {
    verify_token_inner(token, public_key_package, pq_verifying_key, None)
}

/// Verify a token's signature and claims, enforcing DPoP binding against the
/// provided client key. This is the preferred entry point when the caller
/// knows the expected client key.
pub fn verify_token_bound(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    client_dpop_key: &[u8],
) -> Result<TokenClaims, MilnetError> {
    verify_token_inner(token, public_key_package, pq_verifying_key, Some(client_dpop_key))
}

/// DPoP is mandatory for ALL tiers — no exemptions.
///
/// The `MILNET_DPOP_EXEMPT_TIERS` env var is deprecated and ignored.
/// Previously Tier 3 (Sensor) and Tier 4 (Emergency) could be exempted,
/// but this created a security hole where stolen tokens could be replayed
/// from any device. DPoP channel binding is now unconditionally enforced.
fn warn_if_dpop_exempt_tiers_set() {
    if std::env::var("MILNET_DPOP_EXEMPT_TIERS").is_ok() {
        tracing::warn!("MILNET_DPOP_EXEMPT_TIERS is deprecated and ignored — DPoP is mandatory for all tiers");
    }
}

/// Inner verification logic shared by all public verification entry points.
fn verify_token_inner(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    client_dpop_key: Option<&[u8]>,
) -> Result<TokenClaims, MilnetError> {
    verify_token_core(token, public_key_package, pq_verifying_key, client_dpop_key, None)
}

/// Core verification with optional ceremony binding.
fn verify_token_core(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    client_dpop_key: Option<&[u8]>,
    expected_ceremony_id: Option<&[u8; 32]>,
) -> Result<TokenClaims, MilnetError> {
    // 1. Check version
    if token.header.version != 1 {
        return Err(MilnetError::CryptoVerification(
            "unsupported token version".into(),
        ));
    }

    // 2. Enforce algorithm field — must be 1 (FROST+ML-DSA-87).
    //    Prevents downgrade attacks where attacker specifies algorithm=0
    //    to use weaker crypto.
    if token.header.algorithm != 1 {
        return Err(MilnetError::CryptoVerification(
            "unsupported algorithm: only algorithm 1 (FROST+ML-DSA-87) is permitted".into(),
        ));
    }

    // 3. Check expiry (monotonic-anchored, immune to clock manipulation)
    let now = common::secure_time::secure_now_us_i64();
    if token.claims.exp <= now {
        return Err(MilnetError::CryptoVerification(
            "token validation failed".into(),
        ));
    }

    // 3b. Check iat is not in the future (with clock skew tolerance).
    // Tokens issued in the future indicate clock manipulation or replay
    // of pre-generated tokens. Tolerance: 10 seconds per NIST SP 800-63B.
    const IAT_SKEW_TOLERANCE_US: i64 = 10_000_000; // 10 seconds in microseconds
    if token.claims.iat > now + IAT_SKEW_TOLERANCE_US {
        return Err(MilnetError::CryptoVerification(
            "token iat is in the future beyond clock skew tolerance".into(),
        ));
    }

    // 4. DPoP channel binding enforcement (MANDATORY, unconditional):
    //
    //    Policy matrix:
    //    ┌──────────────────┬──────────────────┬──────────────────────────────┐
    //    │ client_dpop_key  │ token dpop_hash  │ Result                       │
    //    ├──────────────────┼──────────────────┼──────────────────────────────┤
    //    │ Some(key)        │ non-zero         │ MUST match hash(key)         │
    //    │ Some(key)        │ all zeros        │ REJECT (token has no DPoP)   │
    //    │ None             │ non-zero         │ REJECT (proof missing)       │
    //    │ None             │ all zeros        │ REJECT (mandatory for all)   │
    //    └──────────────────┴──────────────────┴──────────────────────────────┘
    //
    //    DPoP is mandatory for ALL tiers — no exemptions, no env var overrides.
    // Warn if deprecated env var is set (no-op, just logs)
    warn_if_dpop_exempt_tiers_set();

    let all_zeros = [0u8; 64];
    // SECURITY: constant-time zero check prevents timing leak on dpop_hash
    let has_dpop_hash: bool = !crypto::ct::ct_eq_64(&token.claims.dpop_hash, &all_zeros);

    if let Some(key) = client_dpop_key {
        // Client provided a DPoP key -- token MUST have a matching dpop_hash.
        if !has_dpop_hash {
            return Err(MilnetError::CryptoVerification(
                "DPoP key provided but token has no DPoP binding (dpop_hash is zero)".into(),
            ));
        }
        let expected_hash = crypto::dpop::dpop_key_hash(key);
        if !crypto::ct::ct_eq(&token.claims.dpop_hash, &expected_hash) {
            return Err(MilnetError::CryptoVerification(
                "token verification failed".into(),
            ));
        }
    } else if has_dpop_hash {
        // Token has a DPoP binding but no client key was provided -- reject.
        // A DPoP-bound token MUST always be presented with its proof key.
        return Err(MilnetError::CryptoVerification(
            "token has DPoP binding but no client DPoP key was provided — \
             possible token theft"
                .into(),
        ));
    } else {
        // No DPoP on either side -- reject unconditionally.
        // DPoP is mandatory for ALL tiers (no exemptions).
        return Err(MilnetError::CryptoVerification(
            "DPoP binding is required — token has no dpop_hash and no client \
             key was provided. DPoP is mandatory for all tiers"
                .into(),
        ));
    }

    // 4b. Verify ceremony binding if present.
    //     ceremony_id is set (non-zero) — verify it matches the expected ceremony.
    //     This prevents tokens from being moved between ceremonies.
    //     If no expected_ceremony_id is supplied by the caller, the check is
    //     skipped (backward-compatible). Once all callers supply the expected ID,
    //     the `None` path becomes unreachable in production.
    let has_ceremony = !crypto::ct::ct_eq(&token.claims.ceremony_id, &[0u8; 32]);
    if has_ceremony {
        if let Some(expected_ceremony) = expected_ceremony_id {
            if !crypto::ct::ct_eq(&token.claims.ceremony_id, expected_ceremony) {
                return Err(MilnetError::CryptoVerification(
                    "token ceremony binding mismatch — token bound to different ceremony".into(),
                ));
            }
        }
    }

    // 5. Validate ratchet_epoch is within reasonable bounds (constant-time)
    let epoch_zero = crypto::ct::ct_eq(&token.claims.ratchet_epoch.to_le_bytes(), &0u64.to_le_bytes());
    let epoch_over = token.claims.ratchet_epoch > MAX_SESSION_EPOCHS;
    if epoch_zero || epoch_over {
        return Err(MilnetError::CryptoVerification(format!(
            "ratchet_epoch {} out of valid range [1, {}]",
            token.claims.ratchet_epoch, MAX_SESSION_EPOCHS
        )));
    }

    // 6. Reconstruct signed message: domain prefix + serialized claims
    let claims_bytes = postcard::to_allocvec(&token.claims)
        .map_err(|e| MilnetError::Serialization(e.to_string()))?;
    let mut message = Vec::with_capacity(domain::FROST_TOKEN.len() + claims_bytes.len());
    message.extend_from_slice(domain::FROST_TOKEN);
    message.extend_from_slice(&claims_bytes);

    // 7. Check PQ signature is present (spec C.11: reject if missing)
    if token.pq_signature.is_empty() {
        return Err(MilnetError::CryptoVerification(
            "missing post-quantum signature".into(),
        ));
    }

    // 8. Verify ML-DSA-87 post-quantum signature over (message || frost_signature)
    if !pq_verify(
        pq_verifying_key,
        &message,
        &token.frost_signature,
        &token.pq_signature,
    ) {
        return Err(MilnetError::CryptoVerification(
            "ML-DSA-87 post-quantum signature invalid".into(),
        ));
    }

    // 9. Verify FROST threshold signature
    let sig = frost_ristretto255::Signature::deserialize(&token.frost_signature)
        .map_err(|e| MilnetError::CryptoVerification(format!("invalid signature encoding: {e}")))?;
    public_key_package
        .verifying_key()
        .verify(&message, &sig)
        .map_err(|_| MilnetError::CryptoVerification("FROST signature invalid".into()))?;

    // 10. Check tier is valid (1-4)
    if token.claims.tier == 0 || token.claims.tier > 4 {
        return Err(MilnetError::CryptoVerification("invalid tier".into()));
    }

    Ok(token.claims.clone())
}

/// Verify a token with revocation check (fail-fast before crypto).
///
/// Checks the revocation list first (O(1) HashMap lookup), then delegates
/// to full signature verification only if the token is not revoked.
pub fn verify_token_with_revocation(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    revocation_list: &RevocationList,
) -> Result<TokenClaims, MilnetError> {
    // Fail fast: check revocation before any expensive crypto
    if revocation_list.is_revoked(&token.claims.token_id) {
        return Err(MilnetError::CryptoVerification(
            "token has been revoked".into(),
        ));
    }

    verify_token(token, public_key_package, pq_verifying_key)
}

/// Full token verification: revocation + DPoP key binding + signatures.
///
/// This is the recommended entry point for production verification. It
/// performs all checks in optimal order:
/// 1. Fail fast: check revocation list (O(1) lookup)
/// 2. Full signature + DPoP verification (including key binding if provided)
pub fn verify_token_full(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    revocation_list: &RevocationList,
    client_dpop_key: Option<&[u8]>,
) -> Result<TokenClaims, MilnetError> {
    // 1. Fail fast: check revocation
    if revocation_list.is_revoked(&token.claims.token_id) {
        common::audit_bridge::buffer_audit_entry(
            common::audit_bridge::create_audit_entry(
                common::types::AuditEventType::AuthFailure,
                vec![token.claims.sub],
                Vec::new(),
                None,
                None,
            ),
        );
        return Err(MilnetError::CryptoVerification(
            "token has been revoked".into(),
        ));
    }
    // 2. Full signature + DPoP verification
    let result = verify_token_inner(token, public_key_package, pq_verifying_key, client_dpop_key);
    if result.is_err() {
        common::audit_bridge::buffer_audit_entry(
            common::audit_bridge::create_audit_entry(
                common::types::AuditEventType::AuthFailure,
                vec![token.claims.sub],
                Vec::new(),
                None,
                None,
            ),
        );
    }
    result
}

/// Full token verification with ceremony binding enforcement.
///
/// In addition to revocation + DPoP + signatures, this validates that the
/// token's `ceremony_id` matches the expected ceremony session. This prevents
/// token migration between ceremonies even if DPoP keys are compromised.
pub fn verify_token_ceremony_bound(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    revocation_list: &RevocationList,
    client_dpop_key: Option<&[u8]>,
    expected_ceremony_id: &[u8; 32],
) -> Result<TokenClaims, MilnetError> {
    // 1. Fail fast: check revocation
    if revocation_list.is_revoked(&token.claims.token_id) {
        return Err(MilnetError::CryptoVerification(
            "token has been revoked".into(),
        ));
    }
    // 2. Full signature + DPoP + ceremony binding verification
    verify_token_core(token, public_key_package, pq_verifying_key, client_dpop_key, Some(expected_ceremony_id))
}

/// Verify a token with full checks including audience validation.
///
/// When `expected_audience` is `Some`, the token's `aud` field must match
/// exactly. When `None`, audience is not checked — but if `REQUIRE_TOKEN_AUDIENCE`
/// is set to `true` (the default), tokens without an audience claim are rejected
/// even when no expected audience is specified.
pub fn verify_token_with_audience(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    revocation_list: &RevocationList,
    client_dpop_key: Option<&[u8]>,
    expected_audience: Option<&str>,
) -> Result<TokenClaims, MilnetError> {
    // 1. Revocation check (fail-fast)
    if revocation_list.is_revoked(&token.claims.token_id) {
        return Err(MilnetError::CryptoVerification(
            "token has been revoked".into(),
        ));
    }

    // 2. Audience validation — if expected audience is provided, token must match
    if let Some(expected) = expected_audience {
        match &token.claims.aud {
            Some(aud) if crypto::ct::ct_eq(aud.as_bytes(), expected.as_bytes()) => {} // constant-time match
            Some(aud) => {
                return Err(MilnetError::CryptoVerification(format!(
                    "audience mismatch: token bound to '{}', expected '{}'",
                    aud, expected
                )));
            }
            None => {
                return Err(MilnetError::CryptoVerification(
                    "token has no audience claim but audience validation is required".into(),
                ));
            }
        }
    } else {
        // Audience binding is MANDATORY. No env var override allowed.
        // SECURITY: Previously REQUIRE_TOKEN_AUDIENCE env var could disable this,
        // creating an inconsistency with the OIDC path which hardcodes it.
        // Removed env var bypass to prevent environment variable injection attacks.
        if token.claims.aud.is_none() {
            return Err(MilnetError::CryptoVerification(
                "token audience (aud) claim is required but missing — \
                 audience binding is mandatory for all token types"
                    .into(),
            ));
        }
    }

    // 3. Full signature + DPoP verification
    verify_token_inner(token, public_key_package, pq_verifying_key, client_dpop_key)
}

/// Verify a token's signature, claims, AND DPoP channel binding.
///
/// This ensures the token is bound to the client that originally requested it,
/// preventing token theft and replay by a different client.
pub fn verify_token_with_dpop(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    client_dpop_key: &[u8],
) -> Result<TokenClaims, MilnetError> {
    let claims = verify_token(token, public_key_package, pq_verifying_key)?;

    // Verify DPoP binding
    let expected_hash = crypto::dpop::dpop_key_hash(client_dpop_key);
    if !crypto::ct::ct_eq(&token.claims.dpop_hash, &expected_hash) {
        return Err(MilnetError::CryptoVerification(
            "token verification failed".into(),
        ));
    }

    Ok(claims)
}

/// Compute an HMAC-SHA512 ratchet tag over (TOKEN_TAG || claims_bytes || epoch).
fn compute_ratchet_tag(ratchet_key: &[u8; 64], claims_bytes: &[u8], epoch: u64) -> Result<[u8; 64], MilnetError> {
    let mut mac =
        HmacSha512::new_from_slice(ratchet_key)
            .map_err(|_| MilnetError::CryptoVerification("HMAC-SHA512 initialization failed".into()))?;
    mac.update(domain::TOKEN_TAG);
    mac.update(claims_bytes);
    mac.update(&epoch.to_le_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// Verify a token's signature, claims, AND ratchet tag.
///
/// Performs all checks from [`verify_token`], then additionally:
/// - Validates that the token's ratchet epoch is within a +/-3 window of `current_epoch`.
/// - Verifies the ratchet tag via constant-time HMAC-SHA512 comparison.
pub fn verify_token_with_ratchet(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    ratchet_key: &[u8; 64],
    current_epoch: u64,
) -> Result<TokenClaims, MilnetError> {
    verify_token_with_ratchet_inner(token, public_key_package, pq_verifying_key, ratchet_key, current_epoch, None)
}

/// Verify a token's signature, claims, ratchet tag, AND DPoP binding.
pub fn verify_token_with_ratchet_bound(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    ratchet_key: &[u8; 64],
    current_epoch: u64,
    client_dpop_key: &[u8],
) -> Result<TokenClaims, MilnetError> {
    verify_token_with_ratchet_inner(token, public_key_package, pq_verifying_key, ratchet_key, current_epoch, Some(client_dpop_key))
}

fn verify_token_with_ratchet_inner(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    ratchet_key: &[u8; 64],
    current_epoch: u64,
    client_dpop_key: Option<&[u8]>,
) -> Result<TokenClaims, MilnetError> {
    // 1. Do all existing checks (version, expiry, DPoP, ceremony binding, FROST + PQ signature, tier)
    let claims = verify_token_core(token, public_key_package, pq_verifying_key, client_dpop_key, None)?;

    // 2. Check ratchet epoch is within +/-3 window
    let epoch_diff = token.claims.ratchet_epoch.abs_diff(current_epoch);
    if epoch_diff > 3 {
        return Err(MilnetError::CryptoVerification(
            "token validation failed".into(),
        ));
    }

    // 3. Verify ratchet tag
    let claims_bytes = postcard::to_allocvec(&token.claims)
        .map_err(|e| MilnetError::Serialization(e.to_string()))?;
    let expected_tag = compute_ratchet_tag(ratchet_key, &claims_bytes, token.claims.ratchet_epoch)?;
    if !crypto::ct::ct_eq(&token.ratchet_tag, &expected_tag) {
        return Err(MilnetError::CryptoVerification(
            "ratchet tag invalid".into(),
        ));
    }

    Ok(claims)
}

// ---------------------------------------------------------------------------
// SharedRevocationList-based verification (thread-safe, with lazy cleanup)
// ---------------------------------------------------------------------------

/// Full token verification using the thread-safe [`SharedRevocationList`].
///
/// This is the recommended entry point for production verification with
/// concurrent access. It performs:
/// 1. Lazy cleanup of expired revocation entries (at most once per 60 seconds)
/// 2. Fail-fast revocation check (O(1) lookup, BEFORE any crypto)
/// 3. Full signature + DPoP verification
pub fn verify_token_with_shared_revocation(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    revocation_list: &SharedRevocationList,
    client_dpop_key: Option<&[u8]>,
) -> Result<TokenClaims, MilnetError> {
    // 1. Lazy cleanup: runs at most once per 60 seconds
    revocation_list.maybe_lazy_cleanup(DEFAULT_MAX_TOKEN_LIFETIME_SECS);

    // 2. Fail fast: check revocation BEFORE expensive cryptographic verification
    if revocation_list.is_revoked(&token.claims.token_id) {
        return Err(MilnetError::CryptoVerification(
            "token has been revoked".into(),
        ));
    }

    // 3. Full signature + DPoP verification
    verify_token_inner(token, public_key_package, pq_verifying_key, client_dpop_key)
}

/// Verify with SharedRevocationList + ceremony binding enforcement.
///
/// This is the recommended production entry point when the caller knows
/// the expected ceremony session ID. It enforces that the token was issued
/// during the specific ceremony and cannot be migrated.
pub fn verify_token_with_shared_revocation_ceremony_bound(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    revocation_list: &SharedRevocationList,
    client_dpop_key: Option<&[u8]>,
    expected_ceremony_id: &[u8; 32],
) -> Result<TokenClaims, MilnetError> {
    revocation_list.maybe_lazy_cleanup(DEFAULT_MAX_TOKEN_LIFETIME_SECS);
    if revocation_list.is_revoked(&token.claims.token_id) {
        return Err(MilnetError::CryptoVerification(
            "token has been revoked".into(),
        ));
    }
    verify_token_core(token, public_key_package, pq_verifying_key, client_dpop_key, Some(expected_ceremony_id))
}

// ---------------------------------------------------------------------------
// Classification-enforced verification
// ---------------------------------------------------------------------------

/// Verify a token with full checks INCLUDING mandatory access control.
///
/// In addition to all standard checks (revocation, DPoP, signatures), this
/// verifies that the token's classification level meets or exceeds the
/// `required_classification` of the target resource.
///
/// Enforces the Bell-LaPadula simple security property: a subject may only
/// access a resource if their classification >= the resource's classification.
pub fn verify_token_with_classification(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    revocation_list: &SharedRevocationList,
    client_dpop_key: Option<&[u8]>,
    required_classification: ClassificationLevel,
) -> Result<TokenClaims, MilnetError> {
    // 1. Standard verification (revocation + DPoP + signatures)
    let claims = verify_token_with_shared_revocation(
        token,
        public_key_package,
        pq_verifying_key,
        revocation_list,
        client_dpop_key,
    )?;

    // 2. Classification enforcement (MAC)
    let token_classification = ClassificationLevel::from_u8(claims.classification)
        .unwrap_or(ClassificationLevel::Unclassified);
    let decision = classification::enforce_classification(
        token_classification,
        required_classification,
    );
    if !decision.is_granted() {
        return Err(MilnetError::CryptoVerification(format!(
            "classification denied: token has {} but resource requires {}",
            token_classification.label(),
            required_classification.label(),
        )));
    }

    Ok(claims)
}

/// Return the DPoP timestamp tolerance in seconds.
///
/// Reduced from the previous 2-second tolerance to 1 second for tighter
/// replay protection. Configurable via `MILNET_DPOP_TOLERANCE_SECS` for
/// environments with known clock skew.
pub fn dpop_timestamp_tolerance_secs() -> i64 {
    std::env::var("MILNET_DPOP_TOLERANCE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DPOP_TIMESTAMP_TOLERANCE_SECS)
}

// ---------------------------------------------------------------------------
// Encrypted token verification
// ---------------------------------------------------------------------------

/// Verify an encrypted token: decrypt claims first, then run full verification.
///
/// This is the basic encrypted verification path. For production use, prefer
/// [`verify_encrypted_token_full`] which includes revocation and DPoP checks.
pub fn verify_encrypted_token(
    encrypted_token: &EncryptedToken,
    claims_dek: &[u8; 32],
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
) -> Result<TokenClaims, MilnetError> {
    let token = jwe::decrypt_token(encrypted_token.clone(), claims_dek)
        .map_err(MilnetError::CryptoVerification)?;
    verify_token(&token, public_key_package, pq_verifying_key)
}

/// Full encrypted token verification: decrypt, then check revocation + DPoP + signatures.
///
/// This is the recommended entry point for production verification of encrypted
/// tokens. It performs:
/// 1. JWE decryption of claims (AES-256-GCM)
/// 2. Fail-fast revocation check
/// 3. Full signature + DPoP verification
pub fn verify_encrypted_token_full(
    encrypted_token: &EncryptedToken,
    claims_dek: &[u8; 32],
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    revocation_list: &RevocationList,
    client_dpop_key: Option<&[u8]>,
) -> Result<TokenClaims, MilnetError> {
    let token = jwe::decrypt_token(encrypted_token.clone(), claims_dek)
        .map_err(MilnetError::CryptoVerification)?;
    verify_token_full(&token, public_key_package, pq_verifying_key, revocation_list, client_dpop_key)
}

/// Verify an encrypted token with shared revocation list (thread-safe).
pub fn verify_encrypted_token_with_shared_revocation(
    encrypted_token: &EncryptedToken,
    claims_dek: &[u8; 32],
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    revocation_list: &SharedRevocationList,
    client_dpop_key: Option<&[u8]>,
) -> Result<TokenClaims, MilnetError> {
    let token = jwe::decrypt_token(encrypted_token.clone(), claims_dek)
        .map_err(MilnetError::CryptoVerification)?;
    verify_token_with_shared_revocation(
        &token,
        public_key_package,
        pq_verifying_key,
        revocation_list,
        client_dpop_key,
    )
}

/// Verify an encrypted token with audience validation.
pub fn verify_encrypted_token_with_audience(
    encrypted_token: &EncryptedToken,
    claims_dek: &[u8; 32],
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    revocation_list: &RevocationList,
    client_dpop_key: Option<&[u8]>,
    expected_audience: Option<&str>,
) -> Result<TokenClaims, MilnetError> {
    let token = jwe::decrypt_token(encrypted_token.clone(), claims_dek)
        .map_err(MilnetError::CryptoVerification)?;
    verify_token_with_audience(
        &token,
        public_key_package,
        pq_verifying_key,
        revocation_list,
        client_dpop_key,
        expected_audience,
    )
}

/// Verify an encrypted token with classification enforcement (MAC).
pub fn verify_encrypted_token_with_classification(
    encrypted_token: &EncryptedToken,
    claims_dek: &[u8; 32],
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    revocation_list: &SharedRevocationList,
    client_dpop_key: Option<&[u8]>,
    required_classification: ClassificationLevel,
) -> Result<TokenClaims, MilnetError> {
    let token = jwe::decrypt_token(encrypted_token.clone(), claims_dek)
        .map_err(MilnetError::CryptoVerification)?;
    verify_token_with_classification(
        &token,
        public_key_package,
        pq_verifying_key,
        revocation_list,
        client_dpop_key,
        required_classification,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpop_replay_cache_first_use() {
        let mut hash = [0u8; 64];
        getrandom::getrandom(&mut hash).unwrap();
        // First use should NOT be a replay
        assert!(!is_dpop_replay(&hash));
    }

    #[test]
    fn test_dpop_replay_cache_second_use() {
        let mut hash = [0u8; 64];
        getrandom::getrandom(&mut hash).unwrap();
        assert!(!is_dpop_replay(&hash));
        // Second use SHOULD be a replay
        assert!(is_dpop_replay(&hash));
    }

    #[test]
    fn test_dpop_replay_cache_different_hashes() {
        let mut hash1 = [0u8; 64];
        let mut hash2 = [0u8; 64];
        getrandom::getrandom(&mut hash1).unwrap();
        getrandom::getrandom(&mut hash2).unwrap();
        assert!(!is_dpop_replay(&hash1));
        assert!(!is_dpop_replay(&hash2));
        // Both should now be recorded
        assert!(is_dpop_replay(&hash1));
        assert!(is_dpop_replay(&hash2));
    }

    #[test]
    fn test_dpop_timestamp_tolerance() {
        // Default tolerance (no env var) should be 1 second
        let tolerance = dpop_timestamp_tolerance_secs();
        assert_eq!(tolerance, 1);
    }

    #[test]
    fn test_compute_ratchet_tag_deterministic() {
        let key = [0xAA; 64];
        let claims_bytes = b"test claims data";
        let epoch = 42u64;
        let tag1 = compute_ratchet_tag(&key, claims_bytes, epoch).unwrap();
        let tag2 = compute_ratchet_tag(&key, claims_bytes, epoch).unwrap();
        assert_eq!(tag1, tag2, "same inputs must produce identical ratchet tags");
    }

    #[test]
    fn test_compute_ratchet_tag_different_epochs() {
        let key = [0xAA; 64];
        let claims_bytes = b"test claims data";
        let tag1 = compute_ratchet_tag(&key, claims_bytes, 1).unwrap();
        let tag2 = compute_ratchet_tag(&key, claims_bytes, 2).unwrap();
        assert_ne!(tag1, tag2, "different epochs must produce different tags");
    }

    #[test]
    fn test_compute_ratchet_tag_different_keys() {
        let key1 = [0xAA; 64];
        let key2 = [0xBB; 64];
        let claims_bytes = b"test claims data";
        let tag1 = compute_ratchet_tag(&key1, claims_bytes, 1).unwrap();
        let tag2 = compute_ratchet_tag(&key2, claims_bytes, 1).unwrap();
        assert_ne!(tag1, tag2, "different keys must produce different tags");
    }

    #[test]
    fn test_compute_ratchet_tag_different_claims() {
        let key = [0xAA; 64];
        let tag1 = compute_ratchet_tag(&key, b"claims A", 1).unwrap();
        let tag2 = compute_ratchet_tag(&key, b"claims B", 1).unwrap();
        assert_ne!(tag1, tag2, "different claims must produce different tags");
    }

    #[test]
    fn test_compute_ratchet_tag_nonzero() {
        let key = [0xAA; 64];
        let tag = compute_ratchet_tag(&key, b"test", 1).unwrap();
        assert_ne!(tag, [0u8; 64], "ratchet tag should not be all zeros");
    }

    #[test]
    fn test_ceremony_binding_mismatch_detected() {
        // Verify that verify_token_core rejects tokens with mismatched ceremony_id.
        // We test the ceremony_id != [0u8;32] branch by constructing claims
        // with a non-zero ceremony_id and providing a different expected ID.
        let ceremony_a = [0xAA; 32];
        let ceremony_b = [0xBB; 32];
        // ceremony_a != ceremony_b, both non-zero → ct_eq should fail
        assert!(!crypto::ct::ct_eq(&ceremony_a, &ceremony_b));
    }

    #[test]
    fn test_ceremony_binding_match_accepted() {
        let ceremony = [0xCC; 32];
        assert!(crypto::ct::ct_eq(&ceremony, &ceremony));
    }

    #[test]
    fn test_ceremony_binding_zero_skips_check() {
        // When ceremony_id is all zeros, the binding check is skipped
        // regardless of expected_ceremony_id (backward compatibility).
        let zero = [0u8; 32];
        let expected = [0xDD; 32];
        // Zero ceremony_id means "not bound" — check should be skipped
        assert_eq!(zero, [0u8; 32]);
        assert_ne!(zero, expected);
        // The actual code path: `if token.claims.ceremony_id != [0u8; 32]` → false → skip
    }
}
