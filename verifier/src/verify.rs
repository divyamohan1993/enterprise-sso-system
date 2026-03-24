use common::domain;
use common::error::MilnetError;
use common::revocation::{RevocationList, SharedRevocationList};
use common::types::{Token, TokenClaims};
use crypto::pq_sign::{pq_verify, PqVerifyingKey};
use frost_ristretto255::keys::PublicKeyPackage;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha512 = Hmac<Sha512>;

/// Maximum session epochs (8 hours at 10s/epoch).
const MAX_SESSION_EPOCHS: u64 = 2880;

/// Default max token lifetime for lazy cleanup (8 hours in seconds).
const DEFAULT_MAX_TOKEN_LIFETIME_SECS: i64 = 8 * 60 * 60;

/// Verify a token's signature and claims (spec C.11), enforcing DPoP channel
/// binding.
///
/// DPoP enforcement policy (controlled by `MILNET_REQUIRE_DPOP`, defaults to
/// `true` in production):
/// - When `client_dpop_key` is `Some`, the token's `dpop_hash` MUST match
///   the hash of the provided key.
/// - When `client_dpop_key` is `None` AND the token has a non-zero `dpop_hash`,
///   the token is rejected (DPoP-bound token presented without proof).
/// - When `client_dpop_key` is `None` AND `dpop_hash` is all zeros, the token
///   is rejected in production mode UNLESS the tier is 3 (Sensor) or 4
///   (Emergency) which may lack DPoP capability.
///
/// Verification order:
/// 1. Check version and expiry
/// 2. Enforce algorithm field (must be 1 — prevents downgrade attacks)
/// 3. Enforce DPoP channel binding (mandatory in production)
/// 4. Validate ratchet_epoch is within reasonable bounds
/// 5. Check pq_signature is NOT empty (reject if missing)
/// 6. Verify ML-DSA-65 signature over (claims_msg || frost_signature)
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

/// Returns `true` if DPoP is required based on environment configuration.
///
/// Reads `MILNET_REQUIRE_DPOP`:
/// - `"false"` or `"0"` → DPoP not required (dev/test mode)
/// - anything else or unset → DPoP required (production default)
fn dpop_required() -> bool {
    std::env::var("MILNET_REQUIRE_DPOP")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true)
}

/// Returns `true` if the given tier is exempt from DPoP requirements.
///
/// Tier 3 (Sensor) and Tier 4 (Emergency) devices may lack the computational
/// resources or stable connectivity needed for DPoP key management, so they
/// are exempt from the DPoP binding requirement.
fn is_dpop_exempt_tier(tier: u8) -> bool {
    tier == 3 || tier == 4
}

/// Inner verification logic shared by `verify_token` and `verify_token_bound`.
fn verify_token_inner(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
    client_dpop_key: Option<&[u8]>,
) -> Result<TokenClaims, MilnetError> {
    // 1. Check version
    if token.header.version != 1 {
        return Err(MilnetError::CryptoVerification(
            "unsupported token version".into(),
        ));
    }

    // 2. Enforce algorithm field — must be 1 (FROST+ML-DSA-65).
    //    Prevents downgrade attacks where attacker specifies algorithm=0
    //    to use weaker crypto.
    if token.header.algorithm != 1 {
        return Err(MilnetError::CryptoVerification(
            "unsupported algorithm: only algorithm 1 (FROST+ML-DSA-65) is permitted".into(),
        ));
    }

    // 3. Check expiry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    if token.claims.exp <= now {
        return Err(MilnetError::CryptoVerification(
            "token validation failed".into(),
        ));
    }

    // 4. DPoP channel binding enforcement (MANDATORY in production):
    //
    //    Policy matrix:
    //    ┌──────────────────┬──────────────────┬──────────────────────────────┐
    //    │ client_dpop_key  │ token dpop_hash  │ Result                       │
    //    ├──────────────────┼──────────────────┼──────────────────────────────┤
    //    │ Some(key)        │ non-zero         │ MUST match hash(key)         │
    //    │ Some(key)        │ all zeros        │ REJECT (token has no DPoP)   │
    //    │ None             │ non-zero         │ REJECT (proof missing)       │
    //    │ None             │ all zeros        │ REJECT unless exempt tier    │
    //    └──────────────────┴──────────────────┴──────────────────────────────┘
    //
    //    Tiers 3 (Sensor) and 4 (Emergency) are exempt from DPoP when
    //    MILNET_REQUIRE_DPOP is true — they may lack DPoP capability.
    let all_zeros = [0u8; 32];
    let require_dpop = dpop_required();
    let has_dpop_hash = token.claims.dpop_hash != all_zeros;

    if let Some(key) = client_dpop_key {
        // Client provided a DPoP key — token MUST have a matching dpop_hash.
        if !has_dpop_hash {
            return Err(MilnetError::CryptoVerification(
                "DPoP key provided but token has no DPoP binding (dpop_hash is zero)".into(),
            ));
        }
        let expected_hash = crypto::dpop::dpop_key_hash(key);
        if !crypto::ct::ct_eq(&token.claims.dpop_hash, &expected_hash) {
            return Err(MilnetError::CryptoVerification(
                "DPoP key hash mismatch — token bound to different client".into(),
            ));
        }
    } else if has_dpop_hash && require_dpop {
        // Token has a DPoP binding but no client key was provided — reject.
        // A DPoP-bound token MUST always be presented with its proof key.
        // This check is gated on require_dpop so that test environments
        // (MILNET_REQUIRE_DPOP=false) can verify tokens without DPoP keys.
        return Err(MilnetError::CryptoVerification(
            "token has DPoP binding but no client DPoP key was provided — \
             possible token theft"
                .into(),
        ));
    } else if has_dpop_hash && !require_dpop {
        // DPoP hash present but enforcement disabled (test/dev mode) — warn
        // but allow. This path should NEVER be reached in production.
        tracing::warn!(
            "DPoP binding present but no client key provided — \
             allowed because MILNET_REQUIRE_DPOP=false (test mode)"
        );
    } else if require_dpop && !is_dpop_exempt_tier(token.claims.tier) {
        // No DPoP on either side, production mode, non-exempt tier — reject.
        return Err(MilnetError::CryptoVerification(
            "DPoP binding is required in production mode (MILNET_REQUIRE_DPOP=true) — \
             token has no dpop_hash and no client key was provided. \
             Only Tier 3 (Sensor) and Tier 4 (Emergency) are exempt"
                .into(),
        ));
    }

    // 5. Validate ratchet_epoch is within reasonable bounds
    if token.claims.ratchet_epoch == 0 || token.claims.ratchet_epoch > MAX_SESSION_EPOCHS {
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

    // 8. Verify ML-DSA-65 post-quantum signature over (message || frost_signature)
    if !pq_verify(
        pq_verifying_key,
        &message,
        &token.frost_signature,
        &token.pq_signature,
    ) {
        return Err(MilnetError::CryptoVerification(
            "ML-DSA-65 post-quantum signature invalid".into(),
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
        return Err(MilnetError::CryptoVerification(
            "token has been revoked".into(),
        ));
    }
    // 2. Full signature + DPoP verification
    verify_token_inner(token, public_key_package, pq_verifying_key, client_dpop_key)
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
            Some(aud) if aud == expected => {} // match
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
        // No expected audience specified — enforce audience presence if configured.
        // REQUIRE_TOKEN_AUDIENCE defaults to true; set to "false" to allow tokens without aud.
        let require_aud = std::env::var("REQUIRE_TOKEN_AUDIENCE")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);
        if require_aud && token.claims.aud.is_none() {
            return Err(MilnetError::CryptoVerification(
                "token audience (aud) claim is required but missing — \
                 set REQUIRE_TOKEN_AUDIENCE=false to allow tokens without audience binding"
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
            "DPoP key hash mismatch — token bound to different client".into(),
        ));
    }

    Ok(claims)
}

/// Compute an HMAC-SHA512 ratchet tag over (TOKEN_TAG || claims_bytes || epoch).
fn compute_ratchet_tag(ratchet_key: &[u8; 64], claims_bytes: &[u8], epoch: u64) -> [u8; 64] {
    let mut mac =
        HmacSha512::new_from_slice(ratchet_key).expect("HMAC-SHA512 accepts any key length");
    mac.update(domain::TOKEN_TAG);
    mac.update(claims_bytes);
    mac.update(&epoch.to_le_bytes());
    mac.finalize().into_bytes().into()
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
    // 1. Do all existing checks (version, expiry, FROST + PQ signature, tier)
    let claims = verify_token(token, public_key_package, pq_verifying_key)?;

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
    let expected_tag = compute_ratchet_tag(ratchet_key, &claims_bytes, token.claims.ratchet_epoch);
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
