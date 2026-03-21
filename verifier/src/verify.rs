use frost_ristretto255::keys::PublicKeyPackage;
use common::domain;
use common::error::MilnetError;
use common::types::{Token, TokenClaims};
use crypto::pq_sign::{pq_verify, PqVerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha512 = Hmac<Sha512>;

/// Verify a token's signature and claims (spec C.11).
///
/// Verification order:
/// 1. Check version and expiry
/// 2. Check pq_signature is NOT empty (reject if missing)
/// 3. Verify ML-DSA-65 signature over (claims_msg || frost_signature)
/// 4. Verify FROST signature over claims_msg
/// 5. Check tier validity
///
/// Both PQ and FROST signatures must pass.
pub fn verify_token(
    token: &Token,
    public_key_package: &PublicKeyPackage,
    pq_verifying_key: &PqVerifyingKey,
) -> Result<TokenClaims, MilnetError> {
    // 1. Check version
    if token.header.version != 1 {
        return Err(MilnetError::CryptoVerification(
            "unsupported token version".into(),
        ));
    }

    // 2. Check expiry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    if token.claims.exp <= now {
        return Err(MilnetError::TokenExpired);
    }

    // 3. Reconstruct signed message: domain prefix + serialized claims
    let claims_bytes = postcard::to_allocvec(&token.claims)
        .map_err(|e| MilnetError::Serialization(e.to_string()))?;
    let mut message = Vec::with_capacity(domain::FROST_TOKEN.len() + claims_bytes.len());
    message.extend_from_slice(domain::FROST_TOKEN);
    message.extend_from_slice(&claims_bytes);

    // 4. Check PQ signature is present (spec C.11: reject if missing)
    if token.pq_signature.is_empty() {
        return Err(MilnetError::CryptoVerification(
            "missing post-quantum signature".into(),
        ));
    }

    // 5. Verify ML-DSA-65 post-quantum signature over (message || frost_signature)
    if !pq_verify(pq_verifying_key, &message, &token.frost_signature, &token.pq_signature) {
        return Err(MilnetError::CryptoVerification(
            "ML-DSA-65 post-quantum signature invalid".into(),
        ));
    }

    // 6. Verify FROST threshold signature
    let sig = frost_ristretto255::Signature::deserialize(&token.frost_signature)
        .map_err(|e| MilnetError::CryptoVerification(format!("invalid signature encoding: {e}")))?;
    public_key_package
        .verifying_key()
        .verify(&message, &sig)
        .map_err(|_| MilnetError::CryptoVerification("FROST signature invalid".into()))?;

    // 7. Check tier is valid (1-4)
    if token.claims.tier == 0 || token.claims.tier > 4 {
        return Err(MilnetError::CryptoVerification("invalid tier".into()));
    }

    Ok(token.claims.clone())
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
        return Err(MilnetError::TokenExpired);
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
