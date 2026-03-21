use ed25519_dalek::VerifyingKey;
use milnet_common::domain;
use milnet_common::error::MilnetError;
use milnet_common::types::{Token, TokenClaims};
use std::time::{SystemTime, UNIX_EPOCH};

/// Verify a token's signature and claims.
/// This is the O(1) hot path — must be as fast as possible.
pub fn verify_token(
    token: &Token,
    group_verifying_key: &VerifyingKey,
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

    // 4. Verify FROST threshold signature
    let group = milnet_crypto::threshold::ThresholdGroup {
        threshold: 3,
        total: 5,
        group_verifying_key: *group_verifying_key,
    };
    if !milnet_crypto::threshold::verify_group_signature(&group, &message, &token.frost_signature) {
        return Err(MilnetError::CryptoVerification(
            "FROST signature invalid".into(),
        ));
    }

    // 5. Check tier is valid (1-4)
    if token.claims.tier == 0 || token.claims.tier > 4 {
        return Err(MilnetError::CryptoVerification("invalid tier".into()));
    }

    Ok(token.claims.clone())
}
