use milnet_common::domain;
use milnet_common::error::MilnetError;
use milnet_common::types::{Token, TokenClaims, TokenHeader};
use milnet_crypto::threshold::{combine_partials, SignerShare, ThresholdGroup};

/// Build a threshold-signed token from validated claims.
///
/// Steps:
/// 1. Serialize claims with `FROST_TOKEN` domain prefix.
/// 2. Collect threshold partial signatures from signers.
/// 3. Combine via `combine_partials`.
/// 4. Build the final [`Token`].
pub fn build_token(
    claims: &TokenClaims,
    signers: &mut [SignerShare],
    group: &ThresholdGroup,
) -> Result<Token, MilnetError> {
    // Domain-separated message
    let claims_bytes =
        postcard::to_allocvec(claims).map_err(|e| MilnetError::Serialization(e.to_string()))?;
    let msg = [domain::FROST_TOKEN, &claims_bytes].concat();

    // Collect partial signatures from each signer
    let partials: Vec<_> = signers.iter_mut().map(|s| s.partial_sign(&msg)).collect();

    // Combine partials into a single group signature
    let frost_signature =
        combine_partials(group, &partials, &msg).map_err(MilnetError::CryptoVerification)?;

    Ok(Token {
        header: TokenHeader {
            version: 1,
            algorithm: 1,
            tier: claims.tier,
        },
        claims: claims.clone(),
        ratchet_tag: [0u8; 64], // Phase 3 placeholder
        frost_signature,
        pq_signature: Vec::new(), // PQ placeholder
    })
}
