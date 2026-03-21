use common::domain;
use common::error::MilnetError;
use common::types::{Token, TokenClaims, TokenHeader};
use crypto::threshold::{threshold_sign, SignerShare, ThresholdGroup};
use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// Compute an HMAC-SHA512 ratchet tag over (TOKEN_TAG || claims_bytes || epoch).
fn compute_ratchet_tag(ratchet_key: &[u8; 64], claims_bytes: &[u8], epoch: u64) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(ratchet_key)
        .expect("HMAC-SHA512 accepts any key length");
    mac.update(domain::TOKEN_TAG);
    mac.update(claims_bytes);
    mac.update(&epoch.to_le_bytes());
    mac.finalize().into_bytes().into()
}

/// Build a threshold-signed token from validated claims.
///
/// Steps:
/// 1. Serialize claims with `FROST_TOKEN` domain prefix.
/// 2. Compute ratchet tag via HMAC-SHA512 using the provided ratchet key.
/// 3. Run FROST threshold signing ceremony.
/// 4. Build the final [`Token`].
pub fn build_token(
    claims: &TokenClaims,
    signers: &mut [SignerShare],
    group: &ThresholdGroup,
    ratchet_key: &[u8; 64],
) -> Result<Token, MilnetError> {
    // Domain-separated message
    let claims_bytes =
        postcard::to_allocvec(claims).map_err(|e| MilnetError::Serialization(e.to_string()))?;
    let msg = [domain::FROST_TOKEN, &claims_bytes].concat();

    // Compute real ratchet tag
    let ratchet_tag = compute_ratchet_tag(ratchet_key, &claims_bytes, claims.ratchet_epoch);

    // Run FROST threshold signing
    let frost_signature = threshold_sign(signers, group, &msg, group.threshold)
        .map_err(MilnetError::CryptoVerification)?;

    Ok(Token {
        header: TokenHeader {
            version: 1,
            algorithm: 1,
            tier: claims.tier,
        },
        claims: claims.clone(),
        ratchet_tag,
        frost_signature,
        pq_signature: Vec::new(), // PQ placeholder
    })
}
