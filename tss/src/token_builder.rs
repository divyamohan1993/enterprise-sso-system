use common::domain;
use common::error::MilnetError;
use common::types::{EncryptedToken, Token, TokenClaims, TokenHeader};
use crypto::jwe;
use crypto::pq_sign::{pq_sign, PqSigningKey};
use crypto::threshold::{threshold_sign, SignerShare, ThresholdGroup};
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::distributed::{SignerNode, SigningCoordinator};

type HmacSha512 = Hmac<Sha512>;

/// Compute an HMAC-SHA512 ratchet tag over (TOKEN_TAG || claims_bytes || epoch).
fn compute_ratchet_tag(ratchet_key: &[u8; 64], claims_bytes: &[u8], epoch: u64) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(ratchet_key)
        .unwrap_or_else(|e| {
            tracing::error!("FATAL: HMAC-SHA512 key init failed for ratchet tag: {e}");
            std::process::exit(1);
        });
    mac.update(domain::TOKEN_TAG);
    mac.update(claims_bytes);
    mac.update(&epoch.to_le_bytes());
    mac.finalize().into_bytes().into()
}

/// Prepare claims with an optional audience field.
///
/// If `audience` is `Some`, sets `claims.aud` to that value.
/// Another agent is adding `aud: Option<String>` to `TokenClaims` —
/// this function must be called before serialization so the audience
/// is included in the signed claims.
pub fn prepare_claims_with_audience(
    claims: &TokenClaims,
    audience: Option<String>,
) -> TokenClaims {
    let mut claims = claims.clone();
    claims.aud = audience;
    claims
}

/// Build a threshold-signed token from validated claims (monolithic).
///
/// **Deprecated**: all signer shares live in one process, which defeats
/// the purpose of threshold cryptography.  Use [`build_token_distributed`]
/// instead.
///
/// SECURITY: Gated behind `#[cfg(not(feature = "production"))]` to prevent
/// accidental production use. Co-locating all signer shares in one process
/// collapses 3-of-5 threshold security to effective 1-of-1. Stripped from
/// production binaries built with `--features production`.
///
/// Steps:
/// 1. Serialize claims with `FROST_TOKEN` domain prefix.
/// 2. Compute ratchet tag via HMAC-SHA512 using the provided ratchet key.
/// 3. Run FROST threshold signing ceremony.
/// 4. Build the final [`Token`].
#[cfg(not(feature = "production"))]
#[deprecated(note = "use build_token_distributed — shares must not be co-located")]
/// # Security Warning
///
/// This function co-locates all signing shares in one process, collapsing
/// 3-of-5 threshold security to 1-of-1. It is stripped from production
/// binaries via `#[cfg(not(feature = "production"))]`.
///
/// In production builds, attempting to use this function will fail to compile.
pub fn build_token(
    claims: &TokenClaims,
    signers: &mut [SignerShare],
    group: &ThresholdGroup,
    ratchet_key: &[u8; 64],
    pq_signing_key: &PqSigningKey,
    audience: Option<String>,
) -> Result<Token, MilnetError> {
    // Apply audience to claims before signing
    let claims = prepare_claims_with_audience(claims, audience);

    // Domain-separated message
    let claims_bytes =
        postcard::to_allocvec(&claims).map_err(|e| MilnetError::Serialization(e.to_string()))?;
    let msg = [domain::FROST_TOKEN, &claims_bytes].concat();

    // Compute real ratchet tag
    let ratchet_tag = compute_ratchet_tag(ratchet_key, &claims_bytes, claims.ratchet_epoch);

    // Run FROST threshold signing
    let frost_signature = threshold_sign(signers, group, &msg, group.threshold)
        .map_err(MilnetError::CryptoVerification)?;

    // Compute ML-DSA-87 post-quantum signature over (message || frost_signature)
    let pq_signature = pq_sign(pq_signing_key, &msg, &frost_signature);

    Ok(Token {
        header: TokenHeader {
            version: 1,
            algorithm: 1,
            tier: claims.tier,
        },
        claims,
        ratchet_tag,
        frost_signature,
        pq_signature,
    })
}

/// Build a threshold-signed token with encrypted claims (monolithic, deprecated).
///
/// SECURITY: Gated behind `#[cfg(not(feature = "production"))]` to prevent
/// accidental production use. Stripped from production binaries.
/// See [`build_encrypted_token_distributed`] for the preferred version.
#[cfg(not(feature = "production"))]
#[deprecated(note = "use build_encrypted_token_distributed — shares must not be co-located")]
pub fn build_encrypted_token(
    claims: &TokenClaims,
    signers: &mut [SignerShare],
    group: &ThresholdGroup,
    ratchet_key: &[u8; 64],
    pq_signing_key: &PqSigningKey,
    audience: Option<String>,
    claims_dek: &[u8; 32],
) -> Result<EncryptedToken, MilnetError> {
    #[allow(deprecated)]
    let token = build_token(claims, signers, group, ratchet_key, pq_signing_key, audience)?;
    jwe::encrypt_token(token, claims_dek).map_err(MilnetError::CryptoVerification)
}

/// Build a threshold-signed token using the distributed signing coordinator.
///
/// Each `SignerNode` holds exactly ONE FROST key share and runs in its own
/// process.  The `SigningCoordinator` holds NO signing keys -- it only
/// aggregates the partial signatures produced by the signer nodes.
///
/// Steps:
/// 1. Serialize claims with `FROST_TOKEN` domain prefix.
/// 2. Compute ratchet tag via HMAC-SHA512 using the provided ratchet key.
/// 3. Run the two-round FROST ceremony via the coordinator.
/// 4. Build the final [`Token`].
pub fn build_token_distributed(
    claims: &TokenClaims,
    coordinator: &SigningCoordinator,
    signers: &mut [&mut SignerNode],
    ratchet_key: &[u8; 64],
    pq_signing_key: &PqSigningKey,
    audience: Option<String>,
) -> Result<Token, MilnetError> {
    // Apply audience to claims before signing
    let claims = prepare_claims_with_audience(claims, audience);

    // Domain-separated message
    let claims_bytes =
        postcard::to_allocvec(&claims).map_err(|e| MilnetError::Serialization(e.to_string()))?;
    let msg = [domain::FROST_TOKEN, &claims_bytes].concat();

    // Compute real ratchet tag
    let ratchet_tag = compute_ratchet_tag(ratchet_key, &claims_bytes, claims.ratchet_epoch);

    // Run distributed FROST threshold signing
    let frost_signature = coordinator
        .coordinate_signing(signers, &msg)
        .map_err(MilnetError::CryptoVerification)?;

    // Compute ML-DSA-87 post-quantum signature over (message || frost_signature)
    let pq_signature = pq_sign(pq_signing_key, &msg, &frost_signature);

    Ok(Token {
        header: TokenHeader {
            version: 1,
            algorithm: 1,
            tier: claims.tier,
        },
        claims,
        ratchet_tag,
        frost_signature,
        pq_signature,
    })
}

/// Build a threshold-signed token with encrypted claims for wire transmission.
///
/// The signing is performed over plaintext claims (for verifier-side decryption
/// and verification), but the final token has claims encrypted so they are
/// never plaintext on the wire.
pub fn build_encrypted_token_distributed(
    claims: &TokenClaims,
    coordinator: &SigningCoordinator,
    signers: &mut [&mut SignerNode],
    ratchet_key: &[u8; 64],
    pq_signing_key: &PqSigningKey,
    audience: Option<String>,
    claims_dek: &[u8; 32],
) -> Result<EncryptedToken, MilnetError> {
    let token = build_token_distributed(
        claims,
        coordinator,
        signers,
        ratchet_key,
        pq_signing_key,
        audience,
    )?;
    jwe::encrypt_token(token, claims_dek).map_err(MilnetError::CryptoVerification)
}
