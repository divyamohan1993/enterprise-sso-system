//! Offline / air-gap JWT validation (J9).
//!
//! Validates JWS-style tokens against a pinned trust store and a pre-fetched
//! revocation list, with a CRDT-style replay cache that can be merged
//! across disconnected SCIF nodes.
//!
//! SECURITY (RFC 8725, JSON Web Token Best Current Practices):
//! - §3.1 — `alg` is allowlisted and bound to the pinned key's algorithm;
//!   `none` and any unknown/casing-variant algorithm are rejected at parse
//!   time, before any verifier closure runs.
//! - §3.1/§3.2 — `iss`, `aud` and `nbf`/`exp` are validated against an
//!   explicit [`Policy`]; a token minted for another RP/issuer is rejected
//!   even when it carries a pinned `kid`.
//! - §3.5–3.7 — embedded-key header fields (`jwk`, `jku`, `x5u`, `x5c`) are
//!   rejected via `deny_unknown_fields` on the JOSE header.
//! - CRL freshness is enforced: an expired pre-fetched revocation list is a
//!   hard failure (an air-gap validator cannot refresh it).
//! - Attacker-controlled input is length-capped before decode/parse.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use thiserror::Error;

/// Maximum accepted raw token length (bytes). A JWS for this system is a few
/// hundred bytes; 8 KiB is generous headroom and caps allocation/CPU on a
/// hostile multi-megabyte token before any decode runs.
pub const MAX_TOKEN_LEN: usize = 8 * 1024;
/// Maximum accepted decoded header or payload length (bytes).
pub const MAX_SEGMENT_LEN: usize = 4 * 1024;

#[derive(Debug, Error)]
pub enum OfflineError {
    #[error("malformed token")]
    Malformed,
    #[error("token too large")]
    TooLarge,
    #[error("unknown kid")]
    UnknownKid,
    #[error("algorithm not allowed")]
    AlgNotAllowed,
    #[error("algorithm mismatch with pinned key")]
    AlgMismatch,
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("revoked")]
    Revoked,
    #[error("stale revocation list")]
    StaleRevocation,
    #[error("replayed")]
    Replayed,
    #[error("expired")]
    Expired,
    #[error("not yet valid")]
    NotYetValid,
    #[error("issuer not accepted")]
    IssuerRejected,
    #[error("audience not accepted")]
    AudienceRejected,
    #[error("internal error")]
    Internal,
}

/// Algorithms this offline validator is willing to accept.
///
/// `none` is deliberately absent and unrepresentable: a JOSE header with
/// `alg: "none"` (in any casing) fails [`Algorithm::parse`]. This is the
/// RFC 8725 §3.1 / §2.1 mitigation against the unsigned-token attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rs256,
    Ps256,
    /// ML-DSA-87 — quantum-safe signature, project default for new tokens.
    MlDsa87,
}

impl Algorithm {
    /// Parse a JOSE `alg` value into a known, allowlisted algorithm.
    ///
    /// Case-insensitive on the canonical name so `EdDSA`/`eddsa` casing
    /// bugs cannot smuggle a different algorithm through; `none` and any
    /// unrecognised value are rejected.
    pub fn parse(s: &str) -> Result<Self, OfflineError> {
        // `none` (any casing) and every unrecognised value fall through to
        // the catch-all `Err` — there is deliberately no `Algorithm` variant
        // that represents an unsigned token.
        match s.trim().to_ascii_uppercase().as_str() {
            "ED25519" | "EDDSA" => Ok(Self::Ed25519),
            "ES256" => Ok(Self::EcdsaP256),
            "ES384" => Ok(Self::EcdsaP384),
            "RS256" => Ok(Self::Rs256),
            "PS256" => Ok(Self::Ps256),
            "ML-DSA-87" | "MLDSA87" => Ok(Self::MlDsa87),
            _ => Err(OfflineError::AlgNotAllowed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedKey {
    pub kid: String,
    /// Algorithm this key is pinned to. A token presenting this `kid` with
    /// any other `alg` is rejected (`OfflineError::AlgMismatch`).
    pub algorithm: Algorithm,
    pub public_key_der: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct PinnedTrustStore {
    keys: BTreeMap<String, PinnedKey>,
}

impl PinnedTrustStore {
    pub fn new() -> Self { Self::default() }
    pub fn pin(&mut self, k: PinnedKey) { self.keys.insert(k.kid.clone(), k); }
    pub fn get(&self, kid: &str) -> Option<&PinnedKey> { self.keys.get(kid) }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct RevocationList {
    pub revoked_jtis: BTreeSet<String>,
    pub issued_at: i64,
    pub valid_until: i64,
}

/// CRDT replay cache — append-only set of consumed JTIs, mergeable across nodes.
#[derive(Debug, Default)]
pub struct ReplayCache {
    inner: Mutex<BTreeSet<String>>,
}

impl ReplayCache {
    pub fn new() -> Self { Self::default() }

    /// Try to consume a JTI. `Ok(true)` if newly consumed, `Ok(false)` if it
    /// was already present (a replay). `Err` only on a poisoned lock — kept
    /// distinct so a real internal fault is not masked as a replay event.
    pub fn try_consume(&self, jti: &str) -> Result<bool, OfflineError> {
        let mut g = self.inner.lock().map_err(|_| OfflineError::Internal)?;
        Ok(g.insert(jti.to_string()))
    }

    /// Merge consumed JTIs from a peer node. Errors on a poisoned lock so a
    /// CRDT divergence is surfaced rather than silently dropped.
    pub fn merge(&self, other: &BTreeSet<String>) -> Result<(), OfflineError> {
        let mut g = self.inner.lock().map_err(|_| OfflineError::Internal)?;
        for k in other { g.insert(k.clone()); }
        Ok(())
    }

    pub fn snapshot(&self) -> BTreeSet<String> {
        self.inner.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

/// JOSE header. `deny_unknown_fields` rejects key-injection vectors
/// (`jwk`, `jku`, `x5u`, `x5c` — RFC 8725 §3.5–3.7) at parse time.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwsHeader {
    pub alg: String,
    pub kid: String,
    #[serde(default)]
    pub typ: Option<String>,
}

/// `aud` may be a single string or an array of strings (RFC 7519 §4.1.3).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn accepts(&self, expected: &str) -> bool {
        match self {
            Audience::One(a) => a == expected,
            Audience::Many(v) => v.iter().any(|a| a == expected),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CommonClaims {
    pub jti: String,
    pub iss: String,
    pub aud: Audience,
    pub exp: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
}

/// Validation policy. An offline validator MUST bind tokens to an expected
/// issuer and audience (RFC 8725 §3.1/§3.2) and to an algorithm allowlist.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Issuer the token MUST declare.
    pub expected_iss: String,
    /// Audience this validator answers for; the token's `aud` MUST contain it.
    pub expected_aud: String,
    /// Algorithms accepted in addition to the pinned-key binding. A token's
    /// `alg` must be in this set AND equal the pinned key's algorithm.
    pub allowed_algs: Vec<Algorithm>,
}

impl Policy {
    /// Convenience constructor with the project-default allowlist
    /// (Ed25519 + ML-DSA-87 — quantum-safe-first, plus EdDSA for legacy RPs).
    pub fn new(expected_iss: impl Into<String>, expected_aud: impl Into<String>) -> Self {
        Self {
            expected_iss: expected_iss.into(),
            expected_aud: expected_aud.into(),
            allowed_algs: vec![Algorithm::Ed25519, Algorithm::MlDsa87],
        }
    }
}

pub fn split(token: &str) -> Result<(JwsHeader, Vec<u8>, Vec<u8>, Vec<u8>), OfflineError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(OfflineError::TooLarge);
    }
    let mut it = token.split('.');
    let h = it.next().ok_or(OfflineError::Malformed)?;
    let p = it.next().ok_or(OfflineError::Malformed)?;
    let s = it.next().ok_or(OfflineError::Malformed)?;
    if it.next().is_some() { return Err(OfflineError::Malformed); }
    let hb = URL_SAFE_NO_PAD.decode(h).map_err(|_| OfflineError::Malformed)?;
    let pb = URL_SAFE_NO_PAD.decode(p).map_err(|_| OfflineError::Malformed)?;
    let sb = URL_SAFE_NO_PAD.decode(s).map_err(|_| OfflineError::Malformed)?;
    if hb.len() > MAX_SEGMENT_LEN || pb.len() > MAX_SEGMENT_LEN {
        return Err(OfflineError::TooLarge);
    }
    let header: JwsHeader = serde_json::from_slice(&hb).map_err(|_| OfflineError::Malformed)?;
    Ok((header, pb, sb, format!("{}.{}", h, p).into_bytes()))
}

/// Validate a token against the pinned trust store, revocation list and
/// replay cache, under an explicit [`Policy`].
///
/// Signature verification is delegated to a closure so the crate stays
/// crypto-implementation-agnostic, but the *algorithm* is no longer the
/// closure's responsibility: `validate` rejects `none`, enforces the
/// allowlist, and binds `header.alg` to the pinned key's algorithm before
/// the closure is ever invoked.
pub fn validate<V>(
    token: &str,
    store: &PinnedTrustStore,
    crl: &RevocationList,
    cache: &ReplayCache,
    policy: &Policy,
    now: i64,
    verify: V,
) -> Result<CommonClaims, OfflineError>
where
    V: FnOnce(&PinnedKey, &[u8], &[u8]) -> bool,
{
    // CRL freshness: an air-gap validator runs on a pre-fetched list; if it
    // has expired, revoked tokens would silently pass — fail closed.
    if now >= crl.valid_until {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            "offline-jwt: stale revocation list rejected");
        return Err(OfflineError::StaleRevocation);
    }

    let (header, payload, sig, signing_input) = split(token).map_err(|e| {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            error = %e, "offline-jwt: malformed token rejected");
        e
    })?;

    // RFC 8725 §3.1: reject `none`/unknown alg and enforce the allowlist
    // BEFORE looking at the key or running the verifier.
    let token_alg = Algorithm::parse(&header.alg).map_err(|e| {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            alg = %header.alg, "offline-jwt: algorithm rejected (none/unknown)");
        e
    })?;
    if !policy.allowed_algs.contains(&token_alg) {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            alg = ?token_alg, "offline-jwt: algorithm not in policy allowlist");
        return Err(OfflineError::AlgNotAllowed);
    }

    let key = store.get(&header.kid).ok_or_else(|| {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            kid = %header.kid, "offline-jwt: unknown kid");
        OfflineError::UnknownKid
    })?;

    // Alg-confusion (RFC 8725 §3.1): the token's algorithm MUST equal the
    // algorithm the key was pinned with. This blocks e.g. HS256 presented
    // over an RS-pinned kid.
    if token_alg != key.algorithm {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            kid = %header.kid, token_alg = ?token_alg, pinned_alg = ?key.algorithm,
            "offline-jwt: alg-confusion — header alg does not match pinned key");
        return Err(OfflineError::AlgMismatch);
    }

    if !verify(key, &signing_input, &sig) {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            kid = %header.kid, "offline-jwt: signature invalid");
        return Err(OfflineError::SignatureInvalid);
    }

    let claims: CommonClaims = serde_json::from_slice(&payload).map_err(|_| {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            "offline-jwt: malformed claims payload");
        OfflineError::Malformed
    })?;

    // Temporal validity: nbf <= now < exp.
    if claims.exp <= now {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            "offline-jwt: expired token rejected");
        return Err(OfflineError::Expired);
    }
    if let Some(nbf) = claims.nbf {
        if now < nbf {
            tracing::warn!(target: "siem", file = file!(), line = line!(),
                "offline-jwt: not-yet-valid token rejected");
            return Err(OfflineError::NotYetValid);
        }
    }

    // RFC 8725 §3.1/§3.2: issuer and audience binding.
    if claims.iss != policy.expected_iss {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            "offline-jwt: issuer rejected");
        return Err(OfflineError::IssuerRejected);
    }
    if !claims.aud.accepts(&policy.expected_aud) {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            "offline-jwt: audience rejected");
        return Err(OfflineError::AudienceRejected);
    }

    if crl.revoked_jtis.contains(&claims.jti) {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            "offline-jwt: revoked jti rejected");
        return Err(OfflineError::Revoked);
    }

    // Replay consumption is the last side effect — only a token that has
    // passed every other check is recorded as consumed.
    if !cache.try_consume(&claims.jti)? {
        tracing::warn!(target: "siem", file = file!(), line = line!(),
            "offline-jwt: replayed jti rejected");
        return Err(OfflineError::Replayed);
    }

    tracing::info!(target: "siem", file = file!(), line = line!(),
        kid = %header.kid, alg = ?token_alg, "offline-jwt: token validated");
    Ok(claims)
}
