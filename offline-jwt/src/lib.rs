//! Offline / air-gap JWT validation (J9).
//!
//! Validates JWS-style tokens against a pinned trust store and a pre-fetched
//! revocation list, with a CRDT-style replay cache that can be merged
//! across disconnected SCIF nodes.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OfflineError {
    #[error("malformed token")]
    Malformed,
    #[error("unknown kid")]
    UnknownKid,
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("revoked")]
    Revoked,
    #[error("replayed")]
    Replayed,
    #[error("expired")]
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedKey {
    pub kid: String,
    pub algorithm: String,
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
    pub fn try_consume(&self, jti: &str) -> bool {
        let mut g = match self.inner.lock() { Ok(g) => g, Err(_) => return false };
        g.insert(jti.to_string())
    }
    pub fn merge(&self, other: &BTreeSet<String>) {
        if let Ok(mut g) = self.inner.lock() {
            for k in other { g.insert(k.clone()); }
        }
    }
    pub fn snapshot(&self) -> BTreeSet<String> {
        self.inner.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

#[derive(Debug, Deserialize)]
pub struct JwsHeader {
    pub alg: String,
    pub kid: String,
}

#[derive(Debug, Deserialize)]
pub struct CommonClaims {
    pub jti: String,
    pub exp: i64,
}

pub fn split(token: &str) -> Result<(JwsHeader, Vec<u8>, Vec<u8>, Vec<u8>), OfflineError> {
    let mut it = token.split('.');
    let h = it.next().ok_or(OfflineError::Malformed)?;
    let p = it.next().ok_or(OfflineError::Malformed)?;
    let s = it.next().ok_or(OfflineError::Malformed)?;
    if it.next().is_some() { return Err(OfflineError::Malformed); }
    let hb = URL_SAFE_NO_PAD.decode(h).map_err(|_| OfflineError::Malformed)?;
    let pb = URL_SAFE_NO_PAD.decode(p).map_err(|_| OfflineError::Malformed)?;
    let sb = URL_SAFE_NO_PAD.decode(s).map_err(|_| OfflineError::Malformed)?;
    let header: JwsHeader = serde_json::from_slice(&hb).map_err(|_| OfflineError::Malformed)?;
    Ok((header, pb, sb, format!("{}.{}", h, p).into_bytes()))
}

/// Validate a token against the pinned trust store, revocation list and replay cache.
/// Signature verification is delegated to a closure so the crate stays algorithm-agnostic.
pub fn validate<V>(
    token: &str,
    store: &PinnedTrustStore,
    crl: &RevocationList,
    cache: &ReplayCache,
    now: i64,
    verify: V,
) -> Result<CommonClaims, OfflineError>
where
    V: FnOnce(&PinnedKey, &[u8], &[u8]) -> bool,
{
    let (header, payload, sig, signing_input) = split(token)?;
    let key = store.get(&header.kid).ok_or(OfflineError::UnknownKid)?;
    if !verify(key, &signing_input, &sig) {
        return Err(OfflineError::SignatureInvalid);
    }
    let claims: CommonClaims = serde_json::from_slice(&payload).map_err(|_| OfflineError::Malformed)?;
    if claims.exp <= now { return Err(OfflineError::Expired); }
    if crl.revoked_jtis.contains(&claims.jti) { return Err(OfflineError::Revoked); }
    if !cache.try_consume(&claims.jti) { return Err(OfflineError::Replayed); }
    Ok(claims)
}
