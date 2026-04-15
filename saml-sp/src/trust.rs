//! IdP trust anchor abstraction.
//!
//! The SP NEVER takes the public key from `<KeyInfo>` at face value. Instead,
//! `<Issuer>` is looked up against an allowlist that maps issuer URI to a
//! pinned RSA or ECDSA public key, identified by SHA-512 fingerprint of the
//! DER-encoded SubjectPublicKeyInfo. The certificate inside `<KeyInfo>` is
//! only accepted if its fingerprint matches the pin exactly.

use crate::SamlError;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

/// A pinned IdP public key.
#[derive(Debug, Clone)]
pub struct PinnedKey {
    /// DER-encoded SubjectPublicKeyInfo.
    pub spki_der: Vec<u8>,
    /// SHA-512 fingerprint of `spki_der`. 64 bytes.
    pub spki_sha512: [u8; 64],
    /// Algorithm hint for the verifier.
    pub alg: KeyAlg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlg {
    Rsa,
    EcdsaP256,
    MlDsa87,
}

impl PinnedKey {
    pub fn new(spki_der: Vec<u8>, alg: KeyAlg) -> Self {
        let mut h = Sha512::new();
        h.update(&spki_der);
        let mut fp = [0u8; 64];
        fp.copy_from_slice(&h.finalize());
        Self { spki_der, spki_sha512: fp, alg }
    }
}

/// Trust anchor lookup. Production deployments back this with a config file
/// reloaded on SIGHUP — tests use `StaticTrust`.
pub trait TrustAnchor: Send + Sync {
    fn resolve(&self, issuer: &str) -> Result<&PinnedKey, SamlError>;
}

#[derive(Debug, Default)]
pub struct StaticTrust {
    map: HashMap<String, PinnedKey>,
}

impl StaticTrust {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }
    pub fn insert(&mut self, issuer: impl Into<String>, key: PinnedKey) {
        self.map.insert(issuer.into(), key);
    }
}

impl TrustAnchor for StaticTrust {
    fn resolve(&self, issuer: &str) -> Result<&PinnedKey, SamlError> {
        self.map.get(issuer).ok_or(SamlError::UnknownIssuer)
    }
}

/// Constant-time SHA-512 fingerprint comparison.
pub fn fingerprint_eq(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a.ct_eq(b).into()
}
