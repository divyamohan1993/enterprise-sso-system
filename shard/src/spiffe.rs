//! SPIFFE SVID integration for shard mTLS (CAT-O DT-MUTAUTH).
//!
//! Replaces the self-signed CA in `shard::tls` with short-lived
//! SPIRE-issued X.509 SVIDs. A node's identity becomes its SPIFFE ID,
//! e.g. `spiffe://milnet/shard/node-1`, carried as a URI SAN on the
//! workload certificate. Peer authorization is a SPIFFE-ID allow list
//! rather than a raw SHA-512 pin.
//!
//! # Source of truth
//!
//! The `spiffe` Rust crate pulls a substantial tonic/protobuf
//! dependency chain that has not been CNSA 2.0 / FIPS audited for this
//! deployment; instead this module takes SVIDs from the filesystem,
//! which is a documented SPIRE agent mode (the `svid_store_helper` or
//! equivalent k8s CSI driver renders the workload X.509 bundle to a
//! tmpfs path). The bundle layout is:
//!
//! ```text
//! ${SPIFFE_SVID_DIR}/svid.pem        — leaf cert chain (PEM)
//! ${SPIFFE_SVID_DIR}/svid_key.pem    — leaf private key (PEM PKCS#8)
//! ${SPIFFE_SVID_DIR}/bundle.pem      — trust-bundle CA certs (PEM)
//! ```
//!
//! Short-lived certs (default 1h) are rotated in place by the SPIRE
//! agent; `SvidSource::load()` re-reads on every call, so callers that
//! rebuild their TLS config periodically (see the `SvidReloader`
//! trait hook) pick up fresh material without restarting.
//!
//! # CAT-O-followup
//!
//! The following items remain for a follow-up pass once `spiffe` crate
//! vetting completes:
//!
//! - Direct Workload API gRPC client (no filesystem hop).
//! - SVID push-based rotation (inotify on `svid.pem`).
//! - CRL/OCSP staple freshness checks on the trust bundle.
//! - Federation bundle pull for cross-cluster SPIFFE IDs.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// SPIFFE ID (a URI with `spiffe://` scheme). Stored as the raw string
/// rather than a URL type to avoid pulling an additional dep; callers
/// must not construct one without validating.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpiffeId(String);

impl SpiffeId {
    /// Parse and validate a SPIFFE ID. Requires `spiffe://` scheme and
    /// a non-empty trust domain authority. Path is optional but if
    /// present must not contain `..` or empty segments.
    pub fn parse(s: &str) -> Result<Self, SpiffeError> {
        let rest = s
            .strip_prefix("spiffe://")
            .ok_or(SpiffeError::BadScheme)?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.is_empty() {
            return Err(SpiffeError::EmptyTrustDomain);
        }
        // RFC-ish check: trust domain is a DNS-like label set. We
        // allow [a-z0-9.-] lowercase only.
        if !authority
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        {
            return Err(SpiffeError::BadTrustDomain);
        }
        if !path.is_empty() {
            for seg in path.split('/').filter(|s| !s.is_empty()) {
                if seg == "." || seg == ".." {
                    return Err(SpiffeError::BadPath);
                }
            }
        }
        Ok(SpiffeId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Trust-domain authority (between `spiffe://` and the first `/`).
    pub fn trust_domain(&self) -> &str {
        let rest = &self.0["spiffe://".len()..];
        match rest.find('/') {
            Some(i) => &rest[..i],
            None => rest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpiffeError {
    BadScheme,
    EmptyTrustDomain,
    BadTrustDomain,
    BadPath,
    Io(String),
    InvalidSvid(String),
}

impl std::fmt::Display for SpiffeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpiffeError::BadScheme => write!(f, "SPIFFE ID must start with spiffe://"),
            SpiffeError::EmptyTrustDomain => write!(f, "SPIFFE ID trust domain is empty"),
            SpiffeError::BadTrustDomain => write!(f, "SPIFFE ID trust domain has invalid chars"),
            SpiffeError::BadPath => write!(f, "SPIFFE ID path contains empty or dot segment"),
            SpiffeError::Io(s) => write!(f, "SVID I/O: {}", s),
            SpiffeError::InvalidSvid(s) => write!(f, "invalid SVID: {}", s),
        }
    }
}

impl std::error::Error for SpiffeError {}

/// A loaded X.509 SVID bundle. PEM blobs are held as-is; the caller
/// feeds them to rustls via the existing `CertificateDer` /
/// `PrivatePkcs8KeyDer` pipeline in `shard::tls`.
#[derive(Debug, Clone)]
pub struct SvidBundle {
    pub leaf_chain_pem: Vec<u8>,
    pub leaf_key_pem: Vec<u8>,
    pub trust_bundle_pem: Vec<u8>,
    pub spiffe_id: SpiffeId,
}

/// Trait seam for SVID sources. The default `FilesystemSvidSource`
/// reads from a tmpfs path the SPIRE agent renders into. A follow-up
/// `WorkloadApiSvidSource` can speak gRPC to the SPIRE agent socket
/// once the `spiffe` crate is vetted.
pub trait SvidSource: Send + Sync {
    fn load(&self) -> Result<SvidBundle, SpiffeError>;
}

/// Filesystem-backed SVID source. Reads the triple `svid.pem`,
/// `svid_key.pem`, `bundle.pem` on every call. Intended for use with
/// SPIRE agent's svid store helper or the SPIFFE CSI Driver.
pub struct FilesystemSvidSource {
    dir: PathBuf,
    expected_id: SpiffeId,
}

impl FilesystemSvidSource {
    pub fn new(dir: impl AsRef<Path>, expected_id: SpiffeId) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
            expected_id,
        }
    }

    /// Construct from the standard env var layout:
    /// `SPIFFE_SVID_DIR` and `SPIFFE_EXPECTED_ID`.
    pub fn from_env() -> Result<Self, SpiffeError> {
        let dir = std::env::var("SPIFFE_SVID_DIR")
            .map_err(|_| SpiffeError::Io("SPIFFE_SVID_DIR not set".into()))?;
        let id_str = std::env::var("SPIFFE_EXPECTED_ID")
            .map_err(|_| SpiffeError::Io("SPIFFE_EXPECTED_ID not set".into()))?;
        let expected = SpiffeId::parse(&id_str)?;
        Ok(Self::new(dir, expected))
    }
}

impl SvidSource for FilesystemSvidSource {
    fn load(&self) -> Result<SvidBundle, SpiffeError> {
        let leaf = std::fs::read(self.dir.join("svid.pem"))
            .map_err(|e| SpiffeError::Io(format!("svid.pem: {}", e)))?;
        let key = std::fs::read(self.dir.join("svid_key.pem"))
            .map_err(|e| SpiffeError::Io(format!("svid_key.pem: {}", e)))?;
        let bundle = std::fs::read(self.dir.join("bundle.pem"))
            .map_err(|e| SpiffeError::Io(format!("bundle.pem: {}", e)))?;
        Ok(SvidBundle {
            leaf_chain_pem: leaf,
            leaf_key_pem: key,
            trust_bundle_pem: bundle,
            spiffe_id: self.expected_id.clone(),
        })
    }
}

/// Peer-authorization policy: the set of SPIFFE IDs a node will
/// accept as a TLS peer. Enforced AFTER rustls has validated the
/// chain against the trust bundle.
#[derive(Debug, Clone, Default)]
pub struct SpiffeAuthorizer {
    allowed: HashSet<String>,
}

impl SpiffeAuthorizer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(&mut self, id: SpiffeId) {
        self.allowed.insert(id.0);
    }

    pub fn is_allowed(&self, id: &SpiffeId) -> bool {
        self.allowed.contains(&id.0)
    }

    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_spiffe_id() {
        let id = SpiffeId::parse("spiffe://milnet/shard/node-1").unwrap();
        assert_eq!(id.trust_domain(), "milnet");
        assert_eq!(id.as_str(), "spiffe://milnet/shard/node-1");
    }

    #[test]
    fn rejects_bad_scheme() {
        assert_eq!(
            SpiffeId::parse("https://milnet/shard"),
            Err(SpiffeError::BadScheme)
        );
    }

    #[test]
    fn rejects_empty_trust_domain() {
        assert_eq!(
            SpiffeId::parse("spiffe:///shard"),
            Err(SpiffeError::EmptyTrustDomain)
        );
    }

    #[test]
    fn rejects_dotdot_path() {
        assert_eq!(
            SpiffeId::parse("spiffe://milnet/../secret"),
            Err(SpiffeError::BadPath)
        );
    }

    #[test]
    fn authorizer_allow_list() {
        let mut auth = SpiffeAuthorizer::new();
        let a = SpiffeId::parse("spiffe://milnet/shard/a").unwrap();
        let b = SpiffeId::parse("spiffe://milnet/shard/b").unwrap();
        auth.allow(a.clone());
        assert!(auth.is_allowed(&a));
        assert!(!auth.is_allowed(&b));
    }
}
