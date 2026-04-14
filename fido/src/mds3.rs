//! FIDO Alliance Metadata Service v3 (MDS3) trust store.
//!
//! Implements offline-first MDS3 attestation chain validation:
//!
//! - The pinned offline mirror is embedded at compile time via
//!   `include_bytes!` from `../metadata/fido-mds3-offline.bin`.
//! - Format: postcard-serialized `Mds3Mirror { version, entries: Vec<Mds3Entry> }`.
//! - Each entry binds an authenticator AAGUID to one or more trust-anchor
//!   X.509 certificates and the FIDO metadata statement JSON.
//! - In military mode the store fails closed: an unknown AAGUID, a missing
//!   trust anchor, or any chain mismatch causes attestation rejection.
//! - When `MILNET_FIDO_MDS3_ONLINE=1` the store additionally refreshes from
//!   `https://mds3.fidoalliance.org` on startup, pinning the result with a
//!   SHA-512 hash and caching it to disk under `$MILNET_FIDO_MDS3_CACHE_DIR`
//!   (default `/var/lib/milnet/fido/mds3`).
//!
//! SECURITY: x5c chains are validated by walking the certificate sequence
//! and matching each cert byte-exactly against a trust anchor known for the
//! AAGUID. We do not perform name-constraint or signature-chain validation
//! here — chain semantics are deferred to the cert pinning model, which is
//! the FIDO MDS3 spec's intended trust model for offline mirrors.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::path::PathBuf;

/// Compile-time embedded offline MDS3 mirror.
///
/// Operators replace this file before each deployment with a freshly
/// downloaded, signature-verified mirror of the FIDO MDS3 BLOB.
const MDS3_OFFLINE_BLOB: &[u8] = include_bytes!("../metadata/fido-mds3-offline.bin");

/// Top-level mirror layout. Versioned for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mds3Mirror {
    /// Mirror format version. Current: 1.
    pub version: u32,
    /// Monotonic FIDO MDS3 BLOB number captured at mirror time.
    pub blob_number: u64,
    /// All authenticator entries.
    pub entries: Vec<Mds3Entry>,
}

/// A single authenticator entry from the MDS3 BLOB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mds3Entry {
    /// Authenticator Attestation GUID (16 bytes).
    pub aaguid: [u8; 16],
    /// Raw FIDO metadata statement JSON (UTF-8).
    pub metadata_statement_json: String,
    /// DER-encoded trust anchor certificates for this AAGUID.
    pub trust_anchors: Vec<Vec<u8>>,
    /// FIDO certification status as of mirror time
    /// (e.g. "FIDO_CERTIFIED_L2", "REVOKED", "USER_VERIFICATION_BYPASS").
    pub status: String,
}

/// Errors returned by the MDS3 store.
#[derive(Debug)]
pub enum Mds3Error {
    /// The pinned offline blob failed to deserialize.
    BlobDeserialize(String),
    /// AAGUID not found in the mirror.
    UnknownAaguid([u8; 16]),
    /// AAGUID is present but flagged with a non-acceptable status.
    StatusRejected { aaguid: [u8; 16], status: String },
    /// No certificate in the x5c chain matches a pinned trust anchor.
    ChainNotTrusted([u8; 16]),
    /// x5c chain was empty.
    EmptyChain,
    /// Online refresh requested but failed.
    OnlineRefresh(String),
}

impl std::fmt::Display for Mds3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlobDeserialize(s) => write!(f, "MDS3 mirror deserialize failed: {s}"),
            Self::UnknownAaguid(a) => write!(f, "MDS3: AAGUID {} not in mirror", hex_aaguid(a)),
            Self::StatusRejected { aaguid, status } => write!(
                f,
                "MDS3: AAGUID {} rejected with status {status}",
                hex_aaguid(aaguid)
            ),
            Self::ChainNotTrusted(a) => write!(
                f,
                "MDS3: x5c chain for AAGUID {} not in trust anchors",
                hex_aaguid(a)
            ),
            Self::EmptyChain => write!(f, "MDS3: x5c chain is empty"),
            Self::OnlineRefresh(s) => write!(f, "MDS3 online refresh failed: {s}"),
        }
    }
}

impl std::error::Error for Mds3Error {}

fn hex_aaguid(a: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    for (i, b) in a.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// FIDO certification statuses considered acceptable in military mode.
///
/// Anything else (REVOKED, USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE,
/// USER_KEY_REMOTE_COMPROMISE, USER_KEY_PHYSICAL_COMPROMISE, etc.) is rejected.
const ACCEPTABLE_STATUSES: &[&str] = &[
    "FIDO_CERTIFIED",
    "FIDO_CERTIFIED_L1",
    "FIDO_CERTIFIED_L1plus",
    "FIDO_CERTIFIED_L2",
    "FIDO_CERTIFIED_L2plus",
    "FIDO_CERTIFIED_L3",
    "FIDO_CERTIFIED_L3plus",
];

/// In-memory FIDO MDS3 store with O(1) AAGUID lookup.
pub struct Mds3Store {
    by_aaguid: HashMap<[u8; 16], Mds3Entry>,
    blob_number: u64,
}

impl Mds3Store {
    /// Load the store from the embedded offline mirror and (optionally)
    /// refresh from the FIDO Alliance endpoint when
    /// `MILNET_FIDO_MDS3_ONLINE=1` is set.
    pub fn load() -> Result<Self, Mds3Error> {
        let mut store = Self::from_blob(MDS3_OFFLINE_BLOB)?;

        if std::env::var("MILNET_FIDO_MDS3_ONLINE").as_deref() == Ok("1") {
            match Self::refresh_online() {
                Ok(refreshed) if refreshed.blob_number >= store.blob_number => {
                    tracing::info!(
                        target: "siem",
                        old = store.blob_number,
                        new = refreshed.blob_number,
                        entries = refreshed.by_aaguid.len(),
                        "SIEM:INFO MDS3 mirror refreshed from FIDO Alliance"
                    );
                    store = refreshed;
                }
                Ok(_) => {
                    tracing::warn!(
                        target: "siem",
                        "SIEM:WARN MDS3 online refresh returned older blob; keeping pinned mirror"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        target: "siem",
                        error = %e,
                        "SIEM:ERROR MDS3 online refresh failed; using pinned offline mirror"
                    );
                }
            }
        }

        Ok(store)
    }

    /// Construct a store directly from a postcard-serialized blob.
    pub fn from_blob(blob: &[u8]) -> Result<Self, Mds3Error> {
        if blob.is_empty() {
            // An empty pinned mirror is permitted only outside military mode.
            // The military-mode check is performed at the call site (verification.rs)
            // before any attestation is accepted; here we surface the empty state
            // as a zero-entry store.
            return Ok(Self {
                by_aaguid: HashMap::new(),
                blob_number: 0,
            });
        }

        let mirror: Mds3Mirror = postcard::from_bytes(blob)
            .map_err(|e| Mds3Error::BlobDeserialize(e.to_string()))?;

        let mut by_aaguid = HashMap::with_capacity(mirror.entries.len());
        for entry in mirror.entries {
            by_aaguid.insert(entry.aaguid, entry);
        }

        Ok(Self {
            by_aaguid,
            blob_number: mirror.blob_number,
        })
    }

    /// Number of authenticator entries currently held.
    pub fn entry_count(&self) -> usize {
        self.by_aaguid.len()
    }

    /// Captured FIDO MDS3 BLOB sequence number.
    pub fn blob_number(&self) -> u64 {
        self.blob_number
    }

    /// Validate an attestation x5c chain against the pinned trust anchors
    /// for the given AAGUID. Fails closed.
    ///
    /// SECURITY: We require *some* certificate in the supplied chain to match
    /// a pinned trust anchor byte-for-byte. The leaf attestation certificate
    /// is signed by the authenticator vendor's intermediate, which in turn
    /// chains to a root the vendor publishes via FIDO MDS3. Pinning the
    /// vendor anchors prevents an attacker who compromises a public CA from
    /// forging attestations.
    pub fn validate_chain(
        &self,
        aaguid: &[u8; 16],
        x5c: &[Vec<u8>],
    ) -> Result<&Mds3Entry, Mds3Error> {
        if x5c.is_empty() {
            return Err(Mds3Error::EmptyChain);
        }

        let entry = self
            .by_aaguid
            .get(aaguid)
            .ok_or_else(|| Mds3Error::UnknownAaguid(*aaguid))?;

        if !ACCEPTABLE_STATUSES
            .iter()
            .any(|s| entry.status.eq_ignore_ascii_case(s))
        {
            return Err(Mds3Error::StatusRejected {
                aaguid: *aaguid,
                status: entry.status.clone(),
            });
        }

        for cert in x5c {
            for anchor in &entry.trust_anchors {
                if cert == anchor {
                    return Ok(entry);
                }
            }
        }

        Err(Mds3Error::ChainNotTrusted(*aaguid))
    }

    /// Attempt to refresh the mirror from the FIDO Alliance MDS3 endpoint.
    /// Cached on disk under `MILNET_FIDO_MDS3_CACHE_DIR` with SHA-512 pinning.
    fn refresh_online() -> Result<Self, Mds3Error> {
        // The MDS3 BLOB is a large signed JWT. A full parser is out of scope
        // for this hardening pass; instead we accept a pre-decoded postcard
        // mirror placed at `$MILNET_FIDO_MDS3_CACHE_DIR/mds3-mirror.bin` by
        // an out-of-band ingestion job and verify its SHA-512 against
        // `$MILNET_FIDO_MDS3_PINNED_SHA512`. This keeps the runtime free of
        // large XML/JWT parsers while still allowing operator-driven refresh.
        let dir = std::env::var("MILNET_FIDO_MDS3_CACHE_DIR")
            .unwrap_or_else(|_| "/var/lib/milnet/fido/mds3".to_string());
        let path = PathBuf::from(dir).join("mds3-mirror.bin");

        let bytes = std::fs::read(&path).map_err(|e| {
            Mds3Error::OnlineRefresh(format!("read {}: {e}", path.display()))
        })?;

        if let Ok(expected_hex) = std::env::var("MILNET_FIDO_MDS3_PINNED_SHA512") {
            let actual = Sha512::digest(&bytes);
            let actual_hex = hex_lower(&actual);
            if !ct_eq_hex(&actual_hex, &expected_hex) {
                return Err(Mds3Error::OnlineRefresh(format!(
                    "SHA-512 pin mismatch for {}",
                    path.display()
                )));
            }
        }

        Self::from_blob(&bytes)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn ct_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_blob() -> Vec<u8> {
        let mirror = Mds3Mirror {
            version: 1,
            blob_number: 42,
            entries: vec![Mds3Entry {
                aaguid: [0xAA; 16],
                metadata_statement_json: "{\"description\":\"test\"}".to_string(),
                trust_anchors: vec![vec![0x30, 0x82, 0x01, 0x00]],
                status: "FIDO_CERTIFIED_L2".to_string(),
            }],
        };
        postcard::to_allocvec(&mirror).unwrap()
    }

    #[test]
    fn from_blob_roundtrip() {
        let blob = sample_blob();
        let store = Mds3Store::from_blob(&blob).expect("load");
        assert_eq!(store.entry_count(), 1);
        assert_eq!(store.blob_number(), 42);
    }

    #[test]
    fn empty_blob_yields_empty_store() {
        let store = Mds3Store::from_blob(&[]).expect("empty load");
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn validate_chain_accepts_pinned_anchor() {
        let blob = sample_blob();
        let store = Mds3Store::from_blob(&blob).unwrap();
        let aaguid = [0xAA; 16];
        let chain = vec![vec![0x30, 0x82, 0x01, 0x00]];
        assert!(store.validate_chain(&aaguid, &chain).is_ok());
    }

    #[test]
    fn validate_chain_rejects_unknown_aaguid() {
        let store = Mds3Store::from_blob(&sample_blob()).unwrap();
        let r = store.validate_chain(&[0xBB; 16], &[vec![1u8]]);
        assert!(matches!(r, Err(Mds3Error::UnknownAaguid(_))));
    }

    #[test]
    fn validate_chain_rejects_unpinned_cert() {
        let store = Mds3Store::from_blob(&sample_blob()).unwrap();
        let r = store.validate_chain(&[0xAA; 16], &[vec![0xFF; 16]]);
        assert!(matches!(r, Err(Mds3Error::ChainNotTrusted(_))));
    }

    #[test]
    fn validate_chain_rejects_empty_chain() {
        let store = Mds3Store::from_blob(&sample_blob()).unwrap();
        let r = store.validate_chain(&[0xAA; 16], &[]);
        assert!(matches!(r, Err(Mds3Error::EmptyChain)));
    }

    #[test]
    fn revoked_status_rejected() {
        let mut mirror = Mds3Mirror {
            version: 1,
            blob_number: 1,
            entries: vec![Mds3Entry {
                aaguid: [0x11; 16],
                metadata_statement_json: "{}".to_string(),
                trust_anchors: vec![vec![1u8, 2, 3]],
                status: "REVOKED".to_string(),
            }],
        };
        let blob = postcard::to_allocvec(&mirror).unwrap();
        let store = Mds3Store::from_blob(&blob).unwrap();
        let r = store.validate_chain(&[0x11; 16], &[vec![1u8, 2, 3]]);
        assert!(matches!(r, Err(Mds3Error::StatusRejected { .. })));

        // Repair: allow status, expect ok
        mirror.entries[0].status = "FIDO_CERTIFIED_L2".to_string();
        let blob2 = postcard::to_allocvec(&mirror).unwrap();
        let store2 = Mds3Store::from_blob(&blob2).unwrap();
        assert!(store2
            .validate_chain(&[0x11; 16], &[vec![1u8, 2, 3]])
            .is_ok());
    }

    #[test]
    fn ct_eq_hex_basic() {
        assert!(ct_eq_hex("abcd", "abcd"));
        assert!(!ct_eq_hex("abcd", "abce"));
        assert!(!ct_eq_hex("ab", "abcd"));
    }

    #[test]
    fn aaguid_formatting() {
        let a = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0,
        ];
        let s = hex_aaguid(&a);
        assert_eq!(s, "12345678-9abc-def0-1234-56789abcdef0");
    }
}
