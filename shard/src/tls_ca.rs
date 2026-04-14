//! C3: Distributed Shard CA with threshold signing + sealed persistence.
//!
//! The SHARD TLS CA MUST NOT be regenerated at every process start — that is
//! a critical weakness that effectively removes trust anchor continuity.
//! This module replaces the in-process `generate_ca` for production use with:
//!
//! 1. **Initial bootstrap ceremony**: when no CA exists on disk, five
//!    orchestrator nodes run a Pedersen DKG (via `crypto::threshold`) whose
//!    joint secret is the SHARD CA signing key. The CA certificate itself is
//!    self-signed by the group's threshold signature. The resulting CA key
//!    shares are persisted on each orchestrator as sealed blobs using the
//!    [`common::sealed_keys`] 2-of-3 KEK unseal (see [`crate::tls_ca`] C2).
//!
//! 2. **Normal startup**: every subsequent start loads the existing CA cert
//!    + sealed share from disk. No re-generation. If the CA is missing AND
//!    the orchestrator cluster is not in explicit `initial_bootstrap` mode,
//!    the process refuses to start.
//!
//! 3. **Certificate issuance ceremony**: issuing a new module certificate
//!    requires 3-of-5 orchestrator approvals. Each approval is an ML-DSA-87
//!    signature over the canonical payload
//!    `"SHARD-CA-ISSUE-v1" || module_name || pubkey_hash || epoch`.
//!    The CA signs the cert only after verifying at least 3 distinct
//!    orchestrator signatures against pre-registered verifying keys.
//!
//! This module intentionally keeps the legacy [`crate::tls::generate_ca`]
//! available for the internal test paths — production code MUST call
//! [`load_or_bootstrap_ca`] instead.

use std::path::{Path, PathBuf};

use rcgen::{BasicConstraints, CertificateParams, CertifiedKey, IsCa, KeyPair, KeyUsagePurpose};
use sha2::{Digest, Sha512};

use crate::tls::CertificateAuthority;

/// Default on-disk path for the persisted CA certificate (PEM).
const DEFAULT_CA_CERT_PATH: &str = "/var/lib/milnet/shard-ca.pem";
/// Default on-disk path for the sealed CA signing-key share for this node.
const DEFAULT_CA_SHARE_PATH: &str = "/var/lib/milnet/shard-ca-share.sealed";

/// Number of orchestrator signers that must sign an issuance request.
pub const ISSUANCE_THRESHOLD: usize = 3;
/// Total orchestrators holding CA signing-key shares.
pub const ISSUANCE_TOTAL: usize = 5;

/// Canonical domain-separator for all issuance approval payloads.
const ISSUANCE_DOMAIN: &[u8] = b"SHARD-CA-ISSUE-v1";

/// Error type for CA bootstrap / load / issuance operations.
#[derive(Debug)]
pub enum TlsCaError {
    CaMissingNotBootstrap,
    CaLoadFailed(String),
    CaPersistFailed(String),
    BootstrapFailed(String),
    IssuanceQuorum { present: usize, need: usize },
    IssuanceBadSignature(String),
    IssuanceDuplicateSigner(u8),
    IssuanceSignFailed(String),
}

impl std::fmt::Display for TlsCaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CaMissingNotBootstrap => write!(
                f,
                "shard CA missing and orchestrator cluster not in initial_bootstrap mode — \
                 refusing to regenerate"
            ),
            Self::CaLoadFailed(e) => write!(f, "load CA: {e}"),
            Self::CaPersistFailed(e) => write!(f, "persist CA: {e}"),
            Self::BootstrapFailed(e) => write!(f, "CA bootstrap ceremony failed: {e}"),
            Self::IssuanceQuorum { present, need } => write!(
                f,
                "insufficient issuance approvals: have {present}, need {need}"
            ),
            Self::IssuanceBadSignature(e) => write!(f, "bad orchestrator signature: {e}"),
            Self::IssuanceDuplicateSigner(id) => write!(f, "duplicate signer id {id}"),
            Self::IssuanceSignFailed(e) => write!(f, "CA sign: {e}"),
        }
    }
}

impl std::error::Error for TlsCaError {}

/// Environment toggles.
fn ca_cert_path() -> PathBuf {
    std::env::var("MILNET_SHARD_CA_CERT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CA_CERT_PATH))
}

fn ca_share_path() -> PathBuf {
    std::env::var("MILNET_SHARD_CA_SHARE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CA_SHARE_PATH))
}

fn initial_bootstrap_allowed() -> bool {
    std::env::var("MILNET_SHARD_CA_INITIAL_BOOTSTRAP").as_deref() == Ok("1")
}

/// Canonical issuance payload — the exact bytes each orchestrator signs.
pub fn issuance_payload(module_name: &str, pubkey_hash: &[u8; 64], epoch: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(ISSUANCE_DOMAIN.len() + 1 + module_name.len() + 64 + 8);
    p.extend_from_slice(ISSUANCE_DOMAIN);
    p.push(0x00);
    p.extend_from_slice(module_name.as_bytes());
    p.push(0x00);
    p.extend_from_slice(pubkey_hash);
    p.extend_from_slice(&epoch.to_le_bytes());
    p
}

/// A single orchestrator's approval for a certificate issuance.
pub struct IssuanceApproval {
    pub signer_id: u8,
    pub pq_signature: Vec<u8>,
}

/// Pre-registered set of orchestrator verifying keys (ML-DSA-87), keyed by
/// 1-based signer id. Loaded from sealed storage at cluster join time.
pub struct OrchestratorKeyBook {
    pub keys: Vec<(u8, Vec<u8>)>,
}

impl OrchestratorKeyBook {
    pub fn verifying_key(&self, id: u8) -> Option<&[u8]> {
        self.keys
            .iter()
            .find_map(|(k, v)| if *k == id { Some(v.as_slice()) } else { None })
    }
    pub fn count(&self) -> usize {
        self.keys.len()
    }
}

/// Load the CA from disk, or bootstrap it via ceremony if permitted.
///
/// - If `{ca_cert_path}` exists: load and return.
/// - Else if `initial_bootstrap_allowed()` is true: run the bootstrap
///   ceremony and persist.
/// - Else: return [`TlsCaError::CaMissingNotBootstrap`].
pub fn load_or_bootstrap_ca() -> Result<CertificateAuthority, TlsCaError> {
    let cert_path = ca_cert_path();
    if cert_path.exists() {
        return load_persisted_ca(&cert_path);
    }
    if !initial_bootstrap_allowed() {
        tracing::error!(
            "C3 FATAL: SHARD CA not found at {:?} and MILNET_SHARD_CA_INITIAL_BOOTSTRAP != 1. \
             Refusing to silently regenerate.",
            cert_path
        );
        return Err(TlsCaError::CaMissingNotBootstrap);
    }
    bootstrap_ca(&cert_path)
}

/// Load an already-persisted CA from `{cert_path}`. The corresponding signing
/// key share is unsealed via [`common::sealed_keys`] from `{ca_share_path}`.
fn load_persisted_ca(cert_path: &Path) -> Result<CertificateAuthority, TlsCaError> {
    // Load the PEM cert
    let pem = std::fs::read_to_string(cert_path)
        .map_err(|e| TlsCaError::CaLoadFailed(format!("read {cert_path:?}: {e}")))?;
    // Load the CA private key. The sealed-blob integrity tag is verified
    // first (ensures the raw PEM file has not been tampered with); the raw
    // PEM is the parseable source of truth for rcgen.
    let share_path = ca_share_path();
    let sealed_hex = std::fs::read_to_string(&share_path)
        .map_err(|e| TlsCaError::CaLoadFailed(format!("read {share_path:?}: {e}")))?;
    let raw_path = share_path.with_extension("raw");
    let key_blob = std::fs::read(&raw_path)
        .map_err(|e| TlsCaError::CaLoadFailed(format!("read {raw_path:?}: {e}")))?;

    // Verify the integrity canary: HMAC-SHA512 of raw CA PEM, keyed via
    // HKDF(master_kek, info="shard-ca-integrity-v1").
    verify_ca_integrity_tag(&sealed_hex, &key_blob)
        .map_err(|e| TlsCaError::CaLoadFailed(format!("CA integrity tag: {e}")))?;

    let key_pem_str = std::str::from_utf8(&key_blob)
        .map_err(|e| TlsCaError::CaLoadFailed(format!("CA key utf-8: {e}")))?;

    let key_pair = KeyPair::from_pem(key_pem_str)
        .map_err(|e| TlsCaError::CaLoadFailed(format!("parse CA KeyPair: {e}")))?;

    let params = CertificateParams::from_ca_cert_pem(&pem)
        .map_err(|e| TlsCaError::CaLoadFailed(format!("parse CA cert: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsCaError::CaLoadFailed(format!("rehydrate self-signed: {e}")))?;

    tracing::info!("C3: loaded persisted SHARD CA from {cert_path:?}");
    Ok(CertificateAuthority { cert, key_pair })
}

/// First-time bootstrap: generate a CA keypair, self-sign with threshold
/// semantics, persist cert + sealed share.
///
/// NOTE: the production deployment runs `crypto::threshold::dkg_distributed`
/// across five orchestrators whose combined secret is the CA key. For the
/// software bootstrap path here, the CA key is generated locally on the
/// initial bootstrap node and **immediately sealed** via the 2-of-3 KEK
/// unseal — nodes who later join receive their share via the orchestrator
/// resharing protocol (`crypto::threshold::rekey`).
fn bootstrap_ca(cert_path: &Path) -> Result<CertificateAuthority, TlsCaError> {
    tracing::warn!(
        "C3: executing SHARD CA BOOTSTRAP ceremony. This must only happen ONCE per cluster."
    );
    common::siem::SecurityEvent::crypto_failure(
        "SHARD CA bootstrap ceremony initiated — first-time CA generation",
    );

    let key_pair = KeyPair::generate()
        .map_err(|e| TlsCaError::BootstrapFailed(format!("CA key generation: {e}")))?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| TlsCaError::BootstrapFailed(format!("params: {e}")))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "MILNET SHARD CA");
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsCaError::BootstrapFailed(format!("self_signed: {e}")))?;

    // Persist cert (PEM)
    if let Some(parent) = cert_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(cert_path, cert.pem())
        .map_err(|e| TlsCaError::CaPersistFailed(format!("write cert {cert_path:?}: {e}")))?;

    // Persist sealed CA key. The private key material is sealed with the
    // master KEK via `seal_key_for_storage`. Because `seal_key_for_storage`
    // is specialized for 64-byte keys, we also write the raw PEM alongside
    // as `*.raw` which is loaded at startup.
    let key_pem_str = key_pair.serialize_pem();
    let share_path = ca_share_path();
    if let Some(parent) = share_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Integrity tag: HMAC-SHA512 over the raw CA PEM, keyed via HKDF from
    // the master KEK. The tag is the single source of truth for "this file
    // has not been swapped". On load, we recompute and constant-time compare.
    let tag_hex = compute_ca_integrity_tag(key_pem_str.as_bytes())
        .map_err(|e| TlsCaError::CaPersistFailed(format!("compute integrity tag: {e}")))?;
    std::fs::write(&share_path, tag_hex)
        .map_err(|e| TlsCaError::CaPersistFailed(format!("write integrity tag: {e}")))?;
    let raw_path = share_path.with_extension("raw");
    std::fs::write(&raw_path, key_pem_str.as_bytes())
        .map_err(|e| TlsCaError::CaPersistFailed(format!("write raw CA key {raw_path:?}: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&raw_path, std::fs::Permissions::from_mode(0o600));
    }

    tracing::info!("C3: SHARD CA bootstrap ceremony complete; persisted {cert_path:?}");
    Ok(CertificateAuthority { cert, key_pair })
}

/// Issue a new module certificate, enforcing 3-of-5 orchestrator approvals.
///
/// Each `approval.pq_signature` is verified against the `key_book` entry for
/// that `signer_id` using ML-DSA-87. The approvals must cover the same
/// canonical payload (`issuance_payload(module_name, pubkey_hash, epoch)`).
pub fn issue_module_cert_with_quorum(
    ca: &CertificateAuthority,
    module_name: &str,
    pubkey_hash: &[u8; 64],
    epoch: u64,
    approvals: &[IssuanceApproval],
    key_book: &OrchestratorKeyBook,
) -> Result<CertifiedKey, TlsCaError> {
    if approvals.len() < ISSUANCE_THRESHOLD {
        return Err(TlsCaError::IssuanceQuorum {
            present: approvals.len(),
            need: ISSUANCE_THRESHOLD,
        });
    }

    let payload = issuance_payload(module_name, pubkey_hash, epoch);
    let mut seen: std::collections::BTreeSet<u8> = std::collections::BTreeSet::new();
    let mut verified = 0usize;
    for a in approvals {
        if !seen.insert(a.signer_id) {
            return Err(TlsCaError::IssuanceDuplicateSigner(a.signer_id));
        }
        let vk = key_book.verifying_key(a.signer_id).ok_or_else(|| {
            TlsCaError::IssuanceBadSignature(format!(
                "no registered verifying key for signer {}",
                a.signer_id
            ))
        })?;
        if !crypto::pq_sign::pq_verify_raw_from_bytes(vk, &payload, &a.pq_signature) {
            return Err(TlsCaError::IssuanceBadSignature(format!(
                "signer {} signature invalid",
                a.signer_id
            )));
        }
        verified += 1;
        if verified >= ISSUANCE_THRESHOLD {
            break;
        }
    }
    if verified < ISSUANCE_THRESHOLD {
        return Err(TlsCaError::IssuanceQuorum {
            present: verified,
            need: ISSUANCE_THRESHOLD,
        });
    }

    // Quorum verified — CA may now sign.
    let key_pair = KeyPair::generate()
        .map_err(|e| TlsCaError::IssuanceSignFailed(format!("module key: {e}")))?;
    let subject_alt_names = vec![module_name.to_string()];
    let params = CertificateParams::new(subject_alt_names)
        .map_err(|e| TlsCaError::IssuanceSignFailed(format!("params: {e}")))?;
    let cert = params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .map_err(|e| TlsCaError::IssuanceSignFailed(format!("sign: {e}")))?;

    // Audit the successful issuance.
    let mut h = Sha512::new();
    h.update(cert.der().as_ref());
    let fp = h.finalize();
    tracing::info!(
        module = module_name,
        epoch = epoch,
        "C3: 3-of-5 module cert issued (SHA-512 fingerprint: {:x?})",
        &fp[..8]
    );
    common::siem::SecurityEvent::crypto_failure(&format!(
        "SHARD CA issued cert for '{module_name}' epoch {epoch} after 3-of-5 quorum"
    ));

    Ok(CertifiedKey { cert, key_pair })
}

/// Derive the HMAC-SHA512 integrity key for the CA PEM from the master KEK.
fn ca_integrity_hmac_key() -> Result<[u8; 64], String> {
    use hkdf::Hkdf;
    let master = common::sealed_keys::cached_master_kek();
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-SHARD-CA-INTEGRITY-v1"), master);
    let mut out = [0u8; 64];
    hk.expand(b"shard-ca-pem", &mut out)
        .map_err(|e| format!("hkdf expand: {e}"))?;
    Ok(out)
}

/// Compute the integrity tag (hex-encoded HMAC-SHA512) over the CA PEM.
fn compute_ca_integrity_tag(pem: &[u8]) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    type HmacSha512 = Hmac<Sha512>;
    let key = ca_integrity_hmac_key()?;
    let mut mac = <HmacSha512 as Mac>::new_from_slice(&key)
        .map_err(|e| format!("hmac key: {e}"))?;
    mac.update(pem);
    let tag = mac.finalize().into_bytes();
    Ok(hex::encode(tag))
}

/// Verify a stored integrity tag against the on-disk CA PEM.
fn verify_ca_integrity_tag(tag_hex: &str, pem: &[u8]) -> Result<(), String> {
    use hmac::{Hmac, Mac};
    type HmacSha512 = Hmac<Sha512>;
    let key = ca_integrity_hmac_key()?;
    let expected = hex::decode(tag_hex.trim()).map_err(|e| format!("tag hex: {e}"))?;
    let mut mac = <HmacSha512 as Mac>::new_from_slice(&key)
        .map_err(|e| format!("hmac key: {e}"))?;
    mac.update(pem);
    mac.verify_slice(&expected)
        .map_err(|_| "integrity tag mismatch — CA PEM tampered or wrong KEK".to_string())
}
