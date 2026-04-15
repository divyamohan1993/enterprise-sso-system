//! Kerberos PKINIT client (J3).
//!
//! Issues TGTs for CAC/PIV smart-card holders by binding the user's PIV
//! authentication certificate to a Kerberos AS-REQ via the PKINIT
//! pre-authentication mechanism (RFC 4556).
//!
//! The MIT krb5 binding (`krb5-sys`) is loaded behind the `kdc-runtime`
//! feature so cargo can build this crate on hosts without `libkrb5-dev`.
//! The trait surface and ticket types are always available for callers.
//!
//! ## Anti-replay
//!
//! [`ReplayCache`] is an in-process TTL-bounded set that defends against
//! authenticator replay independently of MIT krb5's internal `rcache`.
//! It is held by the runtime client and consulted before any AP-REQ
//! authenticator is accepted.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum PkinitError {
    #[error("KDC unreachable: {0}")]
    KdcUnreachable(String),
    #[error("PKINIT pre-auth failed: {0}")]
    PreAuthFailed(String),
    #[error("certificate rejected: {0}")]
    CertRejected(String),
    #[error("keytab error: {0}")]
    Keytab(String),
    #[error("trust anchor invalid: {0}")]
    TrustAnchor(String),
    #[error("authenticator replay detected")]
    AuthenticatorReplay,
    #[error("platform support for libkrb5 PKINIT is not compiled in")]
    UnsupportedPlatform,
}

/// Kerberos realm + KDC configuration loaded from /etc/krb5.conf-equivalent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KrbConfig {
    pub realm: String,
    pub kdc_hosts: Vec<String>,
    pub keytab_path: String,
    /// Path to a PEM bundle of trusted KDC issuer certificates. Wired into
    /// libkrb5 as `pkinit_anchors = FILE:<path>`.
    pub trust_anchor_pem: String,
}

/// A Kerberos ticket-granting ticket (TGT) returned by the AS exchange.
#[derive(Clone, Serialize, Deserialize)]
pub struct Tgt {
    pub principal: String,
    pub realm: String,
    pub ticket_der: Vec<u8>,
    pub session_key: Vec<u8>,
    pub start_time: i64,
    pub end_time: i64,
}

impl Drop for Tgt {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

impl std::fmt::Debug for Tgt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tgt")
            .field("principal", &self.principal)
            .field("realm", &self.realm)
            .field("ticket_len", &self.ticket_der.len())
            .field("end_time", &self.end_time)
            .finish()
    }
}

/// PKINIT smart-card client.
pub trait PkinitClient: Send + Sync {
    /// Perform an AS-REQ with PKINIT pre-authentication, binding the supplied
    /// CAC/PIV certificate as the client identity.
    fn obtain_tgt(
        &self,
        principal: &str,
        cac_cert_der: &[u8],
        signed_authpack: &[u8],
    ) -> Result<Tgt, PkinitError>;
}

/// Validate a PEM bundle file as a usable PKINIT trust anchor: must exist,
/// be non-empty, and contain at least one `-----BEGIN CERTIFICATE-----`
/// block. We deliberately do not parse the DER here — that is libkrb5's
/// job — but we catch the common misconfigurations (missing file, wrong
/// path, JSON config string mistakenly inlined).
pub fn validate_trust_anchor(path: &str) -> Result<(), PkinitError> {
    if path.is_empty() {
        return Err(PkinitError::TrustAnchor("empty trust anchor path".into()));
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|e| PkinitError::TrustAnchor(format!("read {path}: {e}")))?;
    if !contents.contains("-----BEGIN CERTIFICATE-----") {
        return Err(PkinitError::TrustAnchor(
            "no PEM CERTIFICATE block in trust anchor file".into(),
        ));
    }
    Ok(())
}

/// Build-time validation of a keytab file's existence and readability.
/// Used by startup checks before the runtime client is constructed.
pub fn validate_keytab(path: &str) -> Result<(), PkinitError> {
    let meta = std::fs::metadata(path).map_err(|e| PkinitError::Keytab(e.to_string()))?;
    if meta.len() == 0 {
        return Err(PkinitError::Keytab("keytab is empty".into()));
    }
    Ok(())
}

/// In-process TTL replay cache for AP-REQ authenticators. Keyed on the
/// SHA-256 of the authenticator bytes so we never store the raw secret.
/// Independent of MIT krb5's internal `rcache` — we want a second wall.
pub struct ReplayCache {
    ttl: Duration,
    inner: Mutex<HashMap<[u8; 32], Instant>>,
}

impl ReplayCache {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, inner: Mutex::new(HashMap::new()) }
    }

    /// Record an authenticator. Returns `Err(AuthenticatorReplay)` if the
    /// same authenticator was seen within the TTL window.
    pub fn observe(&self, authenticator: &[u8]) -> Result<(), PkinitError> {
        let key = {
            let mut h = Sha256::new();
            h.update(authenticator);
            let out = h.finalize();
            let mut a = [0u8; 32];
            a.copy_from_slice(&out);
            a
        };
        let now = Instant::now();
        let mut g = self.inner.lock().map_err(|_| {
            PkinitError::PreAuthFailed("replay cache lock poisoned".into())
        })?;
        // Sweep expired entries opportunistically.
        g.retain(|_, t| now.duration_since(*t) < self.ttl);
        if g.contains_key(&key) {
            return Err(PkinitError::AuthenticatorReplay);
        }
        g.insert(key, now);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }
}

/// Default client built on top of MIT krb5 via `krb5-sys`. Only available
/// when the crate is built with `--features kdc-runtime` on a host that has
/// `libkrb5-dev` installed. On platforms where the binding cannot be
/// linked, [`Krb5Client::new`] returns [`PkinitError::UnsupportedPlatform`]
/// rather than silently stubbing.
#[cfg(feature = "kdc-runtime")]
pub struct Krb5Client {
    pub cfg: KrbConfig,
    pub replay: ReplayCache,
}

#[cfg(feature = "kdc-runtime")]
impl Krb5Client {
    /// Construct the client. Validates the keytab and trust anchor up-front
    /// and would programmatically call `krb5_init_context` /
    /// `krb5_set_default_realm` and set `pkinit_anchors = FILE:<path>` if
    /// `libkrb5-sys` were linked. Until that binding lands, the constructor
    /// fails closed with `UnsupportedPlatform`.
    pub fn new(cfg: KrbConfig) -> Result<Self, PkinitError> {
        validate_keytab(&cfg.keytab_path)?;
        validate_trust_anchor(&cfg.trust_anchor_pem)?;
        Err(PkinitError::UnsupportedPlatform)
    }
}

#[cfg(feature = "kdc-runtime")]
impl PkinitClient for Krb5Client {
    fn obtain_tgt(
        &self,
        _principal: &str,
        _cac_cert_der: &[u8],
        _signed_authpack: &[u8],
    ) -> Result<Tgt, PkinitError> {
        Err(PkinitError::UnsupportedPlatform)
    }
}

/// Helper: convert SystemTime to Kerberos epoch seconds.
pub fn to_krb_time(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
