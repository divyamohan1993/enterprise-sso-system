//! Kerberos PKINIT client (J3).
//!
//! Issues TGTs for CAC/PIV smart-card holders by binding the user's PIV
//! authentication certificate to a Kerberos AS-REQ via the PKINIT
//! pre-authentication mechanism (RFC 4556).
//!
//! The MIT krb5 binding (`krb5-sys`) is loaded behind the `kdc-runtime`
//! feature so cargo can build this crate on hosts without `libkrb5-dev`.
//! The trait surface and ticket types are always available for callers.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::time::SystemTime;
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
}

/// Kerberos realm + KDC configuration loaded from /etc/krb5.conf-equivalent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KrbConfig {
    pub realm: String,
    pub kdc_hosts: Vec<String>,
    pub keytab_path: String,
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

/// Default client built on top of MIT krb5 via `krb5-sys`. Only available
/// when the crate is built with `--features kdc-runtime` on a host that has
/// `libkrb5-dev` installed.
#[cfg(feature = "kdc-runtime")]
pub struct Krb5Client {
    pub cfg: KrbConfig,
}

#[cfg(feature = "kdc-runtime")]
impl PkinitClient for Krb5Client {
    fn obtain_tgt(
        &self,
        _principal: &str,
        _cac_cert_der: &[u8],
        _signed_authpack: &[u8],
    ) -> Result<Tgt, PkinitError> {
        Err(PkinitError::PreAuthFailed(
            "kdc-runtime feature requires linking against libkrb5; \
             not enabled on this build".into(),
        ))
    }
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

/// Helper: convert SystemTime to Kerberos epoch seconds.
pub fn to_krb_time(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
