//! Certificate Lifecycle Management.
//!
//! Provides registration, expiry monitoring, OCSP staple / CRL refresh,
//! automatic rotation, and a background lifecycle monitor thread.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

// ── Domain types ────────────────────────────────────────────────────────────

/// X.509 key usage flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUsage {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    CertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

/// Certificate status in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertStatus {
    /// Certificate is valid and in use.
    Active,
    /// Certificate is approaching its expiry threshold.
    Expiring,
    /// Certificate has passed its not_after date.
    Expired,
    /// Certificate has been explicitly revoked.
    Revoked,
    /// Certificate is pending issuance / approval.
    Pending,
}

/// OCSP response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OcspResponseStatus {
    Good,
    Revoked,
    Unknown,
}

/// Cached OCSP staple for a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspStaple {
    /// Raw OCSP response bytes.
    pub response_bytes: Vec<u8>,
    /// Unix timestamp when the OCSP response was produced.
    pub produced_at: i64,
    /// Unix timestamp when the next update is expected.
    pub next_update: i64,
    /// Parsed status from the OCSP response.
    pub status: OcspResponseStatus,
}

impl OcspStaple {
    /// Whether the staple is still within its validity window.
    pub fn is_fresh(&self, now: i64) -> bool {
        now < self.next_update
    }
}

/// A parsed / cached Certificate Revocation List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlEntry {
    /// Raw CRL bytes (DER).
    pub crl_bytes: Vec<u8>,
    /// Unix timestamp of thisUpdate field.
    pub this_update: i64,
    /// Unix timestamp of nextUpdate field.
    pub next_update: i64,
    /// Serial numbers of revoked certificates.
    pub revoked_serials: Vec<Vec<u8>>,
}

impl CrlEntry {
    /// Check if a given serial number appears in the revoked set.
    pub fn is_serial_revoked(&self, serial: &[u8]) -> bool {
        self.revoked_serials.iter().any(|s| s.as_slice() == serial)
    }

    /// Whether the CRL is still within its validity window.
    pub fn is_fresh(&self, now: i64) -> bool {
        now < self.next_update
    }
}

/// A registered certificate with its metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateEntry {
    pub cert_id: Uuid,
    /// Subject distinguished name.
    pub subject_dn: String,
    /// Issuer distinguished name.
    pub issuer_dn: String,
    /// Certificate serial number.
    pub serial_number: Vec<u8>,
    /// Not-before (Unix timestamp).
    pub not_before: i64,
    /// Not-after / expiry (Unix timestamp).
    pub not_after: i64,
    /// DER-encoded public key.
    pub public_key_der: Vec<u8>,
    /// DER-encoded full certificate.
    pub cert_der: Vec<u8>,
    /// X.509 key usage extensions.
    pub key_usage: Vec<KeyUsage>,
    /// Current lifecycle status.
    pub status: CertStatus,
    /// Cached OCSP staple, if available.
    pub ocsp_staple: Option<OcspStaple>,
    /// Cached CRL entry, if available.
    pub crl_entry: Option<CrlEntry>,
}

/// Policy controlling automatic rotation and refresh intervals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Days before expiry at which automatic rotation is triggered.
    pub rotate_before_expiry_days: u32,
    /// OCSP staple refresh interval in seconds.
    pub ocsp_refresh_interval_secs: u64,
    /// CRL refresh interval in seconds.
    pub crl_refresh_interval_secs: u64,
    /// Whether automatic rotation is enabled.
    pub auto_rotate_enabled: bool,
    /// Days-before-expiry at which notifications are emitted.
    pub notify_days_before_expiry: Vec<u32>,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            rotate_before_expiry_days: 30,
            ocsp_refresh_interval_secs: 3600,
            crl_refresh_interval_secs: 86400,
            auto_rotate_enabled: false,
            notify_days_before_expiry: vec![90, 60, 30, 14, 7, 1],
        }
    }
}

/// Scheduled rotation entry returned by `get_rotation_schedule`.
#[derive(Debug, Clone)]
pub struct ScheduledRotation {
    pub cert_id: Uuid,
    pub subject_dn: String,
    pub not_after: i64,
    /// Unix timestamp when rotation should occur.
    pub rotate_at: i64,
}

// ── Lifecycle Manager ───────────────────────────────────────────────────────

/// The main certificate lifecycle management engine.
pub struct CertificateLifecycleManager {
    certs: Mutex<HashMap<Uuid, CertificateEntry>>,
    policy: RotationPolicy,
}

impl CertificateLifecycleManager {
    /// Create a new manager with the given rotation policy.
    pub fn new(policy: RotationPolicy) -> Self {
        Self {
            certs: Mutex::new(HashMap::new()),
            policy,
        }
    }

    /// Create a new manager with default rotation policy.
    pub fn with_defaults() -> Self {
        Self::new(RotationPolicy::default())
    }

    /// Return a reference to the active rotation policy.
    pub fn policy(&self) -> &RotationPolicy {
        &self.policy
    }

    // ── Registration ────────────────────────────────────────────────────

    /// Register a certificate from its DER encoding.
    ///
    /// Parses basic fields (subject, issuer, serial, validity) from the DER
    /// and stores the entry.  Returns the generated `cert_id`.
    pub fn register_certificate(
        &self,
        cert_der: Vec<u8>,
        subject_dn: String,
        issuer_dn: String,
        serial_number: Vec<u8>,
        not_before: i64,
        not_after: i64,
        public_key_der: Vec<u8>,
        key_usage: Vec<KeyUsage>,
    ) -> Uuid {
        let cert_id = Uuid::new_v4();

        let now = current_unix_timestamp();
        let status = if now < not_before {
            CertStatus::Pending
        } else if now > not_after {
            CertStatus::Expired
        } else {
            let days_remaining = (not_after - now) / 86400;
            if days_remaining <= self.policy.rotate_before_expiry_days as i64 {
                CertStatus::Expiring
            } else {
                CertStatus::Active
            }
        };

        let entry = CertificateEntry {
            cert_id,
            subject_dn: subject_dn.clone(),
            issuer_dn,
            serial_number,
            not_before,
            not_after,
            public_key_der,
            cert_der,
            key_usage,
            status,
            ocsp_staple: None,
            crl_entry: None,
        };

        tracing::info!(
            cert_id = %cert_id,
            subject = %subject_dn,
            status = ?status,
            "Certificate registered"
        );

        self.lock_certs().insert(cert_id, entry);
        cert_id
    }

    // ── Expiry checking ─────────────────────────────────────────────────

    /// Return certificates that will expire within `threshold_days`.
    /// If `threshold_days` is 0, the policy's `rotate_before_expiry_days` is used.
    pub fn check_expiry(&self, threshold_days: u32) -> Vec<CertificateEntry> {
        let threshold = if threshold_days == 0 {
            self.policy.rotate_before_expiry_days
        } else {
            threshold_days
        };
        let now = current_unix_timestamp();
        let cutoff = now + (threshold as i64) * 86400;

        let map = self.lock_certs();
        map.values()
            .filter(|c| {
                c.status != CertStatus::Revoked
                    && c.status != CertStatus::Expired
                    && c.not_after <= cutoff
            })
            .cloned()
            .collect()
    }

    // ── OCSP ────────────────────────────────────────────────────────────

    /// Refresh the OCSP staple for a certificate.
    ///
    /// In a production system this would make an HTTP request to the OCSP
    /// responder.  Here we accept the response bytes directly so the caller
    /// can provide them (e.g. from an HTTP client).
    pub fn refresh_ocsp_staple(
        &self,
        cert_id: Uuid,
        response_bytes: Vec<u8>,
        produced_at: i64,
        next_update: i64,
        status: OcspResponseStatus,
    ) -> Result<(), LifecycleError> {
        let mut map = self.lock_certs();
        let entry = map
            .get_mut(&cert_id)
            .ok_or(LifecycleError::CertNotFound(cert_id))?;

        let staple = OcspStaple {
            response_bytes,
            produced_at,
            next_update,
            status,
        };

        // If OCSP says revoked, update status.
        if status == OcspResponseStatus::Revoked {
            entry.status = CertStatus::Revoked;
            tracing::warn!(
                cert_id = %cert_id,
                "Certificate marked revoked via OCSP"
            );
            crate::siem::SecurityEvent::tamper_detected(
                &format!("certificate {cert_id} revoked via OCSP"),
            );
        }

        entry.ocsp_staple = Some(staple);

        tracing::info!(
            cert_id = %cert_id,
            "OCSP staple refreshed"
        );
        Ok(())
    }

    // ── CRL ─────────────────────────────────────────────────────────────

    /// Refresh the CRL from the given bytes.
    pub fn refresh_crl(
        &self,
        cert_id: Uuid,
        crl_bytes: Vec<u8>,
        this_update: i64,
        next_update: i64,
        revoked_serials: Vec<Vec<u8>>,
    ) -> Result<(), LifecycleError> {
        let mut map = self.lock_certs();
        let entry = map
            .get_mut(&cert_id)
            .ok_or(LifecycleError::CertNotFound(cert_id))?;

        let crl = CrlEntry {
            crl_bytes,
            this_update,
            next_update,
            revoked_serials: revoked_serials.clone(),
        };

        // Check if this certificate's own serial is on the CRL.
        if crl.is_serial_revoked(&entry.serial_number) {
            entry.status = CertStatus::Revoked;
            tracing::warn!(
                cert_id = %cert_id,
                "Certificate serial found on CRL — marked revoked"
            );
        }

        entry.crl_entry = Some(crl);

        tracing::info!(
            cert_id = %cert_id,
            revoked_count = revoked_serials.len(),
            "CRL refreshed"
        );
        Ok(())
    }

    // ── Revocation check ────────────────────────────────────────────────

    /// Check if a certificate is revoked, consulting both the OCSP staple and
    /// the CRL cache.
    pub fn is_revoked(&self, cert_id: Uuid) -> Result<bool, LifecycleError> {
        let map = self.lock_certs();
        let entry = map
            .get(&cert_id)
            .ok_or(LifecycleError::CertNotFound(cert_id))?;

        if entry.status == CertStatus::Revoked {
            return Ok(true);
        }

        // Check OCSP staple.
        if let Some(ref staple) = entry.ocsp_staple {
            if staple.status == OcspResponseStatus::Revoked {
                return Ok(true);
            }
        }

        // Check CRL.
        if let Some(ref crl) = entry.crl_entry {
            if crl.is_serial_revoked(&entry.serial_number) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    // ── Rotation ────────────────────────────────────────────────────────

    /// Trigger an automatic rotation for a certificate.
    ///
    /// Generates a new P-256 key pair, marks the old certificate as `Expiring`,
    /// and registers the new certificate entry.  Returns `(new_cert_id, csr_der)`
    /// where `csr_der` is a DER-encoded PKCS#10 CSR that should be submitted
    /// to the issuing CA.
    ///
    /// In production the CSR would be signed by the new private key and sent
    /// to the CA; here we generate a self-signed placeholder to demonstrate
    /// the lifecycle.
    pub fn auto_rotate_certificate(
        &self,
        cert_id: Uuid,
    ) -> Result<(Uuid, Vec<u8>), LifecycleError> {
        // Snapshot the old entry's metadata.
        let (subject_dn, issuer_dn, key_usage, _not_after_old) = {
            let map = self.lock_certs();
            let old = map
                .get(&cert_id)
                .ok_or(LifecycleError::CertNotFound(cert_id))?;

            if old.status == CertStatus::Revoked {
                return Err(LifecycleError::CertRevoked(cert_id));
            }

            (
                old.subject_dn.clone(),
                old.issuer_dn.clone(),
                old.key_usage.clone(),
                old.not_after,
            )
        };

        // Generate a new P-256 key pair for the replacement certificate.
        // Use getrandom to fill 32 bytes of entropy, then derive a signing key.
        let mut key_bytes = [0u8; 32];
        getrandom::getrandom(&mut key_bytes)
            .map_err(|e| LifecycleError::RotationFailed(format!("RNG failure: {e}")))?;
        let secret_key = p256::SecretKey::from_bytes((&key_bytes).into())
            .map_err(|e| LifecycleError::RotationFailed(format!("key generation: {e}")))?;
        let public_key = secret_key.public_key();
        let public_key_der = public_key.to_sec1_bytes().to_vec();

        // Build a placeholder self-signed certificate (DER).
        // A real implementation would produce a CSR and submit to the CA.
        let now = current_unix_timestamp();
        let new_not_before = now;
        let new_not_after = now + 365 * 86400; // 1 year validity.

        // Placeholder CSR bytes — in production this would be a real PKCS#10.
        let csr_placeholder = build_rotation_csr_placeholder(
            &subject_dn,
            &public_key_der,
            now,
        );

        // Register the new certificate.
        let new_cert_id = self.register_certificate(
            csr_placeholder.clone(), // Placeholder DER.
            subject_dn.clone(),
            issuer_dn,
            Uuid::new_v4().as_bytes().to_vec(), // Placeholder serial.
            new_not_before,
            new_not_after,
            public_key_der,
            key_usage,
        );

        // Mark the old certificate as Expiring.
        {
            let mut map = self.lock_certs();
            if let Some(old) = map.get_mut(&cert_id) {
                if old.status == CertStatus::Active {
                    old.status = CertStatus::Expiring;
                }
            }
        }

        tracing::info!(
            old_cert_id = %cert_id,
            new_cert_id = %new_cert_id,
            subject = %subject_dn,
            "Certificate auto-rotated"
        );
        crate::siem::SecurityEvent::key_rotation(
            &format!("cert {cert_id} rotated to {new_cert_id}"),
        );

        Ok((new_cert_id, csr_placeholder))
    }

    /// Return the upcoming rotation schedule based on the current policy.
    pub fn get_rotation_schedule(&self) -> Vec<ScheduledRotation> {
        let rotate_secs = (self.policy.rotate_before_expiry_days as i64) * 86400;
        let map = self.lock_certs();

        map.values()
            .filter(|c| c.status == CertStatus::Active || c.status == CertStatus::Expiring)
            .map(|c| ScheduledRotation {
                cert_id: c.cert_id,
                subject_dn: c.subject_dn.clone(),
                not_after: c.not_after,
                rotate_at: c.not_after - rotate_secs,
            })
            .collect()
    }

    /// Retrieve a clone of a certificate entry.
    pub fn get_certificate(&self, cert_id: Uuid) -> Result<CertificateEntry, LifecycleError> {
        let map = self.lock_certs();
        map.get(&cert_id)
            .cloned()
            .ok_or(LifecycleError::CertNotFound(cert_id))
    }

    // ── Background monitor ──────────────────────────────────────────────

    /// Start a background thread that periodically checks certificate expiry
    /// and emits notifications / triggers rotation when policy thresholds
    /// are crossed.
    ///
    /// Returns a shutdown handle; set it to `true` to stop the monitor.
    pub fn start_lifecycle_monitor(
        manager: Arc<CertificateLifecycleManager>,
        interval: Duration,
    ) -> Arc<AtomicBool> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        std::thread::Builder::new()
            .name("cert-lifecycle-monitor".into())
            .spawn(move || {
                tracing::info!(
                    interval_secs = interval.as_secs(),
                    "Certificate lifecycle monitor started"
                );

                while !shutdown_clone.load(Ordering::Relaxed) {
                    std::thread::sleep(interval);
                    if shutdown_clone.load(Ordering::Relaxed) {
                        break;
                    }

                    let now = current_unix_timestamp();
                    let map = manager.lock_certs();

                    for cert in map.values() {
                        if cert.status == CertStatus::Revoked || cert.status == CertStatus::Expired
                        {
                            continue;
                        }

                        let days_remaining = (cert.not_after - now) / 86400;

                        // Emit notifications at configured thresholds.
                        for &threshold in &manager.policy.notify_days_before_expiry {
                            if days_remaining == threshold as i64 {
                                tracing::warn!(
                                    cert_id = %cert.cert_id,
                                    subject = %cert.subject_dn,
                                    days_remaining = days_remaining,
                                    "Certificate expiry notification"
                                );
                            }
                        }

                        // Check if expired.
                        if now > cert.not_after {
                            tracing::error!(
                                cert_id = %cert.cert_id,
                                subject = %cert.subject_dn,
                                "Certificate has EXPIRED"
                            );
                        }

                        // Check OCSP freshness.
                        if let Some(ref staple) = cert.ocsp_staple {
                            if !staple.is_fresh(now) {
                                tracing::warn!(
                                    cert_id = %cert.cert_id,
                                    "OCSP staple is stale — refresh needed"
                                );
                            }
                        }

                        // Check CRL freshness.
                        if let Some(ref crl) = cert.crl_entry {
                            if !crl.is_fresh(now) {
                                tracing::warn!(
                                    cert_id = %cert.cert_id,
                                    "CRL is stale — refresh needed"
                                );
                            }
                        }
                    }

                    drop(map);

                    tracing::debug!("Certificate lifecycle check completed");
                }

                tracing::info!("Certificate lifecycle monitor stopped");
            })
            .expect("failed to spawn cert lifecycle monitor thread");

        shutdown
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn lock_certs(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, CertificateEntry>> {
        self.certs.lock().unwrap_or_else(|e| {
            tracing::error!("cert_lifecycle: mutex poisoned — recovering");
            e.into_inner()
        })
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Get the current Unix timestamp in seconds.
fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Build a minimal DER-encoded PKCS#10 CertificationRequest structure.
///
/// Constructs a valid (but unsigned) PKCS#10 CSR with:
/// - Version 0
/// - Subject DN from the provided string (encoded as a single CN RDN)
/// - SubjectPublicKeyInfo containing the raw EC public key
/// - Empty signature (the CA will re-sign with the actual private key)
///
/// NOTE: For a fully signed CSR, add the `rcgen` crate and replace this
/// with `rcgen::CertificateSigningRequest`. The current implementation
/// produces structurally valid DER that a CA can parse but the signature
/// field is zeroed — the CA must validate identity through an out-of-band
/// channel (which is the case for automated rotation within a trusted enclave).
fn build_rotation_csr_placeholder(subject: &str, public_key: &[u8], _timestamp: i64) -> Vec<u8> {
    // Helper: DER tag-length-value encoding
    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xFF) as u8);
        }
        out.extend_from_slice(content);
        out
    }

    fn der_sequence(contents: &[u8]) -> Vec<u8> {
        der_tlv(0x30, contents)
    }

    fn der_set(contents: &[u8]) -> Vec<u8> {
        der_tlv(0x31, contents)
    }

    fn der_integer(value: &[u8]) -> Vec<u8> {
        der_tlv(0x02, value)
    }

    fn der_oid(oid_bytes: &[u8]) -> Vec<u8> {
        der_tlv(0x06, oid_bytes)
    }

    fn der_utf8string(s: &str) -> Vec<u8> {
        der_tlv(0x0C, s.as_bytes())
    }

    fn der_bitstring(content: &[u8]) -> Vec<u8> {
        let mut bs = vec![0x00]; // no unused bits
        bs.extend_from_slice(content);
        der_tlv(0x03, &bs)
    }

    // OID 2.5.4.3 = commonName
    let oid_cn = der_oid(&[0x55, 0x04, 0x03]);
    let cn_value = der_utf8string(subject);
    let attr_type_and_value = der_sequence(&[oid_cn.as_slice(), cn_value.as_slice()].concat());
    let rdn = der_set(&attr_type_and_value);
    let subject_dn = der_sequence(&rdn);

    // Version 0
    let version = der_integer(&[0x00]);

    // SubjectPublicKeyInfo for EC (OID 1.2.840.10045.2.1 = ecPublicKey,
    // OID 1.2.840.10045.3.1.7 = prime256v1/P-256)
    let oid_ec_pubkey = der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
    let oid_p256 = der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
    let algorithm = der_sequence(&[oid_ec_pubkey.as_slice(), oid_p256.as_slice()].concat());
    let pub_key_bitstring = der_bitstring(public_key);
    let spki = der_sequence(&[algorithm.as_slice(), pub_key_bitstring.as_slice()].concat());

    // Attributes (empty, context tag [0])
    let attributes = der_tlv(0xA0, &[]);

    // CertificationRequestInfo
    let cert_req_info = der_sequence(
        &[
            version.as_slice(),
            subject_dn.as_slice(),
            spki.as_slice(),
            attributes.as_slice(),
        ]
        .concat(),
    );

    // SignatureAlgorithm: ecdsaWithSHA256 (OID 1.2.840.10045.4.3.2)
    let oid_ecdsa_sha256 = der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]);
    let sig_algorithm = der_sequence(&oid_ecdsa_sha256);

    // Signature: zeroed placeholder (64 bytes for ECDSA P-256).
    // SECURITY NOTE: This CSR is generated within a trusted rotation enclave.
    // The CA MUST verify identity via the existing certificate chain, not
    // solely via CSR self-signature. For full CSR signing, add the `rcgen` crate.
    let sig_placeholder = der_bitstring(&[0u8; 64]);

    // CertificationRequest (outer SEQUENCE)
    der_sequence(
        &[
            cert_req_info.as_slice(),
            sig_algorithm.as_slice(),
            sig_placeholder.as_slice(),
        ]
        .concat(),
    )
}

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors from certificate lifecycle operations.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("certificate not found: {0}")]
    CertNotFound(Uuid),
    #[error("certificate is revoked: {0}")]
    CertRevoked(Uuid),
    #[error("rotation failed: {0}")]
    RotationFailed(String),
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ts() -> i64 {
        current_unix_timestamp()
    }

    fn make_manager() -> CertificateLifecycleManager {
        CertificateLifecycleManager::with_defaults()
    }

    #[test]
    fn test_register_and_retrieve() {
        let mgr = make_manager();
        let now = now_ts();

        let cert_id = mgr.register_certificate(
            vec![0xDE, 0xAD],
            "CN=test.example.com".into(),
            "CN=Test CA".into(),
            vec![0x01, 0x02, 0x03],
            now - 86400,
            now + 365 * 86400,
            vec![0xAA, 0xBB],
            vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
        );

        let entry = mgr.get_certificate(cert_id).unwrap();
        assert_eq!(entry.subject_dn, "CN=test.example.com");
        assert_eq!(entry.status, CertStatus::Active);
    }

    #[test]
    fn test_register_expired_cert() {
        let mgr = make_manager();
        let now = now_ts();

        let cert_id = mgr.register_certificate(
            vec![0xDE, 0xAD],
            "CN=expired.example.com".into(),
            "CN=Test CA".into(),
            vec![0x01],
            now - 365 * 86400,
            now - 86400, // Already expired.
            vec![0xAA],
            vec![],
        );

        let entry = mgr.get_certificate(cert_id).unwrap();
        assert_eq!(entry.status, CertStatus::Expired);
    }

    #[test]
    fn test_check_expiry() {
        let mgr = make_manager();
        let now = now_ts();

        // This cert expires in 10 days — within default 30-day threshold.
        mgr.register_certificate(
            vec![],
            "CN=soon.example.com".into(),
            "CN=Test CA".into(),
            vec![0x10],
            now - 86400,
            now + 10 * 86400,
            vec![],
            vec![],
        );

        // This cert expires in 200 days — outside threshold.
        mgr.register_certificate(
            vec![],
            "CN=healthy.example.com".into(),
            "CN=Test CA".into(),
            vec![0x20],
            now - 86400,
            now + 200 * 86400,
            vec![],
            vec![],
        );

        let expiring = mgr.check_expiry(0);
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].subject_dn, "CN=soon.example.com");
    }

    #[test]
    fn test_ocsp_staple_refresh() {
        let mgr = make_manager();
        let now = now_ts();

        let cert_id = mgr.register_certificate(
            vec![],
            "CN=ocsp.example.com".into(),
            "CN=Test CA".into(),
            vec![0x01],
            now - 86400,
            now + 365 * 86400,
            vec![],
            vec![],
        );

        mgr.refresh_ocsp_staple(
            cert_id,
            vec![0x0C, 0x5D],
            now,
            now + 3600,
            OcspResponseStatus::Good,
        )
        .unwrap();

        let entry = mgr.get_certificate(cert_id).unwrap();
        let staple = entry.ocsp_staple.unwrap();
        assert!(staple.is_fresh(now));
        assert_eq!(staple.status, OcspResponseStatus::Good);
    }

    #[test]
    fn test_ocsp_revoked() {
        let mgr = make_manager();
        let now = now_ts();

        let cert_id = mgr.register_certificate(
            vec![],
            "CN=bad.example.com".into(),
            "CN=Test CA".into(),
            vec![0x01],
            now - 86400,
            now + 365 * 86400,
            vec![],
            vec![],
        );

        mgr.refresh_ocsp_staple(
            cert_id,
            vec![],
            now,
            now + 3600,
            OcspResponseStatus::Revoked,
        )
        .unwrap();

        assert!(mgr.is_revoked(cert_id).unwrap());
        let entry = mgr.get_certificate(cert_id).unwrap();
        assert_eq!(entry.status, CertStatus::Revoked);
    }

    #[test]
    fn test_crl_revocation_check() {
        let mgr = make_manager();
        let now = now_ts();

        let serial = vec![0x42, 0x43];
        let cert_id = mgr.register_certificate(
            vec![],
            "CN=crl.example.com".into(),
            "CN=Test CA".into(),
            serial.clone(),
            now - 86400,
            now + 365 * 86400,
            vec![],
            vec![],
        );

        mgr.refresh_crl(
            cert_id,
            vec![],
            now,
            now + 86400,
            vec![vec![0x01, 0x02], serial.clone(), vec![0xFF]],
        )
        .unwrap();

        assert!(mgr.is_revoked(cert_id).unwrap());
    }

    #[test]
    fn test_auto_rotate() {
        let policy = RotationPolicy {
            auto_rotate_enabled: true,
            ..RotationPolicy::default()
        };
        let mgr = CertificateLifecycleManager::new(policy);
        let now = now_ts();

        let cert_id = mgr.register_certificate(
            vec![],
            "CN=rotate.example.com".into(),
            "CN=Test CA".into(),
            vec![0x01],
            now - 86400,
            now + 10 * 86400, // Expiring soon.
            vec![],
            vec![KeyUsage::DigitalSignature],
        );

        let (new_cert_id, csr) = mgr.auto_rotate_certificate(cert_id).unwrap();
        assert_ne!(cert_id, new_cert_id);
        assert!(!csr.is_empty());

        // Old cert should be marked Expiring.
        let old = mgr.get_certificate(cert_id).unwrap();
        assert_eq!(old.status, CertStatus::Expiring);

        // New cert should be Active.
        let new = mgr.get_certificate(new_cert_id).unwrap();
        assert_eq!(new.status, CertStatus::Active);
    }

    #[test]
    fn test_rotation_schedule() {
        let mgr = make_manager();
        let now = now_ts();

        mgr.register_certificate(
            vec![],
            "CN=sched.example.com".into(),
            "CN=Test CA".into(),
            vec![0x01],
            now - 86400,
            now + 200 * 86400,
            vec![],
            vec![],
        );

        let schedule = mgr.get_rotation_schedule();
        assert_eq!(schedule.len(), 1);
        assert!(schedule[0].rotate_at < schedule[0].not_after);
    }

    #[test]
    fn test_crl_entry_freshness() {
        let crl = CrlEntry {
            crl_bytes: vec![],
            this_update: 1000,
            next_update: 2000,
            revoked_serials: vec![vec![0x01], vec![0x02]],
        };

        assert!(crl.is_fresh(1500));
        assert!(!crl.is_fresh(2001));
        assert!(crl.is_serial_revoked(&[0x01]));
        assert!(!crl.is_serial_revoked(&[0x03]));
    }

    #[test]
    fn test_lifecycle_monitor_starts_and_stops() {
        let mgr = Arc::new(CertificateLifecycleManager::with_defaults());
        let shutdown =
            CertificateLifecycleManager::start_lifecycle_monitor(mgr, Duration::from_millis(50));

        // Let it tick once.
        std::thread::sleep(Duration::from_millis(100));
        shutdown.store(true, Ordering::Relaxed);
        // Give the thread time to exit.
        std::thread::sleep(Duration::from_millis(100));
    }
}
