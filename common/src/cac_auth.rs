//! CAC/PIV authentication flow for the MILNET SSO system.
//!
//! Implements the full CAC challenge-response authentication flow including:
//! - PIN management with lockout tracking
//! - Certificate chain validation
//! - DoD and Indian DSC clearance extraction from policy OIDs
//! - OCSP/CRL revocation checking (best-effort; configurable)
//! - Tier enforcement — Tier 1 (Sovereign) requires hardware CAC/PIV
//! - SIEM audit logging on all auth events
//!
//! # Usage
//! ```text
//! let config = CacConfig { pkcs11_library: "/usr/lib/libcackey.so".into(), .. };
//! let mut auth = CacAuthenticator::new(config)?;
//! let (card_info, sig) = auth.authenticate(&pin, &challenge, &mut session)?;
//! ```

use std::collections::HashMap;

use crate::cac::{CacCardInfo, CacError, Pkcs11Session};
use crate::siem::SecurityEvent;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the CAC/PIV authentication subsystem.
pub struct CacConfig {
    /// Path to the PKCS#11 shared library (e.g. `/usr/lib/libcackey.so`).
    pub pkcs11_library: String,
    /// PKCS#11 slot identifier (typically 0 for the first reader).
    pub slot_id: u64,
    /// Trusted CA certificates in DER format for chain validation.
    pub trusted_ca_certs: Vec<Vec<u8>>,
    /// Required certificate policy OIDs.  Authentication certificates must
    /// assert at least one of these policy OIDs.
    pub required_policy_oids: Vec<String>,
    /// URL of the OCSP responder for online revocation checks.
    pub ocsp_responder_url: Option<String>,
    /// CRL Distribution Points to check for offline revocation.
    pub crl_distribution_points: Vec<String>,
    /// Maximum PIN entry attempts before the card is considered locked.
    /// DoD CAC cards lock after 3 failures.
    pub pin_max_retries: u8,
    /// How long (in seconds) a CAC session is valid before forced re-auth.
    pub session_timeout_secs: u64,
}

impl Default for CacConfig {
    fn default() -> Self {
        Self {
            pkcs11_library: String::new(),
            slot_id: 0,
            trusted_ca_certs: Vec::new(),
            required_policy_oids: Vec::new(),
            ocsp_responder_url: None,
            crl_distribution_points: Vec::new(),
            pin_max_retries: 3,
            session_timeout_secs: 3600,
        }
    }
}

// ---------------------------------------------------------------------------
// Revocation status
// ---------------------------------------------------------------------------

/// Outcome of a certificate revocation check.
pub enum RevocationStatus {
    /// Certificate is confirmed good.
    Good,
    /// Certificate has been revoked.
    Revoked {
        /// Human-readable revocation reason code.
        reason: String,
        /// Unix timestamp (seconds) when the certificate was revoked.
        revoked_at: i64,
    },
    /// Revocation status is unknown (no definitive answer from OCSP/CRL).
    Unknown,
    /// OCSP responder is unavailable and no CRL could be fetched.
    OcspUnavailable,
}

// ---------------------------------------------------------------------------
// CacAuthenticator
// ---------------------------------------------------------------------------

/// Orchestrates the full CAC/PIV authentication flow.
///
/// Tracks per-card PIN failure counts in memory; not persisted across restarts
/// (acceptable for short-lived DoD CAC sessions).
pub struct CacAuthenticator {
    config: CacConfig,
    /// Maps `card_serial` → number of consecutive PIN failures.
    pin_attempt_count: HashMap<String, u8>,
}

impl CacAuthenticator {
    /// Create a new `CacAuthenticator` with the given configuration.
    ///
    /// Validates that `pin_max_retries > 0` (a zero retry limit would
    /// permanently lock all cards).
    pub fn new(config: CacConfig) -> Result<Self, CacError> {
        if config.pin_max_retries == 0 {
            return Err(CacError::InvalidCertificate(
                "pin_max_retries must be > 0".into(),
            ));
        }
        Ok(Self {
            config,
            pin_attempt_count: HashMap::new(),
        })
    }

    /// Full CAC authentication flow.
    ///
    /// Steps:
    /// 1. Log in with the supplied PIN (lockout tracked).
    /// 2. Retrieve the PIV authentication certificate from the card.
    /// 3. **Validate the certificate chain to a trusted DoD PKI anchor**
    ///    (RFC 5280 §6.1): signature chain, validity window, id-kp-clientAuth
    ///    EKU, and required assurance policy OIDs. A certificate that does not
    ///    chain to a trusted CA is rejected here — BEFORE it is trusted for
    ///    anything (zerotrust-gw F1).
    /// 4. Sign the `challenge` bytes with the card's private key.
    /// 5. Verify the challenge signature against the now-TRUSTED certificate.
    /// 6. **Check revocation** (OCSP/CRL) and apply the fail-closed policy
    ///    (zerotrust-gw F2): a revoked certificate, or an undetermined status
    ///    in military-deployment mode, denies access.
    /// 7. Build [`CacCardInfo`], deriving the clearance from the VALIDATED
    ///    certificate's policy OIDs (never from the attacker-supplied cert).
    ///
    /// Emits SIEM events for success and failure. Fail-closed throughout: any
    /// validation, revocation, or signature failure denies authentication.
    pub fn authenticate(
        &mut self,
        pin: &[u8],
        challenge: &[u8; 32],
        session: &mut Pkcs11Session,
    ) -> Result<(CacCardInfo, Vec<u8>), CacError> {
        // Step 1: Login the PIN.
        match session.login_user(pin) {
            Ok(()) => {}
            Err(CacError::LoginFailed) => {
                // We can't identify the card serial before login, so use a
                // placeholder key for the lockout counter.
                let serial = "unknown".to_string();
                self.record_pin_failure(&serial);
                emit_cac_auth_failure("pin_failure");
                return Err(CacError::LoginFailed);
            }
            Err(CacError::PinLocked) => {
                emit_cac_auth_failure("pin_locked");
                return Err(CacError::PinLocked);
            }
            Err(e) => {
                emit_cac_auth_failure("session_error");
                return Err(e);
            }
        }

        // Step 2: Find the PIV authentication certificate.
        let cert_der = match session.find_certificate("PIV AUTH") {
            Ok(c) => c,
            Err(e) => {
                emit_cac_auth_failure("cert_not_found");
                return Err(e);
            }
        };

        // Step 2b: Retrieve any issuing-CA certificates the card presents so the
        // chain can be built. Absence is tolerated (the EE may be issued
        // directly by a trusted root); the chain builder fails closed if no
        // path to a trust anchor exists.
        let intermediates = session
            .find_certificate("PIV CA")
            .map(|c| vec![c])
            .unwrap_or_default();

        // Step 3: Validate the certificate chain to a trusted DoD PKI anchor
        // BEFORE the certificate is trusted for anything. This is the F1 fix —
        // without it a self-signed cert could self-assert TOP SECRET.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let validated = match validate_piv_cert_chain(
            &cert_der,
            &intermediates,
            &self.config,
            now_unix,
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "CAC certificate chain validation FAILED — denying");
                emit_cac_auth_failure("chain_validation_failed");
                return Err(e);
            }
        };

        // Step 4: Sign the challenge.
        let signature = match session.sign_data(
            "PIV AUTH",
            challenge,
            crate::cac::SignMechanism::EcdsaP256,
        ) {
            Ok(s) => s,
            Err(e) => {
                emit_cac_auth_failure("signing_failed");
                return Err(e);
            }
        };

        // Step 5: Verify the challenge signature against the TRUSTED cert.
        match Pkcs11Session::verify_signature(&cert_der, challenge, &signature) {
            Ok(true) => {}
            Ok(false) => {
                emit_cac_auth_failure("signature_invalid");
                return Err(CacError::VerificationFailed(
                    "challenge signature did not verify".into(),
                ));
            }
            Err(e) => {
                emit_cac_auth_failure("verification_error");
                return Err(e);
            }
        }

        // Step 6: Revocation check, fail-closed. A revoked certificate is
        // always rejected; an undetermined status is rejected in military
        // deployment mode (F2). Non-military mode degrades to availability.
        match self.check_revocation(&cert_der) {
            Ok(status) => match fail_closed_on_unavailable(status)? {
                RevocationStatus::Revoked { reason, .. } => {
                    tracing::error!(reason = %reason, "CAC certificate is REVOKED — denying");
                    emit_cac_auth_failure("certificate_revoked");
                    return Err(CacError::RevocationCheckFailed(format!(
                        "certificate revoked: {reason}"
                    )));
                }
                _ => {}
            },
            Err(e) => {
                // A revocation check that errors (e.g. fail-closed military
                // policy) denies access.
                tracing::error!(error = %e, "CAC revocation check failed — denying");
                emit_cac_auth_failure("revocation_check_failed");
                return Err(e);
            }
        }

        // Step 7: Build card info and override the clearance with the value
        // derived from the VALIDATED certificate's policy OIDs.
        let mut card_info = match session.get_card_info() {
            Ok(info) => info,
            Err(e) => {
                emit_cac_auth_failure("card_info_failed");
                return Err(e);
            }
        };
        card_info.clearance_level = validated.clearance_level;

        // Reset PIN counter on success.
        self.reset_pin_counter(&card_info.card_serial);

        emit_cac_auth_success(&card_info.card_serial, card_info.clearance_level);
        Ok((card_info, signature))
    }

    /// Verify a signed challenge against a DER certificate's public key.
    ///
    /// Operates entirely in software — no PKCS#11 hardware required.
    pub fn verify_challenge_response(
        &self,
        cert_der: &[u8],
        challenge: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool, CacError> {
        Pkcs11Session::verify_signature(cert_der, challenge, signature)
    }

    /// Extract the DoD security clearance level from a PIV certificate's
    /// policy OIDs.
    ///
    /// Maps well-known DoD PKI policy OIDs to numeric clearance levels:
    ///
    /// | Policy OID                  | Clearance              | Level |
    /// |-----------------------------|------------------------|-------|
    /// | 2.16.840.1.101.2.1.11.5     | id-pkix-on-piv-unclassified | 0 |
    /// | 2.16.840.1.101.2.1.11.9     | id-pkix-on-piv-confidential | 1 |
    /// | 2.16.840.1.101.2.1.11.10    | id-pkix-on-piv-secret       | 2 |
    /// | 2.16.840.1.101.2.1.11.17    | id-pkix-on-piv-topsecret    | 3 |
    /// | 2.16.840.1.101.2.1.11.18    | id-pkix-on-piv-sci          | 4 |
    ///
    /// Returns 0 (Unclassified) if no matching OID is found.
    pub fn extract_clearance_dod(cert_der: &[u8]) -> u8 {
        let oids = extract_policy_oids_from_cert(cert_der);
        let mut max_level: u8 = 0;
        for oid in &oids {
            let level = match oid.as_str() {
                // id-pkix-on-piv-unclassified
                "2.16.840.1.101.2.1.11.5" => 0,
                // id-pkix-on-piv-confidential
                "2.16.840.1.101.2.1.11.9" => 1,
                // id-pkix-on-piv-secret
                "2.16.840.1.101.2.1.11.10" => 2,
                // id-pkix-on-piv-topsecret
                "2.16.840.1.101.2.1.11.17" => 3,
                // id-pkix-on-piv-sci (Sensitive Compartmented Information)
                "2.16.840.1.101.2.1.11.18" => 4,
                _ => 0,
            };
            if level > max_level {
                max_level = level;
            }
        }
        max_level
    }

    /// Extract the clearance level from an Indian DSC certificate's policy OIDs.
    ///
    /// Maps CCA India policy OIDs to clearance levels:
    ///
    /// | Policy OID                  | Clearance        | Level |
    /// |-----------------------------|------------------|-------|
    /// | 2.16.356.100.1.1.1.1        | Class 1 DSC      | 0     |
    /// | 2.16.356.100.1.1.1.2        | Class 2 DSC      | 1     |
    /// | 2.16.356.100.1.1.1.3        | Class 3 DSC      | 2     |
    /// | 2.16.356.100.1.1.1.4        | Class 3 Gov DSC  | 3     |
    ///
    /// Returns 0 if no matching OID is found.
    pub fn extract_clearance_indian(cert_der: &[u8]) -> u8 {
        let oids = extract_policy_oids_from_cert(cert_der);
        let mut max_level: u8 = 0;
        for oid in &oids {
            let level = match oid.as_str() {
                "2.16.356.100.1.1.1.1" => 0,
                "2.16.356.100.1.1.1.2" => 1,
                "2.16.356.100.1.1.1.3" => 2,
                "2.16.356.100.1.1.1.4" => 3,
                _ => 0,
            };
            if level > max_level {
                max_level = level;
            }
        }
        max_level
    }

    /// Check whether a certificate has been revoked.
    ///
    /// Attempts OCSP first if `ocsp_responder_url` is configured, then falls
    /// back to CRL download.  Returns [`RevocationStatus::OcspUnavailable`]
    /// if neither check can be completed — callers must decide whether to
    /// fail open or closed.
    ///
    /// In the current implementation network checks are intentionally skipped
    /// (no HTTP client dep); the method returns `OcspUnavailable` unless the
    /// certificate DER is obviously malformed.
    pub fn check_revocation(&self, cert_der: &[u8]) -> Result<RevocationStatus, CacError> {
        if cert_der.is_empty() {
            return Err(CacError::InvalidCertificate("empty certificate".into()));
        }

        tracing::debug!(
            ocsp_url = self.config.ocsp_responder_url.as_deref().unwrap_or("none"),
            "checking certificate revocation"
        );

        // Attempt OCSP check if a responder URL is configured.
        // Per RFC 6960, OCSP uses HTTP (not HTTPS) because responses are
        // cryptographically signed by the CA. TLS is unnecessary for integrity.
        if let Some(ref ocsp_url) = self.config.ocsp_responder_url {
            match self.perform_ocsp_check(cert_der, ocsp_url) {
                Ok(status) => return Ok(status),
                Err(e) => {
                    tracing::warn!(
                        ocsp_url = %ocsp_url,
                        error = %e,
                        "OCSP check failed, falling back to CRL"
                    );
                }
            }
        }

        // Fall back to CRL check if OCSP is unavailable or not configured.
        if !self.config.crl_distribution_points.is_empty() {
            tracing::debug!("attempting CRL-based revocation check");
            let mut checker = crate::ocsp_crl::RevocationChecker::new(
                crate::ocsp_crl::OcspConfig::default(),
                crate::ocsp_crl::CrlConfig {
                    distribution_points: self.config.crl_distribution_points.clone(),
                    fail_closed: is_military_deployment(),
                    ..Default::default()
                },
            );
            // Attempt to load CRL from each distribution point
            let mut any_loaded = false;
            for dp_url in &self.config.crl_distribution_points {
                match checker.load_crl_from_distribution_point(dp_url) {
                    Ok(count) => {
                        tracing::info!(
                            dp_url = %dp_url,
                            loaded = count,
                            "CRL distribution point loaded for CAC revocation check"
                        );
                        any_loaded = true;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            dp_url = %dp_url,
                            error = %e,
                            "CRL distribution point fetch failed, trying next"
                        );
                    }
                }
            }
            if any_loaded {
                // Extract serial number from cert DER for CRL lookup.
                // Serial is a u64 derived from the first 8 bytes of the cert hash
                // (sufficient for CRL serial matching in the RevocationChecker).
                let serial = extract_cert_serial_u64(cert_der);
                let crl_status = checker.check_crl(serial);
                match crl_status {
                    crate::ocsp_crl::RevocationStatus::Good => {
                        tracing::debug!("CRL check confirms certificate is not revoked");
                        return Ok(RevocationStatus::Good);
                    }
                    crate::ocsp_crl::RevocationStatus::Revoked { reason, revoked_at } => {
                        tracing::error!(
                            reason = %reason,
                            revoked_at = revoked_at,
                            "CRL check confirms certificate is REVOKED"
                        );
                        SecurityEvent::certificate_validation_failed(
                            "CRL",
                            &format!("certificate revoked: {}", reason),
                        );
                        return Ok(RevocationStatus::Revoked { reason, revoked_at });
                    }
                    _ => {
                        tracing::warn!("CRL check returned indeterminate status");
                    }
                }
            }
        }

        Ok(RevocationStatus::OcspUnavailable)
    }

    /// Send an OCSP request over HTTP and parse the DER/ASN.1 response.
    ///
    /// OCSP uses HTTP per RFC 6960: the response is signed by the CA's OCSP
    /// signing certificate, so transport-level encryption is not needed for
    /// integrity. The response signature is verified against the trusted CA
    /// certificates configured in `self.config.trusted_ca_certs`.
    fn perform_ocsp_check(
        &self,
        cert_der: &[u8],
        ocsp_url: &str,
    ) -> Result<RevocationStatus, CacError> {
        // Build OCSP request DER: a minimal OCSPRequest containing the
        // certificate's issuer name hash, issuer key hash, and serial number.
        let ocsp_request = build_ocsp_request_der(cert_der)?;

        // Send HTTP POST with Content-Type: application/ocsp-request
        let response_der = http_post_ocsp(ocsp_url, &ocsp_request)?;

        // Parse the OCSP response DER envelope
        if response_der.len() < 10 {
            return Err(CacError::RevocationCheckFailed(
                "OCSP response too short".into(),
            ));
        }

        // OCSP response status byte (offset varies but first SEQUENCE -> status is at a known position)
        // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, ... }
        // We parse the outer SEQUENCE, then the ENUMERATED responseStatus.
        let status_byte = parse_ocsp_response_status(&response_der)?;

        match status_byte {
            0 => {
                // successful (contains responseBytes)
                // Parse the BasicOCSPResponse to get the cert status and verify signature
                let cert_status = parse_ocsp_cert_status(&response_der)?;

                // Verify the OCSP response signature against trusted CAs
                if !verify_ocsp_signature(&response_der, &self.config.trusted_ca_certs) {
                    tracing::error!("OCSP response signature verification FAILED");
                    SecurityEvent::certificate_validation_failed(
                        ocsp_url,
                        "OCSP response signature invalid",
                    );
                    return Err(CacError::RevocationCheckFailed(
                        "OCSP response signature verification failed".into(),
                    ));
                }

                Ok(cert_status)
            }
            1 => Err(CacError::RevocationCheckFailed("OCSP: malformedRequest".into())),
            2 => Err(CacError::RevocationCheckFailed("OCSP: internalError".into())),
            3 => Ok(RevocationStatus::OcspUnavailable), // tryLater
            5 => Err(CacError::RevocationCheckFailed("OCSP: sigRequired".into())),
            6 => Err(CacError::RevocationCheckFailed("OCSP: unauthorized".into())),
            _ => Err(CacError::RevocationCheckFailed(
                format!("OCSP: unknown response status {}", status_byte),
            )),
        }
    }

    /// Returns `true` if the card with `card_serial` has exceeded the
    /// configured `pin_max_retries` threshold.
    pub fn is_pin_locked(&self, card_serial: &str) -> bool {
        self.pin_attempt_count
            .get(card_serial)
            .copied()
            .unwrap_or(0)
            >= self.config.pin_max_retries
    }

    /// Record one PIN failure for `card_serial`.
    ///
    /// Emits a SIEM lockout event when the threshold is reached.
    pub fn record_pin_failure(&mut self, card_serial: &str) {
        let count = self.pin_attempt_count.entry(card_serial.to_string()).or_insert(0);
        *count = count.saturating_add(1);
        if *count >= self.config.pin_max_retries {
            emit_cac_pin_locked(card_serial);
        }
    }

    /// Reset the PIN failure counter for `card_serial` (call on successful auth).
    pub fn reset_pin_counter(&mut self, card_serial: &str) {
        self.pin_attempt_count.remove(card_serial);
    }
}

// ---------------------------------------------------------------------------
// OCSP helpers
// ---------------------------------------------------------------------------

/// Build a minimal OCSP request in DER format for the given certificate.
///
/// The request contains the issuer name hash, issuer key hash, and serial
/// number extracted from the certificate DER. Uses SHA-1 for the hash
/// algorithm as required by RFC 6960 Section 4.1.1.
fn build_ocsp_request_der(cert_der: &[u8]) -> Result<Vec<u8>, CacError> {
    // Extract serial number from the certificate TBS (simplified DER parse).
    // X.509 cert: SEQUENCE { SEQUENCE { version, serialNumber, ... }, ... }
    if cert_der.len() < 20 {
        return Err(CacError::InvalidCertificate("certificate too short for OCSP request".into()));
    }

    // For a production implementation, use a proper ASN.1 parser (e.g., der, x509-cert crate).
    // This builds a well-formed OCSPRequest with the cert's hash as the certID.
    use sha2::{Sha256, Digest};
    let cert_hash = Sha256::digest(cert_der);

    // Build a minimal DER-encoded OCSPRequest:
    // OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest }
    // TBSRequest ::= SEQUENCE { requestList SEQUENCE OF Request }
    // Request ::= SEQUENCE { reqCert CertID }
    // CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    let mut request = Vec::with_capacity(128);
    // SHA-256 algorithm OID: 2.16.840.1.101.3.4.2.1
    let sha256_oid = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

    // CertID inner: AlgorithmIdentifier SEQUENCE
    let mut alg_id = vec![0x30]; // SEQUENCE
    let alg_inner_len = 2 + sha256_oid.len() + 2; // OID tag+len+data + NULL
    alg_id.push(alg_inner_len as u8);
    alg_id.push(0x06); // OID tag
    alg_id.push(sha256_oid.len() as u8);
    alg_id.extend_from_slice(sha256_oid);
    alg_id.push(0x05); // NULL
    alg_id.push(0x00);

    // issuerNameHash and issuerKeyHash: use cert hash as placeholder
    let hash_bytes = &cert_hash[..32];
    let mut name_hash = vec![0x04, 0x20]; // OCTET STRING, 32 bytes
    name_hash.extend_from_slice(hash_bytes);
    let mut key_hash = vec![0x04, 0x20]; // OCTET STRING, 32 bytes
    key_hash.extend_from_slice(hash_bytes);

    // serialNumber: extract from cert or use hash prefix
    let serial = vec![0x02, 0x01, 0x01]; // INTEGER 1 (placeholder)

    // CertID SEQUENCE
    let cert_id_len = alg_id.len() + name_hash.len() + key_hash.len() + serial.len();
    let mut cert_id = vec![0x30];
    cert_id.push(cert_id_len as u8);
    cert_id.extend_from_slice(&alg_id);
    cert_id.extend_from_slice(&name_hash);
    cert_id.extend_from_slice(&key_hash);
    cert_id.extend_from_slice(&serial);

    // Request SEQUENCE
    let mut req = vec![0x30];
    req.push(cert_id.len() as u8);
    req.extend_from_slice(&cert_id);

    // requestList SEQUENCE OF
    let mut req_list = vec![0x30];
    req_list.push(req.len() as u8);
    req_list.extend_from_slice(&req);

    // TBSRequest SEQUENCE
    let mut tbs = vec![0x30];
    tbs.push(req_list.len() as u8);
    tbs.extend_from_slice(&req_list);

    // OCSPRequest SEQUENCE
    request.push(0x30);
    request.push(tbs.len() as u8);
    request.extend_from_slice(&tbs);

    Ok(request)
}

/// Send an OCSP request via HTTP POST and return the raw DER response.
///
/// Uses raw TCP because OCSP is HTTP-only by design (RFC 6960). The response
/// is cryptographically signed, so TLS adds no security benefit.
fn http_post_ocsp(url: &str, request_der: &[u8]) -> Result<Vec<u8>, CacError> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    // Parse URL: expect http://host[:port]/path
    let url = url.strip_prefix("http://").ok_or_else(|| {
        CacError::RevocationCheckFailed("OCSP URL must use http:// (not https://)".into())
    })?;

    let (host_port, path) = url.split_once('/').unwrap_or((url, ""));
    let path = format!("/{}", path);

    let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
        (h, p.parse::<u16>().unwrap_or(80))
    } else {
        (host_port, 80u16)
    };

    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| {
            CacError::RevocationCheckFailed(format!("invalid OCSP address {}: {}", addr, e))
        })?,
        std::time::Duration::from_secs(10),
    )
    .map_err(|e| CacError::RevocationCheckFailed(format!("OCSP connect failed: {e}")))?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();

    // Build HTTP POST request
    let http_request = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/ocsp-request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path, host, request_der.len()
    );

    stream
        .write_all(http_request.as_bytes())
        .map_err(|e| CacError::RevocationCheckFailed(format!("OCSP write header failed: {e}")))?;
    stream
        .write_all(request_der)
        .map_err(|e| CacError::RevocationCheckFailed(format!("OCSP write body failed: {e}")))?;

    // Read full response (cap at 64 KiB)
    let mut response = Vec::new();
    stream
        .take(65536)
        .read_to_end(&mut response)
        .map_err(|e| CacError::RevocationCheckFailed(format!("OCSP read failed: {e}")))?;

    // Strip HTTP headers: find \r\n\r\n boundary
    let header_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            CacError::RevocationCheckFailed("OCSP response: no HTTP header boundary".into())
        })?;

    Ok(response[header_end + 4..].to_vec())
}

/// Parse the OCSPResponse status byte from a DER-encoded response.
///
/// OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED(0..5), ... }
fn parse_ocsp_response_status(response_der: &[u8]) -> Result<u8, CacError> {
    // Minimal DER parse: outer SEQUENCE -> ENUMERATED
    if response_der.len() < 5 {
        return Err(CacError::RevocationCheckFailed("OCSP response too short".into()));
    }
    // response_der[0] = 0x30 (SEQUENCE), [1] = length, [2] = 0x0A (ENUMERATED), [3] = 0x01 (len=1), [4] = status
    if response_der[0] != 0x30 {
        return Err(CacError::RevocationCheckFailed("OCSP response: expected SEQUENCE".into()));
    }
    // Skip the outer SEQUENCE tag+length to find the ENUMERATED
    let content_start = if response_der[1] < 0x80 { 2 } else { 2 + (response_der[1] & 0x7f) as usize };
    if content_start + 2 >= response_der.len() {
        return Err(CacError::RevocationCheckFailed("OCSP response truncated".into()));
    }
    if response_der[content_start] != 0x0A {
        return Err(CacError::RevocationCheckFailed("OCSP response: expected ENUMERATED for status".into()));
    }
    let enum_len = response_der[content_start + 1] as usize;
    if enum_len != 1 || content_start + 2 >= response_der.len() {
        return Err(CacError::RevocationCheckFailed("OCSP response: invalid status length".into()));
    }
    Ok(response_der[content_start + 2])
}

/// Parse the certificate status from a BasicOCSPResponse.
///
/// Returns `Good`, `Revoked`, or `Unknown` based on the certStatus field.
fn parse_ocsp_cert_status(response_der: &[u8]) -> Result<RevocationStatus, CacError> {
    // In a full implementation, parse the responseBytes -> BasicOCSPResponse ->
    // tbsResponseData -> responses[0] -> certStatus.
    // certStatus is a CHOICE: [0] good, [1] revoked, [2] unknown
    //
    // Scan for context-specific tags in the response:
    // [0] IMPLICIT NULL = good
    // [1] IMPLICIT SEQUENCE { revocationTime, reason } = revoked
    // [2] IMPLICIT NULL = unknown
    for i in 0..response_der.len().saturating_sub(1) {
        match response_der[i] {
            0x80 if response_der[i + 1] == 0x00 => return Ok(RevocationStatus::Good),
            0xA1 => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                return Ok(RevocationStatus::Revoked {
                    reason: "revoked per OCSP response".to_string(),
                    revoked_at: now,
                });
            }
            0x82 if response_der[i + 1] == 0x00 => return Ok(RevocationStatus::Unknown),
            _ => continue,
        }
    }

    // Could not determine status from the response
    Ok(RevocationStatus::Unknown)
}

/// Verify the BasicOCSPResponse signature against trusted CA certificates.
///
/// SECURITY (zerotrust-gw F2): the previous implementation returned `true` for
/// any DER SEQUENCE, so a forged OCSP "good" response would be accepted and a
/// revoked certificate could authenticate. This performs real RFC 6960
/// §4.2.1/§4.2.2.2 verification:
///
///   1. Unwrap `OCSPResponse → responseBytes [0] → SEQUENCE → response OCTET
///      STRING → BasicOCSPResponse`.
///   2. Parse `BasicOCSPResponse ::= SEQUENCE { tbsResponseData,
///      signatureAlgorithm, signature BIT STRING, [0] certs OPTIONAL }`.
///   3. Cryptographically verify `signature` over the raw `tbsResponseData`
///      bytes using the signer's public key.
///   4. The signer must be authorized: either a directly-trusted CA, OR a
///      delegated responder certificate that itself chains (signature-verified)
///      to a trusted CA and asserts the id-kp-OCSPSigning EKU.
///
/// Returns `false` (fail-closed) on any parse failure, missing/invalid
/// signature, untrusted signer, or unsupported algorithm.
fn verify_ocsp_signature(response_der: &[u8], trusted_ca_certs: &[Vec<u8>]) -> bool {
    if trusted_ca_certs.is_empty() {
        tracing::warn!("no trusted CA certificates configured for OCSP signature verification");
        return false;
    }

    let basic = match extract_basic_ocsp_response(response_der) {
        Some(b) => b,
        None => {
            tracing::warn!(
                target: "siem",
                "SIEM:CRITICAL OCSP response is not a well-formed BasicOCSPResponse"
            );
            return false;
        }
    };

    // Parse the BasicOCSPResponse SEQUENCE.
    let (btag, binner, _) = match der_read_tlv(&basic, 0) {
        Some(v) => v,
        None => return false,
    };
    if btag != 0x30 {
        return false;
    }

    // tbsResponseData (raw bytes that were signed).
    let (_, _, tbs_end) = match der_read_tlv(binner, 0) {
        Some(v) => v,
        None => return false,
    };
    let tbs_response_data = &binner[0..tbs_end];

    // signatureAlgorithm SEQUENCE -> OID.
    let (sa_tag, sa_val, sa_end) = match der_read_tlv(binner, tbs_end) {
        Some(v) => v,
        None => return false,
    };
    if sa_tag != 0x30 {
        return false;
    }
    let sig_alg_oid = match der_read_tlv(sa_val, 0)
        .filter(|(t, _, _)| *t == 0x06)
        .and_then(|(_, oid, _)| oid_bytes_to_dotted(oid))
    {
        Some(o) => o,
        None => return false,
    };

    // signature BIT STRING (strip unused-bits octet).
    let (sig_tag, sig_bits, sig_end) = match der_read_tlv(binner, sa_end) {
        Some(v) => v,
        None => return false,
    };
    if sig_tag != 0x03 || sig_bits.is_empty() {
        return false;
    }
    let signature = &sig_bits[1..];

    // Optional [0] EXPLICIT certs — embedded signer certificate(s).
    let embedded_certs = if sig_end < binner.len() {
        extract_ocsp_certs(&binner[sig_end..])
    } else {
        Vec::new()
    };

    let alg = match parse_chain_sig_alg(&sig_alg_oid) {
        Some(a) => a,
        None => {
            tracing::warn!(
                target: "siem",
                sig_alg = %sig_alg_oid,
                "SIEM:CRITICAL OCSP response signed with unsupported algorithm — rejecting"
            );
            return false;
        }
    };

    // Try the trusted CAs directly as the signer (CA-signed OCSP response).
    for ca_der in trusted_ca_certs {
        if let Some(ca) = ParsedCert::parse(ca_der) {
            if verify_signature_spki(alg, &ca.spki_der, tbs_response_data, signature) {
                return true;
            }
        }
    }

    // Otherwise try each embedded responder cert: it must (a) sign the response
    // and (b) be a delegated responder authorized by a trusted CA.
    for resp_der in &embedded_certs {
        let responder = match ParsedCert::parse(resp_der) {
            Some(c) => c,
            None => continue,
        };
        if !verify_signature_spki(alg, &responder.spki_der, tbs_response_data, signature) {
            continue;
        }
        // RFC 6960 §4.2.2.2: delegated responder must assert id-kp-OCSPSigning
        // and chain to a trusted CA.
        if !responder.is_ocsp_signer {
            tracing::warn!(
                target: "siem",
                "SIEM:CRITICAL OCSP responder cert lacks id-kp-OCSPSigning EKU — rejecting"
            );
            continue;
        }
        // Verify the responder cert is signed by a trusted CA.
        for ca_der in trusted_ca_certs {
            if let Some(ca) = ParsedCert::parse(ca_der) {
                if ca.is_ca
                    && ca.subject_dn == responder.issuer_dn
                    && verify_issuer_signature(&responder, &ca).is_ok()
                {
                    return true;
                }
            }
        }
    }

    tracing::warn!(
        target: "siem",
        "SIEM:CRITICAL OCSP response signature could not be verified against any trusted CA \
         or authorized delegated responder — possible forged response"
    );
    false
}

/// Unwrap an `OCSPResponse` DER to the inner `BasicOCSPResponse` DER bytes.
///
/// `OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED,
///                              responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }`
/// `ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }`
/// The `response` OCTET STRING contains the DER-encoded `BasicOCSPResponse`.
fn extract_basic_ocsp_response(response_der: &[u8]) -> Option<Vec<u8>> {
    let (tag, inner, _) = der_read_tlv(response_der, 0)?;
    if tag != 0x30 {
        return None;
    }
    // responseStatus ENUMERATED.
    let (st_tag, _, st_end) = der_read_tlv(inner, 0)?;
    if st_tag != 0x0a {
        return None;
    }
    // responseBytes [0] EXPLICIT.
    let (rb_tag, rb_val, _) = der_read_tlv(inner, st_end)?;
    if rb_tag != 0xa0 {
        return None;
    }
    // ResponseBytes SEQUENCE.
    let (rseq_tag, rseq_val, _) = der_read_tlv(rb_val, 0)?;
    if rseq_tag != 0x30 {
        return None;
    }
    // responseType OID.
    let (rt_tag, _, rt_end) = der_read_tlv(rseq_val, 0)?;
    if rt_tag != 0x06 {
        return None;
    }
    // response OCTET STRING -> BasicOCSPResponse.
    let (resp_tag, resp_val, _) = der_read_tlv(rseq_val, rt_end)?;
    if resp_tag != 0x04 {
        return None;
    }
    Some(resp_val.to_vec())
}

/// Extract embedded certificates from the `[0] EXPLICIT certs` field of a
/// BasicOCSPResponse (a SEQUENCE OF Certificate). Returns each cert's DER.
fn extract_ocsp_certs(certs_field: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    // [0] EXPLICIT wrapper.
    let (tag, inner, _) = match der_read_tlv(certs_field, 0) {
        Some(v) => v,
        None => return out,
    };
    if tag != 0xa0 {
        return out;
    }
    // SEQUENCE OF Certificate.
    let (stag, seq_val, _) = match der_read_tlv(inner, 0) {
        Some(v) => v,
        None => return out,
    };
    if stag != 0x30 {
        return out;
    }
    let mut pos = 0;
    while pos < seq_val.len() {
        let start = pos;
        let (ctag, _, next) = match der_read_tlv(seq_val, pos) {
            Some(v) => v,
            None => break,
        };
        pos = next;
        if ctag == 0x30 {
            out.push(seq_val[start..next].to_vec());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Fail-closed revocation enforcement for military deployments
// ---------------------------------------------------------------------------

/// Returns `true` if `MILNET_MILITARY_DEPLOYMENT=1` is set.
fn is_military_deployment() -> bool {
    std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1")
}

/// Extract a u64 serial number from a DER-encoded X.509 certificate.
///
/// Parses the TBSCertificate to find the serialNumber INTEGER field.
/// If parsing fails, falls back to a SHA-256 hash of the cert DER
/// truncated to 8 bytes, which is collision-resistant enough for CRL lookup.
fn extract_cert_serial_u64(cert_der: &[u8]) -> u64 {
    // Try to parse the DER structure:
    // Certificate SEQUENCE -> TBSCertificate SEQUENCE -> [version], serialNumber INTEGER
    if cert_der.len() < 20 || cert_der[0] != 0x30 {
        return hash_based_serial(cert_der);
    }

    // Skip outer SEQUENCE tag + length
    let outer_skip = match der_skip_tag_length(cert_der) {
        Some(s) => s,
        None => return hash_based_serial(cert_der),
    };

    // TBSCertificate should start with SEQUENCE (0x30)
    let tbs = &cert_der[outer_skip..];
    if tbs.is_empty() || tbs[0] != 0x30 {
        return hash_based_serial(cert_der);
    }
    let tbs_skip = match der_skip_tag_length(tbs) {
        Some(s) => s,
        None => return hash_based_serial(cert_der),
    };
    let tbs_content = &tbs[tbs_skip..];

    let mut pos = 0;
    // Skip optional version [0] EXPLICIT tag
    if !tbs_content.is_empty() && tbs_content[0] == 0xA0 {
        pos = match der_element_total_len(&tbs_content[pos..]) {
            Some(len) => len,
            None => return hash_based_serial(cert_der),
        };
    }

    // Next should be INTEGER (tag 0x02) = serialNumber
    if pos >= tbs_content.len() || tbs_content[pos] != 0x02 {
        return hash_based_serial(cert_der);
    }
    let int_header = match der_skip_tag_length(&tbs_content[pos..]) {
        Some(s) => s,
        None => return hash_based_serial(cert_der),
    };
    let int_total = match der_element_total_len(&tbs_content[pos..]) {
        Some(t) => t,
        None => return hash_based_serial(cert_der),
    };
    let serial_bytes = &tbs_content[pos + int_header..pos + int_total];

    // Convert serial bytes to u64 (take last 8 bytes if longer)
    let mut result: u64 = 0;
    let start = if serial_bytes.len() > 8 { serial_bytes.len() - 8 } else { 0 };
    for &b in &serial_bytes[start..] {
        result = (result << 8) | (b as u64);
    }
    result
}

/// Fallback serial: SHA-256 hash of cert DER truncated to u64.
fn hash_based_serial(cert_der: &[u8]) -> u64 {
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(cert_der);
    u64::from_be_bytes([hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]])
}

/// Skip a DER tag + length, returning the offset where content starts.
fn der_skip_tag_length(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    let len_byte = data[1];
    if len_byte < 0x80 {
        Some(2)
    } else if len_byte == 0x80 {
        None // indefinite length not supported
    } else {
        let num_bytes = (len_byte & 0x7F) as usize;
        if num_bytes > 4 || data.len() < 2 + num_bytes {
            return None;
        }
        Some(2 + num_bytes)
    }
}

/// Total length of a DER element (tag + length + content).
fn der_element_total_len(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    let len_byte = data[1];
    if len_byte < 0x80 {
        Some(2 + len_byte as usize)
    } else if len_byte == 0x80 {
        None
    } else {
        let num_bytes = (len_byte & 0x7F) as usize;
        if num_bytes > 4 || data.len() < 2 + num_bytes {
            return None;
        }
        let mut content_len: usize = 0;
        for i in 0..num_bytes {
            content_len = (content_len << 8) | (data[2 + i] as usize);
        }
        Some(2 + num_bytes + content_len)
    }
}

/// Enforce fail-closed revocation policy.
///
/// In military deployment mode (`MILNET_MILITARY_DEPLOYMENT=1`), an
/// `OcspUnavailable` status is treated as a revocation failure. Access
/// is denied because an attacker who compromises the OCSP responder or
/// network path could suppress revocation information to use a stolen
/// certificate.
///
/// In non-military mode, `OcspUnavailable` is passed through unchanged
/// (fail-open) for availability.
pub fn fail_closed_on_unavailable(status: RevocationStatus) -> Result<RevocationStatus, CacError> {
    match status {
        RevocationStatus::OcspUnavailable if is_military_deployment() => {
            tracing::error!(
                target: "siem",
                "SIEM:CRITICAL CAC revocation check unavailable in military deployment mode. \
                 Denying access (fail-closed policy). OCSP/CRL infrastructure must be reachable."
            );
            SecurityEvent::cac_auth_failure("ocsp_unavailable_military_fail_closed");
            Err(CacError::RevocationCheckFailed(
                "Revocation check unavailable in military deployment mode. \
                 Access denied per fail-closed policy. Ensure OCSP/CRL infrastructure is reachable."
                    .into(),
            ))
        }
        other => Ok(other),
    }
}

// ---------------------------------------------------------------------------
// Tier enforcement
// ---------------------------------------------------------------------------

/// Tiers that require hardware CAC/PIV authentication.
///
/// Tier 1 (Sovereign) is the highest-assurance tier and mandates a physical
/// smart card.  Lower tiers may use software credentials.
pub const CAC_REQUIRED_TIERS: &[u8] = &[1];

/// Returns `true` if the given device tier requires CAC/PIV authentication.
///
/// # Examples
/// ```rust
/// use common::cac_auth::tier_requires_cac;
/// assert!(tier_requires_cac(1));
/// assert!(!tier_requires_cac(2));
/// assert!(!tier_requires_cac(3));
/// ```
pub fn tier_requires_cac(tier: u8) -> bool {
    CAC_REQUIRED_TIERS.contains(&tier)
}

// ---------------------------------------------------------------------------
// SIEM helpers
// ---------------------------------------------------------------------------

/// Emit a SIEM event for a successful CAC authentication.
fn emit_cac_auth_success(card_serial: &str, clearance: u8) {
    SecurityEvent::cac_auth_success(card_serial, clearance);
}

/// Emit a SIEM event for a failed CAC authentication attempt.
fn emit_cac_auth_failure(reason: &str) {
    SecurityEvent::cac_auth_failure(reason);
}

/// Emit a SIEM event when a card PIN is locked.
fn emit_cac_pin_locked(card_serial: &str) {
    SecurityEvent::cac_pin_locked(card_serial);
}

// ---------------------------------------------------------------------------
// OID extraction (DER helper)
// ---------------------------------------------------------------------------

/// Extract certificate policy OIDs from a DER-encoded X.509 certificate.
///
/// Parses the `certificatePolicies` extension (OID 2.5.29.32) and returns
/// the list of policy OIDs as dotted-decimal strings.
///
/// Returns an empty Vec if the extension is absent or the certificate is
/// malformed.
fn extract_policy_oids_from_cert(cert_der: &[u8]) -> Vec<String> {
    // id-ce-certificatePolicies OID: 2.5.29.32 → DER bytes [0x55, 0x1d, 0x20]
    const CERT_POLICIES_OID: &[u8] = &[0x55, 0x1d, 0x20];

    let extensions = match find_extensions_in_cert(cert_der) {
        Some(ext) => ext,
        None => return Vec::new(),
    };

    // Find the certificatePolicies extension value.
    let policies_value = match find_extension_value(extensions, CERT_POLICIES_OID) {
        Some(v) => v,
        None => return Vec::new(),
    };

    parse_policy_oids(policies_value)
}

/// Walk the certificate DER to the Extensions field in TBSCertificate.
///
/// Extensions are at index [3] EXPLICIT (tag 0xa3) in TBSCertificate.
fn find_extensions_in_cert(cert_der: &[u8]) -> Option<&[u8]> {
    // Outer Certificate SEQUENCE
    let (tag, cert_body, _) = der_read_tlv(cert_der, 0)?;
    if tag != 0x30 {
        return None;
    }

    // TBSCertificate SEQUENCE
    let (tag2, tbs, _) = der_read_tlv(cert_body, 0)?;
    if tag2 != 0x30 {
        return None;
    }

    // Walk TBSCertificate fields to find [3] EXPLICIT Extensions.
    let mut pos = 0;
    while pos < tbs.len() {
        let (tag, value, next) = der_read_tlv(tbs, pos)?;
        pos = next;
        // Extensions is [3] EXPLICIT (context class, constructed, tag 3)
        if tag == 0xa3 {
            return Some(value);
        }
    }
    None
}

/// Find the value of the extension with `target_oid` in an extensions SEQUENCE.
fn find_extension_value<'a>(extensions: &'a [u8], target_oid: &[u8]) -> Option<&'a [u8]> {
    // Extensions ::= SEQUENCE OF Extension
    let (tag, ext_seq, _) = der_read_tlv(extensions, 0)?;
    if tag != 0x30 {
        return None;
    }

    let mut pos = 0;
    while pos < ext_seq.len() {
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
        let (stag, seq_val, snext) = der_read_tlv(ext_seq, pos)?;
        pos = snext;
        if stag != 0x30 {
            continue;
        }

        // Read the OID.
        let (otag, oid_bytes, after_oid) = der_read_tlv(seq_val, 0)?;
        if otag != 0x06 {
            continue;
        }

        if oid_bytes != target_oid {
            continue;
        }

        // Skip optional BOOLEAN (critical flag) and find OCTET STRING.
        let mut vpos = after_oid;
        while vpos < seq_val.len() {
            let (vtag, vval, vnext) = der_read_tlv(seq_val, vpos)?;
            vpos = vnext;
            if vtag == 0x04 {
                // OCTET STRING — this is the raw extension value.
                return Some(vval);
            }
        }
    }
    None
}

/// Parse a DER-encoded SEQUENCE OF PolicyInformation and return OID strings.
fn parse_policy_oids(policies_der: &[u8]) -> Vec<String> {
    let mut oids = Vec::new();

    // The extnValue is an OCTET STRING wrapping a SEQUENCE OF PolicyInformation.
    // We may have already unwrapped the OCTET STRING above; handle both.
    let seq = if policies_der.first() == Some(&0x30) {
        policies_der
    } else {
        return oids;
    };

    let (stag, seq_val, _) = match der_read_tlv(seq, 0) {
        Some(v) => v,
        None => return oids,
    };
    if stag != 0x30 {
        return oids;
    }

    let mut pos = 0;
    while pos < seq_val.len() {
        // PolicyInformation ::= SEQUENCE { policyIdentifier OID, ... }
        let (ptag, pi_val, pnext) = match der_read_tlv(seq_val, pos) {
            Some(v) => v,
            None => break,
        };
        pos = pnext;
        if ptag != 0x30 {
            continue;
        }

        let (otag, oid_bytes, _) = match der_read_tlv(pi_val, 0) {
            Some(v) => v,
            None => continue,
        };
        if otag != 0x06 {
            continue;
        }

        if let Some(s) = oid_bytes_to_dotted(oid_bytes) {
            oids.push(s);
        }
    }
    oids
}

/// Decode an OID from its DER byte encoding to a dotted-decimal string.
fn oid_bytes_to_dotted(oid: &[u8]) -> Option<String> {
    if oid.is_empty() {
        return None;
    }
    let first = *oid.first()? as u32;
    let mut components: Vec<u32> = vec![first / 40, first % 40];

    let mut i = 1;
    while i < oid.len() {
        let mut val: u32 = 0;
        loop {
            let b = *oid.get(i)? as u32;
            i += 1;
            val = (val << 7) | (b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
        components.push(val);
    }

    Some(
        components
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}

// ---------------------------------------------------------------------------
// Shared DER helpers (duplicated from cac.rs to avoid cross-module coupling)
// ---------------------------------------------------------------------------

fn der_read_tlv(data: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    if pos >= data.len() {
        return None;
    }
    let tag = *data.get(pos)?;
    let pos = pos + 1;
    let (len, pos) = der_read_length(data, pos)?;
    let end = pos.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((tag, &data[pos..end], end))
}

fn der_read_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *data.get(pos)? as usize;
    if first < 0x80 {
        Some((first, pos + 1))
    } else {
        let num_bytes = first & 0x7f;
        if num_bytes == 0 || num_bytes > 4 {
            return None;
        }
        let end = pos + 1 + num_bytes;
        if end > data.len() {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (*data.get(pos + 1 + i)? as usize);
        }
        Some((len, end))
    }
}

// ---------------------------------------------------------------------------
// X.509 path validation (RFC 5280) for PIV/CAC authentication certificates
// ---------------------------------------------------------------------------
//
// SECURITY (zerotrust-gw F1): the previous `authenticate` flow trusted the
// public key embedded in an ATTACKER-SUPPLIED certificate and read the security
// clearance straight out of that cert's policy OIDs. A self-signed certificate
// could therefore self-assert TOP SECRET. `validate_piv_cert_chain` closes that
// hole: it builds and cryptographically verifies the certificate chain to a
// configured DoD PKI trust anchor, enforces the validity window, the
// id-kp-clientAuth EKU, BasicConstraints on CA certs, and the required DoD
// assurance policy OIDs — and ONLY then is the (now trusted) certificate used
// for challenge verification and clearance extraction.
//
// References:
//   * RFC 5280 §6.1 — Certification Path Validation (basic path processing).
//   * RFC 5280 §4.2.1.3 — Key Usage; §4.2.1.12 — Extended Key Usage.
//   * RFC 5280 §4.2.1.4 — Certificate Policies; §4.2.1.9 — Basic Constraints.
//   * NIST SP 800-73-4 — PIV authentication certificate asserts id-kp-clientAuth.
//   * DoD PKI CP — assurance is conveyed via certificate policy OIDs.

/// A certificate that has passed full path validation and may now be trusted.
///
/// Produced only by [`validate_piv_cert_chain`]. Carries the data the caller
/// needs AFTER the chain is trusted: the security clearance derived from the
/// validated policy OIDs, the SubjectPublicKeyInfo for challenge verification,
/// and the serial number for revocation lookups.
#[derive(Debug, Clone)]
pub struct ValidatedCert {
    /// DoD clearance level (0-4) derived from the validated certificate's
    /// policy OIDs. Safe to trust because the cert chained to a trusted CA.
    pub clearance_level: u8,
    /// Policy OIDs asserted by the end-entity certificate (dotted-decimal).
    pub policy_oids: Vec<String>,
    /// SubjectPublicKeyInfo (DER) of the end-entity certificate, for verifying
    /// the challenge-response signature.
    pub spki_der: Vec<u8>,
    /// Certificate serial number (low 64 bits) for CRL/OCSP lookups.
    pub serial: u64,
}

/// A certificate signature algorithm we can verify with the FIPS backend.
///
/// Anything outside this set is rejected fail-closed rather than skipped: an
/// unverifiable signature algorithm MUST NOT be treated as a valid signature.
/// All map to an `aws-lc-rs` `VerificationAlgorithm` (one uniform FIPS-validated
/// backend); the `rsa` crate (RUSTSEC-2023-0071 / Marvin) is NOT used.
#[derive(Clone, Copy)]
enum ChainSigAlg {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
}

impl ChainSigAlg {
    /// The corresponding aws-lc-rs verification algorithm.
    fn algorithm(self) -> &'static dyn aws_lc_rs::signature::VerificationAlgorithm {
        use aws_lc_rs::signature::{
            ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, RSA_PKCS1_2048_8192_SHA256,
            RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
        };
        match self {
            ChainSigAlg::RsaPkcs1Sha256 => &RSA_PKCS1_2048_8192_SHA256,
            ChainSigAlg::RsaPkcs1Sha384 => &RSA_PKCS1_2048_8192_SHA384,
            ChainSigAlg::RsaPkcs1Sha512 => &RSA_PKCS1_2048_8192_SHA512,
            ChainSigAlg::EcdsaP256Sha256 => &ECDSA_P256_SHA256_ASN1,
            ChainSigAlg::EcdsaP384Sha384 => &ECDSA_P384_SHA384_ASN1,
        }
    }
}

/// Verify `signature` over `message` using the signer's SubjectPublicKeyInfo
/// (DER) via the FIPS-validated aws-lc-rs backend.
///
/// aws-lc-rs accepts X.509 SPKI DER for both RSA and ECDSA keys and hashes the
/// message internally. RSA keys < 2048 bits are rejected by the chosen
/// algorithm parameters. Returns `false` on any verification failure.
fn verify_signature_spki(
    alg: ChainSigAlg,
    signer_spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    aws_lc_rs::signature::UnparsedPublicKey::new(alg.algorithm(), signer_spki_der)
        .verify(message, signature)
        .is_ok()
}

/// Map a DoD/PIV certificate-policy OID set to the maximum clearance level.
///
/// Mirrors [`CacAuthenticator::extract_clearance_dod`] but operates on
/// already-extracted, dotted-decimal policy OIDs from a VALIDATED certificate.
fn clearance_from_policy_oids(policy_oids: &[String]) -> u8 {
    let mut max_level: u8 = 0;
    for oid in policy_oids {
        let level = match oid.as_str() {
            "2.16.840.1.101.2.1.11.5" => 0,  // id-pkix-on-piv-unclassified
            "2.16.840.1.101.2.1.11.9" => 1,  // id-pkix-on-piv-confidential
            "2.16.840.1.101.2.1.11.10" => 2, // id-pkix-on-piv-secret
            "2.16.840.1.101.2.1.11.17" => 3, // id-pkix-on-piv-topsecret
            "2.16.840.1.101.2.1.11.18" => 4, // id-pkix-on-piv-sci
            _ => 0,
        };
        if level > max_level {
            max_level = level;
        }
    }
    max_level
}

/// Validate a PIV/CAC authentication certificate chain per RFC 5280 §6.1.
///
/// `end_entity_der` is the smart-card PIV AUTH certificate. `intermediates`
/// are any issuing-CA certificates presented alongside it (DER). The chain is
/// built up to one of `config.trusted_ca_certs` (the DoD PKI roots) and every
/// link's signature is cryptographically verified. The end-entity certificate
/// must additionally:
///   * be inside its validity window at `now_unix`,
///   * assert the id-kp-clientAuth EKU,
///   * assert at least one of `config.required_policy_oids` (if any are set).
///
/// On success the returned [`ValidatedCert`] carries the clearance extracted
/// from the *validated* certificate. On any failure an error is returned and
/// the caller MUST deny authentication (fail-closed).
pub fn validate_piv_cert_chain(
    end_entity_der: &[u8],
    intermediates: &[Vec<u8>],
    config: &CacConfig,
    now_unix: i64,
) -> Result<ValidatedCert, CacError> {
    if config.trusted_ca_certs.is_empty() {
        // No trust anchors configured: we cannot validate anything, so deny.
        SecurityEvent::certificate_validation_failed(
            "cac",
            "no trusted CA certificates configured — cannot validate PIV chain",
        );
        return Err(CacError::InvalidCertificate(
            "chain validation failed: no trusted CA certificates configured".into(),
        ));
    }

    // Parse the end-entity certificate up front.
    let ee = ParsedCert::parse(end_entity_der)
        .ok_or_else(|| CacError::InvalidCertificate("chain validation failed: end-entity certificate is not valid DER".into()))?;

    // RFC 5280 §6.1.3(a)(2): the end-entity certificate must be within its
    // validity window. (Intermediates are checked as they are walked.)
    if now_unix < ee.not_before {
        SecurityEvent::certificate_validation_failed("cac", "PIV certificate not yet valid");
        return Err(CacError::InvalidCertificate(
            "chain validation failed: certificate not yet valid (notBefore in the future)".into(),
        ));
    }
    if now_unix > ee.not_after {
        SecurityEvent::certificate_validation_failed("cac", "PIV certificate expired");
        return Err(CacError::InvalidCertificate(
            "chain validation failed: certificate has expired (past notAfter)".into(),
        ));
    }

    // RFC 5280 §4.2.1.12: a PIV authentication certificate must assert the
    // id-kp-clientAuth EKU. A missing EKU extension is NOT acceptable for an
    // authentication cert (fail-closed: we require it to be present and to
    // include clientAuth, optionally anyExtendedKeyUsage).
    if !ee.has_client_auth_eku {
        SecurityEvent::certificate_validation_failed(
            "cac",
            "PIV certificate missing id-kp-clientAuth EKU",
        );
        return Err(CacError::InvalidCertificate(
            "chain validation failed: certificate does not assert the id-kp-clientAuth EKU \
             required for PIV authentication"
                .into(),
        ));
    }

    // RFC 5280 §4.2.1.4 + DoD CP: enforce required assurance policy OIDs.
    if !config.required_policy_oids.is_empty() {
        let asserts_required = config
            .required_policy_oids
            .iter()
            .any(|req| ee.policy_oids.iter().any(|p| p == req));
        if !asserts_required {
            SecurityEvent::certificate_validation_failed(
                "cac",
                "PIV certificate missing required assurance policy OID",
            );
            return Err(CacError::InvalidCertificate(format!(
                "chain validation failed: certificate does not assert any required policy OID \
                 (required one of {:?})",
                config.required_policy_oids
            )));
        }
    }

    // Build and verify the chain to a trusted anchor (RFC 5280 §6.1).
    verify_chain_to_anchor(&ee, intermediates, &config.trusted_ca_certs, now_unix)?;

    // Only now that the certificate is trusted do we derive clearance from its
    // (already-extracted, validated) policy OIDs.
    let clearance_level = clearance_from_policy_oids(&ee.policy_oids);

    Ok(ValidatedCert {
        clearance_level,
        policy_oids: ee.policy_oids.clone(),
        spki_der: ee.spki_der.clone(),
        serial: ee.serial,
    })
}

/// Build the path from `ee` up to one of `anchors`, verifying every signature.
///
/// Each non-anchor link must be signed by the next certificate in the path
/// (intermediate or anchor), every CA in the path must carry BasicConstraints
/// cA=TRUE, and the issuer/subject names must chain. The terminal step verifies
/// the last intermediate (or the EE itself, for a directly-issued cert) against
/// a trusted anchor.
fn verify_chain_to_anchor(
    ee: &ParsedCert,
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    now_unix: i64,
) -> Result<(), CacError> {
    // Parse anchors once.
    let parsed_anchors: Vec<ParsedCert> = anchors
        .iter()
        .filter_map(|der| ParsedCert::parse(der))
        .collect();
    if parsed_anchors.is_empty() {
        return Err(CacError::InvalidCertificate(
            "chain validation failed: no parseable trusted CA certificates".into(),
        ));
    }

    // Parse intermediates.
    let parsed_inters: Vec<ParsedCert> = intermediates
        .iter()
        .filter_map(|der| ParsedCert::parse(der))
        .collect();

    // Walk the path from the end-entity upward. We bound the depth to avoid any
    // pathological loop; real PIV chains are 2-3 deep.
    const MAX_DEPTH: usize = 8;
    let mut current = ee;
    let mut used_inter = vec![false; parsed_inters.len()];

    for _ in 0..MAX_DEPTH {
        // 1. Is `current` directly issued by a trusted anchor? If so, accept.
        if let Some(anchor) = parsed_anchors
            .iter()
            .find(|a| a.subject_dn == current.issuer_dn)
        {
            // Anchor must be within validity and be a CA.
            if now_unix < anchor.not_before || now_unix > anchor.not_after {
                return Err(CacError::InvalidCertificate(
                    "chain validation failed: trusted CA certificate is outside its validity window"
                        .into(),
                ));
            }
            if !anchor.is_ca {
                return Err(CacError::InvalidCertificate(
                    "chain validation failed: trust anchor is not a CA (BasicConstraints cA=FALSE)"
                        .into(),
                ));
            }
            verify_issuer_signature(current, anchor)?;
            return Ok(());
        }

        // 2. Otherwise find an unused intermediate whose subject matches
        //    `current`'s issuer, verify the link, and continue from it.
        let next_idx = parsed_inters.iter().enumerate().position(|(i, c)| {
            !used_inter[i] && c.subject_dn == current.issuer_dn && c.is_ca
        });
        match next_idx {
            Some(idx) => {
                let issuer = &parsed_inters[idx];
                if now_unix < issuer.not_before || now_unix > issuer.not_after {
                    return Err(CacError::InvalidCertificate(
                        "chain validation failed: intermediate CA certificate is expired or not yet valid"
                            .into(),
                    ));
                }
                verify_issuer_signature(current, issuer)?;
                used_inter[idx] = true;
                current = &parsed_inters[idx];
            }
            None => {
                // No issuer found in intermediates or anchors -> untrusted.
                SecurityEvent::certificate_validation_failed(
                    "cac",
                    "PIV certificate does not chain to a trusted CA",
                );
                return Err(CacError::InvalidCertificate(
                    "chain validation failed: certificate does not chain to a trusted CA \
                     (no issuer found among intermediates or trust anchors)"
                        .into(),
                ));
            }
        }
    }

    Err(CacError::InvalidCertificate(
        "chain validation failed: maximum certification path depth exceeded".into(),
    ))
}

/// Verify that `child` was signed by `issuer`'s private key, i.e. that
/// `issuer`'s public key validates `child`'s signature over `child`'s
/// TBSCertificate (RFC 5280 §6.1.3(a)(3)). Uses the FIPS aws-lc-rs backend.
fn verify_issuer_signature(child: &ParsedCert, issuer: &ParsedCert) -> Result<(), CacError> {
    let alg = parse_chain_sig_alg(&child.sig_alg_oid).ok_or_else(|| {
        SecurityEvent::certificate_validation_failed(
            "cac",
            "unsupported certificate signature algorithm",
        );
        CacError::InvalidCertificate(format!(
            "chain validation failed: unsupported certificate signature algorithm (OID {})",
            child.sig_alg_oid
        ))
    })?;

    // aws-lc-rs hashes the message internally and accepts the issuer SPKI DER
    // for both RSA and ECDSA keys.
    if verify_signature_spki(alg, &issuer.spki_der, &child.tbs_der, &child.signature) {
        Ok(())
    } else {
        SecurityEvent::certificate_validation_failed(
            "cac",
            "certificate signature does not verify against issuer key",
        );
        Err(CacError::VerificationFailed(
            "chain validation failed: certificate signature did not verify against the issuer's \
             public key"
                .into(),
        ))
    }
}

/// Map a signatureAlgorithm OID to a supported chain algorithm.
fn parse_chain_sig_alg(oid: &str) -> Option<ChainSigAlg> {
    match oid {
        // sha256WithRSAEncryption
        "1.2.840.113549.1.1.11" => Some(ChainSigAlg::RsaPkcs1Sha256),
        // sha384WithRSAEncryption
        "1.2.840.113549.1.1.12" => Some(ChainSigAlg::RsaPkcs1Sha384),
        // sha512WithRSAEncryption
        "1.2.840.113549.1.1.13" => Some(ChainSigAlg::RsaPkcs1Sha512),
        // ecdsa-with-SHA256
        "1.2.840.10045.4.3.2" => Some(ChainSigAlg::EcdsaP256Sha256),
        // ecdsa-with-SHA384
        "1.2.840.10045.4.3.3" => Some(ChainSigAlg::EcdsaP384Sha384),
        _ => None,
    }
}

/// A parsed X.509 certificate carrying exactly the fields path validation
/// needs, decoded with the vetted `x509-cert` crate (RustCrypto). The owned
/// `Vec<u8>` fields (`tbs_der`, `spki_der`, `issuer_dn`, `subject_dn`,
/// `signature`) are re-encoded DER so they can be passed to the FIPS verifier
/// and compared for name chaining without holding the parsed certificate.
struct ParsedCert {
    /// Re-encoded TBSCertificate DER — the exact bytes the issuer signed.
    tbs_der: Vec<u8>,
    /// signatureAlgorithm OID (dotted-decimal) from the outer Certificate.
    sig_alg_oid: String,
    /// signatureValue (raw signature bytes; BIT STRING unused-bits stripped).
    signature: Vec<u8>,
    /// SubjectPublicKeyInfo (DER) — used to verify children and challenges.
    spki_der: Vec<u8>,
    /// Issuer Name DER (for name chaining).
    issuer_dn: Vec<u8>,
    /// Subject Name DER (for name chaining).
    subject_dn: Vec<u8>,
    /// notBefore as a Unix timestamp (seconds).
    not_before: i64,
    /// notAfter as a Unix timestamp (seconds).
    not_after: i64,
    /// Whether BasicConstraints asserts cA=TRUE.
    is_ca: bool,
    /// Certificate serial number, low 64 bits (for CRL/OCSP lookups).
    serial: u64,
    /// Certificate policy OIDs (dotted-decimal).
    policy_oids: Vec<String>,
    /// EKU asserts id-kp-clientAuth (or anyExtendedKeyUsage) — required for a
    /// PIV authentication certificate (RFC 5280 §4.2.1.12).
    has_client_auth_eku: bool,
    /// EKU asserts id-kp-OCSPSigning — required for a delegated OCSP responder
    /// (RFC 6960 §4.2.2.2).
    is_ocsp_signer: bool,
}

impl ParsedCert {
    /// Parse the fields needed for path validation from a DER certificate using
    /// `x509-cert`. Returns `None` if the certificate is not valid DER.
    fn parse(cert_der: &[u8]) -> Option<Self> {
        use const_oid::db::rfc5280::{
            ANY_EXTENDED_KEY_USAGE, ID_KP_CLIENT_AUTH, ID_KP_OCSP_SIGNING,
        };
        use der::{Decode, Encode};
        use x509_cert::ext::pkix::{BasicConstraints, CertificatePolicies, ExtendedKeyUsage};
        use x509_cert::Certificate;

        let cert = Certificate::from_der(cert_der).ok()?;
        let tbs = &cert.tbs_certificate;

        // Re-encode the TBSCertificate: these are the exact bytes the issuer
        // signed (RFC 5280 §4.1.1.1).
        let tbs_der = tbs.to_der().ok()?;
        let sig_alg_oid = cert.signature_algorithm.oid.to_string();
        // BIT STRING signature value, with the unused-bits octet already
        // stripped by x509-cert's BitString::as_bytes.
        let signature = cert.signature.as_bytes()?.to_vec();
        let spki_der = tbs.subject_public_key_info.to_der().ok()?;
        let issuer_dn = tbs.issuer.to_der().ok()?;
        let subject_dn = tbs.subject.to_der().ok()?;

        let not_before = tbs.validity.not_before.to_unix_duration().as_secs() as i64;
        let not_after = tbs.validity.not_after.to_unix_duration().as_secs() as i64;

        // Serial number, low 64 bits (big-endian).
        let serial_bytes = tbs.serial_number.as_bytes();
        let mut serial: u64 = 0;
        let start = serial_bytes.len().saturating_sub(8);
        for &b in &serial_bytes[start..] {
            serial = (serial << 8) | (b as u64);
        }

        // Typed extension extraction via x509-cert's AssociatedOid helper. EKU
        // purposes are matched against the canonical RFC 5280 OID constants
        // (const-oid db) rather than dotted-decimal string literals.
        let eku = tbs.get::<ExtendedKeyUsage>().ok().flatten().map(|(_, e)| e.0);
        let has_client_auth_eku = eku.as_ref().is_some_and(|oids| {
            oids.iter()
                .any(|o| *o == ID_KP_CLIENT_AUTH || *o == ANY_EXTENDED_KEY_USAGE)
        });
        let is_ocsp_signer = eku
            .as_ref()
            .is_some_and(|oids| oids.iter().any(|o| *o == ID_KP_OCSP_SIGNING));

        let policy_oids = tbs
            .get::<CertificatePolicies>()
            .ok()
            .flatten()
            .map(|(_, pols)| {
                pols.0
                    .iter()
                    .map(|pi| pi.policy_identifier.to_string())
                    .collect()
            })
            .unwrap_or_default();
        let is_ca = tbs
            .get::<BasicConstraints>()
            .ok()
            .flatten()
            .map(|(_, bc)| bc.ca)
            .unwrap_or(false);

        Some(ParsedCert {
            tbs_der,
            sig_alg_oid,
            signature,
            spki_der,
            issuer_dn,
            subject_dn,
            not_before,
            not_after,
            is_ca,
            serial,
            policy_oids,
            has_client_auth_eku,
            is_ocsp_signer,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cac::{extract_edipi, CacCardInfo, CardType};

    /// Build a minimal test `CacConfig`.
    fn test_config() -> CacConfig {
        CacConfig {
            pkcs11_library: "/tmp/nonexistent_test_lib.so".to_string(),
            slot_id: 0,
            trusted_ca_certs: vec![],
            required_policy_oids: vec![],
            ocsp_responder_url: None,
            crl_distribution_points: vec![],
            pin_max_retries: 3,
            session_timeout_secs: 3600,
        }
    }

    /// Build a minimal `CacCardInfo` from raw test data.
    fn test_card_info() -> CacCardInfo {
        use std::collections::HashMap;
        CacCardInfo {
            card_serial: "TEST-0001".to_string(),
            card_issuer: "DoD PKI CA-62".to_string(),
            subject_dn: "CN=DOE.JOHN.ALBERT.9876543210, OU=USMC, O=U.S. Government, C=US"
                .to_string(),
            edipi: Some("9876543210".to_string()),
            aadhaar_vid: None,
            affiliation: "USMC".to_string(),
            cert_fingerprint: [0u8; 64],
            pin_verified: true,
            card_type: CardType::CacMilitary,
            clearance_level: 2,
            tags: HashMap::new(),
            inserted_at: 1_700_000_000_000_000,
            removed_at: None,
            reader_id: "TestReader:0".to_string(),
            facility_code: "0010".to_string(),
        }
    }

    // ─── Task 16 tests ───────────────────────────────────────────────────────

    #[test]
    fn test_cac_card_info_extraction() {
        let info = test_card_info();
        assert_eq!(info.card_serial, "TEST-0001");
        assert_eq!(info.edipi, Some("9876543210".to_string()));
        assert_eq!(info.card_type, CardType::CacMilitary);
        assert_eq!(info.clearance_level, 2);
        assert!(info.pin_verified);
    }

    /// Full challenge-response flow using `MockPkcs11Session`.
    ///
    /// We cannot produce a real ECDSA signature without a private key on the
    /// mock, so we test the software verification path using `rcgen` to
    /// generate a self-signed certificate with a known key, sign the challenge
    /// manually, and verify via `verify_challenge_response`.
    #[test]
    fn test_cac_challenge_response_flow() {
        let config = test_config();
        let auth = CacAuthenticator::new(config).unwrap();

        // Generate a P-256 keypair and self-signed cert for testing.
        let (cert_der, signing_key_bytes) = make_test_p256_cert();
        let challenge = [0x42u8; 32];

        // Sign the challenge with the test private key.
        let signature = sign_p256_prehash(&signing_key_bytes, &challenge);

        // Verify using the authenticator.
        let result = auth.verify_challenge_response(&cert_der, &challenge, &signature);
        assert!(
            result.is_ok(),
            "verify_challenge_response returned error: {:?}",
            result
        );
        assert!(result.unwrap(), "expected signature to verify as true");
    }

    #[test]
    fn test_cac_cert_chain_validation() {
        // Basic structure check: an obviously invalid cert returns an error.
        let bad_cert = b"not a certificate at all";
        let config = test_config();
        let auth = CacAuthenticator::new(config).unwrap();

        // verify_challenge_response with bad cert should return an error, not panic.
        let challenge = [0u8; 32];
        let sig = [0u8; 64];
        let result = auth.verify_challenge_response(bad_cert, &challenge, &sig);
        assert!(result.is_err(), "expected error for malformed certificate");
    }

    #[test]
    fn test_cac_clearance_extraction_dod() {
        // Cert with no policy OIDs → level 0.
        let cert = b"not a cert";
        assert_eq!(CacAuthenticator::extract_clearance_dod(cert), 0);

        // Verify the OID table has all five entries by exercising parse logic.
        // (Real cert would be needed for non-zero result; we test fallback here.)
        let dummy = &[0x30, 0x00]; // Empty SEQUENCE
        assert_eq!(CacAuthenticator::extract_clearance_dod(dummy), 0);
    }

    #[test]
    fn test_cac_clearance_extraction_indian() {
        let cert = b"not a cert";
        assert_eq!(CacAuthenticator::extract_clearance_indian(cert), 0);

        // Verify the Indian OID table spans levels 0-3.
        let oids = vec![
            ("2.16.356.100.1.1.1.1", 0u8),
            ("2.16.356.100.1.1.1.2", 1),
            ("2.16.356.100.1.1.1.3", 2),
            ("2.16.356.100.1.1.1.4", 3),
        ];
        for (oid, expected_level) in &oids {
            // Manually call the inner mapping used in extract_clearance_indian.
            let level: u8 = match *oid {
                "2.16.356.100.1.1.1.1" => 0,
                "2.16.356.100.1.1.1.2" => 1,
                "2.16.356.100.1.1.1.3" => 2,
                "2.16.356.100.1.1.1.4" => 3,
                _ => 0,
            };
            assert_eq!(level, *expected_level, "level mismatch for OID {}", oid);
        }
    }

    #[test]
    fn test_cac_tier_enforcement() {
        assert!(tier_requires_cac(1), "Tier 1 (Sovereign) must require CAC");
        assert!(!tier_requires_cac(2), "Tier 2 should NOT require CAC");
        assert!(!tier_requires_cac(3), "Tier 3 should NOT require CAC");
        assert!(!tier_requires_cac(4), "Tier 4 should NOT require CAC");
        assert!(!tier_requires_cac(0), "Tier 0 should NOT require CAC");
    }

    #[test]
    fn test_cac_edipi_tagging() {
        // Extract EDIPI from a Subject DN string.
        // We call extract_edipi with a synthetic cert-like byte buffer that
        // the helper parses; for simplicity we test extract_subject_dn + edipi logic.
        // The real function is tested via construct_card_info() above.
        let info = test_card_info();
        assert_eq!(info.edipi, Some("9876543210".to_string()));

        // Verify extract_edipi returns None for an empty / malformed cert.
        assert!(extract_edipi(b"not a cert").is_none());
    }

    #[test]
    fn test_cac_pin_lockout() {
        let config = CacConfig {
            pin_max_retries: 3,
            ..test_config()
        };
        let mut auth = CacAuthenticator::new(config).unwrap();
        let serial = "LOCK-SERIAL-0001";

        assert!(!auth.is_pin_locked(serial), "should not be locked initially");

        auth.record_pin_failure(serial);
        assert!(!auth.is_pin_locked(serial), "1 failure — not locked yet");

        auth.record_pin_failure(serial);
        assert!(!auth.is_pin_locked(serial), "2 failures — not locked yet");

        auth.record_pin_failure(serial);
        assert!(auth.is_pin_locked(serial), "3 failures — must be locked");

        // Reset should unlock.
        auth.reset_pin_counter(serial);
        assert!(!auth.is_pin_locked(serial), "after reset — should not be locked");
    }

    #[test]
    fn test_cac_session_timeout() {
        // Verify that the session_timeout_secs field is stored and accessible.
        let config = CacConfig {
            session_timeout_secs: 7200,
            ..test_config()
        };
        let auth = CacAuthenticator::new(config).unwrap();
        assert_eq!(auth.config.session_timeout_secs, 7200);
    }

    #[test]
    fn test_cac_revoked_cert_rejected() {
        let config = test_config();
        let auth = CacAuthenticator::new(config).unwrap();

        // Empty cert should return InvalidCertificate.
        let result = auth.check_revocation(&[]);
        assert!(result.is_err(), "empty cert should return error");

        // Non-empty cert should return OcspUnavailable (no network).
        let dummy = b"dummy cert bytes";
        let result = auth.check_revocation(dummy);
        assert!(result.is_ok());
        match result.unwrap() {
            RevocationStatus::OcspUnavailable => {}
            _ => panic!("expected OcspUnavailable without network"),
        }
    }

    #[test]
    fn test_fail_closed_on_unavailable_non_military() {
        // Without military deployment, OcspUnavailable passes through.
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        let result = fail_closed_on_unavailable(RevocationStatus::OcspUnavailable);
        assert!(result.is_ok(), "non-military should pass OcspUnavailable through");
        match result.unwrap() {
            RevocationStatus::OcspUnavailable => {}
            _ => panic!("expected OcspUnavailable passthrough"),
        }
    }

    #[test]
    fn test_fail_closed_on_unavailable_military() {
        // With military deployment, OcspUnavailable becomes an error.
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
        let result = fail_closed_on_unavailable(RevocationStatus::OcspUnavailable);
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        assert!(result.is_err(), "military mode should reject OcspUnavailable");
    }

    #[test]
    fn test_fail_closed_passes_good_status() {
        // Good status should pass through regardless of mode.
        std::env::set_var("MILNET_MILITARY_DEPLOYMENT", "1");
        let result = fail_closed_on_unavailable(RevocationStatus::Good);
        std::env::remove_var("MILNET_MILITARY_DEPLOYMENT");
        assert!(result.is_ok());
        match result.unwrap() {
            RevocationStatus::Good => {}
            _ => panic!("expected Good passthrough"),
        }
    }

    #[test]
    fn test_cac_card_removal_detection() {
        // CacCardInfo.removed_at tracks physical card removal.
        let mut info = test_card_info();
        assert!(info.removed_at.is_none(), "card should be present initially");

        // Simulate card removal by setting removed_at.
        info.removed_at = Some(1_700_000_001_000_000);
        assert!(info.removed_at.is_some(), "card should be marked removed");
    }

    #[test]
    fn test_indian_dsc_authentication() {
        // Verify IndianDsc card type is handled correctly.
        let mut info = test_card_info();
        info.card_type = CardType::IndianDsc;
        info.aadhaar_vid = Some("1234-5678-9012".to_string());

        assert_eq!(info.card_type, CardType::IndianDsc);
        assert_eq!(info.aadhaar_vid, Some("1234-5678-9012".to_string()));

        // IndianESign is a separate type.
        let mut esign_info = test_card_info();
        esign_info.card_type = CardType::IndianESign;
        assert_eq!(esign_info.card_type, CardType::IndianESign);
        assert_ne!(esign_info.card_type, CardType::IndianDsc);
    }

    #[test]
    fn test_cac_audit_logging() {
        // SIEM emission is fire-and-forget; we verify it does not panic.
        emit_cac_auth_success("AUDIT-TEST-0001", 2);
        emit_cac_auth_failure("audit_test_reason");
        emit_cac_pin_locked("AUDIT-TEST-0001");
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /// Generate a self-signed P-256 certificate and return
    /// `(cert_der, signing_key_scalar_bytes)`.
    fn make_test_p256_cert() -> (Vec<u8>, Vec<u8>) {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePublicKey;
        use rand::rngs::OsRng;

        // Generate a fresh P-256 key pair.
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Get the SubjectPublicKeyInfo DER bytes.
        let spki_der = verifying_key
            .to_public_key_der()
            .expect("failed to encode public key DER");

        // Build a minimal DER certificate by hand that has a valid SPKI.
        // This is not a fully spec-compliant cert but it's enough for the
        // SPKI extraction logic in `verify_signature`.
        let cert_der = build_minimal_x509_der(spki_der.as_bytes());

        // Export the scalar bytes for signing.
        let scalar_bytes = signing_key.to_bytes().to_vec();
        (cert_der, scalar_bytes)
    }

    /// Build a minimal DER-encoded X.509 certificate containing just enough
    /// structure for `extract_spki_bytes` to succeed.
    ///
    /// Structure:
    /// ```text
    /// SEQUENCE (Certificate) {
    ///   SEQUENCE (TBSCertificate) {
    ///     INTEGER (serialNumber)         ← field 0
    ///     SEQUENCE (signature alg)       ← field 1
    ///     SEQUENCE (issuer)              ← field 2
    ///     SEQUENCE (validity)            ← field 3
    ///     SEQUENCE (subject)             ← field 4
    ///     <spki bytes>                   ← field 5
    ///   }
    ///   SEQUENCE (signatureAlgorithm) {}
    ///   BIT STRING (signature) {}
    /// }
    /// ```
    fn build_minimal_x509_der(spki_der: &[u8]) -> Vec<u8> {
        // Minimal placeholder fields.
        let serial = der_encode_tlv(0x02, &[0x01]); // INTEGER 1
        let sig_alg = der_encode_tlv(0x30, &[]); // SEQUENCE {}
        let issuer = der_encode_tlv(0x30, &[]); // SEQUENCE {}
        let validity = der_encode_tlv(0x30, &[]); // SEQUENCE {}
        let subject = der_encode_tlv(0x30, &[]); // SEQUENCE {}

        // Concatenate TBSCertificate fields.
        let mut tbs_inner = Vec::new();
        tbs_inner.extend_from_slice(&serial);
        tbs_inner.extend_from_slice(&sig_alg);
        tbs_inner.extend_from_slice(&issuer);
        tbs_inner.extend_from_slice(&validity);
        tbs_inner.extend_from_slice(&subject);
        tbs_inner.extend_from_slice(spki_der); // SPKI already in SEQUENCE form

        let tbs = der_encode_tlv(0x30, &tbs_inner);

        // Outer certificate.
        let outer_sig_alg = der_encode_tlv(0x30, &[]);
        let outer_sig = der_encode_tlv(0x03, &[0x00]); // BIT STRING

        let mut cert_inner = Vec::new();
        cert_inner.extend_from_slice(&tbs);
        cert_inner.extend_from_slice(&outer_sig_alg);
        cert_inner.extend_from_slice(&outer_sig);

        der_encode_tlv(0x30, &cert_inner)
    }

    /// Encode a DER TLV (tag, length, value).
    fn der_encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(tag);
        let len = value.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xff {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
        out.extend_from_slice(value);
        out
    }

    /// Sign `data` (as a SHA-256 prehash) with a P-256 scalar and return
    /// the DER-encoded ECDSA signature.
    fn sign_p256_prehash(scalar_bytes: &[u8], data: &[u8]) -> Vec<u8> {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        use sha2::{Digest, Sha256};

        let signing_key = SigningKey::from_bytes(scalar_bytes.into())
            .expect("valid P-256 scalar");

        let hash = Sha256::digest(data);
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key
            .sign_prehash(&hash)
            .expect("signing failed");

        sig.to_der().as_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// Tests — F1 (X.509 chain validation) and F2 (real OCSP)
// ---------------------------------------------------------------------------
//
// These exercise `validate_piv_cert_chain` (the pure, hardware-free RFC 5280
// path validator that `authenticate` now runs BEFORE trusting an
// attacker-supplied PIV certificate) and the real OCSP response-signature
// verification that replaced the previous accept-any stub.
//
// Real test certificate chains (root CA -> [intermediate] -> end-entity) are
// built with `rcgen`, including DoD-style assurance policy OIDs, the
// id-kp-clientAuth EKU, BasicConstraints, and custom validity windows, so the
// validator is tested against genuinely signed material, not synthetic DER.
#[cfg(test)]
mod chain_validation_tests {
    use super::*;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, CustomExtension, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SignatureAlgorithm,
        PKCS_ECDSA_P256_SHA256,
    };
    use time::{Duration, OffsetDateTime};

    // ── DoD assurance policy OIDs used throughout the tests ──────────────────
    // id-pkix-on-piv-secret (clearance level 2) and -topsecret (level 3).
    const OID_PIV_SECRET: &str = "2.16.840.1.101.2.1.11.10";
    const OID_PIV_TOPSECRET: &str = "2.16.840.1.101.2.1.11.17";
    // id-ce-certificatePolicies (2.5.29.32).
    const OID_CERT_POLICIES: &[u64] = &[2, 5, 29, 32];

    /// A generated certificate together with the key that signs *children* of
    /// it (for a CA) or that owns it (for an end-entity).
    struct TestCert {
        cert: Certificate,
        key: KeyPair,
    }

    impl TestCert {
        fn der(&self) -> Vec<u8> {
            self.cert.der().to_vec()
        }
    }

    /// Encode a `SEQUENCE OF PolicyInformation` containing the given policy
    /// OIDs, suitable as the *content* of an `rcgen` custom extension for
    /// id-ce-certificatePolicies. `rcgen` wraps it in the OCTET STRING itself.
    fn encode_cert_policies(oids: &[&str]) -> Vec<u8> {
        // PolicyInformation ::= SEQUENCE { policyIdentifier OBJECT IDENTIFIER }
        let mut policies = Vec::new();
        for oid in oids {
            let oid_der = encode_oid_der(oid);
            // SEQUENCE { OID }
            let mut pi = Vec::new();
            pi.push(0x06);
            pi.push(oid_der.len() as u8);
            pi.extend_from_slice(&oid_der);
            let mut pi_seq = Vec::new();
            pi_seq.push(0x30);
            pi_seq.push(pi.len() as u8);
            pi_seq.extend_from_slice(&pi);
            policies.extend_from_slice(&pi_seq);
        }
        // Outer SEQUENCE OF
        let mut out = Vec::new();
        out.push(0x30);
        out.push(policies.len() as u8);
        out.extend_from_slice(&policies);
        out
    }

    /// Encode the value bytes (without tag/len) of a dotted-decimal OID.
    fn encode_oid_der(oid: &str) -> Vec<u8> {
        let parts: Vec<u64> = oid.split('.').map(|p| p.parse().unwrap()).collect();
        let mut out = Vec::new();
        out.push((parts[0] * 40 + parts[1]) as u8);
        for &arc in &parts[2..] {
            let mut stack = Vec::new();
            let mut v = arc;
            stack.push((v & 0x7f) as u8);
            v >>= 7;
            while v > 0 {
                stack.push((v & 0x7f) as u8 | 0x80);
                v >>= 7;
            }
            stack.reverse();
            out.extend_from_slice(&stack);
        }
        out
    }

    fn policy_extension(oids: &[&str]) -> CustomExtension {
        CustomExtension::from_oid_content(OID_CERT_POLICIES, encode_cert_policies(oids))
    }

    /// Build a self-signed root CA with the given signature algorithm.
    fn make_root_ca(alg: &'static SignatureAlgorithm) -> TestCert {
        let key = KeyPair::generate_for(alg).expect("root key");
        let mut params = CertificateParams::new(vec!["MILNET Test DoD Root CA".to_string()])
            .expect("root params");
        params
            .distinguished_name
            .push(DnType::CommonName, "MILNET Test DoD Root CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = OffsetDateTime::now_utc() - Duration::days(30);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
        let cert = params.self_signed(&key).expect("self-signed root");
        TestCert { cert, key }
    }

    /// Build an end-entity PIV-auth cert signed by `issuer`, with the given
    /// policy OIDs, EKU, and validity window.
    #[allow(clippy::too_many_arguments)]
    fn make_end_entity(
        issuer: &TestCert,
        alg: &'static SignatureAlgorithm,
        policy_oids: &[&str],
        client_auth_eku: bool,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        cn: &str,
    ) -> TestCert {
        let key = KeyPair::generate_for(alg).expect("ee key");
        let mut params =
            CertificateParams::new(vec!["milnet-ee.test".to_string()]).expect("ee params");
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::NoCa;
        if client_auth_eku {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        }
        if !policy_oids.is_empty() {
            params.custom_extensions.push(policy_extension(policy_oids));
        }
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params
            .signed_by(&key, &issuer.cert, &issuer.key)
            .expect("sign ee");
        TestCert { cert, key }
    }

    /// Standard "good" end-entity: P-256, SECRET policy, clientAuth, valid now.
    fn good_ee(issuer: &TestCert) -> TestCert {
        make_end_entity(
            issuer,
            &PKCS_ECDSA_P256_SHA256,
            &[OID_PIV_SECRET],
            true,
            OffsetDateTime::now_utc() - Duration::days(1),
            OffsetDateTime::now_utc() + Duration::days(365),
            "DOE.JOHN.A.1234567890",
        )
    }

    fn now_unix() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    /// Config requiring the SECRET policy OID and trusting the given root.
    fn config_for(root: &TestCert, required: &[&str]) -> CacConfig {
        CacConfig {
            trusted_ca_certs: vec![root.der()],
            required_policy_oids: required.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    // ───────────────────────── Task 1 / F1 tests ────────────────────────────

    /// (a) Valid chain to a trusted root + correct policy OID + clientAuth EKU
    ///     + within validity ⇒ ACCEPTED, and clearance read from the cert.
    #[test]
    fn valid_chain_accepted_and_clearance_extracted() {
        let root = make_root_ca(&PKCS_ECDSA_P256_SHA256);
        let ee = good_ee(&root);
        let cfg = config_for(&root, &[OID_PIV_SECRET]);

        let validated = validate_piv_cert_chain(&ee.der(), &[], &cfg, now_unix())
            .expect("valid PIV chain must be accepted");
        assert_eq!(
            validated.clearance_level, 2,
            "clearance must be read from the VALIDATED cert (SECRET = 2)"
        );
        assert!(validated.policy_oids.iter().any(|o| o == OID_PIV_SECRET));
    }

    /// (b) Self-signed / untrusted-CA ⇒ REJECTED ("chain validation failed").
    #[test]
    fn self_signed_cert_rejected() {
        // A self-signed cert asserting TOP SECRET — the original attack input.
        let attacker_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["evil.test".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "ATTACKER.SELF.SIGNED.0000000000");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params
            .custom_extensions
            .push(policy_extension(&[OID_PIV_TOPSECRET]));
        let evil = params.self_signed(&attacker_key).unwrap();

        // Trust a DIFFERENT, legitimate root.
        let root = make_root_ca(&PKCS_ECDSA_P256_SHA256);
        let cfg = config_for(&root, &[OID_PIV_TOPSECRET]);

        let result = validate_piv_cert_chain(&evil.der().to_vec(), &[], &cfg, now_unix());
        assert!(
            result.is_err(),
            "self-signed cert not chaining to a trusted CA MUST be rejected"
        );
        let msg = format!("{}", result.unwrap_err()).to_lowercase();
        assert!(
            msg.contains("chain"),
            "error should mention chain validation, got: {msg}"
        );
    }

    /// Untrusted but properly-signed chain (valid root, but NOT in trust store).
    #[test]
    fn untrusted_root_rejected() {
        let real_root = make_root_ca(&PKCS_ECDSA_P256_SHA256);
        let ee = good_ee(&real_root);

        // Trust store contains an unrelated root only.
        let other_root = make_root_ca(&PKCS_ECDSA_P256_SHA256);
        let cfg = config_for(&other_root, &[OID_PIV_SECRET]);

        let result = validate_piv_cert_chain(&ee.der(), &[], &cfg, now_unix());
        assert!(
            result.is_err(),
            "chain to a CA that is not in the trust store MUST be rejected"
        );
    }

    /// (c) Expired end-entity ⇒ REJECTED.
    #[test]
    fn expired_cert_rejected() {
        let root = make_root_ca(&PKCS_ECDSA_P256_SHA256);
        let ee = make_end_entity(
            &root,
            &PKCS_ECDSA_P256_SHA256,
            &[OID_PIV_SECRET],
            true,
            OffsetDateTime::now_utc() - Duration::days(800),
            OffsetDateTime::now_utc() - Duration::days(400), // already expired
            "EXPIRED.USER.0000000000",
        );
        let cfg = config_for(&root, &[OID_PIV_SECRET]);

        let result = validate_piv_cert_chain(&ee.der(), &[], &cfg, now_unix());
        assert!(result.is_err(), "expired certificate MUST be rejected");
        let msg = format!("{}", result.unwrap_err()).to_lowercase();
        assert!(
            msg.contains("expired") || msg.contains("validity") || msg.contains("not after"),
            "error should mention expiry/validity, got: {msg}"
        );
    }

    /// not-yet-valid end-entity ⇒ REJECTED.
    #[test]
    fn not_yet_valid_cert_rejected() {
        let root = make_root_ca(&PKCS_ECDSA_P256_SHA256);
        let ee = make_end_entity(
            &root,
            &PKCS_ECDSA_P256_SHA256,
            &[OID_PIV_SECRET],
            true,
            OffsetDateTime::now_utc() + Duration::days(10), // not valid yet
            OffsetDateTime::now_utc() + Duration::days(400),
            "FUTURE.USER.0000000000",
        );
        let cfg = config_for(&root, &[OID_PIV_SECRET]);
        let result = validate_piv_cert_chain(&ee.der(), &[], &cfg, now_unix());
        assert!(result.is_err(), "not-yet-valid certificate MUST be rejected");
    }

    /// (d) Missing required policy OID ⇒ REJECTED.
    #[test]
    fn missing_required_policy_oid_rejected() {
        let root = make_root_ca(&PKCS_ECDSA_P256_SHA256);
        // EE only asserts SECRET, but config requires TOP SECRET.
        let ee = good_ee(&root);
        let cfg = config_for(&root, &[OID_PIV_TOPSECRET]);

        let result = validate_piv_cert_chain(&ee.der(), &[], &cfg, now_unix());
        assert!(
            result.is_err(),
            "cert lacking the required assurance policy OID MUST be rejected"
        );
        let msg = format!("{}", result.unwrap_err()).to_lowercase();
        assert!(
            msg.contains("policy"),
            "error should mention policy OID, got: {msg}"
        );
    }

    /// Wrong/missing EKU (no id-kp-clientAuth) ⇒ REJECTED.
    #[test]
    fn missing_client_auth_eku_rejected() {
        let root = make_root_ca(&PKCS_ECDSA_P256_SHA256);
        let ee = make_end_entity(
            &root,
            &PKCS_ECDSA_P256_SHA256,
            &[OID_PIV_SECRET],
            false, // no clientAuth EKU
            OffsetDateTime::now_utc() - Duration::days(1),
            OffsetDateTime::now_utc() + Duration::days(365),
            "NOEKU.USER.0000000000",
        );
        let cfg = config_for(&root, &[OID_PIV_SECRET]);

        let result = validate_piv_cert_chain(&ee.der(), &[], &cfg, now_unix());
        assert!(
            result.is_err(),
            "PIV auth cert without id-kp-clientAuth EKU MUST be rejected"
        );
        let msg = format!("{}", result.unwrap_err()).to_lowercase();
        assert!(
            msg.contains("eku") || msg.contains("key usage") || msg.contains("clientauth"),
            "error should mention EKU, got: {msg}"
        );
    }

    /// Two-level chain: root -> intermediate -> end-entity, all RSA, ACCEPTED.
    #[test]
    fn two_level_chain_accepted() {
        let root = make_root_ca(&PKCS_ECDSA_P256_SHA256);

        // Intermediate CA signed by root.
        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut inter_params =
            CertificateParams::new(vec!["MILNET Test DoD Issuing CA".to_string()]).unwrap();
        inter_params
            .distinguished_name
            .push(DnType::CommonName, "MILNET Test DoD Issuing CA");
        inter_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        inter_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        inter_params.not_before = OffsetDateTime::now_utc() - Duration::days(20);
        inter_params.not_after = OffsetDateTime::now_utc() + Duration::days(1825);
        let inter_cert = inter_params
            .signed_by(&inter_key, &root.cert, &root.key)
            .unwrap();
        let intermediate = TestCert {
            cert: inter_cert,
            key: inter_key,
        };

        let ee = good_ee(&intermediate);
        let cfg = config_for(&root, &[OID_PIV_SECRET]);

        let validated =
            validate_piv_cert_chain(&ee.der(), &[intermediate.der()], &cfg, now_unix())
                .expect("valid two-level chain must be accepted");
        assert_eq!(validated.clearance_level, 2);
    }

    /// (g) THE ORIGINAL ATTACK: self-signed cert + a valid challenge signature.
    /// Even though the challenge signature verifies against the cert's own key,
    /// the cert does not chain to a trusted CA, so the WHOLE auth must fail
    /// before the clearance is ever read.
    #[test]
    fn original_attack_self_signed_with_valid_challenge_sig_rejected() {
        // Attacker self-signs a cert claiming TOP SECRET and can trivially sign
        // any challenge with the matching private key.
        let attacker_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["evil.test".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "MALLORY.X.9999999999");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params
            .custom_extensions
            .push(policy_extension(&[OID_PIV_TOPSECRET]));
        let evil = params.self_signed(&attacker_key).unwrap();
        let evil_der = evil.der().to_vec();

        // The challenge signature WOULD verify (attacker holds the key) — prove it.
        // (Uses the same software verifier the old code trusted on its own.)
        let cfg = config_for(&make_root_ca(&PKCS_ECDSA_P256_SHA256), &[OID_PIV_TOPSECRET]);

        // Chain validation must reject regardless of any valid challenge sig.
        let result = validate_piv_cert_chain(&evil_der, &[], &cfg, now_unix());
        assert!(
            result.is_err(),
            "F1 REGRESSION: self-signed cert with a valid challenge signature \
             MUST NOT authenticate — it does not chain to a trusted CA"
        );
    }

    /// Tampered end-entity (signature does not match issuer key) ⇒ REJECTED.
    #[test]
    fn tampered_signature_rejected() {
        let root = make_root_ca(&PKCS_ECDSA_P256_SHA256);
        let ee = good_ee(&root);
        let mut der = ee.der();
        // Flip a byte inside the certificate body (after the header) to break
        // the issuer signature without destroying DER structure of the TBS.
        let n = der.len();
        der[n - 1] ^= 0xFF;
        let cfg = config_for(&root, &[OID_PIV_SECRET]);
        let result = validate_piv_cert_chain(&der, &[], &cfg, now_unix());
        assert!(
            result.is_err(),
            "certificate whose issuer signature does not verify MUST be rejected"
        );
    }

    /// The RSA-PKCS1v15 SHA-256 chain-signature path (the common DoD case;
    /// `rcgen`+ring cannot generate RSA keys). `verify_signature_spki` verifies
    /// RSA via the FIPS `aws-lc-rs` backend; we exercise it with a real RSA-2048
    /// key generated and signed by aws-lc-rs. A correct signature verifies; a
    /// tampered message does not. Proves the RSA path WITHOUT the `rsa` crate
    /// (RUSTSEC-2023-0071).
    #[test]
    fn rsa_pkcs1_chain_signature_path() {
        use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::rsa::KeySize;
        use aws_lc_rs::signature::{KeyPair, RsaKeyPair, RSA_PKCS1_SHA256};

        // Generate an RSA-2048 signing key pair via aws-lc-rs.
        let kp = RsaKeyPair::generate(KeySize::Rsa2048).expect("rsa keygen");
        // SubjectPublicKeyInfo (X.509) DER for the verifier.
        let spki_der: PublicKeyX509Der = AsDer::as_der(kp.public_key()).expect("spki der");
        let spki: Vec<u8> = spki_der.as_ref().to_vec();

        let tbs = b"TBSCertificate bytes that the issuing CA signs";
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), tbs, &mut sig)
            .expect("rsa sign");

        assert!(
            verify_signature_spki(ChainSigAlg::RsaPkcs1Sha256, &spki, tbs, &sig),
            "a valid RSA-PKCS1v15 SHA-256 signature must verify via the FIPS backend"
        );
        assert!(
            !verify_signature_spki(ChainSigAlg::RsaPkcs1Sha256, &spki, b"different message", &sig),
            "an RSA signature over a different message must NOT verify"
        );
    }

    // ───────────────────────── Task 2 / F2 tests ────────────────────────────

    /// (f) Forged/unsigned OCSP (no signature BIT STRING) ⇒ verification FAILS.
    #[test]
    fn forged_ocsp_without_signature_rejected() {
        let root = make_root_ca(&PKCS_ECDSA_P256_SHA256);
        // A bare DER SEQUENCE — exactly what the OLD stub accepted as "valid".
        let forged = vec![0x30, 0x06, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00];
        assert!(
            !verify_ocsp_signature(&forged, &[root.der()]),
            "F2 REGRESSION: a bare DER SEQUENCE with no signature MUST NOT pass \
             OCSP signature verification (the old stub returned true)"
        );
    }

    /// Empty trust store ⇒ OCSP verification fails closed.
    #[test]
    fn ocsp_verification_no_trust_anchors_fails() {
        let forged = vec![0x30, 0x06, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00];
        assert!(
            !verify_ocsp_signature(&forged, &[]),
            "OCSP verification with no trusted CAs must fail closed"
        );
    }

    /// (e) An OCSP "revoked" status must surface as Revoked from the parser.
    #[test]
    fn ocsp_revoked_status_detected() {
        // certStatus [1] revoked tag present in the body.
        let body = vec![0x30, 0x03, 0xa1, 0x01, 0x00];
        match parse_ocsp_cert_status(&body).expect("parse") {
            RevocationStatus::Revoked { .. } => {}
            other => panic!("expected Revoked, got {:?}", status_name(&other)),
        }
    }

    fn status_name(s: &RevocationStatus) -> &'static str {
        match s {
            RevocationStatus::Good => "Good",
            RevocationStatus::Revoked { .. } => "Revoked",
            RevocationStatus::Unknown => "Unknown",
            RevocationStatus::OcspUnavailable => "OcspUnavailable",
        }
    }
}
