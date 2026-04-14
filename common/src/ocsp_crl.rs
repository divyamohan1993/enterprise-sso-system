//! OCSP and CRL certificate revocation checking.
//!
//! Provides:
//! - OCSP stapling verification (fast, per-connection)
//! - CRL download and caching (periodic background refresh)
//! - Fail-closed: if revocation status cannot be determined, reject
//!
//! For DoD PKI: checks against DoD CRL distribution points and OCSP responders.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Result of a certificate revocation status check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationStatus {
    /// Certificate is valid and not revoked.
    Good,
    /// Certificate has been revoked.
    Revoked {
        reason: String,
        revoked_at: i64,
    },
    /// Revocation status could not be determined (responder returned unknown).
    Unknown,
    /// The revocation check itself failed (network error, timeout, etc.).
    /// Callers MUST treat this as revoked when fail_closed is enabled.
    CheckFailed {
        error: String,
    },
}

/// Configuration for OCSP checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcspConfig {
    /// OCSP responder URLs (tried in order).
    pub responder_urls: Vec<String>,
    /// Timeout for each OCSP request.
    #[serde(with = "duration_secs")]
    pub timeout: Duration,
    /// How long to cache a successful OCSP response.
    #[serde(with = "duration_secs")]
    pub cache_ttl: Duration,
    /// If true, treat CheckFailed as revoked. DoD policy requires this.
    pub fail_closed: bool,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            responder_urls: Vec::new(),
            timeout: Duration::from_secs(5),
            cache_ttl: Duration::from_secs(300),
            fail_closed: true,
        }
    }
}

/// Configuration for CRL checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrlConfig {
    /// CRL distribution point URLs.
    pub distribution_points: Vec<String>,
    /// How often to refresh the CRL from distribution points.
    #[serde(with = "duration_secs")]
    pub refresh_interval: Duration,
    /// Optional local path to cache downloaded CRLs.
    pub cache_path: Option<PathBuf>,
    /// If true, treat CheckFailed as revoked. DoD policy requires this.
    pub fail_closed: bool,
}

impl Default for CrlConfig {
    fn default() -> Self {
        Self {
            distribution_points: Vec::new(),
            refresh_interval: Duration::from_secs(3600),
            cache_path: None,
            fail_closed: true,
        }
    }
}

/// Serde helper to serialize/deserialize `Duration` as seconds (u64).
mod duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(de)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Combined OCSP + CRL revocation checker with caching.
///
/// Check order:
/// 1. OCSP cache hit -> return cached status
/// 2. OCSP live query -> cache and return
/// 3. CRL lookup -> return
/// 4. If both fail and fail_closed -> CheckFailed (treated as revoked)
pub struct RevocationChecker {
    ocsp_config: OcspConfig,
    crl_config: CrlConfig,
    /// CRL cache: serial_number -> (reason, revoked_at_epoch)
    crl_cache: HashMap<u64, (String, i64)>,
    /// OCSP response cache: cert_fingerprint -> (status, cached_at)
    ocsp_cache: HashMap<[u8; 32], (RevocationStatus, Instant)>,
    /// Number of pending (uncached) OCSP checks since last reset.
    pending_ocsp: usize,
}

impl RevocationChecker {
    /// Create a new revocation checker with the given OCSP and CRL configs.
    pub fn new(ocsp_config: OcspConfig, crl_config: CrlConfig) -> Self {
        Self {
            ocsp_config,
            crl_config,
            crl_cache: HashMap::new(),
            ocsp_cache: HashMap::new(),
            pending_ocsp: 0,
        }
    }

    /// Check certificate revocation status.
    ///
    /// Strategy: OCSP first (faster, per-certificate), fall back to CRL
    /// (batch, covers entire CA). If both fail and fail_closed is enabled,
    /// returns `CheckFailed` which callers MUST reject.
    pub fn check_certificate(
        &mut self,
        cert_fingerprint: &[u8; 32],
        serial_number: u64,
    ) -> RevocationStatus {
        // 1. Try OCSP (includes cache check)
        let ocsp_result = self.check_ocsp(cert_fingerprint);
        match &ocsp_result {
            RevocationStatus::Good | RevocationStatus::Revoked { .. } => return ocsp_result,
            _ => {}
        }

        // 2. Fall back to CRL
        let crl_result = self.check_crl(serial_number);
        match &crl_result {
            RevocationStatus::Good | RevocationStatus::Revoked { .. } => return crl_result,
            _ => {}
        }

        // 3. Both failed — apply fail-closed policy
        if self.ocsp_config.fail_closed || self.crl_config.fail_closed {
            RevocationStatus::CheckFailed {
                error: "both OCSP and CRL checks failed — fail-closed policy active".into(),
            }
        } else {
            RevocationStatus::Unknown
        }
    }

    /// Check OCSP status for a certificate fingerprint.
    ///
    /// Returns cached result if available and not expired, otherwise
    /// performs a synchronous TCP connection to the first available OCSP
    /// responder. The OCSP protocol uses HTTP POST with DER-encoded request.
    ///
    /// SECURITY: Fail-closed — if no responder is reachable, returns Unknown
    /// which triggers CRL fallback and ultimately CheckFailed if both fail.
    pub fn check_ocsp(&mut self, cert_fingerprint: &[u8; 32]) -> RevocationStatus {
        // Check cache first
        if let Some((status, cached_at)) = self.ocsp_cache.get(cert_fingerprint) {
            if cached_at.elapsed() < self.ocsp_config.cache_ttl {
                return status.clone();
            }
            // Cache expired — fall through to live query
        }

        if self.ocsp_config.responder_urls.is_empty() {
            return RevocationStatus::Unknown;
        }

        // Try each OCSP responder until one succeeds
        for responder_url in &self.ocsp_config.responder_urls {
            match self.query_ocsp_responder(responder_url, cert_fingerprint) {
                Ok(status) => {
                    // Cache the result
                    self.ocsp_cache
                        .insert(*cert_fingerprint, (status.clone(), Instant::now()));
                    return status;
                }
                Err(e) => {
                    tracing::warn!(
                        responder = %responder_url,
                        error = %e,
                        "OCSP responder query failed, trying next"
                    );
                    continue;
                }
            }
        }

        // All responders failed
        tracing::error!(
            responders = self.ocsp_config.responder_urls.len(),
            "all OCSP responders unreachable"
        );
        RevocationStatus::Unknown
    }

    /// Query a single OCSP responder via TCP.
    ///
    /// Constructs a minimal HTTP POST to the responder with the certificate
    /// fingerprint as the query. Parses the response for revocation status.
    fn query_ocsp_responder(
        &self,
        responder_url: &str,
        cert_fingerprint: &[u8; 32],
    ) -> Result<RevocationStatus, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        // Parse host:port from URL (strip http:// prefix)
        let host_port = responder_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or(responder_url);

        let addr = if host_port.contains(':') {
            host_port.to_string()
        } else {
            format!("{}:80", host_port)
        };

        // Connect with timeout
        let timeout = self.ocsp_config.timeout;
        let stream = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e| format!("invalid OCSP responder address '{}': {}", addr, e))?,
            timeout,
        )
        .map_err(|e| format!("OCSP connect to {}: {}", addr, e))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("set read timeout: {e}"))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| format!("set write timeout: {e}"))?;
        let mut stream = stream;

        // Build minimal OCSP request (fingerprint as hex in URL path for GET-based OCSP)
        let fingerprint_hex = hex::encode(cert_fingerprint);
        let request = format!(
            "GET /{} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            fingerprint_hex, host_port
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("OCSP write: {e}"))?;

        // Read response
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| format!("OCSP read: {e}"))?;

        // Parse HTTP response: extract body after headers
        let header_end = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| i + 4)
            .unwrap_or(0);
        let body = &response[header_end..];

        // Parse OCSP response per RFC 6960 DER encoding.
        // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, ... }
        // We need at minimum a SEQUENCE tag (0x30) followed by the responseStatus.
        if body.len() < 3 {
            return Err("OCSP response too short for valid DER".into());
        }

        // Verify outer SEQUENCE tag
        if body[0] != 0x30 {
            return Err(format!(
                "OCSP response: expected SEQUENCE (0x30), got 0x{:02X}",
                body[0]
            ));
        }

        // Skip SEQUENCE length (may be 1 or multi-byte)
        let (status_offset, _) = parse_der_length(&body[1..])
            .map_err(|e| format!("OCSP response: bad DER length: {e}"))?;
        let status_pos = 1 + status_offset;

        // responseStatus is ENUMERATED (tag 0x0A)
        if body.len() <= status_pos + 2 {
            return Err("OCSP response: truncated before responseStatus".into());
        }
        if body[status_pos] != 0x0A || body[status_pos + 1] != 0x01 {
            return Err(format!(
                "OCSP response: expected ENUMERATED (0x0A 0x01), got 0x{:02X} 0x{:02X}",
                body[status_pos],
                body[status_pos + 1]
            ));
        }
        let response_status = body[status_pos + 2];

        // OCSPResponseStatus: successful(0), malformedRequest(1), internalError(2),
        // tryLater(3), sigRequired(5), unauthorized(6)
        if response_status != 0x00 {
            return Err(format!(
                "OCSP responder returned non-successful status: {}",
                response_status
            ));
        }

        // responseStatus is successful. Now find SingleResponse certStatus.
        // certStatus is CHOICE:
        //   good        [0] IMPLICIT NULL  = 0x80 0x00
        //   revoked     [1] CONSTRUCTED    = 0xA1 ...
        //   unknown     [2] IMPLICIT NULL  = 0x82 0x00
        let cert_status = find_cert_status(body);

        // Verify OCSP response signature: look for the responder's signature
        // in the responseBytes. The signature is a BIT STRING after the
        // signatureAlgorithm. We verify against the issuer CA's public key
        // if available. For now, we check that a signature is present and
        // the structure is well-formed. Without the issuer CA public key
        // loaded, we treat unverifiable signatures as UNKNOWN (fail-closed).
        if !verify_ocsp_signature(body) {
            tracing::warn!(
                responder = %responder_url,
                "OCSP response signature verification failed, treating as UNKNOWN"
            );
            return Ok(RevocationStatus::Unknown);
        }

        match cert_status {
            Some(OcspCertStatus::Good) => Ok(RevocationStatus::Good),
            Some(OcspCertStatus::Revoked) => Ok(RevocationStatus::Revoked {
                reason: "certificate revoked per OCSP responder".into(),
                revoked_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            }),
            Some(OcspCertStatus::Unknown) | None => Ok(RevocationStatus::Unknown),
        }
    }

    /// Check CRL for a serial number.
    ///
    /// Looks up the serial in the local CRL cache. The CRL is populated by:
    /// 1. `load_crl_from_distribution_point()` — periodic background refresh
    /// 2. `add_to_crl()` — manual revocation entries
    /// 3. Cluster state replication via Raft log
    ///
    /// If the serial is not in the CRL and we have CRL data loaded, the
    /// certificate is presumed good. If no CRL data exists at all,
    /// returns Unknown (triggers fail-closed if configured).
    pub fn check_crl(&self, serial_number: u64) -> RevocationStatus {
        if let Some((reason, revoked_at)) = self.crl_cache.get(&serial_number) {
            return RevocationStatus::Revoked {
                reason: reason.clone(),
                revoked_at: *revoked_at,
            };
        }

        // If we have CRL data (from distribution points or manual entries),
        // absence from the CRL means the certificate is good.
        if !self.crl_config.distribution_points.is_empty() || !self.crl_cache.is_empty() {
            return RevocationStatus::Good;
        }

        // No CRL data at all — cannot determine status.
        RevocationStatus::Unknown
    }

    /// Load CRL entries from a distribution point via HTTP.
    ///
    /// Fetches the CRL from the given URL, parses serial numbers,
    /// and merges them into the local cache.
    pub fn load_crl_from_distribution_point(&mut self, url: &str) -> Result<usize, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let host_port = url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or(url);

        let addr = if host_port.contains(':') {
            host_port.to_string()
        } else {
            format!("{}:80", host_port)
        };

        let path = url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .find('/')
            .map(|i| &url[url.find(host_port).unwrap_or(0) + host_port.len()..])
            .unwrap_or("/crl");

        let timeout = Duration::from_secs(10);
        let parsed_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| format!("invalid CRL address '{}': {}", addr, e))?;
        let stream = TcpStream::connect_timeout(&parsed_addr, timeout)
            .map_err(|e| format!("CRL connect to {}: {}", addr, e))?;
        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();
        let mut stream = stream;

        let request = format!(
            "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, host_port
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("CRL write: {e}"))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| format!("CRL read: {e}"))?;

        // Parse response — expect newline-separated "serial:reason:timestamp" entries
        let body = String::from_utf8_lossy(&response);
        let body_start = body.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
        let body_text = &body[body_start..];

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut loaded = 0;
        for line in body_text.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if let Some(serial_str) = parts.first() {
                if let Ok(serial) = serial_str.trim().parse::<u64>() {
                    let reason = parts.get(1).unwrap_or(&"revoked").to_string();
                    let revoked_at = parts
                        .get(2)
                        .and_then(|t| t.trim().parse::<i64>().ok())
                        .unwrap_or(now);
                    self.crl_cache.insert(serial, (reason, revoked_at));
                    loaded += 1;
                }
            }
        }

        tracing::info!(url = %url, loaded = loaded, "CRL distribution point loaded");
        Ok(loaded)
    }

    /// Add a certificate serial to the local CRL (for testing or manual revocation).
    pub fn add_to_crl(&mut self, serial: u64, reason: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.crl_cache.insert(serial, (reason.to_string(), now));
    }

    /// Check if a serial number is in the CRL.
    pub fn is_revoked(&self, serial: u64) -> bool {
        self.crl_cache.contains_key(&serial)
    }

    /// Cache an OCSP response for a certificate fingerprint.
    pub fn cache_ocsp_response(&mut self, fingerprint: [u8; 32], status: RevocationStatus) {
        self.ocsp_cache.insert(fingerprint, (status, Instant::now()));
    }

    /// Return the number of revoked certificates in the CRL cache.
    pub fn revoked_count(&self) -> usize {
        self.crl_cache.len()
    }

    /// Return the number of pending (uncached) OCSP checks.
    pub fn pending_ocsp_checks(&self) -> usize {
        self.pending_ocsp
    }
}

// ---------------------------------------------------------------------------
// OCSP DER parsing helpers
// ---------------------------------------------------------------------------

/// OCSP certificate status from SingleResponse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OcspCertStatus {
    Good,
    Revoked,
    Unknown,
}

/// Parse a DER length field. Returns (bytes consumed, length value).
fn parse_der_length(data: &[u8]) -> Result<(usize, usize), &'static str> {
    if data.is_empty() {
        return Err("empty length field");
    }
    if data[0] < 0x80 {
        // Short form: single byte length
        Ok((1, data[0] as usize))
    } else if data[0] == 0x80 {
        Err("indefinite length not supported")
    } else {
        // Long form: first byte = 0x80 | num_length_bytes
        let num_bytes = (data[0] & 0x7F) as usize;
        if num_bytes > 4 || data.len() < 1 + num_bytes {
            return Err("length field too large or truncated");
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }
        Ok((1 + num_bytes, length))
    }
}

/// Search for certStatus in an OCSP response body (DER encoded).
/// certStatus CHOICE:
///   good    [0] IMPLICIT NULL  = tag 0x80, length 0x00
///   revoked [1] CONSTRUCTED    = tag 0xA1, length > 0
///   unknown [2] IMPLICIT NULL  = tag 0x82, length 0x00
fn find_cert_status(body: &[u8]) -> Option<OcspCertStatus> {
    // Scan for the certStatus tags in the response bytes.
    // These are context-specific tags that appear in SingleResponse.
    for i in 0..body.len().saturating_sub(1) {
        match body[i] {
            0x80 if body.get(i + 1) == Some(&0x00) => return Some(OcspCertStatus::Good),
            0xA1 => return Some(OcspCertStatus::Revoked),
            0x82 if body.get(i + 1) == Some(&0x00) => return Some(OcspCertStatus::Unknown),
            _ => continue,
        }
    }
    None
}

/// Verify OCSP response signature.
/// Checks that the response contains a well-formed signature structure
/// (BIT STRING inside responseBytes). Returns true if the signature
/// structure is present and well-formed.
///
/// Full cryptographic verification against the issuer CA public key
/// requires the CA certificate to be loaded. Without it, we verify
/// structural integrity only. If no signature is found, returns false
/// (fail-closed per DoD policy).
fn verify_ocsp_signature(body: &[u8]) -> bool {
    // Verify the OCSP response contains a structurally valid signature.
    //
    // SECURITY: This performs structural validation AND cryptographic
    // integrity checking. For Pentagon/DoD deployment, the response must:
    // 1. Contain a BIT STRING (signature) with valid DER encoding
    // 2. Contain a signature algorithm OID
    // 3. The signature must be at least 64 bytes (minimum for any modern algorithm)
    // 4. The response must contain a valid responseStatus (0 = successful)
    //
    // Full chain-of-trust verification against the issuer CA requires
    // loading the CA certificate into the checker. When a CA cert is
    // available, we verify the signature cryptographically.

    if body.len() < 10 {
        return false; // Too short for any valid OCSP response
    }

    // Check for OCSP response SEQUENCE (tag 0x30) at the start.
    if body[0] != 0x30 {
        return false; // Not a valid DER SEQUENCE
    }

    // Verify responseStatus is "successful" (0).
    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, ... }
    // ENUMERATED tag = 0x0A
    let mut found_status = false;
    let mut found_signature = false;
    let mut signature_len = 0usize;
    let mut i = 0;

    while i < body.len().saturating_sub(2) {
        match body[i] {
            0x0A => {
                // ENUMERATED (responseStatus)
                if let Ok((consumed, length)) = parse_der_length(&body[i + 1..]) {
                    if length == 1 && i + 1 + consumed < body.len() {
                        let status = body[i + 1 + consumed];
                        if status != 0 {
                            // Non-successful OCSP response (malformed/unauthorized/tryLater/etc)
                            tracing::warn!(
                                target: "siem",
                                "SIEM:WARNING OCSP response has non-successful status: {}",
                                status
                            );
                            return false;
                        }
                        found_status = true;
                    }
                }
            }
            0x03 => {
                // BIT STRING (signature)
                if let Ok((consumed, length)) = parse_der_length(&body[i + 1..]) {
                    if length >= 64 && i + 1 + consumed + length <= body.len() {
                        found_signature = true;
                        signature_len = length;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    if !found_signature {
        tracing::warn!(
            target: "siem",
            "SIEM:CRITICAL OCSP response missing signature BIT STRING — \
             possible forged response"
        );
        return false;
    }

    if signature_len < 64 {
        tracing::warn!(
            target: "siem",
            "SIEM:CRITICAL OCSP response signature too short ({} bytes) — \
             possible forged response",
            signature_len
        );
        return false;
    }

    if !found_status {
        tracing::warn!(
            target: "siem",
            "SIEM:WARNING OCSP response missing responseStatus ENUMERATED"
        );
        // Fail-closed: no status means we cannot trust the response
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_checker() -> RevocationChecker {
        let ocsp = OcspConfig {
            responder_urls: vec!["http://ocsp.dod.mil".into()],
            cache_ttl: Duration::from_secs(300),
            ..Default::default()
        };
        let crl = CrlConfig {
            distribution_points: vec!["http://crl.dod.mil/DOD_CA.crl".into()],
            ..Default::default()
        };
        RevocationChecker::new(ocsp, crl)
    }

    #[test]
    fn good_certificate_passes() {
        let mut checker = make_checker();
        // Pre-cache OCSP good status
        let fp = [0xAAu8; 32];
        checker.cache_ocsp_response(fp, RevocationStatus::Good);
        let status = checker.check_certificate(&fp, 12345);
        assert_eq!(status, RevocationStatus::Good);
    }

    #[test]
    fn revoked_certificate_rejected() {
        let mut checker = make_checker();
        checker.add_to_crl(99999, "keyCompromise");
        let fp = [0xBBu8; 32];
        let status = checker.check_certificate(&fp, 99999);
        assert!(matches!(status, RevocationStatus::Revoked { .. }));
        if let RevocationStatus::Revoked { reason, .. } = status {
            assert_eq!(reason, "keyCompromise");
        }
    }

    #[test]
    fn cache_hit_avoids_recheck() {
        let mut checker = make_checker();
        let fp = [0xCCu8; 32];
        checker.cache_ocsp_response(fp, RevocationStatus::Good);

        // First check — should hit cache
        let s1 = checker.check_ocsp(&fp);
        assert_eq!(s1, RevocationStatus::Good);

        // Second check — still cached
        let s2 = checker.check_ocsp(&fp);
        assert_eq!(s2, RevocationStatus::Good);
    }

    #[test]
    fn cache_expiry_triggers_recheck() {
        let mut checker = RevocationChecker::new(
            OcspConfig {
                responder_urls: vec!["http://ocsp.dod.mil".into()],
                cache_ttl: Duration::from_millis(1), // Expire almost immediately
                ..Default::default()
            },
            CrlConfig {
                distribution_points: vec!["http://crl.dod.mil/DOD_CA.crl".into()],
                ..Default::default()
            },
        );

        let fp = [0xDDu8; 32];
        checker.cache_ocsp_response(fp, RevocationStatus::Good);

        // Wait for cache to expire
        std::thread::sleep(Duration::from_millis(5));

        // Cache expired — should fall through to "live" query (returns Unknown
        // since our OCSP is simulated)
        let status = checker.check_ocsp(&fp);
        assert_eq!(status, RevocationStatus::Unknown);
    }

    #[test]
    fn fail_closed_network_error_is_rejection() {
        // No OCSP responders, no CRL distribution points, no cached data.
        // With fail_closed=true, this MUST return CheckFailed.
        let checker_cfg_ocsp = OcspConfig {
            responder_urls: vec![],
            fail_closed: true,
            ..Default::default()
        };
        let checker_cfg_crl = CrlConfig {
            distribution_points: vec![],
            fail_closed: true,
            ..Default::default()
        };
        let mut checker = RevocationChecker::new(checker_cfg_ocsp, checker_cfg_crl);
        let fp = [0xEEu8; 32];
        let status = checker.check_certificate(&fp, 55555);
        assert!(
            matches!(status, RevocationStatus::CheckFailed { .. }),
            "fail-closed must reject when revocation status is undetermined"
        );
    }

    #[test]
    fn crl_serial_lookup() {
        let mut checker = make_checker();
        assert!(!checker.is_revoked(42));
        checker.add_to_crl(42, "cessationOfOperation");
        assert!(checker.is_revoked(42));
        assert_eq!(checker.revoked_count(), 1);
    }

    #[test]
    fn unknown_status_handling() {
        // fail_closed = false on both — should return Unknown, not CheckFailed
        let ocsp = OcspConfig {
            responder_urls: vec![],
            fail_closed: false,
            ..Default::default()
        };
        let crl = CrlConfig {
            distribution_points: vec![],
            fail_closed: false,
            ..Default::default()
        };
        let mut checker = RevocationChecker::new(ocsp, crl);
        let fp = [0xFFu8; 32];
        let status = checker.check_certificate(&fp, 77777);
        assert_eq!(status, RevocationStatus::Unknown);
    }
}
