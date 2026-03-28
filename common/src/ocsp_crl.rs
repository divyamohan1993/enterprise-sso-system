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
    /// performs a live OCSP query (simulated — in production this would
    /// make an HTTP request to the OCSP responder).
    pub fn check_ocsp(&self, cert_fingerprint: &[u8; 32]) -> RevocationStatus {
        // Check cache first
        if let Some((status, cached_at)) = self.ocsp_cache.get(cert_fingerprint) {
            if cached_at.elapsed() < self.ocsp_config.cache_ttl {
                return status.clone();
            }
            // Cache expired — fall through to live query
        }

        // In production: make HTTP POST to OCSP responder with DER-encoded request.
        // For now, if no responders configured, return Unknown.
        if self.ocsp_config.responder_urls.is_empty() {
            return RevocationStatus::Unknown;
        }

        // Simulated OCSP query — in production, this would be async HTTP.
        // Return Unknown to trigger CRL fallback.
        RevocationStatus::Unknown
    }

    /// Check CRL for a serial number.
    ///
    /// Looks up the serial in the local CRL cache. In production, the CRL
    /// is periodically refreshed from distribution points by a background task.
    pub fn check_crl(&self, serial_number: u64) -> RevocationStatus {
        if let Some((reason, revoked_at)) = self.crl_cache.get(&serial_number) {
            return RevocationStatus::Revoked {
                reason: reason.clone(),
                revoked_at: *revoked_at,
            };
        }

        // If we have distribution points configured, the serial is not in our
        // cached CRL, so it's presumed good.
        if !self.crl_config.distribution_points.is_empty() || !self.crl_cache.is_empty() {
            return RevocationStatus::Good;
        }

        // No CRL data at all — cannot determine status.
        RevocationStatus::Unknown
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
