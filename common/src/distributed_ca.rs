//! Distributed Certificate Authority with threshold signing.
//!
//! The CA signing key is split across multiple nodes using FROST threshold
//! signatures. No single node holds the complete CA key. Certificate signing
//! requires quorum agreement (t-of-n).
//!
//! On leader failure:
//! - New leader elected via Raft
//! - All nodes share the same CA public key (from DKG)
//! - Any quorum can sign new certificates
//! - Existing certificates remain valid (public key unchanged)

use crate::raft::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Certificate Signing Request for the distributed CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSigningRequest {
    pub module_name: String,
    pub subject_alt_names: Vec<String>,
    pub requested_by: NodeId,
    pub timestamp: i64,
    pub validity_hours: u32,
}

/// Issued certificate record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCert {
    pub serial: u64,
    pub module_name: String,
    pub subject_alt_names: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub issuer_quorum: Vec<NodeId>,
    pub fingerprint: Vec<u8>,
    pub revoked: bool,
}

/// Configuration for the distributed CA.
#[derive(Debug, Clone)]
pub struct DistributedCaConfig {
    /// Minimum signers required (FROST threshold)
    pub threshold: usize,
    /// Total CA signer nodes
    pub total_signers: usize,
    /// Default certificate validity (hours)
    pub default_validity_hours: u32,
    /// Maximum certificate validity (hours)
    pub max_validity_hours: u32,
    /// Auto-renewal threshold (renew when less than this many hours remain)
    pub renewal_threshold_hours: u32,
}

impl Default for DistributedCaConfig {
    fn default() -> Self {
        Self {
            threshold: 2,
            total_signers: 3,
            default_validity_hours: 720,  // 30 days
            max_validity_hours: 8760,     // 1 year
            renewal_threshold_hours: 168, // 7 days
        }
    }
}

/// The distributed CA state.
/// In production, the actual signing is delegated to FROST threshold signing
/// via the TSS service. This module manages the certificate lifecycle.
pub struct DistributedCa {
    config: DistributedCaConfig,
    /// Issued certificates by serial number
    issued: HashMap<u64, IssuedCert>,
    /// Next serial number
    next_serial: u64,
    /// Revoked certificate serials
    revoked: Vec<u64>,
    /// CA public key fingerprint (SHA-512 of the FROST group verifying key)
    ca_fingerprint: Vec<u8>,
}

impl DistributedCa {
    pub fn new(config: DistributedCaConfig, ca_fingerprint: Vec<u8>) -> Self {
        Self {
            config,
            issued: HashMap::new(),
            next_serial: 1,
            revoked: Vec::new(),
            ca_fingerprint,
        }
    }

    /// Request a certificate. Returns the CSR details for threshold signing.
    pub fn create_csr(
        &self,
        module_name: &str,
        sans: Vec<String>,
        requested_by: NodeId,
    ) -> CertSigningRequest {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        CertSigningRequest {
            module_name: module_name.to_string(),
            subject_alt_names: sans,
            requested_by,
            timestamp: now,
            validity_hours: self.config.default_validity_hours,
        }
    }

    /// Record a certificate as issued (after threshold signing completes).
    pub fn record_issued(
        &mut self,
        csr: &CertSigningRequest,
        quorum: Vec<NodeId>,
        fingerprint: Vec<u8>,
    ) -> u64 {
        let serial = self.next_serial;
        self.next_serial += 1;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let expires = now + (csr.validity_hours as i64 * 3600);

        let cert = IssuedCert {
            serial,
            module_name: csr.module_name.clone(),
            subject_alt_names: csr.subject_alt_names.clone(),
            issued_at: now,
            expires_at: expires,
            issuer_quorum: quorum,
            fingerprint,
            revoked: false,
        };
        self.issued.insert(serial, cert);
        serial
    }

    /// Revoke a certificate by serial number.
    pub fn revoke(&mut self, serial: u64) -> bool {
        if let Some(cert) = self.issued.get_mut(&serial) {
            cert.revoked = true;
            self.revoked.push(serial);
            true
        } else {
            false
        }
    }

    /// Check if a certificate is valid (not revoked, not expired).
    pub fn is_valid(&self, serial: u64) -> bool {
        if let Some(cert) = self.issued.get(&serial) {
            if cert.revoked {
                return false;
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            cert.expires_at > now
        } else {
            false
        }
    }

    /// Get certificates that need renewal.
    pub fn needs_renewal(&self) -> Vec<&IssuedCert> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let threshold = self.config.renewal_threshold_hours as i64 * 3600;
        self.issued
            .values()
            .filter(|c| !c.revoked && c.expires_at - now < threshold)
            .collect()
    }

    /// Get all revoked certificate serials (for CRL distribution).
    pub fn revocation_list(&self) -> &[u64] {
        &self.revoked
    }

    /// CA public key fingerprint.
    pub fn ca_fingerprint(&self) -> &[u8] {
        &self.ca_fingerprint
    }

    /// Total issued certificates.
    pub fn issued_count(&self) -> usize {
        self.issued.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn node(n: u8) -> NodeId {
        NodeId(Uuid::from_bytes([n; 16]))
    }

    fn make_ca() -> DistributedCa {
        DistributedCa::new(
            DistributedCaConfig::default(),
            vec![0xCA; 64],
        )
    }

    #[test]
    fn test_csr_creation() {
        let ca = make_ca();
        let csr = ca.create_csr(
            "gateway",
            vec!["gateway.milnet.mil".into()],
            node(1),
        );
        assert_eq!(csr.module_name, "gateway");
        assert_eq!(csr.subject_alt_names, vec!["gateway.milnet.mil"]);
        assert_eq!(csr.validity_hours, 720);
        assert!(csr.timestamp > 0);
    }

    #[test]
    fn test_certificate_issuance() {
        let mut ca = make_ca();
        let csr = ca.create_csr(
            "orchestrator",
            vec!["orch.milnet.mil".into()],
            node(1),
        );
        let quorum = vec![node(1), node(2)];
        let serial = ca.record_issued(&csr, quorum, vec![0xFF; 32]);
        assert_eq!(serial, 1);
        assert_eq!(ca.issued_count(), 1);

        // Second issuance gets serial 2
        let csr2 = ca.create_csr("verifier", vec![], node(2));
        let serial2 = ca.record_issued(&csr2, vec![node(2), node(3)], vec![0xEE; 32]);
        assert_eq!(serial2, 2);
        assert_eq!(ca.issued_count(), 2);
    }

    #[test]
    fn test_certificate_revocation() {
        let mut ca = make_ca();
        let csr = ca.create_csr("tss", vec![], node(1));
        let serial = ca.record_issued(&csr, vec![node(1), node(2)], vec![0xAB; 32]);

        assert!(ca.is_valid(serial));

        // Revoke it
        assert!(ca.revoke(serial));
        assert!(!ca.is_valid(serial));

        // Revoking a non-existent cert returns false
        assert!(!ca.revoke(999));
    }

    #[test]
    fn test_validity_checking() {
        let mut ca = make_ca();
        let csr = ca.create_csr("audit", vec![], node(1));
        let serial = ca.record_issued(&csr, vec![node(1), node(2)], vec![0xCD; 32]);

        // Should be valid (just issued, 30 days validity)
        assert!(ca.is_valid(serial));

        // Non-existent serial is not valid
        assert!(!ca.is_valid(42));

        // Revoked cert is not valid
        ca.revoke(serial);
        assert!(!ca.is_valid(serial));
    }

    #[test]
    fn test_renewal_detection() {
        let mut ca = make_ca();

        // Issue a cert that will expire far in the future (default 720h)
        let csr = ca.create_csr("gateway", vec![], node(1));
        let serial_far = ca.record_issued(&csr, vec![node(1), node(2)], vec![0x11; 32]);

        // Certs with 720h left should NOT need renewal (threshold is 168h)
        let renewals = ca.needs_renewal();
        assert!(
            !renewals.iter().any(|c| c.serial == serial_far),
            "cert with 720h remaining should not need renewal"
        );

        // Manually create a cert that expires very soon
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let soon_cert = IssuedCert {
            serial: 100,
            module_name: "expiring-soon".into(),
            subject_alt_names: vec![],
            issued_at: now - 3600 * 700,
            expires_at: now + 3600 * 24, // 24h left, below 168h threshold
            issuer_quorum: vec![node(1)],
            fingerprint: vec![0x22; 32],
            revoked: false,
        };
        ca.issued.insert(100, soon_cert);

        let renewals = ca.needs_renewal();
        assert!(renewals.iter().any(|c| c.serial == 100));
    }

    #[test]
    fn test_revocation_list() {
        let mut ca = make_ca();

        let csr1 = ca.create_csr("a", vec![], node(1));
        let s1 = ca.record_issued(&csr1, vec![node(1)], vec![]);

        let csr2 = ca.create_csr("b", vec![], node(1));
        let s2 = ca.record_issued(&csr2, vec![node(1)], vec![]);

        let csr3 = ca.create_csr("c", vec![], node(1));
        let _s3 = ca.record_issued(&csr3, vec![node(1)], vec![]);

        assert!(ca.revocation_list().is_empty());

        ca.revoke(s1);
        ca.revoke(s2);

        assert_eq!(ca.revocation_list(), &[s1, s2]);
    }

    #[test]
    fn test_ca_fingerprint() {
        let ca = make_ca();
        assert_eq!(ca.ca_fingerprint(), &[0xCA; 64]);
    }
}
