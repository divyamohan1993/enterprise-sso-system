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

// ── CA Redundancy: Primary/Secondary Failover ──
//
// SECURITY: The CA must NOT be a single point of failure. In a military
// deployment, if the primary CA instance is compromised or unavailable,
// a secondary CA must seamlessly take over certificate issuance using
// the same FROST group verifying key (since the signing key is threshold-split
// across all nodes, any quorum can sign regardless of which CA instance
// coordinates the ceremony).

/// Status of a CA instance in the redundant pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaInstanceStatus {
    /// Actively issuing certificates.
    Primary,
    /// Hot standby, ready to take over.
    Secondary,
    /// Instance is unreachable or failed health checks.
    Unavailable,
}

/// A single CA instance in the redundant CA pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaInstance {
    pub instance_id: String,
    pub node_id: NodeId,
    pub status: CaInstanceStatus,
    pub last_health_check: i64,
    /// Number of consecutive failed health checks.
    pub consecutive_failures: u32,
}

/// Configuration for the redundant CA pool.
#[derive(Debug, Clone)]
pub struct RedundantCaConfig {
    /// Maximum consecutive health check failures before failover.
    pub max_failures_before_failover: u32,
    /// Health check interval in seconds.
    pub health_check_interval_secs: u64,
    /// Maximum age of a CA certificate before rotation (hours).
    pub ca_cert_max_age_hours: u32,
}

impl Default for RedundantCaConfig {
    fn default() -> Self {
        Self {
            max_failures_before_failover: 3,
            health_check_interval_secs: 10,
            ca_cert_max_age_hours: 8760, // 1 year
        }
    }
}

/// Manages a pool of CA instances with automatic failover.
///
/// The redundant CA pool ensures that certificate issuance continues
/// even if the primary CA instance fails. Because the signing key is
/// threshold-split (FROST), any CA instance coordinating a quorum of
/// signers can issue valid certificates.
pub struct RedundantCaPool {
    config: RedundantCaConfig,
    instances: Vec<CaInstance>,
    /// The underlying distributed CA state (shared across instances).
    ca: DistributedCa,
    /// Timestamp of last CA certificate rotation.
    last_ca_rotation: i64,
}

impl RedundantCaPool {
    /// Create a new redundant CA pool with the given instances.
    pub fn new(
        config: RedundantCaConfig,
        ca: DistributedCa,
        instances: Vec<CaInstance>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        Self {
            config,
            instances,
            ca,
            last_ca_rotation: now,
        }
    }

    /// Get the current primary CA instance, if any.
    pub fn primary(&self) -> Option<&CaInstance> {
        self.instances
            .iter()
            .find(|i| i.status == CaInstanceStatus::Primary)
    }

    /// Get all secondary (standby) instances.
    pub fn secondaries(&self) -> Vec<&CaInstance> {
        self.instances
            .iter()
            .filter(|i| i.status == CaInstanceStatus::Secondary)
            .collect()
    }

    /// Record a health check result for a CA instance.
    ///
    /// If the primary exceeds `max_failures_before_failover`, the pool
    /// automatically promotes a secondary to primary.
    pub fn record_health_check(&mut self, instance_id: &str, healthy: bool) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut failover_target: Option<String> = None;

        // Update the instance's health status.
        if let Some(instance) = self.instances.iter_mut().find(|i| i.instance_id == instance_id) {
            instance.last_health_check = now;
            if healthy {
                instance.consecutive_failures = 0;
                if instance.status == CaInstanceStatus::Unavailable {
                    // Recovered instance becomes a secondary.
                    instance.status = CaInstanceStatus::Secondary;
                    tracing::info!(
                        instance_id = %instance_id,
                        "CA instance recovered, demoted to secondary"
                    );
                }
            } else {
                instance.consecutive_failures += 1;
                if instance.consecutive_failures >= self.config.max_failures_before_failover {
                    let was_primary = instance.status == CaInstanceStatus::Primary;
                    instance.status = CaInstanceStatus::Unavailable;
                    tracing::error!(
                        instance_id = %instance_id,
                        failures = instance.consecutive_failures,
                        "CA instance marked unavailable"
                    );

                    // If the primary failed, trigger failover.
                    if was_primary {
                        failover_target = self.promote_secondary();
                    }
                }
            }
        }

        failover_target
    }

    /// Promote the first available secondary to primary.
    ///
    /// Returns the instance_id of the newly promoted primary, or None if
    /// no secondaries are available (total CA failure -- SIEM critical alert).
    fn promote_secondary(&mut self) -> Option<String> {
        for instance in &mut self.instances {
            if instance.status == CaInstanceStatus::Secondary {
                instance.status = CaInstanceStatus::Primary;
                tracing::warn!(
                    instance_id = %instance.instance_id,
                    "FAILOVER: secondary CA promoted to primary"
                );
                crate::siem::SecurityEvent::circuit_breaker_opened("distributed_ca_failover");
                return Some(instance.instance_id.clone());
            }
        }

        // No secondaries available -- critical failure.
        tracing::error!(
            "CRITICAL: No secondary CA instances available for failover. \
             Certificate issuance is UNAVAILABLE."
        );
        None
    }

    /// Check if the CA certificate needs rotation based on age.
    pub fn needs_ca_rotation(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let age_hours = (now - self.last_ca_rotation) / 3600;
        age_hours >= self.config.ca_cert_max_age_hours as i64
    }

    /// Record that a CA certificate rotation has been performed.
    pub fn record_ca_rotation(&mut self) {
        self.last_ca_rotation = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        tracing::info!("CA certificate rotation recorded");
    }

    /// Access the underlying distributed CA.
    pub fn ca(&self) -> &DistributedCa {
        &self.ca
    }

    /// Access the underlying distributed CA mutably.
    pub fn ca_mut(&mut self) -> &mut DistributedCa {
        &mut self.ca
    }

    /// Total number of CA instances in the pool.
    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    /// Number of available (non-unavailable) instances.
    pub fn available_count(&self) -> usize {
        self.instances
            .iter()
            .filter(|i| i.status != CaInstanceStatus::Unavailable)
            .count()
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
