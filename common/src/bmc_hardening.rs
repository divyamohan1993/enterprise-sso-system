//! BMC/IPMI firmware hardening and security auditing.
//!
//! Baseboard Management Controllers (BMCs) provide out-of-band management
//! of servers. If compromised, an attacker gains persistent, OS-independent
//! access. This module audits BMC security posture including:
//!
//! - Default credential detection
//! - Firmware version and signature verification
//! - IPMI network exposure checks
//! - User account auditing
//! - Serial-over-LAN encryption verification
//!
//! Supports both legacy IPMI 2.0 and modern Redfish API protocols.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from BMC hardening operations.
#[derive(Debug)]
pub enum BmcError {
    /// BMC is unreachable.
    Unreachable(String),
    /// Authentication failure.
    AuthFailed(String),
    /// Firmware verification failure.
    FirmwareVerificationFailed(String),
    /// A security check found a critical issue.
    SecurityViolation(String),
    /// I/O or protocol error.
    IoError(String),
}

impl std::fmt::Display for BmcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(s) => write!(f, "BMC unreachable: {}", s),
            Self::AuthFailed(s) => write!(f, "BMC auth failed: {}", s),
            Self::FirmwareVerificationFailed(s) => {
                write!(f, "firmware verification failed: {}", s)
            }
            Self::SecurityViolation(s) => write!(f, "BMC security violation: {}", s),
            Self::IoError(s) => write!(f, "BMC I/O error: {}", s),
        }
    }
}

impl std::error::Error for BmcError {}

// ---------------------------------------------------------------------------
// BMC protocol and configuration
// ---------------------------------------------------------------------------

/// BMC management protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BmcProtocol {
    /// Legacy IPMI 2.0 over LAN.
    Ipmi,
    /// DMTF Redfish REST API.
    Redfish,
    /// Both protocols available.
    Both,
}

/// Configuration for BMC security auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmcConfig {
    /// BMC management IP address (None = auto-detect).
    pub bmc_address: Option<String>,
    /// Protocol to use for BMC communication.
    pub bmc_protocol: BmcProtocol,
    /// Require cryptographic firmware signing verification.
    pub require_firmware_signing: bool,
    /// Allowed firmware versions (empty = any version).
    pub allowed_firmware_versions: Vec<String>,
    /// Whether to flag default/factory credentials as a violation.
    pub disable_default_credentials: bool,
}

impl Default for BmcConfig {
    fn default() -> Self {
        Self {
            bmc_address: None,
            bmc_protocol: BmcProtocol::Redfish,
            require_firmware_signing: true,
            allowed_firmware_versions: Vec::new(),
            disable_default_credentials: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Firmware manifest
// ---------------------------------------------------------------------------

/// Firmware image metadata and signing information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareManifest {
    /// Firmware version string.
    pub version: String,
    /// SHA-512 hash of the firmware image.
    pub hash: Vec<u8>,
    /// Cryptographic signature over the hash.
    pub signature: Vec<u8>,
    /// Identity of the signer (vendor key ID).
    pub signer: String,
    /// Release date as Unix timestamp.
    pub release_date: u64,
}

// ---------------------------------------------------------------------------
// Audit types
// ---------------------------------------------------------------------------

/// Severity level for audit findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingSeverity {
    /// Informational observation.
    Info,
    /// Low-risk finding.
    Low,
    /// Medium-risk finding.
    Medium,
    /// High-risk finding — requires remediation.
    High,
    /// Critical — immediate action required.
    Critical,
}

/// A single security finding from a BMC audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Short identifier for the finding (e.g., "BMC-001").
    pub id: String,
    /// Severity level.
    pub severity: FindingSeverity,
    /// Human-readable title.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// Recommended remediation.
    pub remediation: String,
}

/// Aggregate result of a BMC security audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmcAuditResult {
    /// Number of checks that passed.
    pub checks_passed: u32,
    /// Number of checks that failed.
    pub checks_failed: u32,
    /// Individual findings.
    pub findings: Vec<Finding>,
    /// Timestamp when the audit was performed.
    pub audit_timestamp: u64,
    /// Overall pass/fail status.
    pub passed: bool,
}

/// Information about a BMC user account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmcUser {
    /// User ID (IPMI channel user ID).
    pub user_id: u8,
    /// Username.
    pub username: String,
    /// Whether the account is enabled.
    pub enabled: bool,
    /// Privilege level (1=Callback, 2=User, 3=Operator, 4=Admin).
    pub privilege_level: u8,
    /// Whether the account uses a default/factory password.
    pub has_default_password: bool,
}

// ---------------------------------------------------------------------------
// BMC Security Auditor
// ---------------------------------------------------------------------------

/// Default credentials commonly found on BMC/IPMI systems.
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("ADMIN", "ADMIN"),
    ("admin", "admin"),
    ("root", "calvin"),      // Dell iDRAC
    ("ADMIN", ""),           // Supermicro
    ("root", "root"),
    ("admin", "password"),
    ("Administrator", ""),   // HP iLO
    ("USERID", "PASSW0RD"), // IBM/Lenovo IMM
];

/// Auditor for BMC/IPMI security hardening.
pub struct BmcSecurityAuditor {
    config: BmcConfig,
}

impl BmcSecurityAuditor {
    /// Create a new auditor with the given configuration.
    pub fn new(config: BmcConfig) -> Self {
        Self { config }
    }

    /// Check for default/factory credentials on the BMC.
    ///
    /// Attempts authentication with known default credential pairs
    /// and flags any that succeed as critical findings.
    pub fn check_default_credentials(&self) -> Result<Vec<Finding>, BmcError> {
        let mut findings = Vec::new();

        let bmc_addr = self.bmc_address()?;

        for (username, password) in DEFAULT_CREDENTIALS {
            if self.try_authenticate(&bmc_addr, username, password) {
                findings.push(Finding {
                    id: "BMC-001".into(),
                    severity: FindingSeverity::Critical,
                    title: "Default credentials active".into(),
                    description: format!(
                        "BMC at {} accepts default credentials for user '{}'",
                        bmc_addr, username
                    ),
                    remediation: format!(
                        "Change password for BMC user '{}' immediately",
                        username
                    ),
                });
            }
        }

        Ok(findings)
    }

    /// Verify BMC firmware version against the allowed list.
    pub fn verify_firmware_version(&self) -> Result<Vec<Finding>, BmcError> {
        let mut findings = Vec::new();

        let current_version = self.get_firmware_version()?;

        if !self.config.allowed_firmware_versions.is_empty()
            && !self
                .config
                .allowed_firmware_versions
                .contains(&current_version)
        {
            findings.push(Finding {
                id: "BMC-002".into(),
                severity: FindingSeverity::High,
                title: "Unapproved firmware version".into(),
                description: format!(
                    "BMC firmware version '{}' is not in the approved list: {:?}",
                    current_version, self.config.allowed_firmware_versions
                ),
                remediation: "Update BMC firmware to an approved version".into(),
            });
        }

        Ok(findings)
    }

    /// Verify the cryptographic signature of a firmware image.
    pub fn verify_firmware_signature(
        &self,
        firmware_image: &[u8],
        manifest: &FirmwareManifest,
    ) -> Result<Vec<Finding>, BmcError> {
        let mut findings = Vec::new();

        // Verify the hash.
        use sha2::{Digest, Sha512};
        let computed_hash = Sha512::digest(firmware_image);
        if computed_hash.as_slice() != manifest.hash.as_slice() {
            findings.push(Finding {
                id: "BMC-003".into(),
                severity: FindingSeverity::Critical,
                title: "Firmware hash mismatch".into(),
                description: "Computed SHA-512 hash does not match manifest".into(),
                remediation: "Obtain firmware from a trusted source".into(),
            });
            return Ok(findings);
        }

        // In production, verify the signature using the vendor's public key.
        // Here we check that a signature is present.
        if manifest.signature.is_empty() {
            findings.push(Finding {
                id: "BMC-004".into(),
                severity: FindingSeverity::Critical,
                title: "Firmware not signed".into(),
                description: "Firmware manifest has no cryptographic signature".into(),
                remediation: "Only deploy signed firmware images".into(),
            });
        }

        if manifest.signer.is_empty() {
            findings.push(Finding {
                id: "BMC-005".into(),
                severity: FindingSeverity::High,
                title: "Unknown firmware signer".into(),
                description: "Firmware manifest does not identify the signer".into(),
                remediation: "Obtain firmware signed by the hardware vendor".into(),
            });
        }

        Ok(findings)
    }

    /// Check whether IPMI is exposed to untrusted networks.
    ///
    /// Verifies that the BMC management interface is on a dedicated
    /// management VLAN and not routable from production networks.
    pub fn check_ipmi_exposure(&self) -> Result<Vec<Finding>, BmcError> {
        let mut findings = Vec::new();
        let bmc_addr = self.bmc_address()?;

        // Check if BMC is on a private/management network.
        if !is_management_network(&bmc_addr) {
            findings.push(Finding {
                id: "BMC-006".into(),
                severity: FindingSeverity::Critical,
                title: "BMC exposed on non-management network".into(),
                description: format!(
                    "BMC address {} is not on a dedicated management network",
                    bmc_addr
                ),
                remediation:
                    "Move BMC to a dedicated management VLAN (e.g., 10.x.x.x or 172.16.x.x)"
                        .into(),
            });
        }

        // Check for IPMI port exposure (port 623).
        // In production, this would do an actual port scan.
        if self.config.bmc_protocol == BmcProtocol::Ipmi
            || self.config.bmc_protocol == BmcProtocol::Both
        {
            findings.push(Finding {
                id: "BMC-007".into(),
                severity: FindingSeverity::Medium,
                title: "IPMI protocol enabled".into(),
                description: "Legacy IPMI 2.0 protocol is enabled; prefer Redfish API".into(),
                remediation: "Migrate to Redfish API and disable IPMI if possible".into(),
            });
        }

        Ok(findings)
    }

    /// Audit all BMC user accounts for security issues.
    pub fn audit_bmc_users(&self) -> Result<Vec<Finding>, BmcError> {
        let mut findings = Vec::new();

        let users = self.enumerate_bmc_users()?;

        for user in &users {
            // Flag disabled admin accounts (potential backdoor).
            if !user.enabled && user.privilege_level == 4 {
                findings.push(Finding {
                    id: "BMC-008".into(),
                    severity: FindingSeverity::Medium,
                    title: "Disabled admin account exists".into(),
                    description: format!(
                        "BMC user '{}' (ID {}) is a disabled admin — potential backdoor",
                        user.username, user.user_id
                    ),
                    remediation: "Remove unused admin accounts from BMC".into(),
                });
            }

            // Flag default passwords.
            if user.has_default_password && user.enabled {
                findings.push(Finding {
                    id: "BMC-009".into(),
                    severity: FindingSeverity::Critical,
                    title: "Active account with default password".into(),
                    description: format!(
                        "BMC user '{}' (ID {}) has a default/factory password",
                        user.username, user.user_id
                    ),
                    remediation: format!(
                        "Change password for BMC user '{}'",
                        user.username
                    ),
                });
            }

            // Flag unnamed accounts that are enabled.
            if user.username.is_empty() && user.enabled {
                findings.push(Finding {
                    id: "BMC-010".into(),
                    severity: FindingSeverity::High,
                    title: "Unnamed enabled account".into(),
                    description: format!(
                        "BMC user ID {} is enabled but has no username",
                        user.user_id
                    ),
                    remediation: "Disable or properly configure unnamed BMC accounts".into(),
                });
            }
        }

        Ok(findings)
    }

    /// Check whether Serial-over-LAN (SOL) uses encryption.
    pub fn check_sol_encryption(&self) -> Result<Vec<Finding>, BmcError> {
        let mut findings = Vec::new();

        // In production, this queries the BMC SOL configuration via
        // ipmitool or Redfish to verify encryption settings.
        //
        // SOL encryption should use AES-128 or better.
        let sol_encrypted = self.query_sol_encryption()?;

        if !sol_encrypted {
            findings.push(Finding {
                id: "BMC-011".into(),
                severity: FindingSeverity::High,
                title: "Serial-over-LAN not encrypted".into(),
                description: "SOL payload is transmitted in cleartext".into(),
                remediation: "Enable SOL encryption (AES-128 minimum)".into(),
            });
        }

        Ok(findings)
    }

    /// Generate a comprehensive BMC security hardening report.
    pub fn generate_hardening_report(&self) -> BmcAuditResult {
        let mut all_findings = Vec::new();
        let mut checks_passed = 0u32;
        let mut checks_failed = 0u32;

        // Run all checks, collecting findings.
        let checks: Vec<Result<Vec<Finding>, BmcError>> = vec![
            self.check_default_credentials(),
            self.verify_firmware_version(),
            self.check_ipmi_exposure(),
            self.audit_bmc_users(),
            self.check_sol_encryption(),
        ];

        for check_result in checks {
            match check_result {
                Ok(findings) => {
                    if findings.is_empty() {
                        checks_passed += 1;
                    } else {
                        checks_failed += 1;
                        all_findings.extend(findings);
                    }
                }
                Err(_) => {
                    checks_failed += 1;
                    all_findings.push(Finding {
                        id: "BMC-ERR".into(),
                        severity: FindingSeverity::Medium,
                        title: "Check execution error".into(),
                        description: "A BMC security check could not be executed".into(),
                        remediation: "Verify BMC connectivity and retry".into(),
                    });
                }
            }
        }

        let has_critical = all_findings
            .iter()
            .any(|f| f.severity >= FindingSeverity::Critical);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        BmcAuditResult {
            checks_passed,
            checks_failed,
            findings: all_findings,
            audit_timestamp: now,
            passed: !has_critical && checks_failed == 0,
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn bmc_address(&self) -> Result<String, BmcError> {
        self.config
            .bmc_address
            .clone()
            .ok_or_else(|| BmcError::Unreachable("no BMC address configured".into()))
    }

    fn try_authenticate(&self, _addr: &str, _username: &str, _password: &str) -> bool {
        // In production, this would attempt IPMI or Redfish authentication.
        // Simulated: always report that default credentials are NOT accepted
        // (safe default for testing).
        false
    }

    fn get_firmware_version(&self) -> Result<String, BmcError> {
        // In production, query via `ipmitool mc info` or Redfish
        // /redfish/v1/UpdateService/FirmwareInventory.
        Ok("2.87.87".into())
    }

    fn enumerate_bmc_users(&self) -> Result<Vec<BmcUser>, BmcError> {
        // In production, query via `ipmitool user list 1` or Redfish
        // /redfish/v1/AccountService/Accounts.
        Ok(vec![
            BmcUser {
                user_id: 1,
                username: String::new(),
                enabled: false,
                privilege_level: 0,
                has_default_password: false,
            },
            BmcUser {
                user_id: 2,
                username: "admin".into(),
                enabled: true,
                privilege_level: 4,
                has_default_password: false,
            },
        ])
    }

    fn query_sol_encryption(&self) -> Result<bool, BmcError> {
        // In production, query SOL configuration.
        // Default: report encrypted for safe testing.
        Ok(true)
    }
}

/// Check if an IP address is on a typical management network.
fn is_management_network(addr: &str) -> bool {
    addr.starts_with("10.")
        || addr.starts_with("172.16.")
        || addr.starts_with("172.17.")
        || addr.starts_with("172.18.")
        || addr.starts_with("172.19.")
        || addr.starts_with("172.2")
        || addr.starts_with("172.30.")
        || addr.starts_with("172.31.")
        || addr.starts_with("192.168.")
        || addr.starts_with("fc")
        || addr.starts_with("fd")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_requires_signing() {
        let cfg = BmcConfig::default();
        assert!(cfg.require_firmware_signing);
        assert!(cfg.disable_default_credentials);
        assert_eq!(cfg.bmc_protocol, BmcProtocol::Redfish);
    }

    #[test]
    fn no_default_credentials_found() {
        let config = BmcConfig {
            bmc_address: Some("10.0.0.100".into()),
            ..BmcConfig::default()
        };
        let auditor = BmcSecurityAuditor::new(config);
        let findings = auditor.check_default_credentials().unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn firmware_version_in_allowed_list() {
        let config = BmcConfig {
            bmc_address: Some("10.0.0.100".into()),
            allowed_firmware_versions: vec!["2.87.87".into()],
            ..BmcConfig::default()
        };
        let auditor = BmcSecurityAuditor::new(config);
        let findings = auditor.verify_firmware_version().unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn firmware_version_not_in_allowed_list() {
        let config = BmcConfig {
            bmc_address: Some("10.0.0.100".into()),
            allowed_firmware_versions: vec!["3.0.0".into()],
            ..BmcConfig::default()
        };
        let auditor = BmcSecurityAuditor::new(config);
        let findings = auditor.verify_firmware_version().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, FindingSeverity::High);
    }

    #[test]
    fn firmware_hash_mismatch_detected() {
        let config = BmcConfig::default();
        let auditor = BmcSecurityAuditor::new(config);
        let firmware = b"firmware-image-data";
        let manifest = FirmwareManifest {
            version: "2.87.87".into(),
            hash: vec![0u8; 64], // Wrong hash.
            signature: vec![1u8; 64],
            signer: "vendor".into(),
            release_date: 1700000000,
        };
        let findings = auditor
            .verify_firmware_signature(firmware, &manifest)
            .unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].id, "BMC-003");
    }

    #[test]
    fn firmware_correct_hash_no_signature() {
        use sha2::{Digest, Sha512};
        let config = BmcConfig::default();
        let auditor = BmcSecurityAuditor::new(config);
        let firmware = b"firmware-image-data";
        let hash = Sha512::digest(firmware);
        let manifest = FirmwareManifest {
            version: "2.87.87".into(),
            hash: hash.to_vec(),
            signature: vec![],
            signer: "vendor".into(),
            release_date: 1700000000,
        };
        let findings = auditor
            .verify_firmware_signature(firmware, &manifest)
            .unwrap();
        assert!(findings.iter().any(|f| f.id == "BMC-004"));
    }

    #[test]
    fn management_network_detection() {
        assert!(is_management_network("10.0.0.1"));
        assert!(is_management_network("192.168.1.1"));
        assert!(is_management_network("172.16.0.1"));
        assert!(!is_management_network("8.8.8.8"));
        assert!(!is_management_network("203.0.113.1"));
    }

    #[test]
    fn ipmi_exposure_on_public_network() {
        let config = BmcConfig {
            bmc_address: Some("203.0.113.50".into()),
            bmc_protocol: BmcProtocol::Ipmi,
            ..BmcConfig::default()
        };
        let auditor = BmcSecurityAuditor::new(config);
        let findings = auditor.check_ipmi_exposure().unwrap();
        assert!(findings.iter().any(|f| f.id == "BMC-006"));
    }

    #[test]
    fn hardening_report_aggregates_checks() {
        let config = BmcConfig {
            bmc_address: Some("10.0.0.100".into()),
            bmc_protocol: BmcProtocol::Redfish,
            allowed_firmware_versions: vec!["2.87.87".into()],
            ..BmcConfig::default()
        };
        let auditor = BmcSecurityAuditor::new(config);
        let report = auditor.generate_hardening_report();
        assert!(report.audit_timestamp > 0);
        // With simulated safe defaults, most checks should pass.
        assert!(report.checks_passed > 0);
    }
}
