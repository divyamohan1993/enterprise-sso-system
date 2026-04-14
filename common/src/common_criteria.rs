//! Common Criteria (ISO/IEC 15408) Security Target documentation-as-code.
//!
//! This module defines the Security Target (ST) structure for future Common
//! Criteria evaluation of the MILNET SSO system. It encodes:
//!
//! - Protection Profiles (PP) the system claims conformance to
//! - Evaluation Assurance Level (EAL) declaration
//! - Security Functional Requirements (SFRs) mapped to code modules
//! - Security Assurance Requirements (SARs) mapped to development artifacts
//! - Target of Evaluation (TOE) boundary definition
//!
//! # Purpose
//!
//! This is **documentation-as-code** for a future CC evaluation. It provides
//! machine-readable metadata that can be extracted by evaluation tools and
//! auditors. The actual evaluation must be performed by an accredited
//! Common Criteria Testing Laboratory (CCTL).
//!
//! # References
//!
//! - ISO/IEC 15408-1:2022 (CC Part 1: Introduction and general model)
//! - ISO/IEC 15408-2:2022 (CC Part 2: Security functional components)
//! - ISO/IEC 15408-3:2022 (CC Part 3: Security assurance components)
//! - NIAP Protection Profile for Application Software (PP_APP_v1.4)

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Protection Profiles
// ---------------------------------------------------------------------------

/// NIAP-approved Protection Profiles that the TOE claims conformance to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtectionProfile {
    /// PP_APP_v1.4: Protection Profile for Application Software
    AppSoftware,
    /// PP_OS_v4.3: Protection Profile for General Purpose Operating Systems
    /// (applicable to the hardened deployment environment)
    GeneralPurposeOs,
    /// PP_ND_v2.2e: Collaborative Protection Profile for Network Devices
    /// (applicable to the gateway component)
    NetworkDevice,
    /// PP_MDF_v3.3: Protection Profile for Mobile Device Fundamentals
    /// (applicable if mobile clients are in scope)
    MobileDevice,
}

impl ProtectionProfile {
    /// Return the NIAP identifier string for this protection profile.
    pub fn niap_id(&self) -> &str {
        match self {
            ProtectionProfile::AppSoftware => "PP_APP_v1.4",
            ProtectionProfile::GeneralPurposeOs => "PP_OS_v4.3",
            ProtectionProfile::NetworkDevice => "PP_ND_v2.2e",
            ProtectionProfile::MobileDevice => "PP_MDF_v3.3",
        }
    }

    /// Return the human-readable title.
    pub fn title(&self) -> &str {
        match self {
            ProtectionProfile::AppSoftware => "Protection Profile for Application Software",
            ProtectionProfile::GeneralPurposeOs => "Protection Profile for General Purpose Operating Systems",
            ProtectionProfile::NetworkDevice => "Collaborative Protection Profile for Network Devices",
            ProtectionProfile::MobileDevice => "Protection Profile for Mobile Device Fundamentals",
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluation Assurance Level
// ---------------------------------------------------------------------------

/// Common Criteria Evaluation Assurance Level (EAL1 through EAL7).
///
/// The MILNET SSO system targets **EAL4+** (methodically designed, tested, and
/// reviewed, augmented with additional flaw remediation).
///
/// EAL4+ is the highest level achievable without the developer providing
/// access to the complete formal design model. It is the standard target
/// for military and government SSO systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvaluationAssuranceLevel {
    /// EAL1: Functionally tested
    Eal1,
    /// EAL2: Structurally tested
    Eal2,
    /// EAL3: Methodically tested and checked
    Eal3,
    /// EAL4: Methodically designed, tested, and reviewed
    Eal4,
    /// EAL5: Semiformally designed and tested
    Eal5,
    /// EAL6: Semiformally verified design and tested
    Eal6,
    /// EAL7: Formally verified design and tested
    Eal7,
}

impl EvaluationAssuranceLevel {
    /// Return the numeric level (1-7).
    pub fn as_u8(&self) -> u8 {
        match self {
            EvaluationAssuranceLevel::Eal1 => 1,
            EvaluationAssuranceLevel::Eal2 => 2,
            EvaluationAssuranceLevel::Eal3 => 3,
            EvaluationAssuranceLevel::Eal4 => 4,
            EvaluationAssuranceLevel::Eal5 => 5,
            EvaluationAssuranceLevel::Eal6 => 6,
            EvaluationAssuranceLevel::Eal7 => 7,
        }
    }
}

impl core::fmt::Display for EvaluationAssuranceLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EAL{}", self.as_u8())
    }
}

// ---------------------------------------------------------------------------
// Security Functional Requirements (SFRs)
// ---------------------------------------------------------------------------

/// CC Security Functional Requirement (SFR) class identifiers.
///
/// Each SFR maps to a specific CC Part 2 functional class and is linked
/// to the code module(s) that implement it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityFunctionalRequirement {
    /// CC SFR identifier (e.g., "FIA_UAU.2", "FCS_COP.1").
    pub sfr_id: String,
    /// Human-readable title.
    pub title: String,
    /// CC functional class (e.g., "FIA" = Identification and Authentication).
    pub cc_class: String,
    /// Implementation description.
    pub implementation: String,
    /// Source code modules that implement this SFR.
    pub code_modules: Vec<String>,
    /// Whether this SFR is fully implemented.
    pub implemented: bool,
}

/// Return the default SFR mapping for the MILNET SSO system.
///
/// Maps CC Part 2 functional requirements to actual code modules.
pub fn default_sfr_mapping() -> Vec<SecurityFunctionalRequirement> {
    vec![
        SecurityFunctionalRequirement {
            sfr_id: "FIA_UAU.2".to_string(),
            title: "User authentication before any action".to_string(),
            cc_class: "FIA".to_string(),
            implementation: "OPAQUE PAKE protocol + FIDO2 WebAuthn + CAC/PIV + TOTP. \
                All authentication occurs before any privileged action is permitted."
                .to_string(),
            code_modules: vec![
                "opaque/src/opaque_impl.rs".to_string(),
                "fido/src/authentication.rs".to_string(),
                "common/src/cac_auth.rs".to_string(),
                "common/src/totp.rs".to_string(),
            ],
            implemented: true,
        },
        SecurityFunctionalRequirement {
            sfr_id: "FIA_UID.2".to_string(),
            title: "User identification before any action".to_string(),
            cc_class: "FIA".to_string(),
            implementation: "Identity established via X.509 certificates (CAC/PIV), \
                FIDO2 credential IDs, or OPAQUE user identifiers."
                .to_string(),
            code_modules: vec![
                "common/src/cac.rs".to_string(),
                "fido/src/registration.rs".to_string(),
            ],
            implemented: true,
        },
        SecurityFunctionalRequirement {
            sfr_id: "FCS_COP.1".to_string(),
            title: "Cryptographic operation".to_string(),
            cc_class: "FCS".to_string(),
            implementation: "AES-256-GCM for symmetric encryption, SHA-512/SHA-384 for hashing, \
                ML-DSA-87 for post-quantum signatures, ML-KEM-1024 for key encapsulation. \
                All algorithms are NIST-approved and tracked for FIPS 140-3 validation."
                .to_string(),
            code_modules: vec![
                "crypto/src/pq_sign.rs".to_string(),
                "crypto/src/xwing.rs".to_string(),
                "common/src/cnsa2.rs".to_string(),
                "common/src/fips_validation.rs".to_string(),
            ],
            implemented: true,
        },
        SecurityFunctionalRequirement {
            sfr_id: "FCS_CKM.1".to_string(),
            title: "Cryptographic key generation".to_string(),
            cc_class: "FCS".to_string(),
            implementation: "Key generation via FROST DKG (distributed), X-Wing combiner \
                (X25519 + ML-KEM-1024), and sealed key storage with vTPM binding."
                .to_string(),
            code_modules: vec![
                "crypto/src/frost.rs".to_string(),
                "crypto/src/xwing.rs".to_string(),
                "common/src/sealed_keys.rs".to_string(),
            ],
            implemented: true,
        },
        SecurityFunctionalRequirement {
            sfr_id: "FCS_CKM.4".to_string(),
            title: "Cryptographic key destruction".to_string(),
            cc_class: "FCS".to_string(),
            implementation: "Zeroize trait applied to all key material. Key rotation with \
                secure destruction of old keys via key_rotation module."
                .to_string(),
            code_modules: vec![
                "common/src/key_rotation.rs".to_string(),
                "crypto/src/memguard.rs".to_string(),
            ],
            implemented: true,
        },
        SecurityFunctionalRequirement {
            sfr_id: "FAU_GEN.1".to_string(),
            title: "Audit data generation".to_string(),
            cc_class: "FAU".to_string(),
            implementation: "SIEM event emission for all security-relevant events. \
                BFT audit log with tamper-evident chaining. Structured JSON logging."
                .to_string(),
            code_modules: vec![
                "common/src/siem.rs".to_string(),
                "common/src/encrypted_audit.rs".to_string(),
                "common/src/structured_logging.rs".to_string(),
            ],
            implemented: true,
        },
        SecurityFunctionalRequirement {
            sfr_id: "FDP_ACC.1".to_string(),
            title: "Subset access control".to_string(),
            cc_class: "FDP".to_string(),
            implementation: "Role-based access control via IDM module. Conditional access \
                policies with device tier, risk score, and classification level enforcement."
                .to_string(),
            code_modules: vec![
                "common/src/idm.rs".to_string(),
                "common/src/conditional_access.rs".to_string(),
                "common/src/classification.rs".to_string(),
            ],
            implemented: true,
        },
        SecurityFunctionalRequirement {
            sfr_id: "FPT_TST.1".to_string(),
            title: "TSF self test".to_string(),
            cc_class: "FPT".to_string(),
            implementation: "Binary attestation via BLAKE3 at startup. Measured boot \
                with vTPM PCR extension. Platform integrity monitoring."
                .to_string(),
            code_modules: vec![
                "crypto/src/attest.rs".to_string(),
                "common/src/measured_boot.rs".to_string(),
                "common/src/platform_integrity.rs".to_string(),
            ],
            implemented: true,
        },
        // ── FTP: Trusted Path ──
        SecurityFunctionalRequirement {
            sfr_id: "FTP_ITC.1".to_string(),
            title: "Inter-TSF trusted channel".to_string(),
            cc_class: "FTP".to_string(),
            implementation: "mTLS with certificate pinning between all internal modules. \
                TLS 1.3 with CNSA 2.0 cipher suites for all external communications."
                .to_string(),
            code_modules: vec![
                "shard/src/tls.rs".to_string(),
                "gateway/src/main.rs".to_string(),
            ],
            implemented: true,
        },
        SecurityFunctionalRequirement {
            sfr_id: "FTP_TRP.1".to_string(),
            title: "Trusted path".to_string(),
            cc_class: "FTP".to_string(),
            implementation: "TLS 1.3 trusted path for all user-facing communications. \
                DPoP proof-of-possession prevents token interception."
                .to_string(),
            code_modules: vec![
                "crypto/src/dpop.rs".to_string(),
            ],
            implemented: true,
        },
        // ── FMT: Security Management ──
        SecurityFunctionalRequirement {
            sfr_id: "FMT_SMF.1".to_string(),
            title: "Specification of management functions".to_string(),
            cc_class: "FMT".to_string(),
            implementation: "Admin service exposes management functions with RBAC. \
                Key rotation, user management, and policy configuration available \
                through authenticated admin API."
                .to_string(),
            code_modules: vec![
                "admin/src/routes.rs".to_string(),
                "common/src/idm.rs".to_string(),
            ],
            implemented: false, // Not fully verified: admin API coverage incomplete
        },
        SecurityFunctionalRequirement {
            sfr_id: "FMT_SMR.1".to_string(),
            title: "Security management roles".to_string(),
            cc_class: "FMT".to_string(),
            implementation: "RBAC roles defined (admin, operator, viewer). Role assignment \
                requires ceremony approval at elevated tiers."
                .to_string(),
            code_modules: vec![
                "common/src/idm.rs".to_string(),
                "common/src/conditional_access.rs".to_string(),
            ],
            implemented: true,
        },
        // ── FTA: TOE Access ──
        SecurityFunctionalRequirement {
            sfr_id: "FTA_SSL.1".to_string(),
            title: "TSF-initiated session locking".to_string(),
            cc_class: "FTA".to_string(),
            implementation: "Session idle timeout locks sessions after configurable period. \
                Sovereign tier uses reduced timeouts."
                .to_string(),
            code_modules: vec![
                "common/src/session_limits.rs".to_string(),
            ],
            implemented: true,
        },
        SecurityFunctionalRequirement {
            sfr_id: "FTA_TSE.1".to_string(),
            title: "TOE session establishment".to_string(),
            cc_class: "FTA".to_string(),
            implementation: "Conditional access policies control session establishment based \
                on device tier, risk score, and classification level."
                .to_string(),
            code_modules: vec![
                "common/src/conditional_access.rs".to_string(),
            ],
            implemented: false, // Not fully verified: conditional access policy engine incomplete
        },
    ]
}

// ---------------------------------------------------------------------------
// Security Assurance Requirements (SARs)
// ---------------------------------------------------------------------------

/// CC Security Assurance Requirement (SAR) mapped to development artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAssuranceRequirement {
    /// CC SAR identifier (e.g., "ADV_ARC.1", "ATE_COV.2").
    pub sar_id: String,
    /// Human-readable title.
    pub title: String,
    /// CC assurance class (e.g., "ADV" = Development).
    pub cc_class: String,
    /// Description of how this SAR is satisfied.
    pub satisfaction: String,
    /// Artifacts that provide evidence for this SAR.
    pub evidence_artifacts: Vec<String>,
}

/// Return the default SAR mapping for EAL4+ evaluation.
pub fn default_sar_mapping() -> Vec<SecurityAssuranceRequirement> {
    vec![
        SecurityAssuranceRequirement {
            sar_id: "ADV_ARC.1".to_string(),
            title: "Security architecture description".to_string(),
            cc_class: "ADV".to_string(),
            satisfaction: "Modular architecture with crate-level separation of concerns. \
                Each security domain (crypto, auth, audit) is isolated in dedicated crates."
                .to_string(),
            evidence_artifacts: vec![
                "Cargo.toml workspace members".to_string(),
                "Architecture documentation".to_string(),
            ],
        },
        SecurityAssuranceRequirement {
            sar_id: "ADV_FSP.4".to_string(),
            title: "Complete functional specification".to_string(),
            cc_class: "ADV".to_string(),
            satisfaction: "Public API documented via rustdoc with security invariants. \
                All public functions have doc comments specifying preconditions."
                .to_string(),
            evidence_artifacts: vec![
                "cargo doc output".to_string(),
                "Public API surface audit".to_string(),
            ],
        },
        SecurityAssuranceRequirement {
            sar_id: "ATE_COV.2".to_string(),
            title: "Analysis of coverage".to_string(),
            cc_class: "ATE".to_string(),
            satisfaction: "Comprehensive unit and integration test suites. \
                Each security module has dedicated test coverage."
                .to_string(),
            evidence_artifacts: vec![
                "cargo test output".to_string(),
                "Test coverage report".to_string(),
            ],
        },
        SecurityAssuranceRequirement {
            sar_id: "ATE_FUN.1".to_string(),
            title: "Functional testing".to_string(),
            cc_class: "ATE".to_string(),
            satisfaction: "Automated test suites executed in CI/CD pipeline. \
                STIG scanner integrated into CI for regression detection."
                .to_string(),
            evidence_artifacts: vec![
                "CI/CD pipeline logs".to_string(),
                "STIG scan reports".to_string(),
            ],
        },
        SecurityAssuranceRequirement {
            sar_id: "AVA_VAN.3".to_string(),
            title: "Focused vulnerability analysis".to_string(),
            cc_class: "AVA".to_string(),
            satisfaction: "Dependency auditing via cargo-audit. STIG and CIS benchmark \
                scanning at startup. Continuous monitoring via SIEM integration."
                .to_string(),
            evidence_artifacts: vec![
                "cargo audit report".to_string(),
                "STIG audit results".to_string(),
                "SIEM dashboard".to_string(),
            ],
        },
        SecurityAssuranceRequirement {
            sar_id: "ALC_FLR.2".to_string(),
            title: "Flaw reporting procedures".to_string(),
            cc_class: "ALC".to_string(),
            satisfaction: "Incident response module with automated SIEM alerting. \
                Flaw remediation tracked via POA&M entries in FedRAMP evidence module."
                .to_string(),
            evidence_artifacts: vec![
                "common/src/incident_response.rs".to_string(),
                "common/src/fedramp_evidence.rs (POA&M entries)".to_string(),
            ],
        },
    ]
}

// ---------------------------------------------------------------------------
// Target of Evaluation (TOE) Boundary
// ---------------------------------------------------------------------------

/// Defines the boundary of the Target of Evaluation (TOE).
///
/// The TOE encompasses all software components that implement security
/// functions. Components outside the TOE boundary are part of the
/// operational environment and must meet stated assumptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToeBoundary {
    /// Components included in the TOE.
    pub included_components: Vec<ToeComponent>,
    /// Environmental assumptions (components outside the TOE).
    pub environmental_assumptions: Vec<String>,
}

/// A component within the TOE boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToeComponent {
    /// Component name.
    pub name: String,
    /// Crate or module path.
    pub module_path: String,
    /// Security functions provided by this component.
    pub security_functions: Vec<String>,
}

/// Return the default TOE boundary definition for the MILNET SSO system.
pub fn default_toe_boundary() -> ToeBoundary {
    ToeBoundary {
        included_components: vec![
            ToeComponent {
                name: "Gateway".to_string(),
                module_path: "gateway/".to_string(),
                security_functions: vec![
                    "TLS termination".to_string(),
                    "Rate limiting".to_string(),
                    "Request routing".to_string(),
                ],
            },
            ToeComponent {
                name: "Cryptographic Core".to_string(),
                module_path: "crypto/".to_string(),
                security_functions: vec![
                    "Post-quantum key agreement (X-Wing)".to_string(),
                    "Digital signatures (ML-DSA-87, SLH-DSA)".to_string(),
                    "Binary attestation (BLAKE3)".to_string(),
                    "Threshold cryptography (FROST)".to_string(),
                    "DPoP proof-of-possession".to_string(),
                ],
            },
            ToeComponent {
                name: "Authentication Services".to_string(),
                module_path: "opaque/, fido/".to_string(),
                security_functions: vec![
                    "OPAQUE password-blind protocol".to_string(),
                    "FIDO2/WebAuthn registration and authentication".to_string(),
                ],
            },
            ToeComponent {
                name: "Common Security Infrastructure".to_string(),
                module_path: "common/".to_string(),
                security_functions: vec![
                    "SIEM event emission".to_string(),
                    "FIPS mode enforcement".to_string(),
                    "Key rotation and lifecycle".to_string(),
                    "Session management and limits".to_string(),
                    "RBAC and conditional access".to_string(),
                    "Compliance policy engine".to_string(),
                ],
            },
            ToeComponent {
                name: "Shard (Distributed State)".to_string(),
                module_path: "shard/".to_string(),
                security_functions: vec![
                    "mTLS inter-module communication".to_string(),
                    "Certificate pinning".to_string(),
                    "BFT audit replication".to_string(),
                ],
            },
        ],
        environmental_assumptions: vec![
            "A.PHYSICAL: The TOE operates in a physically secured facility".to_string(),
            "A.NETWORK: Network infrastructure provides basic connectivity; \
             the TOE does not rely on network-level security below TLS"
                .to_string(),
            "A.ADMIN: Administrators are trusted, trained, and follow operational procedures"
                .to_string(),
            "A.OS: The underlying OS is hardened per DISA STIG and CIS benchmarks"
                .to_string(),
            "A.TIME: A trusted time source (NTP with authentication) is available"
                .to_string(),
        ],
    }
}

// ---------------------------------------------------------------------------
// Security Target (top-level)
// ---------------------------------------------------------------------------

/// The complete Common Criteria Security Target for the MILNET SSO system.
pub struct SecurityTarget {
    /// TOE name.
    pub toe_name: String,
    /// TOE version.
    pub toe_version: String,
    /// Target EAL level.
    pub eal: EvaluationAssuranceLevel,
    /// Claimed protection profiles.
    pub protection_profiles: Vec<ProtectionProfile>,
    /// Security Functional Requirements.
    pub sfrs: Vec<SecurityFunctionalRequirement>,
    /// Security Assurance Requirements.
    pub sars: Vec<SecurityAssuranceRequirement>,
    /// TOE boundary definition.
    pub toe_boundary: ToeBoundary,
}

impl SecurityTarget {
    /// Create the default Security Target for the MILNET SSO system.
    ///
    /// Targets EAL4+ with conformance to the Application Software PP.
    pub fn milnet_default() -> Self {
        Self {
            toe_name: "MILNET Enterprise SSO System".to_string(),
            toe_version: env!("CARGO_PKG_VERSION").to_string(),
            eal: EvaluationAssuranceLevel::Eal4,
            protection_profiles: vec![
                ProtectionProfile::AppSoftware,
                ProtectionProfile::NetworkDevice,
            ],
            sfrs: default_sfr_mapping(),
            sars: default_sar_mapping(),
            toe_boundary: default_toe_boundary(),
        }
    }

    /// Return the fraction of SFRs that are fully implemented (0.0 to 1.0).
    ///
    /// Uses the `implemented` flag on each SFR. SFRs marked `implemented: false`
    /// have not been verified and reduce the coverage percentage.
    pub fn sfr_implementation_coverage(&self) -> f64 {
        if self.sfrs.is_empty() {
            return 0.0;
        }
        let verified = self.sfrs.iter().filter(|s| s.implemented).count();
        verified as f64 / self.sfrs.len() as f64
    }

    /// Return SFRs that are NOT implemented.
    pub fn unimplemented_sfrs(&self) -> Vec<&SecurityFunctionalRequirement> {
        self.sfrs.iter().filter(|s| !s.implemented).collect()
    }

    /// Return the CC functional classes covered by implemented SFRs.
    pub fn covered_classes(&self) -> Vec<String> {
        let mut classes: Vec<String> = self
            .sfrs
            .iter()
            .filter(|s| s.implemented)
            .map(|s| s.cc_class.clone())
            .collect();
        classes.sort();
        classes.dedup();
        classes
    }

    /// Generate a text summary of the Security Target.
    pub fn generate_summary(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!(
            "=== Common Criteria Security Target ===\n\n\
             TOE: {} v{}\n\
             Target EAL: {}\n\n",
            self.toe_name, self.toe_version, self.eal
        ));

        report.push_str("Protection Profiles:\n");
        for pp in &self.protection_profiles {
            report.push_str(&format!("  - {} ({})\n", pp.niap_id(), pp.title()));
        }

        report.push_str(&format!(
            "\nSFR Coverage: {:.0}% ({}/{})\n",
            self.sfr_implementation_coverage() * 100.0,
            self.sfrs.iter().filter(|s| s.implemented).count(),
            self.sfrs.len()
        ));

        let unimpl = self.unimplemented_sfrs();
        if !unimpl.is_empty() {
            report.push_str("Unimplemented SFRs:\n");
            for sfr in &unimpl {
                report.push_str(&format!("  - {} ({}): {}\n", sfr.sfr_id, sfr.cc_class, sfr.title));
            }
        }

        report.push_str(&format!("\nSAR Count: {}\n", self.sars.len()));
        report.push_str(&format!(
            "TOE Components: {}\n",
            self.toe_boundary.included_components.len()
        ));
        report.push_str(&format!(
            "CC Classes Covered: {}\n",
            self.covered_classes().join(", ")
        ));

        report
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_profile_ids() {
        assert_eq!(ProtectionProfile::AppSoftware.niap_id(), "PP_APP_v1.4");
        assert_eq!(ProtectionProfile::NetworkDevice.niap_id(), "PP_ND_v2.2e");
    }

    #[test]
    fn test_eal_display() {
        assert_eq!(EvaluationAssuranceLevel::Eal1.to_string(), "EAL1");
        assert_eq!(EvaluationAssuranceLevel::Eal4.to_string(), "EAL4");
        assert_eq!(EvaluationAssuranceLevel::Eal7.to_string(), "EAL7");
    }

    #[test]
    fn test_eal_ordering() {
        assert!(EvaluationAssuranceLevel::Eal1 < EvaluationAssuranceLevel::Eal4);
        assert!(EvaluationAssuranceLevel::Eal4 < EvaluationAssuranceLevel::Eal7);
    }

    #[test]
    fn test_default_sfrs_have_code_references() {
        let sfrs = default_sfr_mapping();
        assert!(!sfrs.is_empty());
        for sfr in &sfrs {
            assert!(!sfr.code_modules.is_empty(), "SFR {} must have code references", sfr.sfr_id);
        }
    }

    #[test]
    fn test_default_sfrs_include_new_classes() {
        let sfrs = default_sfr_mapping();
        let classes: Vec<&str> = sfrs.iter().map(|s| s.cc_class.as_str()).collect();
        assert!(classes.contains(&"FTP"), "must include FTP (Trusted Path)");
        assert!(classes.contains(&"FMT"), "must include FMT (Security Management)");
        assert!(classes.contains(&"FTA"), "must include FTA (TOE Access)");
    }

    #[test]
    fn test_sfr_coverage_not_100_percent() {
        let st = SecurityTarget::milnet_default();
        // With FMT_SMF.1 and FTA_TSE.1 marked as not implemented, coverage < 1.0
        assert!(
            st.sfr_implementation_coverage() < 1.0,
            "SFR coverage should be < 100% with unimplemented SFRs"
        );
        assert!(
            st.sfr_implementation_coverage() > 0.5,
            "SFR coverage should be > 50%"
        );
    }

    #[test]
    fn test_default_sars_have_evidence() {
        let sars = default_sar_mapping();
        assert!(!sars.is_empty());
        for sar in &sars {
            assert!(
                !sar.evidence_artifacts.is_empty(),
                "SAR {} must have evidence artifacts",
                sar.sar_id
            );
        }
    }

    #[test]
    fn test_toe_boundary_has_components() {
        let toe = default_toe_boundary();
        assert!(toe.included_components.len() >= 5);
        assert!(!toe.environmental_assumptions.is_empty());
    }

    #[test]
    fn test_security_target_default() {
        let st = SecurityTarget::milnet_default();
        assert_eq!(st.eal, EvaluationAssuranceLevel::Eal4);
        assert!(!st.protection_profiles.is_empty());
        assert!(!st.sfrs.is_empty());
        assert!(!st.sars.is_empty());
        // Coverage is < 100% with honest assessment
        assert!(st.sfr_implementation_coverage() < 1.0);
    }

    #[test]
    fn test_security_target_summary() {
        let st = SecurityTarget::milnet_default();
        let summary = st.generate_summary();
        assert!(summary.contains("MILNET Enterprise SSO System"));
        assert!(summary.contains("EAL4"));
        assert!(summary.contains("PP_APP_v1.4"));
        // Coverage is no longer 100%
        assert!(!summary.contains("100%"), "should not claim 100% with unimplemented SFRs");
        assert!(summary.contains("Unimplemented SFRs"));
    }

    #[test]
    fn test_unimplemented_sfrs_identified() {
        let st = SecurityTarget::milnet_default();
        let unimpl = st.unimplemented_sfrs();
        assert!(!unimpl.is_empty(), "should identify unimplemented SFRs");
        let ids: Vec<&str> = unimpl.iter().map(|s| s.sfr_id.as_str()).collect();
        assert!(ids.contains(&"FMT_SMF.1") || ids.contains(&"FTA_TSE.1"),
            "should include FMT_SMF.1 or FTA_TSE.1 as unimplemented");
    }

    #[test]
    fn test_covered_classes() {
        let st = SecurityTarget::milnet_default();
        let classes = st.covered_classes();
        assert!(classes.contains(&"FIA".to_string()));
        assert!(classes.contains(&"FCS".to_string()));
        assert!(classes.contains(&"FTP".to_string()));
    }
}
