//! FIPS 140-3 Validation Abstraction Layer.
//!
//! Tracks the CMVP (Cryptographic Module Validation Program) validation status
//! of every cryptographic module used in the MILNET SSO system. This layer
//! provides visibility into which algorithms have been formally validated
//! under FIPS 140-3 and which are pending submission.
//!
//! # Background
//!
//! FIPS 140-3 validation is a multi-step process:
//! 1. Module submitted to a CMVP-accredited lab (CST Lab)
//! 2. Lab performs conformance testing against FIPS standards
//! 3. CMVP reviews and issues a certificate with a level (1-4)
//! 4. Certificate is valid until expiry or revocation
//!
//! Post-quantum algorithms (ML-DSA-87, ML-KEM-1024) have been standardized
//! by NIST (FIPS 203/204) but Rust implementations have not yet completed
//! CMVP validation. This module tracks that gap explicitly.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

// ---------------------------------------------------------------------------
// FIPS Level
// ---------------------------------------------------------------------------

/// FIPS 140-3 security level (1 through 4).
///
/// Each level adds requirements:
/// - Level 1: Basic security, no physical tamper resistance
/// - Level 2: Tamper-evident coatings, role-based authentication
/// - Level 3: Tamper-resistant enclosures, identity-based authentication
/// - Level 4: Complete envelope of protection, environmental failure testing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum FipsLevel {
    Level1,
    Level2,
    Level3,
    Level4,
}

impl FipsLevel {
    /// Return the numeric level (1-4).
    pub fn as_u8(&self) -> u8 {
        match self {
            FipsLevel::Level1 => 1,
            FipsLevel::Level2 => 2,
            FipsLevel::Level3 => 3,
            FipsLevel::Level4 => 4,
        }
    }
}

impl core::fmt::Display for FipsLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Level {}", self.as_u8())
    }
}

// ---------------------------------------------------------------------------
// Validation Status
// ---------------------------------------------------------------------------

/// FIPS 140-3 validation lifecycle state for a cryptographic module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FipsValidationStatus {
    /// Module has not yet been submitted to CMVP for validation.
    NotSubmitted,

    /// Submission is in progress at a CMVP-accredited CST lab.
    InReview,

    /// Module has been validated and holds an active CMVP certificate.
    Validated {
        /// CMVP certificate number (e.g. "4282").
        cert_number: String,
        /// Validated FIPS 140-3 security level.
        level: FipsLevel,
        /// Certificate expiry date in ISO 8601 format (YYYY-MM-DD).
        expiry: String,
    },

    /// Certificate has expired or been revoked. Module must not be used
    /// in FIPS-required contexts until re-validated.
    Historical,
}

impl FipsValidationStatus {
    /// Returns `true` if the module holds a current, active FIPS certificate.
    pub fn is_validated(&self) -> bool {
        matches!(self, FipsValidationStatus::Validated { .. })
    }
}

impl core::fmt::Display for FipsValidationStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FipsValidationStatus::NotSubmitted => write!(f, "Not Submitted"),
            FipsValidationStatus::InReview => write!(f, "In Review"),
            FipsValidationStatus::Validated {
                cert_number,
                level,
                expiry,
            } => write!(
                f,
                "Validated (cert #{}, {}, expires {})",
                cert_number, level, expiry
            ),
            FipsValidationStatus::Historical => write!(f, "Historical (expired/revoked)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Crypto Module
// ---------------------------------------------------------------------------

/// A cryptographic module tracked for FIPS 140-3 validation.
///
/// Each module corresponds to a specific algorithm implementation used
/// in the system (e.g., the `aes-gcm` crate's AES-256-GCM implementation).
#[derive(Debug, Clone)]
pub struct FipsCryptoModule {
    /// Human-readable module name (e.g., "AES-256-GCM (aes-gcm crate)").
    pub module_name: String,
    /// Module version string.
    pub version: String,
    /// FIPS-approved algorithm identifiers implemented by this module
    /// (e.g., ["AES-256-GCM", "AES-256-CBC"]).
    pub algorithms: Vec<String>,
    /// Current CMVP validation status.
    pub validation_status: FipsValidationStatus,
    /// Name of the CST lab performing validation (if applicable).
    pub lab_name: Option<String>,
    /// Date the module was submitted for validation (ISO 8601, if applicable).
    pub submission_date: Option<String>,
}

impl FipsCryptoModule {
    /// Returns `true` if this module holds an active FIPS 140-3 certificate.
    pub fn is_validated(&self) -> bool {
        self.validation_status.is_validated()
    }

    /// Check whether a specific algorithm is implemented by this module.
    pub fn is_approved_algorithm(&self, algo: &str) -> bool {
        self.algorithms.iter().any(|a| a == algo)
    }

    /// Compute the number of days until the FIPS certificate expires.
    ///
    /// Returns `None` if the module is not validated or the expiry date
    /// cannot be parsed. Returns negative values if already expired.
    pub fn days_until_expiry(&self) -> Option<i64> {
        match &self.validation_status {
            FipsValidationStatus::Validated { expiry, .. } => {
                // Parse YYYY-MM-DD and compute days from today.
                // We use a simple manual parser to avoid pulling in chrono.
                parse_days_until(expiry)
            }
            _ => None,
        }
    }
}

/// Simple date parser: compute days from today to a YYYY-MM-DD date string.
/// Returns `None` if parsing fails.
fn parse_days_until(date_str: &str) -> Option<i64> {
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: i64 = parts[0].parse().ok()?;
    let month: i64 = parts[1].parse().ok()?;
    let day: i64 = parts[2].parse().ok()?;

    // Convert to a rough day count using a simplified Julian Day calculation.
    // This is accurate enough for "days until expiry" purposes.
    fn to_day_count(y: i64, m: i64, d: i64) -> i64 {
        // Adjust for January/February
        let (y, m) = if m <= 2 { (y - 1, m + 12) } else { (y, m) };
        let a = y / 100;
        let b = 2 - a + a / 4;
        (365.25_f64 * (y + 4716) as f64) as i64
            + (30.6001_f64 * (m + 1) as f64) as i64
            + d
            + b
            - 1524
    }

    // Get "today" from std::time::SystemTime.
    // Days since Unix epoch (1970-01-01).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let today_days_since_epoch = (now.as_secs() / 86400) as i64;

    let epoch_jd = to_day_count(1970, 1, 1);
    let target_jd = to_day_count(year, month, day);
    let today_jd = epoch_jd + today_days_since_epoch;

    Some(target_jd - today_jd)
}

// ---------------------------------------------------------------------------
// Compliance Registry
// ---------------------------------------------------------------------------

/// Global FIPS compliance registry tracking all cryptographic modules
/// used in the MILNET SSO system.
///
/// This registry provides a single source of truth for the CMVP validation
/// status of every algorithm. It is populated at startup and can be queried
/// by compliance auditors, health checks, and the admin dashboard.
pub struct FipsComplianceRegistry {
    modules: BTreeMap<String, FipsCryptoModule>,
}

impl FipsComplianceRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
        }
    }

    /// Register a cryptographic module in the registry.
    ///
    /// If a module with the same name already exists, it is replaced.
    pub fn register_module(&mut self, module: FipsCryptoModule) {
        self.modules.insert(module.module_name.clone(), module);
    }

    /// Retrieve a module by name.
    pub fn get_module(&self, name: &str) -> Option<&FipsCryptoModule> {
        self.modules.get(name)
    }

    /// Returns `true` if ALL registered modules hold active FIPS certificates.
    pub fn all_validated(&self) -> bool {
        !self.modules.is_empty() && self.modules.values().all(|m| m.is_validated())
    }

    /// Return the total number of registered modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Return how many modules are currently validated.
    pub fn validated_count(&self) -> usize {
        self.modules.values().filter(|m| m.is_validated()).count()
    }

    /// Return a list of modules that are NOT yet validated.
    pub fn unvalidated_modules(&self) -> Vec<&FipsCryptoModule> {
        self.modules.values().filter(|m| !m.is_validated()).collect()
    }

    /// Generate a compliance report as a human-readable string.
    ///
    /// The report includes:
    /// - Summary statistics
    /// - Per-module validation status
    /// - Expiry warnings for modules expiring within 90 days
    /// - Transition plan status
    pub fn generate_compliance_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== FIPS 140-3 Compliance Report ===\n\n");

        let total = self.modules.len();
        let validated = self.validated_count();
        let unvalidated = total - validated;

        report.push_str(&format!(
            "Summary: {}/{} modules validated ({} pending)\n\n",
            validated, total, unvalidated
        ));

        // Per-module details
        for (name, module) in &self.modules {
            report.push_str(&format!("Module: {}\n", name));
            report.push_str(&format!("  Version: {}\n", module.version));
            report.push_str(&format!(
                "  Algorithms: {}\n",
                module.algorithms.join(", ")
            ));
            report.push_str(&format!("  Status: {}\n", module.validation_status));

            if let Some(ref lab) = module.lab_name {
                report.push_str(&format!("  Lab: {}\n", lab));
            }
            if let Some(ref date) = module.submission_date {
                report.push_str(&format!("  Submitted: {}\n", date));
            }

            // Expiry warning
            if let Some(days) = module.days_until_expiry() {
                if days < 0 {
                    report.push_str(&format!(
                        "  WARNING: Certificate EXPIRED {} days ago!\n",
                        -days
                    ));
                } else if days <= 90 {
                    report.push_str(&format!(
                        "  WARNING: Certificate expires in {} days\n",
                        days
                    ));
                }
            }

            report.push('\n');
        }

        // Overall assessment
        if self.all_validated() {
            report.push_str("ASSESSMENT: All modules FIPS 140-3 validated.\n");
        } else {
            report.push_str("ASSESSMENT: NOT fully FIPS 140-3 compliant.\n");
            report.push_str("  The following modules require validation:\n");
            for m in self.unvalidated_modules() {
                report.push_str(&format!(
                    "  - {} ({})\n",
                    m.module_name, m.validation_status
                ));
            }
        }

        report
    }
}

impl Default for FipsComplianceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Honest FIPS compliance summary for auditors and dashboards.
#[derive(Debug, Clone)]
pub struct FipsComplianceSummary {
    /// Total registered cryptographic modules.
    pub total_modules: usize,
    /// Modules with active CMVP certificates.
    pub validated_modules: usize,
    /// Modules pending submission or in review.
    pub unvalidated_modules: Vec<String>,
    /// True percentage of CMVP-validated modules.
    pub compliance_percentage: f64,
    /// Whether the system meets FIPS 140-3 requirements for military deployment.
    pub military_ready: bool,
    /// Human-readable honest assessment.
    pub assessment: String,
}

/// Return an honest FIPS compliance summary from the global registry.
pub fn fips_compliance_summary() -> FipsComplianceSummary {
    let registry = global_registry().lock().unwrap();
    let total = registry.module_count();
    let validated = registry.validated_count();
    let pct = compliance_percentage_from_registry(&registry);
    let unvalidated: Vec<String> = registry
        .unvalidated_modules()
        .iter()
        .map(|m| m.module_name.clone())
        .collect();

    let military_ready = registry.all_validated();

    let assessment = if military_ready {
        "All cryptographic modules hold active FIPS 140-3 CMVP certificates.".to_string()
    } else if validated == 0 {
        format!(
            "NONE of {} cryptographic modules have CMVP validation. \
             All algorithms are NIST-approved but Rust implementations have not been \
             submitted to a CMVP-accredited lab. System is NOT FIPS 140-3 compliant.",
            total
        )
    } else {
        format!(
            "{}/{} modules validated ({:.0}%). {} modules lack CMVP certificates. \
             System is PARTIALLY FIPS 140-3 compliant.",
            validated,
            total,
            pct,
            total - validated
        )
    };

    FipsComplianceSummary {
        total_modules: total,
        validated_modules: validated,
        unvalidated_modules: unvalidated,
        compliance_percentage: pct,
        military_ready,
        assessment,
    }
}

/// Return the true FIPS CMVP validation percentage (0.0 to 100.0).
pub fn compliance_percentage() -> f64 {
    let registry = global_registry().lock().unwrap();
    compliance_percentage_from_registry(&registry)
}

fn compliance_percentage_from_registry(registry: &FipsComplianceRegistry) -> f64 {
    let total = registry.module_count();
    if total == 0 {
        return 0.0;
    }
    (registry.validated_count() as f64 / total as f64) * 100.0
}

/// Run FIPS compliance startup check.
///
/// If `MILNET_MILITARY_DEPLOYMENT=1` and any required module is `NotSubmitted`,
/// logs `SIEM:CRITICAL` with exact module names. Does NOT exit (FIPS submission
/// is an external process), but makes the gap highly visible.
pub fn fips_startup_check() {
    let summary = fips_compliance_summary();
    let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1");

    if is_military && !summary.military_ready {
        tracing::error!(
            "SIEM:CRITICAL FIPS-STARTUP: Military deployment active but {}/{} modules \
             lack CMVP validation. Non-validated modules: [{}]. \
             Compliance: {:.0}%. System is NOT FIPS 140-3 certified.",
            summary.unvalidated_modules.len(),
            summary.total_modules,
            summary.unvalidated_modules.join(", "),
            summary.compliance_percentage,
        );
    } else if !summary.military_ready {
        tracing::warn!(
            "FIPS-STARTUP: {}/{} modules validated ({:.0}%). \
             Non-validated: [{}]",
            summary.validated_modules,
            summary.total_modules,
            summary.compliance_percentage,
            summary.unvalidated_modules.join(", "),
        );
    } else {
        tracing::info!(
            "FIPS-STARTUP: All {} modules hold active CMVP certificates.",
            summary.total_modules,
        );
    }
}

// ---------------------------------------------------------------------------
// Transition Plan
// ---------------------------------------------------------------------------

/// A milestone in the FIPS 140-3 validation transition plan.
#[derive(Debug, Clone)]
pub struct TransitionMilestone {
    /// Milestone identifier (e.g., "M1", "M2").
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Target completion date (ISO 8601).
    pub target_date: String,
    /// Whether this milestone has been completed.
    pub completed: bool,
}

/// FIPS 140-3 transition plan with timeline milestones.
///
/// Tracks the phased approach to achieving full FIPS 140-3 validation
/// for all cryptographic modules in the system.
#[derive(Debug, Clone)]
pub struct FipsTransitionPlan {
    /// Plan name/identifier.
    pub plan_name: String,
    /// Overall target date for full FIPS compliance.
    pub target_completion: String,
    /// Ordered list of milestones.
    pub milestones: Vec<TransitionMilestone>,
}

impl FipsTransitionPlan {
    /// Create the default transition plan for the MILNET SSO system.
    pub fn default_plan() -> Self {
        Self {
            plan_name: "MILNET FIPS 140-3 Validation Plan".into(),
            target_completion: "2027-12-31".into(),
            milestones: vec![
                TransitionMilestone {
                    id: "M1".into(),
                    description: "Select CMVP-accredited CST lab for classical algorithms".into(),
                    target_date: "2026-06-30".into(),
                    completed: false,
                },
                TransitionMilestone {
                    id: "M2".into(),
                    description: "Submit AES-256-GCM, SHA-512, HMAC-SHA512, HKDF modules for testing".into(),
                    target_date: "2026-09-30".into(),
                    completed: false,
                },
                TransitionMilestone {
                    id: "M3".into(),
                    description: "Receive CMVP certificates for classical algorithm modules".into(),
                    target_date: "2027-03-31".into(),
                    completed: false,
                },
                TransitionMilestone {
                    id: "M4".into(),
                    description: "Submit ML-DSA-87 and ML-KEM-1024 modules once CMVP PQ testing guidance is final".into(),
                    target_date: "2027-06-30".into(),
                    completed: false,
                },
                TransitionMilestone {
                    id: "M5".into(),
                    description: "Receive CMVP certificates for post-quantum modules".into(),
                    target_date: "2027-12-31".into(),
                    completed: false,
                },
                TransitionMilestone {
                    id: "M6".into(),
                    description: "Full FIPS 140-3 compliance achieved for all cryptographic modules".into(),
                    target_date: "2027-12-31".into(),
                    completed: false,
                },
            ],
        }
    }

    /// Return the fraction of milestones completed (0.0 to 1.0).
    pub fn completion_fraction(&self) -> f64 {
        if self.milestones.is_empty() {
            return 1.0;
        }
        let completed = self.milestones.iter().filter(|m| m.completed).count();
        completed as f64 / self.milestones.len() as f64
    }

    /// Return milestones that are overdue (target_date in the past, not completed).
    pub fn overdue_milestones(&self) -> Vec<&TransitionMilestone> {
        self.milestones
            .iter()
            .filter(|m| {
                if m.completed {
                    return false;
                }
                // Check if target_date is in the past
                parse_days_until(&m.target_date)
                    .map(|d| d < 0)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Generate a text report of the transition plan status.
    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!("=== {} ===\n\n", self.plan_name));
        report.push_str(&format!(
            "Target completion: {}\n",
            self.target_completion
        ));
        report.push_str(&format!(
            "Progress: {:.0}% ({}/{})\n\n",
            self.completion_fraction() * 100.0,
            self.milestones.iter().filter(|m| m.completed).count(),
            self.milestones.len()
        ));

        for ms in &self.milestones {
            let status = if ms.completed {
                "[DONE]"
            } else {
                "[TODO]"
            };
            report.push_str(&format!(
                "{} {} - {} (target: {})\n",
                status, ms.id, ms.description, ms.target_date
            ));
        }

        let overdue = self.overdue_milestones();
        if !overdue.is_empty() {
            report.push_str(&format!(
                "\nWARNING: {} overdue milestone(s):\n",
                overdue.len()
            ));
            for ms in overdue {
                report.push_str(&format!("  - {} (target was {})\n", ms.id, ms.target_date));
            }
        }

        report
    }
}

// ---------------------------------------------------------------------------
// Global Singleton
// ---------------------------------------------------------------------------

/// Global FIPS compliance registry singleton.
static GLOBAL_REGISTRY: OnceLock<Mutex<FipsComplianceRegistry>> = OnceLock::new();

/// Get a reference to the global FIPS compliance registry.
///
/// The registry is lazily initialized with default module registrations
/// on first access.
pub fn global_registry() -> &'static Mutex<FipsComplianceRegistry> {
    GLOBAL_REGISTRY.get_or_init(|| {
        let mut registry = FipsComplianceRegistry::new();
        register_default_modules(&mut registry);
        Mutex::new(registry)
    })
}

/// Pre-register all cryptographic modules used in the MILNET SSO system
/// with their current CMVP validation status.
fn register_default_modules(registry: &mut FipsComplianceRegistry) {
    // ── Classical algorithms (NIST-standardized, CMVP-testable) ──
    // These use well-established Rust crates. While the *algorithms* are
    // FIPS-approved, the specific Rust crate implementations have not been
    // submitted to CMVP. Noted as NotSubmitted.

    registry.register_module(FipsCryptoModule {
        module_name: "AES-256-GCM (aes-gcm crate)".into(),
        version: "0.10".into(),
        algorithms: vec!["AES-256-GCM".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });

    registry.register_module(FipsCryptoModule {
        module_name: "SHA-512 (sha2 crate)".into(),
        version: "0.10".into(),
        algorithms: vec!["SHA-512".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });

    registry.register_module(FipsCryptoModule {
        module_name: "HMAC-SHA512 (hmac crate)".into(),
        version: "0.12".into(),
        algorithms: vec!["HMAC-SHA512".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });

    registry.register_module(FipsCryptoModule {
        module_name: "HKDF-SHA512 (hkdf crate)".into(),
        version: "0.12".into(),
        algorithms: vec!["HKDF-SHA512".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });

    registry.register_module(FipsCryptoModule {
        module_name: "PBKDF2-SHA512 (pbkdf2 crate)".into(),
        version: "0.12".into(),
        algorithms: vec!["PBKDF2-SHA512".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });

    registry.register_module(FipsCryptoModule {
        module_name: "AEGIS-256 (aegis crate)".into(),
        version: "0.7".into(),
        algorithms: vec!["AEGIS-256".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });

    registry.register_module(FipsCryptoModule {
        module_name: "SHA3-256 (sha3 crate)".into(),
        version: "0.10".into(),
        algorithms: vec!["SHA3-256".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });

    // ── Post-Quantum algorithms (NIST FIPS 203/204/205 standardized) ──
    // NIST has approved ML-DSA and ML-KEM as FIPS standards, but the Rust
    // crate implementations (ml-dsa, ml-kem from RustCrypto/pqcrypto) have
    // NOT been submitted to CMVP for validation. CMVP testing guidance for
    // PQ algorithms is still being finalized.

    registry.register_module(FipsCryptoModule {
        module_name: "ML-DSA-87 (ml-dsa crate)".into(),
        version: "0.2".into(),
        algorithms: vec!["ML-DSA-87".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });

    registry.register_module(FipsCryptoModule {
        module_name: "ML-KEM-1024 (ml-kem crate)".into(),
        version: "0.2".into(),
        algorithms: vec!["ML-KEM-1024".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });

    registry.register_module(FipsCryptoModule {
        module_name: "SLH-DSA-SHA2-256f (slh-dsa crate)".into(),
        version: "0.2".into(),
        algorithms: vec!["SLH-DSA-SHA2-256f".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });

    // ── Threshold cryptography ──
    // FROST is based on Schnorr signatures over Ristretto255. Not a FIPS
    // standard but used for key management. Tracked for completeness.

    registry.register_module(FipsCryptoModule {
        module_name: "FROST-Ristretto255 (frost-ristretto255 crate)".into(),
        version: "2.1".into(),
        algorithms: vec!["FROST-Ristretto255".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });

    // ── Key agreement ──

    registry.register_module(FipsCryptoModule {
        module_name: "X25519 + ML-KEM-1024 X-Wing Combiner".into(),
        version: "0.1".into(),
        algorithms: vec!["X25519".into(), "ML-KEM-1024".into()],
        validation_status: FipsValidationStatus::NotSubmitted,
        lab_name: None,
        submission_date: None,
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_level_display() {
        assert_eq!(FipsLevel::Level1.to_string(), "Level 1");
        assert_eq!(FipsLevel::Level4.to_string(), "Level 4");
    }

    #[test]
    fn test_fips_level_ordering() {
        assert!(FipsLevel::Level1 < FipsLevel::Level2);
        assert!(FipsLevel::Level3 < FipsLevel::Level4);
    }

    #[test]
    fn test_validation_status_display() {
        assert_eq!(
            FipsValidationStatus::NotSubmitted.to_string(),
            "Not Submitted"
        );
        assert_eq!(FipsValidationStatus::InReview.to_string(), "In Review");
        assert_eq!(
            FipsValidationStatus::Historical.to_string(),
            "Historical (expired/revoked)"
        );

        let validated = FipsValidationStatus::Validated {
            cert_number: "4282".into(),
            level: FipsLevel::Level3,
            expiry: "2028-12-31".into(),
        };
        let s = validated.to_string();
        assert!(s.contains("4282"));
        assert!(s.contains("Level 3"));
        assert!(s.contains("2028-12-31"));
    }

    #[test]
    fn test_validation_status_is_validated() {
        assert!(!FipsValidationStatus::NotSubmitted.is_validated());
        assert!(!FipsValidationStatus::InReview.is_validated());
        assert!(!FipsValidationStatus::Historical.is_validated());
        assert!(FipsValidationStatus::Validated {
            cert_number: "1".into(),
            level: FipsLevel::Level1,
            expiry: "2030-01-01".into(),
        }
        .is_validated());
    }

    #[test]
    fn test_crypto_module_is_approved_algorithm() {
        let module = FipsCryptoModule {
            module_name: "test".into(),
            version: "1.0".into(),
            algorithms: vec!["AES-256-GCM".into(), "AES-128-GCM".into()],
            validation_status: FipsValidationStatus::NotSubmitted,
            lab_name: None,
            submission_date: None,
        };
        assert!(module.is_approved_algorithm("AES-256-GCM"));
        assert!(!module.is_approved_algorithm("ChaCha20"));
    }

    #[test]
    fn test_crypto_module_days_until_expiry_not_validated() {
        let module = FipsCryptoModule {
            module_name: "test".into(),
            version: "1.0".into(),
            algorithms: vec![],
            validation_status: FipsValidationStatus::NotSubmitted,
            lab_name: None,
            submission_date: None,
        };
        assert_eq!(module.days_until_expiry(), None);
    }

    #[test]
    fn test_crypto_module_days_until_expiry_future() {
        let module = FipsCryptoModule {
            module_name: "test".into(),
            version: "1.0".into(),
            algorithms: vec!["AES-256-GCM".into()],
            validation_status: FipsValidationStatus::Validated {
                cert_number: "9999".into(),
                level: FipsLevel::Level2,
                expiry: "2099-12-31".into(),
            },
            lab_name: None,
            submission_date: None,
        };
        let days = module.days_until_expiry().expect("should parse");
        assert!(days > 0, "far future date should have positive days");
    }

    #[test]
    fn test_crypto_module_days_until_expiry_past() {
        let module = FipsCryptoModule {
            module_name: "test".into(),
            version: "1.0".into(),
            algorithms: vec!["AES-256-GCM".into()],
            validation_status: FipsValidationStatus::Validated {
                cert_number: "0001".into(),
                level: FipsLevel::Level1,
                expiry: "2020-01-01".into(),
            },
            lab_name: None,
            submission_date: None,
        };
        let days = module.days_until_expiry().expect("should parse");
        assert!(days < 0, "past date should have negative days");
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = FipsComplianceRegistry::new();
        registry.register_module(FipsCryptoModule {
            module_name: "test-mod".into(),
            version: "1.0".into(),
            algorithms: vec!["AES-256-GCM".into()],
            validation_status: FipsValidationStatus::NotSubmitted,
            lab_name: None,
            submission_date: None,
        });

        assert_eq!(registry.module_count(), 1);
        assert!(registry.get_module("test-mod").is_some());
        assert!(registry.get_module("nonexistent").is_none());
    }

    #[test]
    fn test_registry_all_validated() {
        let mut registry = FipsComplianceRegistry::new();

        // Empty registry: all_validated is false (no modules)
        assert!(!registry.all_validated());

        // Add a validated module
        registry.register_module(FipsCryptoModule {
            module_name: "validated-mod".into(),
            version: "1.0".into(),
            algorithms: vec!["AES-256-GCM".into()],
            validation_status: FipsValidationStatus::Validated {
                cert_number: "1234".into(),
                level: FipsLevel::Level3,
                expiry: "2030-01-01".into(),
            },
            lab_name: Some("Acme CST Lab".into()),
            submission_date: Some("2025-01-15".into()),
        });
        assert!(registry.all_validated());

        // Add an unvalidated module
        registry.register_module(FipsCryptoModule {
            module_name: "pending-mod".into(),
            version: "0.1".into(),
            algorithms: vec!["ML-DSA-87".into()],
            validation_status: FipsValidationStatus::InReview,
            lab_name: Some("NIST Lab".into()),
            submission_date: Some("2026-01-01".into()),
        });
        assert!(!registry.all_validated());
    }

    #[test]
    fn test_registry_unvalidated_modules() {
        let mut registry = FipsComplianceRegistry::new();
        registry.register_module(FipsCryptoModule {
            module_name: "validated".into(),
            version: "1.0".into(),
            algorithms: vec![],
            validation_status: FipsValidationStatus::Validated {
                cert_number: "1".into(),
                level: FipsLevel::Level1,
                expiry: "2030-01-01".into(),
            },
            lab_name: None,
            submission_date: None,
        });
        registry.register_module(FipsCryptoModule {
            module_name: "pending".into(),
            version: "0.1".into(),
            algorithms: vec![],
            validation_status: FipsValidationStatus::NotSubmitted,
            lab_name: None,
            submission_date: None,
        });

        let unvalidated = registry.unvalidated_modules();
        assert_eq!(unvalidated.len(), 1);
        assert_eq!(unvalidated[0].module_name, "pending");
    }

    #[test]
    fn test_registry_generate_compliance_report() {
        let mut registry = FipsComplianceRegistry::new();
        registry.register_module(FipsCryptoModule {
            module_name: "AES-256-GCM".into(),
            version: "1.0".into(),
            algorithms: vec!["AES-256-GCM".into()],
            validation_status: FipsValidationStatus::Validated {
                cert_number: "4282".into(),
                level: FipsLevel::Level3,
                expiry: "2099-12-31".into(),
            },
            lab_name: Some("Test Lab".into()),
            submission_date: Some("2025-06-01".into()),
        });
        registry.register_module(FipsCryptoModule {
            module_name: "ML-DSA-87".into(),
            version: "0.2".into(),
            algorithms: vec!["ML-DSA-87".into()],
            validation_status: FipsValidationStatus::NotSubmitted,
            lab_name: None,
            submission_date: None,
        });

        let report = registry.generate_compliance_report();
        assert!(report.contains("1/2 modules validated"));
        assert!(report.contains("NOT fully FIPS 140-3 compliant"));
        assert!(report.contains("ML-DSA-87"));
        assert!(report.contains("AES-256-GCM"));
    }

    #[test]
    fn test_default_modules_registered() {
        let registry = global_registry().lock().unwrap();
        // Should have all the default modules
        assert!(registry.module_count() >= 10);
        assert!(registry.get_module("AES-256-GCM (aes-gcm crate)").is_some());
        assert!(registry.get_module("ML-DSA-87 (ml-dsa crate)").is_some());
        assert!(registry.get_module("ML-KEM-1024 (ml-kem crate)").is_some());
        assert!(registry.get_module("SHA-512 (sha2 crate)").is_some());
        assert!(registry.get_module("HMAC-SHA512 (hmac crate)").is_some());
        assert!(registry.get_module("HKDF-SHA512 (hkdf crate)").is_some());
        assert!(registry
            .get_module("FROST-Ristretto255 (frost-ristretto255 crate)")
            .is_some());
    }

    #[test]
    fn test_default_modules_not_all_validated() {
        let registry = global_registry().lock().unwrap();
        // All default modules are NotSubmitted, so not all validated
        assert!(!registry.all_validated());
    }

    #[test]
    fn test_transition_plan_default() {
        let plan = FipsTransitionPlan::default_plan();
        assert!(!plan.milestones.is_empty());
        assert_eq!(plan.completion_fraction(), 0.0);
    }

    #[test]
    fn test_transition_plan_completion() {
        let mut plan = FipsTransitionPlan::default_plan();
        let total = plan.milestones.len();
        plan.milestones[0].completed = true;
        plan.milestones[1].completed = true;

        let expected = 2.0 / total as f64;
        assert!((plan.completion_fraction() - expected).abs() < 0.001);
    }

    #[test]
    fn test_transition_plan_report() {
        let plan = FipsTransitionPlan::default_plan();
        let report = plan.generate_report();
        assert!(report.contains("MILNET FIPS 140-3 Validation Plan"));
        assert!(report.contains("[TODO]"));
        assert!(report.contains("M1"));
    }

    #[test]
    fn test_parse_days_until_valid() {
        // Just verify it returns Some for a valid date
        let result = parse_days_until("2099-01-01");
        assert!(result.is_some());
        assert!(result.unwrap() > 0);
    }

    #[test]
    fn test_parse_days_until_invalid() {
        assert_eq!(parse_days_until("not-a-date"), None);
        assert_eq!(parse_days_until("2025"), None);
        assert_eq!(parse_days_until(""), None);
    }

    #[test]
    fn test_fips_compliance_summary_honest() {
        let summary = fips_compliance_summary();
        // Default modules are all NotSubmitted
        assert_eq!(summary.validated_modules, 0);
        assert!(!summary.military_ready);
        assert!(summary.compliance_percentage < 0.01);
        assert!(summary.assessment.contains("NONE"));
        assert!(!summary.unvalidated_modules.is_empty());
    }

    #[test]
    fn test_compliance_percentage_zero() {
        let pct = compliance_percentage();
        // All defaults are NotSubmitted
        assert!(pct < 0.01, "expected 0%, got {:.1}%", pct);
    }

    #[test]
    fn test_fips_startup_check_runs() {
        // Just verify it doesn't panic
        fips_startup_check();
    }
}
