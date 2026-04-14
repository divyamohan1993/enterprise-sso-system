//! FIPS 140-3 CMVP Submission Tracker Dashboard for the MILNET SSO system.
//!
//! Provides a comprehensive dashboard for tracking FIPS 140-3 CMVP
//! (Cryptographic Module Validation Program) submissions:
//! - Certificate status tracking (NotSubmitted -> InReview -> Validated -> Historical)
//! - Lab contact management
//! - Certificate expiry alerts
//! - Algorithm transition timeline
//! - Integration with existing `fips_validation.rs`
//!
//! # Integration
//!
//! This module builds on top of `fips_validation::FipsComplianceRegistry` and
//! `fips_validation::FipsTransitionPlan` to provide operational tracking
//! capabilities for the actual CMVP submission process.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::fips_validation::{
    FipsComplianceRegistry, FipsCryptoModule, FipsLevel, FipsTransitionPlan,
    FipsValidationStatus,
};
use crate::siem::SecurityEvent;

// ---------------------------------------------------------------------------
// Lab Contact Management
// ---------------------------------------------------------------------------

/// A CMVP-accredited CST (Cryptographic and Security Testing) laboratory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CstLab {
    /// Lab name.
    pub name: String,
    /// Lab NVLAP (National Voluntary Laboratory Accreditation Program) code.
    pub nvlap_code: String,
    /// Primary contact name.
    pub contact_name: String,
    /// Contact email.
    pub contact_email: String,
    /// Contact phone.
    pub contact_phone: Option<String>,
    /// Lab website.
    pub website: Option<String>,
    /// Whether this lab is currently accredited.
    pub accredited: bool,
    /// Specializations (e.g., "PQ algorithms", "HSM modules").
    pub specializations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Submission Tracking
// ---------------------------------------------------------------------------

/// Lifecycle phase of a CMVP submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SubmissionPhase {
    /// Pre-submission preparation (documentation, source code audit).
    Preparation,
    /// Submitted to CST lab for testing.
    LabTesting,
    /// Lab testing complete, report submitted to CMVP.
    CmvpReview,
    /// CMVP has questions or requires changes.
    CmvpQuestions,
    /// Certificate issued.
    Certified,
    /// Submission withdrawn or rejected.
    Withdrawn,
}

impl SubmissionPhase {
    /// Return a human-readable label.
    pub fn label(&self) -> &str {
        match self {
            SubmissionPhase::Preparation => "Preparation",
            SubmissionPhase::LabTesting => "Lab Testing",
            SubmissionPhase::CmvpReview => "CMVP Review",
            SubmissionPhase::CmvpQuestions => "CMVP Questions",
            SubmissionPhase::Certified => "Certified",
            SubmissionPhase::Withdrawn => "Withdrawn",
        }
    }
}

/// A CMVP submission record for a cryptographic module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CmvpSubmission {
    /// Submission tracking identifier.
    pub tracking_id: String,
    /// Module being submitted.
    pub module_name: String,
    /// Module version.
    pub module_version: String,
    /// Target FIPS security level.
    pub target_level: FipsLevel,
    /// Current submission phase.
    pub phase: SubmissionPhase,
    /// CST lab handling the submission.
    pub lab_name: String,
    /// Date submitted to lab (ISO 8601).
    pub submitted_date: Option<String>,
    /// Estimated certification date (ISO 8601).
    pub estimated_cert_date: Option<String>,
    /// Actual certification date (ISO 8601, if certified).
    pub actual_cert_date: Option<String>,
    /// CMVP certificate number (if certified).
    pub cert_number: Option<String>,
    /// Phase transition history.
    pub history: Vec<PhaseTransition>,
    /// Notes and comments.
    pub notes: Vec<String>,
    /// Cost tracking (USD).
    pub estimated_cost: Option<f64>,
    /// Actual cost to date (USD).
    pub actual_cost: Option<f64>,
}

/// A phase transition event in the submission lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseTransition {
    /// Previous phase.
    pub from: SubmissionPhase,
    /// New phase.
    pub to: SubmissionPhase,
    /// Date of transition (ISO 8601).
    pub date: String,
    /// Who recorded the transition.
    pub recorded_by: String,
    /// Notes.
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// Certificate Expiry Alert
// ---------------------------------------------------------------------------

/// Alert level for certificate expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpiryAlertLevel {
    /// More than 180 days until expiry.
    Normal,
    /// 90-180 days until expiry — start renewal planning.
    Advisory,
    /// 30-90 days until expiry — renewal should be in progress.
    Warning,
    /// Less than 30 days until expiry — critical.
    Critical,
    /// Certificate has already expired.
    Expired,
}

/// Certificate expiry alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiryAlert {
    /// Module name.
    pub module_name: String,
    /// Certificate number.
    pub cert_number: String,
    /// Days until expiry (negative if expired).
    pub days_remaining: i64,
    /// Alert level.
    pub level: ExpiryAlertLevel,
    /// Recommended action.
    pub action: String,
}

// ---------------------------------------------------------------------------
// Algorithm Transition Timeline
// ---------------------------------------------------------------------------

/// An entry in the algorithm transition timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionEntry {
    /// Algorithm being transitioned from.
    pub from_algorithm: String,
    /// Algorithm being transitioned to.
    pub to_algorithm: String,
    /// Regulatory driver (e.g., "CNSA 2.0", "NIST SP 800-131A").
    pub regulatory_driver: String,
    /// Deadline for completing the transition (ISO 8601).
    pub deadline: String,
    /// Current status.
    pub status: TransitionStatus,
    /// Dependencies.
    pub dependencies: Vec<String>,
}

/// Status of an algorithm transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionStatus {
    NotStarted,
    InProgress,
    Completed,
    Blocked,
}

// ---------------------------------------------------------------------------
// FIPS Tracker Dashboard
// ---------------------------------------------------------------------------

/// FIPS 140-3 CMVP Submission Tracker Dashboard.
///
/// Integrates with `FipsComplianceRegistry` and `FipsTransitionPlan` to
/// provide a complete view of the organization's FIPS compliance posture.
pub struct FipsTracker {
    /// CST lab contacts.
    pub labs: Vec<CstLab>,
    /// Active and historical submissions.
    pub submissions: BTreeMap<String, CmvpSubmission>,
    /// Algorithm transition timeline.
    pub transitions: Vec<TransitionEntry>,
}

impl FipsTracker {
    /// Create a new, empty tracker.
    pub fn new() -> Self {
        Self {
            labs: Vec::new(),
            submissions: BTreeMap::new(),
            transitions: Vec::new(),
        }
    }

    /// Register a CST lab.
    pub fn add_lab(&mut self, lab: CstLab) {
        self.labs.push(lab);
    }

    /// Create a new CMVP submission.
    pub fn create_submission(&mut self, submission: CmvpSubmission) {
        self.submissions
            .insert(submission.tracking_id.clone(), submission);
    }

    /// Advance a submission to the next phase.
    pub fn advance_submission(
        &mut self,
        tracking_id: &str,
        new_phase: SubmissionPhase,
        recorded_by: &str,
        note: Option<String>,
    ) -> Result<(), String> {
        let submission = self
            .submissions
            .get_mut(tracking_id)
            .ok_or_else(|| format!("submission not found: {}", tracking_id))?;

        let transition = PhaseTransition {
            from: submission.phase,
            to: new_phase,
            date: now_iso8601(),
            recorded_by: recorded_by.to_string(),
            note,
        };

        submission.history.push(transition);
        submission.phase = new_phase;

        // Emit SIEM event for phase transitions
        SecurityEvent::key_rotation(&format!(
            "CMVP submission {} advanced to {:?}",
            tracking_id,
            new_phase.label()
        ));

        Ok(())
    }

    /// Add a transition timeline entry.
    pub fn add_transition(&mut self, entry: TransitionEntry) {
        self.transitions.push(entry);
    }

    /// Check all submissions for certificate expiry alerts.
    pub fn check_expiry_alerts(
        &self,
        registry: &FipsComplianceRegistry,
    ) -> Vec<ExpiryAlert> {
        let mut alerts = Vec::new();

        for module in registry.unvalidated_modules().iter().chain(
            // Also check validated modules for upcoming expiry
            std::iter::empty()
        ) {
            // Unvalidated modules get an advisory alert
            alerts.push(ExpiryAlert {
                module_name: module.module_name.clone(),
                cert_number: "N/A".to_string(),
                days_remaining: 0,
                level: ExpiryAlertLevel::Advisory,
                action: "Submit module for CMVP validation".to_string(),
            });
        }

        // Check validated modules
        for (_, submission) in &self.submissions {
            if submission.phase == SubmissionPhase::Certified {
                if let Some(ref cert_number) = submission.cert_number {
                    // Check registry for expiry info
                    if let Some(module) = registry.get_module(&submission.module_name) {
                        if let Some(days) = module.days_until_expiry() {
                            let level = match days {
                                d if d < 0 => ExpiryAlertLevel::Expired,
                                d if d <= 30 => ExpiryAlertLevel::Critical,
                                d if d <= 90 => ExpiryAlertLevel::Warning,
                                d if d <= 180 => ExpiryAlertLevel::Advisory,
                                _ => ExpiryAlertLevel::Normal,
                            };

                            let action = match level {
                                ExpiryAlertLevel::Expired => "URGENT: Certificate expired — module must not be used in FIPS mode".to_string(),
                                ExpiryAlertLevel::Critical => "Initiate emergency re-certification".to_string(),
                                ExpiryAlertLevel::Warning => "Re-certification should be in progress".to_string(),
                                ExpiryAlertLevel::Advisory => "Plan re-certification submission".to_string(),
                                ExpiryAlertLevel::Normal => "No action needed".to_string(),
                            };

                            // Only include non-normal alerts
                            if level != ExpiryAlertLevel::Normal {
                                // Emit SIEM for critical/expired
                                if matches!(level, ExpiryAlertLevel::Critical | ExpiryAlertLevel::Expired) {
                                    SecurityEvent::key_rotation(&format!(
                                        "FIPS certificate {} expiry alert: {} days remaining",
                                        cert_number, days
                                    ));
                                }

                                alerts.push(ExpiryAlert {
                                    module_name: submission.module_name.clone(),
                                    cert_number: cert_number.clone(),
                                    days_remaining: days,
                                    level,
                                    action,
                                });
                            }
                        }
                    }
                }
            }
        }

        alerts
    }

    /// Get submissions by phase.
    pub fn submissions_by_phase(&self, phase: SubmissionPhase) -> Vec<&CmvpSubmission> {
        self.submissions
            .values()
            .filter(|s| s.phase == phase)
            .collect()
    }

    /// Get the total estimated cost for all active submissions.
    pub fn total_estimated_cost(&self) -> f64 {
        self.submissions
            .values()
            .filter(|s| !matches!(s.phase, SubmissionPhase::Certified | SubmissionPhase::Withdrawn))
            .filter_map(|s| s.estimated_cost)
            .sum()
    }

    /// Generate a dashboard report.
    pub fn generate_dashboard_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== FIPS 140-3 CMVP Tracker Dashboard ===\n\n");

        // Lab summary
        report.push_str(&format!("Registered CST Labs: {}\n", self.labs.len()));
        for lab in &self.labs {
            report.push_str(&format!(
                "  - {} (NVLAP: {}) — {}\n",
                lab.name, lab.nvlap_code,
                if lab.accredited { "Accredited" } else { "NOT Accredited" }
            ));
        }
        report.push('\n');

        // Submissions by phase
        report.push_str("--- Submissions ---\n");
        for phase in &[
            SubmissionPhase::Preparation,
            SubmissionPhase::LabTesting,
            SubmissionPhase::CmvpReview,
            SubmissionPhase::CmvpQuestions,
            SubmissionPhase::Certified,
        ] {
            let subs = self.submissions_by_phase(*phase);
            if !subs.is_empty() {
                report.push_str(&format!("\n{} ({}):\n", phase.label(), subs.len()));
                for sub in subs {
                    report.push_str(&format!(
                        "  [{}] {} v{} — Level {} | Lab: {}\n",
                        sub.tracking_id,
                        sub.module_name,
                        sub.module_version,
                        sub.target_level.as_u8(),
                        sub.lab_name,
                    ));
                }
            }
        }
        report.push('\n');

        // Cost summary
        let total_cost = self.total_estimated_cost();
        if total_cost > 0.0 {
            report.push_str(&format!(
                "Total estimated cost (active): ${:.0}\n\n",
                total_cost
            ));
        }

        // Transition timeline
        if !self.transitions.is_empty() {
            report.push_str("--- Algorithm Transition Timeline ---\n\n");
            for entry in &self.transitions {
                report.push_str(&format!(
                    "  {} -> {} ({}) — {:?} [deadline: {}]\n",
                    entry.from_algorithm,
                    entry.to_algorithm,
                    entry.regulatory_driver,
                    entry.status,
                    entry.deadline,
                ));
            }
        }

        report
    }

    /// Register the default MILNET transition timeline.
    pub fn register_default_transitions(&mut self) {
        self.transitions.push(TransitionEntry {
            from_algorithm: "RSA-2048".to_string(),
            to_algorithm: "ML-DSA-87".to_string(),
            regulatory_driver: "CNSA 2.0".to_string(),
            deadline: "2030-12-31".to_string(),
            status: TransitionStatus::InProgress,
            dependencies: vec!["CMVP PQ testing guidance finalized".to_string()],
        });

        self.transitions.push(TransitionEntry {
            from_algorithm: "ECDH P-256".to_string(),
            to_algorithm: "ML-KEM-1024".to_string(),
            regulatory_driver: "CNSA 2.0".to_string(),
            deadline: "2030-12-31".to_string(),
            status: TransitionStatus::InProgress,
            dependencies: vec!["ML-KEM FIPS 203 validation".to_string()],
        });

        self.transitions.push(TransitionEntry {
            from_algorithm: "SHA-256".to_string(),
            to_algorithm: "SHA-512".to_string(),
            regulatory_driver: "CNSA 2.0".to_string(),
            deadline: "2028-12-31".to_string(),
            status: TransitionStatus::Completed,
            dependencies: vec![],
        });

        self.transitions.push(TransitionEntry {
            from_algorithm: "AES-128".to_string(),
            to_algorithm: "AES-256".to_string(),
            regulatory_driver: "CNSA 2.0".to_string(),
            deadline: "2028-12-31".to_string(),
            status: TransitionStatus::Completed,
            dependencies: vec![],
        });
    }
}

impl Default for FipsTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_iso8601() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", d.as_secs())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lab() -> CstLab {
        CstLab {
            name: "Acme Security Lab".to_string(),
            nvlap_code: "200ABC-0".to_string(),
            contact_name: "Jane Smith".to_string(),
            contact_email: "jane@acmelab.example".to_string(),
            contact_phone: Some("+1-555-0123".to_string()),
            website: Some("https://acmelab.example".to_string()),
            accredited: true,
            specializations: vec!["Post-quantum algorithms".to_string()],
        }
    }

    fn test_submission() -> CmvpSubmission {
        CmvpSubmission {
            tracking_id: "CMVP-2025-001".to_string(),
            module_name: "AES-256-GCM (aes-gcm crate)".to_string(),
            module_version: "0.10".to_string(),
            target_level: FipsLevel::Level1,
            phase: SubmissionPhase::Preparation,
            lab_name: "Acme Security Lab".to_string(),
            submitted_date: None,
            estimated_cert_date: Some("2027-03-31".to_string()),
            actual_cert_date: None,
            cert_number: None,
            history: Vec::new(),
            notes: vec!["Initial preparation phase".to_string()],
            estimated_cost: Some(75000.0),
            actual_cost: None,
        }
    }

    #[test]
    fn test_tracker_creation() {
        let tracker = FipsTracker::new();
        assert!(tracker.labs.is_empty());
        assert!(tracker.submissions.is_empty());
    }

    #[test]
    fn test_add_lab() {
        let mut tracker = FipsTracker::new();
        tracker.add_lab(test_lab());
        assert_eq!(tracker.labs.len(), 1);
        assert!(tracker.labs[0].accredited);
    }

    #[test]
    fn test_create_submission() {
        let mut tracker = FipsTracker::new();
        tracker.create_submission(test_submission());
        assert_eq!(tracker.submissions.len(), 1);
        assert!(tracker.submissions.contains_key("CMVP-2025-001"));
    }

    #[test]
    fn test_advance_submission() {
        let mut tracker = FipsTracker::new();
        tracker.create_submission(test_submission());

        tracker
            .advance_submission(
                "CMVP-2025-001",
                SubmissionPhase::LabTesting,
                "admin",
                Some("Lab testing initiated".to_string()),
            )
            .expect("advance must succeed");

        let sub = tracker.submissions.get("CMVP-2025-001").unwrap();
        assert_eq!(sub.phase, SubmissionPhase::LabTesting);
        assert_eq!(sub.history.len(), 1);
        assert_eq!(sub.history[0].from, SubmissionPhase::Preparation);
        assert_eq!(sub.history[0].to, SubmissionPhase::LabTesting);
    }

    #[test]
    fn test_advance_nonexistent_submission_fails() {
        let mut tracker = FipsTracker::new();
        let result = tracker.advance_submission(
            "NONEXISTENT",
            SubmissionPhase::LabTesting,
            "admin",
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_submissions_by_phase() {
        let mut tracker = FipsTracker::new();
        tracker.create_submission(test_submission());

        let prep = tracker.submissions_by_phase(SubmissionPhase::Preparation);
        assert_eq!(prep.len(), 1);

        let testing = tracker.submissions_by_phase(SubmissionPhase::LabTesting);
        assert!(testing.is_empty());
    }

    #[test]
    fn test_total_estimated_cost() {
        let mut tracker = FipsTracker::new();
        tracker.create_submission(test_submission());

        let mut sub2 = test_submission();
        sub2.tracking_id = "CMVP-2025-002".to_string();
        sub2.estimated_cost = Some(50000.0);
        tracker.create_submission(sub2);

        assert!((tracker.total_estimated_cost() - 125000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_default_transitions() {
        let mut tracker = FipsTracker::new();
        tracker.register_default_transitions();

        assert!(tracker.transitions.len() >= 4);
        assert!(tracker.transitions.iter().any(|t| t.to_algorithm == "ML-DSA-87"));
        assert!(tracker.transitions.iter().any(|t| t.to_algorithm == "ML-KEM-1024"));
    }

    #[test]
    fn test_dashboard_report() {
        let mut tracker = FipsTracker::new();
        tracker.add_lab(test_lab());
        tracker.create_submission(test_submission());
        tracker.register_default_transitions();

        let report = tracker.generate_dashboard_report();
        assert!(report.contains("CMVP Tracker Dashboard"));
        assert!(report.contains("Acme Security Lab"));
        assert!(report.contains("CMVP-2025-001"));
        assert!(report.contains("ML-DSA-87"));
    }

    #[test]
    fn test_submission_phase_labels() {
        assert_eq!(SubmissionPhase::Preparation.label(), "Preparation");
        assert_eq!(SubmissionPhase::Certified.label(), "Certified");
        assert_eq!(SubmissionPhase::Withdrawn.label(), "Withdrawn");
    }

    #[test]
    fn test_expiry_alert_levels() {
        let mut tracker = FipsTracker::new();
        let registry = FipsComplianceRegistry::new();

        // With empty registry, no alerts
        let alerts = tracker.check_expiry_alerts(&registry);
        assert!(alerts.is_empty());
    }
}
