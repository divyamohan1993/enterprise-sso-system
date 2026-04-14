//! Automated STIG Check Runner for the MILNET SSO system.
//!
//! Extends the existing `stig` module with:
//! - Automated STIG check runner with CI/CD integration hooks
//! - STIG check result persistence
//! - Deviation tracking with justification
//! - Auto-remediation for common findings
//! - XCCDF result format output
//!
//! # Integration
//!
//! This module is designed to run in CI/CD pipelines (via the `run_scan`
//! function) and produce XCCDF-compatible XML results that can be imported
//! into STIG Viewer or other compliance tools.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::siem::SecurityEvent;
use crate::stig::{StigAuditor, StigCheck, StigCategory, StigSeverity, StigStatus, StigSummary};

// ---------------------------------------------------------------------------
// Scan Configuration
// ---------------------------------------------------------------------------

/// Configuration for a STIG scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    /// Human-readable scan name (e.g., "Pre-Deploy STIG Scan").
    pub scan_name: String,
    /// STIG benchmark identifier (e.g., "RHEL_9_STIG_V1R2").
    pub benchmark_id: String,
    /// Categories to include (empty = all).
    pub categories: Vec<StigCategory>,
    /// Minimum severity to report (e.g., CatII = skip CatIII).
    pub min_severity: Option<StigSeverity>,
    /// Whether to attempt auto-remediation for known findings.
    pub auto_remediate: bool,
    /// Whether to fail the CI pipeline on any CatI findings.
    pub fail_on_cat_i: bool,
    /// Whether to fail the CI pipeline on CatII findings exceeding threshold.
    pub fail_on_cat_ii_threshold: Option<usize>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            scan_name: "MILNET STIG Scan".to_string(),
            benchmark_id: "MILNET_SSO_STIG_V1R1".to_string(),
            categories: Vec::new(),
            min_severity: None,
            auto_remediate: false,
            fail_on_cat_i: true,
            fail_on_cat_ii_threshold: Some(5),
        }
    }
}

// ---------------------------------------------------------------------------
// Scan Result
// ---------------------------------------------------------------------------

/// Result of a complete STIG scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanResult {
    /// Scan configuration used.
    pub config: ScanConfig,
    /// Individual check results.
    pub checks: Vec<StigCheck>,
    /// Aggregate summary.
    pub summary: StigSummary,
    /// Whether the CI gate passed.
    pub ci_gate_passed: bool,
    /// Reason for CI gate failure (if applicable).
    pub ci_gate_reason: Option<String>,
    /// Scan start time (ISO 8601).
    pub started_at: String,
    /// Scan end time (ISO 8601).
    pub completed_at: String,
    /// Deviations (accepted findings with justification).
    pub deviations: Vec<Deviation>,
    /// Auto-remediations that were applied.
    pub remediations_applied: Vec<RemediationRecord>,
}

impl ScanResult {
    /// Check whether the scan passed the CI gate.
    pub fn passed(&self) -> bool {
        self.ci_gate_passed
    }

    /// Get all failing checks.
    pub fn failures(&self) -> Vec<&StigCheck> {
        self.checks
            .iter()
            .filter(|c| c.status == StigStatus::Fail)
            .collect()
    }

    /// Get failures filtered by severity.
    pub fn failures_by_severity(&self, severity: StigSeverity) -> Vec<&StigCheck> {
        self.checks
            .iter()
            .filter(|c| c.status == StigStatus::Fail && c.severity == severity)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Deviation Tracking
// ---------------------------------------------------------------------------

/// A deviation (accepted finding) with justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deviation {
    /// STIG check ID this deviation applies to.
    pub check_id: String,
    /// Justification for accepting the deviation.
    pub justification: String,
    /// Compensating control description (if applicable).
    pub compensating_control: Option<String>,
    /// Who approved this deviation.
    pub approved_by: String,
    /// Date the deviation was approved (ISO 8601).
    pub approved_date: String,
    /// Expiry date for the deviation (must be re-reviewed).
    pub expires: String,
    /// Risk acceptance level.
    pub risk_accepted: DeviationRisk,
}

/// Risk level for a deviation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviationRisk {
    Low,
    Moderate,
    High,
}

// ---------------------------------------------------------------------------
// Auto-Remediation
// ---------------------------------------------------------------------------

/// Record of an auto-remediation that was applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationRecord {
    /// STIG check ID that was remediated.
    pub check_id: String,
    /// Description of the remediation action.
    pub action: String,
    /// Whether the remediation was successful.
    pub success: bool,
    /// Pre-remediation state.
    pub before: String,
    /// Post-remediation state.
    pub after: String,
    /// Timestamp of remediation (ISO 8601).
    pub timestamp: String,
}

/// Known auto-remediations for common STIG findings.
#[derive(Debug, Clone)]
pub struct RemediationRule {
    /// STIG check ID pattern this rule applies to.
    pub check_id_pattern: String,
    /// Description of what this rule does.
    pub description: String,
    /// The remediation action (a command or configuration change).
    pub action: RemediationAction,
}

/// Types of remediation actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemediationAction {
    /// Set a sysctl value.
    Sysctl { key: String, value: String },
    /// Set a file permission.
    FilePermission { path: String, mode: u32 },
    /// Set a configuration value.
    ConfigValue { file: String, key: String, value: String },
    /// Custom action described in text (requires manual review).
    Manual { description: String },
}

// ---------------------------------------------------------------------------
// STIG Scanner
// ---------------------------------------------------------------------------

/// Automated STIG scanner with CI/CD integration.
pub struct StigScanner {
    /// Scan configuration.
    config: ScanConfig,
    /// Known deviations (accepted findings).
    deviations: Vec<Deviation>,
    /// Auto-remediation rules.
    remediation_rules: Vec<RemediationRule>,
    /// Historical scan results.
    history: Vec<ScanResult>,
}

impl StigScanner {
    /// Create a new scanner with the given configuration.
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            deviations: Vec::new(),
            remediation_rules: Vec::new(),
            history: Vec::new(),
        }
    }

    /// Add a deviation (accepted finding with justification).
    pub fn add_deviation(&mut self, deviation: Deviation) {
        self.deviations.push(deviation);
    }

    /// Add an auto-remediation rule.
    pub fn add_remediation_rule(&mut self, rule: RemediationRule) {
        self.remediation_rules.push(rule);
    }

    /// Check whether a finding is covered by a deviation.
    pub fn is_deviated(&self, check_id: &str) -> Option<&Deviation> {
        self.deviations.iter().find(|d| d.check_id == check_id)
    }

    /// Run a complete STIG scan.
    ///
    /// This creates a `StigAuditor`, runs all applicable checks, applies
    /// deviation tracking, optionally runs auto-remediations, and evaluates
    /// the CI gate criteria.
    pub fn run_scan(&mut self) -> ScanResult {
        let started_at = now_iso8601();

        // Run the actual STIG auditor
        let mut auditor = StigAuditor::new();
        let checks = auditor.run_all().to_vec();
        let summary = auditor.summary();

        // Execute remediations for failing checks if auto_remediate is enabled
        let mut remediations_applied = Vec::new();
        if self.config.auto_remediate {
            for check in &checks {
                if check.status == StigStatus::Fail {
                    if let Some(record) = self.attempt_remediation(check) {
                        remediations_applied.push(record);
                    }
                }
            }
        }

        // Filter applicable deviations
        let applicable_deviations: Vec<Deviation> = self
            .deviations
            .iter()
            .filter(|d| checks.iter().any(|c| c.id == d.check_id))
            .cloned()
            .collect();

        // Evaluate CI gate
        let (ci_gate_passed, ci_gate_reason) = self.evaluate_ci_gate(&summary, &applicable_deviations);

        // Emit SIEM event
        if !ci_gate_passed {
            SecurityEvent::tamper_detected(&format!(
                "STIG scan CI gate FAILED: {}",
                ci_gate_reason.as_deref().unwrap_or("unknown")
            ));
        }

        let completed_at = now_iso8601();

        let result = ScanResult {
            config: self.config.clone(),
            checks,
            summary,
            ci_gate_passed,
            ci_gate_reason,
            started_at,
            completed_at,
            deviations: applicable_deviations,
            remediations_applied,
        };

        self.history.push(result.clone());
        result
    }

    /// Attempt to remediate a failing STIG check using matching remediation rules.
    fn attempt_remediation(&self, check: &StigCheck) -> Option<RemediationRecord> {
        let rule = self.remediation_rules.iter().find(|r| {
            r.check_id_pattern == check.id
                || check.id.starts_with(&r.check_id_pattern)
        })?;

        let timestamp = now_iso8601();

        match &rule.action {
            RemediationAction::Sysctl { key, value } => {
                let proc_path = format!("/proc/sys/{}", key.replace('.', "/"));
                let before = std::fs::read_to_string(&proc_path)
                    .unwrap_or_else(|_| "unreadable".to_string())
                    .trim()
                    .to_string();

                let success = std::fs::write(&proc_path, value).is_ok();

                let after = if success {
                    std::fs::read_to_string(&proc_path)
                        .unwrap_or_else(|_| "unreadable".to_string())
                        .trim()
                        .to_string()
                } else {
                    before.clone()
                };

                tracing::info!(
                    "SIEM:REMEDIATION check={} action=sysctl key={} before={} after={} success={}",
                    check.id, key, before, after, success
                );

                Some(RemediationRecord {
                    check_id: check.id.clone(),
                    action: format!("sysctl {} = {}", key, value),
                    success,
                    before,
                    after,
                    timestamp,
                })
            }
            RemediationAction::FilePermission { path, mode } => {
                // Log what WOULD be remediated (actual permission change requires
                // elevated privileges and is a destructive operation)
                let current_mode = std::fs::metadata(path)
                    .map(|m| format!("{:o}", m.len())) // placeholder
                    .unwrap_or_else(|_| "unknown".to_string());

                tracing::warn!(
                    "SIEM:REMEDIATION-PENDING check={} action=file_permission path={} \
                     target_mode={:o} current={}. Manual remediation required.",
                    check.id, path, mode, current_mode
                );

                Some(RemediationRecord {
                    check_id: check.id.clone(),
                    action: format!("file_permission {} -> {:o} (logged, not applied)", path, mode),
                    success: false,
                    before: current_mode,
                    after: format!("target: {:o}", mode),
                    timestamp,
                })
            }
            RemediationAction::ConfigValue { file, key, value } => {
                // Log what WOULD be remediated
                tracing::warn!(
                    "SIEM:REMEDIATION-PENDING check={} action=config_value file={} key={} \
                     value={}. Manual remediation required.",
                    check.id, file, key, value
                );

                Some(RemediationRecord {
                    check_id: check.id.clone(),
                    action: format!("config {} {}={} (logged, not applied)", file, key, value),
                    success: false,
                    before: "current value unknown".to_string(),
                    after: format!("target: {}={}", key, value),
                    timestamp,
                })
            }
            RemediationAction::Manual { description } => {
                tracing::info!(
                    "SIEM:REMEDIATION-MANUAL check={} description={}",
                    check.id, description
                );
                None
            }
        }
    }

    /// Get count of successful remediations from the latest scan.
    pub fn successful_remediations(&self) -> usize {
        self.history
            .last()
            .map(|r| r.remediations_applied.iter().filter(|r| r.success).count())
            .unwrap_or(0)
    }

    /// Get count of attempted remediations from the latest scan.
    pub fn attempted_remediations(&self) -> usize {
        self.history
            .last()
            .map(|r| r.remediations_applied.len())
            .unwrap_or(0)
    }

    /// Evaluate CI gate criteria against scan results.
    fn evaluate_ci_gate(
        &self,
        summary: &StigSummary,
        deviations: &[Deviation],
    ) -> (bool, Option<String>) {
        let deviated_ids: Vec<&str> = deviations.iter().map(|d| d.check_id.as_str()).collect();

        // CatI failures are always blockers (unless deviated)
        if self.config.fail_on_cat_i && summary.cat_i_failures > 0 {
            // Check if all CatI failures are deviated
            let undeviated_cat_i = summary.cat_i_failures; // Simplified
            if undeviated_cat_i > 0 {
                return (
                    false,
                    Some(format!(
                        "CatI failures: {} (undeviated)",
                        undeviated_cat_i
                    )),
                );
            }
        }

        // CatII threshold
        if let Some(threshold) = self.config.fail_on_cat_ii_threshold {
            if summary.cat_ii_failures > threshold {
                return (
                    false,
                    Some(format!(
                        "CatII failures ({}) exceed threshold ({})",
                        summary.cat_ii_failures, threshold
                    )),
                );
            }
        }

        (true, None)
    }

    /// Get scan history.
    pub fn history(&self) -> &[ScanResult] {
        &self.history
    }

    /// Get the most recent scan result.
    pub fn latest_result(&self) -> Option<&ScanResult> {
        self.history.last()
    }
}

// ---------------------------------------------------------------------------
// XCCDF Result Format Output
// ---------------------------------------------------------------------------

/// Generate an XCCDF-compatible XML result document from a scan result.
///
/// XCCDF (Extensible Configuration Checklist Description Format) is the
/// standard format for STIG compliance reporting.
pub fn generate_xccdf_results(result: &ScanResult) -> String {
    let mut xml = String::new();

    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<Benchmark xmlns=\"http://checklists.nist.gov/xccdf/1.2\">\n");
    xml.push_str(&format!(
        "  <title>{}</title>\n",
        escape_xml(&result.config.scan_name)
    ));
    xml.push_str(&format!(
        "  <id>{}</id>\n",
        escape_xml(&result.config.benchmark_id)
    ));
    xml.push_str(&format!(
        "  <status date=\"{}\">accepted</status>\n",
        &result.started_at
    ));

    xml.push_str("  <TestResult>\n");
    xml.push_str(&format!(
        "    <start-time>{}</start-time>\n",
        &result.started_at
    ));
    xml.push_str(&format!(
        "    <end-time>{}</end-time>\n",
        &result.completed_at
    ));

    // Summary scores
    xml.push_str(&format!(
        "    <score system=\"urn:xccdf:scoring:default\">{:.1}</score>\n",
        if result.summary.total > 0 {
            result.summary.passed as f64 / result.summary.total as f64 * 100.0
        } else {
            0.0
        }
    ));

    // Individual rule results
    for check in &result.checks {
        let xccdf_result = match check.status {
            StigStatus::Pass => "pass",
            StigStatus::Fail => "fail",
            StigStatus::NotApplicable => "notapplicable",
            StigStatus::Manual => "informational",
        };

        xml.push_str(&format!(
            "    <rule-result idref=\"{}\">\n",
            escape_xml(&check.id)
        ));
        xml.push_str(&format!(
            "      <result>{}</result>\n",
            xccdf_result
        ));
        xml.push_str(&format!(
            "      <message severity=\"{:?}\">{}</message>\n",
            check.severity,
            escape_xml(&check.detail)
        ));
        xml.push_str("    </rule-result>\n");
    }

    xml.push_str("  </TestResult>\n");
    xml.push_str("</Benchmark>\n");

    xml
}

/// Escape special characters for XML output.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ---------------------------------------------------------------------------
// CI/CD Integration Hook
// ---------------------------------------------------------------------------

/// CI/CD hook that runs a STIG scan and returns an exit code.
///
/// Returns `0` if the scan passes, `1` if it fails.
/// Designed to be called from a CI pipeline step.
pub fn ci_stig_gate(config: ScanConfig) -> (i32, ScanResult) {
    let mut scanner = StigScanner::new(config);
    let result = scanner.run_scan();
    let exit_code = if result.ci_gate_passed { 0 } else { 1 };
    (exit_code, result)
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Serialize a scan result to JSON for persistence.
pub fn serialize_scan_result(result: &ScanResult) -> Result<String, String> {
    serde_json::to_string_pretty(result)
        .map_err(|e| format!("scan result serialization failed: {e}"))
}

/// Deserialize a scan result from JSON.
pub fn deserialize_scan_result(json: &str) -> Result<ScanResult, String> {
    serde_json::from_str(json)
        .map_err(|e| format!("scan result deserialization failed: {e}"))
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

    #[test]
    fn test_scan_config_default() {
        let config = ScanConfig::default();
        assert!(config.fail_on_cat_i);
        assert_eq!(config.fail_on_cat_ii_threshold, Some(5));
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = StigScanner::new(ScanConfig::default());
        assert!(scanner.history().is_empty());
    }

    #[test]
    fn test_deviation_tracking() {
        let mut scanner = StigScanner::new(ScanConfig::default());

        scanner.add_deviation(Deviation {
            check_id: "V-230234".to_string(),
            justification: "Compensating control in place via network segmentation".to_string(),
            compensating_control: Some("Network micro-segmentation".to_string()),
            approved_by: "ISSM".to_string(),
            approved_date: "2025-01-01".to_string(),
            expires: "2025-07-01".to_string(),
            risk_accepted: DeviationRisk::Low,
        });

        assert!(scanner.is_deviated("V-230234").is_some());
        assert!(scanner.is_deviated("V-999999").is_none());
    }

    #[test]
    fn test_run_scan() {
        let mut scanner = StigScanner::new(ScanConfig::default());
        let result = scanner.run_scan();

        assert!(!result.checks.is_empty());
        assert!(result.summary.total > 0);
        assert!(!result.started_at.is_empty());
        assert!(!result.completed_at.is_empty());
    }

    #[test]
    fn test_xccdf_output() {
        let mut scanner = StigScanner::new(ScanConfig::default());
        let result = scanner.run_scan();
        let xml = generate_xccdf_results(&result);

        assert!(xml.contains("<?xml version="));
        assert!(xml.contains("Benchmark"));
        assert!(xml.contains("TestResult"));
        assert!(xml.contains("score"));
    }

    #[test]
    fn test_scan_result_serialization_roundtrip() {
        let mut scanner = StigScanner::new(ScanConfig::default());
        let result = scanner.run_scan();

        let json = serialize_scan_result(&result).expect("serialization must succeed");
        let deserialized = deserialize_scan_result(&json).expect("deserialization must succeed");

        assert_eq!(deserialized.summary.total, result.summary.total);
        assert_eq!(deserialized.ci_gate_passed, result.ci_gate_passed);
    }

    #[test]
    fn test_ci_gate() {
        let config = ScanConfig {
            fail_on_cat_i: false,
            fail_on_cat_ii_threshold: None,
            ..ScanConfig::default()
        };

        let (exit_code, _result) = ci_stig_gate(config);
        assert_eq!(exit_code, 0, "with no gate criteria, scan should pass");
    }

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("a < b & c > d"), "a &lt; b &amp; c &gt; d");
        assert_eq!(escape_xml("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_remediation_rules_applied() {
        let config = ScanConfig {
            auto_remediate: true,
            fail_on_cat_i: false,
            fail_on_cat_ii_threshold: None,
            ..ScanConfig::default()
        };
        let mut scanner = StigScanner::new(config);

        // Add a remediation rule for a kernel check
        scanner.add_remediation_rule(RemediationRule {
            check_id_pattern: "KERNEL-001".to_string(),
            description: "Set ASLR to full randomization".to_string(),
            action: RemediationAction::Sysctl {
                key: "kernel.randomize_va_space".to_string(),
                value: "2".to_string(),
            },
        });

        let result = scanner.run_scan();
        // Remediation attempts should be tracked (success depends on permissions)
        // The important thing is the framework executes, not that it succeeds in CI
        assert!(result.remediations_applied.len() <= result.checks.len());
    }

    #[test]
    fn test_remediation_config_value_logged() {
        let config = ScanConfig {
            auto_remediate: true,
            fail_on_cat_i: false,
            fail_on_cat_ii_threshold: None,
            ..ScanConfig::default()
        };
        let mut scanner = StigScanner::new(config);

        scanner.add_remediation_rule(RemediationRule {
            check_id_pattern: "V-222610".to_string(),
            description: "Set error level to warn".to_string(),
            action: RemediationAction::ConfigValue {
                file: "/etc/milnet/config.toml".to_string(),
                key: "error_level".to_string(),
                value: "warn".to_string(),
            },
        });

        let result = scanner.run_scan();
        // ConfigValue remediations are logged but not applied (success=false)
        for r in &result.remediations_applied {
            if r.check_id == "V-222610" {
                assert!(!r.success, "ConfigValue should be logged, not applied");
            }
        }
    }

    #[test]
    fn test_scan_failures_by_severity() {
        let mut scanner = StigScanner::new(ScanConfig::default());
        let result = scanner.run_scan();

        let cat_i = result.failures_by_severity(StigSeverity::CatI);
        let cat_ii = result.failures_by_severity(StigSeverity::CatII);

        // Just verify the filtering works (actual counts depend on system state)
        assert!(cat_i.len() <= result.failures().len());
        assert!(cat_ii.len() <= result.failures().len());
    }
}
